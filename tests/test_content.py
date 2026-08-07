"""Conformance tests for the SIEM content pack.

Sigma CLI validation proves a rule is well-formed YAML that the converter
accepts. It does NOT prove the rule can ever match, because the converter has
never seen the log source. A rule that selects on ``data.tool_sequence`` when
Cohaera emits ``data.tool_seq`` validates cleanly, converts cleanly, deploys
cleanly and fires never. That is the worst failure mode available to detection
content: it counts as coverage in a review and produces nothing.

So these tests do the part validation cannot. They generate REAL verdict records
from real sessions and assert that every field every rule references actually
exists in the output, and that every check ID a rule selects on is one the
engine can actually emit.

Requires PyYAML, which is a dev dependency. The runtime still has zero
dependencies and this file is not imported by the package.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.capabilities import CapabilityManifest
from cohaera.checks import ALL_CHECKS, SequenceGrammar, run_all
from cohaera.identity import run_id
from cohaera.limits import DEFAULT_LIMITS
from cohaera.model import Event, Session, to_cim_event

# Last, so the cohaera imports above stay at the top of the file. PyYAML is a
# dev dependency; the runtime still has none.
yaml = pytest.importorskip("yaml", reason="PyYAML is a dev dependency")

REPO = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO / "content" / "sigma"
MANIFEST = REPO / "content" / "manifest" / "example_capability_manifest.json"
BASE = 1_785_700_000.0

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}

# Modifiers Sigma appends to a field name with a pipe. Stripped before the field
# path is resolved against a real record.
_MODIFIER = re.compile(r"\|.*$")


def sigma_files() -> list[Path]:
    return sorted(SIGMA_DIR.glob("*.yml"))


def load_rule(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# A verdict record that exercises every surface the content pack references
# ---------------------------------------------------------------------------


def _ev(etype, ts, sid="conformance", **kw):
    data = kw.pop("data", {})
    raw = {"timestamp": BASE + ts, "event_type": etype, "session_id": sid,
           "agent_name": "conformance-agent", "framework": "claude",
           "host": "h1", "user": "svc-agent", "data": data}
    raw.update(kw)
    return Event(raw=raw)


def _reference_record() -> dict:
    """One session that trips every check, emitted the way the CLI emits it."""
    events = [
        # untrusted content, with the scanner's marker field present
        _ev("tool_end", 0, tool_name="fetch_kb", span_id="K",
            data={"injection_patterns": ["INSTRUCTION_OVERRIDE"],
                  "has_injection_patterns": True, "tool_result": "..."}),
        # a guardrail fires
        _ev("cost_threshold_exceeded", 1,
            data={"session_cost_usd": 0.63, "threshold_usd": 0.5}),
        # a consequential call COMPLETES afterwards -> CH03/CH04 completed
        _ev("tool_start", 2, tool_name="send_email", span_id="A",
            data={"reversible": False}),
        _ev("tool_end", 3, tool_name="send_email", span_id="A",
            data={"reversible": False, "tool_result": "sent"}),
        # a consequential call ATTEMPTS and fails -> CH03/CH04 attempted
        _ev("tool_start", 4, tool_name="delete_record", span_id="B",
            data={"reversible": False}),
        _ev("tool_error", 5, tool_name="delete_record", span_id="B",
            data={"reversible": False, "error_class": "Timeout"}),
        # an unpaired consequential start -> CH05
        _ev("tool_start", 6, tool_name="transfer_funds", span_id="C",
            data={"reversible": False}),
        # a handoff and a depth marker, for the observra#108 dropped fields
        _ev("agent_handoff", 7, data={"source_agent": "a", "target_agent": "b",
                                      "current_depth": 3}),
        # a field defect -> the integrity rule
        _ev("tool_end", 8, tool_name="ghost", span_id=["not", "a", "string"]),
        # a final response that omits the email -> CH02
        _ev("model_response", 9, data={"response_text": "I looked into it."}),
    ]
    session = Session(session_id="conformance", events=events)

    # A baseline this session violates by ORDER, not by vocabulary -> CH01.
    #
    # It has to know the tools. CH01 now reports not_evaluated when the baseline
    # was fitted on a different workload, because a bigram model out of its
    # distribution scores every transition as unseen and flags every session in
    # that workload. This fixture used to fit on fetch_kb alone and rely on the
    # reference session's other four tools all being novel, which is exactly the
    # out-of-distribution case rather than a detection.
    #
    # So the baseline runs the same tools in a benign order and the reference
    # session reorders them. That is what CH01 is for.
    benign_events = []
    for i, name in enumerate(["fetch_kb", "delete_record", "send_email",
                              "transfer_funds"]):
        benign_events += [
            _ev("tool_start", i * 2, "b", tool_name=name, span_id=f"b{i}"),
            _ev("tool_end", i * 2 + 1, "b", tool_name=name, span_id=f"b{i}")]
    grammar = SequenceGrammar().fit([Session(session_id="b", events=benign_events)])

    findings, cov = run_all(session, grammar)
    provenance = {
        "analysis_run_id": run_id(detector_version="test",
                                  config_hash=DEFAULT_LIMITS.digest(),
                                  source="conformance", input_digest="d"),
        "detector_version": "test",
        "config_hash": DEFAULT_LIMITS.digest(),
        "baseline_hash": grammar.fingerprint(),
        "capability_manifest": CapabilityManifest().as_dict(),
        "correlation_key_version": "producer-supplied",
        "correlation_keyed": False,
        "ingest": {"source": "conformance", "records_accepted": len(events),
                   "records_rejected": 0, "records_with_defects": 1,
                   "reject_ratio": 0.0, "reject_codes": {}, "defect_codes": {},
                   "aborted": False, "abort_reason": ""},
    }
    return to_cim_event(session, findings, coverage=cov, provenance=provenance,
                        sequence=0), findings


REFERENCE_RECORD, REFERENCE_FINDINGS = _reference_record()


def resolve(record: dict, dotted: str):
    """Walk a Sigma dotted field path against a real record. Raises KeyError."""
    node = record
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
            continue
        # data.* fields are emitted inside the data bag; Sigma content and the
        # Exabeam parser both address them with the data. prefix already, so a
        # miss here is a genuine miss.
        raise KeyError(dotted)
    return node


def detection_fields(detection: dict) -> set[str]:
    out: set[str] = set()
    for name, block in detection.items():
        if name == "condition":
            continue
        blocks = block if isinstance(block, list) else [block]
        for b in blocks:
            if isinstance(b, dict):
                out.update(_MODIFIER.sub("", k) for k in b)
    return out


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

def test_content_pack_is_not_empty():
    assert len(sigma_files()) >= 9


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_rule_has_the_required_sigma_keys(path):
    rule = load_rule(path)
    for key in ("title", "id", "status", "description", "logsource", "detection",
                "level", "author", "date"):
        assert key in rule, f"{path.name} missing {key}"
    assert rule["level"] in VALID_LEVELS, rule["level"]
    assert rule["status"] in VALID_STATUS, rule["status"]
    uuid.UUID(str(rule["id"]))
    assert rule["logsource"] == {"product": "cohaera", "service": "session_verdict"}
    assert "condition" in rule["detection"]


def test_rule_ids_are_unique():
    seen: dict[str, str] = {}
    for path in sigma_files():
        rid = str(load_rule(path)["id"])
        assert rid not in seen, f"{path.name} reuses the id from {seen[rid]}"
        seen[rid] = path.name


def test_related_rule_ids_point_at_rules_that_exist():
    """The CH03 and CH04 splits use ``related`` to record the lineage. A
    dangling reference makes the split unauditable."""
    known = {str(load_rule(p)["id"]) for p in sigma_files()}
    for path in sigma_files():
        for rel in load_rule(path).get("related", []):
            assert str(rel["id"]) in known, f"{path.name} relates to a missing rule"
            assert rel["type"] in {"derived", "obsolete", "merged", "renamed",
                                   "similar"}


# ---------------------------------------------------------------------------
# The part Sigma validation cannot do
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_every_selected_check_id_is_one_the_engine_can_emit(path):
    """A rule selecting on a check ID that no longer exists validates cleanly,
    converts cleanly and fires never.

    This is the test that would have caught the CH03/CH04 rename on its own.
    """
    rule = load_rule(path)
    for block in rule["detection"].values():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if not key.startswith("data.triggered_rules"):
                continue
            for wanted in (value if isinstance(value, list) else [value]):
                assert wanted in ALL_CHECKS, (
                    f"{path.name} selects on '{wanted}', which the engine never "
                    f"emits. Known check IDs: {ALL_CHECKS}")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_every_referenced_field_exists_in_a_real_verdict(path):
    """Every field in ``fields:`` and in every selection must resolve against a
    record the engine actually produced."""
    rule = load_rule(path)
    referenced = set(rule.get("fields") or []) | detection_fields(rule["detection"])
    missing = []
    for dotted in sorted(referenced):
        try:
            resolve(REFERENCE_RECORD, dotted)
        except KeyError:
            missing.append(dotted)
    assert not missing, f"{path.name} references fields Cohaera never emits: {missing}"


def test_the_reference_record_actually_trips_every_rule():
    """A conformance fixture that fires nothing proves nothing.

    Every non-coverage rule in the pack must have something to match in the
    reference record, or the field-resolution test above is checking paths
    against a record that could never carry them anyway.
    """
    fired = set(REFERENCE_RECORD["data"]["triggered_rules"])
    assert fired == {
        "CH01_sequence_order", "CH02_concealment_gap",
        "CH03_untrusted_to_completed_action", "CH03_untrusted_to_attempted_action",
        "CH04_guardrail_bypass_completed", "CH04_post_guardrail_attempt",
        "CH05_unpaired_calls",
    }, sorted(fired)
    assert REFERENCE_RECORD["data"]["integrity_defect_count"] >= 1
    assert REFERENCE_RECORD["data"]["coverage"]["completeness"] <= 0.8
    assert REFERENCE_RECORD["data"]["unpaired_consequential_count"] >= 1


def test_split_checks_carry_the_severity_the_rules_assume():
    """The Sigma level and the engine severity must not disagree.

    The whole point of splitting CH04 was that an attempt and a completion no
    longer share a level. If the engine regressed to emitting both at high, the
    content would silently over-alert again.
    """
    by_check = {f.check: f for f in REFERENCE_FINDINGS}
    assert by_check["CH04_guardrail_bypass_completed"].severity == "high"
    assert by_check["CH04_post_guardrail_attempt"].severity == "medium"
    assert by_check["CH03_untrusted_to_attempted_action"].severity == "medium"
    assert by_check["CH03_untrusted_to_completed_action"].severity == "critical"


def test_every_emitted_check_id_has_a_rule():
    """The reverse direction: an engine check with no content is a detection
    nobody receives."""
    selected: set[str] = set()
    for path in sigma_files():
        for block in load_rule(path)["detection"].values():
            if not isinstance(block, dict):
                continue
            for key, value in block.items():
                if key.startswith("data.triggered_rules"):
                    selected.update(value if isinstance(value, list) else [value])
    assert set(ALL_CHECKS) == selected, (
        f"checks with no Sigma rule: {sorted(set(ALL_CHECKS) - selected)}")


# ---------------------------------------------------------------------------
# The capability manifest ships as content too
# ---------------------------------------------------------------------------

def test_example_manifest_loads_and_is_useful():
    manifest = CapabilityManifest.from_file(MANIFEST)
    assert manifest.loaded and manifest.file_digest and manifest.semantic_digest
    assert manifest.klass_for("send_email") == "egress"
    assert manifest.klass_for("delete_record") == "state_change"
    assert manifest.klass_for("draft_reply") == "read_only"
    # The two entries that exist specifically because no lexical rule separates
    # them. If these ever agree, the manifest has stopped earning its keep.
    assert manifest.klass_for("sync_to_partner") == "egress"
    assert manifest.klass_for("sync_local_cache") == "state_change"


def test_example_manifest_is_valid_json_with_a_stable_digest():
    blob = MANIFEST.read_bytes()
    json.loads(blob.decode("utf-8"))
    a = CapabilityManifest.from_file(MANIFEST)
    b = CapabilityManifest.from_file(MANIFEST)
    assert a.file_digest == b.file_digest
    assert a.semantic_digest == b.semantic_digest


def test_manifest_corrects_a_heuristic_misclassification():
    """transfer_funds tokenises to include 'transfer', which is in both the
    egress and the irreversible keyword sets, so the heuristic calls it egress.
    It moves money; it is not primarily a data-egress tool."""
    manifest = CapabilityManifest.from_file(MANIFEST)
    plain = Session(session_id="s", events=[
        _ev("tool_start", 0, tool_name="transfer_funds", span_id="A")])
    declared = Session(session_id="s", manifest=manifest, events=[
        _ev("tool_start", 0, tool_name="transfer_funds", span_id="A")])
    assert plain.tool_calls[0].klass == "egress"
    assert declared.tool_calls[0].klass == "state_change"
    assert declared.tool_calls[0].consequential


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
