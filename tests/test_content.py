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

import copy
import dataclasses
import datetime
import json
import re
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.capabilities import (
    EMPTY_MANIFEST,
    Capability,
    CapabilityManifest,
)
from cohaera.checks import (
    ALL_CHECKS,
    CHECK_FAMILIES,
    SequenceGrammar,
    run_all,
)
from cohaera.identity import NO_TRUST_CONFIG, run_id
from cohaera.limits import DEFAULT_LIMITS
from cohaera.model import Event, Session, to_cim_event

# Last, so the cohaera imports above stay at the top of the file. PyYAML is a
# dev dependency; the runtime still has none.
yaml = pytest.importorskip("yaml", reason="PyYAML is a dev dependency")

REPO = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO / "content" / "sigma"
MANIFEST = REPO / "content" / "manifest" / "example_capability_manifest.json"
CONTENT_README = REPO / "content" / "README.md"
CARD = REPO / "eval" / "evaluation-card.json"
CODEOWNERS = REPO / ".github" / "CODEOWNERS"
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
                                  source="conformance", input_digest="d",
                                  trust_config=NO_TRUST_CONFIG),
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
# Deployment tiers, and the thing that makes them worth anything: they are
# bound to a measurement rather than to the author's confidence
# ---------------------------------------------------------------------------
#
# Every rule in this pack matches on a Cohaera verdict, so "is this rule good
# enough to page somebody" is not a judgement anyone has to make by reading it.
# eval/evaluation-card.json already records, per check, how often it fired on
# the attacks it is responsible for and how often it fired on benign sessions.
# The tier in each rule's ``custom:`` block is a claim about those numbers, and
# these tests re-read the numbers on every run.
#
# The rule that carries the weight is
# ``test_a_production_rule_needs_a_check_the_card_scores_at_zero_benign``. Every
# other assertion here checks that a rule says what it means; that one checks
# that what it means is true.

TIERS = ("production", "hunt", "dashboard")

# A hunt rule is investigation surface. Sigma has no "do not page" field, so the
# level is the thing every downstream router reads, and a hunt rule at high or
# critical will be routed to a queue somebody is paid to answer.
LEVELS_THAT_PAGE = {"high", "critical"}

# The cell the evaluation card publishes in section 4. Named here rather than
# taken from whichever cell looks best: `name_only` and `random_LEAKY` both
# exist to be worse, and reading a tier out of the flattering ablation is the
# failure this whole file is against.
HEADLINE_CELL = "unseen|task_disjoint|manifest"

# The corpus these tiers were decided against. A regenerated corpus is a new
# measurement and the tiers have to be re-confirmed rather than inherited, so
# this is asserted rather than merely recorded. If it fails, re-read section 4
# of the evaluation card and re-derive every rule's `custom.evidence` block --
# do not just paste the new digest in.
CARD_CORPUS_DIGEST = "a3d9aa5099f7e8d3"

# The five values each rule copies out of the card, and the card's own key for
# each. `source` and `card_cell` are provenance; these are the claim.
EVIDENCE_KEYS = ("labelled", "on_target_attacks", "on_benign",
                 "target_precision_pct")


def card_checks() -> dict[str, dict]:
    card = json.loads(CARD.read_text(encoding="utf-8"))
    return card["cells"][HEADLINE_CELL]["check_attribution"]


def selected_checks(rule: dict) -> set[str]:
    out: set[str] = set()
    for block in rule["detection"].values():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if key.startswith("data.triggered_rules"):
                out.update(value if isinstance(value, list) else [value])
    return out


def declared_family(rule: dict) -> str | None:
    """The card's check name for whatever this rule selects on.

    Derived from the rule's own detection through ``CHECK_FAMILIES`` rather than
    from the string in ``custom.evidence.check``, so the rule cannot claim one
    check's evidence while matching another's.
    """
    families = {CHECK_FAMILIES[c] for c in selected_checks(rule)
                if c in CHECK_FAMILIES}
    assert len(families) <= 1, f"rule spans several check families: {families}"
    return families.pop() if families else None


def test_the_card_the_tiers_were_read_from_is_the_card_on_disk():
    """A tier is a statement about a measurement. If the measurement has been
    regenerated, every tier in the pack is unverified until somebody re-reads
    it."""
    card = json.loads(CARD.read_text(encoding="utf-8"))
    assert card["corpus_digest"] == CARD_CORPUS_DIGEST, (
        "the evaluation corpus has changed since the deployment tiers were set. "
        "Re-read section 4 of eval/EVALUATION-CARD.md and re-derive every "
        "custom.evidence block in content/sigma/ before updating this digest.")
    assert HEADLINE_CELL in card["cells"]


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_every_rule_declares_a_deployment_tier(path):
    """Sigma has no tier field, so an untiered rule is a rule whose deployer has
    to guess -- and the pack's own numbers say the guess is wrong for four of
    the seven checks."""
    rule = load_rule(path)
    custom = rule.get("custom")
    assert isinstance(custom, dict), f"{path.name} has no custom: block"
    assert custom.get("deployment_tier") in TIERS, (
        f"{path.name} declares tier {custom.get('deployment_tier')!r}; "
        f"the tiers are {TIERS}")
    assert str(custom.get("tier_rationale", "")).strip(), (
        f"{path.name} states a tier and does not say why")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_every_rule_has_an_owner_and_a_review_date(path):
    """``author`` records who wrote it. That is not the same question as who
    answers for it now, and an unowned rule is a stale rule within two
    quarters."""
    custom = load_rule(path)["custom"]
    owner = str(custom.get("owner", ""))
    assert owner.startswith("@"), f"{path.name} has no owner handle"
    assert owner in CODEOWNERS.read_text(encoding="utf-8"), (
        f"{path.name} is owned by {owner}, who is not in .github/CODEOWNERS")

    cadence = custom.get("review_cadence_days")
    assert isinstance(cadence, int) and 0 < cadence <= 180, (
        f"{path.name} declares a review cadence of {cadence!r}; detection "
        f"content that is not re-read within two quarters is not maintained")
    last, nxt = custom.get("last_reviewed"), custom.get("next_review")
    assert isinstance(last, datetime.date) and isinstance(nxt, datetime.date)
    assert nxt == last + datetime.timedelta(days=cadence), (
        f"{path.name}: next_review {nxt} is not last_reviewed {last} plus "
        f"{cadence} days")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_no_hunt_tier_rule_can_page(path):
    """The tier says never alert. The level is what a router actually reads, so
    the two must not disagree."""
    rule = load_rule(path)
    if rule["custom"]["deployment_tier"] != "hunt":
        pytest.skip("not hunt tier")
    assert rule["level"] not in LEVELS_THAT_PAGE, (
        f"{path.name} is hunt tier at level {rule['level']}. A hunt rule is an "
        f"investigation surface; anything routed on level will page on it.")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_the_check_a_rule_claims_evidence_for_is_the_one_it_selects_on(path):
    """A rule quoting another check's numbers would launder a 27.1% detection
    into a 100% one without changing a line of its detection."""
    rule = load_rule(path)
    stated = rule["custom"]["evidence"].get("check")
    assert stated == declared_family(rule), (
        f"{path.name} claims evidence for {stated!r} but its detection selects "
        f"on {sorted(selected_checks(rule))}, which the engine attributes to "
        f"{declared_family(rule)!r}")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_a_production_rule_needs_a_check_the_card_scores_at_zero_benign(path):
    """THE ONE THAT MATTERS. A rule may not be marked production unless the
    evaluation card records zero benign hits for the check it fires on.

    This is the C4-11 doctrine applied to a tier instead of a count: a claim in
    a committed file that nothing recomputes is a claim that is already drifting.
    "Deployable" is exactly such a claim, it is the most consequential one this
    pack makes, and until now the only thing behind it was that the author
    believed it.

    Note what it does NOT assert. Nothing here says a hunt rule must have benign
    hits -- a check can be quiet and still not be worth paging on. The
    implication runs one way, because that is the direction that costs an
    analyst their night.
    """
    rule = load_rule(path)
    if rule["custom"]["deployment_tier"] != "production":
        pytest.skip("not production tier")

    family = declared_family(rule)
    assert family is not None, (
        f"{path.name} is production and selects no CHxx check, so the "
        f"evaluation card does not score it. A rule with no measurement cannot "
        f"be production in this pack.")
    measured = card_checks()[family]
    assert measured["on_benign"] == 0, (
        f"{path.name} is marked production, but {HEADLINE_CELL} records "
        f"{measured['on_benign']} benign hits for {family} "
        f"({measured['target_precision_pct']}% target precision). Move it to "
        f"hunt or change the detector; do not change the tier alone.")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_every_evidence_number_in_a_rule_matches_the_card(path):
    """The numbers a deploying engineer reads in the rule are the numbers the
    card measured, or the test fails. Hand-copied figures are how the README's
    results table went two corpus revisions stale."""
    rule = load_rule(path)
    evidence = rule["custom"]["evidence"]
    family = evidence.get("check")
    if family is None:
        assert declared_family(rule) is None, (
            f"{path.name} declares no check but selects "
            f"{sorted(selected_checks(rule))}")
        for key in EVIDENCE_KEYS:
            assert key not in evidence, (
                f"{path.name} has no check and still quotes {key}")
        return
    assert evidence.get("card_cell") == HEADLINE_CELL
    measured = card_checks()[family]
    stated = {k: evidence.get(k) for k in EVIDENCE_KEYS}
    truth = {k: measured[k] for k in EVIDENCE_KEYS}
    assert stated == truth, (
        f"{path.name} quotes {stated} for {family}; the card says {truth}")


@pytest.mark.parametrize("path", sigma_files(), ids=lambda p: p.stem)
def test_content_readme_lists_every_rule_at_the_tier_the_rule_declares(path):
    """A tier nobody can see before they deploy is not a control.

    The rule carries it for a pipeline; content/README.md carries it for the
    engineer choosing what to enable, and the two drift the moment one of them
    is edited alone.
    """
    tier = load_rule(path)["custom"]["deployment_tier"]
    rows = [line for line in CONTENT_README.read_text(encoding="utf-8").splitlines()
            if line.startswith("|") and f"`{path.name}`" in line]
    assert rows, f"{path.name} is not listed in content/README.md"
    assert any(f"`{tier}`" in row for row in rows), (
        f"content/README.md does not list {path.name} as {tier}: {rows}")


def test_ch05_is_quarantined_and_the_rule_says_why():
    """CH05 has never fired on an attack it is responsible for, because the
    corpus contains none. That is not a passing grade on zero tests; it is zero
    tests. Deleting the rule would hide the gap, so it ships quarantined and
    says so where somebody about to enable it will read it.
    """
    measured = card_checks()["CH05_unpaired_calls"]
    assert measured["labelled"] == 0 and measured["on_target_attacks"] == 0, (
        "the corpus now labels attacks for CH05. Re-measure it and re-read the "
        "quarantine note in cohaera_unpaired_consequential_call.yml, which "
        "asserts there are none.")
    assert measured["on_benign"] > 0 and measured["target_precision_pct"] == 0.0

    rule = load_rule(SIGMA_DIR / "cohaera_unpaired_consequential_call.yml")
    assert rule["custom"]["deployment_tier"] != "production"
    text = rule["description"] + " ".join(rule["falsepositives"])
    for phrase in ("QUARANTINED", "0.0%", "never demonstrated"):
        assert phrase in text, f"the CH05 rule no longer says {phrase!r}"


def test_ch02_records_that_it_is_blind_by_default_and_expensive_when_it_is_not():
    """The two halves have to appear together. Either on its own reads as a
    tuning note; together they are the trade, and it is the worst in the pack.
    """
    rule = load_rule(SIGMA_DIR / "cohaera_concealment_gap.yml")
    assert rule["custom"]["deployment_tier"] == "hunt"
    text = rule["description"] + " ".join(rule["falsepositives"])
    for phrase in ("capture_tool_data", "hot_cold.py", "27.1%", "108 benign"):
        assert phrase in text, f"the CH02 rule no longer says {phrase!r}"


def test_the_dashboard_tier_did_not_flatten_the_coverage_rules_guidance():
    """The coverage rule's falsepositives block was already right before there
    were tiers: the state is not a false positive, and the alertable event is a
    DROP. Tiering it must not have rewritten that into boilerplate.
    """
    rule = load_rule(SIGMA_DIR / "cohaera_coverage_degraded.yml")
    assert rule["custom"]["deployment_tier"] == "dashboard"
    assert rule["level"] == "informational"
    text = " ".join(rule["falsepositives"])
    assert "NOT A FALSE POSITIVE, A CONFIGURATION STATE" in text
    assert "DROP in completeness" in text


def test_the_tiers_partition_the_pack_the_way_the_card_does():
    """The whole point, stated once as an inventory rather than per rule.

    Three checks measured at zero benign hits, four measured with hundreds
    between them, and a pack that used to present all of them as one thing
    called "14 Sigma rules, validated".
    """
    by_tier: dict[str, set[str | None]] = {}
    for path in sigma_files():
        rule = load_rule(path)
        by_tier.setdefault(rule["custom"]["deployment_tier"], set()).add(
            declared_family(rule))
    assert by_tier["production"] == {"CH04_guardrail_overrun",
                                     "CH06_evidence_integrity",
                                     "CH07_effect_contradiction"}
    assert by_tier["hunt"] == {"CH01_sequence_order", "CH02_concealment_gap",
                               "CH03_untrusted_to_consequential",
                               "CH05_unpaired_calls"}
    assert by_tier["dashboard"] == {None}
    assert set(card_checks()) == set().union(*by_tier.values()) - {None}


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


def test_the_example_manifest_declares_policy_semantics_both_ways():
    """The `policies` section is the remedy for EVASION.md E20, so the shipped
    example has to demonstrate the remedy rather than describe it.

    Both values matter and they fail in opposite directions. `advisory` stops
    CH04 paging on correct behaviour; `blocking` is what lets it use the word
    bypass. An example carrying only one of them would show half the mechanism.
    """
    manifest = CapabilityManifest.from_file(MANIFEST)
    assert manifest.policy("cost_threshold_exceeded").enforcement == "advisory"
    assert manifest.policy("depth_exceeded").enforcement == "blocking"
    # Keyed on a producer's policy_id rather than on an event type, which is
    # what a real policy engine emits and what the lookup has to support.
    assert manifest.policy("external-data-egress").enforcement == "blocking"
    assert manifest.policy("no-such-policy") is None
    # Lookup takes candidates in preference order, so a caller does not have to
    # know which of the two the producer happened to send.
    assert manifest.policy(None, "depth_exceeded").enforcement == "blocking"


# -- COH-R05: frozen the attribute, not the thing it pointed at -------------


def test_a_manifest_cannot_be_edited_after_its_digest_is_taken():
    """The reported reproduction.

    ``@dataclass(frozen=True)`` stops ``manifest.tools = {}``. It does nothing
    about ``manifest.tools["send_email"] = harmless``, and that is the edit that
    matters: it changes which calls are consequential, for every check, while
    both digests go on describing the manifest as it was loaded. The provenance
    chain would assert the run used a policy it had stopped using.
    """
    manifest = CapabilityManifest.from_file(MANIFEST)
    before = (manifest.file_digest, manifest.semantic_digest,
              manifest.klass_for("send_email"))

    harmless = Capability(tool_id="send_email", effects=frozenset({"read"}))
    with pytest.raises(TypeError):
        manifest.tools["send_email"] = harmless
    with pytest.raises(TypeError):
        del manifest.tools["send_email"]
    with pytest.raises(AttributeError):
        manifest.tools.clear()
    with pytest.raises(TypeError):
        manifest.policies["depth_exceeded"] = None

    assert (manifest.file_digest, manifest.semantic_digest,
            manifest.klass_for("send_email")) == before


def test_a_manifest_does_not_share_the_dict_it_was_built_from():
    """Sealing a reference to somebody else's dict seals nothing. The caller
    still holds it, and a manifest that changes when they edit theirs is exactly
    as mutable as one with no seal at all."""
    source = {"send_email": Capability(tool_id="send_email",
                                       effects=frozenset({"egress"}))}
    manifest = CapabilityManifest(tools=source)
    source["send_email"] = Capability(tool_id="send_email",
                                      effects=frozenset({"read"}))
    source["added_later"] = Capability(tool_id="added_later",
                                       effects=frozenset({"delete"}))

    assert manifest.klass_for("send_email") == "egress"
    assert manifest.get("added_later") is None


def test_the_empty_manifest_is_not_shared_mutable_state():
    """It is a module-level singleton handed to every session that has no
    manifest. One write to it would have reclassified tools process-wide."""
    with pytest.raises(TypeError):
        EMPTY_MANIFEST.tools["anything"] = Capability(
            tool_id="anything", effects=frozenset({"egress"}))
    assert not EMPTY_MANIFEST.loaded


def test_a_sealed_manifest_is_still_an_ordinary_mapping_to_read():
    """Sealing must not cost the read API, or callers will reach past it."""
    manifest = CapabilityManifest.from_file(MANIFEST)
    assert "send_email" in manifest.tools
    assert len(manifest.tools) == len(dict(manifest.tools))
    assert sorted(manifest.tools)[0] == min(manifest.tools.keys())
    assert manifest.tools["send_email"].tool_id == "send_email"
    assert dict(manifest.tools) == dict(manifest.tools.items())


def test_a_manifest_can_still_be_copied_and_serialised():
    """The cost of the seal, paid rather than discovered later.

    A mappingproxy cannot be pickled and ``copy.deepcopy`` falls back to pickle
    for types it has no rule for, so sealing broke copying -- including
    ``deepcopy`` of any object HOLDING a manifest, which is every Session.
    Copying an immutable value is the identity, so the manifest says so and the
    containing objects work again.

    ``dataclasses.asdict`` on a manifest is the one thing that does not come
    back, because it recurses past the manifest into the field and meets the
    proxy directly. It was never the serialisation path -- ``as_dict`` is, it is
    what provenance uses, and it emits JSON rather than ``Capability`` objects
    -- so this asserts the supported route works and pins the unsupported one so
    that the trade is written down instead of rediscovered.
    """
    manifest = CapabilityManifest.from_file(MANIFEST)
    assert copy.deepcopy(manifest) is manifest
    assert copy.copy(manifest) is manifest

    session = Session(session_id="s", manifest=manifest, events=[])
    assert copy.deepcopy(session).manifest is manifest

    assert manifest.as_dict()["tool_count"] == len(manifest.tools)
    json.dumps(manifest.as_dict())            # provenance has to serialise it

    with pytest.raises(TypeError):
        dataclasses.asdict(manifest)


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
