"""Tests for the external-validation harness.

Three things are under test here, in ascending order of how much they matter.

1. THE ADAPTERS PARSE WHAT THEY CLAIM TO PARSE, and fail loudly rather than
   quietly when handed something else. A corpus that half-parses produces a
   false-positive rate over a population nobody can describe.

2. THE DOCTRINE HOLDS: absent, never weaker. An adapted session must not carry
   an evidence field its source corpus cannot supply. This is asserted directly
   AND through the mutation that would break it -- the test is written so that
   an adapter which "helpfully" defaults a missing field fails it.

3. THE SCOPE STATEMENT STAYS TRUE. The claim that only CH01, CH02 and CH05 are
   externally validatable today is derived from the engine's own coverage
   contracts run over a real adapted session, not from a table somebody typed.
   This is the test that stops docs/EXTERNAL-VALIDATION.md rotting.

Everything runs against the hand-written fixtures under
``eval/external/fixtures``. Those are ADAPTER FIXTURES, not corpus data, and no
number computed from them means anything about detection performance.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera.checks import (
    ALL_CHECKS,
    CHECK_FAMILIES,
    R_NO_POLICY_EVIDENCE,
    SURFACE_APPROVAL,
    SURFACE_EFFECT_RECEIPT,
    SURFACE_EVENT_INTEGRITY,
    SURFACE_INJECTION_SCANNER,
    SURFACE_POLICY_SEMANTICS,
    coverage,
    run_all,
)
from cohaera.model import scanner_reported
from eval.external import scope
from eval.external.adapters import atbench, stepshield
from eval.external.adapters.base import (
    FABRICABLE_FIELDS,
    AdapterError,
    FabricatedEvidenceError,
    assert_no_fabricated_evidence,
    cim_event,
)
from eval.external.corpus_probe import probe_stepshield_train
from eval.external.run_external import (
    build_session,
    coverage_report,
    run,
    scope_audit,
    split_tasks,
)

FIXTURES = Path(__file__).resolve().parent.parent / "eval" / "external" / "fixtures"
STEPSHIELD_DIR = FIXTURES / "stepshield"
ATBENCH_FILE = FIXTURES / "atbench" / "ADAPTER-FIXTURE-atbench.jsonl"


# ---------------------------------------------------------------------------
# Fixtures are labelled as fixtures
# ---------------------------------------------------------------------------


def test_every_fixture_declares_itself_a_fixture():
    """No file here may be mistakable for real corpus data."""
    paths = sorted(STEPSHIELD_DIR.glob("*.jsonl"))
    assert paths, "stepshield fixtures missing"
    for path in paths:
        record = json.loads(path.read_text(encoding="utf-8"))
        assert "_fixture" in record, f"{path.name} does not declare itself"
        assert record["trajectory_id"].startswith("ADAPTER-FIXTURE-")

    for line in ATBENCH_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            assert "_fixture" in record
            assert record["id"].startswith("ADAPTER-FIXTURE-")


# ---------------------------------------------------------------------------
# 1. The adapters
# ---------------------------------------------------------------------------


def test_stepshield_adapts_the_training_pair_shape():
    sessions = {s.session_id: s
                for s in stepshield.load_directory(STEPSHIELD_DIR)}
    rogue = sessions["ADAPTER-FIXTURE-INV-001-ROGUE"]
    clean = sessions["ADAPTER-FIXTURE-INV-001-CLEAN"]

    assert rogue.is_attack is True
    assert clean.is_attack is False
    # The pair key is what makes the bootstrap a task-level interval. A rogue
    # and its matched clean are one draw, not two.
    assert rogue.task_id == clean.task_id
    assert not rogue.task_clustering_is_degenerate


def test_stepshield_adapts_the_undocumented_generated_benign_shape():
    """The shape data/README.md does not document.

    The corpus's published schema omits ``trajectory_type``, ``task_id`` and
    ``category``, all of which the generated-benign records carry. An adapter
    written from the documentation alone reads the label off the id suffix,
    gets ``00001`` from ``BENIGN-GEN-00001``, and rejects the entire benign
    population -- which is the whole denominator of the headline metric.
    """
    sessions = {s.session_id: s
                for s in stepshield.load_directory(STEPSHIELD_DIR)}
    benign = sessions["ADAPTER-FIXTURE-BENIGN-GEN-00001"]

    assert benign.is_attack is False
    assert benign.kind == "benign"
    # Read from the explicit field, not from the identifier.
    assert benign.task_id == "fixture-benign-pool-0001"
    assert benign.family == "destructive_action"


def test_stepshield_refuses_a_trajectory_whose_type_cannot_be_read():
    with pytest.raises(AdapterError, match="cannot determine the trajectory"):
        stepshield.adapt_trajectory(
            {"trajectory_id": "MYSTERY-042", "steps": [{"action": "ls"}]})


def test_stepshield_refuses_a_step_with_no_action():
    with pytest.raises(AdapterError, match="no string 'action'"):
        stepshield.adapt_trajectory({
            "trajectory_id": "X-1-ROGUE",
            "steps": [{"step": 1, "observation": "hi"}]})


def test_stepshield_missing_directory_names_the_fix():
    """The expected state of a fresh clone. It must say what to do."""
    with pytest.raises(AdapterError) as exc:
        stepshield.load_directory(STEPSHIELD_DIR / "does-not-exist")
    message = str(exc.value)
    assert "git clone https://github.com/glo26/stepshield.git" in message
    assert "CC BY 4.0" in message


def test_atbench_adapts_the_documented_shape():
    sessions = {s.session_id: s for s in atbench.load_path(ATBENCH_FILE)}
    assert sessions["ADAPTER-FIXTURE-ATB-0001"].is_attack is False
    assert sessions["ADAPTER-FIXTURE-ATB-0002"].is_attack is True


def test_atbench_task_clustering_is_degenerate_by_construction():
    """ATBench documents no pairing, so a task IS a session here.

    Recorded as a test rather than a comment because it is the reason a
    task-level bootstrap over ATBench buys none of R-15's correction, and the
    runner's report depends on detecting it.
    """
    for session in atbench.load_path(ATBENCH_FILE):
        assert session.task_clustering_is_degenerate


def test_atbench_refuses_an_unreadable_safety_label():
    with pytest.raises(AdapterError, match="neither safe nor unsafe"):
        atbench.adapt_trajectory({
            "id": "x", "label": "probably fine",
            "trajectory": [{"tool_name": "ls"}]})


def test_atbench_missing_field_reports_the_keys_it_actually_saw():
    """The field names are unverified, so the error has to be actionable."""
    with pytest.raises(AdapterError) as exc:
        atbench.adapt_trajectory({"id": "x", "label": "safe",
                                  "unexpected_key": []})
    message = str(exc.value)
    assert "unexpected_key" in message
    assert "FIELD_MAP" in message


def test_atbench_missing_file_states_there_is_no_licence():
    with pytest.raises(AdapterError) as exc:
        atbench.load_path(ATBENCH_FILE.parent / "nope.jsonl")
    assert "NO LICENCE" in str(exc.value)


# ---------------------------------------------------------------------------
# 2. Absent, never weaker
# ---------------------------------------------------------------------------


def _first_attack(*, mark_untrusted: bool = False):
    """The rogue fixture, which is the one carrying a consequential call."""
    return next(s for s in stepshield.load_directory(
        STEPSHIELD_DIR, mark_untrusted_from_labels=mark_untrusted)
        if s.is_attack)


def _all_adapted():
    return (stepshield.load_directory(STEPSHIELD_DIR)
            + atbench.load_path(ATBENCH_FILE))


def test_no_adapted_session_carries_fabricated_evidence():
    """The doctrine, asserted over every field of every adapted event.

    THE MUTATION THIS TEST EXISTS TO CATCH: make either adapter emit
    ``reversible=True`` on its tool_start events -- the most tempting "harmless"
    default, since neither corpus classifies its actions. Verified by actually
    applying it: two of the four fixture calls flip from ``unknown`` to
    ``read_only``, which removes the TOOL_CLASS_UNKNOWN penalty and inflates the
    reported confidence of every check that reads tool class. This test fails on
    it independently of the adapters' own runtime guard.
    """
    for session in _all_adapted():
        for event in session.events:
            for key in event.get("data", {}):
                assert key not in FABRICABLE_FIELDS, (
                    f"{session.session_id} emitted {key!r}, which forges the "
                    f"{FABRICABLE_FIELDS[key]!r} surface. Absent, never weaker.")


def test_reversible_default_would_be_caught():
    """Prove the guard actually fires, rather than trusting that it would."""
    event = cim_event("s", 1.0, "tool_start", tool="send_email",
                      reversible=True)
    with pytest.raises(FabricatedEvidenceError, match="tool_class"):
        assert_no_fabricated_evidence([event], "mutation")


def test_negative_scanner_claim_would_be_caught():
    """The subtlest fabrication of the three, so it gets its own test.

    ``has_injection_patterns: false`` is a REAL answer to Cohaera -- it means "a
    scanner ran and found nothing", which is why ``scanner_reported`` returns
    True for it. An adapter writing it for a corpus that never ran a scanner
    buys CH03 coverage with an answer nobody gave.
    """
    assert scanner_reported({"has_injection_patterns": False}) is True

    event = cim_event("s", 1.0, "tool_end", tool="read_file",
                      has_injection_patterns=False)
    with pytest.raises(FabricatedEvidenceError, match="injection_scanner"):
        assert_no_fabricated_evidence([event], "mutation")


def test_policy_event_would_be_caught():
    event = cim_event("s", 1.0, "policy_check", tool="send_email")
    with pytest.raises(FabricatedEvidenceError, match="policy or approval"):
        assert_no_fabricated_evidence([event], "mutation")


def test_the_sourced_allowance_is_narrow():
    """Naming one surface as sourced must not unlock the others.

    The opt-in scanner path is the only legitimate use of ``sourced``. If
    passing it also permitted a receipt or a reversibility default, the
    allowance would be a hole rather than a door.
    """
    scanner = cim_event("s", 1.0, "skill_invocation", tool="read_file",
                        injection_patterns=["x"], has_injection_patterns=True)
    # Permitted, because the adapter declared a source for exactly this.
    assert_no_fabricated_evidence(
        [scanner], "opt-in", sourced=frozenset({SURFACE_INJECTION_SCANNER}))

    # Not permitted by the same allowance.
    receipt = cim_event("s", 1.0, "tool_end", tool="send_email",
                        effect_receipt={"scheme": "x"})
    with pytest.raises(FabricatedEvidenceError, match="effect_receipt"):
        assert_no_fabricated_evidence(
            [receipt], "opt-in", sourced=frozenset({SURFACE_INJECTION_SCANNER}))


def test_absences_are_declared_not_merely_missing():
    """A silent gap and a declared gap are different objects."""
    for session in _all_adapted():
        surfaces = session.absences.surfaces
        assert scope.ABSENT_FROM_ALL_PUBLIC_CORPORA <= surfaces, (
            f"{session.session_id} does not declare every absent surface")
        for entry in session.absences.entries:
            assert entry.reason.strip(), "an absence without a reason is a shrug"


def test_untrusted_marking_is_off_by_default():
    """CH03's partial path must be opt-in, or the run is silently label-fed."""
    assert SURFACE_INJECTION_SCANNER in _first_attack().absences.surfaces

    opted_in = _first_attack(mark_untrusted=True)
    assert SURFACE_INJECTION_SCANNER not in opted_in.absences.surfaces


# ---------------------------------------------------------------------------
# 3. The scope statement
# ---------------------------------------------------------------------------


def test_scope_covers_every_check_family_exactly_once():
    families = set(CHECK_FAMILIES.values())
    assert {e.check for e in scope.SCOPE} == families
    assert len(scope.SCOPE) == len({e.check for e in scope.SCOPE})
    # The seven-check claim the documentation makes.
    assert len(families) == 7
    assert set(CHECK_FAMILIES) >= set(ALL_CHECKS)


def test_scope_partition_is_three_one_three():
    assert len(scope.EXTERNALLY_VALIDATABLE) == 3
    assert len(scope.PARTIALLY_VALIDATABLE) == 1
    assert len(scope.NOT_EXTERNALLY_VALIDATABLE) == 3
    assert scope.EXTERNALLY_VALIDATABLE == {
        scope.CH01, scope.CH02, scope.CH05}


def test_scope_matches_what_an_adapted_session_actually_supplies():
    """THE ANTI-ROT TEST.

    Derives the answer from the engine rather than from the table: run
    ``coverage`` over a real adapted session and confirm that every surface the
    scope statement names as blocking is genuinely unavailable, and that no
    check called externally validatable is blocked by a surface the corpus
    cannot supply.

    If somebody adds an approval surface to an adapter, or the engine changes
    which surfaces a check requires, this fails and the document gets fixed.
    """
    session = build_session(_first_attack())

    # The evidence really is absent from the assembled session. This is the
    # ground truth the scope statement rests on -- not what the contracts say
    # about it, which is a separate question tested below.
    assert session.policy_events == []
    assert len(session.approvals) == 0
    # Verification RAN over the stream and found no record carrying an integrity
    # sidecar -- which is the honest shape. `integrity is None` would mean no
    # verification was attempted, a different and weaker statement.
    assert session.integrity is not None
    assert session.integrity.with_integrity == 0
    assert not any(call.receipt for call in session.tool_calls)

    contracts = {c["check"]: c for c in coverage(session, None)["checks"]}

    for entry in scope.SCOPE:
        contract = contracts[entry.check]
        missing = set(contract["missing_surfaces"])
        if entry.status == scope.VALIDATABLE:
            # A validatable check may still be missing its FITTED baseline --
            # CH01's grammar is fitted from the corpus, not carried in it.
            assert not (missing - scope.FITTED_SURFACES), (
                f"{entry.check} is claimed externally validatable but the "
                f"contract reports {missing} missing on an adapted session.")


def test_the_three_unvalidatable_checks_lack_their_evidence_surfaces():
    """Named individually, because the claim is about these three specifically.

    The positioning leans hardest on CH04 and CH06, so "three of seven" is not
    interchangeable with "some of them".
    """
    assert scope.NOT_EXTERNALLY_VALIDATABLE == {
        "CH04_guardrail_overrun",
        "CH06_evidence_integrity",
        "CH07_effect_contradiction",
    }
    blocking = {s for e in scope.SCOPE for s in e.blocking_surfaces
                if e.status == scope.NOT_VALIDATABLE}
    assert blocking == {SURFACE_POLICY_SEMANTICS, SURFACE_APPROVAL,
                        SURFACE_EVENT_INTEGRITY, SURFACE_EFFECT_RECEIPT}


def test_ch04_now_charges_for_absent_guardrail_evidence():
    """The engine finding this branch surfaced, now asserted from the other side.

    This test used to pin a defect. On a session with a consequential call and
    no policy events at all, CH04's coverage contract listed neither
    ``policy_semantics`` nor ``approval_binding`` among its required surfaces
    and therefore reported nothing missing -- the required list was gated on
    whether the session ALREADY HAD policy events, so the one state that cost
    CH04 nothing was the state where no guardrail evidence existed whatsoever,
    which is the state every public corpus is in.

    It was deliberately worded so that fixing the engine would break it. The
    engine was fixed on claude/cohaera-ch04-coverage, this broke, and the
    instruction it carried was followed: the assertion was not reversed to
    keep it passing, it was rewritten to assert the corrected behaviour and
    this page's section 3 was rewritten with it.

    CH04 now behaves like CH06 and CH07 on evidence it does not have: it
    declines, at zero confidence, naming both absent surfaces.
    """
    session = build_session(_first_attack())
    assert any(call.consequential for call in session.tool_calls), (
        "the fixture must contain a consequential call for this to mean "
        "anything")
    assert session.policy_events == []

    ch04 = {c["check"]: c for c in coverage(session, None)["checks"]}[
        "CH04_guardrail_overrun"]

    assert SURFACE_POLICY_SEMANTICS in ch04["required_surfaces"]
    assert SURFACE_APPROVAL in ch04["required_surfaces"]
    assert sorted(ch04["missing_surfaces"]) == sorted(
        [SURFACE_APPROVAL, SURFACE_POLICY_SEMANTICS])
    assert ch04["status"] == "not_evaluated"
    assert ch04["confidence"] == 0.0
    assert R_NO_POLICY_EVIDENCE in ch04["reasons"]


def test_the_runner_no_longer_flags_the_ch04_gap():
    """The audit going quiet is the result, and it has to be asserted.

    While the defect stood, this asserted that the runner surfaced CH04 as a
    check consuming evidence it never charged itself for. With the contract
    corrected there is nothing left to surface, and an audit that stays silent
    is only trustworthy if something fails when it should have spoken --
    test_ch04_now_charges_for_absent_guardrail_evidence is that something.
    """
    sessions = stepshield.load_directory(STEPSHIELD_DIR)
    result = run(sessions, "stepshield")

    flags = result["scope_audit"]["flags"]
    assert not any("CH04_guardrail_overrun" in f for f in flags), (
        f"the CH04 gap is closed but the runner still flags it: {flags}")

    row = result["scope_audit"]["per_check"]["CH04_guardrail_overrun"]
    assert row["unreported_missing_surfaces"] == []

    # And it declines for the stated reason rather than going quiet by
    # accident, which is the distinction this whole directory is about.
    report = result["coverage"]["CH04_guardrail_overrun"]
    assert report["declined_pct"] == 100.0
    assert SURFACE_POLICY_SEMANTICS in report["missing_surfaces"]


def test_ch06_and_ch07_do_decline_and_say_why():
    """The two that behave correctly, so the CH04 finding is not mistaken for
    a blanket claim that coverage is broken."""
    sessions = stepshield.load_directory(STEPSHIELD_DIR)
    result = run(sessions, "stepshield")
    report = result["coverage"]

    assert report["CH06_evidence_integrity"]["declined_pct"] == 100.0
    assert SURFACE_EVENT_INTEGRITY in report[
        "CH06_evidence_integrity"]["missing_surfaces"]

    assert report["CH07_effect_contradiction"]["declined_pct"] == 100.0
    assert SURFACE_EFFECT_RECEIPT in report[
        "CH07_effect_contradiction"]["missing_surfaces"]


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


def test_headline_is_normalised_on_benign_sessions():
    """§5 of the evaluation card: the prevalence-free unit is the benign one."""
    result = run(stepshield.load_directory(STEPSHIELD_DIR), "stepshield")
    head = result["headline"]
    assert "false_positives_per_1000_benign_sessions" in head
    assert "false_positives_per_1000_sessions" in head
    assert "benign-normalised" in head["note"]


def test_target_precision_is_reported_unavailable_not_zero():
    result = run(stepshield.load_directory(STEPSHIELD_DIR), "stepshield")
    assert result["target_precision_available"] is False
    assert "UNAVAILABLE" in result["target_precision_note"]


def test_summary_carries_both_wilson_and_task_bootstrap():
    """Reusing eval.metrics rather than inventing a second approach."""
    result = run(stepshield.load_directory(STEPSHIELD_DIR), "stepshield")
    stats = result["summary"]
    assert "ci95_low" in stats["false_positive_rate"]
    cluster = stats["cluster_aware"]["false_positive_rate"]
    assert "task_bootstrap_ci95" in cluster
    assert "family_bootstrap_ci95" in cluster


def test_split_is_task_disjoint():
    sessions = stepshield.load_directory(STEPSHIELD_DIR)
    train, test = split_tasks(sessions)
    assert train and test
    assert not ({s.task_id for s in train} & {s.task_id for s in test})


def test_split_refuses_a_single_task_corpus():
    sessions = [s for s in stepshield.load_directory(STEPSHIELD_DIR)
                if s.task_id == "ADAPTER-FIXTURE-INV-001"]
    with pytest.raises(AdapterError, match="at least two"):
        split_tasks(sessions)


def test_coverage_report_counts_every_check_family():
    sessions = stepshield.load_directory(STEPSHIELD_DIR)
    _, test = split_tasks(sessions)
    coverages = [run_all(build_session(s), None)[1] for s in test]
    report = coverage_report(coverages)
    assert set(report) == set(CHECK_FAMILIES.values())
    for row in report.values():
        assert row["evaluated"] + row["degraded"] + row["declined"] == row[
            "sessions"]


def test_scope_audit_is_clean_when_evidence_is_charged_for():
    """A control: the audit must not flag indiscriminately.

    Built by hand rather than adapted, because the point is to show the audit
    goes quiet when a contract DOES name its missing surfaces.
    """
    fake = {
        "CH04_guardrail_overrun": {
            "sessions": 1, "evaluated": 0, "degraded": 0, "declined": 1,
            "declined_pct": 100.0, "mean_confidence": 0.0, "reason_codes": {},
            "missing_surfaces": {SURFACE_POLICY_SEMANTICS: 1,
                                 SURFACE_APPROVAL: 1},
        },
    }
    audit = scope_audit(fake)
    assert audit["flags"] == []


# ---------------------------------------------------------------------------
# The corpus probe, and the run it produced
# ---------------------------------------------------------------------------


def test_corpus_probe_pairs_rogue_with_clean_and_counts_identical_sequences():
    """The probe must find the pair and compare its sequences.

    Run against the adapter fixtures, which ship exactly one complete
    ``-ROGUE`` / ``-CLEAN`` pair. The assertion that matters is not the count
    but that a pair was FORMED: a probe that silently found zero pairs would
    divide by zero on the real corpus, and one that found one file twice would
    report every pair identical to itself.
    """
    result = probe_stepshield_train(
        Path(__file__).resolve().parents[1]
        / "eval" / "external" / "fixtures" / "stepshield")

    assert result["pairs"] == 1
    assert result["identical_sequence_pairs"] <= result["pairs"]
    assert result["same_length_pairs"] <= result["pairs"]
    assert result["distinct_actions"] >= 1


def test_corpus_probe_refuses_a_directory_with_no_pairs(tmp_path):
    """No pairs is an error, not an empty result.

    A zero-pair run would otherwise report 0 identical of 0 total, which reads
    as "nothing indistinguishable" -- the reassuring answer -- when it actually
    means the probe was pointed at the wrong directory.
    """
    (tmp_path / "SOMETHING-ELSE.jsonl").write_text('{"steps": []}')
    with pytest.raises(SystemExit):
        probe_stepshield_train(tmp_path)


def test_the_published_external_run_reached_no_check_on_any_session():
    """Pin the finding the results page is built on.

    ``docs/EXTERNAL-RESULTS.md`` states that no check reached ``evaluated`` on a
    single session. That is the claim making a zero interpretable, so it is
    asserted against the committed artefacts rather than left to prose. If a
    future engine change makes a check evaluable on this data, this test fails
    and the page must be rewritten -- which is the intended behaviour, because
    the page would then be wrong.
    """
    run_dir = (Path(__file__).resolve().parents[1]
               / "eval" / "external" / "runs" / "stepshield-2026-08-20")
    artefacts = sorted(p for p in run_dir.glob("*.json")
                       if p.name != "corpus-probe.json")
    assert len(artefacts) == 4, "expected four scored splits"

    for path in artefacts:
        result = json.loads(path.read_text(encoding="utf-8"))
        for name, row in result["coverage"].items():
            assert row["evaluated"] == 0, (
                f"{path.name}: {name} reached 'evaluated' on "
                f"{row['evaluated']} sessions; EXTERNAL-RESULTS.md says none did")
        assert result["summary"]["any_alert_recall"]["numerator"] == 0, (
            f"{path.name}: a detection was recorded; the page reports zero")
