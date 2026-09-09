"""The cohaera_notice record: the alert stream, kept apart from the facts.

A notice is one finding, emitted as its own record type with its own schema and
its own routing field (notice_grade). These tests hold the split in place: the
grade is derived from the measured checks, it is NOT severity, and a router that
pages only on alert-grade notices sees the deterministic checks and none of the
behavioural noise.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from cohaera.checks import (  # noqa: E402
    ALERT_GRADE_CHECKS,
    NOTICE_SCHEMA,
    notice_grade,
    run_all,
    to_notice_events,
)
from cohaera.ingest import load  # noqa: E402
from cohaera.model import to_cim_event  # noqa: E402

EVIDENCE_FAILURE = "lab/local/runs/latest/inputs/03-evidence-failure.jsonl"
CONTRADICTION = "lab/local/runs/latest/inputs/04-contradiction.jsonl"
SUSPECT = "tests/fixtures/suspect.jsonl"


def _notices(path: str):
    """Every notice across every session in a fixture, with its verdict."""
    out = []
    for s in load(str(REPO / path)):
        findings, cov = run_all(s)
        prov = {"analysis_run_id": "run-1", "detector_version": "0.3.0"}
        verdict = to_cim_event(s, findings, coverage=cov, provenance=prov)
        out.append((s, findings, cov, verdict,
                    to_notice_events(s, findings, coverage=cov, provenance=prov,
                                     verdict_id=verdict["verdict_id"])))
    return out


def _make_fixtures():
    # suspect/benign are generated, not committed; build them if absent.
    if not (REPO / SUSPECT).exists():
        subprocess.run([sys.executable, str(REPO / "tests" / "make_fixtures.py")],
                       cwd=REPO, check=True)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

def test_one_notice_per_finding():
    _make_fixtures()
    for _s, findings, _cov, _v, notices in _notices(SUSPECT):
        assert len(notices) == len(findings)
        for n in notices:
            assert n["type"] == "cohaera_notice"
            assert n["schema"] == NOTICE_SCHEMA


def test_notices_join_to_their_verdict():
    _make_fixtures()
    for _s, _f, _cov, verdict, notices in _notices(SUSPECT):
        for n in notices:
            assert n["verdict_id"] == verdict["verdict_id"]
            assert n["data"]["provenance"]["analysis_run_id"] == "run-1"


# ---------------------------------------------------------------------------
# The grade is the split
# ---------------------------------------------------------------------------

def test_notice_grade_function_matches_the_measured_set():
    for c in ALERT_GRADE_CHECKS:
        assert notice_grade(c) == "alert"
    for c in ["CH01_sequence_order", "CH02_concealment_gap",
              "CH03_untrusted_to_completed_action", "CH05_unpaired_calls",
              "CH04_guardrail_bypass_completed",
              "CH07_effect_receipt_does_not_bind"]:
        assert notice_grade(c) == "hunt"


def test_evidence_integrity_is_an_alert_grade_notice():
    grades = {n["data"]["check"]: n["data"]["notice_grade"]
              for _s, _f, _c, _v, ns in _notices(EVIDENCE_FAILURE) for n in ns}
    assert grades.get("CH06_evidence_integrity") == "alert"


def test_effect_contradiction_is_an_alert_grade_notice():
    grades = {n["data"]["check"]: n["data"]["notice_grade"]
              for _s, _f, _c, _v, ns in _notices(CONTRADICTION) for n in ns}
    assert grades.get("CH07_reported_failure_with_effect_receipt") == "alert"


def test_behavioural_checks_are_hunt_grade():
    _make_fixtures()
    seen = {n["data"]["check"]: n["data"]["notice_grade"]
            for _s, _f, _c, _v, ns in _notices(SUSPECT) for n in ns}
    for c in ["CH01_sequence_order", "CH02_concealment_gap",
              "CH05_unpaired_calls"]:
        if c in seen:
            assert seen[c] == "hunt", f"{c} must not be alert-grade"


def test_grade_is_not_severity():
    """The load-bearing decoupling: a hunt-grade notice can be critical.

    Severity says how bad if real; grade says whether it is trusted to page.
    """
    _make_fixtures()
    crit_hunt = [n for _s, _f, _c, _v, ns in _notices(SUSPECT) for n in ns
                 if n["data"]["severity"] == "critical"
                 and n["data"]["notice_grade"] == "hunt"]
    assert crit_hunt, ("expected at least one critical-severity hunt-grade "
                       "notice; CH02 concealment is one")


def test_a_router_pages_only_on_alert_grade():
    """The whole point: page on grade, not severity. Over a session that trips
    both an alert-grade and a hunt-grade notice, the pager sees only the former.
    """
    _s, _f, _c, _v, notices = _notices(EVIDENCE_FAILURE)[0]
    paged = [n for n in notices if n["data"]["notice_grade"] == "alert"]
    hunted = [n for n in notices if n["data"]["notice_grade"] == "hunt"]
    assert {n["data"]["check"] for n in paged} == {"CH06_evidence_integrity"}
    assert hunted, "the behavioural findings still exist -- as hunt, not pages"
    # None of the 420-per-1000 behavioural checks reaches the pager.
    assert all(n["data"]["check"] != "CH02_concealment_gap" for n in paged)
