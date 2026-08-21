"""The demo has to keep demonstrating the thing it claims to demonstrate.

A demo is the one artefact in a repository that gets shown to people and
never gets run by anybody who would notice it had changed. This repository
already argues that a number nothing recomputes is already wrong; a
demonstration nothing re-runs is the same defect wearing a nicer jacket.

So the claims the demo makes in prose are asserted here:

  * with no manifest, Cohaera CANNOT say the cited control is fake, and the
    coverage contract says why;
  * with the manifest, it can, and does;
  * the telemetry is identical between the two runs.

The third is the load-bearing one. If the demo ever produced its finding by
changing the evidence rather than by changing what the evidence is compared
against, the whole story would be a trick.

Run: PYTHONPATH=src python3 -m pytest tests/test_demo.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "demo" / "phantom-guardrail"

sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(DEMO))

import scenario  # noqa: E402

from cohaera.capabilities import EMPTY_MANIFEST, CapabilityManifest  # noqa: E402
from cohaera.checks import run_all  # noqa: E402
from cohaera.ingest import assemble  # noqa: E402
from cohaera.model import Event  # noqa: E402

CITED = "CH04_undeclared_control_cited"


def _events() -> list[Event]:
    return [Event(raw=json.loads(line)) for line in scenario.session_lines()]


def _score(manifest):
    return run_all(assemble(_events(), manifest=manifest)[0])


def test_without_a_manifest_cohaera_cannot_call_the_control_fake():
    """The honest-blindness half. Silence here is not a miss -- it is Cohaera
    declining to answer a question nothing gave it the basis to answer, and
    the coverage contract naming the missing surface."""
    findings, cov = _score(EMPTY_MANIFEST)
    assert CITED not in [f.check for f in findings]
    ch04 = next(c for c in cov["checks"]
                if c["check"] == "CH04_guardrail_overrun")
    assert ch04["status"] != "evaluated"
    assert "NO_CAPABILITY_MANIFEST" in ch04["reasons"]
    assert "POLICY_ENFORCEMENT_DECLARED_IN_BAND" in ch04["reasons"], (
        "the demo's whole run-1 claim is that Cohaera took the control's "
        "semantics from the agent's own event and said so")


def test_with_the_manifest_the_phantom_control_is_named():
    findings, _ = _score(CapabilityManifest.from_obj(scenario.MANIFEST))
    cited = next((f for f in findings if f.check == CITED), None)
    assert cited is not None, [f.check for f in findings]
    assert cited.evidence["undeclared_controls"] == [scenario.PHANTOM]
    assert cited.evidence["declared_controls"] == [
        "case-closure-guard", "evidence-export-guard"]


def test_the_two_runs_score_identical_telemetry():
    """The finding must come from the comparison, never from the evidence.

    Asserted on the digest of the records themselves rather than by reading
    run.py, because a demo that quietly swapped fixtures between runs would
    still look right in the source."""
    before = [json.dumps(e.raw, sort_keys=True) for e in _events()]
    _score(EMPTY_MANIFEST)
    _score(CapabilityManifest.from_obj(scenario.MANIFEST))
    after = [json.dumps(e.raw, sort_keys=True) for e in _events()]
    assert before == after


def test_the_committed_telemetry_matches_the_generator():
    """The .jsonl is committed so a reader can inspect it without running
    anything. Committed artefacts go stale; this is the gate that says so."""
    on_disk = (DEMO / "telemetry.jsonl").read_text(encoding="utf-8")
    assert on_disk == "".join(scenario.session_lines())


def test_the_demo_runs_end_to_end_and_says_what_it_claims():
    proc = subprocess.run([sys.executable, str(DEMO / "run.py")],
                          capture_output=True, text=True, timeout=120,
                          check=False)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    for phrase in ("THE PHANTOM GUARDRAIL", scenario.PHANTOM, CITED,
                   "NO_CAPABILITY_MANIFEST"):
        assert phrase in out, f"the demo no longer prints {phrase!r}"
