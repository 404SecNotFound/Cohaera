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

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "demo" / "phantom-guardrail"
REPLAY = REPO / "demo" / "approval-replay"

sys.path.insert(0, str(REPO / "src"))


from cohaera.capabilities import EMPTY_MANIFEST, CapabilityManifest  # noqa: E402
from cohaera.checks import ch04_guardrail_overrun, run_all  # noqa: E402
from cohaera.evidence import Approval  # noqa: E402
from cohaera.ingest import assemble  # noqa: E402
from cohaera.model import Event  # noqa: E402

CITED = "CH04_undeclared_control_cited"


def _load(name: str, path):
    """Load a demo's scenario module by PATH, never by name.

    Both demos ship a file called `scenario.py`. Importing by name loads
    whichever directory happened to win on sys.path, which silently made the
    phantom-guardrail tests read the approval-replay fixture. Same collision
    class as the `_evasion_rows` one in tools/readme_facts.py, and the reason
    this loader is explicit.
    """
    spec = importlib.util.spec_from_file_location(name, path / "scenario.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _phantom():
    return _load("phantom_scenario", DEMO)


def _replay():
    return _load("replay_scenario", REPLAY)




def _events() -> list[Event]:
    return [Event(raw=json.loads(line))
            for line in _phantom().session_lines()]


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
    findings, _ = _score(CapabilityManifest.from_obj(_phantom().MANIFEST))
    cited = next((f for f in findings if f.check == CITED), None)
    assert cited is not None, [f.check for f in findings]
    assert cited.evidence["undeclared_controls"] == [_phantom().PHANTOM]
    assert cited.evidence["declared_controls"] == [
        "case-closure-guard", "evidence-export-guard"]


def test_the_two_runs_score_identical_telemetry():
    """The finding must come from the comparison, never from the evidence.

    Asserted on the digest of the records themselves rather than by reading
    run.py, because a demo that quietly swapped fixtures between runs would
    still look right in the source."""
    before = [json.dumps(e.raw, sort_keys=True) for e in _events()]
    _score(EMPTY_MANIFEST)
    _score(CapabilityManifest.from_obj(_phantom().MANIFEST))
    after = [json.dumps(e.raw, sort_keys=True) for e in _events()]
    assert before == after


def test_the_committed_telemetry_matches_the_generator():
    """The .jsonl is committed so a reader can inspect it without running
    anything. Committed artefacts go stale; this is the gate that says so."""
    on_disk = (DEMO / "telemetry.jsonl").read_text(encoding="utf-8")
    assert on_disk == "".join(_phantom().session_lines())


def test_the_demo_runs_end_to_end_and_says_what_it_claims():
    proc = subprocess.run([sys.executable, str(DEMO / "run.py")],
                          capture_output=True, text=True, timeout=120,
                          check=False)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    for phrase in ("THE PHANTOM GUARDRAIL", _phantom().PHANTOM, CITED,
                   "NO_CAPABILITY_MANIFEST"):
        assert phrase in out, f"the demo no longer prints {phrase!r}"


# ---------------------------------------------------------------------------
# demo/approval-replay -- the demo whose punchline is a WEAKNESS.
#
# Acts 3 and 4 assert that Cohaera does NOT catch something. That is the
# opposite of a normal test and it is deliberate: E26 is an open evasion, and
# a demo claiming otherwise would be a lie told to an audience. These fail the
# day approvals gain a signature, a window or a nonce -- which is exactly when
# the demo's script needs rewriting.
# ---------------------------------------------------------------------------


def _replay_sessions():
    mod = _replay()
    manifest = CapabilityManifest.from_obj(mod.MANIFEST)
    events = [Event(raw=json.loads(line)) for line in mod.session_lines()]
    return mod, {s.session_id: s for s in assemble(events, manifest=manifest)}


def test_replay_act1_an_approved_transfer_produces_no_finding():
    """The control working. If this ever fires, the demo opens on a false
    positive and every act after it is unreadable."""
    _, s = _replay_sessions()
    session = s["pay-01"]
    assert all(session.covering_approval(c) is not None
               for c in session.consequential_calls)
    assert ch04_guardrail_overrun(session) == []


def test_replay_act2_a_verbatim_approval_is_refused():
    """EVASION.md E26b, the unplanned win. The approval names span AP1 and the
    second call is AP2, so it does not cover it."""
    _, s = _replay_sessions()
    session = s["pay-02"]
    covered = [session.covering_approval(c) is not None
               for c in session.consequential_calls]
    assert covered == [True, False], covered
    assert [f.check for f in ch04_guardrail_overrun(session)] == [
        "CH04_blocking_control_bypassed"]


def test_replay_act3_one_rewritten_field_defeats_it():
    """ASSERTS A WEAKNESS. Rewriting subject.span_id makes the approval cover
    a call it was never issued for, because nothing signs the approval body."""
    _, s = _replay_sessions()
    session = s["pay-03"]
    assert all(session.covering_approval(c) is not None
               for c in session.consequential_calls)
    assert ch04_guardrail_overrun(session) == [], (
        "E26 act 3 no longer evades -- the demo script is now wrong")


def test_replay_act4_the_approval_still_works_a_month_later():
    """ASSERTS A WEAKNESS. No per-approval ledger and no mandatory window."""
    _, s = _replay_sessions()
    session = s["pay-04"]
    assert all(session.covering_approval(c) is not None
               for c in session.consequential_calls)
    assert ch04_guardrail_overrun(session) == [], (
        "E26 act 4 no longer evades -- the demo script is now wrong")


def test_replay_the_fixture_declares_no_window_and_no_signature():
    """The demo's claim is that the approval carries neither. Asserted on the
    fixture rather than trusted from the prose, because a fixture that quietly
    gained an expiry would make acts 3 and 4 prove something else."""
    mod = _replay()
    appr = mod.approval("AP1")
    for absent in ("granted_at", "expires_at", "nonce", "signature"):
        assert absent not in appr, f"the fixture now carries {absent!r}"
    assert "nonce" not in Approval.__dataclass_fields__, (
        "Approval gained a nonce -- E26 is being closed and this demo needs "
        "rewriting, not patching")


def test_the_replay_demo_runs_end_to_end():
    proc = subprocess.run([sys.executable, str(REPLAY / "run.py")],
                          capture_output=True, text=True, timeout=120,
                          check=False)
    assert proc.returncode == 0, proc.stderr
    for phrase in ("THE APPROVAL THAT NEVER EXPIRES", "REFUSED",
                   "ONE FIELD REWRITTEN", "CH04_blocking_control_bypassed"):
        assert phrase in proc.stdout, f"the demo no longer prints {phrase!r}"


def test_the_committed_replay_telemetry_matches_its_generator():
    mod = _replay()
    on_disk = (REPLAY / "telemetry.jsonl").read_text(encoding="utf-8")
    assert on_disk == "".join(mod.session_lines())
