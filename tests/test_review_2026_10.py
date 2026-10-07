# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Three defects from the October 2026 review, kept as regressions.

The review ran four read-only passes over the tree at a271c26 and reproduced,
with scripts rather than argument, three things the existing 1,172 tests did
not cover. Each is pinned here with the reproduction that found it, because a
defect somebody proved once is a defect somebody can reintroduce.

1. **The approval controls were parsed and never read.** `--seen-approvals`
   and `--require-signed-approvals` reached argparse and stopped there: nothing
   opened the ledger and nothing handed the flag to a `Session`, so the E26
   closure that README, OPERATOR-GUIDE and EVASION all described was
   unreachable from the command line. Scoring with and without both flags
   produced byte-identical output. Wiring them exposed a second fault the unit
   tests had been exercising one call at a time: every QUESTION about an
   approval spent its nonce, so CH04 asking "does this cover" and the verdict
   asking "which tier" read each other as a replay.

2. **One hostile record took the whole run down.** A 400-digit timestamp
   raised `OverflowError` from a validator whose contract is "never raises",
   and a JSON object where a string was expected raised `TypeError` from a
   frozenset membership test. Either killed the process with a traceback and
   nothing on stdout, four good sessions included. Both are the same class as
   BUG-01 and C-08, which EVASION.md lists as fixed.

3. **A forged record passed on a stream joined mid-way.** The signature covers
   the chain value a record DECLARES. On a mid-stream join the verifier adopted
   the record's `prev` as the head; with `prev` deleted there was no head, the
   body was never chained, and the signature over the untouched `chain` value
   verified. Edit the first record of any batch after the first, drop one
   field, and the session reported `attested` with no inadmissible code.

Run: PYTHONPATH=src python3 -m pytest tests/test_review_2026_10.py -v
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_approval_trust as approvals  # the E26 fixtures, reused not copied

from cohaera import ed25519, ingest
from cohaera.capabilities import CapabilityManifest
from cohaera.checks import ch04_guardrail_overrun, run_all
from cohaera.cli import EXIT_ERROR, EXIT_OK, EXIT_PARTIAL
from cohaera.cli import main as cli_main
from cohaera.evidence import (
    APPROVAL_AUTHENTICATED,
    APPROVAL_BOUND,
    APPROVAL_SCHEMA,
    APPROVAL_SINGLE_USE,
    INADMISSIBLE,
    R_CHAIN_BROKEN,
    R_CHAIN_UNANCHORED,
    R_JOINED_MIDSTREAM,
    R_SEQUENCE_GAP,
    TRUST_STORE_SCHEMA,
    Approval,
    ApprovalLedger,
    PolicySignature,
    PolicySignatureError,
    StreamLedger,
    StreamVerifier,
    TrustStore,
    enforcement_of,
)
from cohaera.identity import trust_config_digest
from cohaera.limits import DEFAULT_LIMITS, DEFECT_APPROVAL_TYPE, REJECT_RECORD_UNREADABLE
from cohaera.model import Event, json_safe, to_cim_event
from cohaera.validate import IngestReport, finite_number, timestamp
from tools.collector_sign import key_id_for, keys_document, sign_stream

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

SECRET = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUBLIC = ed25519.public_key(SECRET)
KEY_ID = key_id_for(PUBLIC)
KEYS = TrustStore.from_obj(keys_document(PUBLIC, KEY_ID))

HUGE = 10 ** 400     # admitted by _bounded_int (1024 digits), overflows float()

MANIFEST = {"tools": {"wire_transfer_send": {"effects": ["egress"],
                                             "reversible": False}},
            "policies": {"payments-guard": {"enforcement": "blocking"}}}


def _records(n: int, sid: str = "sess-1") -> list[dict]:
    return [{"event_type": "tool_start", "session_id": sid,
             "timestamp": 1000.0 + i, "span_id": f"sp-{i}",
             "tool_name": "alert_read", "data": {"action": "invoke_tool"}}
            for i in range(n)]


def _verify(records: list[dict], ledger: StreamLedger | None = None,
            run_id: str = "") -> StreamVerifier:
    v = StreamVerifier(keys=KEYS, ledger=ledger, run_id=run_id)
    for raw in records:
        e = Event(raw=raw, limits=DEFAULT_LIMITS)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    return v


def _write(tmp_path: Path, name: str, rows: list[dict]) -> Path:
    p = tmp_path / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return p


def _write_json(tmp_path: Path, name: str, obj: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _approval_events(sid: str, span: str, raw_approval: dict) -> list[dict]:
    """A blocking guardrail, an approval, and the consequential call it names."""
    base = approvals.BASE_T
    return [
        {"event_id": f"{sid}-0", "timestamp": base, "session_id": sid,
         "trace_id": sid, "event_type": "cost_threshold_exceeded",
         "agent_name": "payments-agent", "host": "h", "user": "u",
         "data": {"action": "policy_event", "policy_id": "payments-guard",
                  "enforcement": "blocking", "approval": raw_approval}},
        {"event_id": f"{sid}-1", "timestamp": base + 10, "session_id": sid,
         "trace_id": sid, "span_id": span, "event_type": "tool_start",
         "agent_name": "payments-agent", "tool_name": "wire_transfer_send",
         "host": "h", "user": "u",
         "data": {"tool_args": approvals.ARGS, "arg_digest": approvals.DIGEST,
                  "reversible": False}},
        {"event_id": f"{sid}-2", "timestamp": base + 11, "session_id": sid,
         "trace_id": sid, "span_id": span, "event_type": "tool_end",
         "agent_name": "payments-agent", "tool_name": "wire_transfer_send",
         "host": "h", "user": "u", "data": {"result": "success"}},
    ]


def _raw_approval(appr: Approval, span: str) -> dict:
    return {"scheme": APPROVAL_SCHEMA, "decision": "allow",
            "subject": {"span_id": span, "tool_id": "wire_transfer_send",
                        "arg_digest": approvals.DIGEST},
            "granted_by": "user:alice", "nonce": appr.nonce,
            "granted_at": appr.granted_at, "expires_at": appr.expires_at,
            "signature": {"key_id": approvals.KEY_ID,
                          "sig": approvals.b64(appr.signature)}}


def _genuine_events(sid: str = "ok") -> list[dict]:
    return _approval_events(sid, "AP1", _raw_approval(approvals._signed(), "AP1"))


def _replayed_events(sid: str = "e26") -> list[dict]:
    """The E26 attack: an approval signed for AP1, re-pointed at AP2."""
    return _approval_events(sid, "AP2", _raw_approval(approvals._signed(), "AP2"))


def _approval_store_file(tmp_path: Path, role: str = "approval") -> Path:
    return _write_json(tmp_path, "trust-store.json", {
        "scheme": TRUST_STORE_SCHEMA,
        "keys": {approvals.KEY_ID: {
            "roles": [role],
            "key": approvals.b64(ed25519.public_key(approvals.SEED))}}})


def _score(capsys, argv: list[str]) -> tuple[int, list[dict], str]:
    rc = cli_main(["score", *argv])
    captured = capsys.readouterr()
    rows = [json.loads(line) for line in captured.out.splitlines() if line.strip()]
    return rc, rows, captured.err


def _checks_fired(rows: list[dict]) -> set[str]:
    return {f["check"] for r in rows for f in r["data"]["findings"]}


# ===========================================================================
# 1. The approval controls now reach the session
# ===========================================================================

def test_the_flags_reach_the_session_through_load(tmp_path):
    """The whole defect: `load` never passed them on, so no Session had them."""
    p = _write(tmp_path, "t.jsonl", _replayed_events())
    ledger = ApprovalLedger(tmp_path / "seen.json")
    sessions = ingest.load(p, keys=approvals._store(), approval_ledger=ledger,
                           require_signed_approvals=True,
                           manifest=CapabilityManifest.from_obj(MANIFEST),
                           quiet=True)
    (s,) = sessions
    assert s.require_signed_approvals is True
    assert s.trust_store is not None
    assert s.approval_ledger is ledger
    assert [f.check for f in ch04_guardrail_overrun(s)] == [
        "CH04_blocking_control_bypassed"]


def test_cli_require_signed_approvals_refuses_the_replayed_approval(
        tmp_path, capsys):
    """Reproduced as the review did: before the fix this run exited 0 with no
    CH04 finding and no ledger file, identical to a run without the flags."""
    p = _write(tmp_path, "t.jsonl", _replayed_events())
    rc, rows, _ = _score(capsys, [
        str(p), "--tool-manifest", str(_write_json(tmp_path, "m.json", MANIFEST)),
        "--trust-store", str(_approval_store_file(tmp_path)),
        "--require-signed-approvals",
        "--seen-approvals", str(tmp_path / "seen.json")])
    assert rc == EXIT_OK
    assert "CH04_blocking_control_bypassed" in _checks_fired(rows)
    prov = rows[0]["data"]["provenance"]
    assert prov["require_signed_approvals"] is True
    assert prov["approval_ledger"]["enabled"] is True
    assert prov["approval_ledger"]["nonces_known"] == 0


def test_cli_a_genuine_approval_covers_once_and_is_a_replay_on_the_next_run(
        tmp_path, capsys):
    """E26 point 3, end to end. The same signed approval, scored twice against
    one ledger: the first run lets it cover, the second refuses it."""
    p = _write(tmp_path, "t.jsonl", _genuine_events())
    seen = tmp_path / "seen.json"
    argv = [str(p), "--tool-manifest",
            str(_write_json(tmp_path, "m.json", MANIFEST)),
            "--trust-store", str(_approval_store_file(tmp_path)),
            "--require-signed-approvals", "--seen-approvals", str(seen)]

    rc, rows, _ = _score(capsys, argv)
    assert rc == EXIT_OK
    assert "CH04_blocking_control_bypassed" not in _checks_fired(rows)
    assert seen.exists(), "a spent nonce must survive the run"
    assert "n-1" in json.loads(seen.read_text())["nonces"]
    assert rows[0]["data"]["provenance"]["approval_ledger"]["nonces_known"] == 0

    rc, rows, _ = _score(capsys, argv)
    assert rc == EXIT_OK
    assert "CH04_blocking_control_bypassed" in _checks_fired(rows)
    assert rows[0]["data"]["provenance"]["approval_ledger"]["nonces_known"] == 1


def test_cli_refuses_the_flag_when_no_key_may_issue_approvals(tmp_path, capsys):
    """With no approval-role key nothing can verify, so every approved action
    would read as a bypass. That is a misconfiguration, not a verdict."""
    p = _write(tmp_path, "t.jsonl", _genuine_events())
    rc, rows, err = _score(capsys, [
        str(p), "--trust-store", str(_approval_store_file(tmp_path, "collector")),
        "--require-signed-approvals"])
    assert rc == EXIT_ERROR
    assert rows == []
    assert "'approval' role" in err


def test_cli_a_refused_approval_is_named_not_erased(tmp_path, capsys):
    """Found by wiring the flags. An approval that fit the call and that
    nothing could vouch for fell through `_approval_state` to "no approval was
    presented" -- in precisely the run whose purpose was to say one was
    presented and was not good. The finding now names the state and the tier
    the approval reached, which is how an operator tells a ledger that worked
    from one that was never consulted."""
    seen = tmp_path / "seen.json"
    m = _write_json(tmp_path, "m.json", MANIFEST)
    store = _approval_store_file(tmp_path)

    # A rewritten span: the signature fails, so the tier stays at `bound`.
    p = _write(tmp_path, "replay.jsonl", _replayed_events())
    rc, rows, _ = _score(capsys, [str(p), "--tool-manifest", str(m),
                                  "--trust-store", str(store),
                                  "--require-signed-approvals"])
    assert rc == EXIT_OK
    (f,) = [f for r in rows for f in r["data"]["findings"]
            if f["check"] == "CH04_blocking_control_bypassed"]
    assert f["evidence"]["approval_states"] == ["approval_not_assured"]
    assert f["evidence"]["approval_assurance"] == [APPROVAL_BOUND]
    assert "nothing could vouch for it" in f["detail"]

    # A genuine approval whose nonce the ledger has already seen: it verified,
    # so it reached `authenticated`, and it did not cover.
    seen.write_text(json.dumps({"schema": "cohaera.approval_ledger:1",
                                "nonces": {"n-1": 0.0}}))
    p = _write(tmp_path, "spent.jsonl", _genuine_events())
    rc, rows, _ = _score(capsys, [str(p), "--tool-manifest", str(m),
                                  "--trust-store", str(store),
                                  "--require-signed-approvals",
                                  "--seen-approvals", str(seen)])
    assert rc == EXIT_OK
    (f,) = [f for r in rows for f in r["data"]["findings"]
            if f["check"] == "CH04_blocking_control_bypassed"]
    assert f["evidence"]["approval_states"] == ["approval_not_assured"]
    assert f["evidence"]["approval_assurance"] == [APPROVAL_AUTHENTICATED]


def test_asking_about_an_approval_does_not_spend_it(tmp_path):
    """Found by wiring the flags. `assured` and `approval_tier` each called
    `ledger.spend`, so CH04 evaluated twice on one session turned a genuine
    approval into a bypass finding the second time."""
    s = approvals.Session(
        session_id="ok", manifest=CapabilityManifest.from_obj(MANIFEST),
        events=[Event(raw=r) for r in _genuine_events()],
        trust_store=approvals._store(),
        approval_ledger=ApprovalLedger(tmp_path / "seen.json"),
        require_signed_approvals=True)
    assert ch04_guardrail_overrun(s) == []
    assert ch04_guardrail_overrun(s) == []
    assert s.approval_tier(s.approvals[0]) == APPROVAL_SINGLE_USE
    assert s.approval_tier(s.approvals[0]) == APPROVAL_SINGLE_USE
    assert s.approval_ledger.size == 1, "one approval, one nonce, spent once"


def test_a_match_carries_the_tier_the_deployment_reached():
    events = [Event(raw=r) for r in _genuine_events()]
    manifest = CapabilityManifest.from_obj(MANIFEST)
    with_store = approvals.Session(session_id="ok", manifest=manifest,
                                   events=events, trust_store=approvals._store())
    without = approvals.Session(session_id="ok", manifest=manifest, events=events)
    call = with_store.consequential_calls[0]
    assert with_store.approvals_for(call)[0].approval.tier == APPROVAL_AUTHENTICATED
    assert without.approvals_for(call)[0].approval.tier == APPROVAL_BOUND


def test_the_run_identity_is_unchanged_until_a_control_is_switched_on():
    """Every existing verdict keeps its analysis_run_id; a run that gates on
    signatures or consults a nonce ledger gets a different one."""
    before = trust_config_digest()
    assert trust_config_digest(approval_ledger={"enabled": False},
                               require_signed_approvals=False) == before
    assert trust_config_digest(require_signed_approvals=True) != before
    assert trust_config_digest(
        approval_ledger={"enabled": True, "nonces_known": 3}) != before
    assert (trust_config_digest(approval_ledger={"enabled": True, "nonces_known": 3})
            != trust_config_digest(approval_ledger={"enabled": True, "nonces_known": 4}))


# ===========================================================================
# 2. One hostile record never takes the run down
# ===========================================================================

def test_a_400_digit_integer_is_a_defect_not_an_overflow():
    ts, codes = timestamp(HUGE)
    assert ts != ts and codes, "NaN plus a reason, exactly as a bad string gets"
    assert finite_number(HUGE) == (None, ("NUMERIC_NONFINITE",)) or \
        finite_number(HUGE)[0] is None
    assert finite_number(-HUGE)[0] is None
    parsed, _ = Approval.parse({"scheme": APPROVAL_SCHEMA, "decision": "allow",
                                "subject": {"span_id": "S"},
                                "granted_at": HUGE, "expires_at": HUGE})
    assert parsed is not None and parsed.granted_at is None


def test_an_object_where_a_string_is_expected_is_flagged_not_raised():
    assert Approval.parse({"scheme": APPROVAL_SCHEMA, "decision": {},
                           "subject": {"span_id": "S"}}) == (None, (DEFECT_APPROVAL_TYPE,))
    parsed, codes = Approval.parse({"scheme": APPROVAL_SCHEMA, "decision": "allow",
                                    "subject": {"span_id": "S"},
                                    "enforcement": {}})
    assert parsed is not None and parsed.enforcement == "undeclared" and codes
    assert enforcement_of({"enforcement": {}})[0] == "undeclared"
    assert enforcement_of({"enforcement": ["blocking"]})[0] == "undeclared"
    with pytest.raises(PolicySignatureError):
        PolicySignature.from_obj({"scheme": "cohaera.policy_signature:1",
                                  "artifact": {}})


_HOSTILE = [{}, [], [{}], {"a": {}}, True, False, None, "", "x",
            0, -1, 1.5, HUGE, -HUGE, 1e308, "9" * 400]

_RICH = {
    "event_id": "r-1", "timestamp": 1000.0, "session_id": "rich", "trace_id": "rich",
    "span_id": "S1", "event_type": "cost_threshold_exceeded",
    "agent_name": "a", "host": "h", "user": "u", "framework": "f",
    "tool_name": "wire_transfer_send",
    "data": {
        "action": "policy_event", "policy_id": "payments-guard",
        "enforcement": "blocking", "result": "success", "reversible": False,
        "response_text": "done", "has_injection_patterns": False,
        "total_cost_usd": 1.0, "tool_args": {"a": 1}, "arg_digest": "x",
        "approval": {"scheme": APPROVAL_SCHEMA, "decision": "allow",
                     "subject": {"span_id": "S1", "tool_id": "wire_transfer_send",
                                 "arg_digest": "x"},
                     "granted_by": "u", "granted_at": 999.0, "expires_at": 2000.0,
                     "policy_id": "p", "policy_digest": "d", "enforcement": "blocking",
                     "nonce": "n", "signature": {"key_id": "k", "sig": "AA=="}},
        "effect_receipt": {"scheme": "cohaera.receipt:1", "provider": "smtp",
                           "effect_id": "m-1", "span_id": "S1", "status": "ok",
                           "assurance": "provider_returned", "scope": "message"},
    },
    "integrity": {"scheme": "cohaera.integrity:1", "stream_id": "s", "seq": 0,
                  "prev": "p", "chain": "c", "key_id": KEY_ID, "sig": "AA=="},
}


def _leaf_paths(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaf_paths(v, (*prefix, k))
    else:
        yield prefix


def _with(obj, path, value):
    out = copy.deepcopy(obj)
    cur = out
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return out


@pytest.mark.parametrize("path", list(_leaf_paths(_RICH)),
                         ids=lambda p: "/".join(map(str, p)))
def test_every_field_survives_every_type_substitution(tmp_path, path):
    """The sweep the review's fuzzer did by hand. One rich record with every
    sidecar, every leaf replaced by every hostile shape, the whole pipeline
    run to a serialised verdict. The backstop must not be what saves it: a
    reader that raised is a reader that was supposed to flag."""
    rows = [_with(_RICH, path, v) for v in _HOSTILE]
    p = _write(tmp_path, "sweep.jsonl", rows + _records(2, "clean"))
    report = IngestReport(source="sweep")
    sessions = ingest.load(p, keys=KEYS, report=report, quiet=True,
                           manifest=CapabilityManifest.from_obj(MANIFEST))
    assert not [r for r in report.rejects if r.code == REJECT_RECORD_UNREADABLE], \
        "a field reader raised instead of flagging"
    for i, s in enumerate(sessions):
        findings, cov = run_all(s, None)
        json.dumps(json_safe(to_cim_event(s, findings, coverage=cov,
                                          provenance={}, sequence=i)),
                   allow_nan=False, default=str)


def test_the_backstop_quarantines_a_record_whose_reader_raises(tmp_path, monkeypatch):
    """When "never raises" is wrong again, the outcome is one quarantined
    record naming the exception, and every other record is still scored."""
    class Trapped(Event):
        @property
        def defects(self):
            if self.raw.get("session_id") == "boom":
                raise RuntimeError("a reader that was supposed to flag")
            return super().defects
    monkeypatch.setattr(ingest, "Event", Trapped)
    p = _write(tmp_path, "t.jsonl", _records(2, "boom") + _records(3, "fine"))
    report = IngestReport(source="t")
    sessions = ingest.load(p, report=report, quiet=True)
    assert [s.session_id for s in sessions] == ["fine"]
    assert report.rejected == 2 and report.accepted == 3
    assert {r.code for r in report.rejects} == {REJECT_RECORD_UNREADABLE}
    assert "RuntimeError" in report.rejects[0].detail


def test_cli_one_hostile_record_does_not_take_the_run_down(tmp_path, capsys):
    """Reproduced as reported: exit 1, a traceback on stderr, nothing on stdout."""
    bad_clock = dict(_records(1, "bad-clock")[0], timestamp=HUGE)
    bad_enforcement = dict(_records(1, "bad-policy")[0],
                           event_type="cost_threshold_exceeded",
                           data={"action": "policy_event", "enforcement": {},
                                 "approval": {"scheme": APPROVAL_SCHEMA,
                                              "decision": {},
                                              "subject": {"span_id": "x"}}})
    p = _write(tmp_path, "t.jsonl", [bad_clock, bad_enforcement, *_records(4, "good")])
    rc, rows, err = _score(capsys, [str(p)])
    assert rc in (EXIT_OK, EXIT_PARTIAL)
    assert "Traceback" not in err
    assert "good" in {r["data"]["session_id"] for r in rows}


# ===========================================================================
# 3. A record with nothing to chain from is not attested
# ===========================================================================

def test_an_edited_join_record_with_prev_deleted_is_unanchored_and_inadmissible():
    """THE REPRODUCTION. Keep `prev` and the edit is a chain break; delete it
    and, before this fix, the session was attested with no inadmissible code."""
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    batch = copy.deepcopy(signed[5:])
    batch[0]["tool_name"] = "wire_transfer_send"

    kept = copy.deepcopy(batch)
    state = _verify(kept).for_session("sess-1")
    assert R_CHAIN_BROKEN in state.codes and not state.attested

    stripped = copy.deepcopy(batch)
    del stripped[0]["integrity"]["prev"]
    state = _verify(stripped).for_session("sess-1")
    assert R_CHAIN_UNANCHORED in state.codes
    assert R_CHAIN_UNANCHORED in INADMISSIBLE
    assert state.inadmissible == [R_CHAIN_UNANCHORED]
    assert not state.attested
    assert not state.sequence_verified("stream-a", 5), \
        "the forged record must not decide ordering for CH04 either"
    assert state.unanchored == [5]
    assert state.as_dict()["unanchored"] == [5]


def test_an_unedited_join_record_without_prev_is_unanchored_too():
    """The verifier cannot tell an edit from an omission -- that is the point.
    A record at seq > 0 that withholds `prev` makes a claim it will not let
    anyone check, and the honest answer is that nothing vouches for it."""
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    batch = copy.deepcopy(signed[5:])
    del batch[0]["integrity"]["prev"]
    state = _verify(batch).for_session("sess-1")
    assert R_CHAIN_UNANCHORED in state.codes
    assert R_JOINED_MIDSTREAM in state.codes


def test_a_join_that_declares_its_predecessor_is_still_only_declared():
    """What must not change: batched tailing is the ordinary case."""
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    state = _verify(copy.deepcopy(signed[5:])).for_session("sess-1")
    assert R_JOINED_MIDSTREAM in state.codes
    assert R_CHAIN_UNANCHORED not in state.codes
    assert not state.inadmissible and state.attested


def test_the_seed_record_needs_no_predecessor():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    del signed[0]["integrity"]["prev"]
    state = _verify(signed).for_session("sess-1")
    assert R_CHAIN_UNANCHORED not in state.codes and state.attested


def test_the_survivor_after_a_gap_is_unanchored_without_its_prev():
    """Same hole, reached through _force: the resync after a deletion also
    adopted the survivor's `prev`, and an absent one left no head."""
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    rows = copy.deepcopy(signed[:3] + signed[5:])
    rows[3]["tool_name"] = "wire_transfer_send"
    del rows[3]["integrity"]["prev"]
    state = _verify(rows).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert R_CHAIN_UNANCHORED in state.codes
    assert state.unanchored == [5]


def test_ch06_says_what_an_unanchored_record_is(tmp_path):
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    batch = copy.deepcopy(signed[5:])
    batch[0]["tool_name"] = "wire_transfer_send"
    del batch[0]["integrity"]["prev"]
    p = _write(tmp_path, "t.jsonl", batch)
    (s,) = ingest.load(p, keys=KEYS, quiet=True)
    findings, _cov = run_all(s, None)
    (ch06,) = [f for f in findings if f.check.startswith("CH06")]
    assert "declared no predecessor" in ch06.detail
    assert s.integrity is not None and s.integrity.unanchored == [5]


def test_the_ledger_refuses_to_remember_an_unanchored_stream(tmp_path):
    """Otherwise the forged batch would advance the ledger and the genuine
    records at those positions would read as a fork on the next run."""
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    batch = copy.deepcopy(signed[5:])
    del batch[0]["integrity"]["prev"]
    ledger = StreamLedger(path=tmp_path / "seen.json")
    v = _verify(batch, ledger=ledger, run_id="run-1")
    assert v.ledger_refusals and R_CHAIN_UNANCHORED in v.ledger_refusals[0]["reason"]
    assert "stream-a" not in ledger.streams
