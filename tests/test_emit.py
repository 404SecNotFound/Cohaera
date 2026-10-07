"""The producer side (``cohaera.emit``) emits what the verifier accepts.

Every test here has the verifier as its oracle. A signer is not tested by
inspecting the sidecar it wrote; it is tested by feeding the stream to
``StreamVerifier`` under a trust store and asking what the verdict says. The
reference producers in ``tools/`` are the second oracle: where this package
restates a rule the reference has (the key id, the assurance vocabulary, the
sidecar bytes), the two are asserted equal rather than assumed to be.

The boundary tests at the end are the ones that decide whether this package
may exist at all: nothing on the verifier side imports it.

Run: python -m pytest tests/test_emit.py -q
"""

from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera import ed25519
from cohaera.capabilities import CapabilityManifest
from cohaera.checks import (
    EVIDENCE_VERIFIED_COMPLETE,
    EVIDENCE_VERIFIED_PREFIX,
    ch04_guardrail_overrun,
    evidence_status,
)
from cohaera.emit import (
    ASSURANCE_LEVELS,
    ASSURANCE_OPERATION,
    PRIVATE_KEY_SCHEMA,
    SIGNER_STATE_SCHEMA,
    ApprovalIssuer,
    JsonlWriter,
    KeyPair,
    PrivateKeyError,
    SignerStateError,
    StreamSigner,
    add_key,
    binding,
    key_id_for,
    read_private_key,
    read_state,
    receipt,
    trust_store_document,
    trust_store_entry,
    write_private_key,
    write_state,
)
from cohaera.evidence import (
    APPROVAL_AUTHENTICATED,
    APPROVAL_BOUND,
    APPROVAL_SINGLE_USE,
    INADMISSIBLE,
    R_CHAIN_BROKEN,
    R_JOINED_MIDSTREAM,
    R_NO_STREAM_LEDGER,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REPLAY,
    R_STREAM_NOT_CLOSED,
    ROLE_APPROVAL,
    ROLE_COLLECTOR,
    TRUST_STORE_SCHEMA,
    Approval,
    ApprovalLedger,
    EffectReceipt,
    StreamVerifier,
    TrustStore,
    TrustStoreError,
    arg_digest,
    verify_approval,
)
from cohaera.ingest import assemble, read_events
from cohaera.model import Event, Session
from tools import collector_sign, policy_sign, receipt_adapters

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
SEED = bytes(range(32))
PAIR = KeyPair.from_seed(SEED)
STORE = TrustStore.from_obj(trust_store_document(
    {PAIR.key_id: PAIR.trust_store_entry(roles=[ROLE_COLLECTOR, ROLE_APPROVAL])}))
BASE_T = 1_785_740_000.0


def _records(n: int = 6, sid: str = "sess-1") -> list[dict]:
    return [{"event_type": "tool_start", "session_id": sid,
             "timestamp": 1000.0 + i, "span_id": f"sp-{i}",
             "tool_name": "alert_read", "data": {"action": "invoke_tool"}}
            for i in range(n)]


def _verify(signed: list[dict], store: TrustStore = STORE):
    """Feed one batch to a fresh verifier and return the session's audit."""
    v = StreamVerifier(keys=store)
    for raw in signed:
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    return v.for_session("sess-1")


def _status(signed: list[dict], store: TrustStore = STORE) -> str:
    sessions = assemble([Event(raw=r) for r in signed], keys=store)
    assert len(sessions) == 1
    return evidence_status(sessions[0])


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def test_the_key_id_rule_is_the_reference_signers_rule():
    """Restated because tools/ is outside the package; asserted so a change to
    either side fails here rather than in a trust store that names a key
    nobody's signer derives."""
    for _ in range(5):
        pair = KeyPair.generate()
        assert key_id_for(pair.public) == collector_sign.key_id_for(pair.public)
        assert key_id_for(pair.public) == policy_sign.key_id_for(pair.public)
        assert pair.key_id == key_id_for(pair.public)


def test_a_generated_key_signs_what_the_verifier_accepts():
    pair = KeyPair.generate()
    assert len(pair.seed) == 32 and pair.public == ed25519.public_key(pair.seed)
    assert ed25519.verify(pair.public, b"m", ed25519.sign(pair.seed, b"m"))
    assert KeyPair.generate().seed != pair.seed


def test_the_seed_never_appears_in_a_repr():
    assert SEED.hex() not in repr(PAIR)
    assert PAIR.key_id in repr(PAIR)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_private_key_file_is_0600_and_not_overwritten(tmp_path):
    path = write_private_key(tmp_path / "k.json", PAIR)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_private_key(path) == PAIR
    with pytest.raises(PrivateKeyError, match="already exists"):
        write_private_key(path, KeyPair.generate())
    assert read_private_key(path) == PAIR, "a refused overwrite must leave the file alone"
    other = KeyPair.generate()
    write_private_key(path, other, overwrite=True)
    assert read_private_key(path) == other
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_a_private_key_readable_by_others_is_refused(tmp_path):
    path = write_private_key(tmp_path / "k.json", PAIR)
    path.chmod(0o644)
    with pytest.raises(PrivateKeyError, match="readable by others"):
        read_private_key(path)
    assert read_private_key(path, check_mode=False) == PAIR


def test_a_key_file_whose_id_disagrees_with_its_seed_is_refused(tmp_path):
    path = tmp_path / "k.json"
    path.write_text(json.dumps({"scheme": PRIVATE_KEY_SCHEMA, "algorithm": "ed25519",
                                "key_id": "ed25519:0000000000000000",
                                "seed_hex": SEED.hex()}))
    path.chmod(0o600)
    with pytest.raises(PrivateKeyError, match="derives"):
        read_private_key(path)


@pytest.mark.parametrize("document", [
    "[]", '{"scheme": "other"}',
    json.dumps({"scheme": PRIVATE_KEY_SCHEMA, "seed_hex": "zz" * 32}),
    json.dumps({"scheme": PRIVATE_KEY_SCHEMA, "seed_hex": "00" * 31}),
    '{"scheme": "cohaera.private_key:1", "seed_hex": "00", "seed_hex": "11"}',
])
def test_a_malformed_key_file_is_refused(tmp_path, document):
    path = tmp_path / "k.json"
    path.write_text(document)
    path.chmod(0o600)
    with pytest.raises(PrivateKeyError):
        read_private_key(path)


def test_the_trust_store_entry_loads_under_the_verifier_with_what_was_said():
    doc = trust_store_document({PAIR.key_id: trust_store_entry(
        PAIR.public, roles=["collector"], not_before=10.0, not_after=20.0,
        replaces="ed25519:previous")})
    assert doc["scheme"] == TRUST_STORE_SCHEMA
    key = TrustStore.from_obj(doc).get(PAIR.key_id)
    assert key is not None and key.public == PAIR.public
    assert key.roles == frozenset({ROLE_COLLECTOR})
    assert (key.not_before, key.not_after, key.replaces) == (10.0, 20.0, "ed25519:previous")
    assert not key.revoked


def test_the_entry_matches_the_reference_tools_shape():
    assert trust_store_entry(PAIR.public, roles=["collector"]) == \
        collector_sign.keys_document(PAIR.public, PAIR.key_id)["keys"][PAIR.key_id]
    assert trust_store_entry(PAIR.public, roles=["policy", "approval"], revoked_at=5.0) == \
        policy_sign.store_document(PAIR.public, PAIR.key_id, ["approval", "policy"],
                                   revoked_at=5.0)["keys"][PAIR.key_id]


@pytest.mark.parametrize("kw", [
    {"roles": []}, {"roles": ["operator"]}, {"roles": ["collector", "root"]},
    {"roles": ["collector"], "not_before": 20.0, "not_after": 10.0},
    {"roles": ["collector"], "not_after": float("nan")},
    {"roles": ["collector"], "replaces": ""},
    {"roles": ["collector"], "replaces": "a\nb"},
])
def test_an_entry_the_verifier_would_refuse_is_refused_here(kw):
    with pytest.raises(ValueError):
        trust_store_entry(PAIR.public, **kw)


def test_a_role_passed_as_a_bare_string_is_one_role_not_nine():
    entry = trust_store_entry(PAIR.public, roles="collector")
    assert entry["roles"] == ["collector"]


def test_add_key_is_a_rotation_not_an_overwrite():
    old = trust_store_document({PAIR.key_id: PAIR.trust_store_entry(roles=["collector"])})
    new = KeyPair.generate()
    merged = add_key(old, new.key_id, new.trust_store_entry(
        roles=["collector"], replaces=PAIR.key_id))
    assert set(merged["keys"]) == {PAIR.key_id, new.key_id}
    assert set(old["keys"]) == {PAIR.key_id}, "the input document is not mutated"
    with pytest.raises(TrustStoreError, match="already in the store"):
        add_key(merged, PAIR.key_id, PAIR.trust_store_entry(roles=["policy"]))
    with pytest.raises(TrustStoreError, match="cannot carry roles"):
        add_key({"scheme": "cohaera.collector_keys:1", "keys": {}}, new.key_id,
                new.trust_store_entry(roles=["collector"]))


# ---------------------------------------------------------------------------
# StreamSigner: the core round trip
# ---------------------------------------------------------------------------


def test_records_signed_one_at_a_time_verify_complete_under_the_matching_store():
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    signed = [signer.sign(r) for r in _records(12)]
    state = _verify(signed)
    assert not state.inadmissible
    assert state.signatures_verified == 12
    assert state.attested
    assert R_JOINED_MIDSTREAM not in state.codes
    assert _status(signed) == EVIDENCE_VERIFIED_COMPLETE


def test_the_sidecar_is_exactly_what_the_reference_signer_emits():
    """Same records, same stream, same key: the incremental signer and the
    list signer must produce the same bytes, or one of them is wrong."""
    records = _records(7)
    reference = collector_sign.sign_stream(records, "stream-a", SEED, PAIR.key_id)
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    assert [signer.sign(r, attest=(i == 6)) for i, r in enumerate(records)] == reference

    reference = collector_sign.sign_stream(records, "stream-a", SEED, PAIR.key_id,
                                           sign_every=3)
    signer = StreamSigner("stream-a", SEED, PAIR.key_id, sign_every=3)
    assert [signer.sign(r, attest=(i == 6)) for i, r in enumerate(records)] == reference


def test_a_restart_from_state_continues_the_chain():
    """THE CORE TEST. Sign N records, persist state at k, resume, sign the rest.

    Fed as one stream the verifier must see nothing but a clean chain: no
    inadmissible code and no JOINED_MIDSTREAM, because the stream never
    actually restarted. Fed as two batches the second must report ONLY that it
    was joined mid-stream -- a fact about what the verifier saw, not about the
    chain -- and never a break or a gap.
    """
    records = _records(10)
    first = StreamSigner("stream-a", SEED, PAIR.key_id)
    head = [first.sign(r) for r in records[:4]]
    state = json.loads(json.dumps(first.state()))      # through JSON, as persisted
    second = StreamSigner.resume(state, SEED, key_id=PAIR.key_id)
    assert second.next_seq == 4 and second.head == first.head
    tail = [second.sign(r) for r in records[4:]]
    assert [r["integrity"]["seq"] for r in head + tail] == list(range(10))

    whole = _verify(head + tail)
    assert not whole.inadmissible
    assert R_JOINED_MIDSTREAM not in whole.codes
    assert whole.signatures_verified == 10
    assert _status(head + tail) == EVIDENCE_VERIFIED_COMPLETE

    batch_two = _verify(tail)
    assert not batch_two.inadmissible
    # NO_STREAM_LEDGER says this run kept no memory between runs. It is a
    # statement about the verifier's configuration, not about the chain, and
    # the whole-stream case above carries it too.
    # INTEGRITY_STREAM_NOT_CLOSED likewise: nothing closed this stream, and a
    # batch boundary is not a close (E30).
    assert set(batch_two.codes) - {R_NO_STREAM_LEDGER, R_STREAM_NOT_CLOSED} == {
        R_JOINED_MIDSTREAM}, batch_two.codes
    assert batch_two.signatures_verified == 6


def test_state_round_trips_through_the_file_helpers(tmp_path):
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    for r in _records(3):
        signer.sign(r)
    path = write_state(tmp_path / "state.json", signer.state())
    assert read_state(path) == signer.state()
    assert read_state(path)["scheme"] == SIGNER_STATE_SCHEMA
    assert not list(tmp_path.glob(".signer-state-*")), "no temp file left behind"
    resumed = StreamSigner.resume(read_state(path), SEED)
    assert (resumed.stream_id, resumed.key_id, resumed.next_seq, resumed.head) == \
        ("stream-a", PAIR.key_id, 3, signer.head)


def test_the_state_carries_no_secret():
    state = StreamSigner("stream-a", SEED, PAIR.key_id).state()
    assert SEED.hex() not in json.dumps(state)
    assert set(state) == {"scheme", "stream_id", "key_id", "next_seq", "head", "closed"}


def _good_state() -> dict:
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    signer.sign(_records(1)[0])
    return signer.state()


@pytest.mark.parametrize("corrupt", [
    lambda s: s.update(scheme="cohaera.other:1"),
    lambda s: s.update(stream_id=""),
    lambda s: s.update(stream_id="a\x00b"),
    lambda s: s.update(key_id=None),
    lambda s: s.update(next_seq=-1),
    lambda s: s.update(next_seq=True),
    lambda s: s.update(next_seq="1"),
    lambda s: s.update(head="abc"),
    lambda s: s.update(head="g" * 64),
    lambda s: s.update(next_seq=0),      # claims nothing signed, head is not chain[0]
])
def test_a_state_that_does_not_describe_a_chain_is_refused(corrupt):
    """Refused rather than repaired: the alternative to continuing correctly
    is starting at zero, which the ledger reports as a forked history."""
    state = _good_state()
    corrupt(state)
    with pytest.raises(SignerStateError):
        StreamSigner.resume(state, SEED)
    with pytest.raises(SignerStateError):
        StreamSigner.resume([], SEED)


def test_resuming_under_a_different_key_id_is_refused():
    """The chain seed binds the key id. A stream cannot change key mid-chain;
    a rotation is a new stream."""
    with pytest.raises(SignerStateError, match="cannot change key"):
        StreamSigner.resume(_good_state(), SEED, key_id="ed25519:other")


def test_a_record_that_already_carries_integrity_is_refused():
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    signed = signer.sign(_records(1)[0])
    with pytest.raises(ValueError, match="already carries"):
        signer.sign(signed)
    assert signer.next_seq == 1, "a refusal must not consume a sequence number"


@pytest.mark.parametrize("record", [None, [], "{}", 42, ("a", 1)])
def test_a_non_dict_record_is_refused(record):
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    with pytest.raises(TypeError):
        signer.sign(record)
    assert signer.next_seq == 0


def test_the_callers_record_is_never_mutated():
    record = _records(1)[0]
    before = json.dumps(record, sort_keys=True)
    signed = StreamSigner("stream-a", SEED, PAIR.key_id).sign(record)
    assert json.dumps(record, sort_keys=True) == before
    assert "integrity" not in record
    assert signed is not record and "integrity" in signed


@pytest.mark.parametrize("bad", [
    {"timestamp": float("nan")}, {"timestamp": float("inf")},
    {"data": {"ids": {1, 2}}}, {"data": {"when": object()}},
    {"data": {1: "int key"}}, {"data": {"n": 10 ** 1025}},
    {"data": {"blob": b"bytes"}},
])
def test_a_record_the_strict_reader_would_quarantine_is_refused(bad):
    """The chain is over canonical(record), which COERCES: NaN to a marker, a
    set to a list, an object to its repr. The bytes a writer then stores are
    something else, and the signature covers a record nobody kept."""
    record = {**_records(1)[0], **bad}
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    with pytest.raises(ValueError):
        signer.sign(record)
    assert signer.next_seq == 0


def test_a_tuple_is_a_list_on_the_wire_and_is_accepted():
    """json.dumps and json_safe agree on tuples, so the chain and the bytes
    agree; refusing them would be refusing what every writer emits."""
    record = {**_records(1)[0], "data": {"path": ("a", "b")}}
    signed = StreamSigner("stream-a", SEED, PAIR.key_id).sign(record)
    reparsed = json.loads(json.dumps(signed))
    assert not _verify([reparsed]).inadmissible


@pytest.mark.parametrize("rate", [0, -1, 1.5, True, "4"])
def test_a_sampling_rate_that_could_switch_signing_off_is_refused(rate):
    with pytest.raises(ValueError, match="sign_every"):
        StreamSigner("stream-a", SEED, PAIR.key_id, sign_every=rate)


def test_a_sampled_stream_is_complete_only_if_the_last_record_is_marked_final():
    """R-05 from the producer side. One signature covers everything before it
    and nothing after, so a sampled stream whose last record fell between
    signing positions is a prefix. The incremental signer cannot know which
    record is last; the caller says."""
    records = _records(150)
    signer = StreamSigner("stream-a", SEED, PAIR.key_id, sign_every=100)
    signed = [signer.sign(r) for r in records]
    assert [r["integrity"]["seq"] for r in signed if "sig" in r["integrity"]] == [0, 100]
    assert _status(signed) == EVIDENCE_VERIFIED_PREFIX

    signer = StreamSigner("stream-a", SEED, PAIR.key_id, sign_every=100)
    signed = [signer.sign(r, attest=(i == 149)) for i, r in enumerate(records)]
    assert [r["integrity"]["seq"] for r in signed if "sig" in r["integrity"]] == [0, 100, 149]
    assert _status(signed) == EVIDENCE_VERIFIED_COMPLETE


def test_what_the_signer_emits_is_actually_protected():
    """A signer whose output could be edited without the verifier noticing
    would be the fault this project was started over. Delete, alter, replay."""
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    signed = [signer.sign(r) for r in _records(8)]

    deleted = signed[:3] + signed[4:]
    assert R_SEQUENCE_GAP in _verify(deleted).codes

    altered = list(signed)
    altered[2] = {**altered[2], "tool_name": "object_put"}
    assert R_CHAIN_BROKEN in _verify(altered).codes

    replayed = [*signed, signed[5]]
    assert R_SEQUENCE_REPLAY in _verify(replayed).codes

    assert set(_verify(signed).codes) & INADMISSIBLE == set()


def test_a_key_the_store_does_not_hold_does_not_verify():
    other = KeyPair.generate()
    signer = StreamSigner("stream-a", other.seed, other.key_id)
    signed = [signer.sign(r) for r in _records(3)]
    state = _verify(signed)
    assert state.signatures_verified == 0
    assert "INTEGRITY_KEY_UNKNOWN" in state.codes


def test_signing_is_serialised_across_threads():
    """A collector hands records to the signer from several threads. Two
    threads racing for a sequence number would put two records at one position,
    which the verifier reports as a replay."""
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    out: list[dict] = []
    lock = threading.Lock()

    def work(k: int) -> None:
        for r in _records(10, sid="sess-1"):
            s = signer.sign({**r, "data": {"worker": k}})
            with lock:
                out.append(s)

    threads = [threading.Thread(target=work, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out.sort(key=lambda r: r["integrity"]["seq"])
    assert [r["integrity"]["seq"] for r in out] == list(range(40))
    state = _verify(out)
    assert not state.inadmissible and state.signatures_verified == 40


@pytest.mark.parametrize("kw", [
    {"stream_id": ""}, {"stream_id": "a\nb"}, {"stream_id": "x" * 257},
    {"stream_id": 7}, {"key_id": ""}, {"key_id": "k\x1b[2J"},
    {"private_key": b"short"}, {"private_key": SEED.hex()},
])
def test_stream_and_key_identities_are_validated(kw):
    args = {"stream_id": "stream-a", "private_key": SEED, "key_id": PAIR.key_id, **kw}
    with pytest.raises(ValueError):
        StreamSigner(args["stream_id"], args["private_key"], args["key_id"])


# ---------------------------------------------------------------------------
# ApprovalIssuer
# ---------------------------------------------------------------------------

ARGS = {"amount_usd": 250, "to": "acct-1188"}
ISSUER = ApprovalIssuer(SEED, PAIR.key_id)


def _issue(**over) -> dict:
    kw = {"expires_at": BASE_T + 3600.0, "tool_args": ARGS,
          "granted_at": BASE_T - 100.0, "granted_by": "user:alice"}
    kw.update(over)
    return ISSUER.issue("allow", "AP1", "wire_transfer_send", **kw)


def _ev(sid, ts, etype, **data):
    return Event(raw={"event_id": f"{sid}-{ts}", "timestamp": ts,
                      "session_id": sid, "trace_id": sid,
                      "span_id": data.pop("span_id", None),
                      "event_type": etype, "agent_name": "payments-agent",
                      "tool_name": data.pop("tool_name", None),
                      "host": "h", "user": "u", "data": data})


def _session(approval: dict, span: str = "AP1", **kw) -> Session:
    events = [
        _ev("s", BASE_T, "cost_threshold_exceeded", action="policy_event",
            policy_id="payments-guard", enforcement="blocking", approval=approval),
        _ev("s", BASE_T + 10, "tool_start", span_id=span,
            tool_name="wire_transfer_send", tool_args=ARGS, reversible=False),
        _ev("s", BASE_T + 11, "tool_end", span_id=span,
            tool_name="wire_transfer_send", result="success"),
    ]
    manifest = CapabilityManifest.from_obj({
        "tools": {"wire_transfer_send": {"effects": ["egress"], "reversible": False}},
        "policies": {"payments-guard": {"enforcement": "blocking"}}})
    return Session(session_id="s", manifest=manifest, events=events, **kw)


def test_an_issued_approval_reaches_authenticated_and_single_use(tmp_path):
    """THE CORE TEST. Through Session.approval_tier, which is what the verdict
    reports, under a store holding the key with the approval role."""
    approval = _issue()
    s = _session(approval, trust_store=STORE)
    assert s.approval_tier(s.approvals[0]) == APPROVAL_AUTHENTICATED

    ledger = ApprovalLedger(path=tmp_path / "approvals.json")
    s = _session(approval, trust_store=STORE, approval_ledger=ledger)
    assert s.approval_tier(s.approvals[0]) == APPROVAL_SINGLE_USE

    # It covers the call, and CH04 does not fire, with the strict flag on.
    s = _session(approval, trust_store=STORE, require_signed_approvals=True)
    assert s.covering_approval(s.consequential_calls[0]) is not None
    assert ch04_guardrail_overrun(s) == []


def test_a_second_presentation_with_the_span_rewritten_fails_verification():
    """EVASION.md E26 point 2, from the issuer's side: the signature covers
    the span, so the one edit that re-points an approval breaks it."""
    approval = _issue()
    moved = json.loads(json.dumps(approval))
    moved["subject"]["span_id"] = "AP2"
    parsed, codes = Approval.parse(moved)
    assert parsed is not None and not codes
    checked = verify_approval(parsed, STORE)
    assert checked.verified is False and checked.tier == APPROVAL_BOUND

    s = _session(moved, span="AP2", trust_store=STORE, require_signed_approvals=True)
    assert s.covering_approval(s.consequential_calls[0]) is None
    assert [f.check for f in ch04_guardrail_overrun(s)] == ["CH04_blocking_control_bypassed"]


def test_the_nonce_is_spent_once_across_runs(tmp_path):
    approval = _issue()
    path = tmp_path / "approvals.json"
    first = ApprovalLedger(path=path)
    assert _session(approval, trust_store=STORE, approval_ledger=first).approval_tier(
        _session(approval, trust_store=STORE).approvals[0]) == APPROVAL_SINGLE_USE
    first.save()
    again = _session(approval, trust_store=STORE, approval_ledger=ApprovalLedger(path=path))
    assert again.approval_tier(again.approvals[0]) == APPROVAL_AUTHENTICATED


def test_every_approval_gets_a_fresh_nonce_and_signature():
    a, b = _issue(), _issue()
    assert a["nonce"] != b["nonce"]
    assert a["signature"]["sig"] != b["signature"]["sig"]
    assert a["signature"]["key_id"] == PAIR.key_id


def test_an_eternal_approval_cannot_be_issued():
    """E26 point 4 from the producer side. There is no argument combination
    that yields a signed approval with no expiry."""
    with pytest.raises(ValueError, match="expires_at"):
        _issue(expires_at=None)
    with pytest.raises(TypeError):
        ISSUER.issue("allow", "AP1", "wire_transfer_send", tool_args=ARGS)  # type: ignore[call-arg]
    for bad in (float("inf"), float("nan"), "later", True):
        with pytest.raises(ValueError):
            _issue(expires_at=bad)


def test_an_approval_that_expires_before_it_is_granted_is_refused():
    with pytest.raises(ValueError, match="not after"):
        _issue(granted_at=BASE_T, expires_at=BASE_T)
    with pytest.raises(ValueError, match="not after"):
        _issue(granted_at=BASE_T, expires_at=BASE_T - 1)


def test_granted_at_defaults_to_now_and_is_covered_by_the_signature():
    approval = _issue(granted_at=None, expires_at=BASE_T * 2)
    assert isinstance(approval["granted_at"], float)
    parsed, _ = Approval.parse(approval)
    assert verify_approval(parsed, STORE).verified
    assert verify_approval(replace(parsed, granted_at=parsed.granted_at - 1), STORE).verified \
        is False


@pytest.mark.parametrize("field,value", [
    ("span_id", "AP1\n"), ("span_id", "\x1b[2JAP1"), ("span_id", ""),
    ("span_id", "x" * 257), ("span_id", 7),
    ("tool_id", "wire\x00transfer"), ("tool_id", ""),
    ("granted_by", "user:\x7falice"), ("granted_by", ""),
    ("policy_id", "guard\r\n"), ("policy_id", True),
])
def test_identity_fields_refuse_control_characters_and_non_strings(field, value):
    kw = {"decision": "allow", "span_id": "AP1", "tool_id": "wire_transfer_send",
          "expires_at": BASE_T + 10, "granted_at": BASE_T, "tool_args": ARGS}
    kw[field] = value
    with pytest.raises(ValueError, match=field):
        ISSUER.issue(kw.pop("decision"), kw.pop("span_id"), kw.pop("tool_id"), **kw)


def test_an_approval_must_bind_to_the_arguments():
    with pytest.raises(ValueError, match="arg_digest or tool_args"):
        ISSUER.issue("allow", "AP1", "wire_transfer_send",
                     expires_at=BASE_T + 10, granted_at=BASE_T)
    with pytest.raises(ValueError, match="sha256"):
        _issue(tool_args=None, arg_digest="deadbeef")  # type: ignore[arg-type]


def test_tool_args_and_a_declared_digest_must_agree():
    """F-01: a declared digest that contradicts the arguments is a call the
    telemetry cannot agree on, and the issuer must not pick a side."""
    with pytest.raises(ValueError, match="does not match"):
        _issue(arg_digest=arg_digest({"to": "attacker"}))
    both = _issue(arg_digest=arg_digest(ARGS))
    assert both["subject"]["arg_digest"] == arg_digest(ARGS)
    declared_only = ISSUER.issue("allow", "AP1", "wire_transfer_send",
                                 expires_at=BASE_T + 10, granted_at=BASE_T,
                                 arg_digest=arg_digest(ARGS))
    assert declared_only["subject"]["arg_digest"] == arg_digest(ARGS)


def test_decision_enforcement_and_policy_digest_are_validated():
    with pytest.raises(ValueError, match="decision"):
        ISSUER.issue("approve", "AP1", "t", expires_at=BASE_T + 10,
                     granted_at=BASE_T, tool_args=ARGS)
    with pytest.raises(ValueError, match="enforcement"):
        _issue(enforcement="mandatory")
    with pytest.raises(ValueError, match="policy_digest"):
        _issue(policy_digest="1a2b")
    full = _issue(enforcement="blocking", policy_id="payments-guard",
                  policy_digest=arg_digest({"policy": 1}))
    parsed, codes = Approval.parse(full)
    assert not codes and parsed.enforcement == "blocking"
    assert parsed.policy_id == "payments-guard" and parsed.policy_digest == arg_digest({"policy": 1})
    deny = ISSUER.issue("deny", "AP1", "t", expires_at=BASE_T + 10, granted_at=BASE_T,
                        tool_args=ARGS)
    assert verify_approval(Approval.parse(deny)[0], STORE).verified


def test_a_collector_only_key_does_not_authenticate_an_approval():
    """Role separation from the issuer's side: signing with a key the store
    trusts for telemetry buys nothing for approvals."""
    collector_only = TrustStore.from_obj(trust_store_document(
        {PAIR.key_id: PAIR.trust_store_entry(roles=["collector"])}))
    parsed, _ = Approval.parse(_issue())
    assert verify_approval(parsed, collector_only).tier == APPROVAL_BOUND


def test_the_issuer_validates_its_own_key_and_id():
    with pytest.raises(ValueError):
        ApprovalIssuer(b"short", PAIR.key_id)
    with pytest.raises(ValueError):
        ApprovalIssuer(SEED, "")
    assert SEED.hex() not in repr(ISSUER)


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


def test_the_assurance_vocabulary_is_the_reference_adapters_vocabulary():
    assert ASSURANCE_LEVELS == receipt_adapters.ASSURANCE_LEVELS


def test_binding_matches_the_reference_binding_for():
    assert binding("sp-1", "s3_object_put", tool_args={"Key": "k", "Bucket": "b"}) == \
        receipt_adapters.binding_for("sp-1", "s3_object_put", {"Bucket": "b", "Key": "k"})


def test_a_built_receipt_is_what_the_reference_adapter_builds():
    bound = binding("sp-1", "s3_object_put", tool_args={"Key": "k"})
    ours = receipt("aws:s3", "object_version", "3sL4kqtJ", binding=bound,
                   assurance=ASSURANCE_OPERATION, observed_at=12.5,
                   scope={"region": "eu-west-2", "account": "123"})
    theirs = receipt_adapters.adapt("aws.s3.put_object", {"VersionId": "3sL4kqtJ"},
                                    bound, observed_at=12.5,
                                    scope={"account": "123", "region": "eu-west-2"})
    assert ours == theirs
    parsed, codes = EffectReceipt.parse(ours)
    assert parsed is not None and not codes and parsed.binding.complete


def test_a_receipt_that_cannot_bind_or_say_what_it_is_worth_is_refused():
    bound = binding("sp-1", "s3_object_put", tool_args={})
    with pytest.raises(ValueError, match="assurance"):
        receipt("aws:s3", "object_version", "v1", binding=bound, assurance="verified")
    with pytest.raises(ValueError):
        receipt("aws:s3", "object_version", "v1", assurance=ASSURANCE_OPERATION,
                binding={"span_id": "sp-1", "tool_id": "s3_object_put"})
    with pytest.raises(ValueError):
        receipt("aws:s3", "object_version", "", binding=bound, assurance=ASSURANCE_OPERATION)
    with pytest.raises(ValueError):
        receipt("aws:s3", "object\nversion", "v1", binding=bound,
                assurance=ASSURANCE_OPERATION)
    with pytest.raises(ValueError):
        receipt("aws:s3", "object_version", "v1", binding=bound,
                assurance=ASSURANCE_OPERATION, scope={"region": "eu\x00"})


# ---------------------------------------------------------------------------
# JsonlWriter
# ---------------------------------------------------------------------------


def test_the_writer_appends_one_line_per_record_unescaped_and_flushed(tmp_path):
    path = tmp_path / "out.jsonl"
    with JsonlWriter(path) as out:
        out.write({"b": 1, "a": "héllo ✓"})
        # Read while still open: the line must already be on disk.
        assert path.read_bytes() == b'{"a": "h\xc3\xa9llo \xe2\x9c\x93", "b": 1}\n'
        out.write({"a": "two"})
        assert out.count == 2
    with JsonlWriter(path) as out:
        out.write({"a": "three"})
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 4
    assert b"\r" not in path.read_bytes()
    with JsonlWriter(path, append=False) as out:
        out.write({"a": "only"})
    assert path.read_text(encoding="utf-8") == '{"a": "only"}\n'


def test_the_writer_refuses_what_the_strict_reader_would_quarantine(tmp_path):
    path = tmp_path / "out.jsonl"
    with JsonlWriter(path) as out:
        with pytest.raises(TypeError):
            out.write(["not", "a", "record"])
        with pytest.raises(ValueError):
            out.write({"x": float("nan")})
        assert out.count == 0
    assert path.read_bytes() == b""
    with pytest.raises(ValueError, match="closed"):
        out.write({"a": 1})


def test_what_the_writer_wrote_is_what_cohaera_reads(tmp_path):
    path = tmp_path / "signed.jsonl"
    signer = StreamSigner("stream-a", SEED, PAIR.key_id)
    with JsonlWriter(path) as out:
        for r in _records(5):
            out.write(signer.sign(r))
    events = list(read_events(path, quiet=True))
    assert len(events) == 5
    assert all(e.integrity is not None for e in events)
    assert evidence_status(assemble(events, keys=STORE)[0]) == EVIDENCE_VERIFIED_COMPLETE


# ---------------------------------------------------------------------------
# python -m cohaera.emit
# ---------------------------------------------------------------------------


def _emit(*args: str, cwd: Path, stdin: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    return subprocess.run([sys.executable, "-m", "cohaera.emit", *args], cwd=cwd,
                          input=stdin, capture_output=True, text=True, env=env,
                          check=False, timeout=120)


def _raw_lines(records: list[dict]) -> str:
    return "".join(json.dumps(r) + "\n" for r in records)


def _tool_calls(n: int, sid: str = "cli-1") -> list[dict]:
    out = []
    for i in range(n):
        base = {"session_id": sid, "trace_id": sid, "span_id": f"sp-{i}",
                "tool_name": "fetch_ticket", "agent_name": "support-agent"}
        out.append({**base, "event_type": "tool_start", "timestamp": BASE_T + i,
                    "data": {"action": "invoke_tool", "tool_args": {"id": i},
                             "reversible": True}})
        out.append({**base, "event_type": "tool_end", "timestamp": BASE_T + i + 0.5,
                    "data": {"action": "invoke_tool", "result": "success"}})
    return out


def test_the_cli_round_trip_reaches_verified_complete(tmp_path):
    """keygen, sign in two batches through a state file, score. The verdict is
    the oracle, read from `cohaera score` itself rather than from the library."""
    done = _emit("keygen", "--out", "collector.key", "--roles", "collector",
                 "--trust-store", "trust-store.json", cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    key_id = done.stdout.strip()
    assert key_id.startswith("ed25519:")
    assert read_private_key(tmp_path / "collector.key").key_id == key_id
    store = TrustStore.from_file(tmp_path / "trust-store.json")
    assert store.get(key_id) is not None and store.get(key_id).roles == {"collector"}
    assert "mode 0600" in done.stderr

    records = _tool_calls(6)
    (tmp_path / "batch1.jsonl").write_text(_raw_lines(records[:7]), encoding="utf-8")
    (tmp_path / "batch2.jsonl").write_text(_raw_lines(records[7:]), encoding="utf-8")
    first = _emit("sign", "--key", "collector.key", "--stream-id", "collector-01",
                  "--in", "batch1.jsonl", "--out", "signed.jsonl",
                  "--state", "collector-01.state", cwd=tmp_path)
    assert first.returncode == 0, first.stderr
    assert "signed 7 record(s)" in first.stderr
    second = _emit("sign", "--key", "collector.key", "--stream-id", "collector-01",
                   "--in", "batch2.jsonl", "--out", "signed.jsonl", "--append",
                   "--state", "collector-01.state", cwd=tmp_path)
    assert second.returncode == 0, second.stderr
    assert "resuming stream 'collector-01' at seq 7" in second.stderr
    assert read_state(tmp_path / "collector-01.state")["next_seq"] == 12

    signed = [json.loads(line) for line in
              (tmp_path / "signed.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["integrity"]["seq"] for r in signed] == list(range(12))

    score = subprocess.run(
        [sys.executable, "-m", "cohaera.cli", "score", "signed.jsonl",
         "--trust-store", "trust-store.json"],
        cwd=tmp_path, capture_output=True, text=True, check=False, timeout=120,
        env={**os.environ, "PYTHONPATH": str(SRC)})
    assert score.returncode == 0, score.stderr
    verdicts = [json.loads(line) for line in score.stdout.splitlines() if line.strip()]
    assert len(verdicts) == 1
    # R-05: evidence_status lives in coverage, so a quiet session still says
    # how far its own telemetry was established.
    assert verdicts[0]["data"]["coverage"]["evidence_status"] == EVIDENCE_VERIFIED_COMPLETE
    assert "NO_COLLECTOR_KEYS" not in score.stdout
    assert "INTEGRITY_STREAM_JOINED_MIDSTREAM" not in score.stdout


def test_the_cli_signs_stdin_to_stdout(tmp_path):
    write_private_key(tmp_path / "k", PAIR)
    done = _emit("sign", "--key", "k", "--stream-id", "s", cwd=tmp_path,
                 stdin=_raw_lines(_records(3)))
    assert done.returncode == 0, done.stderr
    signed = [json.loads(line) for line in done.stdout.splitlines()]
    assert _status(signed) == EVIDENCE_VERIFIED_COMPLETE


def test_the_cli_refuses_a_batch_with_a_line_it_cannot_sign(tmp_path):
    """Skipping the line would emit a contiguous, attested stream with the
    drop invisible in it. The verifier can only report a deletion it can see."""
    write_private_key(tmp_path / "k", PAIR)
    lines = _raw_lines(_records(2)) + "[1, 2]\n" + _raw_lines(_records(1))
    done = _emit("sign", "--key", "k", "--stream-id", "s", "--out", "signed.jsonl",
                 "--state", "s.state", cwd=tmp_path, stdin=lines)
    assert done.returncode == 1
    assert "line 3" in done.stderr
    assert not (tmp_path / "s.state").exists(), "no state is committed for a refused batch"


def test_the_cli_refuses_a_state_file_for_another_stream(tmp_path):
    write_private_key(tmp_path / "k", PAIR)
    signer = StreamSigner("other", SEED, PAIR.key_id)
    write_state(tmp_path / "s.state", signer.state())
    done = _emit("sign", "--key", "k", "--stream-id", "s", "--state", "s.state",
                 cwd=tmp_path, stdin=_raw_lines(_records(1)))
    assert done.returncode == 1 and "stream 'other'" in done.stderr


def test_the_cli_issues_an_approval_the_verifier_authenticates(tmp_path):
    done = _emit("keygen", "--out", "approver.key", "--roles", "approval",
                 "--trust-store", "ts.json", cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    done = _emit("issue-approval", "--key", "approver.key", "--decision", "allow",
                 "--span-id", "AP1", "--tool-id", "wire_transfer_send",
                 "--tool-args", json.dumps(ARGS), "--granted-at", str(BASE_T - 100),
                 "--expires-in", "3600", "--granted-by", "user:alice",
                 "--policy-id", "payments-guard", "--enforcement", "blocking",
                 cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    approval = json.loads(done.stdout)
    store = TrustStore.from_file(tmp_path / "ts.json")
    parsed, codes = Approval.parse(approval)
    assert not codes and verify_approval(parsed, store).tier == APPROVAL_AUTHENTICATED
    assert approval["expires_at"] == BASE_T - 100 + 3600

    eternal = _emit("issue-approval", "--key", "approver.key", "--decision", "allow",
                    "--span-id", "AP1", "--tool-id", "t", "--tool-args", "{}",
                    cwd=tmp_path)
    assert eternal.returncode == 1 and "expir" in eternal.stderr
    bad_json = _emit("issue-approval", "--key", "approver.key", "--decision", "allow",
                     "--span-id", "AP1", "--tool-id", "t", "--tool-args", "{nope",
                     "--expires-in", "60", cwd=tmp_path)
    assert bad_json.returncode == 1 and "not JSON" in bad_json.stderr


def test_keygen_adds_a_rotation_key_to_an_existing_store(tmp_path):
    first = _emit("keygen", "--out", "a.key", "--roles", "collector",
                  "--trust-store", "ts.json", cwd=tmp_path)
    old_id = first.stdout.strip()
    second = _emit("keygen", "--out", "b.key", "--roles", "collector",
                   "--trust-store", "ts.json", "--replaces", old_id, cwd=tmp_path)
    assert second.returncode == 0, second.stderr
    store = TrustStore.from_file(tmp_path / "ts.json")
    assert set(store.keys) == {old_id, second.stdout.strip()}
    assert store.get(second.stdout.strip()).replaces == old_id
    refused = _emit("keygen", "--out", "a.key", "--roles", "collector", cwd=tmp_path)
    assert refused.returncode == 1 and "already exists" in refused.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_cli_refuses_a_shared_private_key(tmp_path):
    path = write_private_key(tmp_path / "k", PAIR)
    path.chmod(0o644)
    done = _emit("sign", "--key", "k", "--stream-id", "s", cwd=tmp_path, stdin="")
    assert done.returncode == 1 and "readable by others" in done.stderr


# ---------------------------------------------------------------------------
# The boundary
# ---------------------------------------------------------------------------


def test_the_verifier_never_imports_the_emitter():
    """A host that only scores never loads signing code. Checked in a fresh
    interpreter, because the suite's own imports would mask it."""
    script = (
        "import sys\n"
        "import cohaera, cohaera.evidence, cohaera.checks, cohaera.model, cohaera.cli\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('cohaera.emit'))\n"
        "assert not loaded, loaded\n"
        "print('ok')\n"
    )
    done = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True,
                          text=True, check=False, env={**os.environ, "PYTHONPATH": str(SRC)})
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "ok"


def test_no_verifier_module_names_the_emitter_in_source():
    for path in (SRC / "cohaera").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "cohaera.emit" not in text and "from .emit" not in text \
            and "from . import emit" not in text, path


def test_the_emitter_imports_only_the_standard_library_and_cohaera():
    """Zero runtime dependencies is checked in CI against the wheel metadata;
    this is the same claim checked against the import statements."""
    stdlib = sys.stdlib_module_names
    for path in (SRC / "cohaera" / "emit").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            for name in names:
                top = name.split(".")[0]
                assert top in stdlib or top == "cohaera", f"{path.name} imports {name}"
