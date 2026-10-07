# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Evidence-layer hardening: eight defects reproduced at b3cb21a, kept as regressions.

Each was reproduced with a script against the tree BEFORE the fix existed, and
each test below names the defect it pins, so that a reader meeting a strange
line in ``evidence.py`` can find the input that made it strange.

EH-01  ``StreamVerifier.observe`` read the record clock with a numbers-only
       parser while ``validate.timestamp`` accepts a numeric string. A record
       dated ``"4990.0"`` had no clock for the key window or the freshness
       bound, so an expired key signing it got a coverage note instead of an
       inadmissible code.
EH-02  Nothing tied a stream to a key. Any collector-role key could sign any
       stream id, including re-signing records 3 to 5 of another collector's
       stream with the chain intact: ``attested: true``, nothing inadmissible.
EH-03  ``approval_signing_input`` joins fields with ``\\x1f`` and
       ``identity_text`` admits that byte, so one approval's bytes could spell
       a differently-bound one. Separately, four verdict fields sit beside
       "authenticated" and are not signed, and nothing said which.
EH-04  ``ApprovalLedger`` had no lock, no generation guard, a fixed ``.tmp``
       name and no fsync: two concurrent runs both saw a nonce as unspent.
EH-05  ``EffectReceipt.parse`` dropped the ``assurance`` and ``scope`` the
       reference adapters write, so a client-composed SMTP Message-ID read like
       one the provider returned.
EH-06  ``tools/policy_sign.py`` warned about a key holding both roles on a
       line no code path reached.
EH-08  Three hex checks used ``int(x, 16)``, which accepts ``0x``, ``_``, a
       sign, whitespace and Unicode digits.

EH-07, tail truncation of a signed stream, is NOT fixed here. It is catalogued
as EVASION.md E30 and pinned by ``test_evasion_30_...`` in test_evasion.py.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera import ed25519
from cohaera.checks import (
    CH07_CONTRADICTED,
    ch06_evidence_integrity,
    ch07_effect_contradiction,
)
from cohaera.cli import EXIT_ERROR
from cohaera.cli import main as cli_main
from cohaera.evidence import (
    APPROVAL_SCHEMA,
    APPROVAL_SIGNED_FIELDS,
    APPROVAL_UNSIGNED_FIELDS,
    INADMISSIBLE,
    POLICY_SIGNATURE_SCHEMA,
    R_FRESHNESS_UNVERIFIABLE,
    R_KEY_EXPIRED,
    R_KEY_WINDOW_UNCHECKED,
    R_STALE,
    R_STREAM_KEY_CHANGED,
    RECEIPT_BOUND,
    RECEIPT_CLAIMED,
    RECEIPT_RECONCILED,
    RECEIPT_SCHEMA,
    ROLE_APPROVAL,
    TRUST_STORE_SCHEMA,
    Approval,
    ApprovalLedger,
    Binding,
    EffectReceipt,
    Freshness,
    Integrity,
    LedgerError,
    PolicySignature,
    PolicySignatureError,
    StreamVerifier,
    TrustStore,
    _hex_or_none,
    approval_signing_input,
    arg_digest,
    digest_text,
    signing_input,
    verify_approval,
)
from cohaera.limits import DEFAULT_LIMITS, DEFECT_APPROVAL_TYPE, DEFECT_RECEIPT_TYPE
from cohaera.model import Event, Session
from tools import policy_sign
from tools.collector_sign import key_id_for, keys_document, sign_stream
from tools.receipt_adapters import adapt, binding_for

SECRET_A = bytes.fromhex("1a" * 32)
PUBLIC_A = ed25519.public_key(SECRET_A)
KEY_A = key_id_for(PUBLIC_A)
SECRET_B = bytes.fromhex("2b" * 32)
PUBLIC_B = ed25519.public_key(SECRET_B)
KEY_B = key_id_for(PUBLIC_B)
SECRET_C = bytes.fromhex("3c" * 32)
PUBLIC_C = ed25519.public_key(SECRET_C)
KEY_C = key_id_for(PUBLIC_C)

ARGS = {"to": "alice@example.com", "subject": "hi"}


def _records(n: int = 6, ts=None) -> list[dict]:
    return [{"event_type": "tool_start", "session_id": "s1",
             "timestamp": (ts if ts is not None else 1000.0 + i),
             "span_id": f"sp-{i}", "tool_name": "alert_read",
             "data": {"action": "invoke_tool"}} for i in range(n)]


def _store(*entries: dict) -> TrustStore:
    keys: dict = {}
    for entry in entries:
        keys.update(entry["keys"])
    return TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": keys})


def _verify(signed: list[dict], store: TrustStore, **kw):
    v = StreamVerifier(keys=store, **kw)
    events = []
    for raw in signed:
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, "s1")
        events.append(e)
    v.finalise()
    return v.for_session("s1"), events


def _resign_from(signed: list[dict], seq: int, secret: bytes, key_id: str) -> list[dict]:
    """Re-sign every record from ``seq`` on under another key, chain intact.

    The takeover shape: the usurper continues the genuine head rather than
    starting a stream of their own, so sequence and chain both hold.
    """
    out = []
    for record in signed:
        sidecar = dict(record["integrity"])
        if sidecar["seq"] >= seq:
            sidecar["key_id"] = key_id
            sidecar["sig"] = base64.b64encode(ed25519.sign(
                secret, signing_input(sidecar["stream_id"], sidecar["seq"],
                                      sidecar["chain"]))).decode("ascii")
        out.append({**record, "integrity": sidecar})
    return out


def _session_with_integrity(signed: list[dict], store: TrustStore) -> Session:
    state, events = _verify(signed, store)
    s = Session(session_id="s1", events=events)
    s.integrity = state
    s.seal()
    return s


# ---------------------------------------------------------------------------
# EH-01. The record clock is parsed the way validate parses it
# ---------------------------------------------------------------------------


def test_eh01_a_numeric_string_timestamp_is_a_clock_for_the_key_window():
    """A key with not_after=1500 signing a record dated "4990.0" is EXPIRED."""
    store = _store(keys_document(PUBLIC_A, KEY_A, not_after=1500.0))
    signed = sign_stream(_records(3, ts="4990.0"), "st", SECRET_A, KEY_A)
    state, _ = _verify(signed, store)
    assert R_KEY_EXPIRED in state.inadmissible
    assert R_KEY_WINDOW_UNCHECKED not in state.codes
    assert not state.attested


def test_eh01_a_numeric_string_timestamp_is_a_clock_for_freshness():
    store = _store(keys_document(PUBLIC_A, KEY_A))
    signed = sign_stream(_records(3, ts="1000.0"), "st", SECRET_A, KEY_A)
    state, _ = _verify(signed, store,
                       freshness=Freshness(max_age_s=10.0, as_of=5000.0))
    assert state.freshness_checked == 3
    assert R_STALE in state.inadmissible
    assert R_FRESHNESS_UNVERIFIABLE not in state.codes


def test_eh01_a_non_numeric_string_timestamp_is_still_unreadable():
    """Same answer as validate.timestamp: no clock, and the window says so."""
    store = _store(keys_document(PUBLIC_A, KEY_A, not_after=1500.0))
    signed = sign_stream(_records(2, ts="soon"), "st", SECRET_A, KEY_A)
    state, _ = _verify(signed, store)
    assert R_KEY_WINDOW_UNCHECKED in state.codes
    assert R_KEY_EXPIRED not in state.codes


# ---------------------------------------------------------------------------
# EH-02. One key per stream, held
# ---------------------------------------------------------------------------


def test_eh02_a_second_trusted_key_taking_over_mid_stream_is_inadmissible():
    """Key B re-signs records 3-5 of key A's stream. The chain holds; the
    stream does not."""
    store = _store(keys_document(PUBLIC_A, KEY_A), keys_document(PUBLIC_B, KEY_B))
    signed = _resign_from(sign_stream(_records(6), "st", SECRET_A, KEY_A),
                          3, SECRET_B, KEY_B)
    state, _ = _verify(signed, store)
    assert R_STREAM_KEY_CHANGED in state.inadmissible
    assert R_STREAM_KEY_CHANGED in INADMISSIBLE
    assert not state.attested
    assert state.stream_key_changes == [
        {"stream_id": "st", "seq": 3, "from_key_id": KEY_A, "to_key_id": KEY_B}]
    assert state.as_dict()["stream_key_changes"] == state.stream_key_changes


def test_eh02_the_ch06_finding_names_both_keys():
    store = _store(keys_document(PUBLIC_A, KEY_A), keys_document(PUBLIC_B, KEY_B))
    signed = _resign_from(sign_stream(_records(6), "st", SECRET_A, KEY_A),
                          3, SECRET_B, KEY_B)
    findings = ch06_evidence_integrity(_session_with_integrity(signed, store))
    assert len(findings) == 1 and findings[0].severity == "critical"
    assert KEY_A in findings[0].detail and KEY_B in findings[0].detail
    assert "seq 3" in findings[0].detail


def test_eh02_a_rotation_the_trust_store_records_is_not_a_takeover():
    """B replaces A: the same bytes, now a rotation the operator wrote down."""
    store = _store(keys_document(PUBLIC_A, KEY_A),
                   keys_document(PUBLIC_B, KEY_B, replaces=KEY_A))
    signed = _resign_from(sign_stream(_records(6), "st", SECRET_A, KEY_A),
                          3, SECRET_B, KEY_B)
    state, _ = _verify(signed, store)
    assert R_STREAM_KEY_CHANGED not in state.codes
    assert state.attested
    assert state.signing_key_ids == {KEY_A, KEY_B}


def test_eh02_succession_is_followed_transitively():
    """A -> B -> C in the store; C signing after A is the same rotation twice."""
    store = _store(keys_document(PUBLIC_A, KEY_A),
                   keys_document(PUBLIC_B, KEY_B, replaces=KEY_A),
                   keys_document(PUBLIC_C, KEY_C, replaces=KEY_B))
    signed = _resign_from(sign_stream(_records(6), "st", SECRET_A, KEY_A),
                          3, SECRET_C, KEY_C)
    state, _ = _verify(signed, store)
    assert R_STREAM_KEY_CHANGED not in state.codes


def test_eh02_the_retired_key_signing_after_its_successor_is_a_rollback():
    """Succession runs one way. B replaced A; A writing after B is not a
    rotation, it is the retired key back in use."""
    store = _store(keys_document(PUBLIC_A, KEY_A),
                   keys_document(PUBLIC_B, KEY_B, replaces=KEY_A))
    signed = _resign_from(sign_stream(_records(6), "st", SECRET_B, KEY_B),
                          3, SECRET_A, KEY_A)
    state, _ = _verify(signed, store)
    assert R_STREAM_KEY_CHANGED in state.inadmissible
    assert state.stream_key_changes[0]["from_key_id"] == KEY_B
    assert state.stream_key_changes[0]["to_key_id"] == KEY_A


def test_eh02_the_pin_is_taken_on_verification_not_on_the_first_record():
    """A forged first record naming an unknown key must not decide the pin.
    The genuine key verifies at seq 1 and is pinned there; a takeover at seq 4
    is still caught against IT."""
    store = _store(keys_document(PUBLIC_A, KEY_A), keys_document(PUBLIC_B, KEY_B))
    signed = sign_stream(_records(6), "st", SECRET_A, KEY_A)
    signed = _resign_from(signed, 4, SECRET_B, KEY_B)
    first = dict(signed[0]["integrity"])
    first["key_id"] = "ed25519:nobody"
    signed[0] = {**signed[0], "integrity": first}
    state, _ = _verify(signed, store)
    assert R_STREAM_KEY_CHANGED in state.codes
    assert state.stream_key_changes[0]["from_key_id"] == KEY_A


# ---------------------------------------------------------------------------
# EH-03. The signing input is unambiguous, and the verdict says what it covers
# ---------------------------------------------------------------------------


def _approval(**kw) -> dict:
    base = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
            "subject": {"span_id": "sp-send", "tool_id": "send_email",
                        "arg_digest": arg_digest(ARGS)},
            "granted_by": "user:alice", "granted_at": 100.0, "expires_at": 200.0,
            "nonce": "n-1"}
    base.update(kw)
    return base


def test_eh03_the_signer_refuses_a_field_that_would_shift_the_separator():
    """The review's pair: tool_id carrying the digest and nonce "n" versus a
    bound call with nonce "\\x1fn" signed to the same bytes."""
    with pytest.raises(ValueError, match="tool_id"):
        approval_signing_input(
            decision="allow", span_id="sp",
            tool_id="wire_transfer_send\x1fsha256:" + "d" * 64,
            arg_digest=None, nonce="n", granted_at=1.0, expires_at=2.0)
    with pytest.raises(ValueError, match="nonce"):
        approval_signing_input(
            decision="allow", span_id="sp", tool_id="wire_transfer_send",
            arg_digest="sha256:" + "d" * 64, nonce="\x1fn",
            granted_at=1.0, expires_at=2.0)


@pytest.mark.parametrize("bad", ["\x1f", "\x00", "\t", "\n", "\x7f"])
@pytest.mark.parametrize("where", ["span_id", "tool_id", "nonce", "granted_by",
                                   "policy_id", "key_id"])
def test_eh03_an_approval_with_a_control_character_is_absent(where, bad):
    obj = _approval(signature={"key_id": "k-1",
                               "sig": base64.b64encode(bytes(64)).decode()})
    if where in ("span_id", "tool_id"):
        obj["subject"][where] = f"x{bad}y"
    elif where == "key_id":
        obj["signature"]["key_id"] = f"k{bad}1"
    else:
        obj[where] = f"x{bad}y"
    approval, codes = Approval.parse(obj, DEFAULT_LIMITS)
    assert approval is None
    assert codes == (DEFECT_APPROVAL_TYPE,)


def test_eh03_an_ordinary_approval_still_parses_and_verifies():
    """The wire format did not change: a signature made before still holds."""
    secret = bytes.fromhex("4d" * 32)
    public = ed25519.public_key(secret)
    store = TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": {
        "issuer": {"roles": [ROLE_APPROVAL],
                   "key": base64.b64encode(public).decode()}}})
    unsigned, _ = Approval.parse(_approval(), DEFAULT_LIMITS)
    assert unsigned is not None
    sig = ed25519.sign(secret, unsigned.signing_input())
    signed, codes = Approval.parse(_approval(signature={
        "key_id": "issuer", "sig": base64.b64encode(sig).decode()}), DEFAULT_LIMITS)
    assert codes == () and signed is not None
    assert verify_approval(signed, store).verified


def test_eh03_the_verdict_says_which_approval_fields_the_signature_covers():
    approval, _ = Approval.parse(_approval(), DEFAULT_LIMITS)
    d = approval.as_dict()
    assert d["signed_fields"] == list(APPROVAL_SIGNED_FIELDS)
    # The fields printed beside "authenticated" that a signature never reaches.
    for name in APPROVAL_UNSIGNED_FIELDS:
        assert name.split(".")[-1] not in d["signed_fields"]
    for name in ("granted_by", "policy_id", "policy_digest", "enforcement"):
        assert name in d and name in APPROVAL_UNSIGNED_FIELDS
    # The signing input really does not cover them: change all four and the
    # bytes an issuer signs are the same bytes.
    a = Approval(decision="allow", subject=Binding("sp", "t", None),
                 granted_by="alice", policy_id="p1", nonce="n",
                 expires_at=2.0)
    b = Approval(decision="allow", subject=Binding("sp", "t", None),
                 granted_by="mallory", policy_id="p2", nonce="n",
                 expires_at=2.0, enforcement="blocking")
    assert a.signing_input() == b.signing_input()


# ---------------------------------------------------------------------------
# EH-04. The approval ledger is a serialisation point
# ---------------------------------------------------------------------------


def test_eh04_a_second_writer_cannot_overwrite_a_ledger_it_did_not_read(tmp_path):
    """Two runs load, both spend the same nonce, both save. The second save
    used to succeed and the ledger recorded one spend for two 'unspent'
    answers."""
    path = tmp_path / "approvals.json"
    first = ApprovalLedger(path=path)
    second = ApprovalLedger(path=path)
    assert first.spend("n-1") is True and second.spend("n-1") is True
    first.save()
    with pytest.raises(LedgerError, match="generation"):
        second.save()
    # The file on disk is the first writer's, intact, and a fresh load sees
    # the spend.
    assert json.loads(path.read_text())["generation"] == 1
    assert ApprovalLedger(path=path).spend("n-1") is False


def test_eh04_the_lock_excludes_a_concurrent_run(tmp_path):
    path = tmp_path / "approvals.json"
    with ApprovalLedger.locked(path) as held:
        assert held.locked_exclusively
        assert held.spend("n-1") is True
        with pytest.raises(LedgerError, match=r"approval ledger.*--seen-approvals"):
            with ApprovalLedger.locked(path, wait_s=0):
                pass
        held.save()
    # Released on exit: the next run gets in, and sees the spend.
    with ApprovalLedger.locked(path) as after:
        assert after.generation == 1
        assert after.spend("n-1") is False
    assert ApprovalLedger.lock_path_for(path).exists()


def test_eh04_save_leaves_no_fixed_name_scratch_file_behind(tmp_path):
    path = tmp_path / "approvals.json"
    ledger = ApprovalLedger(path=path)
    ledger.spend("n-1")
    ledger.save()
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert leftovers == ["approvals.json"], leftovers
    assert not (tmp_path / "approvals.json.tmp").exists()


def test_eh04_a_ledger_written_before_generations_reads_as_zero(tmp_path):
    path = tmp_path / "approvals.json"
    path.write_text(json.dumps({"schema": "cohaera.approval_ledger:1",
                                "nonces": {"old": 1.0}}))
    ledger = ApprovalLedger(path=path)
    assert ledger.generation == 0
    assert ledger.spend("old") is False
    ledger.spend("new")
    ledger.save()
    assert json.loads(path.read_text())["generation"] == 1


def test_eh04_the_cli_opens_the_approval_ledger_under_the_lock(tmp_path, capsys):
    telemetry = tmp_path / "t.jsonl"
    telemetry.write_text("".join(json.dumps(r) + "\n" for r in _records(2)))
    ledger = tmp_path / "approvals.json"
    rc = cli_main(["score", str(telemetry), "--seen-approvals", str(ledger)])
    err = capsys.readouterr().err
    assert rc != EXIT_ERROR
    assert "approval ledger" in err and "generation 0" in err
    assert ApprovalLedger.lock_path_for(ledger).exists()


# ---------------------------------------------------------------------------
# EH-05. The adapter's assurance caps the receipt tier
# ---------------------------------------------------------------------------


def _call_session(result: str, receipt: dict | None) -> Session:
    start = {"event_type": "tool_start", "session_id": "s", "timestamp": 10.0,
             "span_id": "sp-1", "tool_name": "send_email",
             "data": {"action": "invoke_tool", "reversible": False,
                      "tool_args": ARGS}}
    end_data: dict = {"action": "invoke_tool", "result": result}
    if receipt is not None:
        end_data["effect_receipt"] = receipt
    end = {"event_type": "tool_end" if result == "success" else "tool_error",
           "session_id": "s", "timestamp": 11.0, "span_id": "sp-1",
           "tool_name": "send_email", "data": end_data}
    s = Session(session_id="s", events=[Event(raw=r) for r in (start, end)])
    s.seal()
    return s


def _receipt(**kw) -> dict:
    base = {"scheme": RECEIPT_SCHEMA, "authority": "smtp",
            "kind": "message_id", "identifier": "<abc@example.com>",
            "binding": {"span_id": "sp-1", "tool_id": "send_email",
                        "arg_digest": arg_digest(ARGS)}}
    base.update(kw)
    return base


def test_eh05_assurance_and_scope_are_parsed_and_carried():
    receipt, codes = EffectReceipt.parse(
        _receipt(assurance="client_claimed", scope={"account": "acct_1"}),
        DEFAULT_LIMITS)
    assert codes == ()
    assert receipt.assurance == "client_claimed"
    assert receipt.scope == {"account": "acct_1"}
    d = receipt.as_dict()
    assert d["assurance"] == "client_claimed"
    assert d["scope"] == {"account": "acct_1"}
    assert d["trust_ceiling"] == RECEIPT_CLAIMED


@pytest.mark.parametrize("assurance,ceiling", [
    ("provider_returned_operation", RECEIPT_RECONCILED),
    ("provider_returned_object", RECEIPT_BOUND),
    ("client_claimed", RECEIPT_CLAIMED),
    (None, RECEIPT_RECONCILED),
])
def test_eh05_the_declared_assurance_is_a_ceiling(assurance, ceiling):
    obj = _receipt() if assurance is None else _receipt(assurance=assurance)
    receipt, codes = EffectReceipt.parse(obj, DEFAULT_LIMITS)
    assert codes == ()
    assert receipt.trust_ceiling == ceiling
    assert receipt.capped(RECEIPT_BOUND) == (
        RECEIPT_CLAIMED if ceiling == RECEIPT_CLAIMED else RECEIPT_BOUND)


def test_eh05_a_client_claimed_receipt_reads_claimed_in_ch07_even_when_bound():
    """The review's case: an SMTP Message-ID the client composed, bound
    exactly to a failed send. It used to read `bound`, like one the provider
    returned."""
    claimed = ch07_effect_contradiction(
        _call_session("failure", _receipt(assurance="client_claimed")))
    assert [f.check for f in claimed] == [CH07_CONTRADICTED]
    assert claimed[0].evidence["receipt_trust"] == RECEIPT_CLAIMED
    returned = ch07_effect_contradiction(_call_session(
        "failure", _receipt(assurance="provider_returned_operation")))
    assert returned[0].evidence["receipt_trust"] == RECEIPT_BOUND
    # No assurance at all: the pre-R-17 producer, uncapped as before.
    legacy = ch07_effect_contradiction(_call_session("failure", _receipt()))
    assert legacy[0].evidence["receipt_trust"] == RECEIPT_BOUND


def test_eh05_the_reference_adapter_round_trips_through_the_parser():
    binding = binding_for("sp-1", "send_email", ARGS)
    composed = adapt("smtp.send", {"Message-ID": "<local@client>"}, binding,
                     scope={"host": "mail.example.com"})
    receipt, codes = EffectReceipt.parse(composed, DEFAULT_LIMITS)
    assert codes == () and receipt.assurance == "client_claimed"
    assert receipt.scope == {"host": "mail.example.com"}
    assert receipt.capped(RECEIPT_BOUND) == RECEIPT_CLAIMED
    served = adapt("smtp.send", {"server_message_id": "<srv@mta>"}, binding)
    receipt, _ = EffectReceipt.parse(served, DEFAULT_LIMITS)
    assert receipt.capped(RECEIPT_BOUND) == RECEIPT_BOUND


@pytest.mark.parametrize("bad", ["verified", "", 7, True, {"level": "high"}])
def test_eh05_an_unreadable_assurance_is_absent_flagged_and_caps_at_claimed(bad):
    """Absent-and-flagged, in the direction that fails closed: the adapter
    said something about its evidence and it could not be read, so the
    receipt is worth the least rather than the most."""
    receipt, codes = EffectReceipt.parse(_receipt(assurance=bad), DEFAULT_LIMITS)
    assert receipt is not None, "the receipt still names a call"
    assert codes == (DEFECT_RECEIPT_TYPE,)
    assert receipt.assurance is None and receipt.assurance_unreadable
    assert receipt.trust_ceiling == RECEIPT_CLAIMED
    assert receipt.as_dict()["assurance_unreadable"] is True


@pytest.mark.parametrize("bad", ["eu-west-1", [], {}, {"account": 7},
                                 {"": "x"}, {"account": ""}])
def test_eh05_a_malformed_scope_is_absent_and_flagged(bad):
    receipt, codes = EffectReceipt.parse(_receipt(scope=bad), DEFAULT_LIMITS)
    assert receipt is not None
    assert receipt.scope is None
    assert codes == (DEFECT_RECEIPT_TYPE,)
    # A scope problem says nothing about assurance: no cap from it.
    assert receipt.trust_ceiling == RECEIPT_RECONCILED


# ---------------------------------------------------------------------------
# EH-06. The dual-role warning is reachable
# ---------------------------------------------------------------------------


def _run_policy_sign(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = policy_sign.main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_eh06_a_store_giving_one_key_both_roles_warns(tmp_path):
    rc, out, err = _run_policy_sign(
        ["store", "--secret-hex", "1a" * 32, "--roles", "collector", "policy",
         "--out", str(tmp_path / "store.json")])
    assert rc == 0 and "wrote trust store" in out
    assert "WARNING" in err and "collector" in err
    doc = json.loads((tmp_path / "store.json").read_text())
    assert next(iter(doc["keys"].values()))["roles"] == ["collector", "policy"]


def test_eh06_a_policy_only_store_does_not_warn(tmp_path):
    rc, _, err = _run_policy_sign(
        ["store", "--secret-hex", "1a" * 32, "--roles", "policy",
         "--out", str(tmp_path / "store.json")])
    assert rc == 0 and "WARNING" not in err


def test_eh06_the_sign_path_still_runs_and_never_warns(tmp_path):
    artifact = tmp_path / "baseline.jsonl"
    artifact.write_text("{}\n")
    rc, out, err = _run_policy_sign(
        ["sign", "--artifact", "baseline", "--file", str(artifact),
         "--out", str(tmp_path / "baseline.sig"), "--secret-hex", "1a" * 32,
         "--signed-at", "1785700000"])
    assert rc == 0 and "signed baseline" in out and "WARNING" not in err


# ---------------------------------------------------------------------------
# EH-08. Hex means hex
# ---------------------------------------------------------------------------

LENIENT_HEX = [
    "0x" + "a" * 62,            # prefix
    "a" * 62 + "_a",            # digit separator
    "+" + "a" * 63,             # sign
    " " + "a" * 63,             # whitespace
    chr(0x0661) + "a" * 63,     # ARABIC-INDIC DIGIT ONE, which int() reads as 1
    "a" * 63 + "g",             # plain non-hex, the case it always caught
]


@pytest.mark.parametrize("bad", LENIENT_HEX)
def test_eh08_digest_text_and_chain_hex_are_strict(bad):
    assert len(bad) == 64
    assert digest_text("sha256:" + bad) is None
    assert _hex_or_none(bad) is None
    parsed, codes = Integrity.parse(
        {"scheme": "cohaera.integrity:1", "stream_id": "st", "seq": 1,
         "prev": bad, "chain": "b" * 64}, DEFAULT_LIMITS)
    assert codes == () and parsed is not None
    assert parsed.prev is None, "a lenient prev became a chain head"


@pytest.mark.parametrize("bad", LENIENT_HEX)
def test_eh08_a_policy_signature_digest_is_strict(bad):
    with pytest.raises(PolicySignatureError, match="hexadecimal"):
        PolicySignature.from_obj({
            "scheme": POLICY_SIGNATURE_SCHEMA, "artifact": "baseline",
            "file_sha256": bad, "signed_at": 1, "key_id": "k",
            "sig": base64.b64encode(bytes(64)).decode()})


def test_eh08_uppercase_hex_is_still_read_and_lowercased():
    assert digest_text("sha256:" + "A" * 64) == "sha256:" + "a" * 64
    assert _hex_or_none("B" * 64) == "b" * 64
    sig = PolicySignature.from_obj({
        "scheme": POLICY_SIGNATURE_SCHEMA, "artifact": "baseline",
        "file_sha256": "C" * 64, "signed_at": 1, "key_id": "k",
        "sig": base64.b64encode(bytes(64)).decode()})
    assert sig.file_sha256 == "c" * 64
