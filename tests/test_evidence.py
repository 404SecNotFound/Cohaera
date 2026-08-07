"""P1 evidence trust: schemas, chain verification, binding, and the two new checks.

Everything here tests a mechanism whose job is to be HARD TO FAKE, so most of
these tests are attacks rather than happy paths. The happy paths are the short
ones.

The layout follows docs/EVIDENCE-TRUST.md:

    section 1   the crypto, against RFC 8032, including the malleability case
                that a hand-written Ed25519 verifier gets wrong
    section 2   parsing, where every malformed sidecar must read as ABSENT and
                never as a weaker version of itself
    section 3   the stream verifier: deletion, modification, replay, reorder,
                and the bounds that stop a producer choosing how much work it
                costs to check
    section 4   approval binding and the CH04 enforcement split
    section 5   CH07, and the asymmetry that makes receipts worth collecting
    section 6   the suppression this whole design creates, and its EVASION entry

Run: PYTHONPATH=src python3 -m pytest tests/test_evidence.py -v
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera import ed25519
from cohaera.capabilities import CapabilityManifest
from cohaera.checks import (
    CH04_BYPASSED,
    CH04_COMPLETED,
    CH06_INTEGRITY,
    CH07_CONTRADICTED,
    CH07_UNBOUND,
    EVIDENCE_INADMISSIBLE,
    EVIDENCE_UNATTESTED,
    EVIDENCE_VERIFIED,
    ch04_guardrail_overrun,
    ch06_evidence_integrity,
    ch07_effect_contradiction,
    coverage,
    evidence_status,
    run_all,
)
from cohaera.evidence import (
    APPROVAL_SCHEMA,
    INTEGRITY_SCHEMA,
    R_CHAIN_BROKEN,
    R_KEY_UNKNOWN,
    R_NO_COLLECTOR_KEYS,
    R_PARTIAL_INTEGRITY,
    R_REORDER_BUDGET,
    R_REORDERED,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REPLAY,
    R_SIGNATURE_INVALID,
    RECEIPT_SCHEMA,
    Approval,
    CollectorKeyError,
    CollectorKeys,
    EffectReceipt,
    Integrity,
    StreamVerifier,
    arg_digest,
)
from cohaera.ingest import assemble
from cohaera.limits import (
    DEFAULT_LIMITS,
    DEFECT_APPROVAL_TYPE,
    DEFECT_INTEGRITY_TYPE,
    DEFECT_RECEIPT_TYPE,
)
from cohaera.model import Event, Session
from tools.collector_sign import key_id_for, keys_document, sign_stream

# ---------------------------------------------------------------------------
# 1. The crypto
# ---------------------------------------------------------------------------

# RFC 8032 section 7.1, all four published vectors. These are the only reason to
# believe the pure-Python implementation at all: it was written from the spec,
# and a scheme written from a spec and never checked against its vectors is a
# scheme that works on the author's examples.
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
     "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
     "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_rfc8032_vectors(sk, pk, msg, sig):
    sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
    assert ed25519.public_key(sk) == pk
    assert ed25519.sign(sk, msg) == sig
    assert ed25519.verify(pk, msg, sig)


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_a_flipped_bit_does_not_verify(sk, pk, msg, sig):
    pk, msg, sig = bytes.fromhex(pk), bytes.fromhex(msg), bytearray.fromhex(sig)
    for index in (0, 31, 32, 63):
        bad = bytearray(sig)
        bad[index] ^= 0x01
        assert not ed25519.verify(pk, msg, bytes(bad))


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_signature_malleability_is_rejected(sk, pk, msg, sig):
    """S >= L must not verify.

    The classic Ed25519 verifier bug, and it matters here specifically. Without
    this check, anyone can turn one valid signature into a second, different,
    also-valid signature over the same message -- so a signature would stop
    uniquely identifying the bytes that produced it, and an attacker could
    rewrite the ``sig`` field of a record whose chain they wanted intact.
    """
    pk, msg, sig = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
    s = int.from_bytes(sig[32:], "little")
    if s + ed25519.L >= 2**256:
        pytest.skip("this vector's S + L does not fit in 32 bytes")
    mutated = sig[:32] + (s + ed25519.L).to_bytes(32, "little")
    assert ed25519.verify(pk, msg, sig)
    assert not ed25519.verify(pk, msg, mutated)


def test_verify_never_raises_on_rubbish():
    """Malformed and invalid must produce the same verdict, not an exception.

    A scoring run must not die because one record carried a 3-byte signature.
    """
    pk = bytes.fromhex(RFC8032[1][1])
    for bad_key in (b"", b"\x00" * 31, b"\xff" * 32, None, "notbytes"):
        assert not ed25519.verify(bad_key, b"x", b"\x00" * 64)
    for bad_sig in (b"", b"\x00" * 63, None, 12345):
        assert not ed25519.verify(pk, b"x", bad_sig)


# ---------------------------------------------------------------------------
# 2. Parsing: malformed must read as ABSENT
# ---------------------------------------------------------------------------

GOOD_INTEGRITY = {"scheme": INTEGRITY_SCHEMA, "stream_id": "s1", "seq": 0,
                  "prev": "ab" * 32, "chain": "cd" * 32}
GOOD_RECEIPT = {"scheme": RECEIPT_SCHEMA, "authority": "aws:s3:eu-west-2",
                "kind": "object_version", "identifier": "3sL4kqtJ",
                "binding": {"span_id": "sp-1", "tool_id": "object_put",
                            "arg_digest": arg_digest({"key": "x"})}}
GOOD_APPROVAL = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
                 "subject": {"span_id": "sp-1", "tool_id": "object_put",
                             "arg_digest": arg_digest({"key": "x"})},
                 "granted_by": "user:alice", "granted_at": 10.0,
                 "expires_at": 100.0, "enforcement": "blocking"}


@pytest.mark.parametrize("mutation", [
    {"scheme": "cohaera.integrity:2"},      # a scheme this version cannot read
    {"scheme": None},
    {"stream_id": 17},                      # not a string
    {"stream_id": True},                    # bool is not a stream, even though
                                            # Python would happily index on it
    {"seq": -1},
    {"seq": True},                          # True == 1 aliasing, again
    {"seq": "0"},
    {"sig": "not base64!!"},
    {"sig": base64.b64encode(b"short").decode()},
])
def test_a_malformed_integrity_object_is_absent_not_weaker(mutation):
    obj = {**GOOD_INTEGRITY, **mutation}
    parsed, codes = Integrity.parse(obj, DEFAULT_LIMITS)
    assert parsed is None, f"{mutation} was accepted"
    assert DEFECT_INTEGRITY_TYPE in codes


@pytest.mark.parametrize("mutation", [
    {"scheme": "other"},
    {"authority": None},
    {"identifier": ""},
    {"binding": "sp-1"},                    # a string is not a binding
    {"binding": None},
])
def test_a_malformed_receipt_is_absent(mutation):
    parsed, codes = EffectReceipt.parse({**GOOD_RECEIPT, **mutation},
                                        DEFAULT_LIMITS)
    assert parsed is None
    assert DEFECT_RECEIPT_TYPE in codes


@pytest.mark.parametrize("mutation", [
    {"decision": "maybe"},
    {"decision": True},
    {"subject": {}},                        # names no span: binds to nothing
    {"subject": {"tool_id": "object_put"}},
    {"scheme": "cohaera.approval:0"},
])
def test_a_malformed_approval_is_absent(mutation):
    parsed, codes = Approval.parse({**GOOD_APPROVAL, **mutation}, DEFAULT_LIMITS)
    assert parsed is None
    assert DEFECT_APPROVAL_TYPE in codes


def test_an_unreadable_enforcement_degrades_to_undeclared_not_to_blocking():
    """The one place fail-closed would be wrong.

    Every other malformed field here fails towards MORE suspicion. This one
    fails towards less, on purpose: treating a bad value as ``blocking`` would
    let a producer's serialiser bug manufacture a critical finding, and a
    detector that a typo can make cry wolf is worse than one that stays quiet
    and records that it stayed quiet.
    """
    parsed, codes = Approval.parse({**GOOD_APPROVAL, "enforcement": "BLOCKING!"},
                                   DEFAULT_LIMITS)
    assert parsed is not None
    assert parsed.enforcement == "undeclared"
    assert codes


def test_an_unprefixed_digest_is_not_a_digest():
    """A bare hex string must not bind.

    Accepting one would compare unequal to everything Cohaera computes, which
    reads downstream as an attacker reusing an approval -- a producer's
    formatting choice turned into a security finding.
    """
    subject = {"span_id": "sp-1", "arg_digest": "a" * 64}
    parsed, _ = Approval.parse({**GOOD_APPROVAL, "subject": subject},
                               DEFAULT_LIMITS)
    assert parsed is not None and parsed.subject.arg_digest is None


def test_collector_key_file_is_refused_rather_than_half_loaded():
    for bad in (
        {"keys": {"k": "AAAA"}},                                # no scheme
        {"scheme": "cohaera.collector_keys:1", "keys": {}},     # empty
        {"scheme": "cohaera.collector_keys:1", "keys": {"k": "!!!"}},
        {"scheme": "cohaera.collector_keys:1",
         "keys": {"k": base64.b64encode(b"tooshort").decode()}},
    ):
        with pytest.raises(CollectorKeyError):
            CollectorKeys.from_obj(bad)


# ---------------------------------------------------------------------------
# 3. The stream verifier
# ---------------------------------------------------------------------------

SECRET = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUBLIC = ed25519.public_key(SECRET)
KEY_ID = key_id_for(PUBLIC)
KEYS = CollectorKeys.from_obj(keys_document(PUBLIC, KEY_ID))


def _records(n: int = 6, sid: str = "sess-1") -> list[dict]:
    return [{"event_type": "tool_start", "session_id": sid,
             "timestamp": 1000.0 + i, "span_id": f"sp-{i}",
             "tool_name": "alert_read", "data": {"action": "invoke_tool"}}
            for i in range(n)]


def _run(records: list[dict], keys=KEYS, limits=DEFAULT_LIMITS,
         order: list[int] | None = None) -> StreamVerifier:
    v = StreamVerifier(keys=keys, limits=limits)
    seq = order if order is not None else range(len(records))
    for i in seq:
        raw = records[i]
        e = Event(raw=raw, limits=limits)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    return v


def test_a_clean_signed_stream_verifies():
    signed = sign_stream(_records(), "stream-a", SECRET, KEY_ID)
    state = _run(signed).for_session("sess-1")
    assert not state.inadmissible
    assert state.signatures_verified == 6
    assert state.attested


def test_deleting_a_record_is_detected_as_a_gap():
    """E13's naive case, which before this was catchable only by accident.

    A deleted event was previously visible only when the missing call happened
    to break a learned bigram. A sequence with a hole in it is not luck.
    """
    signed = sign_stream(_records(), "stream-a", SECRET, KEY_ID)
    del signed[3]
    state = _run(signed).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert state.gaps == [{"missing_from": 3, "missing_to": 3, "missing_count": 1}]


def test_records_after_a_deletion_are_not_reported_as_reordered():
    """Found by running the CLI over a tampered stream, not by reading the code.

    Every record after a gap has to be held while the verifier waits for the one
    that never arrives, and counting them on release made a DELETION report
    ``INTEGRITY_RECORDS_REORDERED`` alongside its gap. To an analyst that reads
    as a delivery problem sitting next to a tamper signal, which is the one
    reading this check exists to prevent.
    """
    signed = sign_stream(_records(8), "stream-a", SECRET, KEY_ID)
    del signed[3]
    state = _run(signed).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert R_REORDERED not in state.codes
    assert state.reordered == 0


def test_one_deletion_does_not_read_as_a_wholly_forged_stream():
    """After a gap the verifier resyncs on the survivor's declared predecessor.

    Without that, every record after a deletion also fails to chain, one edit
    reads as total forgery, and -- worse -- the LOCATION of the edit is lost in
    the noise. Localising is half the value of a chain.
    """
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    del signed[4]
    state = _run(signed).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert not state.chain_breaks, "the surviving records should still chain"
    assert state.signatures_verified == 9


def test_modifying_a_record_breaks_the_chain_and_localises():
    signed = sign_stream(_records(), "stream-a", SECRET, KEY_ID)
    signed[2] = {**signed[2], "tool_name": "object_put"}
    state = _run(signed).for_session("sess-1")
    assert R_CHAIN_BROKEN in state.codes
    assert state.chain_breaks == [2], "the break must name the record that moved"


def test_reordering_is_reported_as_reordering_and_not_as_deletion():
    """The difference between a page at 3am and a healthy streaming path."""
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    state = _run(signed, order=[0, 2, 1, 3, 5, 4]).for_session("sess-1")
    assert R_SEQUENCE_GAP not in state.codes
    assert R_REORDERED in state.codes
    assert state.reordered == 2
    assert not state.inadmissible


def test_replaying_a_record_is_detected():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run([*signed, signed[1]]).for_session("sess-1")
    assert R_SEQUENCE_REPLAY in state.codes


def test_a_forged_signature_does_not_verify():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    sidecar = dict(signed[2]["integrity"])
    raw = bytearray(base64.b64decode(sidecar["sig"]))
    raw[10] ^= 0x01
    sidecar["sig"] = base64.b64encode(bytes(raw)).decode()
    signed[2] = {**signed[2], "integrity": sidecar}
    state = _run(signed).for_session("sess-1")
    assert R_SIGNATURE_INVALID in state.codes
    assert state.bad_signatures == [2]


def test_a_key_the_operator_did_not_supply_is_not_trusted():
    other = ed25519.public_key(bytes.fromhex("11" * 32))
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=CollectorKeys.from_obj(
        keys_document(other, "ed25519:someone-else"))).for_session("sess-1")
    assert R_KEY_UNKNOWN in state.codes
    assert state.signatures_verified == 0


def test_without_keys_signatures_are_parsed_and_not_verified():
    """And that state is NAMED, rather than looking like a pass."""
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=CollectorKeys()).for_session("sess-1")
    assert R_NO_COLLECTOR_KEYS in state.codes
    assert state.signatures_verified == 0
    assert not state.inadmissible, "unverified is not the same as failed"


def test_stripping_the_sidecar_from_the_edited_record_is_itself_detected():
    """The obvious way round a chain, closed.

    A record with no integrity object cannot fail a chain check, so an attacker
    who edits one record would simply delete its sidecar. A session where some
    records are attested and others are not is that shape, and it is reported.
    """
    signed = sign_stream(_records(5), "stream-a", SECRET, KEY_ID)
    signed[2] = {k: v for k, v in signed[2].items() if k != "integrity"}
    state = _run(signed).for_session("sess-1")
    assert R_PARTIAL_INTEGRITY in state.codes
    assert state.inadmissible


def test_the_reorder_buffer_is_bounded_and_says_when_the_bound_decided():
    """A producer chooses how far out of order it delivers. That is a budget.

    When the bound forces the call rather than the evidence, the verdict has to
    say which of the two it was, or a bound becomes an undeclared heuristic.
    """
    limits = DEFAULT_LIMITS.with_overrides(max_reorder_window=2)
    signed = sign_stream(_records(8), "stream-a", SECRET, KEY_ID)
    state = _run(signed, limits=limits,
                 order=[0, 5, 6, 7, 1, 2, 3, 4]).for_session("sess-1")
    assert R_REORDER_BUDGET in state.codes
    assert R_SEQUENCE_GAP in state.codes


def test_the_signature_budget_is_bounded():
    """Verification is 5ms of scalar multiplication per record and the producer
    decides how many records there are."""
    limits = DEFAULT_LIMITS.with_overrides(max_signature_verifications=2)
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    v = _run(signed, limits=limits)
    assert v.signatures_verified == 2
    assert v.signature_budget_exhausted


def test_joining_a_stream_midway_is_declared_rather_than_assumed():
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    state = _run(signed[3:]).for_session("sess-1")
    assert "INTEGRITY_STREAM_JOINED_MIDSTREAM" in state.codes
    assert not state.inadmissible, "records before the join are absent, not bad"


def test_integrity_is_verified_in_arrival_order_not_clock_order():
    """Sessions are assembled clock-sorted; streams are written in arrival order.

    Verifying over the sorted list would reorder the stream before checking
    whether it had been reordered, so any clock skew in the input would read as
    a delivery fault. This record set is signed in arrival order and carries a
    deliberately out-of-order clock.
    """
    records = _records(5)
    records[1]["timestamp"] = 9999.0            # a skewed clock, not a reorder
    signed = sign_stream(records, "stream-a", SECRET, KEY_ID)
    events = [Event(raw=r) for r in signed]
    sessions = assemble(events, keys=KEYS)
    assert len(sessions) == 1
    assert not sessions[0].integrity.inadmissible
    assert sessions[0].integrity.signatures_verified == 5


# ---------------------------------------------------------------------------
# 4. Approval binding and the CH04 split
# ---------------------------------------------------------------------------

ARGS = {"recipient": "alice@example.com"}
OTHER_ARGS = {"recipient": "attacker@example.net"}


def _session(*, enforcement: str | None, approval: dict | None = None,
             call_args: dict | None = None,
             manifest: CapabilityManifest | None = None) -> Session:
    """A policy event, then one consequential call that completed."""
    policy: dict = {"event_type": "cost_threshold_exceeded", "session_id": "s",
                    "timestamp": 100.0,
                    "data": {"action": "policy_event", "threshold_usd": 0.5,
                             "policy_id": "cost-guard"}}
    if enforcement is not None:
        policy["data"]["enforcement"] = enforcement
    if approval is not None:
        policy["data"]["approval"] = approval
    start = {"event_type": "tool_start", "session_id": "s", "timestamp": 110.0,
             "span_id": "sp-send", "tool_name": "send_email",
             "data": {"action": "invoke_tool", "reversible": False,
                      "tool_args": call_args if call_args is not None else ARGS}}
    end = {"event_type": "tool_end", "session_id": "s", "timestamp": 111.0,
           "span_id": "sp-send", "tool_name": "send_email",
           "data": {"action": "invoke_tool", "result": "success"}}
    s = Session(session_id="s", events=[Event(raw=r) for r in (policy, start, end)],
                manifest=manifest or CapabilityManifest())
    s.seal()
    return s


def _approval(**kw) -> dict:
    base = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
            "subject": {"span_id": "sp-send", "tool_id": "send_email",
                        "arg_digest": arg_digest(ARGS)},
            "granted_by": "user:alice", "granted_at": 100.0, "expires_at": 200.0}
    base.update(kw)
    return base


def test_an_advisory_control_no_longer_fires_at_all():
    """The corpus's largest single source of false positives, closed by a field.

    An advisory threshold is a notification and continuing past it is the
    intended behaviour. Firing on it was never a detection -- it was Cohaera
    not having been told what the control was for.
    """
    assert ch04_guardrail_overrun(_session(enforcement="advisory")) == []


def test_a_blocking_control_with_no_approval_is_a_bypass_and_may_say_so():
    findings = ch04_guardrail_overrun(_session(enforcement="blocking"))
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert "bypassed" in findings[0].title.lower()
    assert findings[0].evidence["approval_states"] == ["no_approval"]


def test_a_blocking_control_with_a_bound_approval_does_not_fire():
    findings = ch04_guardrail_overrun(
        _session(enforcement="blocking", approval=_approval()))
    assert findings == []


def test_an_approval_for_different_arguments_does_not_cover_the_call():
    """The whole mechanism, in one test.

    An approval for send_email to alice must not cover send_email to an
    attacker. Before argument binding, nothing stopped it -- and the two calls
    are indistinguishable at the span and tool level, which is exactly why
    span-only binding is reported as the weaker thing it is.
    """
    s = _session(enforcement="blocking", approval=_approval(),
                 call_args=OTHER_ARGS)
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == ["approval_for_other_arguments"]


def test_an_expired_approval_is_not_an_approval():
    s = _session(enforcement="blocking",
                 approval=_approval(granted_at=1.0, expires_at=50.0))
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == ["approval_expired"]


def test_an_explicit_denial_is_a_bypass_even_on_an_advisory_control():
    """A refusal naming the exact call outranks the control's own semantics.

    An advisory notice is a suggestion. A DENY bound to this span and these
    arguments is not, and a completed call after one is the policy engine being
    overruled whatever the threshold was for.
    """
    s = _session(enforcement="advisory", approval=_approval(decision="deny"))
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == ["denied"]


def test_undeclared_semantics_keep_the_old_check_and_the_old_wording():
    """Backwards compatibility is a security property here.

    Every deployment that emits nothing new must behave exactly as it did, or
    upgrading Cohaera silently changes what an existing Sigma rule matches.
    """
    findings = ch04_guardrail_overrun(_session(enforcement=None))
    assert [f.check for f in findings] == [CH04_COMPLETED]
    assert "carries no declaration of policy semantics" in findings[0].detail


def test_the_manifest_outranks_an_in_band_advisory_claim():
    """EVASION.md E20, and the answer to it.

    ``enforcement`` arrives in band, and a value of ``advisory`` SUPPRESSES a
    finding, so an agent that wanted CH04 quiet would send it. An operator's
    manifest declaration wins, for the same reason and with the same precedence
    as a tool capability.
    """
    manifest = CapabilityManifest.from_obj({
        "tools": {"send_email": {"effects": ["egress"], "reversible": False}},
        "policies": {"cost-guard": {"enforcement": "blocking"}},
    })
    findings = ch04_guardrail_overrun(
        _session(enforcement="advisory", manifest=manifest))
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["policy_enforcement_source"] == "manifest"


def test_believing_an_in_band_declaration_costs_confidence_and_says_why():
    s = _session(enforcement="blocking")
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH04_guardrail_overrun")
    assert "POLICY_ENFORCEMENT_DECLARED_IN_BAND" in contract["reasons"]
    assert contract["confidence"] < 1.0


def test_a_dangling_approval_is_reported():
    s = _session(enforcement="blocking", approval=_approval(
        subject={"span_id": "sp-nonexistent", "tool_id": "send_email"}))
    assert len(s.dangling_approvals) == 1
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH04_guardrail_overrun")
    assert "APPROVAL_MATCHES_NO_CALL" in contract["reasons"]


# ---------------------------------------------------------------------------
# 5. CH07: the asymmetry
# ---------------------------------------------------------------------------


def _call_session(result: str, receipt: dict | None,
                  call_args: dict | None = None) -> Session:
    start = {"event_type": "tool_start", "session_id": "s", "timestamp": 10.0,
             "span_id": "sp-1", "tool_name": "send_email",
             "data": {"action": "invoke_tool", "reversible": False,
                      "tool_args": call_args if call_args is not None else ARGS}}
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
    base = {"scheme": RECEIPT_SCHEMA, "authority": "smtp:mail.example.com",
            "kind": "message_id", "identifier": "<abc@example.com>",
            "binding": {"span_id": "sp-1", "tool_id": "send_email",
                        "arg_digest": arg_digest(ARGS)}}
    base.update(kw)
    return base


def test_a_reported_failure_with_a_bound_receipt_is_a_detection():
    """The only check here that catches a lying emitter rather than routing
    around one: two fields of the same record disagree, and one of them is not
    the agent's to choose."""
    findings = ch07_effect_contradiction(_call_session("failure", _receipt()))
    assert [f.check for f in findings] == [CH07_CONTRADICTED]
    assert findings[0].severity == "critical"


def test_a_reported_success_with_a_receipt_is_not_a_finding():
    assert ch07_effect_contradiction(_call_session("success", _receipt())) == []


def test_a_reported_success_with_no_receipt_is_coverage_and_not_a_finding():
    """Receipts do not make ``success`` more believable. A finding per
    receiptless call would be a pager storm on day one of any real deployment,
    and it would be a finding about the deployment rather than the agent."""
    s = _call_session("success", None)
    assert ch07_effect_contradiction(s) == []
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH07_effect_contradiction")
    assert contract["status"] == "not_evaluated"
    assert contract["reasons"] == ["NO_EFFECT_RECEIPT"]


def test_a_receipt_copied_onto_another_call_does_not_bind():
    """Without this the mechanism is decorative: a receipt from a call that
    really happened, pasted onto one that did not."""
    stolen = _receipt(binding={"span_id": "sp-99", "tool_id": "send_email",
                               "arg_digest": arg_digest(ARGS)})
    findings = ch07_effect_contradiction(_call_session("failure", stolen))
    assert [f.check for f in findings] == [CH07_UNBOUND]


def test_a_receipt_for_different_arguments_does_not_bind():
    findings = ch07_effect_contradiction(
        _call_session("failure", _receipt(), call_args=OTHER_ARGS))
    assert [f.check for f in findings] == [CH07_UNBOUND]


# ---------------------------------------------------------------------------
# 6. Evidence status, CH06, and what the whole design still cannot do
# ---------------------------------------------------------------------------


def test_a_session_with_no_integrity_evidence_is_unattested_not_verified():
    """The default state of every deployment, and the sentence that matters.

    ``unattested`` does not mean tampering was ruled out. It means nothing was
    ever in a position to rule it in.
    """
    s = _call_session("success", None)
    assert evidence_status(s) == EVIDENCE_UNATTESTED
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == CH06_INTEGRITY)
    assert contract["status"] == "not_evaluated"
    assert contract["confidence"] == 0.0


def test_every_finding_carries_how_far_the_evidence_was_established():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    del signed[2]
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    findings, _ = run_all(sessions[0])
    checks = {f.check for f in findings}
    assert CH06_INTEGRITY in checks
    for f in findings:
        # CH06 is exempt: it IS the statement that the evidence failed, and
        # marking it as resting on failed evidence would be circular.
        expected = (EVIDENCE_VERIFIED if f.check == CH06_INTEGRITY
                    else EVIDENCE_INADMISSIBLE)
        assert f.evidence_status == expected


def test_ch06_stays_quiet_on_a_stream_that_verifies():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    assert ch06_evidence_integrity(sessions[0]) == []
    assert evidence_status(sessions[0]) == EVIDENCE_VERIFIED


def test_a_collector_inside_the_agent_gains_nothing_and_the_contract_says_so():
    """The honest limit, asserted so it cannot be quietly dropped later.

    If the signer is reachable from the agent, a perfectly verified stream is a
    perfectly verified stream of whatever the agent chose to say. The coverage
    assumption is the only place a reader is told that.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    contract = next(c for c in coverage(sessions[0], None)["checks"]
                    if c["check"] == CH06_INTEGRITY)
    assert any("blast radius" in a for a in contract["assumptions"])
    assert any("does not say the collector was truthful" in a
               for a in contract["assumptions"])


def test_the_reference_signer_round_trips_through_the_cli(tmp_path):
    """The wire format has a producer, and it is checked against the verifier.

    A format with no reference producer is a specification nobody can implement
    against.
    """
    raw = tmp_path / "raw.jsonl"
    raw.write_text("".join(json.dumps(r) + "\n" for r in _records(4)),
                   encoding="utf-8")
    signed = sign_stream(
        [json.loads(x) for x in raw.read_text(encoding="utf-8").splitlines()],
        "stream-cli", SECRET, KEY_ID)
    out = tmp_path / "signed.jsonl"
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in signed),
                   encoding="utf-8")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(json.dumps(keys_document(PUBLIC, KEY_ID)),
                         encoding="utf-8")

    loaded = CollectorKeys.from_file(keys_path)
    events = [Event(raw=json.loads(line))
              for line in out.read_text(encoding="utf-8").splitlines()]
    sessions = assemble(events, keys=loaded)
    assert sessions[0].integrity.signatures_verified == 4
    assert not sessions[0].integrity.inadmissible
