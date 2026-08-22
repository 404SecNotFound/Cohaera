"""E26. What an approval is worth, and what makes it worth more.

Written BEFORE the implementation, as the contract the fix has to satisfy.
EVASION.md E26 has four parts and three of them are open:

  1. a VERBATIM copy is already refused -- the span binding does it (E26b);
  2. rewriting `subject.span_id` makes the approval cover a call it was never
     issued for, because nothing signs the approval body;
  3. the same approval works forever, because nothing records it as spent;
  4. it also works with no validity window at all, because the window is
     optional and `covers_clock` returns None rather than False.

The design these tests pin, and the reasoning is load-bearing:

TIERS, NOT A BOOLEAN. Requiring signatures outright would stop every existing
deployment's approvals from covering anything, and CH04 would fire on every
authorised action in the world. Approval assurance is therefore tiered exactly
as receipt trust is (RECEIPT_CLAIMED..RECEIPT_RECONCILED), the verdict reports
which tier it got, and the operator decides whether a low tier still covers.

A NONCE WITHOUT A SIGNATURE IS DECORATION. An attacker who can rewrite
`subject.span_id` can rewrite `nonce` in the same edit. Single-use is therefore
only reachable ON TOP OF an authenticated approval, and that ordering is
asserted rather than assumed.

A SIGNED APPROVAL MUST BE BOUNDED. Rather than a flag saying "also require a
window", the signature covers `expires_at`, and an approval that is signed
without one does not verify. An issuer cannot mint an eternal signed approval.

Run: PYTHONPATH=src python3 -m pytest tests/test_approval_trust.py -v
"""

from __future__ import annotations

import base64
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera import ed25519
from cohaera.capabilities import CapabilityManifest
from cohaera.checks import ch04_guardrail_overrun
from cohaera.evidence import (
    APPROVAL_AUTHENTICATED,
    APPROVAL_BOUND,
    APPROVAL_CLAIMED,
    APPROVAL_SCHEMA,
    APPROVAL_SINGLE_USE,
    APPROVAL_TRUSTED_TIERS,
    ROLE_APPROVAL,
    ROLE_COLLECTOR,
    TRUST_STORE_SCHEMA,
    VALID_ROLES,
    Approval,
    ApprovalLedger,
    TrustStore,
    approval_signing_input,
    arg_digest,
    verify_approval,
)
from cohaera.model import Event, Session


def b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


BASE_T = 1_785_740_000.0
ARGS = {"amount_usd": 250, "to": "acct-1188"}
DIGEST = arg_digest(ARGS)


def _approval(**kw):
    base = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
            "subject": {"span_id": "AP1", "tool_id": "wire_transfer_send",
                        "arg_digest": DIGEST},
            "granted_by": "user:alice"}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# The tier vocabulary
# ---------------------------------------------------------------------------

def test_the_four_tiers_exist_and_are_ordered():
    assert [APPROVAL_CLAIMED, APPROVAL_BOUND, APPROVAL_AUTHENTICATED,
            APPROVAL_SINGLE_USE] == ["claimed", "bound", "authenticated",
                                     "single_use"]


def test_only_the_top_two_tiers_are_trusted():
    """A bound approval proves the approval is ABOUT this call. It never
    proves the approval is genuine, which is the whole of E26 point 2."""
    assert APPROVAL_TRUSTED_TIERS == frozenset(
        {APPROVAL_AUTHENTICATED, APPROVAL_SINGLE_USE})
    assert APPROVAL_CLAIMED not in APPROVAL_TRUSTED_TIERS
    assert APPROVAL_BOUND not in APPROVAL_TRUSTED_TIERS


def test_the_trust_store_gained_an_approval_issuer_role():
    """Approvals are issued by a different party from the one that signs
    telemetry. One key doing both jobs is a weakened deployment and the store
    has to be able to express the difference."""
    assert ROLE_APPROVAL == "approval"
    assert ROLE_APPROVAL in VALID_ROLES


# ---------------------------------------------------------------------------
# Point 4 -- the window
# ---------------------------------------------------------------------------

def test_an_unsigned_approval_still_parses_with_no_window():
    """Unchanged behaviour, asserted so the change is visibly additive.
    Existing deployments do not break."""
    appr, codes = Approval.parse(_approval())
    assert appr is not None and not codes
    assert appr.covers_clock(100.0) is None


def test_a_signed_approval_without_an_expiry_does_not_verify():
    """E26 point 4, closed by construction rather than by a flag. The
    signature covers expires_at, so an approval signed without one cannot
    produce a valid signature over anything."""
    appr, _ = Approval.parse(_approval(
        nonce="n-1", signature={"key_id": "k1", "sig": "00" * 64}))
    assert appr is not None
    assert appr.tier == APPROVAL_BOUND, (
        "an approval with a signature but no window must not reach "
        "authenticated, whatever the signature says")


# ---------------------------------------------------------------------------
# Point 2 -- the signature
# ---------------------------------------------------------------------------

def test_the_signing_input_covers_every_field_an_attacker_would_rewrite():
    """The span is the field E26 rewrites. If the signing input did not cover
    it, the whole mechanism would be decoration -- so this asserts the bytes
    change when each covered field changes."""
    base = approval_signing_input(
        decision="allow", span_id="AP1", tool_id="wire_transfer_send",
        arg_digest=DIGEST, nonce="n-1", granted_at=100.0, expires_at=200.0)
    for field, value in (("span_id", "AP2"), ("tool_id", "other"),
                         ("arg_digest", "0" * 64), ("nonce", "n-2"),
                         ("decision", "deny"), ("granted_at", 101.0),
                         ("expires_at", 201.0)):
        kw = {"decision": "allow", "span_id": "AP1",
              "tool_id": "wire_transfer_send", "arg_digest": DIGEST,
              "nonce": "n-1", "granted_at": 100.0, "expires_at": 200.0}
        kw[field] = value
        assert approval_signing_input(**kw) != base, (
            f"rewriting {field} does not change the signing input")


def test_the_signing_input_is_field_separated_not_json():
    """Canonicalisation problems are where signature bugs live. A fixed field
    list separated by an octet that cannot appear in a validated identity beats
    canonical JSON, and this pins that choice."""
    blob = approval_signing_input(
        decision="allow", span_id="AP1", tool_id="t", arg_digest=DIGEST,
        nonce="n", granted_at=1.0, expires_at=2.0)
    assert isinstance(blob, bytes)
    assert blob.startswith(APPROVAL_SCHEMA.encode())
    assert b"\x1f" in blob
    assert not blob.lstrip().startswith(b"{")


# ---------------------------------------------------------------------------
# Point 3 -- the ledger
# ---------------------------------------------------------------------------

def test_a_disabled_ledger_reports_rather_than_pretends():
    led = ApprovalLedger()
    assert led.enabled is False
    assert led.spend("n-1") is None, (
        "with no ledger there is no answer, and None is not False")


def test_a_nonce_is_spent_once(tmp_path):
    led = ApprovalLedger(path=tmp_path / "approvals.json")
    assert led.enabled is True
    assert led.spend("n-1") is True
    assert led.spend("n-1") is False, "the second use must be refused"
    assert led.spend("n-2") is True


def test_the_ledger_survives_a_reload(tmp_path):
    """E26 point 3 is a CROSS-SESSION replay. A ledger that forgets between
    runs closes nothing."""
    path = tmp_path / "approvals.json"
    first = ApprovalLedger(path=path)
    assert first.spend("n-1") is True
    first.save()
    assert ApprovalLedger(path=path).spend("n-1") is False, (
        "a ledger that forgets between runs closes nothing: E26 point 3 is a "
        "CROSS-SESSION replay")
    # And a ledger with nothing to record does not rewrite the file.
    untouched = ApprovalLedger(path=path)
    untouched.save()
    assert ApprovalLedger(path=path).spend("n-1") is False


def test_a_nonce_is_only_honoured_on_an_authenticated_approval():
    """The ordering that makes the nonce mean anything. An attacker who can
    rewrite the span can rewrite the nonce in the same edit, so single-use is
    reachable only on top of a verified signature."""
    appr, _ = Approval.parse(_approval(nonce="n-1"))
    assert appr is not None
    assert appr.nonce == "n-1"
    assert appr.tier == APPROVAL_BOUND, (
        "an unsigned approval carrying a nonce must not reach single_use")


# ---------------------------------------------------------------------------
# End to end, against a real key. These are the tests that decide whether E26
# is closed, and the ones above only decide whether the parts exist.
# ---------------------------------------------------------------------------

SEED = bytes(range(32))
KEY_ID = "issuer-1"


def _store(role: str = ROLE_APPROVAL):
    return TrustStore.from_obj({
        "scheme": TRUST_STORE_SCHEMA,
        "keys": {KEY_ID: {"roles": [role],
                          "key": b64(ed25519.public_key(SEED))}}})


def _signed(**over):
    """A genuinely signed approval for span AP1."""
    # A window that straddles the calls in these fixtures. An approval whose
    # window has closed is refused by `fresh`, which is a different mechanism
    # from the one under test and would mask it.
    fields = {"decision": "allow", "span_id": "AP1",
              "tool_id": "wire_transfer_send", "arg_digest": DIGEST,
              "nonce": "n-1", "granted_at": BASE_T - 100.0,
              "expires_at": BASE_T + 3600.0}
    fields.update(over)
    sig = ed25519.sign(SEED, approval_signing_input(**fields))
    obj = _approval(
        subject={"span_id": fields["span_id"], "tool_id": fields["tool_id"],
                 "arg_digest": fields["arg_digest"]},
        decision=fields["decision"], nonce=fields["nonce"],
        granted_at=fields["granted_at"], expires_at=fields["expires_at"],
        signature={"key_id": KEY_ID, "sig": b64(sig)})
    appr, codes = Approval.parse(obj)
    assert appr is not None and not codes
    return appr


def test_a_genuine_signature_reaches_authenticated():
    appr = verify_approval(_signed(), _store())
    assert appr.verified is True
    assert appr.tier == APPROVAL_AUTHENTICATED
    assert appr.trusted is True


def test_E26_POINT_2_rewriting_the_span_now_invalidates_the_approval():
    """THE CLOSURE. This is the one field EVASION.md E26 rewrites, and the
    entire mechanism exists to make that edit detectable."""
    appr = _signed()
    moved = replace(appr, subject=replace(appr.subject, span_id="AP2"))
    checked = verify_approval(moved, _store())
    assert checked.verified is False
    assert checked.tier == APPROVAL_BOUND
    assert checked.trusted is False, (
        "E26 point 2 has reopened: a re-pointed approval verified")


def test_a_signature_from_a_key_without_the_approval_role_does_not_count():
    """A collector key signing approvals is one party doing both jobs, which
    is the arrangement the signature exists to rule out."""
    appr = verify_approval(_signed(), _store(role=ROLE_COLLECTOR))
    assert appr.verified is False
    assert appr.tier == APPROVAL_BOUND


def test_with_no_trust_store_a_signed_approval_stays_bound():
    """Every deployment starts here. It must not break, and it must not be
    silently upgraded either."""
    appr = verify_approval(_signed(), TrustStore.from_obj({
        "scheme": TRUST_STORE_SCHEMA,
        "keys": {"collector-only": {
            "roles": [ROLE_COLLECTOR],
            "key": b64(ed25519.public_key(bytes(range(1, 33))))}}}))
    assert appr.verified is False
    assert appr.tier == APPROVAL_BOUND


def test_E26_POINT_3_the_second_use_of_a_nonce_is_refused(tmp_path):
    """Cross-session replay. Same signed approval, twice, through a ledger
    that persisted in between."""
    path = tmp_path / "approvals.json"
    store = _store()

    first_led = ApprovalLedger(path=path)
    first = verify_approval(_signed(), store)
    first = replace(first, unspent=first_led.spend(first.nonce))
    assert first.tier == APPROVAL_SINGLE_USE
    first_led.save()

    # A different run, a different session, thirty days later.
    second = verify_approval(_signed(), store)
    second = replace(second, unspent=ApprovalLedger(path=path).spend(second.nonce))
    assert second.unspent is False
    assert second.tier == APPROVAL_AUTHENTICATED, (
        "a replayed nonce must fall back to authenticated, not climb to "
        "single_use")


def test_E26_POINT_4_an_eternal_approval_cannot_be_signed():
    """The window is closed by construction rather than by a flag: the signing
    input covers expires_at, so there is no valid signature over an approval
    that declares none."""
    fields = {"decision": "allow", "span_id": "AP1",
              "tool_id": "wire_transfer_send", "arg_digest": DIGEST,
              "nonce": "n-1", "granted_at": 100.0, "expires_at": None}
    sig = ed25519.sign(SEED, approval_signing_input(**fields))
    appr, _ = Approval.parse(_approval(
        nonce="n-1", granted_at=100.0,
        signature={"key_id": KEY_ID, "sig": b64(sig)}))
    assert appr is not None
    assert appr.signable is False, "no expiry means nothing to verify"
    assert verify_approval(appr, _store()).tier == APPROVAL_BOUND


def test_an_unsigned_approval_is_unaffected_by_any_of_this():
    """The additive guarantee. Existing deployments keep exactly what they
    had, and the verdict says what tier that is."""
    appr, _ = Approval.parse(_approval())
    checked = verify_approval(appr, _store())
    assert checked.tier == APPROVAL_BOUND
    assert checked.trusted is False


def test_an_unsigned_approval_cannot_reach_single_use_even_with_a_fresh_nonce():
    """THE INVARIANT THE WHOLE DESIGN RESTS ON, and it survived a mutation
    until this test existed.

    An attacker who can rewrite `subject.span_id` -- which is E26 point 2, and
    free -- can rewrite `nonce` in the same edit. So a nonce presented on an
    UNSIGNED approval says nothing at all, and a ledger that has never seen it
    before says nothing either. Single-use has to sit on top of a verified
    signature or it is theatre.

    Asserted by constructing the exact state a careless implementation would
    reach: unspent=True, verified=False.
    """
    appr, _ = Approval.parse(_approval(nonce="never-seen-before"))
    assert appr is not None
    fresh_nonce = replace(appr, unspent=True, verified=False)
    assert fresh_nonce.tier == APPROVAL_BOUND, (
        "an unsigned approval reached single_use on the strength of a nonce "
        "the attacker chose")
    assert fresh_nonce.trusted is False


def test_a_verified_approval_with_no_ledger_stays_authenticated():
    """None is not True. A deployment with no ledger has no memory, and
    reporting 'no memory' as 'unspent' would hand every such deployment a
    single-use guarantee it never earned."""
    appr = verify_approval(_signed(), _store())
    assert appr.unspent is None
    assert appr.tier == APPROVAL_AUTHENTICATED


# ---------------------------------------------------------------------------
# Session level. The evidence layer closing is necessary and not sufficient --
# what matters is whether CH04 fires on the replayed call.
# ---------------------------------------------------------------------------

def _ev(sid, ts, etype, **data):
    return Event(raw={"event_id": f"{sid}-{ts}", "timestamp": ts,
                      "session_id": sid, "trace_id": sid,
                      "span_id": data.pop("span_id", None),
                      "event_type": etype, "agent_name": "payments-agent",
                      "tool_name": data.pop("tool_name", None),
                      "host": "h", "user": "u", "data": data})


def _replay_session(*, store=None, ledger=None, require=False):
    """The E26 attack: an approval issued for AP1, re-pointed at AP2."""
    appr = _signed()
    moved = replace(appr, subject=replace(appr.subject, span_id="AP2"))
    raw = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
           "subject": {"span_id": "AP2", "tool_id": "wire_transfer_send",
                       "arg_digest": DIGEST},
           "granted_by": "user:alice", "nonce": moved.nonce,
           "granted_at": moved.granted_at, "expires_at": moved.expires_at,
           "signature": {"key_id": KEY_ID, "sig": b64(moved.signature)}}
    events = [
        _ev("e26", BASE_T, "cost_threshold_exceeded", action="policy_event",
            policy_id="payments-guard", enforcement="blocking",
            approval=raw),
        _ev("e26", BASE_T + 10, "tool_start", span_id="AP2",
            tool_name="wire_transfer_send", tool_args=ARGS,
            arg_digest=DIGEST, reversible=False),
        _ev("e26", BASE_T + 11, "tool_end", span_id="AP2",
            tool_name="wire_transfer_send", result="success"),
    ]
    manifest = CapabilityManifest.from_obj({
        "tools": {"wire_transfer_send": {"effects": ["egress"],
                                         "reversible": False}},
        "policies": {"payments-guard": {"enforcement": "blocking"}}})
    return Session(session_id="e26", manifest=manifest, events=events,
                   trust_store=store, approval_ledger=ledger,
                   require_signed_approvals=require)


def test_by_default_the_replayed_approval_still_covers():
    """E26 stays OPEN in a default deployment, and that is the honest state.
    Requiring signatures unconditionally would fire CH04 on every authorised
    action in every deployment that has not issued keys -- which is all of
    them, on day one."""
    s = _replay_session()
    assert s.covering_approval(s.consequential_calls[0]) is not None
    assert ch04_guardrail_overrun(s) == []


def test_with_keys_and_the_flag_the_rewritten_span_no_longer_covers():
    """THE CLOSURE, at the level that matters. The approval was issued for
    AP1; the call is AP2; the signature covers the span, so the edit that
    defeats binding also breaks the signature."""
    s = _replay_session(store=_store(), require=True)
    assert s.covering_approval(s.consequential_calls[0]) is None
    assert [f.check for f in ch04_guardrail_overrun(s)] == [
        "CH04_blocking_control_bypassed"]


def test_a_genuine_approval_still_covers_with_the_flag_on():
    """The other half, and the one that decides whether this is deployable.
    Turning the flag on must not break correctly-signed approvals."""
    appr = _signed()
    raw = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
           "subject": {"span_id": "AP1", "tool_id": "wire_transfer_send",
                       "arg_digest": DIGEST},
           "granted_by": "user:alice", "nonce": appr.nonce,
           "granted_at": appr.granted_at, "expires_at": appr.expires_at,
           "signature": {"key_id": KEY_ID, "sig": b64(appr.signature)}}
    events = [
        _ev("ok", BASE_T, "cost_threshold_exceeded", action="policy_event",
            policy_id="payments-guard", enforcement="blocking", approval=raw),
        _ev("ok", BASE_T + 10, "tool_start", span_id="AP1",
            tool_name="wire_transfer_send", tool_args=ARGS,
            arg_digest=DIGEST, reversible=False),
        _ev("ok", BASE_T + 11, "tool_end", span_id="AP1",
            tool_name="wire_transfer_send", result="success"),
    ]
    manifest = CapabilityManifest.from_obj({
        "tools": {"wire_transfer_send": {"effects": ["egress"],
                                         "reversible": False}},
        "policies": {"payments-guard": {"enforcement": "blocking"}}})
    s = Session(session_id="ok", manifest=manifest, events=events,
                trust_store=_store(), require_signed_approvals=True)
    assert s.covering_approval(s.consequential_calls[0]) is not None
    assert ch04_guardrail_overrun(s) == []
    assert s.approval_tier(s.approvals[0]) == APPROVAL_AUTHENTICATED
