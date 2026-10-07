"""``ApprovalIssuer``: mint ``cohaera.approval:1`` objects the verifier trusts.

An approval is worth exactly what its tier says (``cohaera.evidence``,
``APPROVAL_CLAIMED`` through ``APPROVAL_SINGLE_USE``), and until an issuer
signs one every field in it was written by the producer. EVASION.md E26 is the
consequence: rewrite ``subject.span_id`` and an approval covers a call it was
never granted for. The signature is what closes that, and this is the
signature's producer.

THREE RULES, ALL IN THE SIGNING INPUT RATHER THAN IN A FLAG:

    bound       The subject names the span, the tool AND the argument digest.
                An approval for ``send_email`` that does not say to whom is an
                approval for ``send_email`` to anyone (R-10), so the issuer
                refuses to sign without a digest. Give it the call's arguments
                and it computes one with ``cohaera.evidence.arg_digest``, the
                same function the verifier recomputes with.
    bounded     ``expires_at`` is required. ``approval_signing_input`` covers
                it, and ``Approval.signable`` is false without it, so an
                eternal signed approval is not a thing this issuer can mint --
                ``tests/test_approval_trust.py`` pins that from the verifier's
                side and ``tests/test_emit.py`` from this one.
    fresh       Every approval carries a nonce from ``secrets``, so a ledger
                (``--seen-approvals``) can refuse the second presentation.
                The nonce is covered by the signature; a spent approval cannot
                be re-minted by rewriting it.

WHO HOLDS THIS KEY. Not the collector and not the agent. The trust store gives
an issuer the ``approval`` role and ``verify_approval`` refuses any other, so a
collector key signing approvals buys nothing: one party doing both jobs is the
arrangement the signature exists to rule out.
"""

from __future__ import annotations

import base64
import secrets
import time
from typing import Any

from .. import ed25519
from ..evidence import (
    APPROVAL_SCHEMA,
    VALID_DECISIONS,
    VALID_ENFORCEMENT,
    Approval,
    approval_signing_input,
    arg_digest,
    digest_text,
)
from ._fields import finite, identity, optional_identity

_UNSET: Any = object()


def _digest(value: Any, name: str) -> str:
    text = digest_text(value)
    if text is None:
        raise ValueError(f"{name} must be 'sha256:' followed by 64 hex characters, "
                         f"as cohaera.evidence.arg_digest produces")
    return text


def subject_digest(*, arg_digest_text: str | None = None,
                   tool_args: Any = _UNSET) -> str:
    """The argument digest an approval or receipt binds to.

    Takes a declared digest, the arguments themselves, or both -- and when both
    are given they must agree. F-01: a call whose declared digest contradicts
    its captured arguments is unbindable on the verifier side, and an issuer
    that signed the declared one would be attesting a call the telemetry
    cannot agree on.
    """
    declared = None if arg_digest_text is None else _digest(arg_digest_text, "arg_digest")
    computed = None if tool_args is _UNSET else arg_digest(tool_args)
    if declared is None and computed is None:
        raise ValueError(
            "an approval must bind to the call's arguments: give arg_digest or "
            "tool_args. One that does not covers the tool with any arguments at "
            "all, which is EVASION.md E26 with the signature left on")
    if declared is not None and computed is not None and declared != computed:
        raise ValueError(
            f"arg_digest {declared} does not match the digest of tool_args "
            f"({computed}); refusing to sign an approval for a call the "
            f"arguments and the digest disagree about")
    return declared if declared is not None else str(computed)


class ApprovalIssuer:
    """Sign approvals with an ``approval``-role key."""

    def __init__(self, private_key: bytes, key_id: str) -> None:
        if not isinstance(private_key, bytes) or len(private_key) != ed25519.KEY_BYTES:
            raise ValueError(f"private_key must be {ed25519.KEY_BYTES} bytes")
        self._secret = private_key
        self._key_id = identity(key_id, "key_id")

    @property
    def key_id(self) -> str:
        return self._key_id

    def __repr__(self) -> str:
        return f"ApprovalIssuer(key_id={self._key_id!r})"

    def issue(self, decision: str, span_id: str, tool_id: str, *,
              expires_at: float, arg_digest: str | None = None,
              tool_args: Any = _UNSET, granted_at: float | None = None,
              granted_by: str | None = None, policy_id: str | None = None,
              policy_digest: str | None = None,
              enforcement: str | None = None) -> dict[str, Any]:
        """One signed approval for one call, as a JSON-ready object.

        Place it at ``data.approval`` on the policy event that recorded the
        decision (``cost_threshold_exceeded`` or ``depth_exceeded``), before the
        call it covers. ``granted_at`` defaults to now; the verifier requires
        ``granted_at <= call.started_at <= expires_at``, so an approval issued
        after the call started does not cover it.
        """
        if decision not in VALID_DECISIONS:
            raise ValueError(f"decision must be one of {sorted(VALID_DECISIONS)}, "
                             f"got {decision!r}")
        span = identity(span_id, "span_id")
        tool = identity(tool_id, "tool_id")
        digest = subject_digest(arg_digest_text=arg_digest, tool_args=tool_args)
        if expires_at is None:
            # The one refusal that matters most. See the module docstring.
            raise ValueError("expires_at is required: a signed approval with no "
                             "expiry would be valid forever, and the signing "
                             "input covers the expiry precisely so that one "
                             "cannot be minted")
        expiry = finite(expires_at, "expires_at")
        granted = finite(time.time() if granted_at is None else granted_at, "granted_at")
        if expiry <= granted:
            raise ValueError(f"expires_at={expiry} is not after granted_at={granted}: "
                             f"the approval would expire before it was granted")
        by = optional_identity(granted_by, "granted_by")
        policy = optional_identity(policy_id, "policy_id")
        policy_hash = None if policy_digest is None else _digest(policy_digest,
                                                                "policy_digest")
        if enforcement is not None and enforcement not in VALID_ENFORCEMENT:
            raise ValueError(f"enforcement must be one of {sorted(VALID_ENFORCEMENT)}, "
                             f"got {enforcement!r}")
        nonce = secrets.token_hex(16)

        message = approval_signing_input(
            decision=decision, span_id=span, tool_id=tool, arg_digest=digest,
            nonce=nonce, granted_at=granted, expires_at=expiry)
        signature = base64.b64encode(ed25519.sign(self._secret, message)).decode("ascii")

        approval: dict[str, Any] = {
            "scheme": APPROVAL_SCHEMA,
            "decision": decision,
            "subject": {"span_id": span, "tool_id": tool, "arg_digest": digest},
            "granted_at": granted,
            "expires_at": expiry,
            "nonce": nonce,
            "signature": {"key_id": self._key_id, "sig": signature},
        }
        for name, value in (("granted_by", by), ("policy_id", policy),
                            ("policy_digest", policy_hash),
                            ("enforcement", enforcement)):
            if value is not None:
                approval[name] = value

        # The verifier's own parser is the last word on whether this is an
        # approval. It cannot fail after the checks above; if it ever does,
        # the issuer has drifted from the schema and must not emit.
        parsed, codes = Approval.parse(approval)
        if parsed is None or codes or not parsed.signable or not parsed.bound:
            raise RuntimeError(f"issued approval does not parse as "
                               f"{APPROVAL_SCHEMA}: {codes or 'unsignable'}")
        return approval
