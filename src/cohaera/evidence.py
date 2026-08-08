"""The P1 evidence sidecars: collector integrity, effect receipts, approvals.

Everything in :mod:`cohaera.checks` before this file was a sound argument over
its input, and every one of them was conditional on the input being a faithful
record. Nothing established that. Cohaera could tell a malformed record from a
well-formed one and could not tell a true record from a false one, and the
twenty-two defects fixed to date were all on the first boundary.

This module is the second boundary. ``docs/EVIDENCE-TRUST.md`` is the design and
the wire formats; this is the parser and the verifier. Read that document first
if you want the argument. The short version:

    Today a lie costs one boolean. After this, a lie costs a signing key the
    agent process does not hold, or a receipt bound to the exact call and the
    exact arguments.

That is a raise, not a closure, and every docstring here says which of the two
it is doing.

THREE SCHEMAS, THREE DIFFERENT KINDS OF CLAIM
---------------------------------------------
``cohaera.integrity:1``
    Added by the COLLECTOR, after normalisation, before the record leaves the
    host. Sequence, hash chain, signature. Closes modification and deletion by
    anyone who does not hold the collector's key. Does NOT close a compromised
    collector, and in a deployment where the adapter runs in-process with the
    agent it closes nothing at all -- the trust moved from the agent's emitter
    to a key the agent can reach. Deployments in that shape gain nothing here
    and the coverage contract says so.

``cohaera.receipt:1``
    An identifier minted by the system the action HAPPENED TO -- an SMTP
    Message-ID, an S3 version ID, a transaction ID. Drawn from a namespace the
    agent does not control. Cohaera cannot ask the authority whether it is real;
    what it can do is check that the receipt is bound to this exact call, and
    notice when a call reports failure while carrying one.

``cohaera.approval:1``
    Emitted by the policy engine, which already knows every field at the moment
    it decides. Binds a decision to one span and one argument digest. This is
    the cheapest of the three to produce and the one with the largest measured
    effect, because ``benign_hard_advisory_threshold`` is the corpus's single
    largest source of false positives and the fix for it is a declared field.

AND TWO MORE, WHICH ARE ABOUT THE OPERATOR RATHER THAN THE PRODUCER
------------------------------------------------------------------
``cohaera.trust_store:1``
    Which keys are trusted, for WHAT, from when until when, and which have been
    declared compromised. P1.1 shipped a flat map of key ids to bytes and said
    in three places that rotation, revocation and multi-collector fleets need
    more than that. This is the more than that, and :class:`TrustStore`
    enumerates what it is still not, because the gap between a key file and a
    trust store somebody runs a fleet on is exactly the sort of thing a green
    tick hides.

``cohaera.policy_signature:1``
    A detached signature over the capability manifest or the baseline. Those two
    files decide how every record is read -- one says which tools are
    consequential, the other teaches CH01 what normal looks like -- and until
    now both were trusted because they were on disk. Signing them is what
    ``capabilities.py`` said was blocked on a key distribution story; the trust
    store is that story.

PARSING DOCTRINE: ABSENT, NEVER WEAKER
--------------------------------------
Same rule as :mod:`cohaera.validate`, and it matters more here. A malformed
approval is treated as no approval, so a producer cannot buy a bypass with a
type error. A malformed integrity object is treated as no integrity, so a
producer cannot buy silence with one either. Both directions fail closed:

    no approval        -> the continuation is unapproved and CH04 says so
    no integrity       -> the session is reported as unattested, not as clean

The one place this is uncomfortable is ``enforcement``. An unparseable value
falls back to UNDECLARED, which is today's behaviour -- report the sequence,
claim nothing -- rather than to ``blocking``. Treating a malformed field as the
strictest reading would let a producer's typo manufacture a critical finding,
and a detector that can be made to cry wolf by a serialiser bug is worse than
one that stays quiet and says it stayed quiet.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import ed25519
from .identity import canonical
from .limits import (
    DEFAULT_LIMITS,
    DEFECT_APPROVAL_TYPE,
    DEFECT_ENFORCEMENT_TYPE,
    DEFECT_INTEGRITY_TYPE,
    DEFECT_RECEIPT_TYPE,
    Limits,
)
from .validate import identity_text

INTEGRITY_SCHEMA = "cohaera.integrity:1"
RECEIPT_SCHEMA = "cohaera.receipt:1"
APPROVAL_SCHEMA = "cohaera.approval:1"
TRUST_STORE_SCHEMA = "cohaera.trust_store:1"
POLICY_SIGNATURE_SCHEMA = "cohaera.policy_signature:1"
# Superseded by the trust store and still loaded, because a deployment that
# adopted P1.1 wrote one of these and should not be broken by a file format that
# gained fields it does not use.
COLLECTOR_KEYS_SCHEMA = "cohaera.collector_keys:1"

# Tagged into the trust store's semantic digest so the digest commits to the SET
# OF FIELDS it covers, exactly as SEMANTICS_SCHEMA does for the manifest. When a
# later version starts reading a field it ignores today, bumping this makes every
# digest visibly change rather than quietly mean something new.
TRUST_STORE_SEMANTICS = "cohaera.trust_store.semantics:1"

# What a key is allowed to attest. The separation is the point: a collector's key
# signs telemetry, an operator's key signs the policy that decides how telemetry
# is read, and a deployment where one key does both has handed the thing being
# watched authority over the rules it is watched by.
ROLE_COLLECTOR = "collector"          # cohaera.integrity:1 on the wire
ROLE_POLICY = "policy"                # cohaera.policy_signature:1 over a file
VALID_ROLES = frozenset({ROLE_COLLECTOR, ROLE_POLICY})

# What is wrong with the STORE ITSELF, as opposed to with anything verified
# under it. See TrustStore.warnings.
W_LEGACY_SCHEMA = "TRUST_STORE_LEGACY_SCHEMA"
W_SUPERSEDED_OPEN = "TRUST_STORE_SUPERSEDED_KEY_STILL_OPEN"
W_ROTATION_CYCLE = "TRUST_STORE_ROTATION_CYCLE"
W_ALL_KEYS_REVOKED = "TRUST_STORE_ALL_KEYS_REVOKED"

# Where the sidecars live on a record.
INTEGRITY_FIELD = "integrity"          # top level, beside session_id
RECEIPT_FIELD = "effect_receipt"       # in the data bag
APPROVAL_FIELD = "approval"            # in the data bag
ARG_DIGEST_FIELD = "arg_digest"        # in the data bag

# Declared policy semantics. UNDECLARED is not a value a producer sends; it is
# what Cohaera records when nothing said.
ENFORCEMENT_BLOCKING = "blocking"
ENFORCEMENT_ADVISORY = "advisory"
ENFORCEMENT_UNDECLARED = "undeclared"
VALID_ENFORCEMENT = frozenset({ENFORCEMENT_BLOCKING, ENFORCEMENT_ADVISORY})

DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
VALID_DECISIONS = frozenset({DECISION_ALLOW, DECISION_DENY})

# Where a call's argument identity came from. Same shape as ``klass_source``,
# and for the same reason: one of these is a fact and the others are weaker.
ARGS_DECLARED = "producer_declared"    # the producer stated a digest
ARGS_RECOMPUTED = "recomputed"         # Cohaera hashed the captured args
ARGS_ABSENT = "none"

DIGEST_PREFIX = "sha256:"


def arg_digest(args: Any) -> str:
    """Content digest of one call's arguments, in the wire format.

    Routed through ``canonical`` so that a producer sending ``{"a":1,"b":2}``
    and one sending ``{"b":2,"a":1}`` agree, and so that a non-finite float in
    an argument cannot raise from inside binding verification -- which would be
    the same fault this codebase already fixed one layer down in
    ``identity.canonical`` itself.
    """
    blob = canonical(args).encode("utf-8")
    return DIGEST_PREFIX + hashlib.sha256(blob).hexdigest()


def digest_text(value: Any) -> str | None:
    """A ``sha256:<64 hex>`` string, or None. No other digest form is accepted.

    Deliberately strict about the prefix. An unprefixed hex string would compare
    unequal to everything Cohaera computes, so accepting one would turn a
    producer's formatting choice into a silent binding failure -- which reads,
    downstream, as an attacker reusing an approval.
    """
    if not isinstance(value, str) or isinstance(value, bool):
        return None
    if not value.startswith(DIGEST_PREFIX):
        return None
    body = value[len(DIGEST_PREFIX):]
    if len(body) != 64:
        return None
    try:
        int(body, 16)
    except ValueError:
        return None
    return value.lower()


def _short(value: Any, limits: Limits) -> str | None:
    text, _ = identity_text(value, limits.max_identity_chars, "x", "x")
    return text


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    v = float(value)
    return v if math.isfinite(v) else None


def _index(value: Any) -> int | None:
    """A non-negative integer. Booleans are not sequence numbers."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


# ---------------------------------------------------------------------------
# Binding: the part that makes any of this more than decoration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Binding:
    """Which exact call a receipt or an approval refers to.

    All three fields matter and they fail differently. ``span_id`` alone lets a
    receipt be copied from a legitimate call onto a malicious one that happens
    to reuse the span. ``tool_id`` alone lets an approval for ``send_email``
    cover a different send_email. ``arg_digest`` is what stops an approval for
    ``send_email`` to alice covering ``send_email`` to an attacker, and it is
    the only one of the three that constrains what the call actually DID.
    """

    span_id: str | None = None
    tool_id: str | None = None
    arg_digest: str | None = None

    @property
    def complete(self) -> bool:
        return bool(self.span_id and self.tool_id and self.arg_digest)

    def as_dict(self) -> dict[str, Any]:
        return {"span_id": self.span_id, "tool_id": self.tool_id,
                "arg_digest": self.arg_digest}

    @classmethod
    def parse(cls, obj: Any, limits: Limits) -> Binding | None:
        if not isinstance(obj, dict):
            return None
        return cls(span_id=_short(obj.get("span_id"), limits),
                   tool_id=_short(obj.get("tool_id"), limits),
                   arg_digest=digest_text(obj.get("arg_digest")))


# How well a binding held. Ordered from strongest to weakest, because the
# distinction is the whole mechanism and collapsing it to a boolean is how a
# decorative signature field gets shipped.
BOUND_EXACT = "bound"                  # span, tool AND arg digest all matched
BOUND_SPAN_ONLY = "bound_span_only"    # span and tool matched; args unverifiable
BOUND_ARG_MISMATCH = "arg_mismatch"    # span matched, arguments did NOT
BOUND_NONE = "unbound"                 # names no call in this session

BINDING_TRUSTED = frozenset({BOUND_EXACT, BOUND_SPAN_ONLY})


# ---------------------------------------------------------------------------
# cohaera.integrity:1
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Integrity:
    """One record's collector sidecar, parsed. Nothing verified yet."""

    stream_id: str
    seq: int
    prev: str | None = None
    chain: str | None = None
    key_id: str | None = None
    sig: bytes | None = None

    @property
    def signed(self) -> bool:
        return self.sig is not None and self.key_id is not None

    @classmethod
    def parse(cls, obj: Any, limits: Limits = DEFAULT_LIMITS
              ) -> tuple[Integrity | None, tuple[str, ...]]:
        """Absent-and-flagged, never coerced. See the module docstring."""
        if obj is None:
            return None, ()
        if not isinstance(obj, dict):
            return None, (DEFECT_INTEGRITY_TYPE,)
        if obj.get("scheme") != INTEGRITY_SCHEMA:
            return None, (DEFECT_INTEGRITY_TYPE,)
        stream_id = _short(obj.get("stream_id"), limits)
        seq = _index(obj.get("seq"))
        if stream_id is None or seq is None:
            # A sidecar with no stream or no sequence cannot participate in any
            # of the three checks, so it is not a sidecar.
            return None, (DEFECT_INTEGRITY_TYPE,)
        sig_raw = obj.get("sig")
        sig: bytes | None = None
        if sig_raw is not None:
            if not isinstance(sig_raw, str) or isinstance(sig_raw, bool):
                return None, (DEFECT_INTEGRITY_TYPE,)
            try:
                # validate=True: base64 that silently ignores stray characters
                # would let two different strings decode to the same signature.
                sig = base64.b64decode(sig_raw, validate=True)
            except (binascii.Error, ValueError):
                return None, (DEFECT_INTEGRITY_TYPE,)
            if len(sig) != ed25519.SIG_BYTES:
                return None, (DEFECT_INTEGRITY_TYPE,)
        return cls(
            stream_id=stream_id, seq=seq,
            prev=_hex_or_none(obj.get("prev")),
            chain=_hex_or_none(obj.get("chain")),
            key_id=_short(obj.get("key_id"), limits),
            sig=sig,
        ), ()


def _hex_or_none(value: Any) -> str | None:
    if not isinstance(value, str) or isinstance(value, bool) or not value:
        return None
    try:
        int(value, 16)
    except ValueError:
        return None
    return value.lower()


def chain_seed(stream_id: str, key_id: str) -> str:
    """``chain[0] = H(scheme || stream_id || key_id)``."""
    h = hashlib.sha256()
    for part in (INTEGRITY_SCHEMA, stream_id, key_id):
        h.update(part.encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


def body_digest(record: dict[str, Any]) -> str:
    """``H(canonical(record without its "integrity" field))``."""
    body = {k: v for k, v in record.items() if k != INTEGRITY_FIELD}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def chain_step(previous: str, body: str) -> str:
    """``chain[n] = H(chain[n-1] || H(canonical(record without "integrity")))``.

    The record is folded in through its own digest rather than inline. That is a
    deliberate refinement of the shape in ``docs/EVIDENCE-TRUST.md`` and it buys
    a bound: a verifier meeting an out-of-order stream has to hold every record
    it cannot yet chain, and holding a 32-byte digest per pending record instead
    of the record itself makes the reorder buffer a fixed cost rather than one
    the producer chooses by sending large records. Security is unchanged --
    ``H(a || H(b))`` and ``H(a || b)`` are both collision-resistant over the same
    inputs, and both are unambiguous because the separator cannot occur in hex.
    """
    h = hashlib.sha256()
    h.update(previous.encode("utf-8"))
    h.update(b"\x1f")
    h.update(body.encode("utf-8"))
    return h.hexdigest()


def signing_input(stream_id: str, seq: int, chain: str) -> bytes:
    """``scheme || stream_id || seq || chain[n]``.

    The signature covers the CHAIN HEAD, not the record. That is what lets one
    verified signature cover every record before it, so a collector may sign
    every record or every kth without the verifier changing -- and it is why
    signature verification is bounded rather than per-record work.
    """
    return b"\x1f".join((INTEGRITY_SCHEMA.encode("utf-8"),
                         stream_id.encode("utf-8"),
                         str(seq).encode("ascii"),
                         chain.encode("utf-8")))


# ---------------------------------------------------------------------------
# cohaera.receipt:1
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EffectReceipt:
    """An identifier minted by the system the action happened to."""

    authority: str
    kind: str
    identifier: str
    binding: Binding
    observed_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"authority": self.authority, "kind": self.kind,
                "identifier": self.identifier, "observed_at": self.observed_at,
                "binding": self.binding.as_dict()}

    @classmethod
    def parse(cls, obj: Any, limits: Limits = DEFAULT_LIMITS
              ) -> tuple[EffectReceipt | None, tuple[str, ...]]:
        if obj is None:
            return None, ()
        if not isinstance(obj, dict) or obj.get("scheme") != RECEIPT_SCHEMA:
            return None, (DEFECT_RECEIPT_TYPE,)
        authority = _short(obj.get("authority"), limits)
        kind = _short(obj.get("kind"), limits)
        identifier = _short(obj.get("identifier"), limits)
        binding = Binding.parse(obj.get("binding"), limits)
        if not (authority and kind and identifier) or binding is None:
            return None, (DEFECT_RECEIPT_TYPE,)
        return cls(authority=authority, kind=kind, identifier=identifier,
                   binding=binding,
                   observed_at=_finite(obj.get("observed_at"))), ()


# ---------------------------------------------------------------------------
# cohaera.approval:1
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Approval:
    """One policy decision, bound to one call."""

    decision: str
    subject: Binding
    granted_by: str | None = None
    granted_at: float | None = None
    expires_at: float | None = None
    policy_id: str | None = None
    policy_digest: str | None = None
    enforcement: str = ENFORCEMENT_UNDECLARED

    def covers_clock(self, started_at: float) -> bool | None:
        """Was the call inside this approval's validity window?

        Returns None when the approval declares no window at all, because
        "there was no expiry" and "the expiry had passed" are different facts
        and reporting the first as the second would invent a finding.
        """
        if self.granted_at is None and self.expires_at is None:
            return None
        if not math.isfinite(started_at):
            return None
        if self.granted_at is not None and started_at < self.granted_at:
            return False
        if self.expires_at is not None and started_at > self.expires_at:
            return False
        return True

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "subject": self.subject.as_dict(),
                "granted_by": self.granted_by, "granted_at": self.granted_at,
                "expires_at": self.expires_at, "policy_id": self.policy_id,
                "policy_digest": self.policy_digest,
                "enforcement": self.enforcement}

    @classmethod
    def parse(cls, obj: Any, limits: Limits = DEFAULT_LIMITS
              ) -> tuple[Approval | None, tuple[str, ...]]:
        if obj is None:
            return None, ()
        if not isinstance(obj, dict) or obj.get("scheme") != APPROVAL_SCHEMA:
            return None, (DEFECT_APPROVAL_TYPE,)
        decision = obj.get("decision")
        if decision not in VALID_DECISIONS:
            return None, (DEFECT_APPROVAL_TYPE,)
        subject = Binding.parse(obj.get("subject"), limits)
        if subject is None or not subject.span_id:
            # An approval that names no span binds to nothing. Accepting it
            # would recreate the exact fault this schema exists to remove: a
            # broad approval covering whatever came next.
            return None, (DEFECT_APPROVAL_TYPE,)
        enforcement = obj.get("enforcement")
        codes: tuple[str, ...] = ()
        if enforcement is None:
            enforcement = ENFORCEMENT_UNDECLARED
        elif enforcement not in VALID_ENFORCEMENT:
            enforcement, codes = ENFORCEMENT_UNDECLARED, (DEFECT_ENFORCEMENT_TYPE,)
        return cls(
            decision=decision, subject=subject,
            granted_by=_short(obj.get("granted_by"), limits),
            granted_at=_finite(obj.get("granted_at")),
            expires_at=_finite(obj.get("expires_at")),
            policy_id=_short(obj.get("policy_id"), limits),
            policy_digest=digest_text(obj.get("policy_digest")),
            enforcement=enforcement,
        ), codes


def enforcement_of(data: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    """Read a policy event's declared semantics.

    An unparseable value degrades to UNDECLARED rather than to ``blocking``.
    See the module docstring: a detector that a serialiser bug can make cry
    wolf is worse than one that stays quiet and says so.
    """
    value = data.get("enforcement")
    if value is None:
        return ENFORCEMENT_UNDECLARED, ()
    if value in VALID_ENFORCEMENT:
        return str(value), ()
    return ENFORCEMENT_UNDECLARED, (DEFECT_ENFORCEMENT_TYPE,)


# ---------------------------------------------------------------------------
# The trust store, loaded out of band exactly as the capability manifest is
# ---------------------------------------------------------------------------


class TrustStoreError(ValueError):
    """The key file is not a key file. Refuse it; do not half-load it."""


@dataclass(frozen=True)
class TrustedKey:
    """One public key, and the four things an operator can say about it.

    ``cohaera.collector_keys:1`` said one thing -- here are some bytes, trust
    them forever, for everything. Three properties were missing and each of them
    is a real deployment, not a hypothetical:

        roles       A collector's key attests TELEMETRY. An operator's key
                    attests POLICY -- the capability manifest and the baseline.
                    One key doing both means a compromised collector can rewrite
                    the manifest that decides which of its own tools are
                    consequential, which is a privilege escalation dressed as a
                    convenience.
        window      Rotation. ``not_after`` on the outgoing key and
                    ``not_before`` on the incoming one is what a rotation IS,
                    and without them a retired key signs valid records forever.
        revoked_at  Compromise, which is a different fact from rotation and is
                    treated differently below.
        replaces    Succession, so an auditor reading the store can reconstruct
                    the rotation rather than infer it from timestamps.

    WINDOWS ARE JUDGED AGAINST THE RECORD'S OWN CLOCK. REVOCATION IS NOT.
        This is the one part of the design worth arguing with, so here is the
        argument. A window check needs a time to check against, and the only
        time available offline is the one written on the record -- which is
        producer-controlled, and this codebase treats producer-controlled fields
        as claims rather than facts everywhere else.

        It is sound here, and only here, because of what else is true at the
        point the check runs. The chain covers the record including its
        timestamp, the signature covers the chain, and the window is evaluated
        ONLY after that signature has verified. So the key vouches for the
        timestamp, and a key that is not compromised does not lie about when it
        signed. ``StreamVerifier._check_signature`` enforces that ordering, and
        the ordering is the whole reason the check is admissible.

        Revocation breaks precisely that premise. Revoking a key is the operator
        stating that somebody else holds it, and a signature made by an attacker
        proves nothing about the timestamp underneath it -- they would simply
        write a date inside the window. So revocation is NOT evaluated against
        any clock: a key with ``revoked_at`` set is refused outright, for every
        record, whatever the record claims about when it was written.

        The cost of that is real and is not hidden: an archive legitimately
        signed last month by a key revoked yesterday can no longer be verified,
        because distinguishing it from a forgery needs a trusted timestamp and
        Cohaera has no clock it trusts. An operator who wants "this key was good
        until Tuesday" is describing rotation, and should write it as
        ``not_after``, which IS evaluated against the record.
    """

    key_id: str
    public: bytes
    roles: frozenset[str]
    not_before: float | None = None
    not_after: float | None = None
    revoked_at: float | None = None
    replaces: str | None = None

    @property
    def revoked(self) -> bool:
        """Presence, not comparison. See the class docstring."""
        return self.revoked_at is not None

    @property
    def windowed(self) -> bool:
        return self.not_before is not None or self.not_after is not None

    @property
    def open_ended(self) -> bool:
        """Nothing will ever stop this key signing."""
        return not self.windowed and not self.revoked

    def authorises(self, role: str) -> bool:
        return role in self.roles

    def covers_clock(self, when: float | None) -> bool | None:
        """Was ``when`` inside this key's validity window?

        None means the question could not be answered -- an unusable timestamp
        on a key that declares a window. Callers must check :attr:`windowed`
        first, because "this key has no window" and "this key has a window and
        the record has no clock" are different states and reporting the first as
        the second would invent a coverage gap on every well-formed store.
        """
        if when is None or not isinstance(when, (int, float)) or not math.isfinite(when):
            return None
        if self.not_before is not None and when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True

    def semantics(self) -> dict[str, Any]:
        return {"public": base64.b64encode(self.public).decode("ascii"),
                "roles": sorted(self.roles), "not_before": self.not_before,
                "not_after": self.not_after, "revoked_at": self.revoked_at,
                "replaces": self.replaces}

    def brief(self) -> dict[str, Any]:
        """What travels into the verdict. The public key itself does not."""
        return {"key_id": self.key_id, "roles": sorted(self.roles),
                "not_before": self.not_before, "not_after": self.not_after,
                "revoked_at": self.revoked_at, "replaces": self.replaces}


@dataclass(frozen=True)
class TrustStore:
    """The keys the operator supplied, and the digests of the file they came
    from.

    Loaded from a path the operator names, which is the same trust model the
    capability manifest has and is honest about it. This says *these signatures
    verify under a key you supplied, which you said was allowed to sign this
    kind of thing, and which you had not marked compromised*. It does not say
    *this telemetry is genuine*.

    WHAT THIS STILL IS NOT, WRITTEN DOWN RATHER THAN IMPLIED
        No online status check. There is no OCSP, no CRL fetch, no directory
        lookup, because Cohaera is offline by construction. A key revoked five
        minutes ago is revoked here only after somebody edits this file and
        re-runs.

        No key transparency. Nothing proves the store you loaded is the store
        your organisation published; two hosts can hold different files and both
        produce confident verdicts. The pair of digests recorded in provenance
        makes that DETECTABLE after the fact by comparing verdicts. It does not
        prevent it.

        No quorum and no threshold. One key's signature is the whole decision,
        so one compromised key is a full compromise of whatever it was
        authorised for.

        No hardware binding. Nothing here establishes that a private key lives
        in an HSM rather than in a file next to the collector, and where the
        collector runs in-process with the agent the agent can read it -- which
        is the case ``docs/EVIDENCE-TRUST.md`` section 2 says gains nothing from
        any of this.

        No automatic rotation. ``not_after`` and ``replaces`` let an operator
        DESCRIBE a rotation they performed. Nothing performs one.

    That list is the honest boundary between this and a trust store somebody
    would run a fleet on, and it is here rather than in a roadmap because the
    gap between the two is exactly the sort of thing a green tick hides.
    """

    keys: dict[str, TrustedKey] = field(default_factory=dict)
    file_digest: str = ""
    semantic_digest: str = ""
    schema: str = ""
    # Problems with the STORE, as opposed to with anything it was used on.
    # Non-fatal by design: refusing to run over an operator's own bookkeeping
    # slip would be a denial of service against the person trying to tighten
    # their configuration. Surfaced on stderr and in provenance instead.
    warnings: tuple[str, ...] = ()

    @property
    def loaded(self) -> bool:
        return bool(self.keys)

    def get(self, key_id: Any) -> TrustedKey | None:
        if not isinstance(key_id, str) or not key_id:
            return None
        return self.keys.get(key_id)

    def for_role(self, role: str) -> dict[str, TrustedKey]:
        return {k: v for k, v in self.keys.items() if v.authorises(role)}

    def has_role(self, role: str) -> bool:
        return any(v.authorises(role) for v in self.keys.values())

    def as_dict(self, cap: int = 20) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "key_count": len(self.keys),
            "file_digest": self.file_digest,
            "semantic_digest": self.semantic_digest,
            "key_ids": sorted(self.keys)[:cap],
            "collector_key_count": len(self.for_role(ROLE_COLLECTOR)),
            "policy_key_count": len(self.for_role(ROLE_POLICY)),
            "revoked_key_ids": sorted(k for k, v in self.keys.items()
                                      if v.revoked)[:cap],
            "keys": [self.keys[k].brief() for k in sorted(self.keys)[:cap]],
            "warnings": list(self.warnings),
        }

    # ---- loading --------------------------------------------------------

    @classmethod
    def from_obj(cls, obj: Any, file_digest: str = "",
                 limits: Limits = DEFAULT_LIMITS) -> TrustStore:
        if not isinstance(obj, dict):
            raise TrustStoreError("key file root must be a JSON object")
        schema = obj.get("scheme")
        if schema not in (TRUST_STORE_SCHEMA, COLLECTOR_KEYS_SCHEMA):
            raise TrustStoreError(
                f"key file must declare scheme {TRUST_STORE_SCHEMA!r} "
                f"(or the superseded {COLLECTOR_KEYS_SCHEMA!r})")
        legacy = schema == COLLECTOR_KEYS_SCHEMA
        raw = obj.get("keys")
        if not isinstance(raw, dict) or not raw:
            raise TrustStoreError("key file must carry a non-empty 'keys' object")
        if len(raw) > limits.max_collector_keys:
            raise TrustStoreError(
                f"key file declares {len(raw)} keys, exceeding "
                f"max_collector_keys={limits.max_collector_keys}")

        keys: dict[str, TrustedKey] = {}
        for key_id, value in raw.items():
            if not isinstance(key_id, str) or not key_id:
                raise TrustStoreError(f"key id must be a non-empty string: {key_id!r}")
            if len(key_id) > limits.max_identity_chars:
                raise TrustStoreError(f"key id {key_id[:32]!r} is too long")
            keys[key_id] = (_legacy_key(key_id, value) if legacy
                            else _trusted_key(key_id, value, limits))

        warnings = _store_warnings(keys, legacy)
        payload = json.dumps(
            {"schema": TRUST_STORE_SEMANTICS,
             "keys": {k: keys[k].semantics() for k in sorted(keys)}},
            sort_keys=True, separators=(",", ":"))
        return cls(keys=keys, file_digest=file_digest, schema=str(schema),
                   warnings=warnings,
                   semantic_digest=hashlib.sha256(
                       payload.encode("utf-8")).hexdigest()[:16])

    @classmethod
    def from_file(cls, path: str | Path,
                  limits: Limits = DEFAULT_LIMITS) -> TrustStore:
        p = Path(path)
        with p.open("rb") as fh:
            blob = fh.read(limits.max_keyfile_bytes + 1)
        if len(blob) > limits.max_keyfile_bytes:
            raise TrustStoreError(
                f"{p}: key file exceeds max_keyfile_bytes={limits.max_keyfile_bytes}")
        try:
            obj = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrustStoreError(f"{p}: not readable as UTF-8 JSON: {exc}") from exc
        return cls.from_obj(obj, file_digest=hashlib.sha256(blob).hexdigest()[:16],
                            limits=limits)


def _public_bytes(key_id: str, value: Any) -> bytes:
    if not isinstance(value, str) or isinstance(value, bool):
        raise TrustStoreError(f"key {key_id!r} must be a base64 string")
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustStoreError(f"key {key_id!r} is not valid base64: {exc}") from exc
    if len(blob) != ed25519.KEY_BYTES:
        raise TrustStoreError(
            f"key {key_id!r} is {len(blob)} bytes, expected {ed25519.KEY_BYTES}")
    return blob


def _legacy_key(key_id: str, value: Any) -> TrustedKey:
    """A ``cohaera.collector_keys:1`` entry: bare base64, collector role only.

    The role is not a guess. That schema's NAME is the declaration -- a file
    called a collector key file contains collector keys -- so reading it as one
    is faithful rather than lenient. What it cannot do is authorise policy
    signing, and an operator who wants that has to say so in a store that has
    somewhere to say it.
    """
    return TrustedKey(key_id=key_id, public=_public_bytes(key_id, value),
                      roles=frozenset({ROLE_COLLECTOR}))


def _clock_field(key_id: str, spec: dict[str, Any], name: str) -> float | None:
    value = spec.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrustStoreError(
            f"key {key_id!r} {name!r} must be a number of seconds since the "
            f"epoch, got {type(value).__name__}")
    out = float(value)
    if not math.isfinite(out):
        raise TrustStoreError(f"key {key_id!r} {name!r} is not a finite number")
    return out


def _trusted_key(key_id: str, spec: Any, limits: Limits) -> TrustedKey:
    """A ``cohaera.trust_store:1`` entry. Every field checked, nothing defaulted.

    ``roles`` is required and has no default. A key with no declared role is an
    operator who has not decided what the key is for, and picking for them is
    how a collector key ends up able to sign the manifest that says which of the
    collector's own tools are consequential.
    """
    if not isinstance(spec, dict):
        raise TrustStoreError(
            f"key {key_id!r} must map to an object in {TRUST_STORE_SCHEMA}; a "
            f"bare base64 string is {COLLECTOR_KEYS_SCHEMA} syntax")
    public = _public_bytes(key_id, spec.get("key"))

    roles_raw = spec.get("roles")
    if not isinstance(roles_raw, list) or not roles_raw:
        raise TrustStoreError(
            f"key {key_id!r} must declare a non-empty 'roles' list; valid roles "
            f"are {sorted(VALID_ROLES)}")
    bad = [r for r in roles_raw if r not in VALID_ROLES]
    if bad:
        raise TrustStoreError(
            f"key {key_id!r} declares unknown role(s) {bad!r}; valid roles are "
            f"{sorted(VALID_ROLES)}")

    not_before = _clock_field(key_id, spec, "not_before")
    not_after = _clock_field(key_id, spec, "not_after")
    if (not_before is not None and not_after is not None
            and not_before > not_after):
        # A window that closes before it opens is a window nothing can be inside,
        # so every record signed by this key would be reported as out of window
        # and the operator would read it as tampering. Refuse the file instead.
        raise TrustStoreError(
            f"key {key_id!r} has not_before={not_before} after "
            f"not_after={not_after}: no record can ever be inside that window")
    revoked_at = _clock_field(key_id, spec, "revoked_at")

    replaces = spec.get("replaces")
    if replaces is not None:
        if not isinstance(replaces, str) or isinstance(replaces, bool) or not replaces:
            raise TrustStoreError(
                f"key {key_id!r} 'replaces' must be a non-empty key id string")
        if len(replaces) > limits.max_identity_chars:
            raise TrustStoreError(f"key {key_id!r} 'replaces' id is too long")
        if replaces == key_id:
            raise TrustStoreError(f"key {key_id!r} declares that it replaces itself")

    return TrustedKey(key_id=key_id, public=public, roles=frozenset(roles_raw),
                      not_before=not_before, not_after=not_after,
                      revoked_at=revoked_at, replaces=replaces)


def _store_warnings(keys: dict[str, TrustedKey], legacy: bool) -> tuple[str, ...]:
    """Problems with the operator's own file, found once at load.

    A trust store is a document somebody maintains by hand under time pressure,
    and the failure that matters is not a syntax error -- it is a rotation that
    was announced and never enforced. A key superseded by a live one, with no
    ``not_after`` and no ``revoked_at``, keeps signing valid records forever, so
    the rotation exists in the file and not in the verifier. That is invisible
    unless something looks for it.
    """
    found: list[str] = []
    if legacy:
        found.append(W_LEGACY_SCHEMA)

    superseded = {k.replaces for k in keys.values() if k.replaces}
    if any(pid in keys and keys[pid].open_ended for pid in superseded):
        found.append(W_SUPERSEDED_OPEN)

    # A cycle in `replaces` is not a rotation, it is a loop, and reporting it
    # beats following it. Bounded by construction: each step moves to a distinct
    # key or stops.
    for start in sorted(keys):
        seen = {start}
        cur = keys[start].replaces
        while cur in keys:
            if cur in seen:
                found.append(W_ROTATION_CYCLE)
                break
            seen.add(cur)
            cur = keys[cur].replaces
        if W_ROTATION_CYCLE in found:
            break

    if all(k.revoked for k in keys.values()):
        found.append(W_ALL_KEYS_REVOKED)
    return tuple(found)


EMPTY_STORE = TrustStore()


# ---------------------------------------------------------------------------
# cohaera.policy_signature:1 -- the operator's inputs, attested
# ---------------------------------------------------------------------------
#
# WHY THE POLICY FILES NEEDED THIS AND THE TELEMETRY GOT IT FIRST
#     P1.1 signed the stream and left the two files that decide how the stream
#     is READ unsigned, which is the wrong way round for at least one of them.
#     The capability manifest says which tools are consequential -- edit it and
#     an egress tool becomes read_only, and CH02, CH03 and CH04 all stop firing
#     on it without a single telemetry record changing. The baseline is worse
#     still: CH01 is the only detector here that LEARNS, so an attacker who can
#     add sessions to the benign baseline teaches it that the attack is normal,
#     and every subsequent verdict is quietly wrong in the attacker's favour.
#     That is EVASION.md E03 and it was mitigated by "keep the file somewhere
#     safe", which is not a mitigation, it is a hope.
#
#     ``capabilities.py`` said signing was blocked on a key distribution story
#     that did not exist. The trust store above is that story -- not a good one,
#     and its limits are enumerated on TrustStore -- so this is no longer
#     blocked on anything.
#
# DETACHED, OVER THE EXACT BYTES
#     The signature is a separate file and it covers ``sha256(file bytes)``,
#     not a canonicalisation of the parsed content. That is deliberate and it is
#     the same argument capabilities.py makes for keeping BOTH digests: a
#     signature over parsed semantics would verify happily after an edit that
#     adds a field this version does not read, and "did this file change at all"
#     is precisely the question a tamper signal must answer strictly. Detached
#     also means the artifact itself is untouched, so a manifest stays a plain
#     JSON document that any other tool can read.
#
# DOMAIN SEPARATED TWICE
#     The signing input is prefixed with this scheme, so a policy signature can
#     never be presented as a ``cohaera.integrity:1`` signature or the reverse;
#     and it names the artifact KIND, so a signature over a baseline cannot be
#     presented as a signature over a manifest. Both are free to add and both
#     close a cross-protocol substitution that is tedious to notice later.

POLICY_ARTIFACT_MANIFEST = "capability_manifest"
POLICY_ARTIFACT_BASELINE = "baseline"
VALID_POLICY_ARTIFACTS = frozenset({POLICY_ARTIFACT_MANIFEST,
                                    POLICY_ARTIFACT_BASELINE})

P_VERIFIED = "POLICY_SIGNATURE_VERIFIED"
P_ABSENT = "POLICY_SIGNATURE_ABSENT"
P_INVALID = "POLICY_SIGNATURE_INVALID"
P_DIGEST_MISMATCH = "POLICY_SIGNATURE_DIGEST_MISMATCH"
P_ARTIFACT_MISMATCH = "POLICY_SIGNATURE_ARTIFACT_MISMATCH"
P_KEY_UNKNOWN = "POLICY_SIGNATURE_KEY_UNKNOWN"
P_KEY_WRONG_ROLE = "POLICY_SIGNATURE_KEY_ROLE_NOT_AUTHORISED"
P_KEY_REVOKED = "POLICY_SIGNATURE_KEY_REVOKED"
P_KEY_EXPIRED = "POLICY_SIGNATURE_KEY_EXPIRED"
P_KEY_NOT_YET_VALID = "POLICY_SIGNATURE_KEY_NOT_YET_VALID"
P_NO_KEYS = "POLICY_SIGNATURE_NO_POLICY_KEYS"


class PolicySignatureError(ValueError):
    """The signature file is not a signature file. Refuse it."""


def policy_signing_input(artifact: str, file_sha256: str, signed_at: int) -> bytes:
    """``scheme || artifact || sha256(file) || signed_at``.

    ``signed_at`` is inside the signature rather than beside it so that the key
    validity window has something attested to judge against, exactly as a
    record's timestamp is judged for ``cohaera.integrity:1``. It is an integer
    number of seconds, and integer rather than float because a signing input
    must have exactly one byte encoding: ``1785700000.0`` and ``1785700000``
    are the same instant and would otherwise be two different messages.
    """
    return b"\x1f".join((POLICY_SIGNATURE_SCHEMA.encode("utf-8"),
                         artifact.encode("utf-8"),
                         file_sha256.encode("utf-8"),
                         str(signed_at).encode("ascii")))


@dataclass(frozen=True)
class PolicySignature:
    """A detached signature over one operator-supplied file."""

    artifact: str
    file_sha256: str
    signed_at: int
    key_id: str
    sig: bytes

    @classmethod
    def from_obj(cls, obj: Any, limits: Limits = DEFAULT_LIMITS) -> PolicySignature:
        if not isinstance(obj, dict):
            raise PolicySignatureError("signature file root must be a JSON object")
        if obj.get("scheme") != POLICY_SIGNATURE_SCHEMA:
            raise PolicySignatureError(
                f"signature file must declare scheme {POLICY_SIGNATURE_SCHEMA!r}")
        artifact = obj.get("artifact")
        if artifact not in VALID_POLICY_ARTIFACTS:
            raise PolicySignatureError(
                f"signature declares artifact {artifact!r}; valid artifacts are "
                f"{sorted(VALID_POLICY_ARTIFACTS)}")
        digest = obj.get("file_sha256")
        if (not isinstance(digest, str) or isinstance(digest, bool)
                or len(digest) != 64):
            raise PolicySignatureError(
                "signature 'file_sha256' must be a 64-character hex digest")
        try:
            int(digest, 16)
        except ValueError:
            raise PolicySignatureError(
                "signature 'file_sha256' is not hexadecimal") from None
        signed_at = obj.get("signed_at")
        if isinstance(signed_at, bool) or not isinstance(signed_at, int):
            raise PolicySignatureError(
                "signature 'signed_at' must be an integer number of seconds "
                "since the epoch")
        key_id = obj.get("key_id")
        if (not isinstance(key_id, str) or isinstance(key_id, bool) or not key_id
                or len(key_id) > limits.max_identity_chars):
            raise PolicySignatureError("signature 'key_id' must be a key id string")
        raw = obj.get("sig")
        if not isinstance(raw, str) or isinstance(raw, bool):
            raise PolicySignatureError("signature 'sig' must be a base64 string")
        try:
            blob = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PolicySignatureError(f"signature 'sig' is not valid base64: "
                                       f"{exc}") from exc
        if len(blob) != ed25519.SIG_BYTES:
            raise PolicySignatureError(
                f"signature is {len(blob)} bytes, expected {ed25519.SIG_BYTES}")
        return cls(artifact=artifact, file_sha256=digest.lower(),
                   signed_at=signed_at, key_id=key_id, sig=blob)

    @classmethod
    def from_file(cls, path: str | Path,
                  limits: Limits = DEFAULT_LIMITS) -> PolicySignature:
        p = Path(path)
        with p.open("rb") as fh:
            blob = fh.read(limits.max_keyfile_bytes + 1)
        if len(blob) > limits.max_keyfile_bytes:
            raise PolicySignatureError(
                f"{p}: signature file exceeds "
                f"max_keyfile_bytes={limits.max_keyfile_bytes}")
        try:
            obj = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicySignatureError(
                f"{p}: not readable as UTF-8 JSON: {exc}") from exc
        return cls.from_obj(obj, limits=limits)


@dataclass(frozen=True)
class PolicyAttestation:
    """What Cohaera established about one operator-supplied file.

    ``P_ABSENT`` is the value nearly every deployment will carry and it is the
    important one. It does not mean the manifest was checked and found genuine;
    it means nothing was ever in a position to check it. Reporting an unsigned
    manifest as anything other than unsigned is the same fault as a check that
    cannot run reporting itself as clean.
    """

    artifact: str
    status: str = P_ABSENT
    key_id: str = ""
    file_sha256: str = ""
    signed_at: int | None = None
    detail: str = ""

    @property
    def verified(self) -> bool:
        return self.status == P_VERIFIED

    def as_dict(self) -> dict[str, Any]:
        return {"artifact": self.artifact, "status": self.status,
                "verified": self.verified, "key_id": self.key_id,
                "file_sha256": self.file_sha256, "signed_at": self.signed_at,
                "detail": self.detail}


def file_sha256(path: str | Path, max_bytes: int) -> str:
    """Hash a file the signature claims to cover, in bounded memory.

    Chunked rather than ``read_bytes()``: the baseline is telemetry and may be
    gigabytes, and reading an operator-named file whole in order to hash it is
    the same resource fault C4-02 fixed on the ingest path -- work bounded by
    the size of somebody else's file rather than by any number here.

    ``max_bytes`` is the caller's existing bound for that artifact, so a file
    too large to score is also too large to attest, rather than being attested
    and then refused.
    """
    h = hashlib.sha256()
    read = 0
    with Path(path).open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            read += len(chunk)
            if read > max_bytes:
                raise PolicySignatureError(
                    f"{path}: exceeds {max_bytes} bytes, so the signature over "
                    f"it cannot be checked")
            h.update(chunk)
    return h.hexdigest()


def verify_policy_signature(signature: PolicySignature, digest: str,
                            artifact: str, store: TrustStore) -> PolicyAttestation:
    """Check one detached signature against the bytes it claims to cover.

    Same ordering, and for the same reason, as
    ``StreamVerifier._check_signature``: everything decidable from the store
    alone is decided before any scalar multiplication, and the key's validity
    window is judged last, against a ``signed_at`` the signature has by then
    established. See :class:`TrustedKey`.
    """
    out = PolicyAttestation(artifact=artifact, key_id=signature.key_id,
                            file_sha256=signature.file_sha256,
                            signed_at=signature.signed_at)

    def fail(status: str, detail: str) -> PolicyAttestation:
        return replace(out, status=status, detail=detail)

    if signature.artifact != artifact:
        # A real signature over a real file, presented as covering a different
        # kind of file. Without this the artifact tag in the signing input would
        # be decoration: the bytes would still verify, and only this comparison
        # turns that into a refusal.
        return fail(P_ARTIFACT_MISMATCH,
                    f"signature covers {signature.artifact!r}, not {artifact!r}")
    if digest != signature.file_sha256:
        return fail(P_DIGEST_MISMATCH,
                    f"file hashes to {digest[:16]}..., signature covers "
                    f"{signature.file_sha256[:16]}...")
    if not store.has_role(ROLE_POLICY):
        return fail(P_NO_KEYS,
                    "no key in the trust store is authorised for the 'policy' "
                    "role, so nothing here could verify this signature")
    key = store.get(signature.key_id)
    if key is None:
        return fail(P_KEY_UNKNOWN,
                    f"key {signature.key_id!r} is not in the trust store")
    if not key.authorises(ROLE_POLICY):
        return fail(P_KEY_WRONG_ROLE,
                    f"key {signature.key_id!r} is trusted for "
                    f"{sorted(key.roles)}, not for signing policy")
    if key.revoked:
        return fail(P_KEY_REVOKED,
                    f"key {signature.key_id!r} is marked revoked at "
                    f"{key.revoked_at}")
    message = policy_signing_input(signature.artifact, signature.file_sha256,
                                   signature.signed_at)
    if not ed25519.verify(key.public, message, signature.sig):
        return fail(P_INVALID, "the signature did not verify under that key")
    if key.windowed:
        inside = key.covers_clock(float(signature.signed_at))
        if inside is False:
            expired = (key.not_before is None
                       or float(signature.signed_at) >= key.not_before)
            return fail(P_KEY_EXPIRED if expired else P_KEY_NOT_YET_VALID,
                        f"signed at {signature.signed_at}, outside the key's "
                        f"window [{key.not_before}, {key.not_after}]")
    return replace(out, status=P_VERIFIED)


# ---------------------------------------------------------------------------
# Verification: sequence, chain, signature
# ---------------------------------------------------------------------------

# Outcome codes. Stable strings; downstream content will match on them. They
# live here rather than in ``checks`` because this is where they are produced,
# and ``checks`` re-exports them so that every reason code an operator can see
# is importable from one place.
R_NO_INTEGRITY = "NO_INTEGRITY_EVIDENCE"
R_PARTIAL_INTEGRITY = "INTEGRITY_EVIDENCE_PARTIAL"
R_NO_COLLECTOR_KEYS = "NO_COLLECTOR_KEYS"
R_UNSIGNED = "INTEGRITY_UNSIGNED"
R_SEQUENCE_GAP = "INTEGRITY_SEQUENCE_GAP"
R_SEQUENCE_REPLAY = "INTEGRITY_SEQUENCE_REPLAY"
R_CHAIN_BROKEN = "INTEGRITY_CHAIN_BROKEN"
R_SIGNATURE_INVALID = "INTEGRITY_SIGNATURE_INVALID"
R_KEY_UNKNOWN = "INTEGRITY_KEY_UNKNOWN"
R_REORDERED = "INTEGRITY_RECORDS_REORDERED"
R_JOINED_MIDSTREAM = "INTEGRITY_STREAM_JOINED_MIDSTREAM"
R_REORDER_BUDGET = "INTEGRITY_REORDER_BUDGET_EXHAUSTED"
R_STREAM_BUDGET = "INTEGRITY_STREAM_BUDGET_EXHAUSTED"
R_SIGNATURE_BUDGET = "INTEGRITY_SIGNATURE_BUDGET_EXHAUSTED"

# Trust store outcomes. These are statements about the KEY rather than about the
# bytes: a signature can verify perfectly under a key the operator has retired,
# revoked, or never authorised to attest telemetry at all, and reporting that as
# a good signature is how a rotation that never happened looks like one that did.
R_KEY_REVOKED = "INTEGRITY_KEY_REVOKED"
R_KEY_EXPIRED = "INTEGRITY_KEY_EXPIRED"
R_KEY_NOT_YET_VALID = "INTEGRITY_KEY_NOT_YET_VALID"
R_KEY_WRONG_ROLE = "INTEGRITY_KEY_ROLE_NOT_AUTHORISED"
R_KEY_WINDOW_UNCHECKED = "INTEGRITY_KEY_WINDOW_UNCHECKED"

# Freshness. A whole stream can be re-fed from an archive, and every check above
# passes on it, because an old stream is internally perfect -- that is what makes
# replay a different attack from tampering.
R_STALE = "INTEGRITY_EVIDENCE_STALE"
R_FRESHNESS_UNVERIFIABLE = "INTEGRITY_FRESHNESS_UNVERIFIABLE"
R_NO_FRESHNESS_BOUND = "NO_FRESHNESS_BOUND"

# The codes that say the evidence is not admissible, as opposed to merely
# incomplete. A session carrying any of these has findings that rest on a stream
# somebody could have edited, and CH06 says so at critical.
#
# R_KEY_WINDOW_UNCHECKED and R_FRESHNESS_UNVERIFIABLE are deliberately NOT here.
# Both mean a question could not be answered, and answering "could not check"
# with a critical finding is the false-positive engine this project exists to
# argue against -- the same reason NO_INTEGRITY_EVIDENCE is a coverage code and
# not a finding.
INADMISSIBLE = frozenset({R_SEQUENCE_GAP, R_CHAIN_BROKEN, R_SIGNATURE_INVALID,
                          R_KEY_UNKNOWN, R_SEQUENCE_REPLAY, R_PARTIAL_INTEGRITY,
                          R_KEY_REVOKED, R_KEY_EXPIRED, R_KEY_NOT_YET_VALID,
                          R_KEY_WRONG_ROLE, R_STALE})


@dataclass(frozen=True)
class Freshness:
    """The bound that makes replaying a whole archived stream detectable.

    ``INTEGRITY_SEQUENCE_REPLAY`` catches a record replayed inside one run,
    because its sequence position is already filled. It says nothing at all
    about the other replay: capture a signed stream, keep it, and re-feed the
    whole thing next month. Every check in this module passes on that input --
    the sequence is contiguous, the chain holds, the signatures verify -- and
    they pass because the stream really was written by the collector. It is just
    not this month's stream.

    The only anchor available offline is the timestamp on the record, and it
    works here for the reason it works for key windows: it is covered by the
    chain, the chain is covered by the signature, and a replayer holds neither
    key. They can re-send the bytes, and they cannot re-date them. So a
    freshness bound is evaluated ONLY over records whose signature verified, and
    a session with none is reported as ``INTEGRITY_FRESHNESS_UNVERIFIABLE``
    rather than as fresh.

    OFF BY DEFAULT, AND SAYING SO
        ``max_age_s`` unset means no bound, and coverage reports
        ``NO_FRESHNESS_BOUND`` rather than leaving an operator to assume replay
        was considered. It is off by default because the honest default is
        unknowable: an hour is right for a live tail and wrong for a nightly
        batch, and a bound guessed wrong turns every scheduled run into a
        critical finding.

    WHAT IT STILL DOES NOT CLOSE
        Replaying a stream that is still inside the window. Detecting that needs
        memory of which streams have already been scored, which is a ledger that
        survives between runs, and Cohaera keeps no state between runs at all.
        What it does instead is record each stream's identity and extent in the
        verdict -- ``stream_summary`` -- so two runs that scored the same stream
        twice are distinguishable by comparing their verdicts. That is evidence
        after the fact, not prevention, and the difference is the same one this
        whole document keeps drawing.
    """

    max_age_s: float | None = None
    as_of: float | None = None

    @property
    def enabled(self) -> bool:
        return (self.max_age_s is not None and self.as_of is not None
                and math.isfinite(self.max_age_s) and math.isfinite(self.as_of))

    def age_of(self, when: float | None) -> float | None:
        if not self.enabled or when is None or not math.isfinite(when):
            return None
        return float(self.as_of) - float(when)

    def stale(self, when: float | None) -> bool | None:
        """None when the question cannot be answered. Future-dated is not stale.

        A record dated after ``as_of`` is not old, it is wrong, and calling it
        stale would report clock skew as an archive replay. Skew is somebody
        else's finding.
        """
        age = self.age_of(when)
        if age is None:
            return None
        return age > float(self.max_age_s)

    def as_dict(self) -> dict[str, Any]:
        return {"max_age_s": self.max_age_s, "as_of": self.as_of,
                "enabled": self.enabled}


NO_FRESHNESS = Freshness()


@dataclass
class SessionIntegrity:
    """What the stream verifier concluded about one session's records.

    Attached per session rather than per stream because a stream carries many
    sessions interleaved, and "somebody deleted a record from this stream" is a
    much weaker statement than "somebody deleted a record from THIS session".
    Every problem here is attributed to the session whose record revealed it --
    the one that arrived after the gap, or that failed to chain -- which is
    exactly the session an attacker editing a session would disturb.
    """

    with_integrity: int = 0
    without_integrity: int = 0
    streams: set[str] = field(default_factory=set)
    codes: dict[str, int] = field(default_factory=dict)
    gaps: list[dict[str, int]] = field(default_factory=list)
    chain_breaks: list[int] = field(default_factory=list)
    bad_signatures: list[int] = field(default_factory=list)
    unknown_key_ids: set[str] = field(default_factory=set)
    signatures_verified: int = 0
    reordered: int = 0
    # Keys that actually attested this session's records, and how the store
    # judged them. Carried into the verdict because "which key vouched for this"
    # is the first question asked when a key turns out to be compromised, and
    # answering it from a verdict beats re-scoring the archive.
    signing_key_ids: set[str] = field(default_factory=set)
    freshness_checked: int = 0
    oldest_signed_age_s: float | None = None

    @property
    def records(self) -> int:
        return self.with_integrity + self.without_integrity

    @property
    def attested(self) -> bool:
        """Did every record in this session carry a sidecar?"""
        return self.with_integrity > 0 and self.without_integrity == 0

    @property
    def inadmissible(self) -> list[str]:
        return sorted(c for c in self.codes if c in INADMISSIBLE)

    def note(self, code: str) -> None:
        self.codes[code] = self.codes.get(code, 0) + 1

    def as_dict(self, limits: Limits = DEFAULT_LIMITS) -> dict[str, Any]:
        cap = limits.max_evidence_items
        return {
            "records_with_integrity": self.with_integrity,
            "records_without_integrity": self.without_integrity,
            "streams": sorted(self.streams)[:cap],
            "stream_count": len(self.streams),
            "codes": dict(sorted(self.codes.items())),
            "sequence_gaps": self.gaps[:cap],
            "chain_breaks": self.chain_breaks[:cap],
            "invalid_signatures": self.bad_signatures[:cap],
            "unknown_key_ids": sorted(self.unknown_key_ids)[:cap],
            "signatures_verified": self.signatures_verified,
            "records_reordered": self.reordered,
            "signing_key_ids": sorted(self.signing_key_ids)[:cap],
            "freshness_checked": self.freshness_checked,
            "oldest_signed_age_s": self.oldest_signed_age_s,
            "attested": self.attested,
        }


@dataclass
class _Stream:
    stream_id: str
    expected: int = 0
    head: str = ""
    joined_midstream: bool = False
    # The session that owned the last record consumed from this stream. A gap
    # is attributed to the sessions on BOTH sides of it, and this is the one
    # before. Without it, deleting a record from session A on a stream that
    # multiplexes many sessions would charge the gap to whichever session
    # happened to write next -- a false positive on B and a false negative on A,
    # which is precisely backwards.
    last_session: str = ""
    # seq -> (body_digest, Integrity, session_key, record timestamp). Bounded;
    # see the verifier. The timestamp travels with the held record because key
    # windows and freshness are judged against the record's OWN clock, and by
    # the time a held record is finally consumed the raw record is long gone.
    pending: dict[int, tuple[str, Integrity, str, float | None]] = field(
        default_factory=dict)
    # Stream identity as scored, for the verdict. See Freshness: cross-run
    # replay is not preventable here, and this is what makes it auditable.
    first_seq: int | None = None
    last_seq: int | None = None


class StreamVerifier:
    """Verifies ``cohaera.integrity:1`` across a whole input, in arrival order.

    IT HAS TO BE WHOLE-INPUT, NOT PER SESSION
        A collector stream carries every session on the host, interleaved. Its
        sequence numbers count records in the stream, not in any session, so a
        verifier that ran per session would see a gap between every pair of its
        own records and report deletion on a healthy stream. This runs once over
        the input at ingest, and attributes what it finds to the session whose
        record revealed it.

    BOUNDED STATE, INCLUDING THE PART THAT IS NOT OBVIOUS
        One chain head, one expected sequence and one key reference per stream.
        The part that needed a bound is the reorder buffer: a record arriving
        early cannot be chained until the ones before it arrive, so it has to be
        held, and how many are held is a quantity the producer chooses. The
        budget is global rather than per stream, so a producer cannot multiply
        it by claiming ten thousand streams, and exhausting it is reported
        (``INTEGRITY_REORDER_BUDGET_EXHAUSTED``) rather than silently degrading
        into calling every reorder a deletion.

    REORDERING IS NOT DELETION
        On a streaming path records arrive out of order, and a verifier that
        called that a deletion would page somebody every day. A missing sequence
        number is held open while the buffer allows; if it arrives, it is a
        reorder and is counted as one; if the buffer fills or the input ends
        first, it is a gap. Both outcomes say which conclusion was reached.
    """

    def __init__(self, keys: TrustStore = EMPTY_STORE,
                 limits: Limits = DEFAULT_LIMITS,
                 freshness: Freshness = NO_FRESHNESS) -> None:
        self.keys = keys
        self.limits = limits
        self.freshness = freshness
        self.streams: dict[str, _Stream] = {}
        self.sessions: dict[str, SessionIntegrity] = {}
        self.signatures_verified = 0
        self.signature_budget_exhausted = False
        self.stream_budget_exhausted = False
        self._pending_total = 0
        self._saw_any_integrity = False
        self._saw_any_signature = False

    # -- public -----------------------------------------------------------

    def observe(self, record: dict[str, Any], integrity: Integrity | None,
                session_key: str) -> None:
        """Fold one record into its stream. Never raises."""
        state = self.sessions.get(session_key)
        if state is None:
            state = self.sessions[session_key] = SessionIntegrity()
        if integrity is None:
            state.without_integrity += 1
            return
        state.with_integrity += 1
        state.streams.add(integrity.stream_id)
        self._saw_any_integrity = True
        if integrity.signed:
            self._saw_any_signature = True

        stream = self.streams.get(integrity.stream_id)
        if stream is None:
            if len(self.streams) >= self.limits.max_integrity_streams:
                self.stream_budget_exhausted = True
                state.note(R_STREAM_BUDGET)
                return
            stream = self.streams[integrity.stream_id] = _Stream(integrity.stream_id)
            self._begin(stream, integrity, state)

        body = body_digest(record)
        # Read once, here, from the record as it arrived. Not from the assembled
        # Event: the same field is what the chain covers, and the chain is what
        # makes it worth reading at all.
        when = _finite(record.get("timestamp"))
        if integrity.seq == stream.expected:
            self._consume(stream, integrity.seq, body, integrity, session_key, when)
            # A hole was just FILLED, so anything already waiting arrived early
            # and was genuinely reordered.
            self._drain(stream, reordered=True)
        elif integrity.seq < stream.expected:
            # Already accounted for. Either a duplicate delivery or a replay of
            # a record whose position in the chain is taken.
            state.note(R_SEQUENCE_REPLAY)
        else:
            self._hold(stream, integrity.seq, body, integrity, session_key, state,
                       when)

    def finalise(self) -> None:
        """Resolve every stream at end of input. Anything still held is a gap."""
        for stream in sorted(self.streams.values(), key=lambda s: s.stream_id):
            while stream.pending:
                self._force(stream)
                self._drain(stream, reordered=False)
        # Selective stripping. A session where SOME records carry a sidecar and
        # others do not is not a session with partial coverage; it is the shape
        # an attacker produces by removing the evidence from the records they
        # edited, because a record with no integrity object cannot fail a chain
        # check. Only knowable once the whole input has been seen, which is why
        # it is decided here rather than per record.
        for state in self.sessions.values():
            if state.with_integrity and state.without_integrity:
                state.note(R_PARTIAL_INTEGRITY)
            # A freshness bound the operator set and this session could not be
            # measured against. Said once per session rather than per record:
            # the fact is about the session, and a per-record count would read
            # as a hundred problems where there is one.
            if (self.freshness.enabled and state.with_integrity
                    and not state.freshness_checked):
                state.note(R_FRESHNESS_UNVERIFIABLE)

    def summary(self) -> dict[str, Any]:
        return {
            "schema": INTEGRITY_SCHEMA,
            "streams": len(self.streams),
            "records_with_integrity": sum(s.with_integrity
                                          for s in self.sessions.values()),
            "records_without_integrity": sum(s.without_integrity
                                             for s in self.sessions.values()),
            "signatures_verified": self.signatures_verified,
            "keys_loaded": len(self.keys.keys),
            "any_integrity_evidence": self._saw_any_integrity,
            "any_signature_present": self._saw_any_signature,
            "signature_budget_exhausted": self.signature_budget_exhausted,
            "stream_budget_exhausted": self.stream_budget_exhausted,
            "freshness": self.freshness.as_dict(),
            "stream_summary": self.stream_summary(),
        }

    def stream_summary(self) -> list[dict[str, Any]]:
        """Each stream's identity and extent, for the verdict.

        This is the auditable half of replay. Cohaera cannot remember that it
        scored ``eval-collector-0`` from seq 0 to seq 812 yesterday, because it
        remembers nothing between runs. Writing that down means two verdicts can
        be compared and the repeat seen -- by a human, or by a SIEM rule over
        the field, which is a place state DOES survive.
        """
        cap = self.limits.max_evidence_items
        return [{"stream_id": s.stream_id, "first_seq": s.first_seq,
                 "last_seq": s.last_seq, "head": s.head,
                 "joined_midstream": s.joined_midstream}
                for s in sorted(self.streams.values(),
                                key=lambda s: s.stream_id)[:cap]]

    def for_session(self, session_key: str) -> SessionIntegrity:
        return self.sessions.get(session_key) or SessionIntegrity()

    # -- internals --------------------------------------------------------

    def _begin(self, stream: _Stream, integrity: Integrity,
               state: SessionIntegrity) -> None:
        """Establish the chain head from the first record seen for a stream."""
        if integrity.seq == 0:
            stream.head = chain_seed(integrity.stream_id, integrity.key_id or "")
            stream.expected = 0
            return
        # Joined mid-flight: the records before this one were never seen, so
        # nothing can attest to them. Adopt the declared predecessor as the head
        # and say plainly that the stream is only covered from here.
        stream.head = integrity.prev or ""
        stream.expected = integrity.seq
        stream.joined_midstream = True
        state.note(R_JOINED_MIDSTREAM)

    def _session(self, session_key: str) -> SessionIntegrity:
        state = self.sessions.get(session_key)
        if state is None:
            state = self.sessions[session_key] = SessionIntegrity()
        return state

    def _consume(self, stream: _Stream, seq: int, body: str,
                 integrity: Integrity, session_key: str,
                 when: float | None = None) -> None:
        """Chain- and signature-check one in-order record."""
        state = self._session(session_key)
        if stream.first_seq is None:
            stream.first_seq = seq
        stream.last_seq = seq
        expected_chain = chain_step(stream.head, body) if stream.head else None

        if expected_chain is not None and integrity.chain is not None:
            if integrity.chain != expected_chain:
                # Localises: this record is where the stream diverged from what
                # the collector signed.
                state.note(R_CHAIN_BROKEN)
                if len(state.chain_breaks) < self.limits.max_evidence_items:
                    state.chain_breaks.append(seq)
        if integrity.prev is not None and stream.head and integrity.prev != stream.head:
            state.note(R_CHAIN_BROKEN)
            if len(state.chain_breaks) < self.limits.max_evidence_items:
                state.chain_breaks.append(seq)

        # Advance on the record's OWN declared chain when it has one. A single
        # broken record would otherwise poison every record after it, turning
        # one edit into a stream-wide alarm and hiding where the edit was.
        stream.head = integrity.chain or expected_chain or stream.head
        stream.expected = seq + 1
        stream.last_session = session_key

        if integrity.signed:
            self._check_signature(stream, seq, integrity, state, when)
        elif self.keys.loaded:
            state.note(R_UNSIGNED)

    def _check_signature(self, stream: _Stream, seq: int, integrity: Integrity,
                         state: SessionIntegrity, when: float | None) -> None:
        """Verify one record's signature, then judge the key that made it.

        THE ORDER IS THE ARGUMENT, so it is spelled out rather than left to be
        inferred from the control flow:

        1. Unknown key, wrong role, or revoked key -- decided from the store
           alone, before any scalar multiplication. All three are conclusions a
           valid signature cannot overturn: a signature made by a key the
           operator retired, or never authorised to attest telemetry, or
           declared compromised, is a correctly-made signature that means
           nothing. Deciding them first also refuses to spend the most expensive
           operation in this codebase on a key that was never going to count,
           which matters because how many signatures arrive is the producer's
           choice.

        2. The signature itself.

        3. ONLY THEN the record's clock -- validity window and freshness. Both
           read the timestamp the record carries, and that timestamp is worth
           reading only once the signature has established that the collector
           wrote it. Evaluating either before step 2 would be trusting a number
           the producer chose, which is the fault this whole module exists to
           remove rather than relocate. See TrustedKey and Freshness.
        """
        if not self.keys.loaded:
            state.note(R_NO_COLLECTOR_KEYS)
            return
        key = self.keys.get(integrity.key_id)
        if key is None:
            state.note(R_KEY_UNKNOWN)
            state.unknown_key_ids.add(str(integrity.key_id))
            return
        state.signing_key_ids.add(key.key_id)
        if not key.authorises(ROLE_COLLECTOR):
            # A policy key signing telemetry. Either the operator wired the
            # wrong key into the collector, or somebody is attesting the stream
            # with a key that was trusted for something else entirely -- and the
            # second is why the roles exist.
            state.note(R_KEY_WRONG_ROLE)
            return
        if key.revoked:
            state.note(R_KEY_REVOKED)
            return
        if self.signatures_verified >= self.limits.max_signature_verifications:
            self.signature_budget_exhausted = True
            state.note(R_SIGNATURE_BUDGET)
            return
        self.signatures_verified += 1
        state.signatures_verified += 1
        message = signing_input(stream.stream_id, seq, integrity.chain or "")
        if not ed25519.verify(key.public, message, integrity.sig or b""):
            state.note(R_SIGNATURE_INVALID)
            if len(state.bad_signatures) < self.limits.max_evidence_items:
                state.bad_signatures.append(seq)
            return

        if key.windowed:
            inside = key.covers_clock(when)
            if inside is None:
                state.note(R_KEY_WINDOW_UNCHECKED)
            elif not inside:
                state.note(R_KEY_NOT_YET_VALID
                           if key.not_before is not None and when is not None
                           and when < key.not_before else R_KEY_EXPIRED)
        self._check_freshness(state, when)

    def _check_freshness(self, state: SessionIntegrity,
                         when: float | None) -> None:
        """Age one signature-verified record against the operator's bound."""
        if not self.freshness.enabled:
            return
        age = self.freshness.age_of(when)
        if age is None:
            return
        state.freshness_checked += 1
        if state.oldest_signed_age_s is None or age > state.oldest_signed_age_s:
            state.oldest_signed_age_s = age
        if self.freshness.stale(when):
            state.note(R_STALE)

    def _hold(self, stream: _Stream, seq: int, body: str, integrity: Integrity,
              session_key: str, state: SessionIntegrity,
              when: float | None = None) -> None:
        if seq in stream.pending:
            state.note(R_SEQUENCE_REPLAY)
            return
        if self._pending_total >= self.limits.max_reorder_window:
            # The buffer is full and the missing records have not arrived. Call
            # the gap, resync, and record that the decision was forced by a
            # bound rather than by evidence.
            state.note(R_REORDER_BUDGET)
            self._force(stream)
            self._drain(stream, reordered=False)
            if seq == stream.expected:
                self._consume(stream, seq, body, integrity, session_key, when)
                self._drain(stream, reordered=True)
                return
        stream.pending[seq] = (body, integrity, session_key, when)
        self._pending_total += 1

    def _drain(self, stream: _Stream, reordered: bool) -> None:
        """Consume everything now contiguous. ``reordered`` says WHY it was held.

        The distinction is not cosmetic. Records held because the sequence
        number before them was DELETED arrived perfectly in order -- they were
        waiting for something that never came -- and counting them as reordered
        made a deletion report ``INTEGRITY_RECORDS_REORDERED`` alongside the gap,
        which reads to an analyst as a delivery problem rather than as evidence
        of tampering. The caller knows which case it is: a hole filled by an
        arriving record is a reorder, a hole closed by the gap logic is not.
        """
        while stream.expected in stream.pending:
            seq = stream.expected
            body, integrity, session_key, when = stream.pending.pop(seq)
            self._pending_total -= 1
            if reordered:
                state = self._session(session_key)
                state.reordered += 1
                state.note(R_REORDERED)
            self._consume(stream, seq, body, integrity, session_key, when)

    def _force(self, stream: _Stream) -> None:
        """Declare the records between ``expected`` and the next held one gone."""
        if not stream.pending:
            return
        nxt = min(stream.pending)
        if nxt > stream.expected:
            _body, integrity, session_key, _when = stream.pending[nxt]
            gap = {"missing_from": stream.expected, "missing_to": nxt - 1,
                   "missing_count": nxt - stream.expected}
            # Both sides. The records that vanished sat between the last record
            # consumed and this one, so either session could be the one they
            # were taken from, and charging only the later one gets the common
            # case exactly wrong -- see _Stream.last_session.
            for key in dict.fromkeys((stream.last_session, session_key)):
                if not key:
                    continue
                state = self._session(key)
                state.note(R_SEQUENCE_GAP)
                if len(state.gaps) < self.limits.max_evidence_items:
                    state.gaps.append(dict(gap))
            # Resync on the surviving record's own declared predecessor. Without
            # this every record after a deletion would also fail to chain, and
            # one deletion would read as a wholly forged stream.
            stream.head = integrity.prev or ""
            stream.expected = nxt
