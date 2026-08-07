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
from dataclasses import dataclass, field
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
COLLECTOR_KEYS_SCHEMA = "cohaera.collector_keys:1"

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
# Collector keys, loaded out of band exactly as the capability manifest is
# ---------------------------------------------------------------------------


class CollectorKeyError(ValueError):
    """The key file is not a key file. Refuse it; do not half-load it."""


@dataclass(frozen=True)
class CollectorKeys:
    """Public keys the operator supplied, and the digests of the file they came
    from.

    Loaded from a path the operator names, which is the same trust model the
    capability manifest has and is honest about it. This says *these signatures
    verify under a key you supplied*. It does not say *this telemetry is
    genuine*, and rotation, revocation and multi-collector fleets need more than
    a file. ``docs/EVIDENCE-TRUST.md`` section 2 states that gap; it is the
    reason P1.1 shipped as a verifier rather than as a trust store.
    """

    keys: dict[str, bytes] = field(default_factory=dict)
    file_digest: str = ""
    semantic_digest: str = ""

    @property
    def loaded(self) -> bool:
        return bool(self.keys)

    def get(self, key_id: Any) -> bytes | None:
        if not isinstance(key_id, str) or not key_id:
            return None
        return self.keys.get(key_id)

    def as_dict(self) -> dict[str, Any]:
        return {"key_count": len(self.keys), "file_digest": self.file_digest,
                "semantic_digest": self.semantic_digest,
                "key_ids": sorted(self.keys)[:20]}

    @classmethod
    def from_obj(cls, obj: Any, file_digest: str = "",
                 limits: Limits = DEFAULT_LIMITS) -> CollectorKeys:
        if not isinstance(obj, dict):
            raise CollectorKeyError("key file root must be a JSON object")
        if obj.get("scheme") != COLLECTOR_KEYS_SCHEMA:
            raise CollectorKeyError(
                f"key file must declare scheme {COLLECTOR_KEYS_SCHEMA!r}")
        raw = obj.get("keys")
        if not isinstance(raw, dict) or not raw:
            raise CollectorKeyError("key file must carry a non-empty 'keys' object")
        if len(raw) > limits.max_collector_keys:
            raise CollectorKeyError(
                f"key file declares {len(raw)} keys, exceeding "
                f"max_collector_keys={limits.max_collector_keys}")
        keys: dict[str, bytes] = {}
        for key_id, value in raw.items():
            if not isinstance(key_id, str) or not key_id:
                raise CollectorKeyError(f"key id must be a non-empty string: {key_id!r}")
            if len(key_id) > limits.max_identity_chars:
                raise CollectorKeyError(f"key id {key_id[:32]!r} is too long")
            if not isinstance(value, str) or isinstance(value, bool):
                raise CollectorKeyError(f"key {key_id!r} must be a base64 string")
            try:
                blob = base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise CollectorKeyError(
                    f"key {key_id!r} is not valid base64: {exc}") from exc
            if len(blob) != ed25519.KEY_BYTES:
                raise CollectorKeyError(
                    f"key {key_id!r} is {len(blob)} bytes, expected "
                    f"{ed25519.KEY_BYTES}")
            keys[key_id] = blob
        payload = json.dumps({"scheme": COLLECTOR_KEYS_SCHEMA,
                              "keys": {k: base64.b64encode(v).decode("ascii")
                                       for k, v in sorted(keys.items())}},
                             sort_keys=True, separators=(",", ":"))
        return cls(keys=keys, file_digest=file_digest,
                   semantic_digest=hashlib.sha256(
                       payload.encode("utf-8")).hexdigest()[:16])

    @classmethod
    def from_file(cls, path: str | Path,
                  limits: Limits = DEFAULT_LIMITS) -> CollectorKeys:
        p = Path(path)
        with p.open("rb") as fh:
            blob = fh.read(limits.max_keyfile_bytes + 1)
        if len(blob) > limits.max_keyfile_bytes:
            raise CollectorKeyError(
                f"{p}: key file exceeds max_keyfile_bytes={limits.max_keyfile_bytes}")
        try:
            obj = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorKeyError(f"{p}: not readable as UTF-8 JSON: {exc}") from exc
        return cls.from_obj(obj, file_digest=hashlib.sha256(blob).hexdigest()[:16],
                            limits=limits)


EMPTY_KEYS = CollectorKeys()


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

# The codes that say the evidence is not admissible, as opposed to merely
# incomplete. A session carrying any of these has findings that rest on a stream
# somebody could have edited, and CH06 says so at critical.
INADMISSIBLE = frozenset({R_SEQUENCE_GAP, R_CHAIN_BROKEN, R_SIGNATURE_INVALID,
                          R_KEY_UNKNOWN, R_SEQUENCE_REPLAY, R_PARTIAL_INTEGRITY})


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
    # seq -> (body_digest, Integrity, session_key). Bounded; see the verifier.
    pending: dict[int, tuple[str, Integrity, str]] = field(default_factory=dict)


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

    def __init__(self, keys: CollectorKeys = EMPTY_KEYS,
                 limits: Limits = DEFAULT_LIMITS) -> None:
        self.keys = keys
        self.limits = limits
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
        if integrity.seq == stream.expected:
            self._consume(stream, integrity.seq, body, integrity, session_key)
            # A hole was just FILLED, so anything already waiting arrived early
            # and was genuinely reordered.
            self._drain(stream, reordered=True)
        elif integrity.seq < stream.expected:
            # Already accounted for. Either a duplicate delivery or a replay of
            # a record whose position in the chain is taken.
            state.note(R_SEQUENCE_REPLAY)
        else:
            self._hold(stream, integrity.seq, body, integrity, session_key, state)

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
        }

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
                 integrity: Integrity, session_key: str) -> None:
        """Chain- and signature-check one in-order record."""
        state = self._session(session_key)
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
            self._check_signature(stream, seq, integrity, state)
        elif self.keys.loaded:
            state.note(R_UNSIGNED)

    def _check_signature(self, stream: _Stream, seq: int, integrity: Integrity,
                         state: SessionIntegrity) -> None:
        if not self.keys.loaded:
            state.note(R_NO_COLLECTOR_KEYS)
            return
        public = self.keys.get(integrity.key_id)
        if public is None:
            state.note(R_KEY_UNKNOWN)
            state.unknown_key_ids.add(str(integrity.key_id))
            return
        if self.signatures_verified >= self.limits.max_signature_verifications:
            self.signature_budget_exhausted = True
            state.note(R_SIGNATURE_BUDGET)
            return
        self.signatures_verified += 1
        state.signatures_verified += 1
        message = signing_input(stream.stream_id, seq, integrity.chain or "")
        if not ed25519.verify(public, message, integrity.sig or b""):
            state.note(R_SIGNATURE_INVALID)
            if len(state.bad_signatures) < self.limits.max_evidence_items:
                state.bad_signatures.append(seq)

    def _hold(self, stream: _Stream, seq: int, body: str, integrity: Integrity,
              session_key: str, state: SessionIntegrity) -> None:
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
                self._consume(stream, seq, body, integrity, session_key)
                self._drain(stream, reordered=True)
                return
        stream.pending[seq] = (body, integrity, session_key)
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
            body, integrity, session_key = stream.pending.pop(seq)
            self._pending_total -= 1
            if reordered:
                state = self._session(session_key)
                state.reordered += 1
                state.note(R_REORDERED)
            self._consume(stream, seq, body, integrity, session_key)

    def _force(self, stream: _Stream) -> None:
        """Declare the records between ``expected`` and the next held one gone."""
        if not stream.pending:
            return
        nxt = min(stream.pending)
        if nxt > stream.expected:
            _body, integrity, session_key = stream.pending[nxt]
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
