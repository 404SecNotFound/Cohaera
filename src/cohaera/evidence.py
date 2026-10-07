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
import contextlib
import hashlib
import json
import math
import os
import re
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, BinaryIO

from . import ed25519
from .identity import canonical, digest
from .limits import (
    DEFAULT_LIMITS,
    DEFECT_APPROVAL_TYPE,
    DEFECT_ENFORCEMENT_TYPE,
    DEFECT_INTEGRITY_TYPE,
    DEFECT_RECEIPT_TYPE,
    Limits,
)
from .validate import as_finite_float, identity_text, strict_json_loads
from .validate import timestamp as record_clock

INTEGRITY_SCHEMA = "cohaera.integrity:1"
RECEIPT_SCHEMA = "cohaera.receipt:1"
APPROVAL_SCHEMA = "cohaera.approval:1"
APPROVAL_LEDGER_SCHEMA = "cohaera.approval_ledger:1"
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
# E26. Approvals are issued by a different party from the one that signs
# telemetry -- a human, a workflow engine, a ticketing system -- and the whole
# argument for signing an approval is that the agent cannot mint one. A
# deployment where the collector key also signs approvals has one party doing
# both jobs, which is exactly the arrangement the signature was meant to rule
# out, so the store can express the difference and the verdict reports it.
ROLE_APPROVAL = "approval"            # issues cohaera.approval:1
VALID_ROLES = frozenset({ROLE_COLLECTOR, ROLE_POLICY, ROLE_APPROVAL})

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
#
# F-01. There used to be three of these and the ordering between them was
# wrong in the one case that matters. A producer emits BOTH `arg_digest` and
# `tool_args`; the declared digest was taken whenever it was present, with the
# disagreement recorded as a flag nothing acted on. So a call sending to the
# attacker, declaring the digest of a send to Alice, inherited Alice's approval
# and CH04 stayed silent -- which defeats the whole point of requiring a
# complete binding, because the producer chooses the value being bound to.
#
# The digest of arguments Cohaera actually saw is the authoritative one. It is
# the only one that describes the call rather than describing what the producer
# would like the call to be taken for.
ARGS_CONFIRMED = "declared_and_recomputed"  # both present, and they agree
ARGS_RECOMPUTED = "recomputed"         # Cohaera hashed the captured args
ARGS_DECLARED = "producer_declared"    # the producer stated a digest, no args
ARGS_CONTRADICTED = "producer_contradicted"  # both present, and they DISAGREE
ARGS_ABSENT = "none"

# A call whose two argument identities disagree cannot be bound by anything.
# Not "bound weakly" -- an approval or receipt naming either digest is naming a
# call the telemetry itself cannot agree on, and no honest emitter produces
# this. See model.ToolCall.arg_digest_disagrees.
ARGS_UNBINDABLE = frozenset({ARGS_CONTRADICTED})

DIGEST_PREFIX = "sha256:"

# EH-08. Exactly sixty-four lowercase hex digits. Every digest field here used
# to be checked with ``int(value, 16)``, which is a NUMBER parser and accepts a
# good deal that is not hex: a ``0x`` prefix, ``_`` digit separators, a leading
# sign, surrounding whitespace, and any Unicode decimal digit (``int`` reads
# U+0661, ARABIC-INDIC DIGIT ONE, as 1). Each of those is a string that
# compares unequal to the digest
# Cohaera computes while passing the shape check -- a chain ``prev`` of
# ``0xabc...`` read as a well-formed predecessor that matched nothing, which
# downstream is a chain break charged to the producer's formatting. Matched
# AFTER ``.lower()`` so that uppercase hex, which hashlib never emits but a
# hand-written sidecar might, is still read rather than refused.
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _hex64(value: str) -> str | None:
    """``value`` lowercased if it is exactly 64 hex digits, else None."""
    lowered = value.lower()
    return lowered if _HEX64.fullmatch(lowered) else None


# EH-03. The octet that separates fields in every signing input here is
# ``\x1f``, and ``validate.identity_text`` admits it inside a value. So an
# identity carrying one shifts every field after it: a ``tool_id`` of
# ``wire_transfer_send\x1fsha256:D`` with no ``arg_digest`` and nonce ``n``
# signs to the same bytes as ``wire_transfer_send`` WITH that digest and nonce
# ``\x1fn``, and a signature over the first verifies the second. Refusing the
# whole C0 range plus DEL rather than the one separator, because a value with a
# control character in it is not an identity anybody minted on purpose, and a
# narrower rule would be relitigated the next time a separator changed.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def has_control_char(value: str | None) -> bool:
    return value is not None and _CONTROL.search(value) is not None


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
    body = _hex64(value[len(DIGEST_PREFIX):])
    return None if body is None else DIGEST_PREFIX + body


def _short(value: Any, limits: Limits) -> str | None:
    text, _ = identity_text(value, limits.max_identity_chars, "x", "x")
    return text


def _finite(value: Any) -> float | None:
    # One conversion, shared with validate: a 400-digit ``granted_at`` used to
    # raise OverflowError here and kill the run. See validate.as_finite_float.
    return as_finite_float(value)


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
        """``None`` for anything that names no call at all.

        R-01. This used to return ``Binding(None, None, None)`` for ``{}``,
        which is not a weak binding -- it is the absence of one, and every
        caller downstream treated it as a binding that had been checked. An
        object with no usable field in it is a malformed binding and the record
        carrying it is rejected with a defect, per the rejection-vs-defect rule
        in the module docstring.
        """
        if not isinstance(obj, dict):
            return None
        out = cls(span_id=_short(obj.get("span_id"), limits),
                  tool_id=_short(obj.get("tool_id"), limits),
                  arg_digest=digest_text(obj.get("arg_digest")))
        if not (out.span_id or out.tool_id or out.arg_digest):
            return None
        return out


# How well a binding held. Ordered from strongest to weakest, because the
# distinction is the whole mechanism and collapsing it to a boolean is how a
# decorative signature field gets shipped.
BOUND_EXACT = "bound"                  # span, tool AND arg digest all matched
BOUND_SPAN_ONLY = "bound_span_only"    # span and tool matched; args unverifiable
BOUND_ARG_MISMATCH = "arg_mismatch"    # span matched, arguments did NOT
BOUND_NONE = "unbound"                 # names no call in this session


# ---------------------------------------------------------------------------
# How much an effect receipt is WORTH, which is a different axis from BOUND_*.
#
# Binding asks "does this receipt name THIS call?". These ask "did the authority
# actually issue it?". CH07 conflated the two: a receipt binding exactly was
# treated as proof the effect occurred, and the finding said so in as many
# words -- "an identifier minted by the system the action happened to, from a
# namespace the agent does not control". Nothing establishes either clause.
# `authority` is a producer-written string, and a producer that writes the
# record writes the receipt inside it.
#
# The tiers are named in full because two of them are NOT REACHABLE today and
# the gap is the point. cohaera.receipt:1 carries no signature and the trust
# store has no role for receipt authorities, so nothing can currently climb
# past BOUND. Naming the ceiling is how the schema gap stays visible instead of
# being rediscovered by the next reviewer.
# ---------------------------------------------------------------------------

RECEIPT_CLAIMED = "claimed"
"""Parsed, and that is all. The authority is a string the producer chose."""

RECEIPT_BOUND = "bound"
"""The binding names this exact call. Still issued by nobody in particular:
binding proves the receipt is ABOUT this call, never that it is genuine."""

RECEIPT_AUTHENTICATED = "authenticated"
"""The authority attested it -- a signature over the receipt, verified against
a key the operator declared for that authority. NOT REACHABLE: the schema has
no signature field and the trust store has no receipt role."""

RECEIPT_RECONCILED = "reconciled"
"""Confirmed against the authority itself: the identifier was looked up and it
exists. NOT REACHABLE, and out of scope for a detector that reads a stream."""

# ---------------------------------------------------------------------------
# cohaera.approval:1 assurance, tiered for the same reason receipts are.
#
# E26 is four separate weaknesses and only the first was ever closed: a
# VERBATIM copy does not cover a second call, because the binding names a span.
# Rewriting that one field defeated it, nothing recorded an approval as spent,
# and the validity window was optional so an approval could cover forever.
#
# The tiers exist rather than a boolean because requiring signatures outright
# would stop every deployed approval from covering anything, and CH04 would
# fire on every authorised action in the world. The operator decides whether an
# untrusted tier still covers; the verdict always says which tier it got.
# ---------------------------------------------------------------------------

APPROVAL_CLAIMED = "claimed"
"""Parsed. Somebody asserted an approval exists. Nothing more."""

APPROVAL_BOUND = "bound"
"""The subject names this exact call -- span, tool and argument digest. Proves
the approval is ABOUT this call. Proves nothing about who issued it, which is
E26 point 2: one rewritten field moves a real approval onto another call."""

APPROVAL_AUTHENTICATED = "authenticated"
"""An issuer signed it, and the signature verified against a key the operator
gave the `approval` role. The signature covers the span, so the rewrite that
defeats BOUND invalidates it."""

APPROVAL_SINGLE_USE = "single_use"
"""Authenticated AND its nonce had not been spent before. Reachable only ON TOP
of a verified signature: an attacker who can rewrite the span can rewrite the
nonce in the same edit, so a nonce on an unsigned approval is decoration."""

APPROVAL_TRUSTED_TIERS = frozenset({APPROVAL_AUTHENTICATED, APPROVAL_SINGLE_USE})
"""The tiers where the approval is evidence rather than a claim. Unlike
RECEIPT_AUTHENTIC this set is REACHABLE -- the schema has a signature field and
the store has a role -- but it is empty in any deployment that has not issued
keys, which is the state every deployment starts in."""


RECEIPT_AUTHENTIC = frozenset({RECEIPT_AUTHENTICATED, RECEIPT_RECONCILED})
"""The tiers that support a high-confidence accusation. Empty in practice
today, which is the honest state and is asserted by test."""

# Strongest last. Used only to compare tiers; the strings themselves are the
# wire vocabulary and stay as they are.
RECEIPT_TIER_ORDER = (RECEIPT_CLAIMED, RECEIPT_BOUND, RECEIPT_AUTHENTICATED,
                      RECEIPT_RECONCILED)

# ---------------------------------------------------------------------------
# What the ADAPTER said the identifier is worth, which is a third axis.
#
# EH-05. ``tools/receipt_adapters.py`` has written ``assurance`` into every
# receipt since R-17, precisely so that an SMTP ``Message-ID`` the client
# composed would not read like one the provider returned. The parser threw the
# field away, so the two read identically: a ``client_claimed`` receipt bound
# to a failed call produced the same ``bound`` trust, and the same CH07
# finding, as a provider-minted one. The field is the adapter's own statement
# that its evidence is weak, and a verifier that drops it is overruling the
# one party in a position to know.
#
# Each level caps the trust tier a receipt may reach. ``client_claimed`` caps
# at CLAIMED: an identifier the caller may have minted is drawn from a
# namespace the agent controls, which is the one property the mechanism needs
# and the one a binding cannot supply. ``provider_returned_object`` caps at
# BOUND: it can name this call, and it can never attest THIS operation,
# because the identifier is the same for every write to the object.
# ``provider_returned_operation`` is uncapped. An ABSENT assurance is uncapped
# too -- the field is optional, every receipt written before R-17 lacks it,
# and refusing those would switch CH07 off for a producer that has not
# upgraded its adapter. An unrecognised value is absent-and-flagged, never
# read as the strongest level.
# ---------------------------------------------------------------------------

ASSURANCE_PROVIDER_OPERATION = "provider_returned_operation"
ASSURANCE_PROVIDER_OBJECT = "provider_returned_object"
ASSURANCE_CLIENT_CLAIMED = "client_claimed"
RECEIPT_ASSURANCE_CEILING: dict[str, str] = {
    ASSURANCE_PROVIDER_OPERATION: RECEIPT_RECONCILED,
    ASSURANCE_PROVIDER_OBJECT: RECEIPT_BOUND,
    ASSURANCE_CLIENT_CLAIMED: RECEIPT_CLAIMED,
}
VALID_RECEIPT_ASSURANCE = frozenset(RECEIPT_ASSURANCE_CEILING)


def weaker_receipt_tier(a: str, b: str) -> str:
    """The lower of two receipt tiers. Unknown strings rank lowest."""
    rank = {t: i for i, t in enumerate(RECEIPT_TIER_ORDER)}
    return a if rank.get(a, -1) <= rank.get(b, -1) else b


# R-01/R-10. ``BOUND_SPAN_ONLY`` used to sit in this set, and that single line
# was the difference between a mechanism and a decoration. A span-only binding
# says an identifier was presented for a call with this span and this name; it
# says nothing whatsoever about WHAT the call did, which is the only question
# either a receipt or an approval is asked. An approval for send_email to alice
# covered send_email to an attacker, and a receipt bound to nothing at all
# raised a critical contradiction.
#
# The two sets are separate rather than one ordered list because they answer
# different questions and are read from different modules. TRUSTED is the only
# one that may gate a trust decision -- suppressing a finding, or asserting a
# contradiction. CONTEXT is what an analyst is shown so that "a receipt was
# present but did not constrain the arguments" stays visible instead of being
# rounded to silence.
BINDING_TRUSTED = frozenset({BOUND_EXACT})
BINDING_CONTEXT = frozenset({BOUND_SPAN_ONLY})


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
    # E30. The collector's statement that this is the LAST record of the
    # stream. Folded into the signing input, so it cannot be added to or
    # removed from a signed record without the signature failing. A stream
    # that ends without a verified final record is reported as not closed;
    # under --require-closed-streams that is inadmissible, which is what
    # makes cutting the tail off a signed stream detectable at all.
    final: bool = False

    @property
    def signed(self) -> bool:
        return self.sig is not None and self.key_id is not None

    @property
    def chained(self) -> bool:
        """Does this sidecar actually place the record in a chain? F-03.

        ``stream_id`` and ``seq`` alone are two numbers the producer wrote.
        What makes a sequence position checkable is ``prev`` and ``chain``:
        with them the position is covered by the hash chain, and the chain by
        whatever signature reaches it, so a record cannot be moved without the
        move being detectable. Without them the sequence is a preference.

        The distinction was not being drawn, so ordering -- which CH03 and CH04
        both rest on -- accepted a sequence from a sidecar carrying neither. A
        producer emitting `{scheme, stream_id, seq}` and nothing else decided
        what happened before what.
        """
        return bool(self.prev) and bool(self.chain)

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
        final_raw = obj.get("final")
        if final_raw is not None and final_raw is not True:
            # `true` or absent, nothing else. A producer writing "yes" or 1
            # has not closed anything, and a sidecar that cannot say whether
            # it closes the stream is refused whole, as a malformed `sig` is.
            return None, (DEFECT_INTEGRITY_TYPE,)
        return cls(
            stream_id=stream_id, seq=seq,
            prev=_hex_or_none(obj.get("prev")),
            chain=_hex_or_none(obj.get("chain")),
            key_id=_short(obj.get("key_id"), limits),
            sig=sig,
            final=final_raw is True,
        ), ()


# A SHA-256 hex digest is 64 characters. F-14: `prev` and `chain` are outputs
# of `hashlib.sha256().hexdigest()` and nothing else, and accepting any length
# of hex turned a bounded field into an unbounded one that is then copied into
# the verdict and multiplied across every session in the run. Twelve records
# carrying a 64 KiB chain each produced 788 KB of input and 9.58 MB of output:
# a 12.15x amplification against a SIEM that bills by ingest, from accepted
# input, at exit code zero.
CHAIN_HEX_CHARS = 64


def _sig_bytes(value: Any) -> bytes | None:
    """An Ed25519 signature, base64, or None.

    Base64 rather than hex because that is what `cohaera.integrity:1` already
    uses for the same 64 bytes, and two encodings for one kind of field is how
    a producer ends up emitting the wrong one. `validate=True` for the reason
    stated there: base64 that silently ignores stray characters would let two
    different strings decode to the same signature.
    """
    if not isinstance(value, str) or isinstance(value, bool) or not value:
        return None
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return blob if len(blob) == ed25519.SIG_BYTES else None


def _hex_or_none(value: Any) -> str | None:
    if not isinstance(value, str) or isinstance(value, bool) or not value:
        return None
    if len(value) != CHAIN_HEX_CHARS:
        return None
    return _hex64(value)


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


def signing_input(stream_id: str, seq: int, chain: str,
                  final: bool = False) -> bytes:
    """``scheme || stream_id || seq || chain[n]``, plus ``final`` on the last record.

    The signature covers the CHAIN HEAD, not the record. That is what lets one
    verified signature cover every record before it, so a collector may sign
    every record or every kth without the verifier changing -- and it is why
    signature verification is bounded rather than per-record work.

    E30. A closing record signs one more field, the literal ``final``, so that
    the statement "nothing follows this" is the collector's and not the
    producer's. Non-final records sign exactly what they always did, which is
    why every signature made before this field existed still verifies.
    """
    parts = [INTEGRITY_SCHEMA.encode("utf-8"), stream_id.encode("utf-8"),
             str(seq).encode("ascii"), chain.encode("utf-8")]
    if final:
        parts.append(b"final")
    return b"\x1f".join(parts)


def approval_signing_input(*, decision: str, span_id: str, tool_id: str | None,
                           arg_digest: str | None, nonce: str | None,
                           granted_at: float | None,
                           expires_at: float | None) -> bytes:
    """The exact bytes an approval issuer signs.

    A FIXED FIELD LIST, not canonical JSON, and the choice is the same one
    `capabilities` makes about the manifest: a signature embedded in the
    document it signs has to be excised before hashing, which is a
    canonicalisation problem, and canonicalisation problems are where signature
    bugs live. Seven fields, ordered, joined by an octet that cannot appear in
    an identity that survived validation.

    EVERY FIELD AN ATTACKER WOULD REWRITE IS IN HERE. `span_id` above all --
    that is the single field EVASION.md E26 rewrites, and a signing input that
    omitted it would leave the whole mechanism decorative. `nonce` is covered so
    a spent approval cannot be re-minted with a fresh one; `expires_at` is
    covered AND required, so an issuer cannot sign an eternal approval.

    Floats are formatted with `repr` so that the value that round-trips through
    JSON is the value that was signed. Formatting them any other way makes the
    verifier and the issuer disagree about a number they both hold.

    EH-03. Raises ``ValueError`` if any text field carries a control character,
    because the join above is only unambiguous while the separator cannot
    occur inside a field. ``Approval.parse`` refuses such an approval before it
    gets here; this guard is for the SIGNER, so that no issuer can mint an
    approval whose bytes also spell a differently-bound one. The wire format is
    unchanged: every approval that was ever validly signed still verifies.
    """
    for name, text in (("decision", decision), ("span_id", span_id),
                       ("tool_id", tool_id), ("arg_digest", arg_digest),
                       ("nonce", nonce)):
        if has_control_char(text):
            raise ValueError(
                f"approval field {name!r} contains a control character, which "
                f"would make the signing input ambiguous; refusing to sign")

    def num(value: float | None) -> bytes:
        return b"" if value is None else repr(float(value)).encode("ascii")

    return b"\x1f".join((
        APPROVAL_SCHEMA.encode("utf-8"),
        decision.encode("utf-8"),
        span_id.encode("utf-8"),
        (tool_id or "").encode("utf-8"),
        (arg_digest or "").encode("utf-8"),
        (nonce or "").encode("utf-8"),
        num(granted_at),
        num(expires_at),
    ))


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
    # EH-05. The adapter's own statement of what the identifier is worth, and
    # where it lives. Both optional on the wire; see RECEIPT_ASSURANCE_CEILING.
    assurance: str | None = None
    scope: dict[str, str] | None = None
    # True when the adapter wrote an ``assurance`` nothing here could read.
    # Kept apart from ``assurance`` so the unreadable value is ABSENT (never
    # coerced to a level the adapter did not state) while still failing
    # closed: see trust_ceiling.
    assurance_unreadable: bool = False

    @property
    def trust_ceiling(self) -> str:
        """The highest trust tier this receipt's declared assurance supports.

        An absent assurance is uncapped; an UNREADABLE one caps at CLAIMED.
        The two differ on purpose and in the direction that fails closed: the
        adapter said something about its own evidence and the statement could
        not be read, and the one thing that must not happen is for a typo to
        read as the strongest level.
        """
        if self.assurance_unreadable:
            return RECEIPT_CLAIMED
        if self.assurance is None:
            return RECEIPT_RECONCILED
        return RECEIPT_ASSURANCE_CEILING.get(self.assurance, RECEIPT_CLAIMED)

    def capped(self, tier: str) -> str:
        """``tier``, lowered to what the declared assurance supports.

        The caller establishes the tier from binding (and one day from a
        signature); this is the adapter's veto over it. A ``client_claimed``
        receipt that binds exactly is still a receipt the caller may have
        minted, and the verdict has to say ``claimed`` for it.
        """
        return weaker_receipt_tier(tier, self.trust_ceiling)

    def as_dict(self) -> dict[str, Any]:
        return {"authority": self.authority, "kind": self.kind,
                "identifier": self.identifier, "observed_at": self.observed_at,
                "binding": self.binding.as_dict(),
                "assurance": self.assurance,
                "assurance_unreadable": self.assurance_unreadable,
                "trust_ceiling": self.trust_ceiling,
                "scope": dict(self.scope) if self.scope is not None else None}

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
        codes: tuple[str, ...] = ()
        # EH-05. Absent-and-flagged for both optional fields. A malformed
        # assurance must not read as the strongest level, and it must not
        # refuse the receipt either: the receipt still names a call, and what
        # it is worth is capped at CLAIMED by ``trust_ceiling`` rather than
        # guessed. ``_short`` already treats a non-string as absent; a string
        # outside the vocabulary is the case that needs the explicit branch.
        assurance_raw = obj.get("assurance")
        assurance: str | None = None
        unreadable = False
        if assurance_raw is not None:
            text = _short(assurance_raw, limits)
            if text is None or text not in VALID_RECEIPT_ASSURANCE:
                codes, unreadable = (DEFECT_RECEIPT_TYPE,), True
            else:
                assurance = text
        scope_raw = obj.get("scope")
        scope: dict[str, str] | None = None
        if scope_raw is not None:
            scope = _scope(scope_raw, limits)
            if scope is None:
                codes = (DEFECT_RECEIPT_TYPE,)
        return cls(authority=authority, kind=kind, identifier=identifier,
                   binding=binding,
                   observed_at=_finite(obj.get("observed_at")),
                   assurance=assurance, scope=scope,
                   assurance_unreadable=unreadable), codes


def _scope(value: Any, limits: Limits) -> dict[str, str] | None:
    """A receipt's ``scope``: a flat object of bounded identity strings.

    None for anything else. Values are matched for identity -- an account id,
    a region, a repository -- so they get ``identity_text``'s rules rather than
    being stringified. A single bad entry makes the whole scope absent, because
    half a scope would locate the identifier in no account at all while
    looking as if it had.
    """
    if not isinstance(value, dict) or not value:
        return None
    if len(value) > limits.max_evidence_items:
        return None
    out: dict[str, str] = {}
    for key, text in value.items():
        if not isinstance(key, str) or not key or len(key) > limits.max_identity_chars:
            return None
        item = _short(text, limits)
        if item is None:
            return None
        out[key] = item
    return out


# ---------------------------------------------------------------------------
# cohaera.approval:1
# ---------------------------------------------------------------------------


# Where a decision reached Cohaera, which is not the same question as who made
# it. ``granted_by`` is a string the producer chose; this is the path the record
# travelled. Every approval Cohaera can parse today arrives IN BAND -- on the
# same event stream the agent produces -- so an "approved" verdict is the
# producer's claim that a decision was made, not an authorization fact Cohaera
# established. POLICY_ENGINE is named and emitted by nothing, exactly as the
# three unemitted surfaces in checks.py are named: an operator can ask whether
# any of their approvals arrive out of band instead of discovering after an
# incident that none of them do.
APPROVAL_ORIGIN_IN_BAND = "in_band"
APPROVAL_ORIGIN_POLICY_ENGINE = "policy_engine"

# EH-03. The fields an approval signature covers, in signing order, named so
# that the verdict can carry them beside ``approval_assurance``. The verdict
# prints ``granted_by``, ``policy_id``, ``policy_digest`` and ``enforcement``
# next to the word "authenticated", and none of the four is signed: an
# attacker holding an authenticated approval can rewrite who granted it and
# under which policy without disturbing the signature. The signing input is
# NOT widened to cover them, because every approval issued to date would stop
# verifying; the verdict says which fields the signature reaches instead, so
# an analyst does not have to know this paragraph.
APPROVAL_SIGNED_FIELDS = ("scheme", "decision", "subject.span_id",
                          "subject.tool_id", "subject.arg_digest", "nonce",
                          "granted_at", "expires_at")
APPROVAL_UNSIGNED_FIELDS = ("granted_by", "policy_id", "policy_digest",
                            "enforcement", "signature.key_id")


@dataclass(frozen=True)
class Approval:
    """One policy CLAIM, bound to one call.

    Not "one policy decision". The decision was made somewhere Cohaera cannot
    see; what is in hand is an assertion that it happened, carried on a stream
    the subject of the decision produced. ``origin`` records which, and it is
    emitted so that an analyst reading ``approved`` in a verdict can tell the
    claim from the fact without reading this docstring.
    """

    decision: str
    subject: Binding
    granted_by: str | None = None
    granted_at: float | None = None
    expires_at: float | None = None
    policy_id: str | None = None
    policy_digest: str | None = None
    enforcement: str = ENFORCEMENT_UNDECLARED
    origin: str = APPROVAL_ORIGIN_IN_BAND
    # ---- E26 ------------------------------------------------------------
    # Present on the wire. `verified` and `unspent` are NOT: they are set by
    # the verifier and the ledger, so an approval cannot arrive claiming to be
    # authenticated. That is the same rule `IntegrityRecord` follows and it is
    # the reason the tier is a property rather than a field.
    nonce: str | None = None
    key_id: str | None = None
    signature: bytes | None = None
    verified: bool = False
    unspent: bool | None = None

    @property
    def bound(self) -> bool:
        """Does the subject name this call completely -- span, tool, args?

        Completeness of the SUBJECT, judged without a call in hand. Whether it
        matches a particular call is `Binding`'s job and a different question.
        """
        s = self.subject
        return bool(s.span_id and s.tool_id and s.arg_digest)

    @property
    def signable(self) -> bool:
        """Could this approval carry a meaningful signature at all?

        `expires_at` is required, and that is how E26 point 4 closes without a
        flag: the signing input covers the expiry, so an issuer physically
        cannot mint a signed approval that never expires. An approval with a
        signature and no window is refused before any curve arithmetic.
        """
        return bool(self.signature and self.key_id
                    and self.expires_at is not None)

    @property
    def tier(self) -> str:
        if self.verified and self.unspent is True:
            return APPROVAL_SINGLE_USE
        if self.verified:
            return APPROVAL_AUTHENTICATED
        return APPROVAL_BOUND if self.bound else APPROVAL_CLAIMED

    @property
    def trusted(self) -> bool:
        return self.tier in APPROVAL_TRUSTED_TIERS

    def signing_input(self) -> bytes:
        return approval_signing_input(
            decision=self.decision, span_id=self.subject.span_id or "",
            tool_id=self.subject.tool_id, arg_digest=self.subject.arg_digest,
            nonce=self.nonce, granted_at=self.granted_at,
            expires_at=self.expires_at)

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
                "enforcement": self.enforcement,
                "approval_origin": self.origin,
                "approval_assurance": self.tier,
                "nonce_present": self.nonce is not None,
                "issuer_key_id": self.key_id,
                # EH-03. What a signature on this approval covers, whether or
                # not one verified: ``approval_assurance`` says that. Static by
                # design -- it describes the format, so a reader of one verdict
                # learns that ``granted_by`` beside "authenticated" is a claim.
                "signed_fields": list(APPROVAL_SIGNED_FIELDS)}

    @classmethod
    def parse(cls, obj: Any, limits: Limits = DEFAULT_LIMITS
              ) -> tuple[Approval | None, tuple[str, ...]]:
        if obj is None:
            return None, ()
        if not isinstance(obj, dict) or obj.get("scheme") != APPROVAL_SCHEMA:
            return None, (DEFECT_APPROVAL_TYPE,)
        decision = obj.get("decision")
        # Type before membership. ``in`` against a frozenset hashes its
        # operand, and a record carrying ``"decision": {}`` raised
        # ``TypeError: unhashable type`` from a parser whose contract is
        # absent-and-flagged. Same fault COH-R06 closed in the manifest loader.
        if not isinstance(decision, str) or decision not in VALID_DECISIONS:
            return None, (DEFECT_APPROVAL_TYPE,)
        subject = Binding.parse(obj.get("subject"), limits)
        if subject is None or not subject.span_id:
            # An approval that names no span binds to nothing. Accepting it
            # would recreate the exact fault this schema exists to remove: a
            # broad approval covering whatever came next.
            return None, (DEFECT_APPROVAL_TYPE,)
        raw_sig = obj.get("signature")
        sig: dict[str, Any] = raw_sig if isinstance(raw_sig, dict) else {}
        enforcement = obj.get("enforcement")
        codes: tuple[str, ...] = ()
        if enforcement is None:
            enforcement = ENFORCEMENT_UNDECLARED
        elif not isinstance(enforcement, str) or enforcement not in VALID_ENFORCEMENT:
            enforcement, codes = ENFORCEMENT_UNDECLARED, (DEFECT_ENFORCEMENT_TYPE,)
        granted_by = _short(obj.get("granted_by"), limits)
        policy_id = _short(obj.get("policy_id"), limits)
        nonce = _short(obj.get("nonce"), limits)
        key_id = _short(sig.get("key_id"), limits)
        if any(has_control_char(text) for text in (
                subject.span_id, subject.tool_id, nonce, granted_by, policy_id,
                key_id)):
            # EH-03. A control character inside an identity makes the signing
            # input ambiguous (see approval_signing_input), and no identity
            # anybody minted on purpose contains one. Rejection, not defect:
            # with the signed fields in doubt there is nothing left of the
            # approval to keep, and keeping the unsigned ones would let a
            # producer buy a differently-bound approval with a byte. The
            # unsigned identities are held to the same rule so that the
            # guarantee is one sentence rather than a table.
            return None, (DEFECT_APPROVAL_TYPE,)
        return cls(
            decision=decision, subject=subject,
            granted_by=granted_by,
            granted_at=_finite(obj.get("granted_at")),
            expires_at=_finite(obj.get("expires_at")),
            policy_id=policy_id,
            policy_digest=digest_text(obj.get("policy_digest")),
            enforcement=enforcement,
            # Parsed, never trusted here. `verified` stays False until a key
            # says otherwise, so a producer cannot ship `verified: true`.
            nonce=nonce,
            key_id=key_id,
            signature=_sig_bytes(sig.get("sig")),
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
    # Type first: ``"enforcement": {}`` on a policy event hashed a dict here
    # and the TypeError took the whole run with it, four good sessions and all.
    if isinstance(value, str) and value in VALID_ENFORCEMENT:
        return value, ()
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
            obj = strict_json_loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
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
    if not ed25519.admissible_public_key(blob):
        # The trust store is where a key becomes something Cohaera will believe,
        # so it is where a key that nobody could have generated gets refused BY
        # NAME rather than carried and hoped about. `verify` rejects the
        # small-order points too -- it has to, since it is reachable without
        # this parser -- but the cheap check there cannot afford the full
        # prime-order test, and this can: it runs once per key at load, not once
        # per signature.
        raise TrustStoreError(
            f"key {key_id!r} is not a usable Ed25519 public key: it is not a "
            "canonical point of order L on the curve. A key of small order "
            "cannot sign anything, and a verifier that accepts one can be made "
            "to verify anything.")
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
        if not isinstance(artifact, str) or artifact not in VALID_POLICY_ARTIFACTS:
            raise PolicySignatureError(
                f"signature declares artifact {artifact!r}; valid artifacts are "
                f"{sorted(VALID_POLICY_ARTIFACTS)}")
        digest = obj.get("file_sha256")
        if (not isinstance(digest, str) or isinstance(digest, bool)
                or len(digest) != 64):
            raise PolicySignatureError(
                "signature 'file_sha256' must be a 64-character hex digest")
        # EH-08. Strict, not ``int(digest, 16)``: see _HEX64.
        if _hex64(digest) is None:
            raise PolicySignatureError(
                "signature 'file_sha256' is not hexadecimal")
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
            obj = strict_json_loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
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


def stream_sha256(fh: BinaryIO, max_bytes: int, name: str = "<stream>") -> str:
    """Hash an ALREADY-OPEN descriptor, in bounded memory, and rewind it.

    R-07. ``file_sha256`` below hashes a *name*, and a name is not a file: an
    atomic rename between the hash and whatever reads the artefact next leaves
    the two describing different bytes, with the signature holding over
    whichever one the hash happened to find. Hashing the descriptor the caller
    will go on to read closes the window without giving up streaming -- an open
    fd keeps its inode whatever happens to the path.

    The file is left positioned at zero, because the caller's next act is to
    read it.
    """
    h = hashlib.sha256()
    read = 0
    fh.seek(0)
    while True:
        chunk = fh.read(1 << 20)
        if not chunk:
            break
        read += len(chunk)
        if read > max_bytes:
            raise PolicySignatureError(
                f"{name}: exceeds {max_bytes} bytes, so the signature over "
                f"it cannot be checked")
        h.update(chunk)
    fh.seek(0)
    return h.hexdigest()


def file_sha256(path: str | Path, max_bytes: int) -> str:
    """Hash a file the signature claims to cover, in bounded memory.

    Prefer :func:`stream_sha256` wherever the caller will also READ the
    artefact: this function resolves the path a second time and that second
    resolution is the R-07 race.

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
# R-05. Signatures verified, and they stop short of the last record. A stream
# attested to a point and chained after it is a genuinely weaker thing than an
# attested stream, and it used to be reported as the same thing.
R_SIGNATURE_PREFIX_ONLY = "INTEGRITY_SIGNATURE_COVERS_PREFIX_ONLY"
R_PARTIAL_INTEGRITY = "INTEGRITY_EVIDENCE_PARTIAL"
R_NO_COLLECTOR_KEYS = "NO_COLLECTOR_KEYS"
R_UNSIGNED = "INTEGRITY_UNSIGNED"
R_SEQUENCE_GAP = "INTEGRITY_SEQUENCE_GAP"
R_SEQUENCE_REPLAY = "INTEGRITY_SEQUENCE_REPLAY"
R_CHAIN_BROKEN = "INTEGRITY_CHAIN_BROKEN"
# A record past sequence zero was consumed with no chain head to recompute its
# ``chain`` from, because it declared no ``prev`` and nothing before it was
# seen: the first record of a batch joined mid-stream, or the first survivor
# after a gap. Its signature covers the chain value it DECLARED, and with no
# predecessor that value cannot be tied to the body next to it, so the
# signature attests nothing about this record's content. Reproduced before
# this code existed: edit the first record of a later batch, delete its
# ``prev``, and the session reported ``attested`` with no inadmissible code
# -- the edited record was the one the signature was taken to vouch for.
#
# Inadmissible rather than "could not check", and the distinction is the same
# one R_PARTIAL_INTEGRITY draws: the record carries a chain value and a
# signature, which is a CLAIM of attestation, while withholding the one field
# that makes the claim checkable. A collector that chains writes ``prev`` on
# every record (tools/collector_sign.py does, and the schema in
# docs/EVIDENCE-TRUST.md shows it), so a record at seq > 0 without one is
# either a producer that gave up continuity or an edit that removed it, and
# the verifier cannot tell those apart. R_STREAM_BOUNDARY_UNVERIFIED is the
# cross-run version of the same omission and stays non-inadmissible, because
# the ledger join is a question about a head from a PREVIOUS run; this is
# about whether the bytes in THIS run are bound to anything at all.
R_CHAIN_UNANCHORED = "INTEGRITY_CHAIN_UNANCHORED"
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
# EH-02. A verified signature under a DIFFERENT collector key than the one
# that first attested this stream, where the trust store does not record the
# new key as the old one's successor. docs/EVIDENCE-TRUST.md promised "one key
# reference per stream" and nothing held it: ``_Stream`` had no key field, so
# any key with the collector role could sign any stream id, including taking
# one over mid-way -- key B re-signing records 3 to 5 of key A's stream, chain
# intact, reported ``attested`` with nothing inadmissible. Two collector keys
# on one stream is either a rotation the operator wrote down (``replaces``, in
# which case it is accepted and the stream re-pins to the successor) or a
# second party holding a trusted key writing into a stream that is not theirs.
R_STREAM_KEY_CHANGED = "INTEGRITY_STREAM_KEY_CHANGED"

# Freshness. A whole stream can be re-fed from an archive, and every check above
# passes on it, because an old stream is internally perfect -- that is what makes
# replay a different attack from tampering.
R_STALE = "INTEGRITY_EVIDENCE_STALE"
R_FRESHNESS_UNVERIFIABLE = "INTEGRITY_FRESHNESS_UNVERIFIABLE"
R_NO_FRESHNESS_BOUND = "NO_FRESHNESS_BOUND"
# R-13. The other end of the same bound, and it used to have no code at all.
# A freshness window only bounds records from BEFORE ``as_of``; a record dated
# after it was reported not-stale and nothing else, which means a clock the
# operator does not control silently bought unlimited freshness. The stale
# branch cannot be reused for it -- an old record and a future-dated one are
# different faults and a shared code would make the remedy unguessable.
R_FROM_FUTURE = "INTEGRITY_EVIDENCE_FROM_FUTURE"

# The seen-stream ledger. Freshness bounds how OLD a stream may be; this bounds
# how many TIMES it may be scored, which is the replay the freshness window
# cannot see because the replayed stream is still inside it.
R_STREAM_REPLAYED = "INTEGRITY_STREAM_REPLAYED"
R_STREAM_FORKED = "INTEGRITY_STREAM_FORKED"
R_STREAM_SKIPPED_RECORDS = "INTEGRITY_STREAM_RECORDS_NEVER_SCORED"
# R-02. The first record of a continuation declared no predecessor, so the join
# onto the stored head could not be checked at all. Not inadmissible -- it is a
# question that could not be answered, and the doctrine on that is settled -- but
# it must never read as a checked boundary. A producer that omits ``prev`` gives
# up the only cross-run continuity evidence there is; EVASION.md carries it.
R_STREAM_BOUNDARY_UNVERIFIED = "INTEGRITY_STREAM_BOUNDARY_UNVERIFIED"
# E30. Where a stream ENDS. The chain says nothing is missing in between and
# the signatures say the collector wrote what remains; neither says how long
# the stream was meant to be, so cutting records off the end of a signed
# stream left a contiguous, fully verified prefix and no code of any kind.
# A collector that closes its streams signs a `final` record. These four say
# what the verifier found about that.
#
# NOT_CLOSED is coverage, not a finding: a stream fed in batches is open until
# its collector closes it, and calling every live tail tampering would refuse
# every deployment. It degrades CH06 the way NO_STREAM_LEDGER does.
R_STREAM_NOT_CLOSED = "INTEGRITY_STREAM_NOT_CLOSED"
# END_MISSING is the same fact under --require-closed-streams, where the
# operator has said their collectors close every stream, so one that ends
# without its terminator is a stream somebody cut. Inadmissible.
R_STREAM_END_MISSING = "INTEGRITY_STREAM_END_MISSING"
# Records at a sequence past a verified final record, in this run or, through
# the ledger, in a later one. Inadmissible: the collector said nothing follows.
R_RECORDS_AFTER_CLOSE = "INTEGRITY_RECORDS_AFTER_CLOSE"
# A record claimed `final` and nothing trusted vouched for the claim (no key,
# unsigned, or the signature failed on its own account). Coverage: the claim
# does not close the stream, and the verdict says one was made.
R_CLOSE_UNVERIFIED = "INTEGRITY_STREAM_CLOSE_UNVERIFIED"
R_NO_STREAM_LEDGER = "NO_STREAM_LEDGER"
R_LEDGER_EVICTED = "STREAM_LEDGER_EVICTED_THIS_STREAM"
# R-03. The stream was compared against the ledger and deliberately not written
# to it, because its evidence did not earn a place there. Not inadmissible: what
# was wrong with the evidence already has its own code, and this says what the
# ledger DID about it. It matters in the verdict because the omission is
# otherwise invisible -- a stream absent from the ledger looks exactly like one
# that was never seen, and the next run will score it as new.
R_LEDGER_NOT_ADVANCED = "STREAM_LEDGER_NOT_ADVANCED"
R_LEDGER_BUDGET = "STREAM_LEDGER_BUDGET_EXHAUSTED"

# The codes that say the evidence is not admissible, as opposed to merely
# incomplete. A session carrying any of these has findings that rest on a stream
# somebody could have edited, and CH06 says so at critical.
#
# R_KEY_WINDOW_UNCHECKED and R_FRESHNESS_UNVERIFIABLE are deliberately NOT here.
# Both mean a question could not be answered, and answering "could not check"
# with a critical finding is the false-positive engine this project exists to
# argue against -- the same reason NO_INTEGRITY_EVIDENCE is a coverage code and
# not a finding.
INADMISSIBLE = frozenset({R_SEQUENCE_GAP, R_CHAIN_BROKEN, R_CHAIN_UNANCHORED,
                          R_SIGNATURE_INVALID,
                          R_KEY_UNKNOWN, R_SEQUENCE_REPLAY, R_PARTIAL_INTEGRITY,
                          R_KEY_REVOKED, R_KEY_EXPIRED, R_KEY_NOT_YET_VALID,
                          R_KEY_WRONG_ROLE, R_STALE, R_FROM_FUTURE,
                          R_STREAM_REPLAYED, R_STREAM_FORKED,
                          R_STREAM_KEY_CHANGED,
                          R_STREAM_END_MISSING, R_RECORDS_AFTER_CLOSE})

# R_STREAM_SKIPPED_RECORDS is deliberately NOT inadmissible. Records between the
# last scored sequence and this run's first one were never scored, which is
# either deletion or an operator scoring a subset on purpose -- and Cohaera
# cannot tell those apart from inside one run. Reporting a deliberate subset as
# tampering would page somebody for using the tool as documented.


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

    WHAT IT STILL DOES NOT CLOSE, AND WHAT NOW DOES
        Replaying a stream that is still inside the window. A bound on how OLD a
        stream may be cannot see a recent one re-fed, and no amount of tuning
        changes that: the two are the same input.

        That residue is now :class:`StreamLedger`, which is memory of which
        streams have already been scored, surviving between runs in a file the
        operator names with ``--seen-streams``. Freshness bounds how old; the
        ledger bounds how many times. They are complementary and neither
        subsumes the other -- the ledger says nothing about a stream it has
        never seen, which is exactly the archive replay freshness catches.

        ``stream_summary`` stays in the verdict regardless, because it is what
        makes a replay auditable for anyone who did not run with a ledger, and
        because a SIEM rule over the field is a place state survives that this
        process does not control.
    """

    max_age_s: float | None = None
    as_of: float | None = None
    # R-13. How far past ``as_of`` a signed record may be dated before it stops
    # being ordinary clock disagreement. Zero means no tolerance. The CLI fills
    # this from ``Limits.max_future_skew_s``; the field lives here so that the
    # value a run used is in the verdict beside the window it qualifies.
    max_future_skew_s: float = 0.0

    @property
    def enabled(self) -> bool:
        return (self.max_age_s is not None and self.as_of is not None
                and math.isfinite(self.max_age_s) and math.isfinite(self.as_of))

    def age_of(self, when: float | None) -> float | None:
        # `enabled` establishes that both are non-None finite floats, but it is
        # a property and the narrowing does not survive the call, so the two
        # locals restate it for the type checker as well as the reader.
        as_of, max_age = self.as_of, self.max_age_s
        if (as_of is None or max_age is None or when is None
                or not self.enabled or not math.isfinite(when)):
            return None
        return float(as_of) - float(when)

    def stale(self, when: float | None) -> bool | None:
        """None when the question cannot be answered. Future-dated is not stale.

        A record dated after ``as_of`` is not old, it is wrong, and calling it
        stale would report clock skew as an archive replay. That much was always
        right; what was missing is the other finding, which this used to describe
        as "somebody else's" and nobody actually made. See :meth:`from_future`.
        """
        age = self.age_of(when)
        if age is None or self.max_age_s is None:
            return None
        return age > float(self.max_age_s)

    def from_future(self, when: float | None) -> bool | None:
        """Is this record dated further past ``as_of`` than skew allows? R-13.

        A freshness window bounds one direction only. Before this, a signed
        record dated a year ahead returned ``stale() is False`` and nothing
        else, so it read in the verdict exactly like a record written a second
        ago -- and a collector whose clock is wrong, or one an attacker has,
        bought itself unlimited freshness by adding to a number.

        It is inadmissible rather than a warning because of what freshness IS.
        The bound exists so that re-feeding a captured stream is detectable, and
        the whole argument for trusting the timestamp is that it is covered by
        the chain and the chain by the signature -- a replayer can re-send the
        bytes and cannot re-date them. A record dated after the instant it was
        scored breaks that argument at the root: whatever produced it was not
        reading the same clock as the rest of the evidence, and every age
        computed against it is a guess.

        ``None`` when freshness is off or the record has no readable clock,
        never ``False``. "Not checked" is not "checked and fine".
        """
        age = self.age_of(when)
        if age is None:
            return None
        return age < -abs(self.max_future_skew_s)

    def as_dict(self) -> dict[str, Any]:
        return {"max_age_s": self.max_age_s, "as_of": self.as_of,
                "enabled": self.enabled,
                "max_future_skew_s": self.max_future_skew_s}


NO_FRESHNESS = Freshness()


# ---------------------------------------------------------------------------
# The seen-stream ledger
# ---------------------------------------------------------------------------

LEDGER_SCHEMA = "cohaera.stream_ledger:1"

# R-04. POSIX advisory locking, where the platform has it. Imported here rather
# than at the point of use so that the one place that asks "can this host
# actually exclude a concurrent writer" is a module-level fact and not a
# try/except buried in a method. Where it is missing, the generation guard below
# still turns a lost update into a refusal -- it cannot PREVENT the race, but it
# will not let a run report success having silently dropped another run's work.
try:
    import fcntl
    HAVE_FILE_LOCKING = True
except ImportError:                                        # pragma: no cover
    HAVE_FILE_LOCKING = False

# How long to wait for another run to finish with the ledger before giving up.
# Not a Limits field on purpose: config_hash exists so two runs that disagree
# about what they refused to PARSE are known to be incomparable, and how long a
# run was willing to queue says nothing about the records it scored.
LEDGER_LOCK_WAIT_S = 30.0

# How the incoming stream stood against what the ledger remembered.
SEEN_NEW = "new"                  # never scored before
SEEN_ADVANCED = "advanced"        # continues from exactly where scoring stopped
SEEN_DISCONTINUOUS = "discontinuous"   # continues past it, over a gap
SEEN_REPLAYED = "replayed"        # occupies sequence positions already scored
SEEN_FORKED = "forked"            # incompatible history, at or past the boundary
SEEN_AFTER_CLOSE = "after_close"  # continues a stream its collector had closed
SEEN_EVICTED = "evicted"          # was known, and the budget dropped it

# How the incoming stream's first record joined onto what the ledger stored.
# Separate from the status because the status is a judgement and this is the
# observation it rests on -- and because "the producer did not say" has to stay
# distinguishable from "the producer said, and it matched".
BOUNDARY_MATCH = "match"              # declared predecessor == stored head
BOUNDARY_DIFFERS = "differs"          # declared, and it is a different history
BOUNDARY_UNSTATED = "unstated"        # no prev on the first record; unverifiable
BOUNDARY_GAP = "gap"                  # sequences in between were never scored
BOUNDARY_NOT_COMPARED = "not_compared"   # new stream, or an overlap rather than
                                         # a continuation


class LedgerError(ValueError):
    """The ledger file is not a ledger. Refuse it; do not half-load it."""


def _acquire_ledger_lock(handle: Any, lock_file: Path, wait_s: float,
                         what: str = "seen-stream ledger",
                         option: str = "--seen-streams") -> None:
    """Take the exclusive lock, or say why the run is not starting. R-04.

    Non-blocking with a deadline rather than a blocking ``flock``: a run that
    hangs forever behind a stuck peer is indistinguishable from a run that is
    working, and a scheduled job that never returns is worse than one that
    fails. The wait exists because the ordinary case is a peer that is nearly
    finished, not a deadlock.

    ``what`` and ``option`` name the ledger in the refusal, because the same
    lock now guards the approval ledger too (EH-04) and a message blaming the
    wrong file sends the operator to the wrong flag.
    """
    if not HAVE_FILE_LOCKING:                              # pragma: no cover
        return
    deadline = time.monotonic() + max(0.0, wait_s)
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise LedgerError(
                    f"{lock_file}: another run has held the {what} "
                    f"for more than {wait_s:g}s. Runs sharing a ledger "
                    f"serialise on purpose -- two runs reading the same ledger "
                    f"at once would each read its state before the other "
                    f"wrote it, and neither would see the replay. Wait for the "
                    f"other run, or give this one its own {option} file."
                ) from None
            time.sleep(0.05)


def _fsync_directory(directory: Path) -> None:
    """Make a rename durable, not just the bytes it points at.

    Best effort: some filesystems refuse to open a directory for this, and
    failing a completed save over it would be worse than the missing guarantee.
    """
    with contextlib.suppress(OSError, AttributeError):
        fd = os.open(str(directory or "."), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@dataclass(frozen=True)
class SeenStream:
    """What one previous run recorded about one collector stream."""

    stream_id: str
    first_seq: int
    last_seq: int
    head: str                     # chain head AT last_seq
    runs: int = 1
    last_run_id: str = ""
    last_seen_at: float | None = None
    key_ids: tuple[str, ...] = ()
    # E30. A verified final record was seen at last_seq. Once true it stays
    # true: a stream does not reopen, and a later run presenting records past
    # last_seq is INTEGRITY_RECORDS_AFTER_CLOSE rather than advancement.
    closed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"first_seq": self.first_seq, "last_seq": self.last_seq,
                "head": self.head, "runs": self.runs,
                "last_run_id": self.last_run_id,
                "last_seen_at": self.last_seen_at,
                "key_ids": list(self.key_ids),
                "closed": self.closed}


@dataclass(frozen=True)
class SeenVerdict:
    """How this run's view of a stream compared with the ledger's."""

    stream_id: str
    status: str
    overlap_from: int | None = None
    overlap_to: int | None = None
    previous_last_seq: int | None = None
    previous_runs: int = 0
    head_comparison: str = "not_reached"   # match | differs | not_reached
    # R-02. How this run's first record joined onto the ledger's stored head,
    # and what the ledger had stored. Kept in the verdict rather than only in a
    # branch, because "why did this read as a fork" is the first question asked
    # and re-deriving it needs both files.
    boundary: str = BOUNDARY_NOT_COMPARED
    declared_prev: str | None = None
    previous_head: str | None = None

    @property
    def code(self) -> str | None:
        if self.status == SEEN_FORKED:
            return R_STREAM_FORKED
        if self.status == SEEN_REPLAYED:
            return R_STREAM_REPLAYED
        if self.status == SEEN_DISCONTINUOUS:
            return R_STREAM_SKIPPED_RECORDS
        if self.status == SEEN_AFTER_CLOSE:
            return R_RECORDS_AFTER_CLOSE
        return None

    def as_dict(self) -> dict[str, Any]:
        return {"stream_id": self.stream_id, "status": self.status,
                "overlap_from": self.overlap_from, "overlap_to": self.overlap_to,
                "previous_last_seq": self.previous_last_seq,
                "previous_runs": self.previous_runs,
                "head_comparison": self.head_comparison,
                "boundary": self.boundary,
                "declared_prev": self.declared_prev,
                "previous_head": self.previous_head}


class StreamLedger:
    """An OBSERVATION ledger: memory of which collector streams have been seen.

    NOT A DELIVERY LEDGER, AND THE NAME IS THE CLAIM. R-03. This records what
    Cohaera OBSERVED and scored; it does not record what any downstream sink
    durably received, and it does not provide exactly-once scoring. Those are
    different guarantees and only the first one is implementable without an
    output transaction spanning stdout, files and future SIEM sinks -- a design,
    not a patch, and one that is worse done badly than not done.

    What that means concretely, because it is a trade and not a limitation to be
    skipped past. ``cohaera score`` writes this file AFTER emitting its verdicts.
    A run that dies while printing therefore leaves the ledger unadvanced, and
    re-running it re-scores and re-emits: duplicates are possible. The reverse
    ordering was tried first and is worse -- it advanced past findings nobody
    ever saw, so re-running reported a replay and the findings were simply gone.
    A duplicate alert is noise an analyst dismisses in seconds; a missed one is
    the thing this project exists to prevent. Neither ordering is exactly-once.

    THE GAP THIS EXISTS FOR, precisely. Every other check in this module passes
    on a replayed archive, and each for a good reason: the sequence really is
    contiguous, the chain really does hold, the signatures really do verify,
    because the collector really did write those bytes. :class:`Freshness` adds
    the only offline anchor available -- the record's own signed clock -- and
    catches the replay that is OLD. It says nothing about the replay that is
    recent, and its own docstring says so. This is that residue: re-feeding
    yesterday's stream, inside any sane freshness window, scored twice.

    Detecting it needs exactly one thing Cohaera has never had, which is memory
    between runs. That is what this is, and keeping it small is most of the
    design:

        stream_id -> (first_seq, last_seq, head at last_seq, runs, when, keys)

    HOW REPLAY IS TOLD FROM A COLLECTOR RESTART
        These look identical from sequence numbers alone -- both send seq 0
        again -- and conflating them would make every collector restart a
        critical finding. The chain separates them, and it is worth stating why
        it can. A replay re-sends the SAME records, so it rebuilds the SAME
        chain: at any shared sequence the head matches. A restart writes NEW
        records over the same sequence numbers, so the chain diverges: at a
        shared sequence the head differs.

        Same positions, same head      -> replay, and the records are genuine
        Same positions, different head -> a fork: history rewritten and re-signed

        The second is the more serious of the two and gets its own code. It
        means somebody holding a valid collector key produced a second, mutually
        exclusive version of the same stream, and no chain check inside a single
        run can see that, because each version is internally perfect.

    WHAT IT DOES NOT DO, WHICH IS THE PART TO READ
        This is unsigned local state, and it has to be: signing it would mean
        Cohaera attesting to its own attestations, which is the thing
        ``tools/collector_sign.py`` exists to avoid. So an attacker who can
        delete or edit the ledger file removes the detection, and there is no
        cryptography here that stops them -- the `digest` field catches a
        truncated or corrupted write, not a deliberate one.

        It is also per-Cohaera-host. Replay the stream to a DIFFERENT collector
        running its own ledger and nothing has seen it before. Both limits are
        catalogued in EVASION.md rather than argued away, because a ledger that
        is presented as replay-proof is worse than no ledger: it invites the
        operator to stop asking.
    """

    def __init__(self, streams: dict[str, SeenStream] | None = None,
                 path: Path | None = None,
                 limits: Limits = DEFAULT_LIMITS,
                 generation: int = 0) -> None:
        self.streams: dict[str, SeenStream] = dict(streams or {})
        self.path = path
        self.limits = limits
        self.loaded = streams is not None
        # R-04. The generation this instance was READ at. A save writes
        # generation + 1 and first checks that the file on disk is still at the
        # one that was read; anything else means another writer got in, and the
        # record of what it scored is not ours to overwrite.
        self.generation = generation
        # True when this instance holds the exclusive lock for its path.
        self.locked_exclusively = False
        self.evicted = 0
        self.budget_exhausted = False
        self.verdicts: list[SeenVerdict] = []
        # Streams this run touched. The run id is not known while scoring --
        # it is a digest of everything read, so it does not exist until reading
        # finishes -- and stamping it afterwards beats threading a value that
        # is still being computed.
        self._touched: set[str] = set()

    @property
    def enabled(self) -> bool:
        return self.path is not None

    # -- comparison -------------------------------------------------------

    # -- admission --------------------------------------------------------
    #
    # See StreamVerifier._admission for what earns a stream a place here. The
    # short version: this file is worth exactly as much as the weakest thing
    # allowed to write to it, and before R-03 anything with a sequence number
    # could.

    def compare(self, stream_id: str, first_seq: int, last_seq: int,
                head: str, checkpoint_head: str | None,
                first_prev: str | None = None) -> SeenVerdict:
        """Judge one stream against what was recorded. Does not mutate.

        ``checkpoint_head`` is this run's chain head at the ledger's recorded
        ``last_seq``, captured while verifying, or None if this run's records
        never reached that far. It is the only value that can answer the
        replay-or-fork question for an OVERLAP, and when it is absent the
        verdict says ``not_reached`` rather than guessing.

        ``first_prev`` is the predecessor the first record of this run declared,
        and it answers the same question for a CONTINUATION. R-02: this branch
        used to be one line -- ``first_seq > previous.last_seq`` meant
        ``advanced`` -- which asked only that the new records came after the old
        ones and never that they came FROM them. Two different streams got the
        same verdict:

          * seq 3 after a stored last_seq of 2, declaring a predecessor the
            ledger had never recorded. Somebody with a collector key had minted
            a second, incompatible history and glued it to the sequence numbers
            of the first. It read as ordinary advancement, and worse, ``record``
            then stored that history's head -- so the fabricated version became
            the reference every later run was measured against.
          * seq 5 after a stored last_seq of 2, with records 3 and 4 never
            scored by anything. A skipped range, reading as normal progress.

        Three questions now, in this order, and the order is the argument.
        Sequence contiguity first, because with a gap in between there is no
        head to compare against -- the ledger never computed the one that would
        sit at the boundary -- so calling a gap a fork would be inventing an
        answer. Then the declared predecessor. Only a continuation that is both
        contiguous AND joins onto the stored head is ordinary advancement.
        """
        previous = self.streams.get(stream_id)
        if previous is None:
            return SeenVerdict(stream_id, SEEN_NEW)

        if first_seq > previous.last_seq:
            if previous.closed:
                # E30. The collector signed "nothing follows" at last_seq and
                # here is something that follows. Decided before contiguity,
                # because a continuation of a closed stream is wrong whether
                # or not it is contiguous, and the chain comparison below
                # would otherwise call a contiguous one ordinary advancement.
                return SeenVerdict(stream_id, SEEN_AFTER_CLOSE,
                                   previous_last_seq=previous.last_seq,
                                   previous_runs=previous.runs,
                                   boundary=BOUNDARY_NOT_COMPARED,
                                   declared_prev=first_prev,
                                   previous_head=previous.head)
            if first_seq != previous.last_seq + 1:
                # A gap. Deliberately NOT a fork: an operator scoring a subset
                # on purpose and an attacker deleting a range look identical
                # from here, and the ledger holds no head for the sequence in
                # between with which to tell them apart.
                status, boundary = SEEN_DISCONTINUOUS, BOUNDARY_GAP
            elif first_prev is None:
                # Contiguous, and the producer declined to say what it follows.
                # Advancement, because refusing it would break every collector
                # that omits the field -- but the boundary is recorded as
                # unverified rather than as checked.
                status, boundary = SEEN_ADVANCED, BOUNDARY_UNSTATED
            elif first_prev != previous.head:
                # Contiguous, declared, and it names a history this ledger has
                # never seen. The stream id and the sequence numbers line up and
                # the chain does not, which is what a fabricated continuation
                # looks like from here.
                status, boundary = SEEN_FORKED, BOUNDARY_DIFFERS
            else:
                status, boundary = SEEN_ADVANCED, BOUNDARY_MATCH
            return SeenVerdict(stream_id, status,
                               previous_last_seq=previous.last_seq,
                               previous_runs=previous.runs,
                               boundary=boundary,
                               declared_prev=first_prev,
                               previous_head=previous.head)

        overlap_to = min(last_seq, previous.last_seq)
        comparison = "not_reached"
        status = SEEN_REPLAYED
        if checkpoint_head is not None:
            if checkpoint_head == previous.head:
                comparison = "match"
            else:
                comparison = "differs"
                status = SEEN_FORKED
        return SeenVerdict(stream_id, status, overlap_from=first_seq,
                           overlap_to=overlap_to,
                           previous_last_seq=previous.last_seq,
                           previous_runs=previous.runs,
                           head_comparison=comparison,
                           declared_prev=first_prev,
                           previous_head=previous.head)

    # -- recording --------------------------------------------------------

    def record(self, verdict: SeenVerdict, first_seq: int, last_seq: int,
               head: str, run_id: str, when: float | None,
               key_ids: tuple[str, ...] = (), admit: bool = True,
               closed: bool = False) -> None:
        """Fold one verified stream into the ledger.

        A REPLAYED or FORKED stream does NOT advance the recorded position, and
        that is a decision rather than an oversight. Advancing on a replay would
        let the second replay through; adopting a fork's head would make the
        rewritten history the one future runs are measured against, which hands
        the attacker the reference. Nothing legitimate was scored in either case,
        so nothing is recorded except that it happened.

        ``admit`` is R-03 and carries the same argument one step earlier. The
        caller decides whether the stream's evidence earned a place here at all;
        see ``StreamVerifier._admission``. A refused stream is still compared and
        still reported -- the verdict is the analyst's, the commit is the
        ledger's -- and a refused stream that this ledger has never seen is not
        created, so it cannot consume ``max_ledger_streams`` either. That last
        part matters on its own: a producer minting a stream id per record could
        otherwise exhaust the budget with streams it never signed, and eviction
        is what makes an earlier stream's replay undetectable.
        """
        self.verdicts.append(verdict)
        self._touched.add(verdict.stream_id)
        if not admit or verdict.status in (SEEN_REPLAYED, SEEN_FORKED,
                                           SEEN_AFTER_CLOSE):
            # Including the R-02 fork, which is a CONTINUATION rather than an
            # overlap. It matters most there: an overlapping fork at least
            # collides with positions the ledger already holds, while a
            # fabricated continuation would otherwise have its head stored as
            # the reference for every run afterwards.
            previous = self.streams.get(verdict.stream_id)
            if previous is not None:
                self.streams[verdict.stream_id] = replace(
                    previous, runs=previous.runs + 1, last_run_id=run_id,
                    last_seen_at=when)
            return

        previous = self.streams.get(verdict.stream_id)
        if previous is None and len(self.streams) >= self.limits.max_ledger_streams:
            # Refuse to grow rather than evict silently. Eviction would make an
            # earlier stream's replay undetectable without anything saying so,
            # and a producer choosing stream ids controls which one goes.
            self.budget_exhausted = True
            self.evicted += 1
            return
        merged_keys = tuple(sorted(set(key_ids) | set(
            previous.key_ids if previous else ())))
        self.streams[verdict.stream_id] = SeenStream(
            stream_id=verdict.stream_id,
            first_seq=previous.first_seq if previous else first_seq,
            last_seq=max(last_seq, previous.last_seq) if previous else last_seq,
            head=head, runs=(previous.runs + 1) if previous else 1,
            last_run_id=run_id, last_seen_at=when,
            key_ids=merged_keys[:self.limits.max_evidence_items],
            closed=closed or bool(previous.closed if previous else False))

    def state_digest(self) -> str:
        """A digest of the ledger AS READ, before this run writes to it. R-06.

        Every replay and fork verdict in a run is judged against this state, so
        two runs that read different ledgers are not the same run even when the
        telemetry is byte-identical. It goes into the run's identity through
        ``identity.trust_config_digest``.

        Deliberately narrow: stream id, extent and head, and nothing else. The
        run counter, the last run id and the timestamps all move when a stream
        is merely seen again, and folding those in would make the identity of a
        run depend on how many times an unrelated stream had been scored
        before -- which changes no verdict and would break the deduplication
        the ID exists for.
        """
        return digest({"schema": LEDGER_SCHEMA,
                       "streams": [{"stream_id": k,
                                    "first_seq": v.first_seq,
                                    "last_seq": v.last_seq,
                                    "head": v.head,
                                    # Only when set, so every ledger written
                                    # before E30 keeps the digest it had.
                                    **({"closed": True} if v.closed else {})}
                                   for k, v in sorted(self.streams.items())]},
                      24)

    def stamp(self, run_id: str) -> None:
        """Attribute every stream this run touched to the run that scored it.

        Called after scoring, because ``analysis_run_id`` is a digest of the
        whole input and therefore does not exist until the whole input has been
        read. Without it the ledger records that a stream was seen and not by
        which run, which is the first thing anyone asks when a replay fires.
        """
        if not run_id:
            return
        for stream_id in self._touched:
            entry = self.streams.get(stream_id)
            if entry is not None:
                self.streams[stream_id] = replace(entry, last_run_id=run_id)

    # -- persistence ------------------------------------------------------

    def as_document(self) -> dict[str, Any]:
        body = {sid: s.as_dict() for sid, s in sorted(self.streams.items())}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return {
            "scheme": LEDGER_SCHEMA,
            # Catches a truncated or half-written file, NOT a deliberate edit:
            # anything that can rewrite the body can rewrite this too. It is
            # here because a partial write is a real failure mode and silently
            # trusting half a ledger is worse than refusing it.
            "digest": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            # R-04. Monotonic, and deliberately OUTSIDE the digest above. The
            # digest answers "is this file whole"; the generation answers "did
            # somebody else write since I read". Folding the second into the
            # first would make every ledger written before this version fail to
            # load, which would delete the replay memory of every deployment
            # that upgrades -- exactly the state deleting the ledger achieves.
            # A ledger with no generation field reads as 0.
            "generation": self.generation + 1,
            "streams": body,
        }

    @staticmethod
    def lock_path_for(path: str | Path) -> Path:
        """The sidecar this ledger's writers exclude each other on.

        A sidecar rather than the ledger file itself, and that is not a style
        choice. ``save`` finishes with ``os.replace``, which swaps the inode --
        a lock held on the ledger's own descriptor would protect a file that is
        no longer at that name the moment the first writer finishes. The sidecar
        is never replaced, so it stays the same object for every writer.
        """
        p = Path(path)
        return p.with_name(p.name + ".lock")

    @classmethod
    @contextlib.contextmanager
    def locked(cls, path: str | Path, limits: Limits = DEFAULT_LIMITS,
               wait_s: float = LEDGER_LOCK_WAIT_S) -> Iterator[StreamLedger]:
        """Load a ledger under an exclusive lock held until the block exits.

        R-04. ``save`` was atomic and the read-modify-write around it was not.
        Two runs on one host would both load, both score, and both replace: the
        second one's file has no record of the first one's streams, so the next
        replay of those streams is undetectable and nothing said so. Reproduced
        with two processes and a barrier -- it loses an update every time, and
        which one it loses is a coin flip.

        THE LOCK IS HELD FOR THE WHOLE RUN, NOT JUST THE WRITE, and that is the
        expensive choice made deliberately. Locking only around the write would
        stop updates being lost and would NOT stop the thing the ledger exists
        to catch: two runs scoring the same stream concurrently both read
        ``last_seq`` before either wrote, so both call it advancement and
        neither sees the other. That is a replay, and a replay-detector that
        cannot see a replay because it was busy is not worth the file it keeps.
        The cost is that concurrent runs sharing one ledger serialise. A ledger
        IS a serialisation point; the alternative is losing the guarantee.

        SINGLE HOST ONLY. ``flock`` is advisory and local. It does not travel
        over NFS or SMB in any way worth relying on, and it says nothing about a
        second Cohaera host with its own copy -- which the class docstring
        already lists as a limit and EVASION.md catalogues. The generation guard
        in ``save`` is what remains when the lock cannot be taken or was not
        honoured: it cannot prevent the race, but it refuses to overwrite a
        newer file rather than reporting success having dropped it.
        """
        p = Path(path)
        lock_file = cls.lock_path_for(p)
        with lock_file.open("a+b") as handle:
            _acquire_ledger_lock(handle, lock_file, wait_s)
            ledger = cls.load(p, limits=limits)
            ledger.locked_exclusively = HAVE_FILE_LOCKING
            try:
                yield ledger
            finally:
                if HAVE_FILE_LOCKING:
                    with contextlib.suppress(OSError):
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _on_disk_generation(self, target: Path) -> int:
        """The generation of the file as it stands right now, or 0 if absent.

        Read fresh rather than remembered: the whole question is whether the
        file changed under us.
        """
        if not target.exists():
            return 0
        try:
            with target.open("rb") as fh:
                blob = fh.read(self.limits.max_ledger_bytes + 1)
            obj = strict_json_loads(blob.decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            # Unreadable is not "generation 0". Refusing here would mask a
            # corrupt ledger as a concurrency problem; leave it to load(), which
            # says what is actually wrong with the file.
            return -1
        generation = obj.get("generation") if isinstance(obj, dict) else None
        return generation if isinstance(generation, int) and not isinstance(
            generation, bool) and generation >= 0 else 0

    def save(self) -> None:
        """Atomic replace, and refuse to replace something newer than what was read.

        Same durability discipline as the quarantine ledger (C5-06): a run that
        dies mid-write must not leave a ledger that is neither the old one nor
        the new one. R-04 adds the other half -- a run that succeeds must not
        leave a ledger missing another run's work.
        """
        if self.path is None:
            return
        target = Path(self.path)
        current = self._on_disk_generation(target)
        if current != self.generation:
            # Refused loudly rather than merged quietly. A merge would have to
            # guess which of two disagreeing histories for a stream is the real
            # one, and guessing wrong writes the wrong reference for every run
            # afterwards. Losing an update loudly is recoverable; losing it
            # silently is the bug this replaces.
            raise LedgerError(
                f"{target}: the ledger on disk is at generation {current} and "
                f"this run read generation {self.generation}. Another run wrote "
                f"it while this one was scoring, and overwriting would discard "
                f"whatever that run recorded -- so the streams it scored would "
                f"replay undetected. Re-run this input; the ledger on disk is "
                f"intact and is the newer of the two."
                + ("" if HAVE_FILE_LOCKING else
                   " This host has no file locking, so runs sharing a ledger "
                   "cannot exclude each other and must not be run concurrently."))
        blob = json.dumps(self.as_document(), indent=2, sort_keys=True) + "\n"
        if len(blob.encode("utf-8")) > self.limits.max_ledger_bytes:
            raise LedgerError(
                f"{target}: ledger would be {len(blob)} bytes, exceeding "
                f"max_ledger_bytes={self.limits.max_ledger_bytes}. It tracks "
                f"{len(self.streams)} streams; a producer minting a stream id "
                f"per record will do this on purpose.")
        fd, tmp = tempfile.mkstemp(dir=str(target.parent) or ".",
                                   prefix=f".{target.name}.", suffix=".partial")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
            # The rename itself has to reach the disk, not just the bytes it
            # points at. Without this a crash after a successful save can leave
            # the directory entry pointing at the OLD ledger, which is the same
            # lost update arriving by a different route.
            _fsync_directory(target.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self.generation += 1

    @classmethod
    def load(cls, path: str | Path,
             limits: Limits = DEFAULT_LIMITS) -> StreamLedger:
        """Read a ledger, or start an empty one if the file does not exist yet.

        A MISSING file is the first run and is not an error. A file that exists
        and does not parse IS an error: continuing would silently score
        everything as new, which is exactly the state an attacker who deleted
        the ledger wants, and doing it quietly would hide the deletion.
        """
        p = Path(path)
        if not p.exists():
            return cls(streams={}, path=p, limits=limits)
        with p.open("rb") as fh:
            blob = fh.read(limits.max_ledger_bytes + 1)
        if len(blob) > limits.max_ledger_bytes:
            raise LedgerError(
                f"{p}: ledger exceeds max_ledger_bytes={limits.max_ledger_bytes}")
        try:
            obj = strict_json_loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise LedgerError(f"{p}: not readable as UTF-8 JSON: {exc}") from exc
        if not isinstance(obj, dict) or obj.get("scheme") != LEDGER_SCHEMA:
            raise LedgerError(f"{p}: must declare scheme {LEDGER_SCHEMA!r}")
        raw = obj.get("streams")
        if not isinstance(raw, dict):
            raise LedgerError(f"{p}: must carry a 'streams' object")
        payload = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if obj.get("digest") != expected:
            raise LedgerError(
                f"{p}: digest does not match its contents. The file is "
                f"truncated, half-written or edited; it is NOT authenticated, "
                f"so this catches corruption rather than tampering. Delete it "
                f"to start a new ledger and accept that replays before now are "
                f"undetectable.")
        if len(raw) > limits.max_ledger_streams:
            raise LedgerError(
                f"{p}: ledger holds {len(raw)} streams, exceeding "
                f"max_ledger_streams={limits.max_ledger_streams}")
        streams: dict[str, SeenStream] = {}
        for stream_id, spec in raw.items():
            if not isinstance(stream_id, str) or not stream_id:
                raise LedgerError(f"{p}: stream id must be a non-empty string")
            if not isinstance(spec, dict):
                raise LedgerError(f"{p}: stream {stream_id!r} must map to an object")
            first_seq = _index(spec.get("first_seq"))
            last_seq = _index(spec.get("last_seq"))
            head = _hex_or_none(spec.get("head"))
            if first_seq is None or last_seq is None or head is None:
                raise LedgerError(
                    f"{p}: stream {stream_id!r} needs first_seq, last_seq and a "
                    f"hex head; a partial entry cannot judge a replay")
            runs = _index(spec.get("runs")) or 1
            keys = spec.get("key_ids")
            streams[stream_id] = SeenStream(
                stream_id=stream_id, first_seq=first_seq, last_seq=last_seq,
                head=head, runs=runs,
                last_run_id=_short(spec.get("last_run_id"), limits) or "",
                last_seen_at=_finite(spec.get("last_seen_at")),
                key_ids=tuple(k for k in keys if isinstance(k, str))
                if isinstance(keys, list) else (),
                # Absent in ledgers written before E30, which reads as open.
                closed=spec.get("closed") is True)
        # R-04. A ledger written before generations existed has no field and
        # reads as 0, which is correct: the first save under the new code writes
        # generation 1 and every writer afterwards agrees on the sequence.
        generation = obj.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool) \
                or generation < 0:
            generation = 0
        return cls(streams=streams, path=p, limits=limits, generation=generation)

    def summary(self) -> dict[str, Any]:
        return {
            "schema": LEDGER_SCHEMA,
            "enabled": self.enabled,
            "path": str(self.path) if self.path else None,
            "streams_known": len(self.streams),
            "budget_exhausted": self.budget_exhausted,
            "streams_not_recorded": self.evicted,
            "verdicts": [v.as_dict() for v in self.verdicts],
        }


class ApprovalLedger:
    """Memory of which approval nonces have already been spent.

    E26 point 3. Without this an approval works the hundredth time as well as
    the first, in any session, forever. `--seen-streams` gave `cohaera.integrity:1`
    exactly this capability against stream replay and nothing gave it to
    approvals; this is that, for nonces.

    IT INHERITS E22 WHOLE, AND THAT IS NOT A DETAIL. The ledger is a local file
    that cannot be signed by anyone but the host holding it -- signing it with
    the collector key would let the monitored side forge its own memory. So an
    attacker who can delete this file restores the replay, and an attacker who
    replays to a DIFFERENT Cohaera host was never covered because the ledger is
    per-host. Both are catalogued rather than hidden: see EVASION.md E22 and
    E22b, and the new entries this mechanism opens.

    `spend` returns THREE values, deliberately. True is "not seen before",
    False is "seen", and None is "there is no ledger" -- and None must never
    collapse into either. Reporting "no memory" as "unspent" would silently
    grant single-use assurance to every deployment that never enabled it.
    """

    def __init__(self, path: Path | None = None,
                 nonces: dict[str, float] | None = None,
                 limits: Limits = DEFAULT_LIMITS) -> None:
        self._path = path
        self._limits = limits
        self._nonces: dict[str, float] = dict(nonces or {})
        self._dirty = False
        # EH-04. Same guard as StreamLedger.generation: the generation this
        # instance READ, so a save can refuse to overwrite a file another run
        # wrote in between. Two runs that both loaded, both spent the same
        # nonce and both saved used to leave a ledger recording one spend and
        # two runs each told the nonce was fresh -- the replay E26 point 3
        # exists to stop, reintroduced by running the tool twice.
        self.generation = 0
        self.locked_exclusively = False
        if path is not None and path.exists():
            self._load(path)

    def _load(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LedgerError(f"approval ledger {path} is not readable: {exc}") from exc
        if not isinstance(raw, dict):
            raise LedgerError(f"approval ledger {path} root must be an object")
        seen = raw.get("nonces")
        if seen is not None and not isinstance(seen, dict):
            raise LedgerError(f"approval ledger {path}: 'nonces' must be an object")
        for key, value in (seen or {}).items():
            if isinstance(key, str) and key:
                self._nonces[key] = _finite(value) or 0.0
        # A ledger written before generations existed reads as 0, as the
        # stream ledger's does, so the first save under this code writes 1.
        self.generation = _generation_of(raw)

    @staticmethod
    def lock_path_for(path: str | Path) -> Path:
        """The lock sidecar. See StreamLedger.lock_path_for for why a sidecar."""
        return StreamLedger.lock_path_for(path)

    @classmethod
    @contextlib.contextmanager
    def locked(cls, path: str | Path, limits: Limits = DEFAULT_LIMITS,
               wait_s: float = LEDGER_LOCK_WAIT_S) -> Iterator[ApprovalLedger]:
        """Load the ledger under an exclusive lock held until the block exits.

        EH-04, and the argument is StreamLedger.locked's word for word. A
        nonce ledger is a serialisation point by definition -- its one job is
        to answer "has anybody spent this" and two runs answering it
        concurrently both say no. Held for the whole run rather than around
        the write, because the spend happens during assembly and the save
        after emission, and a lock around only the second would let both runs
        spend between them.
        """
        p = Path(path)
        lock_file = cls.lock_path_for(p)
        with lock_file.open("a+b") as handle:
            _acquire_ledger_lock(handle, lock_file, wait_s,
                                 what="approval ledger",
                                 option="--seen-approvals")
            ledger = cls(path=p, limits=limits)
            ledger.locked_exclusively = HAVE_FILE_LOCKING
            try:
                yield ledger
            finally:
                if HAVE_FILE_LOCKING:
                    with contextlib.suppress(OSError):
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @property
    def enabled(self) -> bool:
        return self._path is not None

    @property
    def size(self) -> int:
        return len(self._nonces)

    def spend(self, nonce: str | None, at: float = 0.0) -> bool | None:
        """True if this nonce is new, False if already spent, None if no ledger.

        Recording happens on FIRST SIGHT, before any verdict is reached, so a
        run that crashes after checking cannot hand the same nonce back on the
        next run. That ordering is the same one `StreamLedger` uses and for the
        same reason.
        """
        if self._path is None or not nonce:
            return None
        if nonce in self._nonces:
            return False
        if len(self._nonces) >= self._limits.max_approval_nonces:
            # An attacker chooses how many nonces it presents. Refusing to grow
            # past the bound is the same decision every other bound here makes,
            # and it fails toward "no answer" rather than "unspent".
            return None
        self._nonces[nonce] = at
        self._dirty = True
        return True

    def save(self) -> None:
        """Persist, atomically, only if something changed.

        Cross-session replay is the whole point of the mechanism, so a ledger
        that forgets between runs closes nothing.
        """
        if self._path is None or not self._dirty:
            return
        target = Path(self._path)
        # EH-04. Refuse to replace a file another run wrote since this one
        # read it. The alternative is merging two nonce sets, which sounds
        # harmless and is not: the merge records both runs' spends, and both
        # runs have already told their callers the nonce was unspent.
        current = _on_disk_generation(target, self._limits.max_ledger_bytes)
        if current != self.generation:
            raise LedgerError(
                f"{target}: the approval ledger on disk is at generation "
                f"{current} and this run read generation {self.generation}. "
                f"Another run wrote it while this one was scoring; the nonces "
                f"this run treated as unspent may have been spent by that one. "
                f"Re-run this input; the ledger on disk is the newer of the two."
                + ("" if HAVE_FILE_LOCKING else
                   " This host has no file locking, so runs sharing a ledger "
                   "cannot exclude each other and must not be run concurrently."))
        payload = {"schema": APPROVAL_LEDGER_SCHEMA, "nonces": self._nonces,
                   "generation": self.generation + 1}
        blob = json.dumps(payload, sort_keys=True) + "\n"
        # A unique temporary name and an fsync before the rename, as the
        # stream ledger does. The fixed ``.tmp`` name meant two writers shared
        # one scratch file and could rename each other's half-written bytes
        # into place; the missing fsync meant a crash after a "successful"
        # save could leave an empty ledger, which loads as no nonces spent.
        fd, tmp = tempfile.mkstemp(dir=str(target.parent) or ".",
                                   prefix=f".{target.name}.", suffix=".partial")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
            _fsync_directory(target.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self.generation += 1
        self._dirty = False

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "nonces_recorded": self.size}


def _generation_of(obj: Any) -> int:
    """The ``generation`` an on-disk ledger declares, or 0. Never negative."""
    generation = obj.get("generation") if isinstance(obj, dict) else None
    if isinstance(generation, bool) or not isinstance(generation, int):
        return 0
    return generation if generation >= 0 else 0


def _on_disk_generation(target: Path, max_bytes: int) -> int:
    """The generation of the file as it stands right now, or 0 if absent.

    Read fresh rather than remembered: the whole question is whether the file
    changed under us. Unreadable is -1, not 0, so a corrupt ledger is refused
    as a generation mismatch rather than overwritten as if it were new.
    """
    if not target.exists():
        return 0
    try:
        with target.open("rb") as fh:
            blob = fh.read(max_bytes + 1)
        obj = strict_json_loads(blob.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return -1
    return _generation_of(obj)


NO_APPROVAL_LEDGER = ApprovalLedger()


def verify_approval(approval: Approval, store: TrustStore,
                    now: float | None = None) -> Approval:
    """Return the approval with `verified` set if its issuer signature holds.

    Ordering matches `verify_policy_signature` and `StreamVerifier`: everything
    decidable without arithmetic is decided first, and the key's own validity
    window is judged last. A failure returns the approval UNCHANGED rather than
    marking it refused, because a bad signature and no signature reach the same
    place -- the approval does not climb above BOUND -- and inventing a third
    state would let a producer downgrade a real approval by attaching garbage.
    """
    if not approval.signable:
        return approval
    if not store.has_role(ROLE_APPROVAL):
        return approval
    key = store.get(approval.key_id or "")
    if key is None or not key.authorises(ROLE_APPROVAL):
        return approval
    if key.revoked:
        return approval
    at = approval.granted_at if approval.granted_at is not None else now
    if key.covers_clock(at) is False:
        return approval
    try:
        # (public_key, message, signature). Getting this order wrong makes
        # every signature fail closed, which looks like working code.
        ok = ed25519.verify(key.public, approval.signing_input(),
                            approval.signature or b"")
    except (ValueError, TypeError):
        return approval
    return replace(approval, verified=True) if ok else approval


NO_LEDGER = StreamLedger()


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
    # Sequences consumed with no head to chain them from. See R_CHAIN_UNANCHORED.
    unanchored: list[int] = field(default_factory=list)
    bad_signatures: list[int] = field(default_factory=list)
    unknown_key_ids: set[str] = field(default_factory=set)
    signatures_verified: int = 0
    reordered: int = 0
    # Keys that actually attested this session's records, and how the store
    # judged them. Carried into the verdict because "which key vouched for this"
    # is the first question asked when a key turns out to be compromised, and
    # answering it from a verdict beats re-scoring the archive.
    signing_key_ids: set[str] = field(default_factory=set)
    # EH-02. Each point at which a stream feeding this session changed signing
    # key without the trust store recording a succession: which stream, at
    # which sequence, from which key to which. The pair of key ids is the
    # finding -- "which key took over" is what an operator has to revoke.
    stream_key_changes: list[dict[str, Any]] = field(default_factory=list)
    # Streams this session's records came from that a previous run had already
    # scored. Carried in full because "which stream, which sequence range, and
    # did the history match" is the whole of the finding.
    replayed_streams: list[dict[str, Any]] = field(default_factory=list)
    freshness_checked: int = 0
    oldest_signed_age_s: float | None = None
    # R-05. One entry per stream that fed this session: how far its records ran
    # and how far a verified signature reached into them. Carried in full rather
    # than reduced to a boolean because "signed to 100 of 149" is the finding,
    # and an analyst asked to trust a session needs to see where the attestation
    # stopped rather than be told it did.
    signature_ranges: list[dict[str, Any]] = field(default_factory=list)
    # R-13. The furthest a signed record was dated AHEAD of ``as_of``, in
    # seconds, or None if none was. Positive, and reported separately from
    # ``oldest_signed_age_s`` because a future-dated record has a negative age
    # and would otherwise never be the maximum of anything -- which is how it
    # went unreported in the first place.
    furthest_future_s: float | None = None

    @property
    def records(self) -> int:
        return self.with_integrity + self.without_integrity

    @property
    def attested(self) -> bool:
        """Did a verified signature attest to this session's records? F-03.

        This used to be "did every record carry a sidecar", which is a
        different question with a much weaker answer, and it was published
        under a word every reader takes to mean the stronger one. A stream of
        producer-written sidecars with no ``chain``, no ``prev`` and no
        signature reported ``attested: true``.

        The old question is still worth asking and is now ``sidecars_complete``.
        This one is about who vouched for the bytes.
        """
        return self.signatures_verified > 0 and not self.inadmissible

    @property
    def sidecars_complete(self) -> bool:
        """Did every record in this session carry a sidecar at all?

        The question ``attested`` used to answer. Selective stripping is what
        it catches: a session where some records carry integrity evidence and
        others do not is the shape an attacker produces by removing the
        evidence from the records they edited.
        """
        return self.with_integrity > 0 and self.without_integrity == 0

    @property
    def inadmissible(self) -> list[str]:
        return sorted(c for c in self.codes if c in INADMISSIBLE)

    @property
    def signature_covers_final(self) -> bool:
        """Does a verified signature reach the LAST record of every stream here?

        R-05. The question ``evidence_status`` used to answer with
        ``signatures_verified > 0``, which is a question about whether anything
        was signed rather than about what the signatures covered. A 150-record
        stream signed at 0 and 100 satisfied it while 49 records sat past the
        last attestation, covered by nothing.

        Every stream, not most: a session assembled from two streams is only as
        attested as its weaker half, and averaging that away would report the
        better one.
        """
        if not self.signature_ranges:
            return False
        return all(r["verified_to"] is not None
                   and r["verified_to"] >= r["last_seq"]
                   for r in self.signature_ranges)

    def sequence_verified(self, stream_id: str | None, seq: int | None) -> bool:
        """Is this exact collector position covered by a signature that VERIFIED?

        F-03 fixed ``attested`` for precisely this confusion and left the
        ordering path still carrying it. ``Integrity.chained`` asks whether
        ``prev`` and ``chain`` are PRESENT, which is a question about shape --
        and a producer writes both fields as easily as it writes ``seq``.
        Ordering treated that shape as authoritative and let it OUTRANK the
        wall clock, so two arbitrary hex strings with no signature anywhere
        suppressed a critical CH04 finding. Measured, not theorised: the
        reproduction is in tests/test_hostile.py.

        This asks the other question -- did a signature this deployment trusts
        actually reach this record. A position past ``verified_to``, in a
        stream nothing signed, or in a session whose ledger is inadmissible, is
        not covered.

        An uncovered position is then treated as ABSENT rather than as weak
        evidence, which is the rule the rest of this module already follows.
        That matters for what the fix does NOT do: it does not make ordering
        indeterminate on unsigned streams, which would delete CH03 and CH04
        from every deployment that has not adopted signing. It removes the
        producer's ability to OVERRIDE the clock with an unverifiable number,
        leaving exactly the instrument an unsigned deployment always had.
        """
        if stream_id is None or seq is None or self.inadmissible:
            return False
        return any(r["stream_id"] == stream_id
                   and r["verified_to"] is not None
                   and seq <= r["verified_to"]
                   for r in self.signature_ranges)

    @property
    def signature_coverage(self) -> float:
        """Share of this session's attested records a signature actually reaches.

        Record-weighted across streams rather than averaged per stream, so a
        two-record stream signed to its end cannot offset a thousand-record one
        signed to its middle.
        """
        covered = total = 0
        for r in self.signature_ranges:
            span = r["last_seq"] - r["first_seq"] + 1
            if span <= 0:
                continue
            total += span
            if r["verified_to"] is not None:
                reach = min(r["verified_to"], r["last_seq"]) - r["first_seq"] + 1
                covered += max(0, reach)
        return covered / total if total else 0.0

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
            "unanchored": self.unanchored[:cap],
            "invalid_signatures": self.bad_signatures[:cap],
            "unknown_key_ids": sorted(self.unknown_key_ids)[:cap],
            "signatures_verified": self.signatures_verified,
            "records_reordered": self.reordered,
            "signing_key_ids": sorted(self.signing_key_ids)[:cap],
            "stream_key_changes": self.stream_key_changes[:cap],
            "freshness_checked": self.freshness_checked,
            "oldest_signed_age_s": self.oldest_signed_age_s,
            "furthest_future_s": self.furthest_future_s,
            "signature_ranges": self.signature_ranges[:cap],
            "signature_coverage": round(self.signature_coverage, 4),
            "signature_covers_final": self.signature_covers_final,
            "replayed_streams": self.replayed_streams[:cap],
            "attested": self.attested,
            "sidecars_complete": self.sidecars_complete,
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
    # R-02. The predecessor the FIRST consumed record declared. _begin used to
    # adopt this as the chain head and say nothing else about it, which is the
    # bug: adopting a boundary is not the same as checking one. Recorded here so
    # the ledger can compare it against the head it stored.
    first_prev: str | None = None
    # This run's chain head at the sequence the LEDGER last recorded, captured
    # in passing. It is the only value that separates a replay from a fork --
    # same head means the same records, a different head means the same
    # positions filled with different records -- and it has to be taken while
    # the head is at that sequence, because afterwards it has moved on.
    ledger_checkpoint_seq: int | None = None
    ledger_checkpoint_head: str | None = None
    # Every session whose records came from this stream. A whole-stream replay
    # implicates all of them, unlike a gap, which implicates the two either side.
    sessions_seen: set[str] = field(default_factory=set)
    # R-03. What this stream's OWN evidence did, as opposed to what the sessions
    # it fed concluded. The ledger has to decide whether to remember a stream,
    # and a session is fed by many streams: judging stream A on a code raised by
    # stream B would refuse to advance for a reason that has nothing to do with
    # it, and the next run would then read A as a replay.
    codes: set[str] = field(default_factory=set)
    signatures_verified: int = 0
    # R-05. The highest sequence whose signature VERIFIED. A signature covers
    # the chain head at its own sequence, so one verified signature attests
    # every record up to and including it -- and nothing after it. This is the
    # value that separates a stream signed to its end from one signed to its
    # middle, and there was nothing tracking it.
    highest_verified_seq: int | None = None
    # E30. The sequence at which a VERIFIED final record closed this stream,
    # and whether any record claimed to, verified or not.
    closed_at: int | None = None
    final_seen: bool = False
    # Records consumed for this stream that reached no scored session, because
    # assembly dropped them on max_sessions or max_events_per_session. Their
    # positions were verified and their content was never looked at.
    unscored_records: int = 0
    # EH-02. The key id of the first signature that VERIFIED on this stream:
    # the "one key reference per stream" the design promised. Pinned on
    # verification rather than on the first record's ``key_id`` field, because
    # that field is producer-written and pinning an unverified claim would let
    # a forged first record decide which key the genuine ones are judged
    # against. Re-pinned only to a key the trust store records as this one's
    # successor.
    key_id: str | None = None
    # The key under which the most recent signature verified, pinned or not.
    # ``stream_key_changes`` records a TRANSITION, so a usurper signing three
    # records in a row is one change in the verdict and three in the code
    # count, rather than three identical entries.
    last_verified_key_id: str | None = None


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
                 freshness: Freshness = NO_FRESHNESS,
                 ledger: StreamLedger | None = None,
                 run_id: str = "",
                 require_closed: bool = False) -> None:
        self.keys = keys
        self.limits = limits
        # E30. --require-closed-streams: the operator's statement that their
        # collectors close every stream, which turns "not closed" from
        # coverage into inadmissible evidence.
        self.require_closed = require_closed
        self.freshness = freshness
        self.ledger = ledger if ledger is not None else NO_LEDGER
        self.run_id = run_id
        self.streams: dict[str, _Stream] = {}
        self.sessions: dict[str, SessionIntegrity] = {}
        self.signatures_verified = 0
        self.signature_budget_exhausted = False
        # R-12. Wall clock actually spent in signature verification, so the
        # bound is on the work and not on a proxy for it.
        self.signature_seconds = 0.0
        self.stream_budget_exhausted = False
        # R-03. Streams compared against the ledger and deliberately not written
        # to it, with the reason. Carried into the run summary because a stream
        # missing from the ledger is indistinguishable from one never seen.
        self.ledger_refusals: list[dict[str, Any]] = []
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
            # Ask the ledger, once per stream, which sequence to snapshot the
            # chain head at. Nothing is judged here -- that happens at finalise,
            # when this run's full extent is known.
            previous = self.ledger.streams.get(integrity.stream_id)
            if previous is not None:
                stream.ledger_checkpoint_seq = previous.last_seq
            self._begin(stream, integrity, state)

        body = body_digest(record)
        # Read once, here, from the record as it arrived. Not from the assembled
        # Event: the same field is what the chain covers, and the chain is what
        # makes it worth reading at all.
        #
        # EH-01. The same parse as ``validate.timestamp``, so that the clock
        # the key window and the freshness bound are judged against is the
        # clock every other check sees. This used to be ``_finite``, which
        # takes numbers only, while validate accepts a numeric string -- so a
        # record dated ``"4990.0"`` was ordered by that clock everywhere else
        # and had NO clock here. A key with ``not_after=1500`` signing it got
        # KEY_WINDOW_UNCHECKED, a coverage note, instead of KEY_EXPIRED, which
        # is inadmissible; and the freshness bound was skipped for it. A
        # producer chose the type of one field and bought its way out of two
        # checks. A non-numeric string is unreadable here as it is there.
        clock, clock_defects = record_clock(record.get("timestamp"))
        when = None if clock_defects else clock
        if integrity.seq == stream.expected:
            self._consume(stream, integrity.seq, body, integrity, session_key, when)
            # A hole was just FILLED, so anything already waiting arrived early
            # and was genuinely reordered.
            self._drain(stream, reordered=True)
        elif integrity.seq < stream.expected:
            # Already accounted for. Either a duplicate delivery or a replay of
            # a record whose position in the chain is taken.
            self._note(state, stream, R_SEQUENCE_REPLAY)
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
        # E30. Whether each stream was closed by its collector. Decided here
        # because "the last record" is only knowable once there are no more,
        # and before the ledger comparison so that a stream cut short is not
        # also remembered as having ended where the cut was.
        for stream in sorted(self.streams.values(), key=lambda s: s.stream_id):
            if stream.first_seq is None or stream.closed_at is not None:
                continue
            for session_key in stream.sessions_seen:
                if not session_key:
                    continue
                state = self._session(session_key)
                self._note(state, stream, R_STREAM_NOT_CLOSED)
                if stream.final_seen:
                    self._note(state, stream, R_CLOSE_UNVERIFIED)
                if self.require_closed:
                    self._note(state, stream, R_STREAM_END_MISSING)
        self._judge_against_ledger()
        # R-05. How far each stream ran and how far its attestation reached,
        # attributed to every session it fed. Done here rather than per record
        # because "the last record" is only knowable once there are no more.
        for stream in sorted(self.streams.values(), key=lambda s: s.stream_id):
            if stream.first_seq is None or stream.last_seq is None:
                continue
            span = {"stream_id": stream.stream_id,
                    "first_seq": stream.first_seq,
                    "last_seq": stream.last_seq,
                    "verified_to": stream.highest_verified_seq}
            for session_key in stream.sessions_seen:
                if session_key:
                    self._session(session_key).signature_ranges.append(dict(span))
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

    def _admission(self, stream: _Stream) -> str:
        """Why this stream may NOT be written to the ledger, or "" if it may.

        R-03. ``record`` used to be called for every stream that had a first and
        a last sequence, with no requirement that any of it verified. Three ways
        that poisons the file it is supposed to protect, all reproduced:

        1. UNSIGNED ADMISSION. Under a loaded trust store, a chained-but-unsigned
           stream -- which needs no key and anyone able to append to the input
           can write -- was recorded with its head. The genuine signed stream at
           the same positions then read as ``forked``, so the attacker turned a
           squatted stream id into a critical finding against the real collector
           and, worse, made the real one look like the rewrite.

        2. UNSCORED ADMISSION. Assembly drops events past ``max_sessions`` and
           ``max_events_per_session``, and the verifier had already recorded
           their positions. With ``--max-sessions 1`` over two sessions the
           ledger advanced across all six records, so the three belonging to the
           session nobody scored were marked as already seen. They can now never
           be scored: re-feeding them reads as a replay.

        3. EVIDENCE THAT DID NOT HOLD. A broken chain, an invalid signature, a
           revoked or unauthorised key, a stale or future-dated record -- none of
           it stopped the position being committed as a scored fact.

        The trust store is the switch on the first rule, and that is deliberate.
        An operator who has loaded no keys has told Cohaera nothing about who may
        attest, so requiring a verified signature would disable the ledger for
        every unsigned deployment -- which is most of them, today. Once keys ARE
        loaded, an unsigned record is not evidence, and the ledger is exactly the
        place that must not treat it as any.
        """
        if stream.unscored_records:
            return (f"{stream.unscored_records} record(s) were verified and "
                    f"never scored, because assembly dropped them on a budget")
        failed = sorted(stream.codes & INADMISSIBLE)
        if failed:
            return f"the stream's own evidence did not hold ({', '.join(failed)})"
        if self.keys.loaded and not stream.signatures_verified:
            return ("no record on this stream carried a signature this trust "
                    "store accepts")
        return ""

    def _judge_against_ledger(self) -> None:
        """Compare every stream this run saw with what previous runs recorded.

        Runs at finalise because the question is about the stream's whole
        extent, not any one record, and because the checkpoint head it depends
        on is only complete once the last record has been consumed.

        A replay or a fork is attributed to EVERY session whose records came
        from that stream, which is different from how a gap is attributed. A gap
        implicates the two sessions either side of it; a replayed stream
        implicates all of them equally, because every session in it was scored
        before.
        """
        if not self.ledger.enabled:
            for state in self.sessions.values():
                if state.with_integrity:
                    state.note(R_NO_STREAM_LEDGER)
            return
        for stream in sorted(self.streams.values(), key=lambda s: s.stream_id):
            if stream.first_seq is None or stream.last_seq is None:
                continue
            verdict = self.ledger.compare(
                stream.stream_id, stream.first_seq, stream.last_seq,
                stream.head, stream.ledger_checkpoint_head,
                first_prev=stream.first_prev)
            keys = tuple(sorted({k for sid in stream.sessions_seen
                                 for k in self._session(sid).signing_key_ids}))
            refusal = self._admission(stream)
            self.ledger.record(verdict, stream.first_seq, stream.last_seq,
                               stream.head, self.run_id, self.freshness.as_of,
                               key_ids=keys, admit=not refusal,
                               closed=stream.closed_at is not None)
            if refusal:
                self.ledger_refusals.append(
                    {"stream_id": stream.stream_id, "reason": refusal,
                     "first_seq": stream.first_seq, "last_seq": stream.last_seq})
            code = verdict.code
            for session_key in stream.sessions_seen:
                if not session_key:
                    continue
                state = self._session(session_key)
                if code:
                    # R-02. SEEN_DISCONTINUOUS carries R_STREAM_SKIPPED_RECORDS
                    # through SeenVerdict.code now, so the gap case arrives here
                    # rather than being re-derived from an arithmetic test on a
                    # status that had already called it ordinary advancement.
                    state.note(code)
                    state.replayed_streams.append(verdict.as_dict())
                if refusal:
                    state.note(R_LEDGER_NOT_ADVANCED)
                if verdict.boundary == BOUNDARY_UNSTATED:
                    # Continuous by sequence, and nothing said what it follows.
                    # Reported next to the advancement rather than instead of
                    # it: the records were scored, and the join was not checked.
                    state.note(R_STREAM_BOUNDARY_UNVERIFIED)
                if self.ledger.budget_exhausted:
                    state.note(R_LEDGER_BUDGET)

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
            "signature_seconds": round(self.signature_seconds, 3),
            "stream_budget_exhausted": self.stream_budget_exhausted,
            "freshness": self.freshness.as_dict(),
            "stream_ledger": self.ledger.summary(),
            "stream_ledger_refusals": self.ledger_refusals[
                :self.limits.max_evidence_items],
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
                 "first_prev": s.first_prev,
                 "joined_midstream": s.joined_midstream,
                 "closed_at": s.closed_at}
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

    @staticmethod
    def _note(state: SessionIntegrity, stream: _Stream, code: str) -> None:
        """Record a code against the session AND the stream that raised it.

        R-03. Everything downstream of a record's verification is a fact about
        two things at once -- the session whose record revealed it, which is what
        the verdict reports, and the stream it arrived on, which is what the
        ledger has to judge before it agrees to remember that stream.
        """
        state.note(code)
        stream.codes.add(code)

    def _note_chain_break(self, stream: _Stream, session_key: str,
                          seq: int) -> None:
        """Charge an ambiguous stream boundary to both adjacent sessions.

        A mismatch discovered on the current record can mean that record was
        altered, or that the previous record supplied a false chain head.  When
        a stream multiplexes sessions, assigning the break only to the current
        session lets the previous session inherit coverage from a later
        signature.  As with a sequence gap, neither side of the boundary can be
        admitted independently.
        """
        for key in dict.fromkeys((stream.last_session, session_key)):
            if not key:
                continue
            state = self._session(key)
            self._note(state, stream, R_CHAIN_BROKEN)
            if len(state.chain_breaks) < self.limits.max_evidence_items:
                state.chain_breaks.append(seq)

    def _consume(self, stream: _Stream, seq: int, body: str,
                 integrity: Integrity, session_key: str,
                 when: float | None = None) -> None:
        """Chain- and signature-check one in-order record."""
        state = self._session(session_key)
        if stream.first_seq is None:
            stream.first_seq = seq
            stream.first_prev = integrity.prev
        stream.last_seq = seq
        if stream.closed_at is not None and seq > stream.closed_at:
            # E30. The collector signed "nothing follows" and this follows.
            self._note(state, stream, R_RECORDS_AFTER_CLOSE)
        if integrity.final:
            stream.final_seen = True
        expected_chain = chain_step(stream.head, body) if stream.head else None
        if expected_chain is None and seq > 0:
            # No head, past the seed. Either _begin adopted an absent ``prev``
            # on a mid-stream join or _force resynced onto one after a gap;
            # either way the body in hand is bound to nothing, whatever the
            # record's own ``chain`` and signature say. Charged to this
            # session only: there is no earlier session on the stream to
            # share it with, which is the whole problem.
            self._note(state, stream, R_CHAIN_UNANCHORED)
            if len(state.unanchored) < self.limits.max_evidence_items:
                state.unanchored.append(seq)

        chain_mismatch = (expected_chain is not None
                          and integrity.chain is not None
                          and integrity.chain != expected_chain)
        prev_mismatch = (integrity.prev is not None and bool(stream.head)
                         and integrity.prev != stream.head)
        if chain_mismatch or prev_mismatch:
            # Localises: this boundary is where the stream diverged from what
            # the collector signed.  One record can fail both comparisons, but
            # it is still one broken boundary.
            self._note_chain_break(stream, session_key, seq)

        # Advance on the record's OWN declared chain when it has one. A single
        # broken record would otherwise poison every record after it, turning
        # one edit into a stream-wide alarm and hiding where the edit was.
        stream.head = integrity.chain or expected_chain or stream.head
        stream.expected = seq + 1
        stream.last_session = session_key
        stream.sessions_seen.add(session_key)
        if not session_key:
            # R-03. Assembly attributes a dropped event to no session, so this
            # record's position was verified and its content was never scored.
            stream.unscored_records += 1
        # Snapshot the head the instant this run passes the sequence the ledger
        # last recorded. Taken here rather than at finalise because by then the
        # head has advanced and the comparison is no longer possible.
        if (stream.ledger_checkpoint_seq is not None
                and seq == stream.ledger_checkpoint_seq):
            stream.ledger_checkpoint_head = stream.head

        if integrity.signed:
            self._check_signature(stream, seq, integrity, state, when)
        elif self.keys.loaded:
            self._note(state, stream, R_UNSIGNED)

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
            self._note(state, stream, R_KEY_UNKNOWN)
            state.unknown_key_ids.add(str(integrity.key_id))
            return
        state.signing_key_ids.add(key.key_id)
        if not key.authorises(ROLE_COLLECTOR):
            # A policy key signing telemetry. Either the operator wired the
            # wrong key into the collector, or somebody is attesting the stream
            # with a key that was trusted for something else entirely -- and the
            # second is why the roles exist.
            self._note(state, stream, R_KEY_WRONG_ROLE)
            return
        if key.revoked:
            self._note(state, stream, R_KEY_REVOKED)
            return
        # R-12. Count and clock. The count is charged before the work so a
        # producer cannot get one free verification per budget check; the clock
        # is what makes the bound mean the same thing on a slow host as on a
        # fast one.
        if (self.signatures_verified >= self.limits.max_signature_verifications
                or self.signature_seconds >= self.limits.max_signature_seconds):
            self.signature_budget_exhausted = True
            state.note(R_SIGNATURE_BUDGET)
            return
        self.signatures_verified += 1
        state.signatures_verified += 1
        message = signing_input(stream.stream_id, seq, integrity.chain or "",
                                final=integrity.final)
        started = time.monotonic()
        verified = ed25519.verify(key.public, message, integrity.sig or b"")
        self.signature_seconds += time.monotonic() - started
        if not verified:
            self._note(state, stream, R_SIGNATURE_INVALID)
            if len(state.bad_signatures) < self.limits.max_evidence_items:
                state.bad_signatures.append(seq)
            return
        # Counted only here, after every reason the signature could have failed
        # to establish anything has been ruled out. R-03 reads this to decide
        # whether the ledger may remember the stream, so an increment anywhere
        # earlier would let an unauthorised or invalid signature buy admission.
        stream.signatures_verified += 1
        # R-05. Same argument, one line further: how far the attestation
        # reaches is only a fact once the signature has actually held.
        if (stream.highest_verified_seq is None
                or seq > stream.highest_verified_seq):
            stream.highest_verified_seq = seq
        if integrity.final and (stream.closed_at is None or seq < stream.closed_at):
            # E30. Verified, so the closing statement is the collector's.
            # The lowest verified close wins: everything past it is already
            # charged as after-close in _consume.
            stream.closed_at = seq
        self._pin_key(stream, seq, key, state)

        if key.windowed:
            inside = key.covers_clock(when)
            if inside is None:
                state.note(R_KEY_WINDOW_UNCHECKED)
            elif not inside:
                self._note(state, stream,
                           R_KEY_NOT_YET_VALID
                           if key.not_before is not None and when is not None
                           and when < key.not_before else R_KEY_EXPIRED)
        self._check_freshness(state, stream, when)

    def _pin_key(self, stream: _Stream, seq: int, key: TrustedKey,
                 state: SessionIntegrity) -> None:
        """Hold a stream to the key that first attested it. EH-02.

        Called only after a signature VERIFIED, so the pin is a fact the
        operator's trust store established rather than a field the producer
        wrote. The first verified key is pinned; every later verified
        signature must be under that key or under a key the store records as
        succeeding it, directly or through a chain of ``replaces``. Anything
        else is a second trusted party writing into this stream and is
        inadmissible: the chain can hold perfectly across the takeover, since
        the usurper continues it from the genuine head, which is exactly why
        the chain alone was never going to notice.

        Succession is followed FORWARD from the new key only. A stream signed
        by the successor and then by the retired predecessor is a rollback,
        not a rotation, and the ``not_after`` on the retired key is the
        operator's tool for that case rather than this one.
        """
        previous, stream.last_verified_key_id = stream.last_verified_key_id, key.key_id
        if stream.key_id is None:
            stream.key_id = key.key_id
            return
        if key.key_id == stream.key_id:
            return
        if self._succeeds(key, stream.key_id):
            # A rotation the operator wrote down. The stream re-pins to the
            # successor so that the predecessor cannot sign into it again
            # without the same question being asked in the other direction.
            stream.key_id = key.key_id
            return
        self._note(state, stream, R_STREAM_KEY_CHANGED)
        if (key.key_id != previous
                and len(state.stream_key_changes) < self.limits.max_evidence_items):
            state.stream_key_changes.append(
                {"stream_id": stream.stream_id, "seq": seq,
                 "from_key_id": stream.key_id, "to_key_id": key.key_id})

    def _succeeds(self, key: TrustedKey, predecessor: str) -> bool:
        """Does ``key`` replace ``predecessor``, directly or transitively?

        Bounded by the number of keys in the store: ``replaces`` is a chain
        that _store_warnings already flags when it loops, and a loop here
        would otherwise be a producer-reachable hang.
        """
        seen: set[str] = set()
        current: TrustedKey | None = key
        while current is not None and current.replaces and current.key_id not in seen:
            if current.replaces == predecessor:
                return True
            seen.add(current.key_id)
            current = self.keys.get(current.replaces)
        return False

    def _check_freshness(self, state: SessionIntegrity, stream: _Stream,
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
        if self.freshness.from_future(when):
            ahead = -age
            if (state.furthest_future_s is None
                    or ahead > state.furthest_future_s):
                state.furthest_future_s = ahead
            self._note(state, stream, R_FROM_FUTURE)
        if self.freshness.stale(when):
            self._note(state, stream, R_STALE)

    def _hold(self, stream: _Stream, seq: int, body: str, integrity: Integrity,
              session_key: str, state: SessionIntegrity,
              when: float | None = None) -> None:
        if seq in stream.pending:
            self._note(state, stream, R_SEQUENCE_REPLAY)
            return
        if self._pending_total >= self.limits.max_reorder_window:
            # The buffer is full and the missing records have not arrived. Call
            # the gap, resync, and record that the decision was forced by a
            # bound rather than by evidence.
            self._note(state, stream, R_REORDER_BUDGET)
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
                self._note(state, stream, R_SEQUENCE_GAP)
                if len(state.gaps) < self.limits.max_evidence_items:
                    state.gaps.append(dict(gap))
            # Resync on the surviving record's own declared predecessor. Without
            # this every record after a deletion would also fail to chain, and
            # one deletion would read as a wholly forged stream.
            stream.head = integrity.prev or ""
            stream.expected = nxt
