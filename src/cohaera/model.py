"""Core data model for Cohaera.

Observra emits a flat, per-event stream. Its rule engine signature is
``evaluate_rules(event_type, data)``, which is stateless and cannot see two events.
Cohaera's job starts by giving the stream a shape: a Session, with derived
behavioural features that only exist once events are grouped.

Everything here is deliberately dependency-free stdlib so it runs anywhere.

Type handling lives in :mod:`cohaera.validate`, not here. Every accessor on
``Event`` reads through it, so a directly-constructed ``Event`` is as safe as one
that came through the ingest firewall. That is the fix for the whole class of
"unhashable type" and "'dict' object has no attribute 'lower'" faults: there is
no longer a path that reaches a dict lookup or a ``.lower()`` with a value whose
type was never checked.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from functools import cached_property
from typing import Any, ClassVar, cast

from . import evidence, validate
from .capabilities import EMPTY_MANIFEST, CapabilityManifest
from .evidence import (
    ARGS_ABSENT,
    ARGS_CONFIRMED,
    ARGS_CONTRADICTED,
    ARGS_DECLARED,
    ARGS_RECOMPUTED,
    Approval,
    EffectReceipt,
    Integrity,
    SessionIntegrity,
)
from .identity import CorrelationKey, canonical, digest
from .identity import verdict_id as _verdict_id
from .limits import (
    DEFAULT_LIMITS,
    DEFECT_RESPONSE_TEXT_LENGTH,
    DEFECT_RESPONSE_TEXT_TYPE,
    Limits,
)
from .validate import (
    json_safe,  # re-exported: part of the public API
    marker_list,
    scanner_claim,
)


def scanner_marked(data: Any) -> bool:
    """Did a scanner say, in a well-formed way, that it FOUND markers here?

    The one predicate CH03 is allowed to build a critical finding on, and it
    lives here rather than in ``checks`` so that the answer cannot differ
    between the check that fires and the coverage report that says whether the
    check could run. A malformed claim is neither True nor False: it is a
    defect, already recorded on the Event, and it counts as no claim at all.
    """
    if not isinstance(data, Mapping):
        return False
    claim, _ = scanner_claim(data.get("has_injection_patterns"))
    if claim:
        return True
    markers, _ = marker_list(data.get("injection_patterns"))
    return bool(markers)


def scanner_reported(data: Any) -> bool:
    """Did a scanner report at all -- finding markers or finding none?

    ``has_injection_patterns: false`` and an empty ``injection_patterns`` list
    are both real answers, and the difference between "no markers" and "no
    scanner" is the whole reason coverage exists. A malformed claim is not an
    answer, so a producer cannot buy CH03 coverage with a type error.
    """
    if not isinstance(data, Mapping):
        return False
    claim, codes = scanner_claim(data.get("has_injection_patterns"))
    if claim is not None and not codes:
        return True
    markers, codes = marker_list(data.get("injection_patterns"))
    return markers is not None and not codes

# ---------------------------------------------------------------------------
# Vocabulary lifted from observra's schema/cim_schema.toml so Cohaera stays
# aligned with upstream rather than inventing a parallel taxonomy.
# Source: schema/cim_schema.toml, observra v1.1.0.
# ---------------------------------------------------------------------------

IRREVERSIBLE_KEYWORDS = {
    "delete", "drop", "truncate", "remove", "destroy", "send_email",
    "send_message", "publish", "post", "transfer", "pay", "charge",
    "deploy", "overwrite", "format", "wipe",
}

REVERSIBLE_KEYWORDS = {
    "read", "get", "fetch", "list", "search", "query", "draft",
    "preview", "analyze", "summarize",
}

# Tools whose effect leaves the trust boundary. Distinct from irreversibility:
# a tool can be reversible locally and still exfiltrate.
# NOTE the omissions. "request" was removed after review: as a whole token it
# matches request_permission and request_review, which are not egress. "post"
# stays because postmortem_read no longer matches under token splitting.
EGRESS_KEYWORDS = {
    "http", "https", "post", "send", "webhook", "upload", "publish",
    "email", "message", "notify", "sync", "export", "transfer", "exfiltrate",
}

TERMINAL_EVENTS = {
    "model_response", "model_error", "turn", "tool_end", "tool_error",
    "agent_end", "agent_handoff_error",
}

POLICY_EVENTS = {"cost_threshold_exceeded", "depth_exceeded"}

# Where a call's class came from. Coverage reads this: a session classified
# entirely by name heuristic cannot honestly report full confidence.
SOURCE_MANIFEST = "manifest"
SOURCE_NAME = "name_heuristic"
SOURCE_PRODUCER_FLAG = "producer_reversible_flag"
SOURCE_NONE = "unclassified"

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _classify(tool_name: Any) -> str:
    """Classify a tool as read_only, state_change, egress or unknown.

    Two defects fixed after the second external review.

    1. TYPE SAFETY. This did ``tool_name.lower()`` on whatever it was handed. A
       non-string tool_name (int, list, dict) raised AttributeError from inside
       a security check. Anything untyped is now ``unknown``.

    2. SUBSTRING COLLISIONS. Matching was ``any(k in t ...)`` on raw substrings,
       which produced genuinely bad results:

           budget_report        -> read_only   ("get" inside "budget")
           forget_password      -> read_only   ("get" inside "forget")
           request_permission   -> egress      ("request" is a whole word here,
                                                but the effect is not egress)
           postmortem_read      -> egress      ("post" inside "postmortem")

       Now split on non-alphanumerics and match WHOLE TOKENS only. Multi-word
       keywords such as ``send_email`` are matched against the token sequence.

    Egress still wins over state_change: data leaving the boundary is the more
    consequential property for a concealment check.

    This is still a name heuristic and it will still be wrong. It is now the
    LAST resort rather than the only one: see :mod:`cohaera.capabilities` for the
    exact per-tool declaration that outranks it. Tools that match nothing return
    ``unknown``, which must degrade coverage rather than silently read as safe.
    """
    if not isinstance(tool_name, str) or not tool_name:
        return "unknown"
    tokens = [t for t in _TOKEN_SPLIT.split(tool_name.lower()) if t]
    if not tokens:
        return "unknown"
    tokset = set(tokens)
    joined = "_".join(tokens)

    def _hit(keywords: set[str]) -> bool:
        for k in keywords:
            if "_" in k:
                if k in joined:            # multi-word keyword, e.g. send_email
                    return True
            elif k in tokset:              # whole token only
                return True
        return False

    if _hit(EGRESS_KEYWORDS):
        return "egress"
    if _hit(IRREVERSIBLE_KEYWORDS):
        return "state_change"
    if _hit(REVERSIBLE_KEYWORDS):
        return "read_only"
    return "unknown"


def cap_list(items: list[Any], limit: int) -> tuple[list[Any], int]:
    """Return at most ``limit`` items, plus how many were dropped.

    Bounds the OUTPUT. Measuring the previous code found that a session with 300
    policy events and 300 consequential calls produced a 6.3 MB verdict record
    from 900 input events, a 61x amplification, because every finding carried
    every call. An evidence field that grows with the square of a hostile input
    is a denial of service against the collector, not just against Cohaera.
    """
    if limit < 0 or len(items) <= limit:
        return list(items), 0
    return list(items[:limit]), len(items) - limit


def evidence_list(items: list[Any], limits: Limits) -> dict[str, Any]:
    """A bounded evidence field that says so when it is bounded."""
    shown, dropped = cap_list(items, limits.max_evidence_items)
    out: dict[str, Any] = {"items": shown, "total": len(items)}
    if dropped:
        out["truncated"] = dropped
    return out


class FrozenDict(dict):
    """A dict that refuses to be changed.

    A ``dict`` subclass rather than ``MappingProxyType`` on purpose. Cohaera
    tests record shape with ``isinstance(x, dict)`` in the schema firewall, the
    classifier and the serialiser, and a proxy is not a dict, so swapping one in
    would have made every record's ``data`` bag read as absent-and-defective.
    This keeps `dict` behaviour -- lookups, ``.get``, ``json.dumps`` -- and
    removes only the ability to mutate.
    """

    __slots__ = ()

    def _immutable(self, *_a: Any, **_kw: Any) -> Any:
        raise TypeError(
            "this record is frozen: Event.raw is immutable once constructed "
            "because derived values are cached from it (C4-07)")

    __setitem__ = _immutable
    __delitem__ = _immutable
    pop = _immutable                    # type: ignore[assignment]
    popitem = _immutable                # type: ignore[assignment]
    clear = _immutable                  # type: ignore[assignment]
    update = _immutable                 # type: ignore[assignment]
    setdefault = _immutable             # type: ignore[assignment]
    __ior__ = _immutable                # type: ignore[assignment]


_CONTAINERS = (dict, list, tuple)


def freeze(value: Any, _depth: int = 0, _max_depth: int = 100) -> Any:
    """Deep-freeze a decoded JSON value: dicts become FrozenDict, lists tuples.

    Depth-bounded for the same reason ``json_safe`` is: this walks
    producer-controlled structure. The ingest firewall refuses over-deep records
    long before this sees them, so the bound is the second wall, for Events
    built in memory rather than parsed from a line.

    Scalars are passed through at the call site rather than by recursing into
    this function, because most values in a record ARE scalars: a typical
    observra record made 18 calls per event when only 4 of its values were
    containers, and this runs once per event on the ingest hot path.
    """
    if _depth > _max_depth:
        return FrozenDict({"_truncated_depth": _max_depth})
    d = _depth + 1
    if isinstance(value, dict):
        return FrozenDict({
            k: (freeze(v, d, _max_depth) if isinstance(v, _CONTAINERS) else v)
            for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v, d, _max_depth) if isinstance(v, _CONTAINERS) else v
                     for v in value)
    return value


@dataclass(frozen=True)
class Event:
    """One observra CIM record, parsed but not interpreted.

    ``raw`` is kept verbatim. Every accessor reads it through
    :mod:`cohaera.validate`, so ``raw`` can contain anything JSON can express
    without a downstream consumer ever seeing a value of an unexpected type.

    C4-07. ``raw`` used to be an ordinary mutable dict while ``view`` was cached
    on first access, so ``e.raw["tool_name"] = "delete_everything"`` left every
    accessor still reporting the old name -- the class, the correlation key, the
    digest, all of it. The record and the engine's belief about the record could
    disagree indefinitely, and nothing raised.

    That is not a caching bug to paper over with an invalidate() call. The API
    PERMITTED mutation behind a cache, and any fix that leaves the mutation
    possible only narrows the window. So the record is frozen instead: the
    dataclass refuses rebinding, and ``freeze`` makes the payload itself
    immutable all the way down. A cache over an immutable value cannot go stale.
    C4-08 is the same fault one layer up; see :class:`Session`.
    """

    raw: dict[str, Any]
    limits: Limits = field(default=DEFAULT_LIMITS, repr=False, compare=False)

    def __post_init__(self) -> None:
        # COH-R13. A record is a JSON OBJECT, and this is where that stops
        # being an assumption. `Event(raw="{}")` used to construct happily --
        # freeze turns a str into a str and a list into a tuple -- and then
        # raise `AttributeError: 'str' object has no attribute 'get'` from
        # whichever accessor happened to run first, a crash arbitrarily far
        # from the line that caused it.
        #
        # This is not the rule-3 case and must not be softened into it. A
        # non-object arriving from the wire is already quarantined by ingest as
        # NOT_A_JSON_OBJECT and never reaches this constructor; a non-object
        # arriving here came from Cohaera's own code or from a tool building
        # events in memory, which is a defect in the caller rather than a
        # hostile record to be tolerated. Absent-and-flagged is for fields
        # inside a record. It is not for the record not being one.
        if not isinstance(self.raw, dict):
            raise TypeError(
                "Event.raw must be a JSON object, not "
                f"{type(self.raw).__name__}. A record read from a stream is "
                "quarantined as NOT_A_JSON_OBJECT before it reaches here, so "
                "this is a caller building an Event by hand.")
        if not isinstance(self.raw, FrozenDict):
            object.__setattr__(self, "raw", freeze(self.raw))

    @cached_property
    def view(self) -> validate.RecordView:
        return validate.view(self.raw, self.limits)

    @cached_property
    def _evidence(self) -> tuple[Any, Any, Any, tuple[str, ...]]:
        """Parse the three P1 sidecars once. See :mod:`cohaera.evidence`.

        Cached on the frozen record for the same reason every other derived
        value is: a sidecar parse is a canonical-JSON hash away from being
        expensive, and the record cannot change underneath the cache.
        """
        codes: list[str] = []

        def take(pair):
            value, c = pair
            codes.extend(c)
            return value

        integrity = take(Integrity.parse(self.raw.get(evidence.INTEGRITY_FIELD),
                                         self.limits))
        data = self.data
        receipt = take(EffectReceipt.parse(data.get(evidence.RECEIPT_FIELD),
                                           self.limits))
        approval = take(Approval.parse(data.get(evidence.APPROVAL_FIELD),
                                       self.limits))
        if self.event_type in POLICY_EVENTS:
            take(evidence.enforcement_of(data))
        return integrity, receipt, approval, tuple(dict.fromkeys(codes))

    @property
    def integrity(self) -> Integrity | None:
        return self._evidence[0]

    @property
    def effect_receipt(self) -> EffectReceipt | None:
        return self._evidence[1]

    @property
    def approval(self) -> Approval | None:
        return self._evidence[2]

    @property
    def enforcement(self) -> str:
        """A policy event's declared semantics, or ``undeclared``."""
        return evidence.enforcement_of(self.data)[0]

    @property
    def defects(self) -> tuple[str, ...]:
        """Fields that were not what they claimed to be, as reason codes."""
        return tuple(dict.fromkeys(self.view.defects + self._evidence[3]))

    @property
    def event_type(self) -> str:
        """Always a string.

        R2-02. This returned the raw value, so a list or dict event_type raised
        "unhashable type" from ``e.event_type not in {...}`` inside CH04. A
        malformed field in one record should never abort scoring the session.
        """
        return self.view.event_type

    @property
    def agent_name(self) -> str | None:
        return self.view.agent_name

    @property
    def timestamp(self) -> float:
        """Never raises. C-08: an unvalidated float() here was a trivial DoS.

        A malformed timestamp returns NaN rather than killing the run. NaN sorts
        last via ``sort_key`` and is detectable downstream via ``timestamp_valid``.
        """
        return self.view.ts

    @property
    def timestamp_valid(self) -> bool:
        t = self.view.ts
        return math.isfinite(t) and t > 0

    @property
    def sort_key(self) -> tuple[int, float]:
        """Total order that a NaN cannot corrupt.

        ``sorted(events, key=lambda e: e.timestamp)`` is not merely unstable
        with a NaN in the list, it is wrong: NaN compares False against
        everything, so the partition step of the sort leaves elements on
        whichever side they started. Events with no usable clock now sort to the
        end as a block, in arrival order.
        """
        t = self.view.ts
        return (0, t) if math.isfinite(t) else (1, 0.0)

    @property
    def span_id(self) -> str | None:
        """A bounded non-empty string, or None.

        BUG-01 and BUG-04 both die here. A list or dict span reached
        ``open_by_span[sid]`` and raised ``unhashable type``. A boolean span
        aliased an integer one, because Python hashes ``True`` and ``1``
        identically, so a terminal event for span ``1`` closed the call opened
        with span ``true``. Neither is possible once a span must be a string.
        """
        return self.view.span_id

    @property
    def tool_name(self) -> str | None:
        """Always a string or None. Producers do send non-strings."""
        return self.view.tool_name

    @property
    def data(self) -> dict[str, Any]:
        d = self.raw.get("data")
        return d if isinstance(d, dict) else {}

    @property
    def response_text(self) -> str | None:
        """Bounded string, or None.

        BUG-02. A truthy dict, list, int or float here became the session's
        final response and CH02 called ``.lower()`` on it. That is an
        AttributeError raised from inside a security check, which takes the
        whole scoring run down: denial of service, and detection suppression for
        every other session in the same file.
        """
        text, _ = validate.semantic_text(
            self.data.get("response_text"), self.limits.max_response_chars,
            "x", "x")
        return text

    def get(self, key: str, default: Any = None) -> Any:
        """Look in the envelope first, then the data bag."""
        if key in self.raw and self.raw[key] is not None:
            return self.raw[key]
        return self.data.get(key, default)

    def digest(self) -> str:
        """Content identity for this record. Stable across runs."""
        return digest(self.raw, 16)


@dataclass
class ToolCall:
    """A tool_start paired with its tool_end or tool_error."""

    name: str
    started_at: float
    span_id: str | None = None
    ended_at: float | None = None
    result: str | None = None          # success | failure | None if unpaired
    duration_ms: float | None = None
    reversible: bool | None = None     # observra auto-injects this
    had_args: bool = False             # was tool_args captured at all
    had_result: bool = False           # was tool_result captured at all
    error_class: str | None = None
    # C-02 / C-05: an explicit pairing state beats inferring one from `result`.
    #   open           tool_start with no terminal event yet
    #   complete       start and terminal seen exactly once
    #   orphan_end     terminal event with no matching start
    #   mismatched_end terminal event whose span does not match any open call
    #   duplicate_end  a second terminal event arrived for a completed call
    state: str = "open"
    manifest: CapabilityManifest = field(default=EMPTY_MANIFEST, repr=False,
                                         compare=False)
    # ---- P1 evidence ----------------------------------------------------
    # The call's argument identity, and where it came from. Approvals and
    # receipts bind on this, so a call that has none can be bound only by span,
    # which is a weaker claim that the verdict has to state rather than assume.
    arg_digest: str | None = None
    arg_digest_source: str = ARGS_ABSENT
    # True when the producer declared a digest AND Cohaera could recompute one
    # from the captured arguments, and they disagree. That is the producer
    # contradicting itself about its own call, which no honest emitter does.
    arg_digest_disagrees: bool = False
    receipt: EffectReceipt | None = None
    # ---- ordering (COH-R11) ---------------------------------------------
    # The collector sequence this call STARTED at, when the start event carried
    # a cohaera.integrity:1 sidecar. Wall clock is the producer's to choose and
    # ties in it are both accidental (coarse clocks) and forgeable; a sequence
    # inside a stream is covered by the hash chain and the signature over its
    # head, so it cannot be reordered without detection. See checks._ordering.
    start_stream: str | None = None
    start_seq: int | None = None

    @property
    def capability(self):
        return self.manifest.get(self.name)

    @property
    def klass_source(self) -> str:
        """Where this call's class came from. Coverage weights on it."""
        if self.capability is not None:
            return SOURCE_MANIFEST
        if _classify(self.name) == "egress":
            return SOURCE_NAME
        if self.reversible is not None:
            return SOURCE_PRODUCER_FLAG
        return SOURCE_NAME if _classify(self.name) != "unknown" else SOURCE_NONE

    @property
    def klass(self) -> str:
        """read_only | state_change | egress | unknown.

        Precedence:
          1. an exact capability manifest entry. Declared out of band by the
             operator, so it outranks anything on the event itself.
          2. egress by name. Data leaving the boundary is the property that
             matters most and reversibility says nothing about it.
          3. the producer's ``reversible`` flag, authoritative in BOTH
             directions (C-03).
          4. the name heuristic.

        Steps 2 to 4 are all guesses about an attacker-supplied string. Step 1
        is the only one that is a statement of fact, which is why unknown
        classification now degrades the confidence of every check that reads it
        rather than being reported as a standalone gap.
        """
        cap = self.capability
        if cap is not None:
            return cap.klass
        by_name = _classify(self.name)
        if by_name == "egress":
            return "egress"
        if self.reversible is False:
            return "state_change"
        if self.reversible is True:
            return "read_only"
        return by_name

    @property
    def consequential(self) -> bool:
        return self.klass in {"state_change", "egress"}

    @property
    def executed(self) -> bool:
        """Did this call actually complete successfully?

        C-04 on the review's CH04 note: a started-but-failed call is not an
        executed action, and treating it as one overstates impact.
        """
        return self.state == "complete" and self.result == "success"

    @property
    def clock_valid(self) -> bool:
        return math.isfinite(self.started_at)

    def brief(self, limits: Limits = DEFAULT_LIMITS) -> dict[str, Any]:
        """The bounded evidence row used by every check."""
        return {
            "tool": validate.sanitise_display(self.name, limits.max_evidence_value_chars),
            "class": self.klass,
            "class_source": self.klass_source,
            "at": self.started_at if math.isfinite(self.started_at) else None,
            "state": self.state,
            "result": self.result,
            "completed": self.executed,
        }


def _num(value: Any) -> float | None:
    v, _ = validate.finite_number(value)
    return v


def _argument_identity(data: dict[str, Any]) -> tuple[str | None, str, bool]:
    """(digest, source, disagrees) for one call's arguments.

    Two sources, and they are not equivalent. A producer-DECLARED digest is what
    the policy engine's approval was written against, so it is what a binding
    has to compare with. A RECOMPUTED one is a hash of the arguments Cohaera
    actually saw, which is the stronger claim about what the call did but is
    only available when the adapter captured arguments at all -- and observra
    strips them on the hot path, so in most deployments it will not be.

    When both exist they must agree. A producer whose declared digest does not
    match its own emitted arguments is contradicting itself, and that is worth
    surfacing: it is the shape of an agent declaring the digest an approval
    covers while sending different arguments.
    """
    declared = evidence.digest_text(data.get(evidence.ARG_DIGEST_FIELD))
    args = data.get("tool_args")
    computed = evidence.arg_digest(args) if args is not None else None
    if declared and computed:
        # F-01. The RECOMPUTED value is returned in both branches, and that is
        # the fix. It used to return `declared` unconditionally here, so a
        # producer that emitted arguments for one call and the digest of
        # another had the digest of another believed -- and an approval written
        # for the other call covered this one.
        #
        # When they agree the two values are equal and the choice is moot; the
        # source records that both were present, which is a stronger artefact
        # than either alone. When they disagree the captured arguments are what
        # the call did, and the source says the producer contradicted itself,
        # which makes the call unbindable rather than bindable-to-the-lie.
        if declared == computed:
            return computed, ARGS_CONFIRMED, False
        return computed, ARGS_CONTRADICTED, True
    if declared:
        return declared, ARGS_DECLARED, False
    if computed:
        return computed, ARGS_RECOMPUTED, False
    return None, ARGS_ABSENT, False


@dataclass(frozen=True)
class ApprovalMatch:
    """One approval, weighed against one call.

    ``fresh`` is deliberately tri-state. False is an expired or not-yet-valid
    approval; None is an approval that declared no window at all, which is a
    weaker artefact than a fresh one and a different thing from a stale one.
    Collapsing the two would report "approval expired" about an approval that
    never claimed to expire.
    """

    approval: Approval
    binding: str
    fresh: bool | None
    # F-02. Was the approval RECORD observed before the call it covers started?
    #
    # True, False, or None when nothing could order the two. Distinct from
    # ``fresh``, which asks only whether the approval's own declared window
    # contains the call -- and ``granted_at`` is a number the producer writes.
    # An approval emitted after the call completed, backdated to before it,
    # satisfies ``fresh`` completely and is a retroactive authorisation.
    observed_before_call: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"binding": self.binding, "fresh": self.fresh,
                "observed_before_call": self.observed_before_call,
                **self.approval.as_dict()}


class SealedSessionError(RuntimeError):
    """An attempt to mutate a session that has already been scored against."""


# Pure cache plumbing: rebinding these cannot change what the session IS, only
# how often its derived values are recomputed over an event list that can no
# longer change. Everything else is frozen by seal(). See Session.__setattr__.
_SESSION_CACHE_FIELDS = frozenset({"_caches", "_revision"})


@dataclass
class Session:
    """A correlated agent session. This is the object observra never builds.

    Derived values are cached. BUG-05: the first cache was populated on first
    access and never invalidated, so appending a terminal event left the call
    reported as still open. That was fixed by keying the cache on
    ``len(self.events)``.

    C4-08. Keying on LENGTH is not keying on CONTENT, and the difference is
    reachable: replace an event in place with ``s.events[0] = other`` and the
    length is unchanged, so every cached feature -- tool classes, egress counts,
    the call pairing, the content digest the verdict ID commits to -- is served
    from the old set. A read-only tool silently stands in for an exfiltration.

    This is C4-07 one layer up, and it has the same answer. Rather than add
    another invalidation hook for callers to forget, a session that is finished
    being built is SEALED: ``events`` becomes a tuple, so neither ``append`` nor
    index assignment exists any more, and a cache over an immutable sequence
    cannot go stale. :func:`cohaera.ingest.assemble` seals every session it
    returns, so everything the CLI scores is immutable by the time a check sees
    it. Streaming assembly keeps the mutable path: build with :meth:`add_event`,
    which bumps a revision counter, then :meth:`seal` when the session ends.
    """

    session_id: str
    events: Sequence[Event] = field(default_factory=list)
    correlation: CorrelationKey | None = field(default=None, compare=False)
    limits: Limits = field(default=DEFAULT_LIMITS, repr=False, compare=False)
    manifest: CapabilityManifest = field(default=EMPTY_MANIFEST, repr=False,
                                         compare=False)
    # What the stream verifier concluded about this session's records. Set by
    # :func:`cohaera.ingest.assemble`, because sequence verification is a
    # whole-input property and cannot be recomputed from one session's events.
    # None means no verification was run at all, which is NOT the same as
    # "verification found nothing" and must not be reported as clean.
    integrity: SessionIntegrity | None = field(default=None, compare=False)
    _caches: dict[str, tuple[Any, Any]] = field(default_factory=dict, repr=False,
                                                compare=False)
    _revision: int = field(default=0, repr=False, compare=False)
    _sealed: bool = field(default=False, repr=False, compare=False)

    @property
    def sealed(self) -> bool:
        return self._sealed

    def __setattr__(self, name: str, value: Any) -> None:
        """COH-R13. Seal the SESSION, not just its event list.

        ``seal`` froze ``events`` and nothing else, which closed one route to a
        stale cache and left the others open. ``manifest`` is the clearest:
        classification reads it, so rebinding it after sealing either serves
        classes cached under the previous manifest -- an egress call still
        reported read_only -- or silently reclassifies the session under a
        manifest it was never sealed with. ``integrity`` is worse in kind,
        because None there means no verification ran and must not be
        distinguishable from a verdict; ``limits`` changes every bound the
        evidence was cut to; and ``_sealed`` itself was rebindable, so the seal
        could simply be switched off and ``add_event`` used again.

        This is C4-07 and C4-08 a third time, and it gets the same answer they
        did: remove the mutation rather than add an invalidation hook for
        callers to forget. ``cohaera.ingest.assemble`` assigns ``integrity``
        before it seals, and ``eval.harness.SessionCache`` hands one sealed
        session to three scoring regimes on the strength of this guarantee.
        """
        # `_sealed` is absent from __dict__ until the dataclass __init__ sets
        # it last, so construction is unaffected.
        if self.__dict__.get("_sealed") and name not in _SESSION_CACHE_FIELDS:
            raise SealedSessionError(
                f"session {self.session_id!r} is sealed; {name!r} cannot be "
                "rebound because derived values are cached from it and every "
                "reader of a sealed session assumes it cannot change (C4-08, "
                "COH-R13)")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if self.__dict__.get("_sealed"):
            raise SealedSessionError(
                f"session {self.session_id!r} is sealed; {name!r} cannot be "
                "deleted (COH-R13)")
        object.__delattr__(self, name)

    # ---- cache plumbing --------------------------------------------------
    def _cached(self, key: str, build):
        # Length AND revision. Once sealed the events are a tuple and neither
        # can change; before that, length still catches a bare ``.events.append``
        # and the revision catches an in-place replacement made through
        # add_event/invalidate.
        token = (self._revision, len(self.events))
        hit = self._caches.get(key)
        if hit is not None and hit[0] == token:
            return hit[1]
        value = build()
        self._caches[key] = (token, value)
        return value

    def invalidate(self) -> None:
        """Drop every derived value. Call after mutating ``events`` in place."""
        self._caches.clear()
        self._revision += 1

    def seal(self) -> None:
        """Freeze the session. Idempotent; after this it is read-only."""
        if self._sealed:
            return
        # Order matters: `_sealed` goes last because __setattr__ refuses every
        # other rebinding once it is set, and that includes these two.
        self.events = tuple(self.events)
        self.invalidate()
        self._sealed = True

    def add_event(self, event: Event) -> None:
        """Append an event and invalidate everything derived from the old set."""
        if self._sealed:
            raise SealedSessionError(
                f"session {self.session_id!r} is sealed; its derived values are "
                "cached and adding an event would serve stale ones (C4-08)")
        if isinstance(self.events, tuple):      # defensive: sealed flag cleared
            self.events = list(self.events)
        # `events` is Sequence because a SEALED session's is a tuple. Before
        # sealing it is always a list, which the line above guarantees.
        cast("list[Event]", self.events).append(event)
        self.invalidate()

    # ---- identity -------------------------------------------------------
    @property
    def agent_names(self) -> list[str]:
        seen: list[str] = []
        for e in self.events:
            n = e.agent_name
            if n and n not in seen:
                seen.append(n)
        return seen

    @property
    def framework(self) -> str:
        return next((e.view.framework for e in self.events if e.view.framework),
                    "unknown")

    @property
    def host(self) -> str | None:
        return next((e.view.host for e in self.events if e.view.host), None)

    @property
    def user(self) -> str | None:
        return next((e.view.user for e in self.events if e.view.user), None)

    @property
    def correlation_confidence(self) -> float:
        return self.correlation.confidence if self.correlation else 1.0

    @property
    def content_digest(self) -> str:
        """Identity of the events this session was actually built from.

        C4-01: verdict_id committed only to (run, session_id, findings). Two
        sessions with different events but the same findings therefore produced
        the same verdict_id, so a SIEM deduplicating on it would drop the second
        as a retry. Computed once per session, lazily, at emit time.
        """
        def build() -> str:
            h = hashlib.sha256()
            for e in self.ordered_events:
                blob = canonical(e.raw).encode("utf-8")
                h.update(len(blob).to_bytes(8, "big"))
                h.update(blob)
            return h.hexdigest()[:32]
        return self._cached("content_digest", build)

    @property
    def integrity_defects(self) -> dict[str, int]:
        """Field-level defect codes seen in this session, with counts."""
        def build() -> dict[str, int]:
            counts: dict[str, int] = {}
            for e in self.events:
                for code in e.defects:
                    counts[code] = counts.get(code, 0) + 1
            return dict(sorted(counts.items()))
        return self._cached("defects", build)

    # ---- time -----------------------------------------------------------
    @property
    def _valid_ts(self) -> list[float]:
        return [e.timestamp for e in self.events if e.timestamp_valid]

    @property
    def started_at(self) -> float:
        return min(self._valid_ts, default=0.0)

    @property
    def ended_at(self) -> float:
        return max(self._valid_ts, default=0.0)

    @property
    def duration_s(self) -> float:
        return round(self.ended_at - self.started_at, 3)

    @property
    def clock_defects(self) -> int:
        return sum(1 for e in self.events if not e.timestamp_valid)

    @property
    def ordered_events(self) -> list[Event]:
        return self._cached("ordered", lambda: sorted(self.events,
                                                      key=lambda e: e.sort_key))

    # ---- tool calls -----------------------------------------------------
    @property
    def tool_calls(self) -> list[ToolCall]:
        """Pair tool_start with tool_end / tool_error. Cached per session.

        Pairing is by span_id where available, falling back to tool_name FIFO,
        because not every adapter propagates span_id consistently.
        """
        return self._cached("calls", self._build_calls)

    def _build_calls(self) -> list[ToolCall]:
        calls: list[ToolCall] = []
        # C-02 fix. Previously a span match popped the call out of open_by_span
        # but left it in open_by_name, so a later name-only terminal event could
        # find the SAME call again and overwrite a recorded success with a
        # failure. One identity, removed from every index atomically.
        #
        # The name index is a deque with LAZY deletion rather than a list with
        # ``idx in bucket`` followed by ``bucket.remove(idx)``. Both of those
        # are O(n) scans, so N same-name calls cost O(N^2) to pair, and the
        # cache only hid the cost from the second access onwards. Closed calls
        # are now marked in a set and skipped when the front of the queue is
        # popped, which is amortised O(1) per call.
        open_by_span: dict[str, int] = {}            # span_id -> index into calls
        open_by_name: dict[str, deque[int]] = {}     # name    -> indices, FIFO
        closed: set[int] = set()
        seen_spans: set[str] = set()                 # every span we have closed

        def _release(idx: int) -> None:
            """Retire this call from BOTH indices. The whole point of the fix."""
            tc = calls[idx]
            if tc.span_id and open_by_span.get(tc.span_id) == idx:
                open_by_span.pop(tc.span_id, None)
            closed.add(idx)

        def _next_open_by_name(name: str) -> int | None:
            bucket = open_by_name.get(name)
            if not bucket:
                return None
            while bucket and bucket[0] in closed:
                bucket.popleft()
            return bucket[0] if bucket else None

        for e in self.ordered_events:
            etype = e.event_type
            if etype == "tool_start":
                adigest, asource, adisagrees = _argument_identity(e.data)
                tc = ToolCall(
                    name=e.tool_name or "<unnamed>",
                    started_at=e.timestamp,
                    span_id=e.span_id,
                    reversible=validate.tri_state_bool(e.data.get("reversible"))[0],
                    had_args=e.data.get("tool_args") is not None,
                    state="open",
                    manifest=self.manifest,
                    arg_digest=adigest,
                    arg_digest_source=asource,
                    arg_digest_disagrees=adisagrees,
                    # F-03. Only from a CHAINED sidecar. A stream id and a
                    # sequence with no `prev` and no `chain` are two numbers
                    # the producer wrote, and letting them order events hands
                    # the producer the decision CH03 and CH04 rest on.
                    start_stream=(e.integrity.stream_id
                                  if e.integrity and e.integrity.chained
                                  else None),
                    start_seq=(e.integrity.seq
                               if e.integrity and e.integrity.chained
                               else None),
                )
                started = len(calls)
                calls.append(tc)
                if tc.span_id and tc.span_id not in open_by_span:
                    # Span collision: two open calls claiming the same span are
                    # not merged. The first keeps the index; the second falls
                    # back to name matching rather than silently overwriting.
                    open_by_span[tc.span_id] = started
                open_by_name.setdefault(tc.name, deque()).append(started)

            elif etype in {"tool_end", "tool_error"}:
                sid = e.span_id
                name = e.tool_name or "<unnamed>"
                idx: int | None = None

                # R2-01 fix. A supplied span_id is an IDENTITY ASSERTION. If it
                # does not match an open call, this terminal event must NOT be
                # allowed to close a different call by name. The old fallback
                # let an unknown or duplicate span mark an unrelated concurrent
                # call as failed, which fabricates findings.
                if sid:
                    idx = open_by_span.get(sid)          # strict, no fallback
                    if idx is not None and calls[idx].name != name:
                        idx = None                       # span/name disagreement
                else:
                    idx = _next_open_by_name(name)

                if idx is None or idx in closed:
                    # No open start to match. Record it as an orphan terminal
                    # rather than inventing a successful call out of nothing.
                    calls.append(ToolCall(
                        name=name, started_at=e.timestamp, span_id=sid,
                        ended_at=e.timestamp,
                        result="failure" if etype == "tool_error" else "success",
                        duration_ms=_num(e.data.get("duration_ms")),
                        reversible=validate.tri_state_bool(
                            e.data.get("reversible"))[0],
                        had_result=e.data.get("tool_result") is not None,
                        error_class=validate.identity_text(
                            e.data.get("error_class") or e.data.get("error_type_name"),
                            self.limits.max_identity_chars, "x", "x")[0],
                        state=("duplicate_end" if (sid and sid in seen_spans)
                               else "mismatched_end" if sid
                               else "orphan_end"),
                        manifest=self.manifest,
                        receipt=e.effect_receipt,
                    ))
                    continue

                tc = calls[idx]
                if tc.span_id:
                    seen_spans.add(tc.span_id)
                _release(idx)
                tc.ended_at = e.timestamp
                tc.result = "failure" if etype == "tool_error" else "success"
                tc.duration_ms = _num(e.data.get("duration_ms"))
                tc.error_class = validate.identity_text(
                    e.data.get("error_class") or e.data.get("error_type_name"),
                    self.limits.max_identity_chars, "x", "x")[0]
                rev, _ = validate.tri_state_bool(e.data.get("reversible"))
                if rev is not None:
                    tc.reversible = rev
                tc.had_result = e.data.get("tool_result") is not None
                tc.receipt = e.effect_receipt
                tc.state = "complete"

        return calls

    @property
    def tool_sequence(self) -> list[str]:
        return [tc.name for tc in self.tool_calls]

    @property
    def consequential_calls(self) -> list[ToolCall]:
        """Cached. CH03 and CH04 both walk this, and CH04 walked it once per
        policy event, which is where the O(policy_events * calls) blow-up came
        from."""
        return self._cached("consequential",
                            lambda: [tc for tc in self.tool_calls if tc.consequential])

    @property
    def unclassified_calls(self) -> list[ToolCall]:
        return [tc for tc in self.tool_calls if tc.klass == "unknown"]

    # ---- text surfaces (privacy-gated upstream) --------------------------
    @property
    def user_messages(self) -> list[str]:
        out = []
        for e in self.events:
            if e.event_type != "user_message":
                continue
            text, _ = validate.semantic_text(
                e.data.get("user_message_text"), self.limits.max_user_message_chars,
                "x", "x")
            if text:
                out.append(text)
        return out

    @property
    def final_response(self) -> str | None:
        """Last model_response text, if the adapter captured it.

        observra strips strings on the hot path (core/hot_cold.py) and
        response_text is a claude-adapter extra, so this is frequently None.
        That absence is a finding, not an error. See checks.coverage.

        A non-string here used to become the response and crash CH02. It is now
        treated as absent, with INVALID_RESPONSE_TEXT_TYPE recorded on the event
        so coverage can say CH02 was blinded rather than clean.
        """
        def build() -> str | None:
            texts = [e.response_text for e in self.ordered_events
                     if e.event_type == "model_response" and e.response_text]
            return texts[-1] if texts else None
        return self._cached("final_response", build)

    @property
    def response_text_rejected(self) -> bool:
        """True if a model_response carried a response_text of the wrong type."""
        return DEFECT_RESPONSE_TEXT_TYPE in self.integrity_defects

    @property
    def response_text_truncated(self) -> bool:
        """True if a model_response was longer than the bound and was cut. F-04.

        The truncation was always recorded as a field defect and nothing acted
        on it. CH02's whole conclusion is "this text does not mention the
        action", and a text that was cut short cannot support that conclusion
        about the part that was cut -- while the check reported full
        confidence. A disclosure sitting thirty-three characters past the cap
        produced a CRITICAL concealment finding.

        Note the asymmetry this enables and the fix depends on: finding a
        disclosure in a truncated prefix is still sound. Only the ABSENCE
        conclusion is unsupportable.
        """
        return DEFECT_RESPONSE_TEXT_LENGTH in self.integrity_defects

    # ---- security-relevant counters -------------------------------------
    @property
    def injection_markers(self) -> list[str]:
        def build() -> list[str]:
            out: list[str] = []
            cap = self.limits.max_injection_markers
            for e in self.events:
                if len(out) >= cap:
                    break
                items, _ = marker_list(e.data.get("injection_patterns"))
                if not items:
                    continue
                for p in items:
                    if len(out) >= cap:
                        break
                    out.append(p[:self.limits.max_marker_chars])
            return out
        return self._cached("markers", build)

    @property
    def max_delegation_depth(self) -> int:
        # Read once per event and narrowed with a walrus, rather than three
        # separate .get calls the type checker has to prove agree with each
        # other. `bool` is excluded because it is a subclass of `int` and a
        # producer sending `current_depth: true` would otherwise contribute 1.
        depths: list[int] = [
            d for e in self.events
            if isinstance(d := e.data.get("current_depth"), int)
            and not isinstance(d, bool)]
        return max(depths) if depths else 0

    @property
    def handoffs(self) -> list[tuple[str, str]]:
        out = []
        for e in self.events:
            if e.event_type not in {"agent_handoff", "agent_handoff_error"}:
                continue
            src = validate.identity_text(e.data.get("source_agent"),
                                         self.limits.max_identity_chars, "x", "x")[0]
            dst = validate.identity_text(e.data.get("target_agent"),
                                         self.limits.max_identity_chars, "x", "x")[0]
            out.append((src or "?", dst or "?"))
        return out

    @property
    def policy_events(self) -> list[str]:
        return [e.event_type for e in self.events if e.event_type in POLICY_EVENTS]

    # ---- P1 approvals ---------------------------------------------------
    @property
    def approvals(self) -> list[Approval]:
        """Every well-formed approval in this session, in arrival order.

        Bounded. An approval is a producer-supplied object and a session that
        claims a hundred thousand of them is a resource attack, not a
        well-governed agent.
        """
        def build() -> list[Approval]:
            out: list[Approval] = []
            for e in self.ordered_events:
                if len(out) >= self.limits.max_approvals_per_session:
                    break
                a = e.approval
                if a is not None:
                    out.append(a)
            return out
        return self._cached("approvals", build)

    @property
    def _approvals_by_span(self) -> dict[str, list[tuple[Approval, Event]]]:
        """Each approval WITH the record that carried it. F-02.

        The record's own observed position is the only thing that can tell a
        pre-authorisation from a retroactive one, and the ``Approval`` object
        carries nothing but what the producer declared about itself.
        """
        def build() -> dict[str, list[tuple[Approval, Event]]]:
            index: dict[str, list[tuple[Approval, Event]]] = {}
            seen = 0
            for e in self.ordered_events:
                if seen >= self.limits.max_approvals_per_session:
                    break
                a = e.approval
                if a is None:
                    continue
                seen += 1
                if a.subject.span_id:
                    index.setdefault(a.subject.span_id, []).append((a, e))
            return index
        return self._cached("approvals_by_span", build)

    @staticmethod
    def _observed_before(record: Event, call: ToolCall) -> bool | None:
        """Did this approval record arrive before the call started? F-02.

        Sequence first, for the reason every other ordering decision here uses
        it: a position inside a collector stream is covered by the hash chain
        and the signature over its head, and a wall clock is a number the
        producer chooses. Clock only as a fallback, and ``None`` when neither
        can answer -- which is not permission. See ``covering_approval``.
        """
        integrity = record.integrity
        if (integrity is not None and integrity.chained
                and integrity.seq is not None
                and call.start_seq is not None
                and integrity.stream_id == call.start_stream):
            return integrity.seq < call.start_seq
        started = call.started_at
        if started is None or not record.timestamp_valid:
            return None
        # A NaN start reaches here as an unusable comparison, so guard it the
        # same way: an ordering that cannot be established is not an ordering.
        if started != started:                    # NaN
            return None
        return record.timestamp <= started

    def approvals_for(self, call: ToolCall) -> list[ApprovalMatch]:
        """Every approval naming this call's span, and how well each one bound.

        Span alone is not a binding. An approval that names the span but a
        different tool does not cover this call; one that names the span and the
        tool but a different argument digest is the reuse case this schema
        exists to catch, and it is reported as a mismatch rather than silently
        dropped, because "an approval was presented for this call and did not
        fit it" is a stronger statement than "no approval was presented".
        """
        if not call.span_id:
            return []
        out: list[ApprovalMatch] = []
        for a, record in self._approvals_by_span.get(call.span_id, ()):
            if a.subject.tool_id and a.subject.tool_id != call.name:
                continue
            if call.arg_digest_source in evidence.ARGS_UNBINDABLE:
                # F-01. The call's own two argument identities disagree, so
                # there is no value here for an approval to bind to. Reported
                # as a mismatch rather than dropped: an approval was presented
                # against a call the telemetry cannot describe, and that is a
                # stronger statement than "no approval was presented".
                binding = evidence.BOUND_ARG_MISMATCH
            elif (a.subject.arg_digest and call.arg_digest
                    and a.subject.arg_digest != call.arg_digest):
                binding = evidence.BOUND_ARG_MISMATCH
            elif a.subject.complete and call.arg_digest:
                # All three named by the approval, and all three checked: the
                # span by the index that produced this list, the tool by the
                # skip above, the arguments here. Anything less is not exact.
                binding = evidence.BOUND_EXACT
            else:
                # R-10. Either the approval or the call declined to identify
                # part of the call. The span still binds; what the call DID does
                # not, and a verdict built on this has to say which of the two
                # it got -- so this value no longer covers anything, it only
                # annotates. See evidence.BINDING_TRUSTED.
                binding = evidence.BOUND_SPAN_ONLY
            out.append(ApprovalMatch(
                approval=a, binding=binding,
                fresh=a.covers_clock(call.started_at),
                observed_before_call=self._observed_before(record, call)))
        return out

    def covering_approval(self, call: ToolCall) -> ApprovalMatch | None:
        """The ALLOW that actually covers this call, if any.

        Three things have to hold and each of them was once a way through. The
        decision has to be ALLOW. The approval has to be inside its validity
        window -- an expired approval is not an approval. And the binding has to
        be EXACT: R-10 removed ``bound_span_only`` from
        ``evidence.BINDING_TRUSTED``, so an approval that names the span and the
        tool but not the arguments no longer covers a call at all. It is still
        returned by ``approvals_for`` and still reported, because "an approval
        was presented and did not constrain this call" is a stronger statement
        than "no approval was presented" -- it is just not coverage.

        F-02 adds a fourth, and it is the one a producer could walk past most
        easily. The approval RECORD has to have been observed before the call
        started. ``fresh`` checks the approval's declared window against the
        call, and every value in that window is a number the producer writes:
        an approval emitted after the call completed, backdated to before it,
        passes ``fresh`` perfectly. That is a retroactive authorisation, it is
        exactly how a completed bypass would be papered over, and it used to
        silence CH04 completely.

        ``observed_before_call is None`` -- nothing could order the two -- does
        NOT cover the call either. An ordering Cohaera cannot establish is not
        an ordering in its favour, and the alternative is a producer omitting
        the sequence to buy the benefit of the doubt.
        """
        for m in self.approvals_for(call):
            if m.approval.decision != evidence.DECISION_ALLOW:
                continue
            if m.binding not in evidence.BINDING_TRUSTED or m.fresh is False:
                continue
            if m.observed_before_call is not True:
                continue
            return m
        return None

    @property
    def dangling_approvals(self) -> list[Approval]:
        """Approvals whose subject matches no call in this session.

        Either the emitter is wrong, or an approval was harvested for reuse
        somewhere Cohaera cannot see. Both are worth a line in the record.
        """
        def build() -> list[Approval]:
            spans = {c.span_id for c in self.tool_calls if c.span_id}
            return [a for a in self.approvals
                    if a.subject.span_id not in spans]
        return self._cached("dangling_approvals", build)

    @property
    def total_cost_usd(self) -> float:
        """Finite, or zero. An infinite cost is not a cost, it is a bad field."""
        session_costs = [v for v in (_num(e.data.get("session_cost_usd"))
                                     for e in self.events) if v is not None]
        if session_costs:
            return round(max(session_costs), 6)
        per_call = sum(v for v in (_num(e.data.get("cost_usd"))
                                   for e in self.events) if v is not None)
        return round(per_call, 6)

    @property
    def error_count(self) -> int:
        return sum(1 for e in self.events
                   if e.event_type in {"tool_error", "model_error",
                                       "agent_handoff_error"})

    def features(self) -> dict[str, Any]:
        """The derived feature vector. This is what a SIEM should receive."""
        return self._cached("features", self._build_features)

    def _build_features(self) -> dict[str, Any]:
        calls = self.tool_calls
        seq, seq_dropped = cap_list(self.tool_sequence, self.limits.max_evidence_items)
        return {
            "session_id": self.session_id,
            "agent_names": self.agent_names,
            "framework": self.framework,
            "host": self.host,
            "user": self.user,
            "started_at": self.started_at,
            "duration_s": self.duration_s,
            "event_count": len(self.events),
            "tool_call_count": len(calls),
            "distinct_tools": len({c.name for c in calls}),
            "tool_sequence": seq,
            "tool_sequence_truncated": seq_dropped,
            "read_only_count": sum(1 for c in calls if c.klass == "read_only"),
            "state_change_count": sum(1 for c in calls if c.klass == "state_change"),
            "egress_count": sum(1 for c in calls if c.klass == "egress"),
            "unknown_class_count": sum(1 for c in calls if c.klass == "unknown"),
            "manifest_classified_count": sum(1 for c in calls
                                             if c.klass_source == SOURCE_MANIFEST),
            "unpaired_calls": sum(1 for c in calls
                                  if c.state in {"open", "orphan_end",
                                                 "mismatched_end", "duplicate_end"}),
            "open_starts": sum(1 for c in calls if c.state == "open"),
            "orphan_terminals": sum(1 for c in calls if c.state in
                                    {"orphan_end", "mismatched_end", "duplicate_end"}),
            "unpaired_consequential_count": sum(
                1 for c in calls
                if c.consequential and c.state != "complete"),
            "error_count": self.error_count,
            "injection_markers": self.injection_markers,
            "max_delegation_depth": self.max_delegation_depth,
            "handoff_count": len(self.handoffs),
            "handoff_chain": [f"{a}->{b}" for a, b in
                              self.handoffs[:self.limits.max_evidence_items]],
            "policy_events": self.policy_events[:self.limits.max_evidence_items],
            "policy_event_count": len(self.policy_events),
            "total_cost_usd": self.total_cost_usd,
            "has_final_response_text": self.final_response is not None,
            "tool_results_captured": sum(1 for c in calls if c.had_result),
            # ---- telemetry integrity, not agent behaviour -----------------
            "correlation": (self.correlation.as_dict() if self.correlation
                            else {"kind": "session_id", "confidence": 1.0,
                                  "key_version": "producer-supplied", "keyed": False}),
            "integrity_defects": self.integrity_defects,
            "integrity_defect_count": sum(self.integrity_defects.values()),
            "invalid_timestamp_count": self.clock_defects,
        }


@dataclass
class Finding:
    """One correlation result.

    Shaped to survive the trip into a SIEM. Deliberately carries the security
    fields that observra issue #108 reports the published parser drops:
    triggered_rules, max_severity, source_agent, target_agent, injection_patterns.

    ``family`` groups the split checks. CH03 and CH04 each became two check IDs
    because a completed action and a failed attempt are different facts and the
    old shared wording asserted the stronger one for both. Content that wants
    either can match ``family``; content that wants only the completed case
    matches ``check``.
    """

    check: str
    severity: str                       # critical | high | medium | low | info
    session_id: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    family: str = ""
    confidence: float = 1.0
    # How far the telemetry underneath this finding was itself established.
    # Defaults to ``unattested`` rather than to a verified value, because that
    # is the true state of every deployment that emits no integrity evidence,
    # and a default that reads as "checked" would be the exact failure this
    # field exists to remove. See cohaera.checks.evidence_status.
    evidence_status: str = "unattested"

    _ORDER: ClassVar[dict[str, int]] = {
        "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @property
    def rank(self) -> int:
        return self._ORDER.get(self.severity, 0)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_ORDER", None)
        return d


# The output contract's version, named once. R-20: it was a default argument
# spelled as a literal in one place and as a string in the parser field map in
# another, which is how the two drift apart without anything failing.
#
# 0.3 rather than 0.2 because the contract MOVED, and a parser that trusts the
# version string has to be told. `evidence_status` no longer emits "verified":
# it emits "verified_complete" or "verified_prefix", because one signature over
# a chain head anchors the prefix up to that head and says nothing about an
# unsigned tail (R-05). Provenance gained `trust_config_digest`, and
# `stream_ledger` gained the generation and state digest the run was actually
# judged against (R-06). A SIEM rule matching on the old vocabulary silently
# stops matching, and a version that did not move would have hidden that.
SESSION_SCHEMA = "cohaera:0.3"


def to_cim_event(session: Session, findings: list[Finding],
                 schema: str = SESSION_SCHEMA,
                 coverage: dict[str, Any] | None = None,
                 provenance: dict[str, Any] | None = None,
                 sequence: int | None = None) -> dict[str, Any]:
    """Emit one correlation-grade CIM record per session.

    Note the ``type`` and ``schema`` keys. observra issue #108 records that the
    Exabeam sender emits ``event_type`` where the published ABA parser expects
    ``type``, and never emits ``schema`` at all, so no correlation rule can
    match. Cohaera emits both, plus ``event_type`` for backwards compatibility.

    ``verdict_id`` is a digest of the run identity, the session and the findings
    (SEC-06). Scoring the same input twice under the same configuration produces
    the same ID, so a SIEM can recognise a retry; changing the input, the
    bounds, the baseline or the detector version changes it, so a genuine
    re-analysis is visibly new.
    """
    fired = sorted({f.check for f in findings})
    families = sorted({f.family for f in findings if f.family})
    max_sev = max(findings, key=lambda f: f.rank).severity if findings else "info"
    feats = session.features()
    prov = dict(provenance or {})

    finding_dicts = [f.as_dict() for f in findings]
    fdigest = digest(finding_dicts, 32)
    vid = _verdict_id(
        run=str(prov.get("analysis_run_id", "")),
        session_id=session.session_id,
        findings_digest=fdigest,
        # C4-01: commit to the evidence and the confidence, not just the verdict.
        # A session whose events or coverage changed is a different verdict even
        # when the findings list happens to match.
        session_digest=session.content_digest,
        coverage_digest=digest(coverage or {}, 32),
        schema=schema,
    )

    record: dict[str, Any] = {
        "type": "cohaera_session_verdict",
        "schema": schema,
        "event_type": "cohaera_session_verdict",
        "timestamp": session.ended_at,
        "session_id": session.session_id,
        "trace_id": session.session_id,
        "agent_name": session.agent_names[0] if session.agent_names else None,
        "framework": session.framework,
        "host": session.host,
        "user": session.user,
        "log_source_type": "cohaera",
        "verdict_id": vid,
        "findings_digest": fdigest,
        "sequence": sequence,
        "data": {
            **feats,
            "triggered_rules": fired,
            "triggered_families": families,
            "max_severity": max_sev,
            "finding_count": len(findings),
            "findings": finding_dicts,
            "provenance": prov,
        },
    }
    if coverage is not None:
        record["data"]["coverage"] = coverage
    return json_safe(record)
