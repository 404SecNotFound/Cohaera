"""The shared contract every external-corpus adapter is held to.

An adapter is the single most dangerous file in this directory, because it is
where optimism creeps in. Cohaera's checks read evidence surfaces; a public
trace corpus carries some of them and not others; and the tempting thing to do
with a surface the corpus does not carry is to write a plausible value for it
so that the run produces numbers instead of declines.

Every such value is a lie that propagates into every figure downstream.

THE DOCTRINE: ABSENT, NEVER WEAKER
----------------------------------
If the source corpus does not carry a field, the adapted session does not carry
it either. It is omitted and recorded in an :class:`AbsenceLedger`. It is never
defaulted to a value that reads as benign, as safe, or as evidenced.

This is not a style preference. Three concrete defaults would each silently
invalidate the whole harness, and all three are one keystroke away:

``reversible: true``
    ``ToolCall.klass`` resolves an absent capability manifest by consulting the
    producer's ``reversible`` flag ahead of the name heuristic. Measured, not
    assumed: on the adapter fixtures this flips two of four calls from
    ``unknown`` to ``read_only``. A tool whose name the heuristic already reads
    as egress -- ``send_email`` -- survives, because egress-by-name outranks the
    producer flag. So the damage is not that the consequential population
    empties; it is subtler and harder to notice.

    Two things go wrong. Every tool the keyword lists do not recognise silently
    becomes ``read_only`` rather than ``unknown``, so a state-changing tool with
    an unfamiliar name reads as a harmless read. And ``unknown`` is what
    DEGRADES coverage confidence -- removing it inflates the confidence of every
    check that reads tool class, so the run reports itself better-evidenced than
    it is. A default of ``false`` is no better: it makes everything a
    ``state_change`` and manufactures alerts instead of suppressing them.

    Omitting the flag lets the heuristic answer or return ``unknown``, and
    ``unknown`` costs confidence exactly as it should.

``has_injection_patterns: false``
    ``model.scanner_reported`` treats an explicit ``false`` as a real answer --
    "a scanner ran here and found nothing" -- because the difference between no
    markers and no scanner is the entire reason coverage exists. An adapter that
    helpfully writes ``false`` for a corpus that never ran a scanner BUYS CH03
    coverage with a fabricated answer, and CH03 would report itself evaluated
    across a corpus on which it could not have concluded anything.

``effect_receipt`` / ``approval`` stubs
    A synthesised receipt or approval is an attestation from an authority that
    was never asked. CH06 and CH07 exist to say whether such an attestation is
    present and consistent; manufacturing one converts both checks from a
    measurement into a tautology.

So the rule this module enforces mechanically, rather than by convention, is:
an adapter may only emit an evidence field it can point at a source field for.
:func:`assert_no_fabricated_evidence` runs over every event an adapter produces
and raises if a fabricable field appears. It is called by the adapters
themselves, not only by the tests, so the doctrine holds at runtime.

WHAT NO PUBLIC TRACE CORPUS CARRIES
-----------------------------------
Both corpora this directory targets -- and, as far as I can find, every public
agent-trajectory benchmark -- record what the agent DID: a user request, tool
calls with arguments, tool results or environment feedback, and a final
response. None of them record what the surrounding SYSTEM did about it. There
are no policy decision events, no approval grants bound to call arguments, and
no receipts from the authority an action actually reached.

That is not an oversight by their authors. Those artefacts are produced by a
control plane, and these corpora are generated or replayed traces with no
control plane behind them. It does mean the three Cohaera checks that read
those surfaces cannot be externally validated by this route at all, which
``docs/EXTERNAL-VALIDATION.md`` states plainly and ``tests/test_external.py``
holds to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Cohaera's own surface names, imported rather than restated. If the engine
# renames a surface, this file fails to import instead of quietly describing a
# surface that no longer exists.
from cohaera.checks import (
    SURFACE_APPROVAL,
    SURFACE_EFFECT_RECEIPT,
    SURFACE_EVENT_INTEGRITY,
    SURFACE_INJECTION_SCANNER,
    SURFACE_POLICY_SEMANTICS,
)

# ---------------------------------------------------------------------------
# The fabricable set
# ---------------------------------------------------------------------------

# Event ``data`` keys an adapter must never write unless the source corpus
# supplied the underlying fact. Each maps to the surface it would forge.
#
# Read this as the enforcement half of the module docstring. A field is on this
# list when writing a plausible default for it makes the session look MORE
# benign or BETTER evidenced than the source supports -- which is the only
# direction of error that matters, because it is the one that flatters the
# detector.
FABRICABLE_FIELDS: dict[str, str] = {
    # Classification. `true` reads as read_only, which empties the
    # consequential population every downstream check is computed over.
    "reversible": "tool_class",
    # Injection scanner. Both keys are real answers to `scanner_reported`,
    # so either one buys CH03 coverage the corpus did not pay for.
    "has_injection_patterns": SURFACE_INJECTION_SCANNER,
    "injection_patterns": SURFACE_INJECTION_SCANNER,
    # P1 evidence sidecars. No public corpus carries any of the three.
    "effect_receipt": SURFACE_EFFECT_RECEIPT,
    "approval": SURFACE_APPROVAL,
    "cohaera.approval:1": SURFACE_APPROVAL,
    "cohaera.receipt:1": SURFACE_EFFECT_RECEIPT,
    "integrity": SURFACE_EVENT_INTEGRITY,
    "cohaera.integrity:1": SURFACE_EVENT_INTEGRITY,
    # Policy semantics. An adapter writing `enforcement: enforced` asserts that
    # a control plane was in the loop and let the call through, which is the
    # single most load-bearing claim CH04 makes.
    "enforcement": SURFACE_POLICY_SEMANTICS,
    "policy_decision": SURFACE_POLICY_SEMANTICS,
    "threshold_usd": SURFACE_POLICY_SEMANTICS,
}

# Event types that ARE policy semantics. Emitting one at all is the fabrication;
# there is no benign value for it.
FABRICABLE_EVENT_TYPES = frozenset({
    "policy_check", "policy_violation", "guardrail_triggered",
    "approval_granted", "approval_request", "permission_check",
})


class FabricatedEvidenceError(AssertionError):
    """An adapter emitted an evidence field its source corpus cannot support.

    Raised at adapt time rather than reported at score time, because a run that
    reaches the scoring stage on fabricated evidence has already produced
    numbers somebody may quote.
    """


def assert_no_fabricated_evidence(events: list[dict[str, Any]],
                                  source: str,
                                  sourced: frozenset[str] = frozenset()) -> None:
    """Refuse to hand back events carrying evidence the corpus never had.

    The doctrine's teeth. Called by every adapter on its own output.

    ``sourced`` names the surfaces this adapter can point at a real source field
    for, and is the ONLY way to emit a field on the fabricable list. It is
    deliberately awkward: an adapter must name the surface explicitly, at the
    call site, for that one adaptation. There is no default and no global
    setting, because the failure being designed against is a surface becoming
    permanently permitted after one legitimate use.

    Today exactly one surface is ever passed here -- the injection scanner, by
    the StepShield adapter, only when its opt-in has actually marked a step from
    the corpus's own per-step annotation. Every other fabricable field is
    unreachable by construction.
    """
    for i, event in enumerate(events):
        etype = event.get("event_type")
        if etype in FABRICABLE_EVENT_TYPES:
            raise FabricatedEvidenceError(
                f"{source}: event {i} has event_type {etype!r}. No public trace "
                "corpus carries policy or approval events; emitting one would "
                "manufacture the control-plane evidence CH04 exists to weigh.")
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        for key in data:
            surface = FABRICABLE_FIELDS.get(key)
            if surface is None or surface in sourced:
                continue
            raise FabricatedEvidenceError(
                f"{source}: event {i} data carries {key!r}, which would "
                f"forge the {surface!r} surface. The source corpus does not "
                "supply it. Omit the field and record the absence in the "
                "ledger instead -- absent, never weaker.")


# ---------------------------------------------------------------------------
# The absence ledger
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Absence:
    """One evidence surface the source corpus cannot supply, and why."""

    surface: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"surface": self.surface, "reason": self.reason}


@dataclass(frozen=True)
class AbsenceLedger:
    """Everything an adapted session is missing, stated up front.

    Carried on the session rather than logged, because the point is that a
    consumer of an adapted session can ask what it does not contain WITHOUT
    re-deriving it from the absence of fields. A silent gap and a declared gap
    are different objects, and only one of them can be reasoned about.
    """

    entries: tuple[Absence, ...] = ()

    @property
    def surfaces(self) -> frozenset[str]:
        return frozenset(e.surface for e in self.entries)

    def as_list(self) -> list[dict[str, str]]:
        return [e.as_dict() for e in self.entries]


# The three surfaces that are absent from EVERY public agent-trajectory corpus
# found so far. Shared, because both adapters declare the identical absence for
# the identical reason, and two copies of a claim drift.
NO_CONTROL_PLANE = (
    Absence(SURFACE_POLICY_SEMANTICS,
            "The corpus records agent behaviour, not the decisions of a policy "
            "engine. There are no policy events, so CH04 cannot establish that "
            "a guardrail existed to be overrun."),
    Absence(SURFACE_APPROVAL,
            "No approval records. The corpus has no control plane that could "
            "have granted one, so CH04's approval binding has nothing to bind."),
    Absence(SURFACE_EVENT_INTEGRITY,
            "The traces are distributed as JSON files with no collector "
            "signature or hash chain, so CH06 has no stream to verify."),
    Absence(SURFACE_EFFECT_RECEIPT,
            "No provider receipts. Nothing in the corpus attests that a call "
            "reached an authority, so CH07 cannot contradict a claimed effect."),
)


# ---------------------------------------------------------------------------
# Adapted sessions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdaptedSession:
    """One external trajectory, mapped into records Cohaera's ingest accepts.

    Deliberately parallel to ``eval.harness.Labelled`` -- same field names for
    the same meanings -- so the external runner can reuse the corpus harness's
    scoring path rather than growing a second one that drifts.

    ``target_check`` is the field that does NOT carry over, and its emptiness is
    a finding rather than an omission. The internal corpus labels every attack
    with the Cohaera check responsible for catching it, which is what makes
    target-attributable recall computable. No external corpus carries such a
    label -- they label a trajectory unsafe, not "unsafe in the way CH02 is
    supposed to notice" -- so it is empty here and every metric derived from it
    is reported as unavailable rather than as zero.
    """

    session_id: str
    events: tuple[dict[str, Any], ...]
    is_attack: bool
    # The clustering unit for the bootstrap interval. Where a corpus pairs a
    # rogue and a clean trajectory on one task, both share a task_id and the
    # bootstrap treats them as one draw. Where it does not, this degenerates to
    # the session id and the runner says so rather than reporting a task-level
    # interval that is secretly a session-level one.
    task_id: str
    family: str
    kind: str
    absences: AbsenceLedger
    corpus: str
    target_check: str = ""
    notes: tuple[str, ...] = field(default=())

    @property
    def task_clustering_is_degenerate(self) -> bool:
        """True when task_id carries no information beyond session identity."""
        return self.task_id == self.session_id


# ---------------------------------------------------------------------------
# CIM record construction
# ---------------------------------------------------------------------------

_SAFE_ID = re.compile(r"[^A-Za-z0-9._:-]+")


def safe_id(value: str) -> str:
    """A corpus identifier reduced to something usable as a session key."""
    return _SAFE_ID.sub("-", str(value)).strip("-") or "unknown"


def cim_event(session_id: str, ts: float, event_type: str, *,
              agent: str | None = None,
              tool: str | None = None,
              span: str | None = None,
              source: str = "external",
              **data: Any) -> dict[str, Any]:
    """Build one observra-shaped CIM record.

    Mirrors ``eval.corpus.generate._ev`` in shape -- deliberately, since a
    record that Cohaera's ingest treats differently from the internal corpus's
    records would make the two evaluations incomparable.

    ``data`` is passed through as given. It is NOT sanitised here of fabricable
    fields, because a caller that legitimately has scanner evidence must be able
    to emit it; the check runs over the finished event list in
    :func:`assert_no_fabricated_evidence`, where the adapter states which
    surfaces its source actually supports.
    """
    tick = int(ts * 1000) % 100_000_000
    return {
        "event_id": f"ev-{session_id}-{tick}-{event_type}",
        "timestamp": round(ts, 3),
        "trace_id": session_id,
        "session_id": session_id,
        "span_id": span or f"sp-{tick}",
        "event_type": event_type,
        "agent_name": agent,
        "tool_name": tool,
        "framework": "external-corpus",
        "host": None,
        "user": None,
        # log_source_type is what marks these as adapted rather than collected.
        # A record in a SIEM that came from a benchmark must not be
        # indistinguishable from one that came from a collector.
        "data": {"log_source_type": f"cohaera.external.{source}", **data},
    }


class AdapterError(ValueError):
    """The source record does not match the format the adapter documents."""


def require_mapping(value: Any, what: str, where: str) -> dict[str, Any]:
    """Fail loudly, naming the record, rather than adapting a wrong shape.

    Adapters are run against data a human downloaded from a third party months
    after this code was written. The failure mode to design against is not a
    crash; it is an adapter that quietly produces three events from a schema it
    half-recognises and a run that reports a false-positive rate over a corpus
    it mostly could not read.
    """
    if not isinstance(value, dict):
        raise AdapterError(
            f"{where}: expected {what} to be a JSON object, got "
            f"{type(value).__name__}. The adapter is written against the schema "
            "documented in docs/EXTERNAL-VALIDATION.md; if the corpus has "
            "changed shape, fix the adapter rather than the data.")
    return value
