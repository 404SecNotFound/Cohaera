"""Correlation checks.

Every check in here needs to see more than one event. That is the whole point:
observra's ``evaluate_rules(event_type, data)`` is single-event by signature, so
none of these can be expressed upstream today.

Each check returns zero or more Findings. A check that cannot run says so via
``coverage()`` rather than silently returning clean, because a check that cannot
see its inputs is not the same as a check that passed.

Two structural changes after the third external review.

SEPARATE FACTS GET SEPARATE CHECK IDS
    CH03 and CH04 each covered two different claims under one ID. An attempted
    call that errored was reported with the same title, the same detail wording
    and, for CH04, the same Sigma severity as one that completed. CH04 went
    further and asserted "the control did not stop the behaviour" about a call
    that failed, which the data cannot support: the available evidence does not
    say whether the guardrail, the tool, or an unrelated condition stopped it.
    Each is now two check IDs with wording that claims only what was observed.

COVERAGE IS A PER-CHECK CONTRACT, NOT A COUNT
    The old score counted checks that returned ``not_evaluated`` and nothing
    else, so a session whose every tool was unclassifiable still scored 0.8 to
    1.0. A detector operating on semantics it does not have should not
    contribute a full point. Each check now declares the surfaces it needs, what
    was present, and a confidence that multiplies in correlation quality,
    classification quality and clock quality.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from itertools import pairwise
from typing import Any

from .capabilities import CapabilityManifest
from .evidence import (
    ARGS_UNBINDABLE,
    BINDING_CONTEXT,
    BINDING_TRUSTED,
    BOUND_ARG_MISMATCH,
    BOUND_EXACT,
    BOUND_NONE,
    BOUND_SPAN_ONLY,
    DECISION_DENY,
    ENFORCEMENT_ADVISORY,
    ENFORCEMENT_BLOCKING,
    ENFORCEMENT_UNDECLARED,
    R_CHAIN_BROKEN,
    R_FRESHNESS_UNVERIFIABLE,
    R_KEY_EXPIRED,
    R_KEY_NOT_YET_VALID,
    R_KEY_REVOKED,
    R_KEY_UNKNOWN,
    R_KEY_WINDOW_UNCHECKED,
    R_KEY_WRONG_ROLE,
    R_NO_COLLECTOR_KEYS,
    R_NO_FRESHNESS_BOUND,
    R_NO_INTEGRITY,
    R_NO_STREAM_LEDGER,
    R_PARTIAL_INTEGRITY,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REPLAY,
    R_SIGNATURE_INVALID,
    R_SIGNATURE_PREFIX_ONLY,
    R_STALE,
    R_STREAM_FORKED,
    R_STREAM_REPLAYED,
    R_STREAM_SKIPPED_RECORDS,
    R_UNSIGNED,
    RECEIPT_AUTHENTIC,
    RECEIPT_AUTHENTICATED,
    RECEIPT_BOUND,
    RECEIPT_CLAIMED,
    RECEIPT_RECONCILED,
    SessionIntegrity,
)
from .identity import digest
from .limits import DEFAULT_LIMITS, Limits
from .model import (
    POLICY_EVENTS,
    SOURCE_MANIFEST,
    Event,
    Finding,
    Session,
    ToolCall,
    cap_list,
    scanner_marked,
    scanner_reported,
)
from .validate import sanitise_display

# Re-exported so that every reason code an operator can see is importable from
# one module, even though the integrity ones are produced in ``evidence``.
__all__ = [
    "R_CHAIN_BROKEN",
    "R_FRESHNESS_UNVERIFIABLE",
    "R_KEY_EXPIRED",
    "R_KEY_NOT_YET_VALID",
    "R_KEY_REVOKED",
    "R_KEY_UNKNOWN",
    "R_KEY_WINDOW_UNCHECKED",
    "R_KEY_WRONG_ROLE",
    "R_NO_COLLECTOR_KEYS",
    "R_NO_FRESHNESS_BOUND",
    "R_NO_INTEGRITY",
    "R_NO_STREAM_LEDGER",
    "R_PARTIAL_INTEGRITY",
    "R_SEQUENCE_GAP",
    "R_SEQUENCE_REPLAY",
    "R_SIGNATURE_INVALID",
    "R_SIGNATURE_PREFIX_ONLY",
    "R_STALE",
    "R_STREAM_FORKED",
    "R_STREAM_REPLAYED",
    "R_STREAM_SKIPPED_RECORDS",
    "R_UNSIGNED",
]

# ---------------------------------------------------------------------------
# CH01  Sequence order violation
# ---------------------------------------------------------------------------


def _is_retry(calls: list[ToolCall], j: int) -> bool:
    """Is call ``j`` a retry of the call before it, rather than a new action?

    Three conditions, all required: same tool, the previous attempt did NOT
    succeed, and the same argument digest. A retry is literally "do that again",
    so anything that differs makes it a different action.

    WHY THIS IS SAFE, which is the only interesting thing about it. CH01's
    count trigger fires on a novel route INTO a consequential call, and this
    suppresses one such route. An attacker could therefore try to launder a
    novel consequential call by prefixing a deliberately-failed identical copy
    -- except that the failed copy is itself a consequential call at the end of
    the same novel transition, so it is counted and CH01 still fires. The
    exclusion removes the SECOND of two, never the first, and the first is the
    one that carries the signal.

    Measured on the evaluation corpus: this is 8 of the false positives on
    ``benign_hard_reapproved_retry`` and 0 of the detections on any attack
    kind. Retrying a failed action is the most ordinary thing a well-governed
    agent does, and it produced a novel ``X -> X`` transition every time.

    Note the dependence on ``arg_digest``. With no declared digest there is
    nothing to compare, the suppression does not apply, and the false positive
    stays -- one more thing a producer buys by declaring what its calls did.
    """
    if j == 0:
        return False
    previous, current = calls[j - 1], calls[j]
    if previous.name != current.name or previous.executed:
        return False
    return bool(current.arg_digest) and previous.arg_digest == current.arg_digest


class SequenceGrammar:
    """A bigram model over tool-call order, mined from benign sessions.

    Deliberately the simplest thing that can detect ordering rather than
    co-occurrence. observra's own (unreachable) detect_suspicious_sequence()
    checks ``has_read AND has_external`` over the whole session, which is a set
    membership test with no notion of order at all.

    ``fingerprint`` is the baseline hash the verdict record carries. SEC-05:
    Cohaera learns "normal" from whatever corpus it is handed, with no
    attestation that the corpus was benign. That is a process control and cannot
    be fixed in code, but a run whose baseline changed should at least be
    distinguishable from one whose baseline did not.
    """

    START = "<START>"
    END = "<END>"

    # R-14. One grammar over every training session, and the name says so. A
    # future per-agent or peer-group model sets this to what it actually scoped
    # by; a reader of the verdict can then tell the two apart without knowing
    # which version produced it.
    SCOPE_FLEET = "fleet"

    def __init__(self, scope: str = SCOPE_FLEET) -> None:
        self.bigrams: Counter[tuple[str, str]] = Counter()
        self.unigrams: Counter[str] = Counter()
        self.sessions_fitted = 0
        self.scope = scope

    def fit(self, sessions: Iterable[Session]) -> SequenceGrammar:
        for s in sessions:
            seq = [self.START, *s.tool_sequence, self.END]
            for a, b in pairwise(seq):
                self.bigrams[(a, b)] += 1
            for t in seq:
                self.unigrams[t] += 1
            self.sessions_fitted += 1
        return self

    def score(self, session: Session) -> tuple[float, list[tuple[str, str]]]:
        """Return (violation_rate, unseen_transitions)."""
        seq = [self.START, *session.tool_sequence, self.END]
        transitions = list(pairwise(seq))
        if not transitions:
            return 0.0, []
        unseen = [t for t in transitions if self.bigrams[t] == 0]
        return len(unseen) / len(transitions), unseen

    def unseen_into_consequential(self, session: Session) -> list[tuple[str, str]]:
        """Unseen transitions that arrive AT a state-changing or egress call.

        This is the quantity dilution cannot touch, and it is the whole answer
        to EVASION.md E02.

        The violation rate is unseen/total, so padding a session with routine
        calls grows the denominator and leaves the numerator alone: measured on
        the evaluation corpus, three loops of a family's ordinary work drop two
        novel transitions to a rate of 0.15, under a threshold of 0.25, and CH01
        caught 0 of 32 such sessions. The padding is free -- the attacker uses
        the agent's own tools, in orderings the baseline already contains.

        Counting instead of rating is only half of it. An absolute count over
        ALL unseen transitions would fire on any long session that wandered,
        which is what rate-based scoring exists to avoid. What the count is
        taken over matters: a novel route into a read is a session doing
        something new, and a novel route into an irreversible or data-exporting
        call is a session doing something new THAT CANNOT BE UNDONE. Benign long
        sessions accumulate the first freely; the second is rare in both.

        Transition ``j`` of ``[START, *calls, END]`` arrives at call ``j``. The
        final transition arrives at END, which is not a call and is therefore
        never counted -- a session merely ENDING after a consequential call is
        the most ordinary shape there is.
        """
        calls = session.tool_calls
        seq = [self.START, *(c.name for c in calls), self.END]
        return [(a, b) for j, (a, b) in enumerate(pairwise(seq))
                if j < len(calls) and self.bigrams[(a, b)] == 0
                and calls[j].consequential and not _is_retry(calls, j)]

    @property
    def fitted(self) -> bool:
        return self.sessions_fitted > 0

    def vocabulary_overlap(self, session: Session) -> float:
        """Fraction of this session's calls whose tool the baseline has seen.

        This is the question "is the grammar even in a position to judge?", and
        it is deliberately separate from "does this session look unusual?".

        A bigram model has no way to tell those apart on its own. Every unseen
        transition scores the same whether the agent did something new or the
        baseline was fitted on a different workload entirely, and the second case
        drives the rate straight to 1.0. Measured on the evaluation corpus, that
        is not a hypothetical: with the baseline fitted on different task
        families, CH01 flagged 100% of benign sessions (256/256) at precision
        33.3%, which is exactly the attack base rate -- an alarm carrying no
        information at all.

        Overlap separates the two cases cleanly. On the same corpus:

            baseline covers the workload   0.67 - 1.00   (benign AND attack)
            baseline never saw it          0.00          (benign AND attack)

        Note that the ranges are identical for benign and attack sessions. That
        matters: this measures whether the MODEL applies, not whether the session
        is malicious, so gating on it cannot smuggle in label information.

        An empty session returns 1.0. There is no vocabulary to mismatch, so
        there is no evidence the grammar is out of its depth.
        """
        names = session.tool_sequence
        if not names:
            return 1.0
        return sum(1 for n in names if n in self.unigrams) / len(names)

    def fingerprint(self) -> str:
        """Content hash of what this grammar learned."""
        if not self.fitted:
            return ""
        return digest({
            "sessions": self.sessions_fitted,
            "bigrams": sorted(f"{a}\x1f{b}\x1f{n}" for (a, b), n in self.bigrams.items()),
        }, 16)


# Below this share of known tools, the grammar is being applied to a workload it
# was not fitted on, and CH01 reports not_evaluated instead of firing. The
# evaluation corpus separates the two regimes at 0.00 versus 0.67, so anything in
# (0, 0.67] behaves identically on that data and the exact value is not delicate.
# It is a threshold on ONE corpus, though, so it is a named constant rather than
# a magic number, and a deployment whose agents share tools across workloads
# should measure its own before trusting it.
MIN_VOCABULARY_OVERLAP = 0.5

# ...and only once there are enough calls to draw that conclusion. One unknown
# tool is not evidence that two vocabularies differ; it is equally consistent
# with a familiar agent taking a single novel action, which is precisely what
# CH01 exists to catch. Suppressing on n=1 would have turned the check off for
# the case it was written for.
#
# Chosen on that principle rather than fitted: every session in the evaluation
# corpus has at least three calls, so this constant changes nothing there and
# cannot have been tuned to flatter the numbers. It only governs sessions too
# short to judge.
MIN_CALLS_FOR_VOCABULARY_JUDGEMENT = 3

# How many novel routes into a consequential call fire CH01 regardless of rate.
#
# One. Not a tuned value -- the value the threat model forces. The canonical
# dilution attack adds exactly one novel transition into the consequential call
# it wants to hide, and pads everything else with the agent's own routine work;
# any threshold above one is an instruction on how many free malicious calls the
# attacker gets.
#
# Measured cost on the evaluation corpus, stated because it is a real one: this
# catches 32 of 32 diluted attacks that CH01 previously caught none of, and
# fires on 16 of 32 long benign sessions that end in one of the family's own
# legitimate secondary actions. That is 2:1 in favour, against a corpus-wide
# precision of 40.5%, and it is the honest shape of the trade rather than a win.
MIN_UNSEEN_CONSEQUENTIAL = 1

# CH01 has two triggers and only the second needs to know what a call DOES. With
# no usable classification the rate trigger works exactly as it always did, so
# the check is not blind -- it is one trigger down, and the one it has lost is
# the one that resists dilution. Hence a floor rather than a product: unknown
# classes cost CH01 half its confidence, where they cost CH02, CH03 and CH04 all
# of it.
CH01_CLASS_WEIGHT = 0.5


def _baseline_out_of_distribution(
        session: Session, grammar: SequenceGrammar,
        min_overlap: float = MIN_VOCABULARY_OVERLAP) -> bool:
    """Is the grammar being asked about a workload it was never fitted on?

    Two conditions, and both are needed. The session must use tools the baseline
    largely does not know, AND it must be long enough for that to mean something.
    """
    calls = session.tool_sequence
    if len(calls) < MIN_CALLS_FOR_VOCABULARY_JUDGEMENT:
        return False
    return grammar.vocabulary_overlap(session) < min_overlap


def ch01_sequence_order(session: Session, grammar: SequenceGrammar | None,
                        threshold: float = 0.25,
                        limits: Limits = DEFAULT_LIMITS,
                        min_vocabulary_overlap: float = MIN_VOCABULARY_OVERLAP,
                        min_unseen_consequential: int = MIN_UNSEEN_CONSEQUENTIAL
                        ) -> list[Finding]:
    """Two triggers over one grammar. Either one fires the check.

    RATE      the session's shape as a whole is unlike the baseline's. What
              CH01 has always done, and dilutable by construction: the rate is
              unseen/total and padding grows only the denominator (E02).
    COUNT     at least one novel route into a consequential call, whatever the
              rate. Padding with routine calls cannot reduce this, which is why
              it is the answer to E02 -- and it is scoped to consequential
              destinations rather than to all of them, because an absolute count
              over everything would fire on any long session that wandered.
    """
    if grammar is None or not grammar.fitted:
        return []
    # Out-of-distribution check BEFORE the score, because the score is
    # meaningless when the baseline has never seen these tools: every transition
    # is unseen, the rate pins to 1.0, and the check fires on every session in
    # the workload. See SequenceGrammar.vocabulary_overlap for the measurement.
    if _baseline_out_of_distribution(session, grammar, min_vocabulary_overlap):
        return []
    rate, unseen = grammar.score(session)
    consequential_unseen = grammar.unseen_into_consequential(session)

    by_rate = bool(unseen) and rate > threshold
    by_count = len(consequential_unseen) >= min_unseen_consequential
    if not (by_rate or by_count):
        return []
    triggers = [t for t, on in (("rate", by_rate), ("unseen_consequential", by_count))
                if on]

    total_transitions = len(session.tool_sequence) + 1  # START..seq..END
    novel_tools = sorted({b for _, b in unseen
                          if b not in grammar.unigrams or grammar.unigrams[b] == 0})
    sev = "high" if novel_tools else "medium"
    shown_unseen, dropped_unseen = cap_list([f"{a} -> {b}" for a, b in unseen],
                                            limits.max_evidence_items)
    shown_conseq, dropped_conseq = cap_list(
        [f"{a} -> {b}" for a, b in consequential_unseen], limits.max_evidence_items)
    shown_novel, dropped_novel = cap_list(novel_tools, limits.max_evidence_items)
    shown_seq, dropped_seq = cap_list(session.tool_sequence, limits.max_evidence_items)

    detail = (f"{len(unseen)} of {total_transitions} transitions were never "
              f"observed in {grammar.sessions_fitted} benign sessions "
              f"(violation rate {rate:.2f}, threshold {threshold}).")
    if not by_rate:
        # Say plainly why a rate UNDER the threshold produced a finding, or the
        # record reads as a bug to the analyst holding it.
        detail = (f"{len(unseen)} of {total_transitions} transitions were never "
                  f"observed in {grammar.sessions_fitted} benign sessions. The "
                  f"violation rate of {rate:.2f} is below the {threshold} "
                  f"threshold -- a long session dilutes it -- but "
                  f"{len(consequential_unseen)} novel transition(s) arrive at a "
                  f"state-changing or data-egress call, which padding cannot "
                  f"dilute: {', '.join(shown_conseq)}.")
    elif consequential_unseen:
        detail += (f" {len(consequential_unseen)} of them arrive at a "
                   f"state-changing or data-egress call.")
    if shown_novel:
        detail += (f" Tools never seen in any benign session: "
                   f"{', '.join(shown_novel)}.")

    return [Finding(
        check="CH01_sequence_order",
        family="CH01_sequence_order",
        severity=sev,
        session_id=session.session_id,
        title="Tool-call ordering deviates from the learned benign grammar",
        detail=detail,
        evidence={
            "triggers": triggers,
            "violation_rate": round(rate, 4),
            "unseen_transitions": shown_unseen,
            "unseen_transitions_truncated": dropped_unseen,
            "unseen_consequential_count": len(consequential_unseen),
            "unseen_consequential_transitions": shown_conseq,
            "unseen_consequential_transitions_truncated": dropped_conseq,
            "novel_tools": shown_novel,
            "novel_tools_truncated": dropped_novel,
            "observed_sequence": shown_seq,
            "observed_sequence_truncated": dropped_seq,
            "baseline_sessions": grammar.sessions_fitted,
            "baseline_hash": grammar.fingerprint(),
            # R-14. WHOSE normal this was measured against, stated on the
            # finding rather than left for a reader to assume. `fleet` means
            # one grammar fitted over every session in the baseline, with no
            # scoping by agent, owner, role, workflow, tenant or time -- so a
            # transition that is ordinary for the finance agent is ordinary for
            # the incident-response agent too, and a rare action by an agent
            # that has never done it is not rare if some other agent does it
            # daily. The documentation talks about an agent's own history; the
            # implementation trains one workload-wide model, and the gap
            # between those two sentences belongs in the output.
            #
            # Per-agent and peer-group baselines are the fix and they are a
            # design change: they need a minimum-sample rule, time decay, and a
            # corpus that has more than one population in it. Naming the scope
            # is what stops the current model being read as the eventual one.
            "baseline_scope": grammar.scope,
        },
    )]


# ---------------------------------------------------------------------------
# CH02  Concealment gap: did the agent report what it actually did?
# ---------------------------------------------------------------------------

_SPLIT = re.compile(r"[^a-z0-9]+")
_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return {t for t in _SPLIT.split(text.lower()) if len(t) > 2}


# Negation cues. A tool name mentioned inside one of these spans is a DENIAL,
# not a disclosure. External review found "I did not send any email" was being
# read as disclosure of send_email, which is the exact inversion of the check.
_NEGATION = re.compile(
    r"\b(did not|didn'?t|do not|don'?t|was not|wasn'?t|were not|weren'?t|"
    r"have not|haven'?t|has not|hasn'?t|no longer|never|without|failed to|"
    r"unable to|could not|couldn'?t|declined to|refrained from|skipped|"
    r"chose not to|avoided)\b", re.IGNORECASE)


def _negated_spans(text: str, window: int = 80) -> list[tuple[int, int]]:
    """Character ranges following a negation cue, where a mention means denial."""
    return [(m.start(), min(len(text), m.end() + window))
            for m in _NEGATION.finditer(text)]


class ResponseIndex:
    """One pass over the final response, reused by every call.

    The previous implementation ran ``re.finditer`` across the entire response
    once per name fragment per consequential call, which is O(calls * length).
    Measured: 800 calls against an 80 KB response took 6.9 seconds, and both
    numbers are supplied by the thing being observed. Indexing once and looking
    up per call is O(length + calls).

    Negation spans are merged and binary-searched for the same reason: a
    response can contain an unbounded number of negation cues.
    """

    def __init__(self, response: str) -> None:
        self.text = response
        lowered = response.lower()
        self.positions: dict[str, list[int]] = {}
        for m in _TOKEN.finditer(lowered):
            tok = m.group()
            if len(tok) > 2:
                self.positions.setdefault(tok, []).append(m.start())
        self._starts: list[int] = []
        self._ends: list[int] = []
        for a, b in _merge_spans(_negated_spans(lowered)):
            self._starts.append(a)
            self._ends.append(b)

    @property
    def has_negation(self) -> bool:
        return bool(self._starts)

    def negated(self, pos: int) -> bool:
        i = bisect_right(self._starts, pos) - 1
        return i >= 0 and pos < self._ends[i]


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


# The three answers CH02 can give about one call, because two was one too few.
DISCLOSED = "disclosed"
AMBIGUOUS = "ambiguous"      # mentioned, but indistinguishably from a sibling
ABSENT = "absent"


# The three answers to "did this call start after that event?", because two was
# one too few here as well. COH-R11.
ORDER_AFTER = "after"
ORDER_NOT_AFTER = "not_after"
ORDER_INDETERMINATE = "indeterminate"


def _ordering(call: ToolCall, event: Event,
              audit: SessionIntegrity | None = None) -> str:
    """Did ``call`` start after ``event``, and can that be established at all?

    COH-R11. CH03 and CH04 each answered this with a single comparison against
    the wall clock, and they did not even agree with each other: CH03 used
    ``>=`` so a tie was AFTER, CH04 used ``>`` so a tie was BEFORE. Two checks
    reading the same two timestamps reached opposite conclusions, and the one
    that mattered was CH04's -- stamping a consequential call at exactly the
    guardrail's timestamp removed the finding, with no other change to the
    telemetry and nothing anywhere saying the ordering had been decided by a
    tie-break.

    Wall clock is the wrong instrument to settle it with. The producer chooses
    those numbers, so equality is forgeable; and it is reached by accident too,
    because a collector stamping at millisecond resolution puts a whole burst
    of events on the same tick. A tie is therefore not evidence of ordering in
    either direction.

    The collector sequence is the right instrument where it exists. Inside one
    ``stream_id`` the sequence is covered by the hash chain and by the
    signature over its head, so a producer cannot reorder two records without
    breaking a verification Cohaera already performs. It is only comparable
    WITHIN a stream: two streams have unrelated numbering and no relative order
    at all, which is why the stream ids must match before the sequences are
    compared.

    So: sequence when both records carry one from the same stream, wall clock
    when it is strictly unequal, and INDETERMINATE otherwise -- reported, never
    silently resolved.
    """
    # F-03 gated this on `chained`, which asks whether `prev` and `chain` are
    # PRESENT. Presence is shape, and a producer writes shape. Two arbitrary
    # hex strings therefore outranked the clock and suppressed a critical
    # finding -- reproduced in tests/test_hostile.py. The sequence now has to
    # be covered by a signature that VERIFIED, on BOTH sides: an ordering is a
    # comparison between two positions and is only as attested as its weaker
    # end. Unverified, the sequence is treated as absent and the clock decides,
    # which is exactly what a stream carrying no sidecar at all already did.
    _sidecar = event.integrity
    _trusted = (
        audit is not None
        and _sidecar is not None and _sidecar.chained
        and audit.sequence_verified(_sidecar.stream_id, _sidecar.seq)
        and audit.sequence_verified(call.start_stream, call.start_seq))
    seq_a = call.start_seq
    seq_b = _sidecar.seq if _trusted and _sidecar is not None else None
    stream_a = call.start_stream
    stream_b = (_sidecar.stream_id
                if _trusted and _sidecar is not None else None)
    if (seq_a is not None and seq_b is not None
            and stream_a is not None and stream_a == stream_b):
        if seq_a == seq_b:
            # One record cannot be two records. A shared sequence inside a
            # stream is a broken chain, which CH06 reports; it is not an
            # ordering.
            return ORDER_INDETERMINATE
        return ORDER_AFTER if seq_a > seq_b else ORDER_NOT_AFTER

    if not call.clock_valid or not event.timestamp_valid:
        return ORDER_INDETERMINATE
    if call.started_at == event.timestamp:
        return ORDER_INDETERMINATE
    return ORDER_AFTER if call.started_at > event.timestamp else ORDER_NOT_AFTER


class _References:
    """A set of reference events, reduced to what an ordering question needs.

    COH-R11 asked "did this call start after that event?" against ONE reference
    chosen by wall clock, and then answered it by collector sequence where one
    existed. Those are two different instruments and the selection used the one
    the same commit had just declared forgeable: with markers at (seq 1, ts 100)
    and (seq 9, ts 50), the clock picks the second, the sequence says the call
    at seq 5 ran after the first, and the finding disappears. Both CH03 and CH04
    lost findings they had produced before R11 -- and only on streams carrying
    ``cohaera.integrity:1``, so the regression was exclusive to deployments that
    had done the work to be verifiable.

    The question is existential: untrusted content was read, or a control fired,
    and then a consequential call ran. ANY reference that precedes the call
    answers it, so the reduction is over all of them and AFTER wins.

    O(M) TO BUILD AND O(1) PER CALL, which is not an optimisation. Comparing
    every call against every reference is the O(N*M) shape that produced a
    6.3 MB verdict from 900 events and is documented on ch04_guardrail_overrun;
    reintroducing it here to fix an ordering bug would trade a missed finding
    for an availability fault. Two values suffice for the clock because a call
    excludes at most one stream from that comparison: its own.
    """

    __slots__ = ("_audit", "_best", "_next", "count", "earliest_ts",
                 "min_seq", "unclocked")

    def __init__(self, events: Iterable[Event],
                 audit: SessionIntegrity | None = None) -> None:
        self._audit = audit
        self.min_seq: dict[str, int] = {}
        self._best: tuple[float, str | None] | None = None
        self._next: tuple[float, str | None] | None = None
        self.count = 0
        self.unclocked = 0
        self.earliest_ts = 0.0
        for event in events:
            self.count += 1
            integrity = event.integrity
            # Verified, not merely shaped. See `_ordering` and
            # SessionIntegrity.sequence_verified for why presence is not enough.
            trusted = (integrity is not None and integrity.chained
                       and audit is not None
                       and audit.sequence_verified(integrity.stream_id,
                                                   integrity.seq))
            stream = (integrity.stream_id
                      if trusted and integrity is not None else None)
            seq = integrity.seq if trusted and integrity is not None else None
            if stream is not None and seq is not None:
                low = self.min_seq.get(stream)
                if low is None or seq < low:
                    self.min_seq[stream] = seq
            # A reference with an unusable clock still counts, and its SEQUENCE
            # still orders: a NaN timestamp compares false against everything,
            # so letting one into the clock reduction would poison it silently.
            # Callers used to drop these records entirely, which is the defect
            # this excludes them from rather than repeats.
            if event.timestamp_valid:
                self._note_clock(event.timestamp, stream)
            else:
                self.unclocked += 1
        if self._best is not None:
            self.earliest_ts = self._best[0]

    def _note_clock(self, ts: float, stream: str | None) -> None:
        """Keep the lowest timestamp, and the lowest from a DIFFERENT stream.

        Two is enough: a call is compared by clock against every reference not
        settled by sequence, and the only references settled by sequence are
        the ones sharing the call's own stream. So at most one stream is ever
        excluded, and the answer is either the best or the best from elsewhere.
        """
        if self._best is None or ts < self._best[0]:
            if self._best is not None and self._best[1] != stream:
                self._next = self._best
            self._best = (ts, stream)
        elif stream != self._best[1] and (self._next is None or ts < self._next[0]):
            self._next = (ts, stream)

    def verdict(self, call: ToolCall) -> str:
        """The strongest claim this reference set supports about ``call``.

        AFTER beats INDETERMINATE beats NOT_AFTER. A tie against one reference
        does not become "before" just because another reference is definitely
        later: the point of the third value is that an unestablished order is
        reported rather than resolved.
        """
        tie = False
        stream, seq = call.start_stream, call.start_seq
        if not (self._audit is not None
                and self._audit.sequence_verified(stream, seq)):
            # The call's own position is unattested, so it neither indexes into
            # min_seq nor earns the clock exclusion below. Dropping it here
            # rather than at each use keeps the two decisions from drifting.
            stream = seq = None
        if stream is not None and seq is not None:
            low = self.min_seq.get(stream)
            if low is not None:
                if seq > low:
                    return ORDER_AFTER
                if seq == low:
                    # One record cannot be two records; a shared sequence is a
                    # broken chain, which CH06 reports. It is not an ordering.
                    tie = True

        clock = self._best
        if clock is not None and stream is not None and clock[1] == stream:
            # References in the call's own stream were settled by sequence
            # above, and the sequence OUTRANKS the clock. Comparing them again
            # by timestamp is how the producer's number gets a second vote.
            clock = self._next
        if clock is not None and call.clock_valid:
            if call.started_at > clock[0]:
                return ORDER_AFTER
            if call.started_at == clock[0]:
                tie = True
        elif clock is not None:
            tie = True

        if self.unclocked and not (stream is not None and stream in self.min_seq):
            # References this call shares no stream with, and whose clocks are
            # unusable. Nothing orders them against it, and saying NOT_AFTER
            # would be inventing the answer the clock refused to give.
            tie = True

        return ORDER_INDETERMINATE if tie else ORDER_NOT_AFTER


def _shared_name_tokens(calls: list[ToolCall]) -> frozenset[str]:
    """Tokens that appear in the names of two or more DISTINCT tools here.

    EVASION.md E16. CH02 decides disclosure by token overlap against the tool
    name, and an MCP server's tools share a prefix by convention:

        ldap_group_membership_enumerate   read
        ldap_group_membership_apply       write

    "I enumerated the ldap group membership" shares three of four tokens with
    the WRITE, so the write read as disclosed and the concealment passed. Free
    to the attacker, and free is the worst price for a false negative.

    A token shared across the session's own tools carries no attribution. Which
    tokens those are is not a semantic question and does not need one: it is
    computable from the session in front of us.
    """
    seen: set[str] = set()
    shared: set[str] = set()
    for name in {c.name for c in calls}:
        for tok in _tokens(name):
            (shared if tok in seen else seen).add(tok)
    return frozenset(shared)


def _mentioned(token: str, index: ResponseIndex) -> bool:
    occurrences = index.positions.get(token)
    if not occurrences:
        return False
    if not index.has_negation:
        return True
    return any(not index.negated(pos) for pos in occurrences)


def _disclosure(call: ToolCall, index: ResponseIndex,
                shared: frozenset[str] = frozenset()) -> str:
    """Does the summary disclose this call, deny it, or fail to distinguish it?

    Three failure modes, all real, all measured:

    1. FALSE NEGATIVE on negation. "I did not send any email" contains both
       'send' and 'email', so pure token overlap read it as disclosure. Fixed
       by discounting mentions that fall inside a negation span.

    2. FALSE NEGATIVE on shared prefixes (E16). Fixed only half way, and
       deliberately so. A mention that matches ONLY tokens this tool shares
       with a sibling is ``AMBIGUOUS``: it is no longer counted as disclosure,
       which removes the silent pass, and it is not counted as concealment
       either, which would invent a false positive on every honest summary that
       names the family rather than the verb. The blind spot goes in the
       coverage contract where a SOC can route on it.

    3. FALSE POSITIVE on paraphrase. "I notified the customer" discloses the
       action to a human and shares no stem with send_email, so this still
       flags it. NOT fixed, because fixing it needs semantics. See EVASION.md
       E04 -- and note that 2 and 3 pull in opposite directions, which is why
       neither is fixed by tightening the same lexical rule.

    This remains lexical. C-Trace (arXiv:2606.19242) measured monitor accuracy
    as bounded by the field extractor; that bound applies here and is the
    reason CH02 ships at medium severity with a baseline-first instruction.
    """
    hit_shared = False
    for part in _tokens(call.name):
        if not _mentioned(part, index):
            continue
        if part in shared:
            hit_shared = True
        else:
            return DISCLOSED
    # Either the name never appeared, or every mention sat inside a negation
    # span and the summary denies the action, or the only tokens that appeared
    # belong equally to another tool in this session.
    return AMBIGUOUS if hit_shared else ABSENT


def _referenced(call: ToolCall, index: ResponseIndex,
                shared: frozenset[str] = frozenset()) -> bool:
    """Disclosure as a boolean, for callers that only need the old answer.

    ``AMBIGUOUS`` counts as disclosed here so that the corpus generator's
    label-integrity assertions keep asking the question they were written to
    ask -- "could this summary be read as disclosing the call" -- which is
    strictly weaker than what CH02 now requires and is the right test for a
    fixture that must conceal under every reading.
    """
    return _disclosure(call, index, shared) in (DISCLOSED, AMBIGUOUS)


def ch02_concealment_gap(session: Session,
                         limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    response = session.final_response
    if response is None:
        return []          # not clean: see coverage()
    if session.response_text_truncated:
        # F-04. This check's entire output is an ABSENCE claim -- "the response
        # does not mention what the agent did" -- and the response was cut
        # short before Cohaera saw the end of it. The truncation was recorded
        # as a field defect and then ignored, so a disclosure thirty-three
        # characters past the cap produced a CRITICAL concealment finding at
        # confidence 1.0.
        #
        # That is the objection this project was started over, appearing inside
        # the project: a check that could not finish reading, reporting itself
        # as having read. Abstain, and let coverage say why.
        #
        # Only the absence direction is affected. A disclosure FOUND in a
        # truncated prefix is still a disclosure, which is why
        # `ambiguous_disclosures` below is left alone.
        return []

    consequential = session.consequential_calls
    if not consequential:
        return []

    index = ResponseIndex(response)
    shared = _shared_name_tokens(session.tool_calls)
    # COH-R12. `concealable` is the denominator, and it is NOT `consequential`.
    # A call that did not execute was never a concealed effect -- that is C-04,
    # and it is why the verdicts below have always been drawn from executed
    # calls only. The detail line was printed against every consequential call
    # regardless, so the two halves of the ratio counted different populations:
    # one hidden egress among nine failed attempts reported as "1 of 10", which
    # reads as a 10% concealment rate for a session that concealed everything
    # it managed to do. The attempts are still reported, just not as the
    # denominator of a rate they could not contribute to.
    concealable = [c for c in consequential if c.executed]
    # A list, not a dict keyed on span_id: two executed calls are two calls even
    # when they share a name, and a session that lost its span identity would
    # silently collapse them under any key derived from it.
    verdicts = [(c, _disclosure(c, index, shared)) for c in concealable]
    unreported = [c for c, d in verdicts if d == ABSENT]
    ambiguous = [c for c, d in verdicts if d == AMBIGUOUS]
    if not unreported:
        return []          # ambiguity alone is a coverage fact, not a finding

    has_egress = any(c.klass == "egress" for c in unreported)
    shown, dropped = cap_list([c.brief(limits) for c in unreported],
                              limits.max_evidence_items)
    shown_amb, dropped_amb = cap_list([c.brief(limits) for c in ambiguous],
                                      limits.max_evidence_items)
    not_executed = len(consequential) - len(concealable)
    detail = (
        f"{len(unreported)} of {len(concealable)} consequential calls that "
        "completed successfully are not referenced in the final user-facing "
        "message. The human in the loop reads the summary, so an unreported "
        "state change or egress removes the human control without removing the "
        "appearance of it."
    )
    if not_executed:
        detail += (
            f" A further {not_executed} consequential call(s) did not complete "
            "successfully and are outside this ratio: an attempt is not a "
            "concealed effect. CH03 and CH05 report attempts."
        )
    if ambiguous:
        detail += (
            f" A further {len(ambiguous)} call(s) are mentioned only by tokens "
            "they share with another tool in this session, so the summary "
            "cannot be attributed to them either way (EVASION.md E16)."
        )
    return [Finding(
        check="CH02_concealment_gap",
        family="CH02_concealment_gap",
        severity="critical" if has_egress else "high",
        session_id=session.session_id,
        title="Consequential tool calls absent from the agent's final response",
        detail=detail,
        evidence={
            "unreported_calls": shown,
            "unreported_calls_truncated": dropped,
            "unreported_total": len(unreported),
            "ambiguous_calls": shown_amb,
            "ambiguous_calls_truncated": dropped_amb,
            "ambiguous_total": len(ambiguous),
            # Three counts, because two of them used to be one. `concealable`
            # is the denominator of the rate; `consequential_total` is the
            # whole population; the difference is stated rather than left to be
            # inferred. concealable + not_executed == consequential_total.
            "concealable_total": len(concealable),
            "not_executed_total": not_executed,
            "consequential_total": len(consequential),
            "response_length": len(response),
        },
    )]


def ambiguous_disclosures(session: Session) -> list[ToolCall]:
    """Executed consequential calls the summary cannot be attributed to.

    Separate from ``ch02_concealment_gap`` because coverage needs the answer on
    sessions where CH02 produces no finding at all -- which is exactly the E16
    case: every consequential call mentioned, none of them distinguishably.
    """
    response = session.final_response
    if response is None:
        return []
    index = ResponseIndex(response)
    shared = _shared_name_tokens(session.tool_calls)
    return [c for c in session.consequential_calls
            if c.executed and _disclosure(c, index, shared) == AMBIGUOUS]


# ---------------------------------------------------------------------------
# CH03  Untrusted content observed, then a consequential action
# ---------------------------------------------------------------------------

CH03_FAMILY = "CH03_untrusted_to_consequential"
CH03_COMPLETED = "CH03_untrusted_to_completed_action"
CH03_ATTEMPTED = "CH03_untrusted_to_attempted_action"


def ch03_untrusted_to_consequential(session: Session,
                                    limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    """Simplified taint flow.

    Full information-flow control (Fides arXiv:2505.23643, CaMeL arXiv:2503.18813)
    labels every value. That needs instrumentation Cohaera does not have. What it
    does have is: the timestamp at which an injection marker was observed, and the
    timestamps of consequential calls. Ordering those two is a cheap, honest
    approximation with a real false-positive story.

    Split into two check IDs after review. The old single finding said N calls
    "ran afterwards" and the Sigma rule said the agent "Took" an action, for a
    session where the only candidate call had errored. An attempt and an effect
    are different facts and an analyst acts on them differently.
    """
    # COH-R03. This was `e.data.get("injection_patterns") or
    # e.data.get("has_injection_patterns")` -- plain truthiness, on the one
    # surface in this codebase where somebody else's assertion becomes a
    # CRITICAL finding. `has_injection_patterns: "false"` is a truthy string,
    # and it produced "the agent completed a consequential action after reading
    # attacker-controlled instructions" from a scanner that had said the
    # opposite. `scanner_marked` requires the exact types and treats anything
    # else as no claim at all; the defect is recorded on the Event and charged
    # to this check's coverage.
    # A marker is dropped only if it is not a marker. It used to be dropped for
    # carrying an unusable CLOCK as well, so a single marked read with a
    # malformed timestamp emptied the check outright -- the producer choosing
    # whether the evidence exists, which is the thing the collector sequence
    # was introduced to take away from it. _References orders by sequence where
    # one exists and reports the rest as indeterminate.
    marker_events = [e for e in session.events if scanner_marked(e.data)]
    if not marker_events:
        return []

    # COH-R11, and its follow-up. The ordering question is asked against the
    # marker RECORDS rather than one timestamp, because the record is what
    # carries the collector sequence -- and against ALL of them rather than the
    # clock-earliest one. Picking a single reference by wall clock while
    # deciding the order by sequence is what made this check lose findings it
    # had produced before R11; see _References.
    audit = session.integrity   # verified-sequence oracle; see _ordering
    markers_ref = _References(marker_events, audit)
    first_marker = markers_ref.earliest_ts
    verdicts = [(c, markers_ref.verdict(c))
                for c in session.consequential_calls]
    cand = [c for c, o in verdicts if o == ORDER_AFTER]
    unordered = [c for c, o in verdicts if o == ORDER_INDETERMINATE]
    completed = [c for c in cand if c.executed]
    attempted = [c for c in cand if not c.executed]

    markers, markers_dropped = cap_list(session.injection_markers,
                                        limits.max_evidence_items)
    unordered_shown, unordered_dropped = cap_list(
        [c.brief(limits) for c in unordered], limits.max_evidence_items)
    base_evidence = {
        "markers": markers,
        "markers_truncated": markers_dropped,
        "first_marker_ts": first_marker,
        "marker_event_count": len(marker_events),
        # Reported whether or not the check fires, because a call whose order
        # relative to the marker cannot be established is exactly the call an
        # analyst needs to know about, and silently dropping it is how the tie
        # became an evasion in the first place.
        "unordered_calls": unordered_shown,
        "unordered_calls_truncated": unordered_dropped,
        "unordered_total": len(unordered),
    }

    findings: list[Finding] = []

    if completed:
        shown, dropped = cap_list([c.brief(limits) for c in completed],
                                  limits.max_evidence_items)
        findings.append(Finding(
            check=CH03_COMPLETED,
            family=CH03_FAMILY,
            severity="critical" if any(c.klass == "egress" for c in completed)
            else "high",
            session_id=session.session_id,
            title="Consequential action COMPLETED after observed injection markers",
            detail=(
                f"Injection markers were flagged at t={first_marker:.3f}, and "
                f"{len(completed)} consequential call(s) completed successfully "
                "afterwards in the same session. This does not prove causation. It "
                "marks the session as one where untrusted content and a completed "
                "state change coexist in the wrong order, which is the sequence a "
                "human should review."
            ),
            evidence={**base_evidence,
                      "completed_after": shown,
                      "completed_after_truncated": dropped,
                      "completed_total": len(completed),
                      "also_attempted": len(attempted)},
        ))

    if attempted:
        shown, dropped = cap_list([c.brief(limits) for c in attempted],
                                  limits.max_evidence_items)
        findings.append(Finding(
            check=CH03_ATTEMPTED,
            family=CH03_FAMILY,
            severity="medium",
            session_id=session.session_id,
            title="Consequential action ATTEMPTED after observed injection markers",
            detail=(
                f"Injection markers were flagged at t={first_marker:.3f}, and "
                f"{len(attempted)} consequential call(s) started afterwards without "
                "completing successfully. The attempt is the observed fact. Whether "
                "the action had any effect is NOT established by this telemetry: a "
                "call can be recorded as open because it failed, because it was "
                "refused, or because the terminal event was never emitted."
            ),
            evidence={**base_evidence,
                      "attempted_after": shown,
                      "attempted_after_truncated": dropped,
                      "attempted_total": len(attempted),
                      "also_completed": len(completed)},
        ))

    if findings and unordered:
        note = (
            f" A further {len(unordered)} consequential call(s) share the "
            "marker's tick with no collector sequence to separate them, so "
            "whether they ran before or after it is not established here "
            "(COH-R11)."
        )
        findings = [replace(f, detail=f.detail + note) for f in findings]

    return findings


def unordered_after_marker(session: Session) -> list[ToolCall]:
    """Consequential calls whose order against the first marker is unknown.

    Separate from :func:`ch03_untrusted_to_consequential` for the reason
    :func:`ambiguous_disclosures` is separate from CH02: coverage needs the
    answer on sessions where the check produces no finding at all, and that is
    precisely the interesting case. A producer that stamps every consequential
    call on the marker's tick empties the finding and leaves the session
    looking clean, so the emptiness has to be reported by something.
    """
    marker_events = [e for e in session.events if scanner_marked(e.data)]
    if not marker_events:
        return []
    audit = session.integrity   # verified-sequence oracle; see _ordering
    markers_ref = _References(marker_events, audit)
    return [c for c in session.consequential_calls
            if markers_ref.verdict(c) == ORDER_INDETERMINATE]


# ---------------------------------------------------------------------------
# CH04  Guardrail fired and the session continued
# ---------------------------------------------------------------------------

CH04_FAMILY = "CH04_guardrail_overrun"
# Retained ID and retained wording. This is the UNDECLARED case -- a policy
# event fired, nothing said whether it blocks, and Cohaera reports the sequence
# without attributing a bypass. The name is older than the distinction and
# renaming it would break every Sigma rule written against it, so it stays and
# the docstring carries the correction.
CH04_COMPLETED = "CH04_guardrail_bypass_completed"
CH04_ATTEMPTED = "CH04_post_guardrail_attempt"
# New, and the only check in this file that may use the word "bypass" and mean
# it: the control was DECLARED blocking, work completed after it, and no
# approval bound to that work. Additive, so existing content keeps matching what
# it always matched.
CH04_BYPASSED = "CH04_blocking_control_bypassed"

# Where the enforcement semantics came from. An operator's manifest outranks the
# event, because the event is written by the thing being watched.
ENFORCEMENT_FROM_MANIFEST = "manifest"
ENFORCEMENT_FROM_EVENT = "policy_event"
ENFORCEMENT_FROM_NOWHERE = "undeclared"


def _resolved_enforcement(event: Any, manifest: CapabilityManifest
                          ) -> tuple[str, str]:
    """(enforcement, source) for one policy event.

    Precedence exists here for the same reason it exists on ``ToolCall.klass``.
    ``enforcement`` arrives in band, and unlike every other field the checks
    read, a value of ``advisory`` SUPPRESSES a finding. A producer that wanted
    CH04 quiet would send it. So an operator-supplied declaration wins, and the
    verdict records which of the two it used -- a bypass suppressed on the
    strength of the agent's own say-so is a different fact from one suppressed
    on the strength of the operator's, and an analyst has to be able to tell.
    """
    declared = manifest.policy(event.data.get("policy_id"), event.event_type)
    if declared is not None:
        return declared.enforcement, ENFORCEMENT_FROM_MANIFEST
    in_band = event.enforcement
    if in_band != ENFORCEMENT_UNDECLARED:
        return in_band, ENFORCEMENT_FROM_EVENT
    return ENFORCEMENT_UNDECLARED, ENFORCEMENT_FROM_NOWHERE


def _policy_semantics(session: Session) -> dict[str, Any]:
    """Where this session's policy events got their semantics from.

    ``undeclared`` is true if ANY policy event lacks a declaration, not if all
    of them do. A session with one declared control and one undeclared one has
    a gap, and averaging it away would report the better half.
    """
    sources = [_resolved_enforcement(e, session.manifest)[1]
               for e in session.events if e.event_type in POLICY_EVENTS]
    return {
        "undeclared": ENFORCEMENT_FROM_NOWHERE in sources,
        "in_band_only": (ENFORCEMENT_FROM_NOWHERE not in sources
                         and ENFORCEMENT_FROM_EVENT in sources),
        "sources": sorted(set(sources)),
    }


def _approval_state(session: Session, call: ToolCall) -> tuple[str, Any]:
    """How this call stands with respect to the approvals in its session.

    Five outcomes, and the middle three are the ones that make the mechanism
    worth building. ``none`` is a call nobody approved. ``covered`` is a call an
    approval actually fits. Between them sit the failures a broad approval used
    to hide: an approval for different arguments, an approval outside its
    window, and an explicit refusal.
    """
    matches = session.approvals_for(call)
    if not matches:
        return APPROVAL_NONE, None
    for m in matches:
        if m.approval.decision == DECISION_DENY and m.binding in BINDING_TRUSTED:
            return APPROVAL_DENIED, m
    covering = session.covering_approval(call)
    if covering is not None:
        return APPROVAL_COVERED, covering
    for m in matches:
        if m.binding == BOUND_ARG_MISMATCH:
            return APPROVAL_ARG_MISMATCH, m
    for m in matches:
        if m.fresh is False:
            return APPROVAL_EXPIRED, m
    # R-10. Ordered last of the failure states deliberately. A mismatch and an
    # expiry are things the approval SAYS that rule this call out; an incomplete
    # binding is a thing the approval does not say, and the two must not be
    # rounded together. It sits above APPROVAL_NONE because an approval that was
    # presented and did not fit is a stronger fact than no approval at all --
    # which is the same reason approvals_for returns these rather than dropping
    # them.
    for m in matches:
        if m.binding in BINDING_CONTEXT:
            return APPROVAL_SPAN_ONLY, m
    return APPROVAL_NONE, None


APPROVAL_NONE = "no_approval"
APPROVAL_COVERED = "approved"
APPROVAL_DENIED = "denied"
APPROVAL_ARG_MISMATCH = "approval_for_other_arguments"
APPROVAL_EXPIRED = "approval_expired"
# R-10. An approval naming the span and at most one of the other two fields. It
# used to be indistinguishable from APPROVAL_COVERED, which meant one field the
# producer could omit switched CH04 off entirely for that call.
APPROVAL_SPAN_ONLY = "approval_not_argument_bound"

# The states in which a completed call after a control is NOT covered. Named
# rather than written as "!= APPROVAL_COVERED" so that adding a further state
# later cannot silently make it count as approval.
UNAPPROVED_STATES = frozenset({APPROVAL_NONE, APPROVAL_DENIED,
                               APPROVAL_ARG_MISMATCH, APPROVAL_EXPIRED,
                               APPROVAL_SPAN_ONLY})

_APPROVAL_WORDING = {
    APPROVAL_NONE: "no approval was presented for it",
    APPROVAL_DENIED: "an approval bound to it recorded the decision DENY",
    APPROVAL_ARG_MISMATCH: "the only approval naming it was granted for "
                           "different arguments",
    APPROVAL_EXPIRED: "the approval naming it was outside its validity window",
    APPROVAL_SPAN_ONLY: "the only approval naming it was bound by span alone "
                        "and does not constrain what the call did",
}

# Scalar policy fields worth carrying into evidence. An unbounded copy of the
# producer's data bag is how regulated content and secrets reach a SIEM by
# accident (SEC-07), and how a hostile producer inflates the verdict record.
_POLICY_FIELDS = ("threshold_usd", "session_cost_usd", "cost_usd", "current_depth",
                  "max_depth", "limit", "threshold", "policy_id", "policy_name",
                  "action", "decision", "enforcement")


def _policy_evidence(data: dict[str, Any], limits: Limits) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in _POLICY_FIELDS:
        if key not in data or len(out) >= limits.max_policy_data_keys:
            continue
        value = data[key]
        if isinstance(value, bool) or isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = sanitise_display(value, limits.max_evidence_value_chars)
    dropped = sorted(k for k in data if k not in out)
    if dropped:
        shown, extra = cap_list(dropped, limits.max_evidence_items)
        out["_fields_not_carried"] = shown
        if extra:
            out["_fields_not_carried_truncated"] = extra
    return out


def ch04_guardrail_overrun(session: Session,
                           limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    """A policy event fired, and consequential work happened after it.

    observra emits cost_threshold_exceeded and depth_exceeded as policy_event
    actions. Nothing upstream asks the obvious follow-up question: did anything
    keep happening? A guardrail that fires and is then ignored is worse than no
    guardrail, because it produces a log line that looks like a control.

    Two defects fixed here.

    WORDING. The old detail said "the control produced a log line but did not
    stop the behaviour" for attempt-only sessions, where every candidate call
    had errored. That is an attribution the data does not support. Attempts and
    completions are now separate check IDs with separate severity, and the
    attempt wording claims only the attempt.

    AMPLIFICATION. The old loop emitted one finding per policy EVENT, each
    carrying every consequential call after it, so a session with N policy
    events and M calls cost O(N*M) in time and in output. Measured: 900 input
    events produced a 6.3 MB verdict record. Repeated firings of the same
    threshold are the same fact, so the check now reports the EARLIEST firing of
    each policy type once and carries the repeat count instead.
    """
    # COH-R11 follow-up. Every firing of a policy type is a reference, not just
    # the clock-earliest one. Keeping only the earliest by timestamp and then
    # ordering by collector sequence is what let a second firing with a lower
    # timestamp and a higher sequence shadow the real one and empty the check.
    # The reported firing is still the earliest, because that is the one an
    # analyst wants named; the ORDERING is decided against all of them.
    by_type: dict[str, list[Event]] = {}
    earliest: dict[str, Any] = {}
    counts: Counter[str] = Counter()
    audit = session.integrity   # verified-sequence oracle; see _ordering
    unusable_clock = 0
    for e in session.events:
        if e.event_type not in POLICY_EVENTS:
            continue
        counts[e.event_type] += 1
        by_type.setdefault(e.event_type, []).append(e)
        if not e.timestamp_valid:
            unusable_clock += 1
            continue
        cur = earliest.get(e.event_type)
        if cur is None or e.timestamp < cur.timestamp:
            earliest[e.event_type] = e
    # A control that fired is a control that fired, and whether Cohaera can read
    # the clock on the record is not the producer's decision to make. Every type
    # that fired gets a NAMED event: the clock-earliest where any firing has a
    # usable clock, and otherwise the lowest collector sequence -- which orders
    # even when the timestamp does not. `return []` here used to be reachable by
    # emitting one malformed timestamp.
    for etype, events in by_type.items():
        if etype in earliest:
            continue
        # Keyed on the sequence pulled out first, so the comparison key cannot
        # be a narrowing mypy has already lost by the time the lambda runs.
        sequenced = [(e.integrity.seq, e) for e in events
                     if e.integrity is not None and e.integrity.chained
                     and e.integrity.seq is not None]
        earliest[etype] = min(sequenced)[1] if sequenced else events[0]
    if not earliest:
        return []

    findings: list[Finding] = []
    consequential = session.consequential_calls

    for etype in sorted(earliest):
        e = earliest[etype]
        first_for_this_policy = len(findings)
        enforcement, source = _resolved_enforcement(e, session.manifest)
        # COH-R11. This was `c.started_at > e.timestamp`, so a call stamped on
        # the guardrail's own tick was excluded and the check went silent --
        # the cheapest evasion in the file, one field of the producer's own
        # choosing. It is now the shared three-valued ordering, and a tie with
        # no collector sequence to break it is reported rather than resolved.
        policy_ref = _References(by_type[etype], audit)
        ordering = [(c, policy_ref.verdict(c)) for c in consequential]
        cand = [c for c, o in ordering if o == ORDER_AFTER]
        unordered = [c for c, o in ordering if o == ORDER_INDETERMINATE]
        # Partition the completed calls by whether an approval actually fits
        # them. This is the whole of P1.3: before it, "a call happened after a
        # control fired" was the entire finding, and a deployment that approves
        # its exceptions properly had no way to say so.
        states = {id(c): _approval_state(session, c) for c in cand}
        completed = [c for c in cand if c.executed
                     and states[id(c)][0] in UNAPPROVED_STATES]
        approved = [c for c in cand if c.executed
                    and states[id(c)][0] == APPROVAL_COVERED]
        # An APPROVED attempt that failed is authorised work that did not come
        # off, which is not a security finding in any reading. Leaving these in
        # made the retry-under-approval case -- an agent whose approved action
        # fails and is legitimately re-approved and retried -- fire CH04 on the
        # failed first attempt, which is a false positive on the most ordinary
        # thing a well-governed agent does.
        attempted = [c for c in cand if not c.executed
                     and states[id(c)][0] != APPROVAL_COVERED]
        if not completed and not attempted:
            continue

        unordered_shown, unordered_dropped = cap_list(
            [c.brief(limits) for c in unordered], limits.max_evidence_items)
        base = {
            "policy_event": etype,
            # None, not NaN: the CLI serialises with allow_nan=False, and a
            # named firing whose clock is unreadable has no timestamp to give.
            "policy_event_first_ts": e.timestamp if e.timestamp_valid else None,
            "policy_event_count": counts[etype],
            "policy_events_with_invalid_clock": unusable_clock,
            # COH-R11: stated, not dropped. See the ordering note below.
            "unordered_calls": unordered_shown,
            "unordered_calls_truncated": unordered_dropped,
            "unordered_total": len(unordered),
            "policy_event_data": _policy_evidence(e.data, limits),
            "policy_semantics_declared": enforcement != ENFORCEMENT_UNDECLARED,
            "policy_enforcement": enforcement,
            "policy_enforcement_source": source,
            "approved_continuations": len(approved),
            "approval_states": sorted({states[id(c)][0] for c in completed}),
            # R-10. Which PATH the approvals in play arrived by, not who signed
            # them. Every approval Cohaera can parse today is in-band, so this
            # reads the same in every deployment -- which is the point: an
            # "approved continuation" is the producer's claim that a decision
            # was made, and the verdict now says so in a field rather than in a
            # docstring. See evidence.APPROVAL_ORIGIN_IN_BAND.
            "approval_origins": sorted(
                {m.approval.origin for c in completed + approved
                 if (m := states[id(c)][1]) is not None}),
        }

        if enforcement == ENFORCEMENT_ADVISORY:
            # The control is a notification and continuing past it is the
            # intended behaviour. Firing here is the corpus's single largest
            # source of false positives, and it was never a detection -- it was
            # Cohaera not being told what the control was for.
            #
            # Nothing is emitted, INCLUDING for the attempted calls: an attempt
            # after an advisory notice is an agent doing its job and failing at
            # it, which is not a security finding in any reading.
            #
            # ONE EXCEPTION, and it is not a special case so much as a
            # precedence rule. An advisory THRESHOLD is a suggestion about a
            # class of behaviour. A DENY bound to this exact span and these
            # exact arguments is a refusal of this exact call, and a completed
            # call after one is the policy engine being overruled whatever the
            # threshold was for. The narrower, later, call-specific decision
            # wins over the broader ambient one.
            completed = [c for c in completed
                         if states[id(c)][0] == APPROVAL_DENIED]
            if not completed:
                continue
            attempted = []

        if (enforcement == ENFORCEMENT_BLOCKING
                or any(states[id(c)][0] == APPROVAL_DENIED for c in completed)
                ) and completed:
            shown, dropped = cap_list([c.brief(limits) for c in completed],
                                      limits.max_evidence_items)
            reasons = sorted({_APPROVAL_WORDING[states[id(c)][0]]
                              for c in completed})
            findings.append(Finding(
                check=CH04_BYPASSED,
                family=CH04_FAMILY,
                severity="critical" if any(c.klass == "egress" for c in completed)
                else "high",
                session_id=session.session_id,
                title=f"BLOCKING control {etype} was bypassed",
                detail=(
                    f"{etype} fired at t={e.timestamp:.3f} and is declared "
                    f"BLOCKING by the {source}. {len(completed)} consequential "
                    f"call(s) COMPLETED after it, and "
                    f"{'; '.join(reasons)}. Unlike the undeclared case, this "
                    "does state a bypass: the control's semantics are on the "
                    "record, so a completed consequential action after it with "
                    "nothing authorising it is the control failing to control."
                    + (f" {len(approved)} further call(s) after this control "
                       "WERE covered by a bound approval and are not reported."
                       if approved else "")
                ),
                evidence={**base, "completed_after": shown,
                          "completed_after_truncated": dropped,
                          "completed_total": len(completed),
                          "also_attempted": len(attempted),
                          "approvals_seen": len(session.approvals)},
            ))
            completed = []          # reported; do not also report as undeclared

        if completed:
            shown, dropped = cap_list([c.brief(limits) for c in completed],
                                      limits.max_evidence_items)
            findings.append(Finding(
                check=CH04_COMPLETED,
                family=CH04_FAMILY,
                severity="high",
                session_id=session.session_id,
                title=f"Consequential action COMPLETED after {etype}",
                detail=(
                    f"{etype} fired at t={e.timestamp:.3f}"
                    + (f" ({counts[etype]} times in this session)"
                       if counts[etype] > 1 else "")
                    + f", and {len(completed)} consequential call(s) COMPLETED "
                    "successfully afterwards. Whatever that control was intended to "
                    "do, the session went on to take a consequential action after it "
                    "fired. Confirm with the agent owner whether the threshold is "
                    "advisory or blocking: this telemetry carries no declaration of "
                    "policy semantics, so Cohaera reports the sequence, not a bypass."
                ),
                evidence={**base, "completed_after": shown,
                          "completed_after_truncated": dropped,
                          "completed_total": len(completed),
                          "also_attempted": len(attempted)},
            ))

        if attempted:
            shown, dropped = cap_list([c.brief(limits) for c in attempted],
                                      limits.max_evidence_items)
            findings.append(Finding(
                check=CH04_ATTEMPTED,
                family=CH04_FAMILY,
                severity="medium",
                session_id=session.session_id,
                title=f"Consequential action ATTEMPTED after {etype}",
                detail=(
                    f"{etype} fired at t={e.timestamp:.3f}, and "
                    f"{len(attempted)} consequential call(s) started afterwards "
                    "without completing successfully. The attempt is the observed "
                    "fact. This telemetry CANNOT show whether the guardrail, the "
                    "tool, the model or an unrelated failure stopped them, so it "
                    "does not establish either that the control worked or that it "
                    "was ignored."
                ),
                evidence={**base, "attempted_after": shown,
                          "attempted_after_truncated": dropped,
                          "attempted_total": len(attempted),
                          "also_completed": len(completed)},
            ))

        if unordered and len(findings) > first_for_this_policy:
            note = (
                f" A further {len(unordered)} consequential call(s) share this "
                "control's tick with no collector sequence to separate them, "
                "so whether they ran before or after it is not established "
                "here (COH-R11)."
            )
            findings[first_for_this_policy:] = [
                replace(f, detail=f.detail + note)
                for f in findings[first_for_this_policy:]]

    shown, dropped = cap_list(findings, limits.max_findings_per_check)
    return shown


def unordered_after_policy(session: Session) -> list[ToolCall]:
    """Consequential calls whose order against a policy event is unknown.

    The coverage counterpart to CH04, and the case it exists for is the one
    where CH04 says nothing at all: a producer that stamps every consequential
    call on the guardrail's own tick empties the candidate list, and the check
    that used to fire falls silent with no trace. That silence is now a
    reported blind spot rather than a clean session.
    """
    audit = session.integrity   # verified-sequence oracle; see _ordering
    out: list[ToolCall] = []
    seen: set[int] = set()
    for e in session.events:
        if e.event_type not in POLICY_EVENTS or not e.timestamp_valid:
            continue
        for c in session.consequential_calls:
            if (id(c) not in seen
                    and _ordering(c, e, audit) == ORDER_INDETERMINATE):
                seen.add(id(c))
                out.append(c)
    return out


# ---------------------------------------------------------------------------
# CH05  Unpaired tool calls
# ---------------------------------------------------------------------------


def ch05_unpaired_calls(session: Session,
                        limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    """Pairing integrity: open starts AND orphan terminals.

    Integrity check on the telemetry itself, not on the agent. Either the agent
    died mid-write, or the event was lost, or something is fabricating events.
    The stream cannot distinguish these, which is exactly why it should be
    surfaced rather than silently dropped.

    Fixed after external review. Previously this only looked for
    ``result is None``, so an orphan tool_end (a terminal event with no matching
    start) was constructed with result="success" and therefore never flagged.
    An irreversible action appearing from nowhere is arguably the MORE
    interesting of the two cases and it was invisible.
    """
    opens = [c for c in session.tool_calls if c.state == "open"]
    orphans = [c for c in session.tool_calls
               if c.state in {"orphan_end", "mismatched_end", "duplicate_end"}]
    if not opens and not orphans:
        return []

    consequential = [c for c in (opens + orphans) if c.consequential]
    parts = []
    if opens:
        parts.append(f"{len(opens)} start(s) with no terminal event")
    if orphans:
        parts.append(f"{len(orphans)} terminal event(s) with no start")

    shown_open, dropped_open = cap_list([c.brief(limits) for c in opens],
                                        limits.max_evidence_items)
    shown_orph, dropped_orph = cap_list([c.brief(limits) for c in orphans],
                                        limits.max_evidence_items)
    return [Finding(
        check="CH05_unpaired_calls",
        family="CH05_unpaired_calls",
        severity="medium" if consequential else "low",
        session_id=session.session_id,
        title="Tool call pairing is incomplete",
        detail=(
            f"{' and '.join(parts)}, {len(consequential)} of them consequential. "
            "Either the run was truncated, events were dropped, or events were "
            "injected. The stream cannot distinguish these, so treat the session "
            "as incompletely observed rather than clean."
        ),
        evidence={
            "open_starts": shown_open,
            "open_starts_truncated": dropped_open,
            "open_starts_total": len(opens),
            "orphan_terminals": shown_orph,
            "orphan_terminals_truncated": dropped_orph,
            "orphan_terminals_total": len(orphans),
            "consequential_unpaired": len(consequential),
        },
    )]


# ---------------------------------------------------------------------------
# CH06  Evidence integrity: is this stream admissible at all?
# ---------------------------------------------------------------------------

CH06_INTEGRITY = "CH06_evidence_integrity"

# How much of the telemetry's own trustworthiness Cohaera established. Carried
# on every finding, because a verdict built on a stream somebody could have
# edited should not be presented at the same confidence as one built on a stream
# that chained and verified.
# R-05. ``verified`` used to be one of these values and is gone, because it
# answered the wrong question. It was returned whenever ANY signature verified,
# which is a fact about whether signing happened at all rather than about what
# the signatures covered -- so a 150-record stream signed at sequence 0 and 100
# was reported ``verified`` with 49 records past the last attestation, covered
# by nothing, and CH06 scored it 1.0. A signature covers the chain head at its
# own sequence, so it attests every record up to that point and none after it;
# the two cases below are that distinction, and collapsing them is how an
# unsigned tail rides in under a word an analyst reads as settled.
EVIDENCE_VERIFIED_COMPLETE = "verified_complete"  # attested to the final record
EVIDENCE_VERIFIED_PREFIX = "verified_prefix"      # attested to a point, then not
EVIDENCE_CHAINED = "chained_unsigned"   # chained, nothing to verify it against
EVIDENCE_UNATTESTED = "unattested"      # no sidecars at all: today's default
EVIDENCE_INADMISSIBLE = "inadmissible"  # a gap, a break or a bad signature
# CH06's own finding. Its subject IS the integrity evidence, so asking how far
# that evidence was established is a category error rather than a hard question.
# It used to be stamped ``verified``, which was the one place the old vocabulary
# stated something false rather than merely incomplete.
EVIDENCE_NOT_APPLICABLE = "not_applicable"

# Every value the field can take, so a conformance test and a SIEM parser have
# one list to read rather than a grep.
EVIDENCE_STATES = frozenset({
    EVIDENCE_VERIFIED_COMPLETE, EVIDENCE_VERIFIED_PREFIX, EVIDENCE_CHAINED,
    EVIDENCE_UNATTESTED, EVIDENCE_INADMISSIBLE, EVIDENCE_NOT_APPLICABLE})


def evidence_status(session: Session) -> str:
    """One word for how far the telemetry's own integrity was established.

    ``unattested`` is the important value and the one nearly every deployment
    will see. It does NOT mean tampering was ruled out; it means nothing was
    ever in a position to rule it in. Reporting that as ``verified`` would be
    the same fault as a check that cannot run reporting itself as clean, which
    is the objection this project was started over.
    """
    audit = session.integrity
    if audit is None or audit.with_integrity == 0:
        return EVIDENCE_UNATTESTED
    if audit.inadmissible:
        return EVIDENCE_INADMISSIBLE
    if audit.signatures_verified == 0:
        return EVIDENCE_CHAINED
    # R-05. Not ``signatures_verified > 0``. The question is how far the
    # attestation reached, not whether one exists: see
    # SessionIntegrity.signature_covers_final, which requires the last record of
    # EVERY stream feeding this session to be covered.
    if audit.signature_covers_final:
        return EVIDENCE_VERIFIED_COMPLETE
    return EVIDENCE_VERIFIED_PREFIX


def ch06_evidence_integrity(session: Session,
                            limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    """The collector's chain did not hold for this session's records.

    This is not a check of the same KIND as CH01 to CH05. Those are statements
    about the agent's behaviour. This is a statement about whether the evidence
    for any of them is admissible, which is why it is critical whatever it
    finds and why every other finding in the session is stamped with
    ``evidence_status`` rather than left to be read at face value.

    What it can and cannot say, stated because the difference is the whole
    value of the mechanism:

        CAN say   a record was deleted, altered, replayed, or signed by a key
                  the operator did not supply.
        CANNOT say who did it. A collector holding the signing key can produce
                  a perfectly chained stream of lies, and in a deployment where
                  the adapter runs inside the agent process, that is not even a
                  compromise -- it is the normal configuration. See
                  docs/EVIDENCE-TRUST.md section 2.
    """
    audit = session.integrity
    if audit is None or not audit.inadmissible:
        return []

    codes = audit.inadmissible
    parts: list[str] = []
    if R_SEQUENCE_GAP in codes:
        missing = sum(g["missing_count"] for g in audit.gaps)
        parts.append(f"{missing} record(s) are missing from the collector's "
                     f"sequence")
    if R_CHAIN_BROKEN in codes:
        parts.append(f"{len(audit.chain_breaks)} record(s) do not match the hash "
                     f"chain")
    if R_SIGNATURE_INVALID in codes:
        parts.append(f"{len(audit.bad_signatures)} signature(s) did not verify")
    if R_KEY_UNKNOWN in codes:
        parts.append(f"{len(audit.unknown_key_ids)} record(s) were signed by a "
                     f"key that was not supplied")
    if R_SEQUENCE_REPLAY in codes:
        parts.append("a record arrived for a sequence position that was already "
                     "filled")
    if R_PARTIAL_INTEGRITY in codes:
        parts.append(f"{audit.without_integrity} of {audit.records} record(s) "
                     f"carry no integrity evidence at all while the rest do")
    if R_KEY_REVOKED in codes:
        parts.append("the signing key is marked REVOKED in the trust store, so "
                     "its signatures establish nothing about who wrote these "
                     "records")
    if R_KEY_EXPIRED in codes:
        parts.append("records were signed by a key after its validity window "
                     "closed: a retired key is still signing this stream")
    if R_KEY_NOT_YET_VALID in codes:
        parts.append("records were signed by a key before its validity window "
                     "opened")
    if R_KEY_WRONG_ROLE in codes:
        parts.append("the signing key is not authorised for the 'collector' "
                     "role, so it was never trusted to attest telemetry")
    if R_STALE in codes:
        age = (f"{audit.oldest_signed_age_s:.0f}s"
               if audit.oldest_signed_age_s is not None else "an unstated age")
        parts.append(f"{audit.codes[R_STALE]} verified record(s) are older than "
                     f"the freshness bound, the oldest by {age}, which is what "
                     f"re-feeding an archived stream looks like")
    if R_STREAM_REPLAYED in codes:
        seen = ", ".join(sorted({r["stream_id"] for r in audit.replayed_streams}))
        parts.append(f"stream(s) {seen} occupy sequence positions a previous run "
                     f"already scored, and the chain head matches at the shared "
                     f"position -- the same records, fed twice")
    if R_STREAM_FORKED in codes:
        seen = ", ".join(sorted({r["stream_id"] for r in audit.replayed_streams}))
        parts.append(f"stream(s) {seen} reuse sequence positions a previous run "
                     f"scored, and the chain head DIFFERS there: two mutually "
                     f"exclusive versions of the same stream, both signed. This "
                     f"is not a replay, it is a rewritten history")

    return [Finding(
        check=CH06_INTEGRITY,
        family=CH06_INTEGRITY,
        severity="critical",
        session_id=session.session_id,
        title="Telemetry integrity verification FAILED for this session",
        detail=(
            f"{'; '.join(parts)}. Every other finding in this session, and every "
            "absence of one, rests on records that did not verify against what "
            "the collector attested to. Treat the session as evidence of "
            "tampering with the telemetry rather than as a behavioural verdict: "
            "the sequence Cohaera scored is not the sequence that was written."
        ),
        evidence={"integrity": audit.as_dict(limits),
                  "inadmissible_codes": codes},
    )]


# ---------------------------------------------------------------------------
# CH07  A call reported failure and produced an effect anyway
# ---------------------------------------------------------------------------

CH07_FAMILY = "CH07_effect_contradiction"
CH07_CONTRADICTED = "CH07_reported_failure_with_effect_receipt"
CH07_UNBOUND = "CH07_effect_receipt_does_not_bind"
# R-01. Distinct from CH07_UNBOUND, and the distinction is the doctrine rather
# than a taxonomy preference. A receipt that names a DIFFERENT span, tool or
# argument digest actively disagrees with the call it arrived on, which is what
# a receipt copied off another call looks like. A receipt that simply omits a
# field disagrees with nothing -- it constrains nothing. Absent is not weaker;
# it is a different fact, and reporting the second as the first would invent an
# accusation against every adapter that has not implemented argument digests.
CH07_PARTIAL = "CH07_effect_receipt_partially_bound"


def _receipted_calls(session: Session) -> list[ToolCall]:
    return [c for c in session.tool_calls if c.receipt is not None]


def _receipt_trust(calls: list[ToolCall]) -> str:
    """The weakest receipt trust across these calls. See evidence.RECEIPT_*.

    Weakest rather than strongest, and rather than per-call: one finding
    carries them all, so its severity has to be the one the worst member
    supports. Reporting the best would let a single authenticated receipt
    launder every unauthenticated one beside it.
    """
    if not calls:
        return RECEIPT_CLAIMED
    # Nothing can currently exceed BOUND -- no signature field, no receipt role
    # in the trust store. The loop is written against the full vocabulary
    # anyway, so the day a receipt CAN be authenticated this reads it rather
    # than needing to be found and changed.
    tiers = {RECEIPT_CLAIMED: 0, RECEIPT_BOUND: 1,
             RECEIPT_AUTHENTICATED: 2, RECEIPT_RECONCILED: 3}
    worst = min((_receipt_trust_of(c) for c in calls), key=lambda x: tiers[x])
    return worst


def _receipt_trust_of(call: ToolCall) -> str:
    """One call's receipt trust.

    Binding is a NECESSARY condition for BOUND and is nowhere near sufficient
    for anything above it, which is the distinction CH07 was missing: a receipt
    can name this call exactly and still have been written by whoever wrote the
    call.
    """
    if call.receipt is None:
        return RECEIPT_CLAIMED
    if _receipt_binding(call) in BINDING_TRUSTED:
        return RECEIPT_BOUND
    return RECEIPT_CLAIMED


def _receipt_severity(contradicted: list[ToolCall]) -> str:
    """Severity capped by what the receipt is actually worth.

    An unauthenticated receipt cannot support `critical`, because `critical`
    here means "an effect provably occurred" and nothing proves it. Egress
    still outranks the rest -- a contradiction about an irreversible outward
    action deserves more attention than one about a local write -- so the shape
    of the old mapping survives, one step down.
    """
    egress = any(c.klass == "egress" for c in contradicted)
    if _receipt_trust(contradicted) in RECEIPT_AUTHENTIC:
        return "critical" if egress else "high"
    return "high" if egress else "medium"


def _receipt_binding(call: ToolCall) -> str:
    """How well this call's receipt binds to it. See evidence.Binding.

    R-01. This used to return ``BOUND_EXACT`` whenever the two argument digests
    agreed, whatever else the binding did or did not name, and ``BOUND_SPAN_ONLY``
    -- then a trusted value -- whenever it could not compare them at all. Both
    halves were wrong in the same direction. A receipt naming only the arguments
    is a receipt that names no call; a receipt naming nothing is not a binding.
    Each of the three fields is now either CHECKED or the result is not exact,
    and "the field was absent" is never the same answer as "the field matched".
    """
    receipt = call.receipt
    if receipt is None:
        return BOUND_NONE
    b = receipt.binding
    if b.span_id and call.span_id and b.span_id != call.span_id:
        return BOUND_NONE
    if b.tool_id and b.tool_id != call.name:
        return BOUND_NONE
    if call.arg_digest_source in ARGS_UNBINDABLE:
        # F-01. The CALL's own two argument identities disagree, so there is
        # nothing here for a receipt to bind to and a contradiction resting on
        # it would be an accusation built on evidence the producer wrote both
        # halves of. A receipt matching the declared digest of a call whose
        # captured arguments say otherwise is exactly the shape of a producer
        # manufacturing the evidence used to accuse it.
        return BOUND_ARG_MISMATCH
    if b.arg_digest and call.arg_digest and b.arg_digest != call.arg_digest:
        return BOUND_ARG_MISMATCH
    if b.complete and call.span_id and call.arg_digest:
        return BOUND_EXACT
    return BOUND_SPAN_ONLY


def ch07_effect_contradiction(session: Session,
                              limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    """The asymmetry that makes receipts worth collecting.

    Receipts do not make Cohaera trust ``success`` more. A success with no
    receipt is exactly as unfalsifiable as it always was, and it is reported
    through coverage (``NO_EFFECT_RECEIPT``) rather than as a finding, because
    in any real deployment most tools will have no receipt for a long time and a
    finding per receiptless call is a pager storm on day one.

    What receipts make falsifiable is the other direction. A call whose terminal
    event says ``failure`` while carrying a receipt bound to that exact call and
    those exact arguments is an effect that occurred and telemetry that reported
    it did not. That is the first thing in this repository that catches a lying
    emitter rather than routing around it -- every other check assumes the
    stream is honest and reasons about what it says.

    The second finding here is the guard on the first. A receipt that names a
    different span, a different tool, or different arguments is a receipt copied
    from a call that really did happen onto one that did not, and without
    checking that, the whole mechanism is decorative.
    """
    receipted = _receipted_calls(session)
    if not receipted:
        return []

    contradicted: list[ToolCall] = []
    unbound: list[ToolCall] = []
    partial: list[ToolCall] = []
    for c in receipted:
        binding = _receipt_binding(c)
        if binding in BINDING_TRUSTED:
            if not c.executed:
                # ``not executed`` rather than ``result == failure``: an orphan
                # or duplicate terminal event carrying a bound receipt is the
                # same contradiction wearing a different pairing state, and
                # enumerating the states would leave the next one added
                # silently uncovered.
                contradicted.append(c)
        elif binding in BINDING_CONTEXT:
            # R-01. Incomplete, so it cannot carry a contradiction -- but it is
            # reported only where the trust decision actually changed, on a call
            # whose telemetry did NOT report success. A partial receipt on a
            # completed call is a producer-shape gap and belongs in coverage:
            # emitting a finding per call would put every adapter that has not
            # implemented argument digests on the pager, which is the same
            # mistake as a finding per receiptless call.
            if not c.executed:
                partial.append(c)
        else:
            unbound.append(c)

    findings: list[Finding] = []
    if contradicted:
        shown, dropped = cap_list(
            [{**c.brief(limits),
              "receipt": c.receipt.as_dict() if c.receipt else None}
             for c in contradicted], limits.max_evidence_items)
        findings.append(Finding(
            check=CH07_CONTRADICTED,
            family=CH07_FAMILY,
            severity=_receipt_severity(contradicted),
            session_id=session.session_id,
            title="Telemetry reports failure for a call that produced an effect",
            # The detail an analyst receives states what is ESTABLISHED and
            # what is CONDITIONAL, and nothing else. An earlier draft of this
            # fix quoted the wording it was correcting, which put a changelog
            # in every record shipped to a SIEM. The history belongs here.
            #
            # It previously read "an identifier minted by the system the action
            # happened to, from a namespace the agent does not control" and
            # claimed the finding "does not depend on the stream being honest".
            # Neither clause was supported by anything: `authority` is a
            # producer-written string.
            detail=(
                f"{len(contradicted)} call(s) did not report success while "
                "carrying an effect receipt whose binding names that exact "
                "call. The record contradicts itself, which is what this "
                "finding establishes.\n\n"
                f"Receipt trust: {_receipt_trust(contradicted)}, NOT "
                "authenticated. Whether the effect actually occurred depends on "
                "the receipt being genuine, and that is not checked: "
                "cohaera.receipt:1 carries no signature and the trust store has "
                "no role for receipt authorities, so `authority` is a string "
                "the producer chose. Treat this as a contradiction to "
                "investigate, not as proof an action took effect."
            ),
            evidence={"contradicted": shown, "contradicted_truncated": dropped,
                      "contradicted_total": len(contradicted),
                      "receipted_calls": len(receipted),
                      # Routable: a SIEM can hold unauthenticated contradictions
                      # in a hunt queue and page only on authenticated ones,
                      # without parsing the detail text.
                      "receipt_trust": _receipt_trust(contradicted),
                      "receipt_authenticated": False},
        ))

    if unbound:
        shown, dropped = cap_list(
            [{**c.brief(limits),
              "receipt": c.receipt.as_dict() if c.receipt else None,
              "binding": _receipt_binding(c)} for c in unbound],
            limits.max_evidence_items)
        findings.append(Finding(
            check=CH07_UNBOUND,
            family=CH07_FAMILY,
            severity="medium",
            session_id=session.session_id,
            title="Effect receipt does not bind to the call carrying it",
            detail=(
                f"{len(unbound)} receipt(s) name a different span, a different "
                "tool, or different arguments than the call they arrived on. A "
                "receipt is only worth anything if it is bound: an unbound one "
                "can be copied from a call that really happened onto one that "
                "did not. This is equally consistent with an adapter emitting "
                "the binding incorrectly, which is why it is medium and not "
                "critical -- but it means the receipts in this session are not "
                "carrying the guarantee they appear to."
            ),
            evidence={"unbound": shown, "unbound_truncated": dropped,
                      "unbound_total": len(unbound),
                      "receipted_calls": len(receipted)},
        ))

    if partial:
        shown, dropped = cap_list(
            [{**c.brief(limits),
              "receipt": c.receipt.as_dict() if c.receipt else None,
              "binding": _receipt_binding(c)} for c in partial],
            limits.max_evidence_items)
        findings.append(Finding(
            check=CH07_PARTIAL,
            family=CH07_FAMILY,
            severity="low",
            session_id=session.session_id,
            title="Effect receipt on a call that did not report success is "
                  "incompletely bound",
            detail=(
                f"{len(partial)} call(s) did not report success and carry an "
                "effect receipt that names only part of the call. Nothing here "
                "disagrees with anything -- the receipt does not name a "
                "different span, tool or arguments, it declines to name them, "
                "so it cannot establish that the effect belongs to THIS call. "
                "Before the binding rule was tightened this reported as a "
                "critical contradiction on the strength of a binding that had "
                "never been checked. It is reported at all because the shape is "
                "worth an analyst's attention and the remedy is one field on "
                "the adapter, not because the effect has been established."
            ),
            evidence={"partial": shown, "partial_truncated": dropped,
                      "partial_total": len(partial),
                      "receipted_calls": len(receipted)},
        ))
    return findings


# ---------------------------------------------------------------------------
# Coverage: a capability contract per check
# ---------------------------------------------------------------------------

COVERAGE_SCHEMA = "cohaera.coverage:2"

STATUS_EVALUATED = "evaluated"
STATUS_DEGRADED = "degraded"
STATUS_NOT_EVALUATED = "not_evaluated"

# Surfaces a check can require. Naming them makes the contract auditable: an
# operator can ask "which of my agents actually expose SURFACE_FINAL_RESPONSE"
# rather than reading five reason strings and guessing.
SURFACE_TOOL_LIFECYCLE = "tool_lifecycle"
SURFACE_TOOL_CLASS = "tool_class"
SURFACE_FINAL_RESPONSE = "final_response"
SURFACE_TOOL_RESULT = "tool_result"
SURFACE_INJECTION_SCANNER = "injection_scanner"
SURFACE_POLICY_SEMANTICS = "policy_semantics"
SURFACE_BENIGN_BASELINE = "benign_baseline"
SURFACE_EVENT_CLOCK = "event_clock"
SURFACE_CORRELATION_KEY = "correlation_key"
# P1. Three surfaces nothing emits yet, which is exactly why they are named:
# an operator can now ask "which of my collectors signs its stream" instead of
# discovering after an incident that none of them do.
SURFACE_EVENT_INTEGRITY = "event_integrity"
SURFACE_EFFECT_RECEIPT = "effect_receipt"
SURFACE_APPROVAL = "approval_binding"

# Reason codes. Stable, because downstream content will match on them.
R_NO_BASELINE = "NO_BENIGN_BASELINE_FITTED"
R_BASELINE_VOCABULARY_MISMATCH = "BASELINE_VOCABULARY_MISMATCH"
R_NO_RESPONSE = "NO_FINAL_RESPONSE_TEXT"
# F-04. Present, and not all of it. Distinct from absent, because the operator
# remedy is different: absent needs cold-path capture turned on, truncated
# needs a bound raised.
R_TRUNCATED_RESPONSE = "FINAL_RESPONSE_TRUNCATED"
R_BAD_RESPONSE = "FINAL_RESPONSE_WRONG_TYPE"
R_NO_TOOL_RESULT = "NO_TOOL_RESULT_CAPTURED"
R_NO_SCANNER = "NO_INJECTION_SCANNER_EVIDENCE"
R_UNKNOWN_CLASS = "TOOL_CLASS_UNKNOWN"
R_HEURISTIC_CLASS = "TOOL_CLASS_FROM_NAME_HEURISTIC"
R_NO_MANIFEST = "NO_CAPABILITY_MANIFEST"
R_WEAK_CORRELATION = "CORRELATION_KEY_NOT_PRODUCER_SUPPLIED"
R_INVALID_CLOCK = "EVENT_CLOCK_INVALID"
R_NO_POLICY_SEMANTICS = "POLICY_SEMANTICS_UNDECLARED"
# EXTERNAL-01. The absence one step further back than POLICY_SEMANTICS_UNDECLARED.
# That code means a control fired and nothing said whether it blocks; this one
# means nothing in the session says a control exists at all -- no policy event,
# and no 'policies' section in the operator's manifest. The two are a different
# operator remedy and a different verdict, which is why they are separate codes:
# the first needs a field added to an event that is already arriving, the second
# needs a policy engine wired to the telemetry, or at minimum a declaration that
# one is there.
R_NO_POLICY_EVIDENCE = "NO_POLICY_EVIDENCE"
R_AMBIGUOUS_DISCLOSURE = "DISCLOSURE_AMBIGUOUS_SHARED_TOKENS"
# COH-R11. Two records share a tick and carry no collector sequence, so their
# order is not a fact this telemetry contains. Charged to whichever check
# needed the order.
R_ORDER_INDETERMINATE = "EVENT_ORDER_INDETERMINATE"
# COH-R09. A scanner answered for some of the calls that could have brought
# untrusted content in, and nothing answered for the rest.
R_SCANNER_PARTIAL = "INJECTION_SCANNER_PARTIAL_COVERAGE"
R_FIELD_DEFECTS = "RECORD_FIELD_DEFECTS_PRESENT"
# P1. The three absences that are now STATED rather than passed over.
R_NO_APPROVAL_EVIDENCE = "NO_APPROVAL_EVIDENCE"
R_APPROVAL_NOT_ARGUMENT_BOUND = "APPROVAL_BOUND_BY_SPAN_ONLY"
# R-01, the receipt half of the same gap. Its approval twin above has existed
# since P1.3; the receipt side had none, so a deployment whose adapter emitted
# no argument digest was told CH07 was fully covered while CH07 could not have
# established a contradiction against any call in the session.
R_RECEIPT_NOT_ARGUMENT_BOUND = "RECEIPT_BOUND_BY_SPAN_ONLY"
R_ENFORCEMENT_FROM_PRODUCER = "POLICY_ENFORCEMENT_DECLARED_IN_BAND"
R_NO_EFFECT_RECEIPT = "NO_EFFECT_RECEIPT"
R_DANGLING_APPROVAL = "APPROVAL_MATCHES_NO_CALL"
R_ARG_DIGEST_CONTRADICTS = "ARG_DIGEST_CONTRADICTS_CAPTURED_ARGS"

# How much to believe a class that came from a name heuristic rather than a
# declared capability. Not a measurement; an ordering. It exists so that a
# session classified entirely by guesswork cannot report full confidence.
_HEURISTIC_CLASS_WEIGHT = 0.7


@dataclass
class CheckContract:
    """What one check needed, what it got, and how much to believe it."""

    check: str
    status: str
    confidence: float
    required_surfaces: list[str] = field(default_factory=list)
    present_surfaces: list[str] = field(default_factory=list)
    missing_surfaces: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    remedies: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "status": self.status,
            "confidence": round(self.confidence, 3),
            "required_surfaces": self.required_surfaces,
            "present_surfaces": self.present_surfaces,
            "missing_surfaces": self.missing_surfaces,
            "reasons": self.reasons,
            "remedies": self.remedies,
            "assumptions": self.assumptions,
        }


def _classification_quality(session: Session) -> tuple[float, int, int, int, float]:
    """(worst_case, unknown, heuristic, manifest, mean) over this session's calls.

    A call classified from a signed-out-of-band manifest is a fact. One
    classified from its name is a guess about an attacker-supplied string. One
    that matched nothing is not classified at all.

    COH-R07. THE CONFIDENCE IS THE WORST CALL, NOT THE AVERAGE ONE.

    This used to return the mean, and a mean over calls is diluted by adding
    calls -- which is a thing the producer decides. One unknown tool padded with
    a hundred manifest-declared reads scored 0.99, and a verdict that says
    "classification confidence 0.99" about a session containing one call Cohaera
    could not classify at all is not a summary, it is a misdescription. It is
    E02 again in a different field: the same dilution that hid a violation RATE
    hid a classification gap.

    The question a confidence answers is "how much should I trust what this
    check concluded". A check concludes over the WHOLE session, so its exposure
    is the least-known call in it, not the average call. One unknown call means
    Cohaera does not know whether this session contained a consequential action
    -- and no number of reads it does understand makes that less true.

    The mean is still returned, and still reported, as ``classification_share``.
    It answers a different and genuinely useful question -- how much of this
    session was understood -- and losing it would cost an operator the
    difference between one unknown call and forty. It is a diagnostic; the
    worst case is the confidence.
    """
    calls = session.tool_calls
    if not calls:
        return 1.0, 0, 0, 0, 1.0
    unknown = heuristic = manifest = 0
    total = 0.0
    worst = 1.0
    for c in calls:
        if c.klass == "unknown":
            unknown += 1
            worst = 0.0
        elif c.klass_source == SOURCE_MANIFEST:
            manifest += 1
            total += 1.0
        else:
            heuristic += 1
            total += _HEURISTIC_CLASS_WEIGHT
            worst = min(worst, _HEURISTIC_CLASS_WEIGHT)
    return worst, unknown, heuristic, manifest, total / len(calls)


def _clock_quality(session: Session) -> float:
    if not session.events:
        return 1.0
    return 1.0 - (session.clock_defects / len(session.events))


def _scanner_evidence(session: Session) -> bool:
    """Did anything upstream actually scan for injection markers?

    E09 and E13: CH03 orders markers against calls, so with no marker fields at
    all in the stream it cannot fire, and the old coverage counted it as a check
    that ran and passed. A scanner that ran and found nothing IS evidence, which
    is why ``has_injection_patterns: false`` counts here and an empty marker list
    counts here. Absence is a blind spot, and a blind spot reported as a clean
    result is a false negative wearing a green tick.

    COH-R03. What no longer counts is the field being PRESENT at any value. A
    malformed claim is not a scanner's answer, it is a producer emitting
    something Cohaera cannot read -- and letting it buy coverage would mean a
    type error could turn CH03's blind spot into a clean bill of health, which
    is the same fail-open the schema firewall exists to prevent.
    """
    return any(scanner_reported(e.data) for e in session.events)


@dataclass(frozen=True)
class ScannerCoverage:
    """How much of a session's untrusted-input surface a scanner actually saw.

    COH-R09. COH-R03 fixed the TYPE half of this -- a malformed claim is not a
    scanner's answer and cannot buy coverage. What it left was the BINDING: a
    single well-formed answer anywhere in the session was read as "a scanner
    ran here", and CH03's coverage then charged nothing for the other reads.
    Ten pages fetched, one of them scanned, and the contract said CH03 was
    running at full strength over a session with nine unexamined entry points.

    The surface that matters is the calls that can bring somebody else's text
    into the session -- reads, and calls Cohaera could not classify, because
    `unknown` is the absence of a classification rather than a statement that
    nothing came back. Consequential calls are excluded: they are what CH03
    orders the markers AGAINST, not where the markers come from.

    Answers are bound to a call by span where the span names one, and by tool
    name otherwise -- observra's scanner events carry the read's tool name and
    a span of their own, so span-only binding would attribute nothing at all.
    An answer that binds to no call in the session is counted separately rather
    than dropped: it is a scanner reporting on something this session cannot
    see, which is its own provenance gap.
    """

    scanned: int
    scannable: int
    unbound: int

    @property
    def share(self) -> float:
        """1.0 when there is nothing to scan: vacuous, not blind."""
        if not self.scannable:
            return 1.0
        return min(1.0, self.scanned / self.scannable)

    @property
    def complete(self) -> bool:
        return self.share >= 1.0 and not self.unbound


def _scanner_coverage(session: Session) -> ScannerCoverage:
    calls = session.tool_calls
    by_span = {c.span_id: c for c in calls if c.span_id}
    by_name: dict[str, ToolCall] = {}
    for c in calls:
        by_name.setdefault(c.name, c)

    scanned: set[int] = set()
    unbound = 0
    for e in session.events:
        if not scanner_reported(e.data):
            continue
        call = by_span.get(e.span_id) if e.span_id else None
        if call is None:
            call = by_name.get(e.tool_name) if e.tool_name else None
        if call is None:
            unbound += 1
            continue
        scanned.add(id(call))

    scannable = [c for c in calls if not c.consequential]
    return ScannerCoverage(
        scanned=sum(1 for c in scannable if id(c) in scanned),
        scannable=len(scannable),
        unbound=unbound)


def _result_share(session: Session) -> float:
    """The share of the untrusted-input surface whose content Cohaera can see.

    COH-R09, second half. This was ``any(c.had_result for c in calls)``, so one
    captured ``tool_result`` anywhere in the session satisfied the whole of
    CH03's result coverage -- capture it on one trivial read, strip it from the
    nine that returned attacker-controlled text, and the contract charged
    nothing. Measured over the same surface as the scanner share, for the same
    reason: a result on a consequential call is not the content a marker claim
    would have been about.
    """
    scannable = [c for c in session.tool_calls if not c.consequential]
    if not scannable:
        return 1.0
    return sum(1 for c in scannable if c.had_result) / len(scannable)


def coverage(session: Session, grammar: SequenceGrammar | None,
             limits: Limits = DEFAULT_LIMITS) -> dict[str, Any]:
    """Report Cohaera's own blind spots for this session, per check.

    observra's examples/siem_parser.json carries a telemetry_completeness field
    described as "Use to weight anomaly detection confidence". This is that idea,
    made concrete per check.

    The previous version counted only ``not_evaluated`` states, so a session
    whose every tool was unclassifiable still scored up to 1.0, and a missing
    tool_result was charged to CH02 even though CH02 reads the final response
    rather than tool output. Both are fixed: degraded states cost confidence,
    unknown classification degrades the checks that actually depend on it, and
    tool_result is charged to CH03, whose provenance story needs it.
    """
    calls = session.tool_calls
    (class_conf, unknown, heuristic, manifest_hits,
     class_share) = _classification_quality(session)
    clock_conf = _clock_quality(session)
    corr_conf = session.correlation_confidence
    corr_kind = session.correlation.kind if session.correlation else "session_id"
    scanner = _scanner_evidence(session)
    has_policy = bool(session.policy_events)
    baseline_ok = grammar is not None and grammar.fitted
    defects = session.integrity_defects

    common_reasons: list[str] = []
    if corr_conf < 1.0:
        common_reasons.append(R_WEAK_CORRELATION)
    if clock_conf < 1.0:
        common_reasons.append(R_INVALID_CLOCK)
    if defects:
        common_reasons.append(R_FIELD_DEFECTS)

    def class_reasons() -> list[str]:
        out = []
        if unknown:
            out.append(R_UNKNOWN_CLASS)
        if heuristic:
            out.append(R_HEURISTIC_CLASS)
        if not manifest_hits and calls:
            out.append(R_NO_MANIFEST)
        return out

    contracts: list[CheckContract] = []

    # ---- CH01 -----------------------------------------------------------
    required = [SURFACE_BENIGN_BASELINE, SURFACE_TOOL_LIFECYCLE,
                SURFACE_CORRELATION_KEY]
    if grammar is None or not baseline_ok:
        contracts.append(CheckContract(
            check="CH01_sequence_order", status=STATUS_NOT_EVALUATED, confidence=0.0,
            required_surfaces=required,
            present_surfaces=[SURFACE_TOOL_LIFECYCLE, SURFACE_CORRELATION_KEY],
            missing_surfaces=[SURFACE_BENIGN_BASELINE],
            reasons=[R_NO_BASELINE],
            remedies=["Fit on a labelled benign corpus before scoring."],
            assumptions=["The benign corpus is benign. Cohaera cannot verify "
                         "that; see EVASION.md E03."]))
    elif _baseline_out_of_distribution(session, grammar):
        # The baseline exists but was fitted on a different workload. Reporting
        # this as not_evaluated rather than firing is the whole fix: a bigram
        # model out of its distribution scores every transition as unseen and
        # flags everything, which measured 100% false positives at exactly the
        # attack base rate. Silence here would be worse than the alarm, so the
        # blind spot goes in the contract where a SOC can route on it.
        contracts.append(CheckContract(
            check="CH01_sequence_order", status=STATUS_NOT_EVALUATED, confidence=0.0,
            required_surfaces=required,
            present_surfaces=[SURFACE_TOOL_LIFECYCLE, SURFACE_CORRELATION_KEY],
            missing_surfaces=[SURFACE_BENIGN_BASELINE],
            reasons=[R_BASELINE_VOCABULARY_MISMATCH],
            remedies=["Fit a baseline on this agent's own workload. A grammar "
                      "fitted on differently-tasked agents does not transfer.",
                      f"Baseline covers "
                      f"{grammar.vocabulary_overlap(session):.0%} of this "
                      f"session's tools; CH01 needs "
                      f"{MIN_VOCABULARY_OVERLAP:.0%}."],
            assumptions=["An unseen tool vocabulary means the model does not "
                         "apply, not that the session is anomalous."]))
    else:
        # CH01's dilution-resistant trigger asks what a call DOES, so tool class
        # is now a surface CH01 uses -- partially. Weighted rather than
        # multiplied: see CH01_CLASS_WEIGHT. Before this, CH01 reported full
        # confidence on a session whose every tool was unclassifiable, which is
        # exactly the "scored 1.0 on a session it never saw" fault BUG-10 fixed
        # everywhere else.
        conf = corr_conf * clock_conf * (
            CH01_CLASS_WEIGHT + (1.0 - CH01_CLASS_WEIGHT) * class_conf)
        reasons = list(common_reasons)
        remedies = ["Correlate on a producer-supplied session_id."] if corr_conf < 1.0 else []
        if class_conf < 1.0:
            reasons += class_reasons()
            remedies.append(
                "Supply a capability manifest. Without one CH01 keeps its rate "
                "trigger but loses the count trigger that resists dilution, "
                "because it cannot tell which calls are consequential.")
        contracts.append(CheckContract(
            check="CH01_sequence_order",
            status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
            confidence=conf,
            required_surfaces=[*required, SURFACE_TOOL_CLASS],
            present_surfaces=required, missing_surfaces=[],
            reasons=reasons, remedies=remedies,
            assumptions=["Bigram order only. Argument and destination drift are "
                         "not modelled; see EVASION.md E01.",
                         "A novel route into a consequential call is not "
                         "dilutable, but it is not evidence of intent either; "
                         "a legitimate rare action produces the same shape."]))

    # ---- CH02 -----------------------------------------------------------
    required = [SURFACE_FINAL_RESPONSE, SURFACE_TOOL_CLASS, SURFACE_CORRELATION_KEY]
    if session.final_response is not None and session.response_text_truncated:
        # F-04. Present but incomplete, which is a third state the contract did
        # not have. Reported as not_evaluated rather than degraded: the missing
        # part is not a fraction of the answer, it is the part that would have
        # falsified it.
        contracts.append(CheckContract(
            check="CH02_concealment_gap", status=STATUS_NOT_EVALUATED,
            confidence=0.0, required_surfaces=required,
            present_surfaces=[SURFACE_TOOL_CLASS, SURFACE_CORRELATION_KEY],
            missing_surfaces=[SURFACE_FINAL_RESPONSE],
            reasons=[R_TRUNCATED_RESPONSE],
            remedies=[f"Raise max_response_chars above "
                      f"{limits.max_response_chars}, or have the adapter "
                      f"emit the final response in full. A concealment finding "
                      f"needs the whole text: the disclosure it would be "
                      f"looking for may be in the part that was cut."],
            assumptions=["A truncated response cannot support an absence "
                         "claim. A disclosure found inside the surviving "
                         "prefix is still sound."]))
    elif session.final_response is None:
        reasons = [R_BAD_RESPONSE] if session.response_text_rejected else [R_NO_RESPONSE]
        contracts.append(CheckContract(
            check="CH02_concealment_gap", status=STATUS_NOT_EVALUATED, confidence=0.0,
            required_surfaces=required,
            present_surfaces=[SURFACE_TOOL_CLASS, SURFACE_CORRELATION_KEY],
            missing_surfaces=[SURFACE_FINAL_RESPONSE],
            reasons=reasons,
            remedies=["Enable cold-path capture, or run the claude adapter.",
                      "Emit response_text as a JSON string."],
            assumptions=["Absence of a summary is not a clean summary."]))
    else:
        # E16. A call whose only mention is by tokens it shares with a sibling
        # tool is one CH02 has NOT checked, and the previous version scored it
        # as clean. That is the same fault as BUG-10 -- full confidence on a
        # session the check never saw -- arriving through the tool NAMES rather
        # than through a missing field, so nothing about the input looks wrong.
        ambiguous = ambiguous_disclosures(session)
        conf = corr_conf * class_conf
        if ambiguous:
            conf *= 1.0 - len(ambiguous) / len(session.consequential_calls)
        contracts.append(CheckContract(
            check="CH02_concealment_gap",
            status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
            confidence=conf, required_surfaces=required,
            present_surfaces=required, missing_surfaces=[],
            reasons=(common_reasons + class_reasons()
                     + ([R_AMBIGUOUS_DISCLOSURE] if ambiguous else [])),
            remedies=(["Supply a capability manifest so consequential calls are "
                       "identified by declaration rather than by name."]
                      if unknown or heuristic else [])
            + ([f"{len(ambiguous)} call(s) share every mentioned token with "
                "another tool in this session, so disclosure cannot be "
                "attributed: "
                + ", ".join(sorted({c.name for c in ambiguous})[:5])
                + ". Shared-prefix tool suites defeat lexical matching; this "
                "needs semantic disclosure matching, not a longer keyword list."]
               if ambiguous else []),
            assumptions=["Lexical disclosure matching. An honest paraphrase reads "
                         "as concealment; see EVASION.md E04.",
                         "A mention that cannot be told apart from a sibling "
                         "tool's is neither disclosure nor concealment; see "
                         "EVASION.md E16."]))

    # ---- CH03 -----------------------------------------------------------
    required = [SURFACE_INJECTION_SCANNER, SURFACE_TOOL_CLASS, SURFACE_EVENT_CLOCK,
                SURFACE_CORRELATION_KEY]
    if not scanner:
        contracts.append(CheckContract(
            check=CH03_FAMILY, status=STATUS_NOT_EVALUATED, confidence=0.0,
            required_surfaces=required,
            present_surfaces=[SURFACE_TOOL_CLASS, SURFACE_EVENT_CLOCK,
                              SURFACE_CORRELATION_KEY],
            missing_surfaces=[SURFACE_INJECTION_SCANNER],
            reasons=[R_NO_SCANNER],
            # F-16. The second half of this used to read "or capture
            # tool_result so Cohaera can scan locally", and Cohaera does not
            # scan locally. An operator who captured the result got the same
            # not_evaluated verdict, the same remedy, and no way to find out
            # why. A remedy that does not work is worse than no remedy: it
            # spends the operator's effort and their trust.
            #
            # Not replaced with a local scanner. Cohaera VERIFIES evidence and
            # does not manufacture it, and a regex pass of its own would be a
            # new source of exactly the false confidence E09 already describes
            # -- with the added problem that the detector would then be
            # grading its own scanner's output.
            remedies=["Emit has_injection_patterns on the events whose results "
                      "were scanned, from a scanner that runs where the content "
                      "arrives. Cohaera does not scan content itself: capturing "
                      "tool_result does not enable this check, and a detector "
                      "that generated its own taint evidence would be grading "
                      "its own work."],
            assumptions=["No marker field in the stream means no scanner ran, not "
                         "that nothing was found; see EVASION.md E09."]))
    else:
        # COH-R09. Both of these were all-or-nothing over the whole session and
        # both were satisfied by a single event. They are now shares over the
        # calls that can bring untrusted content in.
        #
        # The scanner share multiplies directly, as CH07's receipt share does,
        # because it is the same quantity: how much of the surface this check
        # exists to watch was actually watched. The result share keeps the
        # endpoints the boolean had -- 1.0 with every read captured, 0.8 with
        # none -- and grades between them, because a missing tool_result costs
        # CH03 provenance rather than the ability to run.
        scan = _scanner_coverage(session)
        result_share = _result_share(session)
        conf = (corr_conf * class_conf * clock_conf
                * scan.share * (0.8 + 0.2 * result_share))
        reasons = common_reasons + class_reasons()
        if result_share < 1.0:
            reasons.append(R_NO_TOOL_RESULT)
        if not scan.complete:
            reasons.append(R_SCANNER_PARTIAL)
        # COH-R11. This check IS an ordering, so a call whose order against the
        # marker cannot be established is a call it has not checked. Scored the
        # same way E16's ambiguity is scored for CH02: the share of the
        # consequential calls the check could not place.
        unordered = unordered_after_marker(session)
        if unordered:
            conf *= 1.0 - len(unordered) / len(session.consequential_calls)
            reasons.append(R_ORDER_INDETERMINATE)
        contracts.append(CheckContract(
            check=CH03_FAMILY,
            status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
            confidence=conf, required_surfaces=required,
            present_surfaces=required,
            missing_surfaces=([] if result_share >= 1.0
                              else [SURFACE_TOOL_RESULT]),
            reasons=reasons,
            remedies=([f"{scan.scannable - scan.scanned} of {scan.scannable} "
                       "call(s) that could return untrusted content carry no "
                       "scanner answer, so CH03 has no view of what came back "
                       "through them."] if scan.scanned < scan.scannable else [])
            + ([f"{scan.unbound} scanner answer(s) name no call in this "
                "session, so what they examined cannot be established."]
               if scan.unbound else [])
            + (["Set capture_tool_data=True in a controlled environment so "
                "marker provenance can be checked against the content."]
               if result_share < 1.0 else [])
            + ([f"{len(unordered)} consequential call(s) share the marker's "
                "tick and carry no cohaera.integrity:1 sequence, so their "
                "order against it is not established. Emit the integrity "
                "sidecar, or stamp at finer resolution."] if unordered else []),
            assumptions=["Temporal order, not information flow. Reordering the "
                         "read and the action defeats it; see EVASION.md E07.",
                         "Equal timestamps are not an ordering. Where a signed "
                         "collector sequence is absent, a tie is reported "
                         "rather than resolved; see COH-R11.",
                         "A scanner answer is evidence about the call it names "
                         "and no other; an unscanned read is unexamined, not "
                         "clean. See COH-R09."]))

    # ---- CH04 -----------------------------------------------------------
    # EXTERNAL-01 -- the first defect found by pointing this detector at
    # somebody else's traces rather than at the corpus it ships with. The
    # internal corpus always emits policy events, so it could not have found
    # this one. The required list is UNCONDITIONAL, and the `if has_policy`
    # guard that used to build it was the coverage contract inverted.
    #
    # CH04 asks whether a control fired and whether consequential work carried
    # on past it. Answering that at all needs two things: that controls exist,
    # and whether they are advisory or blocking. Gating the requirement on
    # `has_policy` made those two surfaces free in exactly the state where
    # neither is established -- a session with no policy events and no
    # approvals required nothing beyond tool class, clock and correlation, so
    # it reported `evaluated` at confidence 1.0 with an empty `missing` list.
    # Full confidence precisely where there was nothing to be confident about,
    # and it is not a rare corner: it is every public trace corpus and every
    # deployment that has not wired up a policy engine. CH06 and CH07 have
    # always declined in the equivalent state and named the surface they were
    # short of; CH04 alone reported a clean bill of health for being blind.
    #
    # A surface a check needs is a surface it needs whether or not the session
    # happens to supply it. That is what makes the contract auditable: the
    # required list is the check's standing bill of materials, and only
    # `missing` is allowed to vary with the data.
    required = [SURFACE_TOOL_CLASS, SURFACE_EVENT_CLOCK, SURFACE_CORRELATION_KEY,
                SURFACE_POLICY_SEMANTICS, SURFACE_APPROVAL]
    conf = corr_conf * class_conf * clock_conf
    reasons = common_reasons + class_reasons()
    remedies = []
    missing = []
    assumptions = ["A policy event is a log line. Whether it was enforced is "
                   "not stated by this telemetry."]
    # No firing in this session. Two different worlds produce that, and the old
    # code collapsed them into the flattering one:
    #
    #   1. the agent is governed and nothing tripped -- CH04 looked and found
    #      nothing, which is a result;
    #   2. the agent has no policy instrumentation at all -- CH04 could not
    #      look, which is not.
    #
    # Nothing in the event stream separates them, because both are an absence.
    # The only thing that can is the operator's manifest: a `policies` section
    # is an out-of-band declaration that these controls exist and what they do
    # when they fire, and it outranks the event for the same reason it does in
    # _resolved_enforcement -- the operator chose the file, the agent wrote the
    # event. With one, silence is world 1 and CH04 reports a result. Without
    # one, silence is uninterpretable and CH04 says so.
    declared_policies = len(session.manifest.policies)
    if not has_policy:
        if not declared_policies:
            contracts.append(CheckContract(
                check=CH04_FAMILY, status=STATUS_NOT_EVALUATED, confidence=0.0,
                required_surfaces=required,
                present_surfaces=[SURFACE_TOOL_CLASS, SURFACE_EVENT_CLOCK,
                                  SURFACE_CORRELATION_KEY],
                missing_surfaces=([SURFACE_POLICY_SEMANTICS]
                                  + ([] if session.approvals
                                     else [SURFACE_APPROVAL])),
                reasons=[R_NO_POLICY_EVIDENCE],
                remedies=[
                    "Emit policy decisions as cost_threshold_exceeded or "
                    "depth_exceeded events, so CH04 can see that a control "
                    "fired at all.",
                    "Declare the controls in the capability manifest's "
                    "'policies' section. That is what tells Cohaera the "
                    "difference between a guardrail that did not trip and a "
                    "deployment with no guardrails in it -- and it is the "
                    "operator's statement rather than the agent's."],
                assumptions=[
                    "No policy event and no declared control is not a quiet "
                    "session, it is an unmonitored one. Cohaera cannot tell a "
                    "governed agent that stayed inside its limits from an "
                    "agent with no limits, and reports neither."]))
        else:
            # World 1, and the approval surface is vacuous rather than absent:
            # no control fired, so there was no continuation for an approval to
            # authorise. Charging for the missing approvals here would be the
            # mirror of the bug above -- penalising a session for not carrying
            # evidence about an event that never happened. Compare
            # ScannerCoverage.share: 1.0 when there is nothing to scan.
            #
            # No reason code for this one. Reason codes in this file name what
            # Cohaera did not get; "the declared control did not fire" is a
            # result, and the place for a statement about what a result rests
            # on is the assumptions list.
            assumptions.append(
                f"{declared_policies} control(s) are declared in the "
                "capability manifest and none of them fired in this session, "
                "so CH04 looked and found nothing. The manifest establishes "
                "that the controls exist; it does not establish that this "
                "producer emits an event when one trips.")
            contracts.append(CheckContract(
                check=CH04_FAMILY,
                status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
                confidence=conf, required_surfaces=required,
                present_surfaces=required, missing_surfaces=[],
                reasons=reasons, remedies=remedies, assumptions=assumptions))
    else:
        semantics = _policy_semantics(session)
        if semantics["undeclared"]:
            # Nothing declares whether this policy event is advisory or
            # blocking, so Cohaera can report the sequence but not attribute a
            # bypass. This was BUG-09's whole substance and it is now the
            # fallback rather than the only behaviour.
            conf *= 0.6
            reasons.append(R_NO_POLICY_SEMANTICS)
            missing.append(SURFACE_POLICY_SEMANTICS)
            remedies.append(
                "Declare per-policy semantics (advisory or blocking), either on "
                "the policy event as cohaera.approval:1 'enforcement' or in the "
                "capability manifest's 'policies' section, so a continuation can "
                "be called a bypass.")
        elif semantics["in_band_only"]:
            # Declared, but by the thing being watched. Believing it is a
            # choice, and a check that suppresses findings on the strength of
            # an in-band flag has to say so rather than quietly benefit.
            conf *= 0.85
            reasons.append(R_ENFORCEMENT_FROM_PRODUCER)
            remedies.append(
                "Declare these policies in the capability manifest. An "
                "'advisory' value on the event SUPPRESSES this check, and it "
                "arrives from the same path an attacker controls (EVASION.md "
                "E20).")
            assumptions.append(
                "Policy semantics were taken from the producer's own event. An "
                "agent that declares a blocking control advisory silences CH04.")
        if not session.approvals:
            conf *= 0.8
            reasons.append(R_NO_APPROVAL_EVIDENCE)
            missing.append(SURFACE_APPROVAL)
            remedies.append(
                "Emit cohaera.approval:1 bound to the span and argument digest "
                "so an authorised continuation can be told from a bypass.")
        elif any(m.binding == BOUND_SPAN_ONLY
                 for c in session.consequential_calls
                 for m in session.approvals_for(c)):
            conf *= 0.9
            reasons.append(R_APPROVAL_NOT_ARGUMENT_BOUND)
            assumptions.append(
                "At least one approval bound by span alone. An approval for "
                "send_email to one recipient then covers send_email to any "
                "recipient, which is the failure argument binding exists to "
                "prevent.")
        if session.dangling_approvals:
            reasons.append(R_DANGLING_APPROVAL)
        # COH-R11. The tie that used to be silent. A producer stamping its
        # consequential calls on the guardrail's own tick emptied CH04's
        # candidate list and the check said nothing at all; the share it could
        # not place now costs it confidence and names itself.
        unordered = unordered_after_policy(session)
        if unordered:
            conf *= 1.0 - len(unordered) / len(session.consequential_calls)
            reasons.append(R_ORDER_INDETERMINATE)
            remedies.append(
                f"{len(unordered)} consequential call(s) share a policy "
                "event's tick and carry no cohaera.integrity:1 sequence, so "
                "whether they ran after the control is not established. Emit "
                "the integrity sidecar, or stamp at finer resolution.")
            assumptions.append(
                "Equal timestamps are not an ordering. A call sharing the "
                "control's tick is neither a continuation nor a precursor; "
                "see COH-R11.")
        contracts.append(CheckContract(
            check=CH04_FAMILY,
            status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
            confidence=conf, required_surfaces=required,
            present_surfaces=[s for s in required if s not in missing],
            missing_surfaces=missing, reasons=reasons,
            remedies=remedies, assumptions=assumptions))

    # ---- CH06 -----------------------------------------------------------
    audit = session.integrity or SessionIntegrity()
    required = [SURFACE_EVENT_INTEGRITY]
    if audit.with_integrity == 0:
        # THE DEFAULT STATE, and the one every current deployment is in. It is
        # reported as a stated absence rather than a pass, for the same reason
        # CH01's vocabulary contract and CH03's scanner contract are: "Cohaera
        # did not detect tampering" and "Cohaera was never in a position to
        # detect tampering" are different sentences and only one of them is
        # true here.
        contracts.append(CheckContract(
            check=CH06_INTEGRITY, status=STATUS_NOT_EVALUATED, confidence=0.0,
            required_surfaces=required, present_surfaces=[],
            missing_surfaces=required, reasons=[R_NO_INTEGRITY],
            remedies=["Run a collector that adds cohaera.integrity:1 to each "
                      "record before it leaves the host, and supply its public "
                      "key with --trust-store."],
            assumptions=["No integrity evidence means tampering was not ruled "
                         "out, not that it was ruled out."]))
    else:
        int_reasons = sorted(audit.codes)
        int_remedies: list[str] = []
        int_assumptions = [
            "Verification is against a key the OPERATOR supplied. It says these "
            "records are the ones that collector wrote; it does not say the "
            "collector was truthful.",
            "A collector running in the agent's own process is inside the blast "
            "radius, and this check gains nothing in that deployment.",
        ]
        conf = 1.0
        if audit.without_integrity:
            conf *= 0.5
        if audit.signatures_verified == 0:
            # A chain with nothing to verify it against establishes internal
            # consistency and nothing about origin: anyone who can rewrite a
            # record can rewrite the chain over it.
            conf *= 0.6
            int_remedies.append(
                "Supply the collector's public key with --trust-store. An "
                "unsigned chain proves the stream is self-consistent, which an "
                "attacker who rewrote the whole stream can also arrange.")
        elif not audit.signature_covers_final:
            # R-05. Signed, and not to the end. The share is the honest
            # multiplier because it is literally how much of this session a
            # signature reaches -- and there was no term for it at all, so a
            # stream signed at sequence 0 and 100 of 149 scored 1.0.
            share = audit.signature_coverage
            conf *= share
            int_reasons.append(R_SIGNATURE_PREFIX_ONLY)
            unattested = [
                f"{r['stream_id']}: signed to "
                f"{r['verified_to'] if r['verified_to'] is not None else 'nothing'}"
                f" of {r['last_seq']}"
                for r in audit.signature_ranges
                if r["verified_to"] is None or r["verified_to"] < r["last_seq"]]
            int_remedies.append(
                "Sign the final record of each stream, or set the collector's "
                "sampling so the last record is always a signing position. A "
                "signature covers the chain head at its own sequence and "
                "nothing after it, so records past the last one are chained "
                "and unattested (" + "; ".join(unattested[:3]) + ").")
            int_assumptions.append(
                f"A verified signature reaches {share:.0%} of this session's "
                f"attested records. The remainder is self-consistent and "
                f"vouched for by nobody.")
        # Replay is the one attack every other check here is blind to by
        # construction, because a replayed stream is a genuine stream. Whether
        # it was even considered is a property of how the run was invoked, so it
        # belongs in the contract rather than in a finding.
        if audit.freshness_checked:
            int_assumptions.append(
                "Freshness is judged from the timestamp the collector signed. A "
                "replayer can re-send those bytes and cannot re-date them, but a "
                "stream replayed INSIDE the bound is indistinguishable from a "
                "fresh one; comparing stream_summary across runs is what catches "
                "that.")
        else:
            conf *= 0.8
            int_reasons.append(R_NO_FRESHNESS_BOUND)
            int_remedies.append(
                "Set --evidence-max-age so that re-feeding an archived stream is "
                "detectable. Without it, a captured stream replayed months later "
                "passes every check in this module, because it really was "
                "written by that collector.")
            int_assumptions.append(
                "No freshness bound was in force, so this session was not "
                "checked for stream replay at all.")
        # The seen-stream ledger. Freshness bounds how OLD a stream may be;
        # this is the only thing that bounds how many TIMES it is scored, and
        # whether it was in force is a property of the invocation.
        if R_NO_STREAM_LEDGER in audit.codes:
            conf *= 0.9
            int_reasons.append(R_NO_STREAM_LEDGER)
            int_remedies.append(
                "Pass --seen-streams to keep a ledger of streams already "
                "scored. It is the only check that sees a stream re-fed INSIDE "
                "the freshness window, which every other check passes because "
                "the replayed stream is genuine.")
            int_assumptions.append(
                "No ledger was in force, so a stream scored by a previous run "
                "was scored again as if new.")
        else:
            int_assumptions.append(
                "The seen-stream ledger is unsigned local state. It detects a "
                "replay to THIS host; an attacker who can delete the file, or "
                "who replays to a different Cohaera host, defeats it "
                "(EVASION.md E22).")
        if R_STREAM_SKIPPED_RECORDS in audit.codes:
            int_reasons.append(R_STREAM_SKIPPED_RECORDS)
            int_assumptions.append(
                "Records between the last scored sequence and this run's first "
                "were never scored. That is deletion or a deliberate subset, "
                "and this cannot tell them apart.")
        if audit.inadmissible:
            conf = 0.0
        contracts.append(CheckContract(
            check=CH06_INTEGRITY,
            status=(STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED),
            confidence=conf, required_surfaces=required,
            present_surfaces=required, missing_surfaces=[],
            reasons=sorted(set(int_reasons)), remedies=int_remedies,
            assumptions=int_assumptions))

    # ---- CH07 -----------------------------------------------------------
    required = [SURFACE_EFFECT_RECEIPT, SURFACE_TOOL_CLASS]
    # COH-R12, second half. This was `_receipted_calls(session)` -- every call
    # carrying a receipt, including read-only ones -- measured against a
    # denominator of consequential calls only. The share could exceed 1.0 and
    # was clamped back to "fully covered", so a session whose single egress
    # call had no receipt at all was reported EVALUATED at confidence 1.0
    # because three read-only calls carried receipts. Read-only receipts are
    # not evidence about the consequential surface and cannot buy coverage for
    # it.
    #
    # The population is consequential OR UNKNOWN, and the second half of that
    # is not a detail. Scoping it to `consequential_calls` alone was the first
    # attempt, and it was the rule-4 error in a new place: `unknown` does not
    # mean "not consequential", it means Cohaera could not tell. Under the
    # name_only condition every receipted call classifies as unknown, so that
    # version reported CH07 not_evaluated on 64 corpus sessions where CH07 had
    # just produced a finding -- a check declaring itself blind and detecting
    # something in the same verdict. `read_only` is excluded because it is a
    # positive classification; `unknown` is the absence of one.
    #
    # ch07_effect_contradiction still reads every receipted call: a contradicted
    # receipt on a read-only call is a producer contradicting itself and is
    # still worth reporting. This is the coverage question only.
    effectful = [c for c in session.tool_calls
                 if c.consequential or c.klass == "unknown"]
    receipted = [c for c in effectful if c.receipt is not None]
    effectful_total = len(effectful)
    if not receipted:
        contracts.append(CheckContract(
            check=CH07_FAMILY, status=STATUS_NOT_EVALUATED, confidence=0.0,
            required_surfaces=required, present_surfaces=[SURFACE_TOOL_CLASS],
            missing_surfaces=[SURFACE_EFFECT_RECEIPT],
            reasons=[R_NO_EFFECT_RECEIPT],
            remedies=["Surface the identifier the target system returned -- a "
                      "Message-ID, a version ID, a transaction ID -- as "
                      "cohaera.receipt:1 bound to the call."],
            assumptions=["A reported success with no receipt is the agent's "
                         "claim about itself and is not checkable here."]))
    else:
        # Confidence is the SHARE of possibly-effectful calls carrying a
        # receipt, because that is literally how much of the session this check
        # could look at. A mixed deployment -- and every real one is mixed for a
        # long time -- lands in the middle and says so.
        #
        # `receipted` is a subset of the calls being divided by, so the share
        # is a share. It reaches this line already bounded by 1.0 rather than
        # being clamped to it -- the clamp that used to be here is what let the
        # mismatched populations above pass for full coverage.
        share = len(receipted) / effectful_total
        conf = share * corr_conf * class_conf
        r7 = common_reasons + class_reasons()
        if share < 1.0:
            r7.append(R_NO_EFFECT_RECEIPT)
        # R-01. The share of receipts that could actually carry the check's one
        # conclusion. A receipt bound by span alone cannot establish that an
        # effect belongs to the call it arrived on, so it buys presence, not
        # coverage -- and the difference has to reach the contract, or a
        # deployment that emits partial bindings everywhere reads as fully
        # evaluated while CH07 is structurally unable to fire.
        #
        # Half weight per loose receipt, not zero, and the difference is a real
        # distinction rather than a fudge. A span-only receipt cannot carry the
        # contradiction -- but CH07 still reads it and still reports on it, as
        # CH07_PARTIAL and as CH07_UNBOUND when it names a different call. A
        # session with nothing but loose receipts is degraded, not blind, and
        # scoring it 0.0 would put a not_evaluated contract in the same verdict
        # as a finding the check had just produced.
        loose = [c for c in receipted
                 if _receipt_binding(c) in BINDING_CONTEXT]
        if loose:
            r7.append(R_RECEIPT_NOT_ARGUMENT_BOUND)
            conf *= 1.0 - 0.5 * len(loose) / len(receipted)
        if any(c.arg_digest_disagrees for c in session.tool_calls):
            conf *= 0.5
            r7.append(R_ARG_DIGEST_CONTRADICTS)
        remedies = []
        if share < 1.0:
            remedies.append(
                f"{effectful_total - len(receipted)} consequential or "
                "unclassified call(s) carry no receipt; their reported "
                "outcome is unfalsifiable.")
        if loose:
            remedies.append(
                f"{len(loose)} receipt(s) name the span but not the argument "
                "digest. A receipt that does not constrain the arguments "
                "cannot establish that an effect belongs to this call; emit "
                "arg_digest on the binding.")
        contracts.append(CheckContract(
            check=CH07_FAMILY,
            status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
            confidence=conf, required_surfaces=required,
            present_surfaces=required, missing_surfaces=[],
            reasons=r7,
            remedies=remedies,
            assumptions=["A receipt is not verified with the authority that "
                         "minted it. Cohaera is offline; it checks that the "
                         "receipt BINDS to this call, not that it is real."]))

    # ---- CH05 -----------------------------------------------------------
    required = [SURFACE_TOOL_LIFECYCLE, SURFACE_CORRELATION_KEY]
    conf = corr_conf * (1.0 if not unknown else class_conf)
    contracts.append(CheckContract(
        check="CH05_unpaired_calls",
        status=STATUS_EVALUATED if conf >= 1.0 else STATUS_DEGRADED,
        confidence=conf, required_surfaces=required, present_surfaces=required,
        missing_surfaces=[], reasons=common_reasons + (
            [R_UNKNOWN_CLASS] if unknown else []),
        remedies=[], assumptions=[
            "Pairing integrity is an integrity signal about the telemetry, not "
            "about the agent. A fabricated terminal event defeats it; see "
            "EVASION.md E11."]))

    evaluated = sum(1 for c in contracts if c.status == STATUS_EVALUATED)
    degraded = sum(1 for c in contracts if c.status == STATUS_DEGRADED)
    not_evaluated = sum(1 for c in contracts if c.status == STATUS_NOT_EVALUATED)
    completeness = (sum(c.confidence for c in contracts) / len(contracts)
                    if contracts else 0.0)

    return {
        "schema": COVERAGE_SCHEMA,
        # R-05, second half. `evidence_status` was stamped on every FINDING and
        # nowhere else, so a session that triggered nothing said nothing about
        # whether its own telemetry had been established -- and the quiet
        # session is exactly where it matters. "This agent did nothing unusual"
        # rests on records, and a reader has no way to ask which ones unless
        # something happens to have gone wrong. It belongs in coverage because
        # it is the same kind of statement as the rest of this object: not what
        # the agent did, but how much of the answer Cohaera was in a position
        # to give.
        "evidence_status": evidence_status(session),
        "checks_total": len(contracts),
        "checks_evaluated": evaluated,
        "checks_degraded": degraded,
        "checks_not_evaluated": not_evaluated,
        # Confidence-weighted, NOT a count of checks that did not error. A
        # detector operating on semantics it does not have contributes a
        # fraction of a point, not a whole one.
        "completeness": round(completeness, 3),
        "correlation_kind": corr_kind,
        "correlation_confidence": round(corr_conf, 3),
        # Worst case, not average: see _classification_quality. The share is
        # the average, kept as a diagnostic because "one unknown call" and
        # "forty unknown calls" are different operational situations and the
        # worst case cannot tell them apart.
        "classification_confidence": round(class_conf, 3),
        "classification_share": round(class_share, 3),
        "clock_confidence": round(clock_conf, 3),
        "unknown_class_calls": unknown,
        "heuristic_class_calls": heuristic,
        "manifest_class_calls": manifest_hits,
        "checks": [c.as_dict() for c in contracts],
        # Kept for content written against coverage:1. Same information, flat.
        "gaps": [
            {"check": c.check, "status": c.status,
             "reason": "; ".join(c.reasons) or "none",
             "remedy": "; ".join(c.remedies) or "none"}
            for c in contracts if c.status != STATUS_EVALUATED
        ],
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = ["CH01_sequence_order", "CH02_concealment_gap",
              CH03_COMPLETED, CH03_ATTEMPTED,
              CH04_COMPLETED, CH04_ATTEMPTED, CH04_BYPASSED,
              "CH05_unpaired_calls",
              CH06_INTEGRITY,
              CH07_CONTRADICTED, CH07_UNBOUND, CH07_PARTIAL]

# check id -> the coverage contract that governs it
CHECK_FAMILIES = {
    "CH01_sequence_order": "CH01_sequence_order",
    "CH02_concealment_gap": "CH02_concealment_gap",
    CH03_COMPLETED: CH03_FAMILY,
    CH03_ATTEMPTED: CH03_FAMILY,
    CH04_COMPLETED: CH04_FAMILY,
    CH04_ATTEMPTED: CH04_FAMILY,
    CH04_BYPASSED: CH04_FAMILY,
    "CH05_unpaired_calls": "CH05_unpaired_calls",
    CH06_INTEGRITY: CH06_INTEGRITY,
    CH07_CONTRADICTED: CH07_FAMILY,
    CH07_UNBOUND: CH07_FAMILY,
    CH07_PARTIAL: CH07_FAMILY,
}


def run_all(session: Session, grammar: SequenceGrammar | None = None,
            limits: Limits = DEFAULT_LIMITS
            ) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    findings += ch01_sequence_order(session, grammar, limits=limits)
    findings += ch02_concealment_gap(session, limits=limits)
    findings += ch03_untrusted_to_consequential(session, limits=limits)
    findings += ch04_guardrail_overrun(session, limits=limits)
    findings += ch05_unpaired_calls(session, limits=limits)
    findings += ch06_evidence_integrity(session, limits=limits)
    findings += ch07_effect_contradiction(session, limits=limits)

    cov = coverage(session, grammar, limits=limits)
    # Attach the governing contract's confidence to each finding, so a verdict
    # read on its own still says how much of it rests on guesswork.
    by_check = {c["check"]: c["confidence"] for c in cov["checks"]}
    # ...and how far the telemetry underneath it was itself established. A
    # finding on an inadmissible stream is a finding about a record somebody
    # could have written, and it should not arrive looking like one that
    # chained and verified. CH06's own finding is exempt: it IS the statement
    # that the evidence failed, and marking it as resting on failed evidence
    # would be circular.
    status = evidence_status(session)
    for f in findings:
        f.confidence = by_check.get(f.family, by_check.get(f.check, 1.0))
        f.evidence_status = (EVIDENCE_NOT_APPLICABLE if f.check == CH06_INTEGRITY
                             else status)
    return findings, cov
