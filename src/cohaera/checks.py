"""Correlation checks.

Every check in here needs to see more than one event. That is the whole point:
observra's ``evaluate_rules(event_type, data)`` is single-event by signature, so
none of these can be expressed upstream today.

Each check returns zero or more Findings. A check that cannot run says so via
``coverage()`` rather than silently returning clean, because a check that cannot
see its inputs is not the same as a check that passed.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Iterable

from .model import Finding, Session, ToolCall

# ---------------------------------------------------------------------------
# CH01  Sequence order violation
# ---------------------------------------------------------------------------


class SequenceGrammar:
    """A bigram model over tool-call order, mined from benign sessions.

    Deliberately the simplest thing that can detect ordering rather than
    co-occurrence. observra's own (unreachable) detect_suspicious_sequence()
    checks ``has_read AND has_external`` over the whole session, which is a set
    membership test with no notion of order at all.
    """

    START = "<START>"
    END = "<END>"

    def __init__(self) -> None:
        self.bigrams: Counter[tuple[str, str]] = Counter()
        self.unigrams: Counter[str] = Counter()
        self.sessions_fitted = 0

    def fit(self, sessions: Iterable[Session]) -> "SequenceGrammar":
        for s in sessions:
            seq = [self.START, *s.tool_sequence, self.END]
            for a, b in zip(seq, seq[1:]):
                self.bigrams[(a, b)] += 1
            for t in seq:
                self.unigrams[t] += 1
            self.sessions_fitted += 1
        return self

    def score(self, session: Session) -> tuple[float, list[tuple[str, str]]]:
        """Return (violation_rate, unseen_transitions)."""
        seq = [self.START, *session.tool_sequence, self.END]
        transitions = list(zip(seq, seq[1:]))
        if not transitions:
            return 0.0, []
        unseen = [t for t in transitions if self.bigrams[t] == 0]
        return len(unseen) / len(transitions), unseen

    @property
    def fitted(self) -> bool:
        return self.sessions_fitted > 0


def ch01_sequence_order(session: Session, grammar: SequenceGrammar | None,
                        threshold: float = 0.25) -> list[Finding]:
    if grammar is None or not grammar.fitted:
        return []
    rate, unseen = grammar.score(session)
    if rate <= threshold or not unseen:
        return []

    total_transitions = len(session.tool_sequence) + 1  # START..seq..END
    novel_tools = sorted({b for _, b in unseen
                          if b not in grammar.unigrams or grammar.unigrams[b] == 0})
    sev = "high" if novel_tools else "medium"
    return [Finding(
        check="CH01_sequence_order",
        severity=sev,
        session_id=session.session_id,
        title="Tool-call ordering deviates from the learned benign grammar",
        detail=(
            f"{len(unseen)} of {total_transitions} transitions were never observed "
            f"in {grammar.sessions_fitted} benign sessions "
            f"(violation rate {rate:.2f}, threshold {threshold})."
            + (f" Tools never seen in any benign session: {', '.join(novel_tools)}."
               if novel_tools else "")
        ),
        evidence={
            "violation_rate": round(rate, 4),
            "unseen_transitions": [f"{a} -> {b}" for a, b in unseen],
            "novel_tools": novel_tools,
            "observed_sequence": session.tool_sequence,
            "baseline_sessions": grammar.sessions_fitted,
        },
    )]


# ---------------------------------------------------------------------------
# CH02  Concealment gap: did the agent report what it actually did?
# ---------------------------------------------------------------------------

_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return {t for t in _SPLIT.split(text.lower()) if len(t) > 2}


def _referenced(call: ToolCall, response_tokens: set[str]) -> bool:
    """Crude reference test: do the tool name's word parts appear in the summary?

    LIMITATION, stated plainly: this is lexical, not semantic. An agent that
    says "I have emailed the report" without naming send_email will read as a
    concealment gap here. v2 should use an LLM judge, and will then inherit the
    judge's error rate. C-Trace (arXiv:2606.19242) measured exactly this: monitor
    accuracy is bounded by the field extractor. Report the bound, do not hide it.
    """
    parts = {p for p in _SPLIT.split(call.name.lower()) if len(p) > 2}
    return bool(parts & response_tokens)


def ch02_concealment_gap(session: Session) -> list[Finding]:
    response = session.final_response
    if response is None:
        return []          # not clean: see coverage()

    consequential = session.consequential_calls
    if not consequential:
        return []

    rtok = _tokens(response)
    unreported = [c for c in consequential
                  if c.result == "success" and not _referenced(c, rtok)]
    if not unreported:
        return []

    has_egress = any(c.klass == "egress" for c in unreported)
    return [Finding(
        check="CH02_concealment_gap",
        severity="critical" if has_egress else "high",
        session_id=session.session_id,
        title="Consequential tool calls absent from the agent's final response",
        detail=(
            f"{len(unreported)} of {len(consequential)} consequential calls succeeded "
            "but are not referenced in the final user-facing message. The human in "
            "the loop reads the summary, so an unreported state change or egress "
            "removes the human control without removing the appearance of it."
        ),
        evidence={
            "unreported_calls": [
                {"tool": c.name, "class": c.klass, "at": c.started_at}
                for c in unreported
            ],
            "consequential_total": len(consequential),
            "response_length": len(response),
        },
    )]


# ---------------------------------------------------------------------------
# CH03  Untrusted content observed, then a consequential action
# ---------------------------------------------------------------------------


def ch03_untrusted_to_consequential(session: Session) -> list[Finding]:
    """Simplified taint flow.

    Full information-flow control (Fides arXiv:2505.23643, CaMeL arXiv:2503.18813)
    labels every value. That needs instrumentation Cohaera does not have. What it
    does have is: the timestamp at which an injection marker was observed, and the
    timestamps of consequential calls. Ordering those two is a cheap, honest
    approximation with a real false-positive story.
    """
    marker_times = [
        e.timestamp for e in session.events
        if e.data.get("injection_patterns") or e.data.get("has_injection_patterns")
    ]
    if not marker_times:
        return []

    first_marker = min(marker_times)
    after = [c for c in session.consequential_calls if c.started_at >= first_marker]
    if not after:
        return []

    return [Finding(
        check="CH03_untrusted_to_consequential",
        severity="critical" if any(c.klass == "egress" for c in after) else "high",
        session_id=session.session_id,
        title="Consequential action followed observed injection markers",
        detail=(
            f"Injection markers were flagged at t={first_marker:.3f}, and "
            f"{len(after)} consequential call(s) ran afterwards in the same session. "
            "This does not prove causation. It marks the session as one where "
            "untrusted content and a state change coexist in the wrong order, "
            "which is the sequence a human should review."
        ),
        evidence={
            "markers": session.injection_markers,
            "first_marker_ts": first_marker,
            "calls_after": [{"tool": c.name, "class": c.klass, "at": c.started_at}
                            for c in after],
        },
    )]


# ---------------------------------------------------------------------------
# CH04  Guardrail fired and the session continued
# ---------------------------------------------------------------------------


def ch04_guardrail_overrun(session: Session) -> list[Finding]:
    """A policy event fired, and consequential work happened after it.

    observra emits cost_threshold_exceeded and depth_exceeded as policy_event
    actions. Nothing upstream asks the obvious follow-up question: did anything
    keep happening? A guardrail that fires and is then ignored is worse than no
    guardrail, because it produces a log line that looks like a control.
    """
    findings: list[Finding] = []
    for e in session.events:
        if e.event_type not in {"cost_threshold_exceeded", "depth_exceeded"}:
            continue
        after = [c for c in session.consequential_calls if c.started_at > e.timestamp]
        if not after:
            continue
        findings.append(Finding(
            check="CH04_guardrail_overrun",
            severity="high",
            session_id=session.session_id,
            title=f"Session continued with consequential actions after {e.event_type}",
            detail=(
                f"{e.event_type} fired at t={e.timestamp:.3f}, then "
                f"{len(after)} consequential call(s) executed. The control produced "
                "a log line but did not stop the behaviour."
            ),
            evidence={
                "policy_event": e.event_type,
                "policy_event_data": e.data,
                "calls_after": [{"tool": c.name, "class": c.klass} for c in after],
            },
        ))
    return findings


# ---------------------------------------------------------------------------
# CH05  Unpaired tool calls
# ---------------------------------------------------------------------------


def ch05_unpaired_calls(session: Session) -> list[Finding]:
    """tool_start with no terminal event.

    Integrity check on the telemetry itself. An unpaired consequential call means
    either the agent died mid-write, or the event was lost. Both matter, and the
    log cannot tell you which, which is exactly why it should be surfaced rather
    than silently dropped.
    """
    unpaired = [c for c in session.tool_calls if c.result is None]
    if not unpaired:
        return []
    consequential = [c for c in unpaired if c.consequential]
    return [Finding(
        check="CH05_unpaired_calls",
        severity="medium" if consequential else "low",
        session_id=session.session_id,
        title="Tool calls started with no terminal event",
        detail=(
            f"{len(unpaired)} tool call(s) have a tool_start with no tool_end or "
            f"tool_error, {len(consequential)} of them consequential. Either the "
            "run was truncated or events were dropped; the stream cannot "
            "distinguish these, so treat the session as incompletely observed."
        ),
        evidence={"unpaired": [{"tool": c.name, "class": c.klass, "at": c.started_at}
                               for c in unpaired]},
    )]


# ---------------------------------------------------------------------------
# Coverage: what could not be evaluated, and why
# ---------------------------------------------------------------------------


def coverage(session: Session, grammar: SequenceGrammar | None) -> dict[str, Any]:
    """Report Cohaera's own blind spots for this session.

    observra's examples/siem_parser.json carries a telemetry_completeness field
    described as "Use to weight anomaly detection confidence". This is that idea,
    made concrete per check. A detection that silently cannot run is a false
    negative wearing a green tick.
    """
    gaps: list[dict[str, str]] = []

    if session.final_response is None:
        gaps.append({
            "check": "CH02_concealment_gap",
            "status": "not_evaluated",
            "reason": (
                "No response_text on any model_response. observra strips strings on "
                "the hot path (core/hot_cold.py) and response_text is a claude-adapter "
                "extra, so the final user-facing message is not in this stream."
            ),
            "remedy": "Enable cold-path capture, or run the claude adapter.",
        })

    if not any(c.had_result for c in session.tool_calls) and session.tool_calls:
        gaps.append({
            "check": "CH02_concealment_gap",
            "status": "degraded",
            "reason": "No tool_result captured; capture_tool_data defaults to False.",
            "remedy": "Set capture_tool_data=True in a controlled environment.",
        })

    if grammar is None or not grammar.fitted:
        gaps.append({
            "check": "CH01_sequence_order",
            "status": "not_evaluated",
            "reason": "No benign baseline fitted. A grammar needs benign sessions first.",
            "remedy": "Fit on a labelled benign corpus before scoring.",
        })

    unknown = sum(1 for c in session.tool_calls if c.klass == "unknown")
    if unknown:
        gaps.append({
            "check": "classification",
            "status": "degraded",
            "reason": (
                f"{unknown} tool call(s) could not be classified as read_only, "
                "state_change or egress by name or by observra's reversible flag."
            ),
            "remedy": "Add these tool names to the classification map.",
        })

    evaluated = 5 - len({g["check"] for g in gaps if g["status"] == "not_evaluated"})
    return {
        "checks_total": 5,
        "checks_evaluated": max(evaluated, 0),
        "completeness": round(max(evaluated, 0) / 5, 2),
        "gaps": gaps,
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = ["CH01_sequence_order", "CH02_concealment_gap",
              "CH03_untrusted_to_consequential", "CH04_guardrail_overrun",
              "CH05_unpaired_calls"]


def run_all(session: Session,
            grammar: SequenceGrammar | None = None) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    findings += ch01_sequence_order(session, grammar)
    findings += ch02_concealment_gap(session)
    findings += ch03_untrusted_to_consequential(session)
    findings += ch04_guardrail_overrun(session)
    findings += ch05_unpaired_calls(session)
    return findings, coverage(session, grammar)
