"""Core data model for Cohaera.

Observra emits a flat, per-event stream. Its rule engine signature is
``evaluate_rules(event_type, data)``, which is stateless and cannot see two events.
Cohaera's job starts by giving the stream a shape: a Session, with derived
behavioural features that only exist once events are grouped.

Everything here is deliberately dependency-free stdlib so it runs anywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

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
EGRESS_KEYWORDS = {
    "http", "request", "post", "send", "webhook", "upload", "publish",
    "email", "message", "notify", "sync", "export", "transfer",
}

TERMINAL_EVENTS = {
    "model_response", "model_error", "turn", "tool_end", "tool_error",
    "agent_end", "agent_handoff_error",
}

POLICY_EVENTS = {"cost_threshold_exceeded", "depth_exceeded"}


def _classify(tool_name: str | None) -> str:
    """Classify a tool as read_only, state_change, or egress.

    Egress wins over state_change, because data leaving the boundary is the
    more consequential property for a concealment check.
    """
    if not tool_name:
        return "unknown"
    t = tool_name.lower()
    if any(k in t for k in EGRESS_KEYWORDS):
        return "egress"
    if any(k in t for k in IRREVERSIBLE_KEYWORDS):
        return "state_change"
    if any(k in t for k in REVERSIBLE_KEYWORDS):
        return "read_only"
    return "unknown"


@dataclass
class Event:
    """One observra CIM record, parsed but not interpreted."""

    raw: dict[str, Any]

    @property
    def event_type(self) -> str:
        return self.raw.get("event_type", "")

    @property
    def timestamp(self) -> float:
        return float(self.raw.get("timestamp") or 0.0)

    @property
    def data(self) -> dict[str, Any]:
        d = self.raw.get("data")
        return d if isinstance(d, dict) else {}

    @property
    def tool_name(self) -> str | None:
        return self.raw.get("tool_name")

    @property
    def agent_name(self) -> str | None:
        return self.raw.get("agent_name")

    def get(self, key: str, default: Any = None) -> Any:
        """Look in the envelope first, then the data bag."""
        if key in self.raw and self.raw[key] is not None:
            return self.raw[key]
        return self.data.get(key, default)


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

    @property
    def klass(self) -> str:
        """read_only | state_change | egress | unknown.

        Prefer observra's own ``reversible`` flag when present; fall back to
        name matching. Upstream truth beats our heuristic.
        """
        by_name = _classify(self.name)
        if self.reversible is False and by_name == "read_only":
            # observra says irreversible, our keyword said read. Trust observra.
            return "state_change"
        return by_name

    @property
    def consequential(self) -> bool:
        return self.klass in {"state_change", "egress"}


@dataclass
class Session:
    """A correlated agent session. This is the object observra never builds."""

    session_id: str
    events: list[Event] = field(default_factory=list)

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
        return next((e.raw.get("framework") for e in self.events
                     if e.raw.get("framework")), "unknown")

    @property
    def host(self) -> str | None:
        return next((e.raw.get("host") for e in self.events if e.raw.get("host")), None)

    @property
    def user(self) -> str | None:
        return next((e.raw.get("user") for e in self.events if e.raw.get("user")), None)

    # ---- time -----------------------------------------------------------
    @property
    def started_at(self) -> float:
        return min((e.timestamp for e in self.events), default=0.0)

    @property
    def ended_at(self) -> float:
        return max((e.timestamp for e in self.events), default=0.0)

    @property
    def duration_s(self) -> float:
        return round(self.ended_at - self.started_at, 3)

    # ---- tool calls -----------------------------------------------------
    @property
    def tool_calls(self) -> list[ToolCall]:
        """Pair tool_start with tool_end / tool_error.

        Pairing is by span_id where available, falling back to tool_name FIFO,
        because not every adapter propagates span_id consistently.
        """
        calls: list[ToolCall] = []
        open_by_span: dict[str, ToolCall] = {}
        open_by_name: dict[str, list[ToolCall]] = {}

        for e in sorted(self.events, key=lambda x: x.timestamp):
            if e.event_type == "tool_start":
                tc = ToolCall(
                    name=e.tool_name or "<unnamed>",
                    started_at=e.timestamp,
                    span_id=e.raw.get("span_id"),
                    reversible=e.data.get("reversible"),
                    had_args=e.data.get("tool_args") is not None,
                )
                calls.append(tc)
                if tc.span_id:
                    open_by_span[tc.span_id] = tc
                open_by_name.setdefault(tc.name, []).append(tc)

            elif e.event_type in {"tool_end", "tool_error"}:
                tc = None
                sid = e.raw.get("span_id")
                if sid and sid in open_by_span:
                    tc = open_by_span.pop(sid)
                else:
                    pending = open_by_name.get(e.tool_name or "<unnamed>", [])
                    tc = pending.pop(0) if pending else None

                if tc is None:
                    # tool_end with no matching start. Record it anyway; an
                    # unpaired terminal event is itself worth surfacing.
                    tc = ToolCall(name=e.tool_name or "<unnamed>",
                                  started_at=e.timestamp,
                                  span_id=sid)
                    calls.append(tc)

                tc.ended_at = e.timestamp
                tc.result = "failure" if e.event_type == "tool_error" else "success"
                tc.duration_ms = e.data.get("duration_ms")
                tc.error_class = e.data.get("error_class") or e.data.get("error_type_name")
                if e.data.get("reversible") is not None:
                    tc.reversible = e.data.get("reversible")
                tc.had_result = e.data.get("tool_result") is not None

        return calls

    @property
    def tool_sequence(self) -> list[str]:
        return [tc.name for tc in self.tool_calls]

    @property
    def consequential_calls(self) -> list[ToolCall]:
        return [tc for tc in self.tool_calls if tc.consequential]

    # ---- text surfaces (privacy-gated upstream) --------------------------
    @property
    def user_messages(self) -> list[str]:
        return [e.data["user_message_text"] for e in self.events
                if e.event_type == "user_message" and e.data.get("user_message_text")]

    @property
    def final_response(self) -> str | None:
        """Last model_response text, if the adapter captured it.

        observra strips strings on the hot path (core/hot_cold.py) and
        response_text is a claude-adapter extra, so this is frequently None.
        That absence is a finding, not an error. See checks.coverage.
        """
        texts = [e.data.get("response_text") for e in sorted(
            self.events, key=lambda x: x.timestamp)
            if e.event_type == "model_response" and e.data.get("response_text")]
        return texts[-1] if texts else None

    # ---- security-relevant counters -------------------------------------
    @property
    def injection_markers(self) -> list[str]:
        out: list[str] = []
        for e in self.events:
            pats = e.data.get("injection_patterns")
            if isinstance(pats, list):
                out.extend(pats)
            elif isinstance(pats, str) and pats:
                out.extend(p.strip() for p in pats.split(",") if p.strip())
        return out

    @property
    def max_delegation_depth(self) -> int:
        depths = [e.data.get("current_depth") for e in self.events
                  if isinstance(e.data.get("current_depth"), int)]
        return max(depths) if depths else 0

    @property
    def handoffs(self) -> list[tuple[str, str]]:
        return [(e.data.get("source_agent") or "?", e.data.get("target_agent") or "?")
                for e in self.events
                if e.event_type in {"agent_handoff", "agent_handoff_error"}]

    @property
    def policy_events(self) -> list[str]:
        return [e.event_type for e in self.events if e.event_type in POLICY_EVENTS]

    @property
    def total_cost_usd(self) -> float:
        c = [e.data.get("session_cost_usd") for e in self.events
             if isinstance(e.data.get("session_cost_usd"), (int, float))]
        if c:
            return round(max(c), 6)
        per_call = sum(e.data.get("cost_usd", 0) or 0 for e in self.events
                       if isinstance(e.data.get("cost_usd"), (int, float)))
        return round(per_call, 6)

    @property
    def error_count(self) -> int:
        return sum(1 for e in self.events
                   if e.event_type in {"tool_error", "model_error", "agent_handoff_error"})

    def features(self) -> dict[str, Any]:
        """The derived feature vector. This is what a SIEM should receive."""
        calls = self.tool_calls
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
            "tool_sequence": self.tool_sequence,
            "read_only_count": sum(1 for c in calls if c.klass == "read_only"),
            "state_change_count": sum(1 for c in calls if c.klass == "state_change"),
            "egress_count": sum(1 for c in calls if c.klass == "egress"),
            "unknown_class_count": sum(1 for c in calls if c.klass == "unknown"),
            "unpaired_calls": sum(1 for c in calls if c.result is None),
            "error_count": self.error_count,
            "injection_markers": self.injection_markers,
            "max_delegation_depth": self.max_delegation_depth,
            "handoff_count": len(self.handoffs),
            "handoff_chain": [f"{a}->{b}" for a, b in self.handoffs],
            "policy_events": self.policy_events,
            "total_cost_usd": self.total_cost_usd,
            "has_final_response_text": self.final_response is not None,
            "tool_results_captured": sum(1 for c in calls if c.had_result),
        }


@dataclass
class Finding:
    """One correlation result.

    Shaped to survive the trip into a SIEM. Deliberately carries the security
    fields that observra issue #108 reports the published parser drops:
    triggered_rules, max_severity, source_agent, target_agent, injection_patterns.
    """

    check: str
    severity: str                       # critical | high | medium | low | info
    session_id: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    _ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @property
    def rank(self) -> int:
        return self._ORDER.get(self.severity, 0)


def to_cim_event(session: Session, findings: list[Finding],
                 schema: str = "cohaera:0.1") -> dict[str, Any]:
    """Emit one correlation-grade CIM record per session.

    Note the ``type`` and ``schema`` keys. observra issue #108 records that the
    Exabeam sender emits ``event_type`` where the published ABA parser expects
    ``type``, and never emits ``schema`` at all, so no correlation rule can
    match. Cohaera emits both, plus ``event_type`` for backwards compatibility.
    """
    fired = sorted({f.check for f in findings})
    max_sev = max(findings, key=lambda f: f.rank).severity if findings else "info"
    feats = session.features()

    return {
        "type": "cohaera_session_verdict",
        "schema": schema,
        "event_type": "cohaera_session_verdict",
        "timestamp": session.ended_at,
        "session_id": session.session_id,
        "trace_id": session.session_id,
        "agent_name": (session.agent_names or [None])[0],
        "framework": session.framework,
        "host": session.host,
        "user": session.user,
        "log_source_type": "cohaera",
        "data": {
            **feats,
            "triggered_rules": fired,
            "max_severity": max_sev,
            "finding_count": len(findings),
            "findings": [asdict(f) for f in findings],
        },
    }
