"""Core data model for Cohaera.

Observra emits a flat, per-event stream. Its rule engine signature is
``evaluate_rules(event_type, data)``, which is stateless and cannot see two events.
Cohaera's job starts by giving the stream a shape: a Session, with derived
behavioural features that only exist once events are grouped.

Everything here is deliberately dependency-free stdlib so it runs anywhere.
"""

from __future__ import annotations

import math
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

    This is still a name heuristic and it will still be wrong. The real fix is
    producer-signed capability manifests keyed on exact tool ID. Tools that do
    not match anything return ``unknown``, which must degrade coverage rather
    than silently read as safe.
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


@dataclass
class Event:
    """One observra CIM record, parsed but not interpreted."""

    raw: dict[str, Any]

    @property
    def event_type(self) -> str:
        """Always a string.

        R2-02. This returned the raw value, so a list or dict event_type raised
        "unhashable type" from ``e.event_type not in {...}`` inside CH04. A
        malformed field in one record should never abort scoring the session.
        """
        v = self.raw.get("event_type")
        return v if isinstance(v, str) else ""

    @property
    def agent_name(self) -> str | None:
        n = self.raw.get("agent_name")
        return n if isinstance(n, str) else None

    @property
    def timestamp(self) -> float:
        """Never raises. C-08: an unvalidated float() here was a trivial DoS.

        A malformed timestamp returns NaN rather than killing the run. NaN sorts
        last and is detectable downstream via ``timestamp_valid``.
        """
        raw = self.raw.get("timestamp")
        if isinstance(raw, bool):
            return float("nan")            # True is not a timestamp
        if isinstance(raw, (int, float)):
            return float(raw) if math.isfinite(raw) else float("nan")
        if isinstance(raw, str):
            try:
                v = float(raw)
            except ValueError:
                return float("nan")
            return v if math.isfinite(v) else float("nan")  # rejects "inf"/"nan"
        return float("nan")

    @property
    def timestamp_valid(self) -> bool:
        t = self.timestamp
        return math.isfinite(t) and t > 0

    @property
    def tool_name(self) -> str | None:
        """Always a string or None. Producers do send non-strings."""
        n = self.raw.get("tool_name")
        return n if isinstance(n, str) else None

    @property
    def data(self) -> dict[str, Any]:
        d = self.raw.get("data")
        return d if isinstance(d, dict) else {}

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
    # C-02 / C-05: an explicit pairing state beats inferring one from `result`.
    #   open           tool_start with no terminal event yet
    #   complete       start and terminal seen exactly once
    #   orphan_end     terminal event with no matching start
    #   duplicate_end  a second terminal event arrived for a completed call
    state: str = "open"

    @property
    def klass(self) -> str:
        """read_only | state_change | egress | unknown.

        C-03 fix. The producer's ``reversible`` flag is now authoritative in
        BOTH directions, and it no longer only rescues names already classified
        as read_only.

        Precedence:
          1. egress by name always wins. Data leaving the boundary is the
             property that matters most and reversibility says nothing about it.
          2. reversible is False  -> state_change
          3. reversible is True   -> read_only
          4. fall back to the name heuristic

        Still a heuristic. The real fix is typed capability manifests per
        producer, which is Phase 1 work, not this.
        """
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


@dataclass
class Session:
    """A correlated agent session. This is the object observra never builds."""

    session_id: str
    events: list[Event] = field(default_factory=list)
    _calls_cache: list[ToolCall] | None = field(default=None, repr=False,
                                                compare=False)

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
    def _valid_ts(self) -> list[float]:
        return [e.timestamp for e in self.events if e.timestamp == e.timestamp]

    @property
    def started_at(self) -> float:
        return min(self._valid_ts, default=0.0)

    @property
    def ended_at(self) -> float:
        return max(self._valid_ts, default=0.0)

    @property
    def duration_s(self) -> float:
        return round(self.ended_at - self.started_at, 3)

    # ---- tool calls -----------------------------------------------------
    @property
    def tool_calls(self) -> list[ToolCall]:
        """Pair tool_start with tool_end / tool_error. Cached per session.

        Pairing is by span_id where available, falling back to tool_name FIFO,
        because not every adapter propagates span_id consistently.
        """
        if self._calls_cache is not None:
            return self._calls_cache
        calls: list[ToolCall] = []
        # C-02 fix. Previously a span match popped the call out of open_by_span
        # but left it in open_by_name, so a later name-only terminal event could
        # find the SAME call again and overwrite a recorded success with a
        # failure. One identity, removed from every index atomically.
        open_by_span: dict[str, int] = {}          # span_id -> index into calls
        open_by_name: dict[str, list[int]] = {}    # name    -> indices, FIFO
        closed: set[int] = set()
        seen_spans: set[str] = set()      # every span we have ever closed

        def _release(idx: int) -> None:
            """Remove this call from BOTH indices. The whole point of the fix."""
            tc = calls[idx]
            if tc.span_id and open_by_span.get(tc.span_id) == idx:
                open_by_span.pop(tc.span_id, None)
            bucket = open_by_name.get(tc.name)
            if bucket and idx in bucket:
                bucket.remove(idx)
            closed.add(idx)

        for e in sorted(self.events, key=lambda x: x.timestamp):
            if e.event_type == "tool_start":
                tc = ToolCall(
                    name=e.tool_name or "<unnamed>",
                    started_at=e.timestamp,
                    span_id=e.raw.get("span_id"),
                    reversible=e.data.get("reversible"),
                    had_args=e.data.get("tool_args") is not None,
                    state="open",
                )
                idx = len(calls)
                calls.append(tc)
                if tc.span_id:
                    if tc.span_id in open_by_span:
                        # Span collision: two open calls claim the same span.
                        # Do not silently overwrite; leave the first indexed and
                        # let this one fall back to name matching.
                        pass
                    else:
                        open_by_span[tc.span_id] = idx
                open_by_name.setdefault(tc.name, []).append(idx)

            elif e.event_type in {"tool_end", "tool_error"}:
                sid = e.raw.get("span_id")
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
                    bucket = open_by_name.get(name) or []
                    idx = bucket[0] if bucket else None

                if idx is None or idx in closed:
                    # No open start to match. Record it as an orphan terminal
                    # rather than inventing a successful call out of nothing.
                    orphan = ToolCall(
                        name=name, started_at=e.timestamp, span_id=sid,
                        ended_at=e.timestamp,
                        result="failure" if e.event_type == "tool_error" else "success",
                        duration_ms=e.data.get("duration_ms"),
                        reversible=e.data.get("reversible"),
                        had_result=e.data.get("tool_result") is not None,
                        error_class=(e.data.get("error_class")
                                     or e.data.get("error_type_name")),
                        state=("duplicate_end" if (sid and sid in seen_spans)
                               else "mismatched_end" if sid
                               else "orphan_end"),
                    )
                    calls.append(orphan)
                    continue

                tc = calls[idx]
                if tc.span_id:
                    seen_spans.add(tc.span_id)
                _release(idx)
                tc.ended_at = e.timestamp
                tc.result = "failure" if e.event_type == "tool_error" else "success"
                tc.duration_ms = e.data.get("duration_ms")
                tc.error_class = (e.data.get("error_class")
                                  or e.data.get("error_type_name"))
                if e.data.get("reversible") is not None:
                    tc.reversible = e.data.get("reversible")
                tc.had_result = e.data.get("tool_result") is not None
                tc.state = "complete"

        self._calls_cache = calls
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


def json_safe(o: Any) -> Any:
    """Coerce a value tree into something json.dumps(allow_nan=False) accepts.

    R2-02. Producers send non-finite floats and unhashable values. Emitting
    Infinity or NaN produces output that is not valid JSON, and crashing on
    serialisation turns a bad input line into a lost verdict. Neither is
    acceptable for a security control, so values that cannot be represented are
    replaced with a typed marker that an analyst can see.
    """
    if isinstance(o, float):
        return o if math.isfinite(o) else {"_invalid_number": repr(o)}
    if isinstance(o, dict):
        return {(k if isinstance(k, str) else repr(k)): json_safe(v)
                for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [json_safe(v) for v in o]
    if o is None or isinstance(o, (str, int, bool)):
        return o
    return repr(o)


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

    return json_safe({
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
    })
