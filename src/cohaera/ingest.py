"""Read observra JSONL and assemble sessions.

observra's default backend writes one JSON object per line to a local file.
Sessions are recoverable because every record carries session_id and trace_id.
Nothing upstream does this grouping, so it lives here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable, Iterator

from .model import Event, Session

# C-04: events with no correlation key are bucketed within this many seconds
# of each other, per (host, user, agent). Never globally.
ANON_WINDOW_S = 300.0


def read_events(path: str | Path) -> Iterator[Event]:
    """Yield Events from a JSONL file, reporting malformed lines on STDERR.

    C-07 fix. This previously used a bare print(), which put diagnostics on
    stdout and corrupted the JSONL stream the CLI promises. stdout is data.
    stderr is commentary. One malformed line must never invalidate the pipe.
    """
    p = Path(path)
    bad = 0
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                bad += 1
                print(f"[cohaera] {p.name}:{lineno} malformed JSON, quarantined: {exc}",
                      file=sys.stderr)
                continue
            if isinstance(obj, dict):
                yield Event(raw=obj)
            else:
                bad += 1
                print(f"[cohaera] {p.name}:{lineno} not a JSON object, quarantined",
                      file=sys.stderr)
    if bad:
        print(f"[cohaera] {p.name}: {bad} record(s) quarantined", file=sys.stderr)


def _anon_key(e: Event, counter: dict[tuple, float]) -> str:
    """C-04 fix: a collision-resistant key for events with no session or trace id.

    The old behaviour put every unidentified event into one global
    '<no-session-id>' bucket, which let an injection marker on host-A correlate
    with an egress action on host-B under a different user. That is a
    correlation the data does not support, and it manufactures findings.

    Now: bucket by (host, user, agent, framework) and a bounded time window.
    Unrelated producers can no longer be joined. This is still a fallback, not a
    correlation key. Verdicts built on it should be treated as low confidence.
    """
    ident = (e.raw.get("host"), e.raw.get("user"),
             e.raw.get("agent_name"), e.raw.get("framework"))
    ts = e.timestamp
    if ts != ts:                      # NaN, no usable clock
        return "anon|" + "|".join(str(x) for x in ident) + "|no-clock"
    start = counter.get(ident)
    if start is None or ts - start > ANON_WINDOW_S:
        counter[ident] = ts
        start = ts
    return ("anon|" + "|".join(str(x) for x in ident)
            + f"|w{int(start // ANON_WINDOW_S)}")


def assemble(events: Iterable[Event]) -> list[Session]:
    """Group a flat event stream into Sessions.

    Keyed on session_id, then trace_id, then a scoped anonymous key. Anonymous
    events are NEVER merged across host, user, agent or time window.
    """
    buckets: dict[str, Session] = {}
    anon_counter: dict[tuple, float] = {}

    ordered = sorted(events, key=lambda e: (e.timestamp != e.timestamp, e.timestamp))
    for e in ordered:
        key = e.raw.get("session_id") or e.raw.get("trace_id")
        if not key:
            key = _anon_key(e, anon_counter)
        if key not in buckets:
            buckets[key] = Session(session_id=key)
        buckets[key].events.append(e)

    sessions = list(buckets.values())
    for s in sessions:
        s.events.sort(key=lambda x: (x.timestamp != x.timestamp, x.timestamp))
    sessions.sort(key=lambda s: s.started_at)
    return sessions


def load(path: str | Path) -> list[Session]:
    return assemble(read_events(path))
