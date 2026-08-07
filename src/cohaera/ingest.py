"""Read observra JSONL and assemble sessions.

observra's default backend writes one JSON object per line to a local file.
Sessions are recoverable because every record carries session_id and trace_id.
Nothing upstream does this grouping, so it lives here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator

from .model import Event, Session


def read_events(path: str | Path) -> Iterator[Event]:
    """Yield Events from a JSONL file, skipping malformed lines loudly."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                # Do not silently drop. A malformed telemetry line is a
                # collection problem worth knowing about.
                print(f"[cohaera] {p.name}:{lineno} malformed JSON, skipped: {exc}")
                continue
            if isinstance(obj, dict):
                yield Event(raw=obj)


def assemble(events: Iterable[Event]) -> list[Session]:
    """Group a flat event stream into Sessions.

    Keyed on session_id, falling back to trace_id, falling back to a synthetic
    bucket so that events with neither are still visible rather than discarded.
    """
    buckets: dict[str, Session] = {}
    for e in events:
        key = e.raw.get("session_id") or e.raw.get("trace_id") or "<no-session-id>"
        if key not in buckets:
            buckets[key] = Session(session_id=key)
        buckets[key].events.append(e)

    sessions = list(buckets.values())
    for s in sessions:
        s.events.sort(key=lambda x: x.timestamp)
    sessions.sort(key=lambda s: s.started_at)
    return sessions


def load(path: str | Path) -> list[Session]:
    return assemble(read_events(path))
