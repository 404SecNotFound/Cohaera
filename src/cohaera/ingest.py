"""Read observra JSONL and assemble sessions.

observra's default backend writes one JSON object per line to a local file.
Sessions are recoverable because every record carries session_id and trace_id.
Nothing upstream does this grouping, so it lives here.

This is the trust boundary. Everything crossing it is produced by the system
Cohaera is meant to assess, so the reader is written to survive input that was
built to break it rather than input that was merely malformed by accident:

  * lines are read with a byte bound, so a single 4 GB line cannot be
    materialised into memory before anything gets a chance to reject it;
  * nesting depth is measured before ``json.loads`` runs, because the decoder is
    recursive and a 10,000-level array terminated the process with
    RecursionError (BUG-03) long before any Python-level guard could see it;
  * every failure mode at the record boundary is caught and quarantined, not
    just ``json.JSONDecodeError``;
  * the run stops on a budget, so an unbounded stream cannot exhaust the host;
  * and the reader reports what it refused, so the CLI can exit non-zero
    instead of claiming success over a pipeline that silently lost records.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable, Iterator

from .capabilities import EMPTY_MANIFEST, CapabilityManifest
from .identity import ANON_WINDOW_S, Correlator
from .limits import (
    DEFAULT_LIMITS, Limits, REJECT_LINE_TOO_LONG, REJECT_MALFORMED_JSON,
    REJECT_NESTING_TOO_DEEP, REJECT_NOT_AN_OBJECT, REJECT_TOO_MANY_EVENTS,
    REJECT_TOO_MANY_KEYS, REJECT_TOO_MANY_SESSIONS, REJECT_UNDECODABLE,
    json_depth_exceeds,
)
from .model import Event, Session
from .validate import IngestReport, Reject, digest_bytes, sanitise_display

__all__ = ["read_events", "assemble", "load", "ANON_WINDOW_S"]

_CHUNK = 65536


def _bounded_lines(path: Path, max_bytes: int) -> Iterator[tuple[int, bytes, bool]]:
    """Yield ``(lineno, payload, oversize)`` without ever buffering an unbounded line.

    ``file.readline()`` reads until a newline arrives, so a producer that never
    emits one can force the reader to allocate the whole file. This reads fixed
    chunks and abandons a line the moment it exceeds the bound, then resynchronises
    on the next newline. An oversize line is reported once, with the byte count,
    and its content is never retained.
    """
    with path.open("rb") as fh:
        buf = bytearray()
        lineno = 1
        skipping = False
        skipped_bytes = 0
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            start = 0
            while True:
                nl = chunk.find(b"\n", start)
                if nl < 0:
                    tail = chunk[start:]
                    if skipping:
                        skipped_bytes += len(tail)
                    else:
                        buf += tail
                        if len(buf) > max_bytes:
                            skipping = True
                            skipped_bytes = len(buf)
                            buf.clear()
                    break
                if skipping:
                    skipped_bytes += nl - start
                    yield lineno, b"", True
                    skipping = False
                    skipped_bytes = 0
                else:
                    buf += chunk[start:nl]
                    if len(buf) > max_bytes:
                        yield lineno, b"", True
                    else:
                        yield lineno, bytes(buf), False
                    buf.clear()
                lineno += 1
                start = nl + 1
        if skipping:
            yield lineno, b"", True
        elif buf:
            yield lineno, bytes(buf), len(buf) > max_bytes


def read_events(path: str | Path, limits: Limits = DEFAULT_LIMITS,
                report: IngestReport | None = None,
                quiet: bool = False) -> Iterator[Event]:
    """Yield Events from a JSONL file, quarantining anything that is not one.

    C-07 fix, kept: diagnostics go to stderr, because stdout is the JSONL stream
    the CLI promises and one malformed line must never invalidate the pipe.

    Every diagnostic is escaped through ``sanitise_display``. SEC-08: a producer
    that puts a newline and an ANSI sequence into a field could otherwise forge
    an entire log line on the operator's terminal, including a fake all-clear.
    """
    p = Path(path)
    rep = report if report is not None else IngestReport()
    rep.source = rep.source or p.name

    def _reject(lineno: int, code: str, detail: str = "",
                blob: bytes = b"", nbytes: int = 0) -> None:
        rep.add_reject(Reject(source=p.name, line=lineno, code=code,
                              detail=sanitise_display(detail, 200),
                              digest=digest_bytes(blob) if blob else "",
                              bytes_seen=nbytes or len(blob)))
        if not quiet:
            print(f"[cohaera] {sanitise_display(p.name, 120)}:{lineno} "
                  f"{code}: {sanitise_display(detail, 160)}", file=sys.stderr)

    for lineno, payload, oversize in _bounded_lines(p, limits.max_line_bytes):
        if oversize:
            _reject(lineno, REJECT_LINE_TOO_LONG,
                    f"line exceeds max_line_bytes={limits.max_line_bytes}")
            continue
        payload = payload.strip()
        if not payload:
            continue

        if rep.accepted >= limits.max_events_total:
            rep.aborted = True
            rep.abort_reason = REJECT_TOO_MANY_EVENTS
            _reject(lineno, REJECT_TOO_MANY_EVENTS,
                    f"max_events_total={limits.max_events_total} reached; "
                    "remaining records not read")
            return

        try:
            line = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            _reject(lineno, REJECT_UNDECODABLE, str(exc), payload)
            continue

        # Depth first, before the recursive decoder ever sees the string.
        if json_depth_exceeds(line, limits.max_nesting_depth):
            _reject(lineno, REJECT_NESTING_TOO_DEEP,
                    f"nesting exceeds max_nesting_depth={limits.max_nesting_depth}",
                    payload)
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            _reject(lineno, REJECT_MALFORMED_JSON, str(exc), payload)
            continue
        except RecursionError:
            # Belt and braces. The depth pre-scan should make this unreachable,
            # but the guarantee must not depend on sys.getrecursionlimit().
            _reject(lineno, REJECT_NESTING_TOO_DEEP,
                    "decoder recursion limit reached", payload)
            continue
        except (ValueError, MemoryError) as exc:      # pragma: no cover - defensive
            _reject(lineno, REJECT_MALFORMED_JSON, f"{type(exc).__name__}: {exc}",
                    payload)
            continue

        if not isinstance(obj, dict):
            _reject(lineno, REJECT_NOT_AN_OBJECT,
                    f"top-level {type(obj).__name__}, expected object", payload)
            continue
        if len(obj) > limits.max_record_keys:
            _reject(lineno, REJECT_TOO_MANY_KEYS,
                    f"{len(obj)} keys exceeds max_record_keys="
                    f"{limits.max_record_keys}", payload)
            continue

        e = Event(raw=obj, limits=limits)
        rep.note_defects(e.defects)
        rep.accepted += 1
        yield e

    if rep.rejected and not quiet:
        print(f"[cohaera] {sanitise_display(p.name, 120)}: {rep.rejected} record(s) "
              f"quarantined, {rep.accepted} accepted, "
              f"{rep.defective} accepted with field defects", file=sys.stderr)


def assemble(events: Iterable[Event], limits: Limits = DEFAULT_LIMITS,
             correlator: Correlator | None = None,
             manifest: CapabilityManifest = EMPTY_MANIFEST,
             report: IngestReport | None = None,
             quiet: bool = False) -> list[Session]:
    """Group a flat event stream into Sessions.

    Keyed on session_id, then trace_id, then a scoped anonymous key, then
    isolation. See :class:`cohaera.identity.Correlator` for why the last two are
    different things: a record with SOME identity can be bucketed with other
    records sharing that identity inside a time window, but a record with NONE
    has nothing for a merge to rest on and is isolated instead (BUG-06).

    Every session carries the correlation kind and confidence it was built from,
    so a verdict assembled out of guesswork cannot present itself as one
    assembled from a producer-supplied session ID.
    """
    corr = correlator or Correlator(limits=limits)
    rep = report if report is not None else IngestReport()
    buckets: dict[str, Session] = {}
    dropped_sessions = 0
    dropped_events = 0

    ordered = sorted(events, key=lambda e: e.sort_key)
    for e in ordered:
        rv = e.view
        # e.digest is passed uncalled: only the isolation branch needs it.
        key = corr.key_for(rv, raw_digest=e.digest)
        s = buckets.get(key.value)
        if s is None:
            if len(buckets) >= limits.max_sessions:
                dropped_sessions += 1
                continue
            s = Session(session_id=key.value, correlation=key, limits=limits,
                        manifest=manifest)
            buckets[key.value] = s
        if len(s.events) >= limits.max_events_per_session:
            dropped_events += 1
            continue
        s.events.append(e)

    if dropped_sessions:
        rep.aborted = True
        rep.abort_reason = REJECT_TOO_MANY_SESSIONS
        if not quiet:
            print(f"[cohaera] {dropped_sessions} event(s) discarded: "
                  f"max_sessions={limits.max_sessions} reached", file=sys.stderr)
    if dropped_events:
        rep.aborted = True
        rep.abort_reason = rep.abort_reason or REJECT_TOO_MANY_EVENTS
        if not quiet:
            print(f"[cohaera] {dropped_events} event(s) discarded: "
                  f"max_events_per_session={limits.max_events_per_session} reached",
                  file=sys.stderr)

    sessions = list(buckets.values())
    for s in sessions:
        s.events.sort(key=lambda x: x.sort_key)
        s.invalidate()
    sessions.sort(key=lambda s: (s.started_at, s.session_id))
    return sessions


def load(path: str | Path, limits: Limits = DEFAULT_LIMITS,
         correlator: Correlator | None = None,
         manifest: CapabilityManifest = EMPTY_MANIFEST,
         report: IngestReport | None = None,
         quiet: bool = False) -> list[Session]:
    """Read and group one telemetry file. The report is filled in as a side effect."""
    rep = report if report is not None else IngestReport()
    events = list(read_events(path, limits=limits, report=rep, quiet=quiet))
    return assemble(events, limits=limits, correlator=correlator,
                    manifest=manifest, report=rep, quiet=quiet)
