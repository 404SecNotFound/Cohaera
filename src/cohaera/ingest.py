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

import hashlib
import json
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capabilities import EMPTY_MANIFEST, CapabilityManifest
from .evidence import EMPTY_KEYS, CollectorKeys, StreamVerifier
from .identity import ANON_WINDOW_S, Correlator
from .limits import (
    DEFAULT_LIMITS,
    REJECT_LINE_TOO_LONG,
    REJECT_MALFORMED_JSON,
    REJECT_NESTING_TOO_DEEP,
    REJECT_NOT_AN_OBJECT,
    REJECT_RATIO_EXCEEDED,
    REJECT_TOO_MANY_BYTES,
    REJECT_TOO_MANY_EVENTS,
    REJECT_TOO_MANY_KEYS,
    REJECT_TOO_MANY_RECORDS,
    REJECT_TOO_MANY_REJECTS,
    REJECT_TOO_MANY_SESSIONS,
    REJECT_UNDECODABLE,
    Limits,
    json_depth_exceeds,
)
from .model import Event, Session
from .validate import IngestReport, Reject, digest_bytes, sanitise_display

__all__ = ["ANON_WINDOW_S", "RawLine", "assemble", "load", "read_events"]

_CHUNK = 65536


@dataclass(frozen=True)
class RawLine:
    """One physical record as it came off the disk, bounded but accounted for.

    C4-09. The previous reader reported an oversize line as ``(lineno, b"",
    True)`` and nothing else, so the quarantine ledger recorded the one class of
    record where size IS the finding with ``bytes_seen=0`` and an empty digest.
    An analyst asking "how big was the line that broke the budget, and was it
    the same line each time" got zeros and blanks. The byte count was already
    being computed to enforce the bound; it was simply thrown away.

    ``payload`` is empty for an oversize line -- the content is still never
    retained -- but ``nbytes`` and ``digest`` are real. The digest is streamed
    over the whole line as it passes through, so two runs seeing the same
    oversize record produce the same digest without either ever holding it.

    ``digest`` is populated ONLY for an oversize line, which is the only case
    where the caller cannot compute it from ``payload`` itself. Hashing every
    line here would be a second SHA-256 pass over the whole file to produce a
    value nothing reads on the healthy path.
    """

    lineno: int
    payload: bytes          # b"" when oversize; the content is never retained
    oversize: bool
    nbytes: int             # bytes in the record, excluding the line terminator
    digest: str             # sha256 of an oversize record; "" otherwise


def _bounded_lines(path: Path, max_bytes: int) -> Iterator[RawLine]:
    """Yield :class:`RawLine` without ever buffering an unbounded line.

    ``file.readline()`` reads until a newline arrives, so a producer that never
    emits one can force the reader to allocate the whole file. This reads fixed
    chunks and abandons a line's CONTENT the moment it exceeds the bound, while
    continuing to count and hash what streams past, then resynchronises on the
    next newline. Peak memory is ``max_bytes + _CHUNK`` regardless of input.
    """
    with path.open("rb") as fh:
        buf = bytearray()
        hasher: Any = None
        nbytes = 0
        lineno = 1
        oversize = False

        def feed(seg: bytes) -> None:
            # Hashing starts only when a line goes oversize, and covers the
            # prefix already buffered plus everything after it. Hashing every
            # line here instead would cost a second SHA-256 pass over the whole
            # file on the path where it is never read: a healthy record's digest
            # is taken by the caller, from the bytes it already holds.
            nonlocal nbytes, oversize, hasher
            nbytes += len(seg)
            if oversize:
                hasher.update(seg)           # counted and hashed, not retained
                return
            # extend(), not ``+=``: an augmented assignment would rebind ``buf``
            # as a local of this closure and raise UnboundLocalError.
            buf.extend(seg)
            if len(buf) > max_bytes:
                oversize = True
                hasher = hashlib.sha256()
                hasher.update(buf)
                buf.clear()

        def finish() -> RawLine:
            return RawLine(lineno=lineno, payload=b"" if oversize else bytes(buf),
                           oversize=oversize, nbytes=nbytes,
                           digest=hasher.hexdigest()[:16] if oversize else "")

        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            start = 0
            while True:
                nl = chunk.find(b"\n", start)
                if nl < 0:
                    feed(chunk[start:])
                    break
                feed(chunk[start:nl])
                yield finish()
                buf.clear()
                hasher = None
                nbytes = 0
                oversize = False
                lineno += 1
                start = nl + 1
        if nbytes:
            yield finish()                   # last line, no trailing newline


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
                blob: bytes = b"", nbytes: int = 0, digest: str = "") -> None:
        # The content digest must commit to everything READ. An oversize record
        # is never retained, so its streamed digest stands in for its bytes.
        rep.note_bytes(blob if blob else digest.encode("ascii"),
                       b"R" + code.encode("ascii"))
        rep.add_reject(Reject(source=p.name, line=lineno, code=code,
                              detail=sanitise_display(detail, 200),
                              digest=digest or (digest_bytes(blob) if blob else ""),
                              bytes_seen=nbytes or len(blob)))
        if not quiet:
            print(f"[cohaera] {sanitise_display(p.name, 120)}:{lineno} "
                  f"{code}: {sanitise_display(detail, 160)}", file=sys.stderr)

    records_read = 0
    bytes_read = 0

    def _budget_hit() -> tuple[str, str]:
        """The first live budget this run has exhausted, as (code, detail).

        C4-02. All of these used to be checked somewhere that a hostile file
        could walk straight past. ``max_events_total`` counted only ACCEPTED
        records, so a file of pure garbage was bounded by nothing; ``max_rejects``
        and ``max_reject_ratio`` were checked by the CLI AFTER ``load`` had
        already read every byte, which makes them a report rather than a budget.
        Checked here, per record, they stop the work instead of describing it.
        """
        if records_read >= limits.max_records_total:
            return REJECT_TOO_MANY_RECORDS, (
                f"max_records_total={limits.max_records_total} reached")
        if bytes_read >= limits.max_input_bytes:
            return REJECT_TOO_MANY_BYTES, (
                f"max_input_bytes={limits.max_input_bytes} reached "
                f"after {bytes_read} byte(s)")
        if rep.accepted >= limits.max_events_total:
            return REJECT_TOO_MANY_EVENTS, (
                f"max_events_total={limits.max_events_total} reached")
        if limits.max_rejects is not None and rep.rejected > limits.max_rejects:
            return REJECT_TOO_MANY_REJECTS, (
                f"{rep.rejected} rejected record(s) exceeds "
                f"max_rejects={limits.max_rejects}")
        if (limits.max_reject_ratio is not None
                and records_read >= limits.max_reject_ratio_floor
                and rep.total
                and rep.reject_ratio > limits.max_reject_ratio):
            return REJECT_RATIO_EXCEEDED, (
                f"reject ratio {rep.reject_ratio:.4f} exceeds "
                f"max_reject_ratio={limits.max_reject_ratio}")
        return "", ""

    for raw in _bounded_lines(p, limits.max_line_bytes):
        lineno = raw.lineno

        code, detail = _budget_hit()
        if code:
            rep.aborted = True
            rep.abort_reason = code
            _reject(lineno, code, f"{detail}; remaining records not read")
            return

        records_read += 1
        bytes_read += raw.nbytes

        if raw.oversize:
            # C4-09: the byte count and digest are real even though the content
            # was never retained. Size is the whole of this finding.
            _reject(lineno, REJECT_LINE_TOO_LONG,
                    f"line exceeds max_line_bytes={limits.max_line_bytes} "
                    f"({raw.nbytes} bytes)",
                    nbytes=raw.nbytes, digest=raw.digest)
            continue
        payload = raw.payload
        record = payload.strip()
        if not record:
            continue

        try:
            line = record.decode("utf-8")
        except UnicodeDecodeError as exc:
            _reject(lineno, REJECT_UNDECODABLE, str(exc), record)
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
                    record)
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
        rep.note_bytes(record, b"A")
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
             quiet: bool = False,
             keys: CollectorKeys = EMPTY_KEYS) -> list[Session]:
    """Group a flat event stream into Sessions.

    Keyed on session_id, then trace_id, then a scoped anonymous key, then
    isolation. See :class:`cohaera.identity.Correlator` for why the last two are
    different things: a record with SOME identity can be bucketed with other
    records sharing that identity inside a time window, but a record with NONE
    has nothing for a merge to rest on and is isolated instead (BUG-06).

    Every session carries the correlation kind and confidence it was built from,
    so a verdict assembled out of guesswork cannot present itself as one
    assembled from a producer-supplied session ID.

    INTEGRITY IS VERIFIED IN ARRIVAL ORDER, NOT IN SORTED ORDER
        Sessions are assembled from events sorted by clock, because that is what
        pairing and ordering checks need. Collector sequence numbers are about
        the order records were WRITTEN, so verifying them over the sorted list
        would reorder the stream before checking whether it had been reordered,
        and every clock skew in the input would read as a delivery fault. The
        verifier therefore gets the events as they arrived, after the sorted
        pass has established which session each one belongs to.
    """
    corr = correlator or Correlator(limits=limits)
    rep = report if report is not None else IngestReport()
    buckets: dict[str, Session] = {}
    dropped_sessions = 0
    dropped_events = 0

    # Materialised rather than consumed by ``sorted`` alone: arrival order is a
    # second, independent reading of the same events and both are needed.
    incoming = list(events)
    session_of: dict[int, str] = {}

    ordered = sorted(incoming, key=lambda e: e.sort_key)
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
        session_of[id(e)] = key.value
        s.events.append(e)

    # A dropped event still occupies a position in its collector stream, so it
    # is observed for sequence continuity and attributed to no session. Omitting
    # it would manufacture a gap out of Cohaera's own budget.
    verifier = StreamVerifier(keys=keys, limits=limits)
    for e in incoming:
        verifier.observe(e.raw, e.integrity, session_of.get(id(e), ""))
    verifier.finalise()
    for key_value, s in buckets.items():
        s.integrity = verifier.for_session(key_value)

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
        # C4-08. Sealed, not merely invalidated. Batch assembly is finished with
        # these sessions, and everything downstream caches derived values off
        # them, so the event list is made immutable rather than left mutable
        # behind a cache that only notices a change of LENGTH.
        s.seal()
    sessions.sort(key=lambda s: (s.started_at, s.session_id))
    return sessions


def load(path: str | Path, limits: Limits = DEFAULT_LIMITS,
         correlator: Correlator | None = None,
         manifest: CapabilityManifest = EMPTY_MANIFEST,
         report: IngestReport | None = None,
         quiet: bool = False,
         keys: CollectorKeys = EMPTY_KEYS) -> list[Session]:
    """Read and group one telemetry file. The report is filled in as a side effect."""
    rep = report if report is not None else IngestReport()
    events = list(read_events(path, limits=limits, report=rep, quiet=quiet))
    return assemble(events, limits=limits, correlator=correlator,
                    manifest=manifest, report=rep, quiet=quiet, keys=keys)
