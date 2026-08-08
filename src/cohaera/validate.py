"""The schema firewall: one place that decides what a field is allowed to be.

Before this module, type handling was spread across ``Event`` properties,
``ingest.assemble`` and ``checks``. Each site guessed independently and each
guess was slightly different, which is how a list ``span_id`` reached a dict
lookup and raised ``unhashable type: 'list'`` from inside a security check.

There are two failure modes to hold apart, and the previous code conflated them:

REJECTION
    The record cannot be trusted to be a record at all. It never becomes an
    Event. It goes to the quarantine ledger with a reason code and a digest.

DEFECT
    The record is a record, but one field is not what it claims to be. The
    record survives, the bad field is treated as ABSENT rather than coerced into
    a plausible-looking value, and the defect code travels with the Event so
    that coverage can lower confidence for the checks that depended on it.

The distinction matters because of SEC-02, fail-open semantic coercion. The old
code turned a malformed tool name into ``<unnamed>``, which classifies as
``unknown``, which is not consequential, which means a malicious action with a
hostile name became invisible to CH02, CH03 and CH04 at once. Absent-and-flagged
is safe. Absent-and-silent is not.

Nothing here truncates an identity. A truncated correlation key is a forged
correlation key: ``session-AAAA...A-victim`` and ``session-AAAA...A-attacker``
collide the moment you cut them to a fixed width. Over-long identities are
rejected, not shortened. Only semantic surfaces (the final response, a user
message) are truncated, and the truncation is itself recorded as a defect.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any

from .limits import (
    DEFAULT_LIMITS,
    DEFECT_DATA_TYPE,
    DEFECT_EVENT_TYPE_TYPE,
    DEFECT_IDENTITY_TYPE,
    DEFECT_NUMERIC_NONFINITE,
    DEFECT_RESPONSE_TEXT_LENGTH,
    DEFECT_RESPONSE_TEXT_TYPE,
    DEFECT_REVERSIBLE_TYPE,
    DEFECT_SESSION_KEY_TYPE,
    DEFECT_SPAN_LENGTH,
    DEFECT_SPAN_TYPE,
    DEFECT_TIMESTAMP,
    DEFECT_TOOL_NAME_LENGTH,
    DEFECT_TOOL_NAME_TYPE,
    Limits,
)

_NAN = float("nan")


# ---------------------------------------------------------------------------
# Scalar coercion
# ---------------------------------------------------------------------------


def identity_text(value: Any, max_chars: int,
                  type_code: str, length_code: str) -> tuple[str | None, tuple[str, ...]]:
    """Accept a bounded, non-empty string. Reject everything else outright.

    ``bool`` is rejected before ``str`` because ``True`` is not a name, and
    because Python's ``True == 1`` aliasing is exactly the bug that let a call
    with ``span_id: true`` be closed by a terminal event carrying ``span_id: 1``.
    Once every span is a string that whole class disappears.
    """
    if value is None:
        return None, ()
    if isinstance(value, bool) or not isinstance(value, str):
        return None, (type_code,)
    if not value:
        return None, ()                      # empty string is absence, not a defect
    if len(value) > max_chars:
        # Deliberately NOT truncated. See the module docstring.
        return None, (length_code,)
    return value, ()


def semantic_text(value: Any, max_chars: int,
                  type_code: str, length_code: str) -> tuple[str | None, tuple[str, ...]]:
    """Accept a string, truncating if it is over-long.

    Used only for surfaces that are read for meaning rather than matched for
    identity: the final response, a user message. Truncation is recorded so a
    check can say it saw part of the text rather than all of it.
    """
    if value is None:
        return None, ()
    if isinstance(value, bool) or not isinstance(value, str):
        return None, (type_code,)
    if not value:
        return None, ()
    if len(value) > max_chars:
        return value[:max_chars], (length_code,)
    return value, ()


def timestamp(value: Any) -> tuple[float, tuple[str, ...]]:
    """Return a finite positive epoch seconds value, or NaN plus a defect code.

    NaN is the sentinel rather than an exception because one unparseable clock
    in a 200,000-event stream must not abort the run. It sorts last, it fails
    every ordering comparison, and ``timestamp_valid`` exposes it. Checks that
    depend on ordering degrade their own confidence when they see one.
    """
    if isinstance(value, bool):
        return _NAN, (DEFECT_TIMESTAMP,)      # True is not a timestamp
    if isinstance(value, (int, float)):
        v = float(value)
    elif isinstance(value, str):
        try:
            v = float(value)
        except ValueError:
            return _NAN, (DEFECT_TIMESTAMP,)
    else:
        return _NAN, (DEFECT_TIMESTAMP,)
    if not math.isfinite(v) or v <= 0:
        # Rejects "inf", "nan", "-1" and 0. An epoch of zero is not a clock,
        # it is a default that somebody forgot to fill in.
        return _NAN, (DEFECT_TIMESTAMP,)
    return v, ()


def finite_number(value: Any) -> tuple[float | None, tuple[str, ...]]:
    """A finite int/float, or None. Booleans are not numbers here."""
    if value is None:
        return None, ()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, (DEFECT_NUMERIC_NONFINITE,)
    v = float(value)
    if not math.isfinite(v):
        return None, (DEFECT_NUMERIC_NONFINITE,)
    return v, ()


def tri_state_bool(value: Any) -> tuple[bool | None, tuple[str, ...]]:
    """True, False, or None-with-a-defect. Never a truthiness guess.

    ``reversible`` decides whether a call is consequential. Reading ``"no"`` or
    ``0`` as False would let a producer flip a check's verdict with a type.
    """
    if value is None:
        return None, ()
    if isinstance(value, bool):
        return value, ()
    return None, (DEFECT_REVERSIBLE_TYPE,)


# ---------------------------------------------------------------------------
# Record-level validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordView:
    """A validated read of one raw record.

    ``raw`` is kept verbatim so nothing is lost and checks can still reach
    producer extras. The validated fields are what the engine is allowed to act
    on, and ``defects`` says which fields were dropped on the way.
    """

    raw: dict[str, Any]
    event_type: str
    session_key: str | None
    trace_key: str | None
    span_id: str | None
    tool_name: str | None
    host: str | None
    user: str | None
    agent_name: str | None
    framework: str | None
    ts: float
    defects: tuple[str, ...] = ()

    @property
    def has_identity(self) -> bool:
        """Any field that could support correlating this record with another.

        Fully anonymous records — no session, no trace, no host, no user, no
        agent, no framework — have nothing that can support a merge, and the
        review is right that bucketing them by time alone fabricates sessions.
        """
        return any((self.session_key, self.trace_key, self.host, self.user,
                    self.agent_name, self.framework))


def view(raw: dict[str, Any], limits: Limits = DEFAULT_LIMITS) -> RecordView:
    """Validate one already-parsed record. Never raises."""
    defects: list[str] = []

    def take(pair: tuple[Any, tuple[str, ...]]) -> Any:
        value, codes = pair
        defects.extend(codes)
        return value

    et = raw.get("event_type")
    if et is None:
        event_type = ""
    elif isinstance(et, str) and not isinstance(et, bool):
        event_type = et if len(et) <= limits.max_identity_chars else ""
        if not event_type:
            defects.append(DEFECT_EVENT_TYPE_TYPE)
    else:
        event_type = ""
        defects.append(DEFECT_EVENT_TYPE_TYPE)

    session_key = take(identity_text(raw.get("session_id"), limits.max_session_key_chars,
                                     DEFECT_SESSION_KEY_TYPE, DEFECT_SESSION_KEY_TYPE))
    trace_key = take(identity_text(raw.get("trace_id"), limits.max_session_key_chars,
                                   DEFECT_SESSION_KEY_TYPE, DEFECT_SESSION_KEY_TYPE))
    span_id = take(identity_text(raw.get("span_id"), limits.max_span_chars,
                                 DEFECT_SPAN_TYPE, DEFECT_SPAN_LENGTH))
    tool_name = take(identity_text(raw.get("tool_name"), limits.max_tool_name_chars,
                                   DEFECT_TOOL_NAME_TYPE, DEFECT_TOOL_NAME_LENGTH))

    ident = {}
    for key in ("host", "user", "agent_name", "framework"):
        ident[key] = take(identity_text(raw.get(key), limits.max_identity_chars,
                                        DEFECT_IDENTITY_TYPE, DEFECT_IDENTITY_TYPE))

    ts = take(timestamp(raw.get("timestamp")))

    if raw.get("data") is not None and not isinstance(raw.get("data"), dict):
        defects.append(DEFECT_DATA_TYPE)

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    if "response_text" in data:
        _, codes = semantic_text(data.get("response_text"), limits.max_response_chars,
                                 DEFECT_RESPONSE_TEXT_TYPE, DEFECT_RESPONSE_TEXT_LENGTH)
        defects.extend(codes)
    if "reversible" in data:
        _, codes = tri_state_bool(data.get("reversible"))
        defects.extend(codes)

    # dict.fromkeys, not set(), so the order is the order they were found in.
    return RecordView(
        raw=raw, event_type=event_type, session_key=session_key, trace_key=trace_key,
        span_id=span_id, tool_name=tool_name, host=ident["host"], user=ident["user"],
        agent_name=ident["agent_name"], framework=ident["framework"], ts=ts,
        defects=tuple(dict.fromkeys(defects)),
    )


# ---------------------------------------------------------------------------
# Quarantine ledger
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Reject:
    """One record Cohaera refused to accept.

    Carries a digest rather than the record. A quarantine ledger that reproduces
    hostile input verbatim into a log pipeline is its own problem (SEC-07), and
    the digest is enough to correlate with the source file if somebody needs the
    original.
    """

    source: str
    line: int
    code: str
    detail: str = ""
    digest: str = ""
    bytes_seen: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "line": self.line, "code": self.code,
            "detail": self.detail, "digest": self.digest,
            "bytes_seen": self.bytes_seen,
        }


@dataclass
class IngestReport:
    """What the reader accepted, refused, and stopped short of.

    The CLI turns this into an exit code. Before this existed, ``cmd_score``
    returned 0 unconditionally, so a pipeline could lose every record but two
    and still be marked successful.
    """

    source: str = ""
    accepted: int = 0
    rejected: int = 0
    defective: int = 0
    rejects: list[Reject] = field(default_factory=list)
    # C4-01. Run identity used to hash this report's SUMMARY -- source path plus
    # counts -- so two entirely different files written to the same path with the
    # same accepted and rejected counts produced the SAME analysis_run_id. A SIEM
    # deduplicating on it would discard the second as a retry.
    #
    # This is a streaming hash over the exact bytes of every record read, in
    # order, accepted and rejected alike. One hashlib update per line, no JSON
    # round trip, so it costs nothing measurable. Order is deliberately part of
    # the identity: the same records in a different order are a different input.
    _content: Any = field(default_factory=hashlib.sha256, repr=False,
                          compare=False)
    reject_codes: dict[str, int] = field(default_factory=dict)
    defect_codes: dict[str, int] = field(default_factory=dict)
    aborted: bool = False
    abort_reason: str = ""
    # What the collector-stream verifier concluded across the whole input, as
    # opposed to per session. Filled in by ``ingest.assemble``. It carries the
    # per-stream extent that makes a cross-run replay visible by comparing two
    # verdicts, which is the only form of replay detection available to a
    # process that keeps no state between runs. See evidence.Freshness.
    integrity: dict[str, Any] = field(default_factory=dict)

    def note_bytes(self, blob: bytes, tag: bytes = b"") -> None:
        """Fold one raw record into the content digest, accepted or rejected."""
        self._content.update(tag)
        self._content.update(len(blob).to_bytes(8, "big"))
        self._content.update(blob)

    @property
    def content_digest(self) -> str:
        """Identity of what was actually READ, not of the summary counts."""
        return self._content.hexdigest()[:32]

    def add_reject(self, r: Reject, keep: int = 1000) -> None:
        self.rejected += 1
        self.reject_codes[r.code] = self.reject_codes.get(r.code, 0) + 1
        if len(self.rejects) < keep:
            self.rejects.append(r)

    def note_defects(self, codes: tuple[str, ...]) -> None:
        if codes:
            self.defective += 1
        for c in codes:
            self.defect_codes[c] = self.defect_codes.get(c, 0) + 1

    @property
    def total(self) -> int:
        return self.accepted + self.rejected

    @property
    def reject_ratio(self) -> float:
        return (self.rejected / self.total) if self.total else 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "records_accepted": self.accepted,
            "records_rejected": self.rejected,
            "records_with_defects": self.defective,
            "reject_ratio": round(self.reject_ratio, 6),
            "reject_codes": dict(sorted(self.reject_codes.items())),
            "defect_codes": dict(sorted(self.defect_codes.items())),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "content_digest": self.content_digest,
        }

    def merge(self, other: IngestReport) -> IngestReport:
        self.accepted += other.accepted
        self.rejected += other.rejected
        self.defective += other.defective
        self.rejects.extend(other.rejects)
        for k, v in other.reject_codes.items():
            self.reject_codes[k] = self.reject_codes.get(k, 0) + v
        for k, v in other.defect_codes.items():
            self.defect_codes[k] = self.defect_codes.get(k, 0) + v
        self.note_bytes(other.content_digest.encode("ascii"), b"MERGE")
        self.aborted = self.aborted or other.aborted
        self.abort_reason = self.abort_reason or other.abort_reason
        return self


def digest_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Serialisation safety
# ---------------------------------------------------------------------------


def json_safe(o: Any, _depth: int = 0, _max_depth: int = 100) -> Any:
    """Coerce a value tree into something json.dumps(allow_nan=False) accepts.

    R2-02. Producers send non-finite floats and unhashable values. Emitting
    Infinity or NaN produces output that is not valid JSON, and crashing on
    serialisation turns a bad input line into a lost verdict. Neither is
    acceptable for a security control, so values that cannot be represented are
    replaced with a typed marker that an analyst can see.

    It lives here rather than in ``model`` because hashing a raw record needs the
    same coercion: computing a content digest of an event whose ``duration_ms``
    is ``Infinity`` must not raise from inside session assembly, which is the
    same fault as the one this function was written to prevent, one layer down.

    Depth-bounded, because this walks producer-controlled structure and would
    otherwise recurse as deeply as the input nests. The ingest firewall refuses
    deep records long before this sees them; this is the second wall, for
    structures assembled in memory rather than parsed from a line.
    """
    if _depth > _max_depth:
        return {"_truncated_depth": _max_depth}
    if isinstance(o, float):
        return o if math.isfinite(o) else {"_invalid_number": repr(o)}
    if isinstance(o, dict):
        return {(k if isinstance(k, str) else repr(k)):
                json_safe(v, _depth + 1, _max_depth) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [json_safe(v, _depth + 1, _max_depth) for v in o]
    if o is None or isinstance(o, (str, int, bool)):
        return o
    return repr(o)


# ---------------------------------------------------------------------------
# Display safety
# ---------------------------------------------------------------------------

# C0 controls except nothing (all of them), DEL, and the C1 range. Kept as an
# explicit class rather than str.isprintable() because the latter also strips
# legitimate non-ASCII text an analyst may need to read.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitise_display(value: Any, max_chars: int = 200) -> str:
    """Make a producer-controlled string safe to write to a terminal.

    SEC-08. Session IDs and agent names went to stderr unescaped, so a producer
    could embed a newline and an ANSI sequence and forge a log line:

        session_id = "a\\n[cohaera] 0 finding(s) ALL CLEAR\\x1b[2J"

    printed a fake all-clear summary and then cleared the screen above it. The
    JSON on stdout was always escaped correctly; the human-readable half was not,
    and the human-readable half is the one somebody reads at 3am.

    Control characters become visible escapes rather than disappearing, because
    an identifier that CONTAINS a newline is itself a finding.
    """
    text = value if isinstance(value, str) else repr(value)
    text = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    if len(text) > max_chars:
        text = text[:max_chars] + f"...(+{len(text) - max_chars} chars)"
    return text
