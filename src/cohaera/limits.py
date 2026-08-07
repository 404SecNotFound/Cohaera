"""Resource bounds for the ingestion and scoring path.

Cohaera sits at a telemetry trust boundary. Everything it reads is produced by
the system it is meant to assess, so every dimension of that input is an
attacker-controlled quantity: line length, nesting depth, event count, string
length, how many calls share a name, how long the final response is.

The third external review demonstrated four separate resource faults, and
measuring the code found two more that the review missed:

  * a 10,000-level nested array terminated parsing with RecursionError;
  * a session with N policy events and M consequential calls made CH04 emit N
    findings each carrying M evidence rows, which is O(N*M) time AND output.
    900 input events produced a 6.3 MB verdict record, a 61x amplification;
  * CH02's disclosure test scanned the whole final response once per call,
    which is O(calls * response_length). 800 calls against an 80 KB response
    took 6.9 seconds.

None of these need a clever fix. They need a number. This module is the numbers,
in one place, so a deployment can lower them and so the verdict record can carry
the digest of the bounds that produced it.

Every bound is a REJECT boundary, not a truncate-and-continue boundary, except
where explicitly named ``*_chars`` on an evidence field. Silently truncating an
identity is how a correlation key gets forged.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any

# ---------------------------------------------------------------------------
# Reason codes. Stable strings, because they end up in a SIEM and somebody will
# eventually write a rule against one. Adding is fine; renaming is a breaking
# change to downstream content.
# ---------------------------------------------------------------------------

# --- record-level rejections (the record never becomes an Event) -----------
REJECT_MALFORMED_JSON = "MALFORMED_JSON"
REJECT_NOT_AN_OBJECT = "NOT_A_JSON_OBJECT"
REJECT_LINE_TOO_LONG = "LINE_EXCEEDS_MAX_BYTES"
REJECT_NESTING_TOO_DEEP = "NESTING_EXCEEDS_MAX_DEPTH"
REJECT_UNDECODABLE = "LINE_NOT_VALID_UTF8"
REJECT_TOO_MANY_EVENTS = "EVENT_BUDGET_EXHAUSTED"
REJECT_TOO_MANY_SESSIONS = "SESSION_BUDGET_EXHAUSTED"
REJECT_TOO_MANY_KEYS = "RECORD_EXCEEDS_MAX_KEYS"

# --- field-level defects (the record survives, degraded and labelled) ------
DEFECT_EVENT_TYPE_TYPE = "INVALID_EVENT_TYPE"
DEFECT_SPAN_TYPE = "INVALID_SPAN_TYPE"
DEFECT_SPAN_LENGTH = "SPAN_EXCEEDS_MAX_CHARS"
DEFECT_SESSION_KEY_TYPE = "INVALID_SESSION_KEY_TYPE"
DEFECT_TOOL_NAME_TYPE = "INVALID_TOOL_NAME_TYPE"
DEFECT_TOOL_NAME_LENGTH = "TOOL_NAME_EXCEEDS_MAX_CHARS"
DEFECT_RESPONSE_TEXT_TYPE = "INVALID_RESPONSE_TEXT_TYPE"
DEFECT_RESPONSE_TEXT_LENGTH = "RESPONSE_TEXT_TRUNCATED"
DEFECT_TIMESTAMP = "INVALID_TIMESTAMP"
DEFECT_IDENTITY_TYPE = "INVALID_IDENTITY_FIELD_TYPE"
DEFECT_DATA_TYPE = "INVALID_DATA_BAG_TYPE"
DEFECT_REVERSIBLE_TYPE = "INVALID_REVERSIBLE_TYPE"
DEFECT_NUMERIC_NONFINITE = "NONFINITE_NUMERIC_FIELD"

ALL_REJECT_CODES = (
    REJECT_MALFORMED_JSON, REJECT_NOT_AN_OBJECT, REJECT_LINE_TOO_LONG,
    REJECT_NESTING_TOO_DEEP, REJECT_UNDECODABLE, REJECT_TOO_MANY_EVENTS,
    REJECT_TOO_MANY_SESSIONS, REJECT_TOO_MANY_KEYS,
)

ALL_DEFECT_CODES = (
    DEFECT_EVENT_TYPE_TYPE, DEFECT_SPAN_TYPE, DEFECT_SPAN_LENGTH,
    DEFECT_SESSION_KEY_TYPE, DEFECT_TOOL_NAME_TYPE, DEFECT_TOOL_NAME_LENGTH,
    DEFECT_RESPONSE_TEXT_TYPE, DEFECT_RESPONSE_TEXT_LENGTH, DEFECT_TIMESTAMP,
    DEFECT_IDENTITY_TYPE, DEFECT_DATA_TYPE, DEFECT_REVERSIBLE_TYPE,
    DEFECT_NUMERIC_NONFINITE,
)


@dataclass(frozen=True)
class Limits:
    """Every bound Cohaera enforces, and the digest of the set it used.

    Defaults are sized for a collector VM reading agent telemetry, not for a
    benchmark. They are deliberately generous enough that no honest producer
    trips them and tight enough that a hostile one cannot exhaust the host.
    """

    # ---- ingestion ------------------------------------------------------
    max_line_bytes: int = 1_048_576          # 1 MiB per JSONL record
    max_nesting_depth: int = 64              # JSON containers, before parsing
    max_record_keys: int = 512               # top-level keys in one record
    max_events_total: int = 2_000_000        # per scoring run
    max_events_per_session: int = 100_000
    max_sessions: int = 100_000

    # ---- identity and correlation ---------------------------------------
    max_span_chars: int = 256
    max_session_key_chars: int = 256
    max_tool_name_chars: int = 256
    max_identity_chars: int = 256            # host, user, agent_name, framework

    # ---- semantic surfaces ----------------------------------------------
    max_response_chars: int = 200_000        # final response CH02 will scan
    max_user_message_chars: int = 64_000
    max_injection_markers: int = 200
    max_marker_chars: int = 256

    # ---- evidence emitted into the verdict ------------------------------
    # Bounds the OUTPUT, which is the amplification vector the review's
    # quadratic note pointed at from the wrong end.
    max_evidence_items: int = 50
    max_evidence_value_chars: int = 512
    max_policy_data_keys: int = 20
    max_findings_per_check: int = 20

    # ---- CLI reject policy ----------------------------------------------
    max_rejects: int | None = None           # None = unlimited
    max_reject_ratio: float | None = None    # None = unlimited, else 0.0..1.0

    def digest(self) -> str:
        """Stable hash of this bound set, for the verdict's config_hash.

        Two runs that disagree about what they refused to parse are not
        comparable, and an analyst needs to be able to see that from the record
        rather than from a changelog.
        """
        blob = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def with_overrides(self, **kw: Any) -> Limits:
        """Return a copy with the non-None overrides applied."""
        return replace(self, **{k: v for k, v in kw.items() if v is not None})


DEFAULT_LIMITS = Limits()


def json_depth_exceeds(text: str, max_depth: int) -> bool:
    """True if ``text`` nests JSON containers deeper than ``max_depth``.

    A pre-scan, deliberately, because ``json.loads`` is recursive and blows the
    C stack before any Python-level guard can see the input. Catching
    RecursionError afterwards works but leaves the interpreter close to a limit
    it should never have approached; refusing the line first is cheaper and does
    not depend on the recursion limit being set to any particular value.

    String contents are skipped so that a JSON string full of braces cannot be
    mistaken for nesting. Only structural brackets count.
    """
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "[" or ch == "{":
            depth += 1
            if depth > max_depth:
                return True
        elif ch == "]" or ch == "}":
            depth -= 1
    return False
