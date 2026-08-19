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
import math
from dataclasses import asdict, dataclass, fields, replace
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
REJECT_TOO_MANY_RECORDS = "RECORD_BUDGET_EXHAUSTED"
REJECT_TOO_MANY_BYTES = "INPUT_BYTE_BUDGET_EXHAUSTED"
REJECT_TOO_MANY_REJECTS = "REJECT_BUDGET_EXHAUSTED"
REJECT_RATIO_EXCEEDED = "REJECT_RATIO_EXCEEDED"
REJECT_MEMORY_BUDGET = "RESIDENT_MEMORY_BUDGET_EXHAUSTED"

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
# The upstream scanner's claim about a record. CH03 is the only check that turns
# somebody else's assertion into a critical finding, so it is the one place a
# type error was worth a severity: `has_injection_patterns: "false"` is a
# truthy string, and reading it as truth produced a critical
# completed-action finding on a session where no scanner had found anything.
# Exact types only, and a malformed claim is ABSENT rather than believed.
DEFECT_SCANNER_CLAIM_TYPE = "INVALID_SCANNER_CLAIM"
DEFECT_INJECTION_MARKERS_TYPE = "INVALID_INJECTION_MARKERS"

# --- P1 evidence sidecars (docs/EVIDENCE-TRUST.md) -------------------------
# A malformed evidence object is treated as ABSENT, never as a weaker version of
# itself. That direction matters more here than anywhere else in the firewall:
# a half-parsed approval that still binds to a span would let a producer buy a
# bypass with a type error, and a half-parsed integrity object would let one buy
# silence. Absent is fail-closed for all three -- no approval means an
# unapproved continuation, no integrity means the session is reported as
# unattested.
DEFECT_INTEGRITY_TYPE = "INVALID_INTEGRITY_OBJECT"
DEFECT_RECEIPT_TYPE = "INVALID_EFFECT_RECEIPT"
DEFECT_APPROVAL_TYPE = "INVALID_APPROVAL_OBJECT"
DEFECT_ENFORCEMENT_TYPE = "INVALID_POLICY_ENFORCEMENT"

# COH-R02. Peak resident bytes per byte of accepted input, measured across
# record shapes and rounded up for headroom; see max_resident_bytes.
#
# R-11. This constant alone cannot bound the cost, and the reason is not that
# it is set too low. A byte count cannot see SHAPE. Measured on this host,
# Python 3.11, peak traced memory through the full load path against raw input
# bytes, 120 records each carrying 900 elements:
#
#     arrays of empty maps      18.2x
#     arrays of one-key maps    19.4x
#     arrays of empty lists      2.9x
#     arrays of small integers   6.2x
#
# A factor of six between shapes that are within a few percent of each other on
# the wire, and an external review measured 51x for the map-heavy case on a
# different host -- which is the same finding, louder: whatever single number
# is chosen is wrong for some shape, and raising it until it is safe for the
# worst one makes it useless for the common one.
#
# So the estimate is now the LARGER of the byte estimate and a shape estimate,
# and the shape is counted during the parse rather than inferred after it.
RESIDENT_BYTES_PER_INPUT_BYTE = 32

# Measured the same way: total peak divided by objects built. An empty dict is
# 64 bytes in CPython 3.11 before anything is in it, and each one is retained
# again in the Event, the sealed session tuple and the identity map. Rounded up
# from ~197 bytes per one-key object with headroom for those copies.
RESIDENT_BYTES_PER_CONTAINER = 256
RESIDENT_BYTES_PER_KEY = 64

REJECT_RECORD_SHAPE = "RECORD_SHAPE_EXCEEDED"

ALL_REJECT_CODES = (
    REJECT_MALFORMED_JSON, REJECT_NOT_AN_OBJECT, REJECT_LINE_TOO_LONG,
    REJECT_NESTING_TOO_DEEP, REJECT_UNDECODABLE, REJECT_TOO_MANY_EVENTS,
    REJECT_TOO_MANY_SESSIONS, REJECT_TOO_MANY_KEYS, REJECT_TOO_MANY_RECORDS,
    REJECT_TOO_MANY_BYTES, REJECT_TOO_MANY_REJECTS, REJECT_RATIO_EXCEEDED,
    REJECT_MEMORY_BUDGET, REJECT_RECORD_SHAPE,
)

ALL_DEFECT_CODES = (
    DEFECT_EVENT_TYPE_TYPE, DEFECT_SPAN_TYPE, DEFECT_SPAN_LENGTH,
    DEFECT_SESSION_KEY_TYPE, DEFECT_TOOL_NAME_TYPE, DEFECT_TOOL_NAME_LENGTH,
    DEFECT_RESPONSE_TEXT_TYPE, DEFECT_RESPONSE_TEXT_LENGTH, DEFECT_TIMESTAMP,
    DEFECT_IDENTITY_TYPE, DEFECT_DATA_TYPE, DEFECT_REVERSIBLE_TYPE,
    DEFECT_NUMERIC_NONFINITE, DEFECT_INTEGRITY_TYPE, DEFECT_RECEIPT_TYPE,
    DEFECT_APPROVAL_TYPE, DEFECT_ENFORCEMENT_TYPE,
    DEFECT_SCANNER_CLAIM_TYPE, DEFECT_INJECTION_MARKERS_TYPE,
)


class LimitsError(ValueError):
    """A bound that is not a bound.

    C4-05. ``Limits`` accepted anything the type annotations suggested and
    checked none of it, so ``Limits(max_evidence_items=-1)`` constructed happily
    and then SILENTLY DISABLED the output cap, because ``cap_list`` reads a
    negative limit as unlimited. A deployment lowering a bound by typo raised the
    ceiling instead, and nothing anywhere said so. ``max_reject_ratio=2.0`` was
    accepted the same way, which is a reject budget that can never trip.

    A bound that cannot be trusted to bound is worse than no bound, because the
    operator believes it is there.
    """


# Fields whose value may be None (unlimited) and are otherwise counts.
_OPTIONAL_COUNT_FIELDS = frozenset({"max_rejects"})
# Fields whose value may be None (unlimited) and are otherwise a 0.0..1.0 ratio.
_OPTIONAL_RATIO_FIELDS = frozenset({"max_reject_ratio"})
# Integer fields where zero is meaningful rather than a disabled bound.
_NONNEGATIVE_INT_FIELDS = frozenset({"max_reject_ratio_floor"})
# Fields measured in seconds rather than in things counted. Finite and >= 0:
# zero is a real setting (tolerate no skew at all) and a non-finite value would
# disable the bound rather than widen it, which is the R-13 fault one layer up.
_NONNEGATIVE_SECONDS_FIELDS = frozenset({"max_future_skew_s",
                                         "max_signature_seconds"})


@dataclass(frozen=True)
class Limits:
    """Every bound Cohaera enforces, and the digest of the set it used.

    Defaults are sized for a collector VM reading agent telemetry, not for a
    benchmark. They are deliberately generous enough that no honest producer
    trips them and tight enough that a hostile one cannot exhaust the host.

    Every field is validated at construction. See :class:`LimitsError`; the
    rules are enumerated in ``__post_init__`` and ``test_hostile`` asserts that
    every field is covered by exactly one of them, so a bound added later cannot
    quietly escape validation.
    """

    # ---- ingestion ------------------------------------------------------
    max_line_bytes: int = 1_048_576          # 1 MiB per JSONL record
    max_nesting_depth: int = 64              # JSON containers, before parsing
    max_record_keys: int = 512               # top-level keys in one record
    max_events_total: int = 2_000_000        # ACCEPTED events per scoring run
    max_events_per_session: int = 100_000
    max_sessions: int = 100_000

    # C4-02. ``max_events_total`` counts only what was ACCEPTED, so a file of
    # nothing but malformed lines passed through it untouched: every record was
    # still read, decoded, depth-scanned and hashed, and the run was bounded by
    # the size of the attacker's file rather than by any number here. These two
    # bound the WORK, not the yield, and are checked on every record.
    max_records_total: int = 4_000_000       # records READ, accepted or not
    max_input_bytes: int = 2_147_483_648     # 2 GiB of record bytes per run

    # COH-R02. THE BOUND THAT WAS MISSING, AND WHY THE ONES ABOVE ARE NOT IT.
    #
    # Every bound above counts input. None of them counts what the input turns
    # INTO, and this design holds the whole run in memory: `load` materialises
    # every Event, groups them, and returns every Session at once. A parsed
    # record is not the size of its bytes -- it is a dict of str objects, a
    # frozen copy, and cached derived values -- so the ratio is large and it is
    # driven by how many KEYS a record has rather than how long it is.
    #
    # Measured, peak RSS against input bytes, 20,000 records per shape:
    #
    #     8 keys per record       26.7x        128 keys      18.0x
    #     40 keys                 21.6x        500 keys      20.1x
    #     one 3 KB string          1.9x        typical observra record  16.3x
    #
    # So `max_input_bytes` at 2 GiB was a licence for roughly 64 GiB of
    # process. It read as a bound and behaved as a suggestion.
    #
    # RESIDENT_BYTES_PER_INPUT_BYTE is the factor rounded up with headroom, and
    # `max_resident_bytes` is the budget an operator actually cares about. With
    # the defaults, memory binds first at about 64 MiB of accepted input --
    # thirty-two times stricter than before, and the number is now one somebody
    # can reason about against the RAM on the box.
    #
    # It is conservative for string-heavy telemetry, which amplifies about 2x
    # rather than 20x. That direction is deliberate: a budget that stops a run
    # early is an inconvenience, and one that stops it late is an OOM kill.
    #
    # THIS IS A BUDGET, NOT AN ARCHITECTURE. The honest fix is to stop holding
    # the run in memory -- bounded session windows, a spool, external sorting.
    # Until that exists this makes the failure a reported abort with a reason
    # code instead of the kernel choosing which process dies.
    max_resident_bytes: int = 2_147_483_648  # 2 GiB of assembled state

    # R-11. Per RECORD, checked during the parse. One 1 MiB line can build
    # tens of thousands of objects, and the between-lines budget check cannot
    # see that until the record is already in memory. These are generous for
    # real telemetry -- the corpus's largest record builds under a hundred
    # objects -- and cheap to raise for a producer that genuinely needs more.
    max_containers_per_record: int = 20_000
    max_keys_per_record: int = 50_000

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

    # ---- capability manifest --------------------------------------------
    # C4-06. The manifest is read from a file the operator names, but "the
    # operator named it" is not the same as "the operator wrote it" -- it is
    # routinely generated by the producer being assessed. It gets the same
    # treatment as telemetry.
    max_manifest_bytes: int = 4_194_304      # 4 MiB of manifest JSON
    max_manifest_tools: int = 10_000
    max_manifest_field_chars: int = 256      # tool id, destination, arg name
    max_manifest_sensitive_args: int = 64    # per tool

    # ---- P1 evidence (docs/EVIDENCE-TRUST.md) ---------------------------
    # Every one of these bounds an attacker-chosen quantity. A producer picks
    # how many streams it claims, how far out of order it delivers, and how many
    # signatures it asks to have checked -- and a signature check is a few
    # milliseconds of pure-Python scalar multiplication (about 2.5 ms since
    # ed25519._mul_base precomputed the fixed-base half of it; it was 4), which
    # is the most expensive thing in this codebase per unit of attacker effort.
    # The comb changed the constant, not the shape: the work is still linear in
    # a number the producer chooses, which is why the bound below stays.
    max_integrity_streams: int = 10_000
    # How far a record may arrive out of order before the gap ahead of it is
    # called a deletion. This is the reordering-versus-deletion decision from
    # EVIDENCE-TRUST section 2, and it is a bound rather than a heuristic
    # because the buffer it governs is producer-controlled.
    max_reorder_window: int = 64
    # R-12. TWO bounds, because a count is not a time.
    #
    # A trusted key id with an invalid signature costs a full verification --
    # the answer is not known until the scalar work is done -- and the producer
    # decides how many arrive. The count has always been charged BEFORE the
    # verification runs, so the accounting is right; what it cannot do is bound
    # the wall clock, because the cost of one verification is a property of the
    # host and not of this file. Measured here at about 0.5 ms per full invalid
    # verification, so 100,000 is roughly fifty seconds; an external review
    # measured about three minutes for the same cap on a slower machine.
    #
    # The seconds bound is the one that holds across hosts. Both are budgets
    # rather than errors: exhausting either yields INTEGRITY_SIGNATURE_BUDGET_-
    # EXHAUSTED and an evidence status that says the attestation was not
    # established, which is the coverage-contract answer rather than a crash or
    # a silent pass.
    max_signature_verifications: int = 100_000
    max_signature_seconds: float = 30.0
    max_approvals_per_session: int = 1_000
    max_collector_keys: int = 1_000
    max_keyfile_bytes: int = 1_048_576
    # R-13. How far past --evidence-as-of a signature-verified record may be
    # dated before it is INTEGRITY_EVIDENCE_FROM_FUTURE. Five minutes, which is
    # the tolerance Kerberos has used for decades for the same reason: it
    # absorbs ordinary NTP disagreement between two hosts and nothing more.
    # Zero would make every slightly-fast collector inadmissible; an hour would
    # let a wrong clock buy an hour of unearned freshness. Only meaningful when
    # a freshness bound is set, since without one nothing is aged at all.
    max_future_skew_s: float = 300.0
    # ---- the seen-stream ledger -----------------------------------------
    # The one piece of state Cohaera keeps between runs, so it is also the one
    # that can grow without an operator noticing. A stream id is producer-chosen,
    # so a hostile producer can mint a new one per record and turn the ledger
    # into an unbounded disk write on the collector host -- which is the same
    # amplification fault as the 6.3 MB verdict, relocated to a file that
    # persists. Bounded, with the eviction REPORTED, because an evicted stream
    # is a stream whose replay is no longer detectable.
    max_ledger_streams: int = 100_000
    max_ledger_bytes: int = 33_554_432       # 32 MiB of ledger JSON

    # ---- CLI reject policy ----------------------------------------------
    max_rejects: int | None = None           # None = unlimited
    max_reject_ratio: float | None = None    # None = unlimited, else 0.0..1.0
    # The ratio is meaningless on a tiny sample: one bad line out of one is a
    # ratio of 1.0 and would abort a healthy 10 GB file on its first hiccup. The
    # live check waits for this many records before it starts believing itself.
    max_reject_ratio_floor: int = 100

    def __post_init__(self) -> None:
        """Refuse a bound that cannot bound. See :class:`LimitsError`."""
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in _OPTIONAL_COUNT_FIELDS:
                if value is None:
                    continue
                if isinstance(value, bool) or not isinstance(value, int):
                    raise LimitsError(
                        f"{f.name} must be an int or None, got {value!r}")
                if value < 0:
                    raise LimitsError(f"{f.name} must be >= 0, got {value!r}")
            elif f.name in _OPTIONAL_RATIO_FIELDS:
                if value is None:
                    continue
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise LimitsError(
                        f"{f.name} must be a number or None, got {value!r}")
                if not math.isfinite(value) or not 0.0 <= float(value) <= 1.0:
                    raise LimitsError(
                        f"{f.name} must be within 0.0..1.0, got {value!r}")
            elif f.name in _NONNEGATIVE_SECONDS_FIELDS:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise LimitsError(
                        f"{f.name} must be a number of seconds, got {value!r}")
                if not math.isfinite(value) or float(value) < 0.0:
                    raise LimitsError(
                        f"{f.name} must be a finite number of seconds >= 0, "
                        f"got {value!r}")
            else:
                floor = 0 if f.name in _NONNEGATIVE_INT_FIELDS else 1
                if isinstance(value, bool) or not isinstance(value, int):
                    raise LimitsError(f"{f.name} must be an int, got {value!r}")
                if value < floor:
                    raise LimitsError(
                        f"{f.name} must be >= {floor}, got {value!r}")

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
