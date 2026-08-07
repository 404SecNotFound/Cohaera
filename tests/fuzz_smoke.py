"""Malformed-input fuzz smoke test.

The third external review found six exception classes with a 50,000-case
malformed-input run. Every one of them was a type that a producer can put in a
JSON field and that the code then handed to an operation which assumed
otherwise: a list into a dict lookup, an object into ``.lower()``, ten thousand
nested arrays into a recursive parser.

This is the small, deterministic version that runs on every commit. It is a
smoke test, not a campaign: it generates a few thousand hostile records rather
than fifty thousand, with a fixed seed so a failure is reproducible from the
seed alone. Run it with a larger count locally before a release.

    python tests/fuzz_smoke.py            # 2000 trials, the CI default
    python tests/fuzz_smoke.py 50000      # the review's campaign size

Exit code 0 means no trial raised. Any raised exception is printed with the
record that produced it and the exit code is 1.
"""

from __future__ import annotations

import json
import random
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.checks import SequenceGrammar, run_all
from cohaera.identity import Correlator
from cohaera.ingest import assemble, read_events
from cohaera.limits import Limits
from cohaera.model import Event, to_cim_event
from cohaera.validate import IngestReport

SEED = 20260807

# Every one of these is a value a producer can put in any JSON field, and every
# one of them reached a type-specific operation somewhere in the pre-0.2 code.
# NOTE ON ESCAPES. The hostile strings below are written as \u/\x escapes rather
# than as literal characters. U+202E in particular is the Trojan Source bidi
# override (CVE-2021-42574): pasted raw, it changes how the surrounding line
# RENDERS to a human reviewer without changing what Python executes. A file that
# fuzzes a security tool is the last place that should ship an unreadable line.
SCALARS = [
    None, True, False, 0, 1, -1, 2 ** 63, -(2 ** 63), 0.0, 1.5, -1.5,
    float("inf"), float("-inf"), float("nan"),
    "", " ", "\x00", "\n", "\x1b[2J", "\u202e",       # bidi override, escaped: see the note below
    "\U0001f642", "\\", '"',
    "a" * 5000, "0", "1e400", "nan", "inf", "NaN", "Infinity",
    "<unnamed>", "send_email", "tool_start",
]

ENVELOPE = ["event_id", "timestamp", "session_id", "trace_id", "span_id",
            "event_type", "agent_name", "tool_name", "framework", "host",
            "user", "data", "log_source_type", "schema", "type"]

DATA_KEYS = ["reversible", "tool_args", "tool_result", "duration_ms",
             "error_class", "error_type_name", "response_text",
             "injection_patterns", "has_injection_patterns", "current_depth",
             "session_cost_usd", "cost_usd", "source_agent", "target_agent",
             "user_message_text", "threshold_usd", "max_depth", "policy_id"]

EVENT_TYPES = ["tool_start", "tool_end", "tool_error", "model_response",
               "cost_threshold_exceeded", "depth_exceeded", "agent_handoff",
               "user_message", "session_start", "agent_end", ""]

# Lines that are not records at all. The reader must quarantine each of these
# and carry on rather than terminating the run.
BAD_LINES = [
    "[" * 5000 + "]" * 5000,        # RecursionError in the decoder (BUG-03)
    "{" * 300,
    "not json at all",
    "[1,2,3]",
    '"just a string"',
    "null",
    "123",
    "{}",
    '{"a":',
    "\x00\x01\x02",
    "x" * 2_000_000,                # oversize line
    "",
    "   ",
    '{"event_type":"tool_start","timestamp":1e400}',
    '{"event_type":"tool_start","timestamp":NaN}',
]


def _no_bare_constants(name: str):
    """json.loads accepts NaN and Infinity by default. Cohaera must not emit them.

    Checked by round-trip rather than substring search: a record can legitimately
    carry the STRING "Infinity" in a text field, and a naive scan of the
    serialised blob fails on valid output.
    """
    raise AssertionError(f"bare JSON constant {name!r} was emitted")


def rand_value(rng: random.Random, depth: int = 0):
    r = rng.random()
    if depth >= 3 or r < 0.6:
        return rng.choice(SCALARS)
    if r < 0.8:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {str(rng.choice(SCALARS))[:20]: rand_value(rng, depth + 1)
            for _ in range(rng.randint(0, 4))}


def rand_record(rng: random.Random) -> dict:
    rec: dict = {}
    for k in ENVELOPE:
        if rng.random() < 0.75:
            rec[k] = rand_value(rng)
    if rng.random() < 0.7:
        rec["event_type"] = rng.choice(EVENT_TYPES)
    if rng.random() < 0.6:
        rec["timestamp"] = 1_785_700_000.0 + rng.random() * 100
    if rng.random() < 0.5:
        rec["session_id"] = rng.choice(["s1", "s2", "", None, 5, ["a"]])
    data = {k: rand_value(rng) for k in DATA_KEYS if rng.random() < 0.4}
    if rng.random() < 0.8:
        rec["data"] = data
    return rec


def score_in_memory(rng: random.Random, failures: dict) -> int:
    records = [rand_record(rng) for _ in range(rng.randint(1, 8))]
    try:
        sessions = assemble([Event(raw=r) for r in records],
                            correlator=Correlator(b"fuzz-secret"))
        grammar = SequenceGrammar().fit(sessions) if rng.random() < 0.3 else None
        for s in sessions:
            findings, cov = run_all(s, grammar)
            blob = json.dumps(to_cim_event(s, findings, coverage=cov,
                                           provenance={"analysis_run_id": "fuzz"},
                                           sequence=0), allow_nan=False)
            json.loads(blob, parse_constant=_no_bare_constants)
            if rng.random() < 0.2:
                # BUG-05: derived state must refresh when the session grows.
                s.add_event(Event(raw=rand_record(rng)))
                run_all(s, grammar)
    except Exception as exc:
        failures.setdefault(f"{type(exc).__name__}: {str(exc)[:90]}",
                            (records, traceback.format_exc()))
    return len(records)


def score_from_file(rng: random.Random, path: Path, failures: dict) -> int:
    lines = [rng.choice(BAD_LINES) if rng.random() < 0.4
             else json.dumps(rand_record(rng), default=str)
             for _ in range(rng.randint(1, 12))]
    path.write_text("\n".join(lines) + ("\n" if rng.random() < 0.8 else ""),
                    encoding="utf-8", errors="replace")
    try:
        limits = Limits(max_line_bytes=rng.choice([1024, 65536, 1_048_576]),
                        max_nesting_depth=rng.choice([8, 64]))
        rep = IngestReport()
        events = list(read_events(path, limits=limits, report=rep, quiet=True))
        for s in assemble(events, limits=limits,
                          correlator=Correlator(None, limits=limits), report=rep):
            findings, cov = run_all(s, limits=limits)
            blob = json.dumps(to_cim_event(s, findings, coverage=cov),
                              allow_nan=False)
            json.loads(blob, parse_constant=_no_bare_constants)
    except Exception as exc:
        failures.setdefault(f"INGEST {type(exc).__name__}: {str(exc)[:90]}",
                            (lines[:3], traceback.format_exc()))
    return len(lines)


def score_raw_bytes(rng: random.Random, path: Path, failures: dict) -> int:
    blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 2000)))
    path.write_bytes(blob)
    try:
        rep = IngestReport()
        events = list(read_events(path, report=rep, quiet=True))
        for s in assemble(events, report=rep):
            findings, cov = run_all(s)
            json.dumps(to_cim_event(s, findings, coverage=cov), allow_nan=False)
    except Exception as exc:
        failures.setdefault(f"BYTES {type(exc).__name__}: {str(exc)[:90]}",
                            (blob[:60], traceback.format_exc()))
    return 1


def main(trials: int = 2000, seed: int = SEED) -> int:
    rng = random.Random(seed)
    failures: dict = {}
    records = 0
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fuzz.jsonl"
        for i in range(trials):
            phase = i % 10
            if phase < 7:
                records += score_in_memory(rng, failures)
            elif phase < 9:
                records += score_from_file(rng, path, failures)
            else:
                records += score_raw_bytes(rng, path, failures)

    print(f"[fuzz] seed={seed} trials={trials:,} records={records:,}")
    print(f"[fuzz] unique exception classes: {len(failures)}")
    for key, (sample, tb) in failures.items():
        print("\n" + "=" * 70)
        print(key)
        print("sample:", repr(sample)[:800])
        print(tb[-2000:])
    return 1 if failures else 0


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    raise SystemExit(main(n))
