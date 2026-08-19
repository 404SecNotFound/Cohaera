"""Hostile-input regression tests.

Every test in this file corresponds to a defect that was REPRODUCED against
revision c832721 before it was fixed. The reproduction came first; the fix came
second; this file is what stops it coming back.

The existing suites test intended shapes. ``test_cohaera.py`` builds well-formed
fixtures and asserts the checks fire correctly on them. ``test_evasion.py``
builds well-formed fixtures that defeat the checks. Neither one puts a list where
a string belongs, and that is the entire class of fault the third review found:

    span_id: ["a","b"]         -> TypeError: unhashable type: 'list'
    span_id: true / 1          -> two calls share one dictionary key
    response_text: {"x": 1}    -> AttributeError: 'dict' has no attribute 'lower'
    10,000 nested arrays       -> RecursionError, parsing terminated
    no identity fields at all  -> unrelated records merged into one session

A telemetry trust boundary is graded on the input it was not designed for.
Run: PYTHONPATH=src python3 -m pytest tests/test_hostile.py -v
"""

from __future__ import annotations

import gc
import json
import random
import subprocess
import sys
import time
import tracemalloc
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.capabilities import EMPTY_MANIFEST, CapabilityManifest, ManifestError
from cohaera.checks import (
    ORDER_AFTER,
    ORDER_INDETERMINATE,
    ORDER_NOT_AFTER,
    R_NO_TOOL_RESULT,
    R_ORDER_INDETERMINATE,
    R_SCANNER_PARTIAL,
    SequenceGrammar,
    _ordering,
    _References,
    _scanner_coverage,
    ch02_concealment_gap,
    ch03_untrusted_to_consequential,
    ch04_guardrail_overrun,
    ch07_effect_contradiction,
    coverage,
    run_all,
    unordered_after_marker,
)
from cohaera.cli import (
    EXIT_BUDGET,
    EXIT_ERROR,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_STRICT_REJECT,
    _probe_writable,
    _write_reject_log_atomic,
    main,
)
from cohaera.evidence import RECEIPT_SCHEMA, TrustStore, TrustStoreError, arg_digest
from cohaera.identity import (
    KIND_ISOLATED_ANON,
    KIND_SCOPED_ANON,
    NO_TRUST_CONFIG,
    Correlator,
    run_id,
)
from cohaera.ingest import assemble, load, read_events
from cohaera.limits import (
    DEFAULT_LIMITS,
    REJECT_LINE_TOO_LONG,
    REJECT_MALFORMED_JSON,
    REJECT_MEMORY_BUDGET,
    REJECT_NESTING_TOO_DEEP,
    REJECT_NOT_AN_OBJECT,
    REJECT_RATIO_EXCEEDED,
    REJECT_TOO_MANY_BYTES,
    REJECT_TOO_MANY_RECORDS,
    REJECT_TOO_MANY_REJECTS,
    REJECT_UNDECODABLE,
    RESIDENT_BYTES_PER_INPUT_BYTE,
    Limits,
    LimitsError,
)
from cohaera.model import (
    Event,
    SealedSessionError,
    Session,
    cap_list,
    json_safe,
    to_cim_event,
)
from cohaera.validate import (
    IngestReport,
    Reject,
    StrictJSONError,
    sanitise_display,
    strict_json_loads,
)

BASE = 1_785_700_000.0

# Values a producer can put in any JSON field. Every one of these reached a
# type-specific operation somewhere in the old code.
HOSTILE_SCALARS = [None, True, False, 0, -1, 1.5, float("inf"), float("-inf"),
                   float("nan"), "", "   ", "x" * 10_000, [], {}, ["a", "b"],
                   {"a": 1}, [{"b": [1, 2]}]]


def ev(etype, ts=0.0, sid="s1", **kw):
    data = kw.pop("data", {})
    raw = {"timestamp": BASE + ts if isinstance(ts, (int, float)) else ts,
           "event_type": etype, "data": data}
    if sid is not None:
        raw["session_id"] = sid
    raw.update(kw)
    return Event(raw=raw)


def sess(*events, sid="s1"):
    return Session(session_id=sid, events=list(events))


def write_jsonl(tmp_path, lines, name="t.jsonl"):
    p = tmp_path / name
    p.write_text("".join(line if line.endswith("\n") else line + "\n"
                         for line in lines), encoding="utf-8")
    return p


# =====================================================================
# BUG-01 / BUG-04  span identity
# =====================================================================

@pytest.mark.parametrize("span", [["a", "b"], {"a": 1}, 1, 1.5, True, False,
                                  None, "", 3.0, [1, [2, [3]]]])
def test_bug01_non_string_span_never_crashes_assembly(span):
    """BUG-01. A list or dict span_id reached ``open_by_span[sid]``.

    ``unhashable type: 'list'`` raised from inside a security check takes down
    the whole scoring run, so one crafted record denies service for every other
    session in the same file.
    """
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id=span,
                data={"reversible": False}),
             ev("tool_end", 1, tool_name="send_email", span_id=span,
                data={"reversible": False}))
    calls = s.tool_calls                      # must not raise
    assert calls, "the call must still be observed, not dropped"
    assert all(c.span_id is None or isinstance(c.span_id, str) for c in calls)


def test_bug04_boolean_and_integer_spans_do_not_alias():
    """BUG-04. Python hashes True and 1 identically, so ``{True: x}[1]`` hits.

    Two concurrent calls with spans ``true`` and ``1`` shared one dictionary
    slot, and the terminal event for span 1 closed the call opened with span
    true. That is call-identity corruption: a success recorded against the wrong
    action.

    Both spans are now rejected as non-strings, so the calls fall back to
    name FIFO and the terminal event closes the one that started first. The
    important property is that the SECOND call is not silently reported as
    complete on the strength of the first call's terminal event.
    """
    s = sess(ev("tool_start", 0, tool_name="t", span_id=True),
             ev("tool_start", 1, tool_name="t", span_id=1),
             ev("tool_end", 2, tool_name="t", span_id=1))
    states = [c.state for c in s.tool_calls]
    assert states.count("complete") == 1, states
    assert states.count("open") == 1, states
    assert all(c.span_id is None for c in s.tool_calls)


def test_over_long_span_is_rejected_not_truncated():
    """A truncated identity is a forged identity: two long spans sharing a
    prefix would collide the moment they were cut to a fixed width."""
    long_span = "s" * (DEFAULT_LIMITS.max_span_chars + 1)
    e = ev("tool_start", 0, tool_name="t", span_id=long_span)
    assert e.span_id is None
    assert "SPAN_EXCEEDS_MAX_CHARS" in e.defects


def test_span_identity_still_wins_when_valid():
    """The R2-01 strict-span property must survive the type fix."""
    s = sess(ev("tool_start", 0, tool_name="t", span_id="A"),
             ev("tool_start", 1, tool_name="t", span_id="B"),
             ev("tool_end", 2, tool_name="t", span_id="B"))
    by_span = {c.span_id: c.state for c in s.tool_calls}
    assert by_span["B"] == "complete"
    assert by_span["A"] == "open"


# =====================================================================
# BUG-02  final response type
# =====================================================================

@pytest.mark.parametrize("bad", [{"x": 1}, ["a"], 5, 5.5, True, [{"n": 1}]])
def test_bug02_non_string_response_text_does_not_crash_ch02(bad):
    """BUG-02. ``.lower()`` on a dict raised AttributeError inside CH02."""
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A",
                data={"reversible": False}),
             ev("tool_end", 1, tool_name="send_email", span_id="A",
                data={"reversible": False}),
             ev("model_response", 2, data={"response_text": bad}))
    assert ch02_concealment_gap(s) == []       # must not raise
    assert s.final_response is None


def test_bug02_bad_response_type_is_reported_as_blind_not_clean():
    """SEC-02. Silently treating a malformed field as absent is fail-open.

    CH02 not firing looks identical to CH02 passing unless coverage says which
    one happened, and the reason code has to distinguish "the producer never
    captured a summary" from "the producer sent a summary that was not text".
    """
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A",
                data={"reversible": False}),
             ev("tool_end", 1, tool_name="send_email", span_id="A",
                data={"reversible": False}),
             ev("model_response", 2, data={"response_text": {"evil": 1}}))
    cov = coverage(s, None)
    ch02 = next(c for c in cov["checks"] if c["check"] == "CH02_concealment_gap")
    assert ch02["status"] == "not_evaluated"
    assert ch02["reasons"] == ["FINAL_RESPONSE_WRONG_TYPE"]


def test_over_long_response_is_truncated_and_says_so():
    """A semantic surface may be truncated. An identity may not."""
    limits = Limits(max_response_chars=100)
    e = Event(raw={"event_type": "model_response", "timestamp": BASE,
                   "data": {"response_text": "a" * 500}}, limits=limits)
    assert len(e.response_text) == 100
    assert "RESPONSE_TEXT_TRUNCATED" in e.defects


# =====================================================================
# BUG-03  parser resource bounds
# =====================================================================

def test_bug03_deeply_nested_json_is_quarantined_not_fatal(tmp_path):
    """BUG-03. json.loads is recursive; 10,000 nested arrays raised
    RecursionError, which ``except json.JSONDecodeError`` did not catch."""
    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "a", "tool_name": "x"})
    p = write_jsonl(tmp_path, ["[" * 10_000 + "]" * 10_000, good])
    rep = IngestReport()
    events = list(read_events(p, report=rep, quiet=True))
    assert len(events) == 1, "the valid record after the bomb must still be read"
    assert rep.reject_codes.get(REJECT_NESTING_TOO_DEEP) == 1


def test_depth_guard_ignores_brackets_inside_strings(tmp_path):
    """A JSON string full of braces is not nesting and must not be refused."""
    payload = json.dumps({"event_type": "x", "timestamp": BASE, "session_id": "a",
                          "data": {"note": "{" * 500 + "[" * 500}})
    rep = IngestReport()
    assert len(list(read_events(write_jsonl(tmp_path, [payload]),
                                report=rep, quiet=True))) == 1
    assert rep.rejected == 0


def test_oversize_line_is_bounded_without_being_buffered(tmp_path):
    """A line larger than the bound must be refused, and the reader must
    resynchronise on the next newline rather than losing the rest of the file."""
    limits = Limits(max_line_bytes=1024)
    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "a", "tool_name": "x"})
    huge = json.dumps({"event_type": "x", "timestamp": BASE, "session_id": "b",
                       "data": {"pad": "A" * 20_000}})
    p = write_jsonl(tmp_path, [huge, good, huge, good])
    rep = IngestReport()
    events = list(read_events(p, limits=limits, report=rep, quiet=True))
    assert len(events) == 2, "both good records after oversize lines must survive"
    assert rep.reject_codes.get(REJECT_LINE_TOO_LONG) == 2


def test_invalid_utf8_is_quarantined(tmp_path):
    p = tmp_path / "b.jsonl"
    p.write_bytes(b'{"event_type":"x","timestamp":1,"session_id":"a"}\n'
                  b'\xff\xfe not utf8\n')
    rep = IngestReport()
    events = list(read_events(p, report=rep, quiet=True))
    assert len(events) == 1
    assert rep.reject_codes.get(REJECT_UNDECODABLE) == 1


def test_non_object_and_malformed_lines_are_quarantined(tmp_path):
    p = write_jsonl(tmp_path, ['[1,2,3]', '"a string"', '{not json',
                               json.dumps({"event_type": "x", "timestamp": BASE,
                                           "session_id": "a"})])
    rep = IngestReport()
    events = list(read_events(p, report=rep, quiet=True))
    assert len(events) == 1
    assert rep.reject_codes.get(REJECT_NOT_AN_OBJECT) == 2
    assert rep.reject_codes.get(REJECT_MALFORMED_JSON) == 1


def test_event_budget_stops_the_run(tmp_path):
    line = json.dumps({"event_type": "x", "timestamp": BASE, "session_id": "a"})
    p = write_jsonl(tmp_path, [line] * 50)
    rep = IngestReport()
    events = list(read_events(p, limits=Limits(max_events_total=10),
                              report=rep, quiet=True))
    assert len(events) == 10
    assert rep.aborted


# =====================================================================
# BUG-05  stale derived state
# =====================================================================

def test_bug05_appending_an_event_invalidates_the_call_cache():
    """BUG-05. The cache was populated on first access and never invalidated.

    Batch loading hid this because the event list was complete before any check
    ran. A streaming service would have reported a completed call as open
    forever, which is a wrong verdict rather than a slow one.
    """
    s = sess(ev("tool_start", 0, tool_name="t", span_id="A"))
    assert s.tool_calls[0].state == "open"
    s.events.append(ev("tool_end", 1, tool_name="t", span_id="A"))
    assert s.tool_calls[0].state == "complete", "cache was not invalidated"


def test_bug05_add_event_is_the_supported_path():
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A",
                data={"reversible": False}))
    assert s.features()["unpaired_calls"] == 1
    s.add_event(ev("tool_end", 1, tool_name="send_email", span_id="A",
                   data={"reversible": False}))
    assert s.features()["unpaired_calls"] == 0
    assert s.features()["tool_call_count"] == 1


def test_bug05_every_derived_value_refreshes():
    s = sess(ev("tool_start", 0, tool_name="read_x", span_id="A"))
    assert s.final_response is None
    assert s.injection_markers == []
    s.add_event(ev("model_response", 5, data={"response_text": "done",
                                              "injection_patterns": ["X"]}))
    assert s.final_response == "done"
    assert s.injection_markers == ["X"]


# =====================================================================
# BUG-06 / BUG-07  correlation keys
# =====================================================================

def test_bug06_fully_anonymous_records_are_isolated_not_merged():
    """BUG-06. No session, no trace, no host, no user, no agent, no framework.

    There is no identity here for a merge to rest on, so bucketing by clock
    alone joined an injection marker and an egress call that had nothing in
    common except arrival time, and manufactured a critical finding out of two
    unrelated records.
    """
    a = Event(raw={"event_type": "tool_end", "timestamp": BASE,
                   "tool_name": "fetch_kb",
                   "data": {"injection_patterns": ["X"],
                            "has_injection_patterns": True}})
    b = Event(raw={"event_type": "tool_start", "timestamp": BASE + 5,
                   "tool_name": "send_email", "data": {"reversible": False}})
    sessions = assemble([a, b])
    assert len(sessions) == 2, "records with no identity must not be correlated"
    assert all(s.correlation.kind == "isolated_anonymous" for s in sessions)
    assert all(s.correlation_confidence == 0.0 for s in sessions)
    assert sum(len(run_all(s)[0]) for s in sessions
               if any(f.family == "CH03_untrusted_to_consequential"
                      for f in run_all(s)[0])) == 0


def test_scoped_anonymous_still_groups_the_same_producer():
    """The useful half of the C-04 fix must survive the BUG-06 fix."""
    c = Event(raw={"event_type": "tool_start", "timestamp": BASE, "host": "host-A",
                   "user": "alice", "tool_name": "fetch"})
    d = Event(raw={"event_type": "tool_end", "timestamp": BASE + 1, "host": "host-A",
                   "user": "alice", "tool_name": "fetch"})
    out = assemble([c, d])
    assert len(out) == 1
    assert out[0].correlation.kind == "scoped_anonymous"
    assert 0.0 < out[0].correlation_confidence < 1.0


def test_bug07_anonymous_key_does_not_leak_identity():
    """BUG-07. The key embedded repr() of host, user, agent and framework, and
    that key is emitted as session_id into a SIEM."""
    e = Event(raw={"event_type": "x", "timestamp": BASE, "host": "secret-host-01",
                   "user": "alice@corp.example", "agent_name": "billing-agent"})
    sid = assemble([e])[0].session_id
    for leaked in ("secret-host-01", "alice@corp.example", "billing-agent"):
        assert leaked not in sid, f"{leaked} leaked into the correlation key"


def test_hmac_correlation_keys_differ_per_deployment_secret():
    """With a secret, the key is an HMAC and a short identity space cannot be
    enumerated from the SIEM copy by anyone who does not hold the key."""
    raw = {"event_type": "x", "timestamp": BASE, "host": "h", "user": "u"}
    k1 = assemble([Event(raw=dict(raw))], correlator=Correlator(b"secret-one"))[0]
    k2 = assemble([Event(raw=dict(raw))], correlator=Correlator(b"secret-two"))[0]
    k3 = assemble([Event(raw=dict(raw))], correlator=Correlator(b"secret-one"))[0]
    assert k1.session_id != k2.session_id, "different secrets must not collide"
    assert k1.session_id == k3.session_id, "same secret must be stable across runs"
    assert k1.correlation.keyed is True
    assert k1.correlation.key_version == "hmac-sha256-v1"


def test_unkeyed_correlation_is_labelled_as_such():
    e = Event(raw={"event_type": "x", "timestamp": BASE, "host": "h"})
    s = assemble([e], correlator=Correlator(None))[0]
    assert s.correlation.keyed is False
    assert s.correlation.key_version == "sha256-unkeyed-v1"


def test_identity_field_separator_cannot_be_forged():
    """host "a|b" + user "c" must not collide with host "a" + user "b|c"."""
    x = assemble([Event(raw={"event_type": "e", "timestamp": BASE,
                             "host": "a|b", "user": "c"})])[0]
    y = assemble([Event(raw={"event_type": "e", "timestamp": BASE,
                             "host": "a", "user": "b|c"})])[0]
    assert x.session_id != y.session_id


@pytest.mark.parametrize("bad", [["a"], {"b": 1}, 7, True, 1.5])
def test_non_string_session_and_trace_keys_fall_through(bad):
    """A list session_id used to raise ``unhashable type`` from assembly."""
    e = Event(raw={"event_type": "x", "timestamp": BASE, "session_id": bad,
                   "trace_id": bad, "host": "h"})
    s = assemble([e])[0]                       # must not raise
    assert s.correlation.kind == "scoped_anonymous"
    assert "INVALID_SESSION_KEY_TYPE" in e.defects


# =====================================================================
# BUG-08 / BUG-09  lifecycle wording and severity
# =====================================================================

def _marker_then(result_event):
    return sess(ev("tool_end", 0, tool_name="fetch_kb", span_id="K",
                   data={"injection_patterns": ["X"], "has_injection_patterns": True}),
                ev("tool_start", 5, tool_name="send_email", span_id="B",
                   data={"reversible": False}),
                result_event)


def test_bug08_ch03_attempt_only_does_not_claim_the_call_ran():
    """BUG-08. The title said 'Attempted' and the detail said the call 'ran
    afterwards'. An open or failed call was presented as an effect."""
    s = _marker_then(ev("tool_error", 6, tool_name="send_email", span_id="B",
                        data={"reversible": False}))
    findings = ch03_untrusted_to_consequential(s)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "CH03_untrusted_to_attempted_action"
    assert f.severity == "medium"
    assert "ATTEMPTED" in f.title
    assert "ran afterwards" not in f.detail
    assert "is NOT established by this telemetry" in f.detail


def test_bug08_ch03_completed_is_a_separate_check_id():
    s = _marker_then(ev("tool_end", 6, tool_name="send_email", span_id="B",
                        data={"reversible": False}))
    findings = ch03_untrusted_to_consequential(s)
    assert [f.check for f in findings] == ["CH03_untrusted_to_completed_action"]
    assert findings[0].severity == "critical"        # completed egress
    assert findings[0].family == "CH03_untrusted_to_consequential"


def test_ch03_reports_completed_and_attempted_separately():
    s = sess(ev("tool_end", 0, tool_name="fetch_kb", span_id="K",
                data={"injection_patterns": ["X"], "has_injection_patterns": True}),
             ev("tool_start", 5, tool_name="delete_record", span_id="B",
                data={"reversible": False}),
             ev("tool_end", 6, tool_name="delete_record", span_id="B",
                data={"reversible": False}),
             ev("tool_start", 7, tool_name="send_email", span_id="C",
                data={"reversible": False}),
             ev("tool_error", 8, tool_name="send_email", span_id="C",
                data={"reversible": False}))
    checks = {f.check: f for f in ch03_untrusted_to_consequential(s)}
    assert set(checks) == {"CH03_untrusted_to_completed_action",
                           "CH03_untrusted_to_attempted_action"}
    assert checks["CH03_untrusted_to_completed_action"].severity == "high"
    assert checks["CH03_untrusted_to_attempted_action"].severity == "medium"


def test_bug09_ch04_attempt_only_does_not_claim_the_control_failed():
    """BUG-09. A cost event followed by tool_start + tool_error produced
    "the control did not stop the behaviour" at severity high.

    The action failed. This telemetry cannot say whether the guardrail, the
    tool, or something else stopped it, and asserting the guardrail was ignored
    is an attribution the data does not support.
    """
    s = sess(ev("cost_threshold_exceeded", 0, data={"session_cost_usd": 0.9}),
             ev("tool_start", 5, tool_name="delete_record", span_id="A",
                data={"reversible": False}),
             ev("tool_error", 6, tool_name="delete_record", span_id="A",
                data={"reversible": False}))
    findings = ch04_guardrail_overrun(s)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "CH04_post_guardrail_attempt"
    assert f.severity == "medium"
    assert "did not stop the behaviour" not in f.detail
    assert "CANNOT show whether the guardrail" in f.detail


def test_bug09_ch04_completed_keeps_high_severity_and_hedges_on_semantics():
    s = sess(ev("cost_threshold_exceeded", 0, data={"session_cost_usd": 0.9}),
             ev("tool_start", 5, tool_name="delete_record", span_id="A",
                data={"reversible": False}),
             ev("tool_end", 6, tool_name="delete_record", span_id="A",
                data={"reversible": False}))
    f = ch04_guardrail_overrun(s)[0]
    assert f.check == "CH04_guardrail_bypass_completed"
    assert f.severity == "high"
    assert f.evidence["policy_semantics_declared"] is False
    assert "advisory or blocking" in f.detail


def test_ch04_policy_semantics_gap_is_in_the_coverage_contract():
    s = sess(ev("cost_threshold_exceeded", 0, data={"session_cost_usd": 0.9}),
             ev("tool_start", 5, tool_name="delete_record", span_id="A",
                data={"reversible": False}),
             ev("tool_end", 6, tool_name="delete_record", span_id="A",
                data={"reversible": False}))
    cov = coverage(s, None)
    ch04 = next(c for c in cov["checks"] if c["check"] == "CH04_guardrail_overrun")
    assert "POLICY_SEMANTICS_UNDECLARED" in ch04["reasons"]
    assert "policy_semantics" in ch04["missing_surfaces"]


# =====================================================================
# BUG-10  coverage confidence
# =====================================================================

def test_bug10_low_correlation_confidence_caps_completeness():
    """A verdict assembled out of guesswork must not present itself as one
    assembled from a producer-supplied session ID."""
    events = [Event(raw={"event_type": "tool_start", "timestamp": BASE,
                         "host": "h", "tool_name": "send_email",
                         "data": {"reversible": False}}),
              Event(raw={"event_type": "tool_end", "timestamp": BASE + 1,
                         "host": "h", "tool_name": "send_email",
                         "data": {"reversible": False}})]
    s = assemble(events)[0]
    cov = coverage(s, None)
    assert cov["correlation_confidence"] < 1.0
    assert cov["completeness"] < 0.5
    assert all("CORRELATION_KEY_NOT_PRODUCER_SUPPLIED" in c["reasons"]
               for c in cov["checks"] if c["status"] == "degraded")


def test_bug10_tool_result_gap_is_charged_to_ch03_not_ch02():
    """The old code charged a missing tool_result to CH02, which reads the final
    RESPONSE. Tool-output visibility is CH03's provenance problem."""
    s = sess(ev("tool_start", 0, tool_name="fetch_kb", span_id="A"),
             ev("tool_end", 1, tool_name="fetch_kb", span_id="A",
                data={"has_injection_patterns": False}),
             ev("model_response", 2, data={"response_text": "done"}))
    cov = coverage(s, None)
    by_check = {c["check"]: c for c in cov["checks"]}
    assert "NO_TOOL_RESULT_CAPTURED" in by_check["CH03_untrusted_to_consequential"]["reasons"]
    assert "NO_TOOL_RESULT_CAPTURED" not in by_check["CH02_concealment_gap"]["reasons"]


def test_bug10_missing_scanner_makes_ch03_not_evaluated():
    """E09. With no marker field anywhere in the stream, no upstream scanner
    ran, so CH03 could not have fired. That is a blind spot, not a pass."""
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A",
                data={"reversible": False}),
             ev("tool_end", 1, tool_name="send_email", span_id="A",
                data={"reversible": False}))
    ch03 = next(c for c in coverage(s, None)["checks"]
                if c["check"] == "CH03_untrusted_to_consequential")
    assert ch03["status"] == "not_evaluated"
    assert ch03["reasons"] == ["NO_INJECTION_SCANNER_EVIDENCE"]


def test_capability_manifest_raises_classification_confidence():
    manifest = CapabilityManifest.from_obj({
        "producer": "test", "manifest_version": "1",
        "tools": {"frobnicate": {"effects": ["egress"], "reversible": False,
                                 "destination": "external:https"}}})
    s = Session(session_id="s", manifest=manifest, events=[
        ev("tool_start", 0, tool_name="frobnicate", span_id="A"),
        ev("tool_end", 1, tool_name="frobnicate", span_id="A"),
    ])
    assert s.tool_calls[0].klass == "egress"
    assert s.tool_calls[0].klass_source == "manifest"
    cov = coverage(s, None)
    assert cov["classification_confidence"] == 1.0
    assert cov["manifest_class_calls"] == 1


# -- COH-R07: a mean over calls is diluted by adding calls -------------------
#
# E02 said a violation RATE can be padded under threshold. This is the same
# attack against a different denominator: the classification confidence in every
# verdict was a mean over the session's calls, and the producer decides how many
# calls there are.


def _padded_session(known_reads: int, declared: bool) -> Session:
    """One tool Cohaera cannot classify, buried in tools it can."""
    tools = {"read_file": {"effects": ["read"]}} if declared else {}
    manifest = CapabilityManifest.from_obj(
        {"tools": tools}) if declared else EMPTY_MANIFEST
    events = [ev("tool_start", 0, tool_name="frobnicate_ledger", span_id="X"),
              ev("tool_end", 1, tool_name="frobnicate_ledger", span_id="X")]
    for i in range(known_reads):
        events += [ev("tool_start", 2 + 2 * i, tool_name="read_file", span_id=f"r{i}"),
                   ev("tool_end", 3 + 2 * i, tool_name="read_file", span_id=f"r{i}")]
    return Session(session_id="s", manifest=manifest, events=events)


@pytest.mark.parametrize("declared", [True, False])
def test_classification_confidence_cannot_be_padded_upwards(declared):
    """The reproduction. One unclassifiable call, then 0, 1, 5, 20 and 100
    harmless ones -- the confidence must not move, because the thing it is
    confident about has not changed.

    With a manifest covering the padding it reached 0.99, and a verdict claiming
    99% classification confidence over a session containing a call Cohaera could
    not classify at all is a misdescription, not a summary.
    """
    seen = {coverage(_padded_session(n, declared), None)["classification_confidence"]
            for n in (0, 1, 5, 20, 100)}
    assert seen == {0.0}, f"confidence moved with padding: {sorted(seen)}"


def test_the_share_still_says_how_much_of_the_session_was_understood():
    """The average is not deleted, it is demoted. One unknown call out of two
    and one out of a hundred are different operational situations, and the worst
    case cannot tell them apart."""
    shares = [coverage(_padded_session(n, True), None)["classification_share"]
              for n in (0, 1, 20, 100)]
    assert shares == sorted(shares), shares
    assert shares[0] == 0.0 and shares[-1] > 0.98


def test_the_worst_call_sets_the_confidence_not_the_best():
    """A session is scored as a whole, so its exposure is its least-known call.
    A single name-heuristic guess among manifest declarations caps the session
    at the heuristic's weight -- it does not average away."""
    manifest = CapabilityManifest.from_obj(
        {"tools": {"declared_tool": {"effects": ["read"]}}})
    events = [ev("tool_start", 0, tool_name="declared_tool", span_id="A"),
              ev("tool_end", 1, tool_name="declared_tool", span_id="A")]
    all_declared = Session(session_id="s", manifest=manifest, events=list(events))
    assert coverage(all_declared, None)["classification_confidence"] == 1.0

    events += [ev("tool_start", 2, tool_name="send_email", span_id="B"),
               ev("tool_end", 3, tool_name="send_email", span_id="B")]
    mixed = Session(session_id="s", manifest=manifest, events=events)
    cov = coverage(mixed, None)
    assert cov["classification_confidence"] == 0.7
    assert cov["classification_share"] == 0.85, (
        "the mean of 1.0 and 0.7 -- which is exactly what must NOT be the "
        "confidence")


def test_manifest_outranks_the_producer_reversible_flag():
    """SEC-03. ``reversible`` arrives in band from the path an attacker would
    control to hide an action. A manifest is loaded out of band."""
    manifest = CapabilityManifest.from_obj({
        "tools": {"quiet_name": {"effects": ["delete"]}}})
    s = Session(session_id="s", manifest=manifest, events=[
        ev("tool_start", 0, tool_name="quiet_name", span_id="A",
           data={"reversible": True})])
    assert s.tool_calls[0].klass == "state_change"


@pytest.mark.parametrize("bad", [
    {"tools": "not an object"},
    {"tools": {"t": {"effects": []}}},
    {"tools": {"t": {"effects": ["teleport"]}}},
    {"tools": {"t": {"effects": ["read"], "reversible": "yes"}}},
    {"tools": {"": {"effects": ["read"]}}},
    ["not", "an", "object"],
])
def test_bad_manifest_is_refused_not_half_loaded(bad):
    with pytest.raises(ManifestError):
        CapabilityManifest.from_obj(bad)


# -- COH-R06: every malformed shape must leave as a ManifestError -----------
#
# The list above is a list of shapes somebody thought of. This is the general
# claim behind it, and it is the one the sixth review asked for: whatever a
# manifest field contains, the loader raises ManifestError or it succeeds. It
# does not raise anything else, and it does not quietly succeed with the field
# dropped. Two defects were live when this was written:
#
#     effects: [{}]          -> TypeError: unhashable type: 'dict'
#     sensitive_args: 0      -> loaded, with sensitive_args silently empty
#
# The first is `in` against a frozenset hashing its operand before anything
# checked the type. The second is `spec.get(...) or []`, which turns every
# falsey non-list into an empty one and skips the type check entirely.

_HOSTILE_VALUES = (
    None, True, False, 0, 1, -1, 0.5, float("inf"), "", "x", "read",
    [], [[]], [{}], [None], [True], [0], ["read", 1], {}, {"a": 1},
    [{"nested": ["deep"]}], ("read",), b"read", "read,write",
)

_TOOL_FIELDS = ("effects", "reversible", "destination", "requires_approval",
                "sensitive_args")
_POLICY_FIELDS = ("enforcement", "description")


@pytest.mark.parametrize("field_name", _TOOL_FIELDS)
def test_no_tool_field_value_escapes_as_anything_but_a_manifest_error(field_name):
    """Exhaustive over one axis at a time, which is what makes a failure
    readable: the parametrize id names the field and the assertion names the
    value, so a regression says which field and which shape rather than
    'the fuzzer found something'."""
    for value in _HOSTILE_VALUES:
        spec = {"effects": ["read"], field_name: value}
        try:
            manifest = CapabilityManifest.from_obj({"tools": {"t": spec}})
        except ManifestError:
            continue
        except Exception as exc:          # anything else is the defect
            raise AssertionError(
                f"{field_name}={value!r} escaped as "
                f"{type(exc).__name__}: {exc}") from exc
        # Accepting it is allowed. Accepting it and then not meaning it is not:
        # a value that loads must be represented, not dropped.
        capability = manifest.get("t")
        assert capability is not None, f"{field_name}={value!r} vanished"
        if field_name == "sensitive_args" and value not in (None, []):
            # `None` is absence and `[]` is an explicit declaration of none.
            # Everything else that LOADS must be represented -- the defect was
            # `0` and `False` arriving here as an empty tuple.
            assert capability.sensitive_args, (
                f"sensitive_args={value!r} loaded as empty; a mis-typed "
                "declaration must raise, not silently declare nothing")


@pytest.mark.parametrize("field_name", _POLICY_FIELDS)
def test_no_policy_field_value_escapes_as_anything_but_a_manifest_error(field_name):
    """The policies section has the same membership-before-type bug shape:
    `enforcement not in VALID_ENFORCEMENT` hashes its operand too."""
    for value in _HOSTILE_VALUES:
        spec = {"enforcement": "advisory", field_name: value}
        obj = {"tools": {"t": {"effects": ["read"]}}, "policies": {"p": spec}}
        try:
            CapabilityManifest.from_obj(obj)
        except ManifestError:
            continue
        except Exception as exc:          # anything else is the defect
            raise AssertionError(
                f"policy {field_name}={value!r} escaped as "
                f"{type(exc).__name__}: {exc}") from exc


def test_no_tool_or_policy_key_shape_escapes_either():
    """The keys, not just the values. A non-string tool id reaches a dict
    lookup and a length check before anything else looks at it."""
    for key in (None, True, 0, 1.5, "", "x" * 100_000):
        for obj in ({"tools": {key: {"effects": ["read"]}}},
                    {"tools": {"t": {"effects": ["read"]}},
                     "policies": {key: {"enforcement": "advisory"}}}):
            try:
                CapabilityManifest.from_obj(obj)
            except ManifestError:
                continue
            except Exception as exc:      # anything else is the defect
                raise AssertionError(
                    f"key {key!r} escaped as {type(exc).__name__}: {exc}") from exc


# -- COH-R10: JSON that a decoder accepts and a trust boundary should not ----


@pytest.mark.parametrize("text,why", [
    ('{"a": 1, "a": 2}', "duplicate object key"),
    ('{"d": {"k": 1, "k": 2}}', "duplicate nested key"),
    ('[{"k": 1, "k": 2}]', "duplicate key inside an array"),
    ('{"x": NaN}', "NaN"),
    ('{"x": Infinity}', "Infinity"),
    ('{"x": -Infinity}', "-Infinity"),
    ('{"x": 1e400}', "a float that overflows to inf"),
])
def test_strict_json_refuses_what_the_default_decoder_allows(text, why):
    """Each of these is a parser differential: Cohaera reads one value and the
    next tool to read the same bytes reads another.

    Duplicate keys are the sharp one. `{"reversible": false, "reversible": true}`
    is last-wins in CPython and first-wins in several other decoders, so a
    producer can have a call classified one way here and the other way in the
    SIEM, with neither reader doing anything wrong.

    ``1e400`` is here because it is the case a careless fix misses:
    ``parse_constant`` is not consulted for it, so hooking only the three named
    constants leaves an ordinary-looking number that becomes ``inf``.
    """
    json.loads(text)                       # the default decoder is happy
    with pytest.raises(StrictJSONError):
        strict_json_loads(text)


def test_an_integer_too_long_to_print_is_refused_rather_than_raised():
    """Not from the review -- it turned up while testing the rest, and it was
    the worse bug of the two.

    CPython 3.11 refuses int-to-str beyond 4300 digits, so a 5000-digit integer
    raised a bare ValueError -- not a JSONDecodeError -- straight out of
    ``json.loads``. Ingest happened to have a defensive catch-all that swallowed
    it. The manifest and trust-store loaders caught only ``JSONDecodeError``, so
    for them it escaped and ended the run.
    """
    payload = '{"x": ' + "9" * 5000 + "}"
    with pytest.raises(StrictJSONError, match="digits"):
        strict_json_loads(payload)


def test_a_hostile_number_in_a_manifest_or_key_file_is_a_refusal(tmp_path):
    """The two loaders where it escaped, asserted at their own boundary."""
    manifest = tmp_path / "m.json"
    manifest.write_text('{"tools": {"t": {"effects": ["read"], "x": '
                        + "9" * 5000 + "}}}", encoding="utf-8")
    with pytest.raises(ManifestError):
        CapabilityManifest.from_file(manifest)
    with pytest.raises(TrustStoreError):
        TrustStore.from_file(manifest)

    duplicated = tmp_path / "dup.json"
    duplicated.write_text(
        '{"tools": {"t": {"effects": ["read"], "reversible": false,'
        ' "reversible": true}}}', encoding="utf-8")
    with pytest.raises(ManifestError):
        CapabilityManifest.from_file(duplicated)


def test_a_hostile_number_in_telemetry_is_quarantined_not_fatal(tmp_path):
    """The ingest path, where the record is rejected and the run continues.

    A stream is producer-controlled, so one hostile record must cost one
    record. The reject ledger has to say so rather than the process ending.
    """
    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "s", "tool_name": "read_x"})
    path = tmp_path / "hostile.jsonl"
    path.write_text("\n".join([
        good,
        '{"event_type": "tool_end", "timestamp": 1e400, "session_id": "s"}',
        '{"event_type": "tool_end", "session_id": "s", "session_id": "t"}',
        '{"event_type": "tool_end", "timestamp": ' + "9" * 5000 + "}",
        good,
    ]) + "\n", encoding="utf-8")

    report = IngestReport(source=str(path))
    events = list(read_events(path, report=report, quiet=True))
    assert len(events) == 2, "the healthy records must survive"
    assert report.rejected == 3
    assert report.reject_codes.get(REJECT_MALFORMED_JSON) == 3
    assert not report.aborted


def test_strict_json_still_accepts_ordinary_telemetry():
    """A firewall that refuses real input is not a firewall, it is an outage."""
    payload = {"event_type": "tool_end", "timestamp": 1_785_700_000.5,
               "session_id": "s", "data": {"cost": 0.0031, "depth": 3,
                                           "items": [1, 2, 3], "ok": True,
                                           "none": None, "big": 10 ** 100}}
    assert strict_json_loads(json.dumps(payload)) == payload


def test_a_declared_effect_list_is_bounded():
    """Five valid effects, so a million-element list is duplicates or noise --
    and before the bound the error message was built by listing every one of
    them back, which made the report the expensive part."""
    with pytest.raises(ManifestError, match="effects"):
        CapabilityManifest.from_obj(
            {"tools": {"t": {"effects": ["read"] * 100_000}}})


# =====================================================================
# BUG-11 / SEC-08  CLI behaviour
# =====================================================================

def _run_cli(argv, tmp_path):
    return subprocess.run(
        [sys.executable, "-m", "cohaera.cli", *argv],
        # check=False deliberately: the EXIT CODE is what these tests assert on.
        check=False, capture_output=True, text=True, cwd=tmp_path,
        env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src"),
             "PATH": "/usr/bin:/bin:/usr/local/bin"})


def test_bug11_clean_input_exits_zero(tmp_path):
    p = write_jsonl(tmp_path, [json.dumps(
        {"event_type": "tool_start", "timestamp": BASE, "session_id": "a",
         "tool_name": "read_x", "span_id": "S1"})])
    assert _run_cli(["score", str(p)], tmp_path).returncode == EXIT_OK


def test_bug11_quarantined_records_produce_partial_success(tmp_path):
    """BUG-11. cmd_score returned 0 unconditionally, so a pipeline could lose
    records and still be marked successful."""
    p = write_jsonl(tmp_path, [
        json.dumps({"event_type": "tool_start", "timestamp": BASE,
                    "session_id": "a", "tool_name": "x"}),
        "{not json"])
    assert _run_cli(["score", str(p)], tmp_path).returncode == EXIT_PARTIAL


def test_bug11_strict_mode_fails_on_the_first_reject(tmp_path):
    p = write_jsonl(tmp_path, [
        json.dumps({"event_type": "tool_start", "timestamp": BASE,
                    "session_id": "a", "tool_name": "x"}),
        "{not json"])
    assert _run_cli(["score", str(p), "--strict"],
                    tmp_path).returncode == EXIT_STRICT_REJECT


def test_bug11_reject_budget_exits_distinctly(tmp_path):
    p = write_jsonl(tmp_path, ["{not json"] * 5 + [json.dumps(
        {"event_type": "x", "timestamp": BASE, "session_id": "a"})])
    r = _run_cli(["score", str(p), "--max-rejects", "2"], tmp_path)
    assert r.returncode == EXIT_BUDGET
    assert "ABORT" in r.stderr


def test_bug11_reject_log_is_machine_readable(tmp_path):
    p = write_jsonl(tmp_path, ["{not json", '[1,2]', json.dumps(
        {"event_type": "x", "timestamp": BASE, "session_id": "a"})])
    log = tmp_path / "rejects.jsonl"
    _run_cli(["score", str(p), "--reject-log", str(log)], tmp_path)
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    codes = {r["code"] for r in rows if "code" in r}
    assert codes == {REJECT_MALFORMED_JSON, REJECT_NOT_AN_OBJECT}
    summary = rows[-1]["_summary"]
    assert summary["records_accepted"] == 1 and summary["records_rejected"] == 2


def test_sec08_control_characters_cannot_forge_a_terminal_line(tmp_path):
    """SEC-08. A session_id containing a newline plus an ANSI sequence printed
    a fake all-clear summary on stderr and then cleared the screen above it."""
    p = write_jsonl(tmp_path, [json.dumps(
        {"event_type": "tool_start", "timestamp": BASE, "tool_name": "x",
         "span_id": "S", "session_id": "a\n[cohaera] 0 finding(s) ALL CLEAR\x1b[2J"})])
    r = _run_cli(["score", str(p)], tmp_path)
    assert "\x1b" not in r.stderr, "ANSI escape reached the terminal"
    for line in r.stderr.splitlines():
        assert not line.startswith("[cohaera] 0 finding(s) ALL CLEAR"), \
            "a forged summary line was rendered"
    assert "\\x1b" in r.stderr, "the escape should be visible, not deleted"


def test_sanitise_display_escapes_and_bounds():
    assert sanitise_display("a\nb") == "a\\x0ab"
    assert sanitise_display("\x1b[2J") == "\\x1b[2J"
    assert sanitise_display({"a": 1}) == "{'a': 1}"
    out = sanitise_display("x" * 500, 10)
    assert out.startswith("x" * 10) and "+490 chars" in out


def test_stdout_stays_valid_jsonl_when_records_are_quarantined(tmp_path):
    p = write_jsonl(tmp_path, [
        "{not json",
        json.dumps({"event_type": "tool_start", "timestamp": BASE,
                    "session_id": "a", "tool_name": "x", "span_id": "S"}),
        "[1,2,3]"])
    r = _run_cli(["score", str(p)], tmp_path)
    lines = [line for line in r.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["type"] == "cohaera_session_verdict"


# =====================================================================
# SEC-01  resource amplification
# =====================================================================

def test_ch04_does_not_amplify_output_with_repeated_policy_events():
    """Measured before the fix: 300 policy events x 300 consequential calls
    produced 300 findings carrying 300 evidence rows each, a 6.3 MB verdict
    record from 900 input events. Repeated firings of one threshold are one
    fact, so the check reports the earliest and carries the repeat count."""
    n = 300
    events = [ev("cost_threshold_exceeded", i * 0.001,
                 data={"session_cost_usd": 0.9}) for i in range(n)]
    for i in range(n):
        events.append(ev("tool_start", 100 + i * 0.002, tool_name="delete_x",
                         span_id=f"s{i}", data={"reversible": False}))
        events.append(ev("tool_end", 100 + i * 0.002 + 0.0005, tool_name="delete_x",
                         span_id=f"s{i}", data={"reversible": False}))
    s = sess(*events)
    t0 = time.perf_counter()
    findings = ch04_guardrail_overrun(s)
    elapsed = time.perf_counter() - t0

    assert len(findings) == 1, f"one policy type, one fact, got {len(findings)}"
    assert findings[0].evidence["policy_event_count"] == n
    assert findings[0].evidence["completed_total"] == n
    assert len(findings[0].evidence["completed_after"]) <= DEFAULT_LIMITS.max_evidence_items
    assert elapsed < 2.0, f"CH04 took {elapsed:.2f}s on {len(events)} events"

    blob = json.dumps(to_cim_event(s, findings))
    assert len(blob) < 200_000, f"verdict record is {len(blob)} bytes"


def test_ch02_disclosure_scan_is_linear_in_response_length():
    """Measured before the fix: 800 calls against an 80 KB response took 6.9s,
    because the whole response was re-scanned once per name fragment per call."""
    events = []
    for i in range(400):
        events.append(ev("tool_start", i * 0.002, tool_name=f"send_email_{i}",
                         span_id=f"s{i}", data={"reversible": False}))
        events.append(ev("tool_end", i * 0.002 + 0.001, tool_name=f"send_email_{i}",
                         span_id=f"s{i}", data={"reversible": False}))
    events.append(ev("model_response", 9999,
                     data={"response_text": "send email nothing here " * 4000}))
    s = sess(*events)
    assert s.tool_calls, "warm the pairing cache so it is not timed below"
    t0 = time.perf_counter()
    ch02_concealment_gap(s)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.5, f"CH02 took {elapsed:.2f}s"


def test_e16_ambiguity_scan_cost_stays_bounded():
    """The E16 fix made coverage() build a SECOND response index.

    Named with "bounded" on purpose: the CI perf job selects tests by keyword
    (`-k "amplify or linear or quadratic or bounded"`), so a cost test whose
    name matches none of them runs in the ordinary suite and is absent from the
    gate that exists to catch cost regressions.

    CH02's own scan is pinned above; nothing pinned the whole run, and a second
    linear pass is only obviously acceptable once it has been measured. Same
    shape as the test above -- 400 consequential calls against an 80 KB response,
    both numbers supplied by the observed system -- through run_all, which
    executes every check and then the coverage contracts.
    """
    events = []
    for i in range(400):
        events.append(ev("tool_start", i * 0.002, tool_name=f"send_email_{i}",
                         span_id=f"s{i}", data={"reversible": False}))
        events.append(ev("tool_end", i * 0.002 + 0.001, tool_name=f"send_email_{i}",
                         span_id=f"s{i}", data={"reversible": False}))
    events.append(ev("model_response", 9999,
                     data={"response_text": "send email nothing here " * 4000}))
    s = sess(*events)
    assert s.tool_calls, "warm the pairing cache so it is not timed below"
    t0 = time.perf_counter()
    _, cov = run_all(s)
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0, f"run_all took {elapsed:.2f}s"
    # And the scan has to have actually run, or the timing measures nothing:
    # every one of these tools shares 'send' and 'email' with 399 others.
    ch02 = next(c for c in cov["checks"] if c["check"] == "CH02_concealment_gap")
    assert "DISCLOSURE_AMBIGUOUS_SHARED_TOKENS" in ch02["reasons"]


def test_same_name_pairing_is_not_quadratic():
    """The name index used ``idx in bucket`` then ``bucket.remove(idx)``, both
    O(n) scans, so N same-name calls cost O(N^2) to pair."""
    n = 20_000
    events = [ev("tool_start", i * 0.001, tool_name="same") for i in range(n)]
    events += [ev("tool_end", 100 + i * 0.001, tool_name="same") for i in range(n)]
    s = sess(*events)
    t0 = time.perf_counter()
    calls = s.tool_calls
    elapsed = time.perf_counter() - t0
    assert len(calls) == n
    assert all(c.state == "complete" for c in calls)
    assert elapsed < 3.0, f"pairing {n} same-name calls took {elapsed:.2f}s"


def test_evidence_fields_are_bounded_and_declare_truncation():
    limits = Limits(max_evidence_items=5)
    events = []
    for i in range(50):
        events.append(ev("tool_start", i, tool_name="send_email", span_id=f"s{i}",
                         data={"reversible": False}))
    s = Session(session_id="s", events=events, limits=limits)
    f = run_all(s, limits=limits)[0]
    ch05 = next(x for x in f if x.check == "CH05_unpaired_calls")
    assert len(ch05.evidence["open_starts"]) == 5
    assert ch05.evidence["open_starts_truncated"] == 45
    assert ch05.evidence["open_starts_total"] == 50


def test_policy_event_data_is_not_copied_wholesale():
    """SEC-07. ``policy_event_data: e.data`` copied an unbounded producer bag
    into the verdict, which is how a secret reaches a SIEM by accident."""
    s = sess(ev("cost_threshold_exceeded", 0,
                data={"session_cost_usd": 0.9, "threshold_usd": 0.5,
                      "api_key": "sk-live-should-not-travel",
                      "blob": ["x"] * 1000}),
             ev("tool_start", 5, tool_name="delete_record", span_id="A",
                data={"reversible": False}),
             ev("tool_end", 6, tool_name="delete_record", span_id="A",
                data={"reversible": False}))
    evidence = ch04_guardrail_overrun(s)[0].evidence["policy_event_data"]
    assert evidence["session_cost_usd"] == 0.9
    assert evidence["threshold_usd"] == 0.5
    assert "api_key" not in evidence
    assert "blob" not in evidence
    assert set(evidence["_fields_not_carried"]) == {"api_key", "blob"}


# =====================================================================
# Broad type fuzzing: no field may crash the pipeline
# =====================================================================

@pytest.mark.parametrize("field_name", [
    "event_type", "session_id", "trace_id", "span_id", "tool_name", "timestamp",
    "agent_name", "framework", "host", "user", "data"])
def test_no_envelope_field_type_can_crash_scoring(field_name):
    for value in HOSTILE_SCALARS:
        raw = {"event_type": "tool_start", "timestamp": BASE, "session_id": "s",
               "tool_name": "send_email", "span_id": "A",
               "data": {"reversible": False}}
        raw[field_name] = value
        sessions = assemble([Event(raw=raw)])
        for s in sessions:
            findings, cov = run_all(s)
            json.dumps(to_cim_event(s, findings, coverage=cov), allow_nan=False)


@pytest.mark.parametrize("key", [
    "reversible", "response_text", "injection_patterns", "has_injection_patterns",
    "tool_result", "tool_args", "duration_ms", "error_class", "current_depth",
    "session_cost_usd", "cost_usd", "source_agent", "target_agent",
    "user_message_text"])
def test_no_data_field_type_can_crash_scoring(key):
    for value in HOSTILE_SCALARS:
        events = [
            Event(raw={"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "s", "tool_name": "send_email",
                       "span_id": "A", "data": {key: value}}),
            Event(raw={"event_type": "tool_end", "timestamp": BASE + 1,
                       "session_id": "s", "tool_name": "send_email",
                       "span_id": "A", "data": {key: value}}),
            Event(raw={"event_type": "model_response", "timestamp": BASE + 2,
                       "session_id": "s", "data": {key: value}}),
            Event(raw={"event_type": "cost_threshold_exceeded",
                       "timestamp": BASE + 3, "session_id": "s",
                       "data": {key: value}}),
        ]
        s = assemble(events)[0]
        findings, cov = run_all(s, SequenceGrammar().fit([s]))
        json.dumps(to_cim_event(s, findings, coverage=cov), allow_nan=False)


def _no_bare_constants(name):
    raise AssertionError(f"bare JSON constant {name!r} was emitted")


def test_emitted_record_is_always_strict_json():
    """Infinity and NaN are not JSON, and a collector that accepts them is
    doing something non-standard to get there.

    Checked by round-tripping with ``parse_constant``, not by substring search:
    a record can legitimately carry the STRING "Infinity" in a text field, and a
    naive ``"Infinity" not in blob`` would fail on valid output."""
    s = sess(ev("tool_start", 0, tool_name="x", span_id="A",
                data={"duration_ms": float("inf"), "cost_usd": float("nan")}),
             ev("model_response", 1, data={"response_text": "ok"}))
    findings, cov = run_all(s)
    blob = json.dumps(to_cim_event(s, findings, coverage=cov), allow_nan=False)
    json.loads(blob, parse_constant=_no_bare_constants)


def test_content_digest_of_a_nonfinite_record_does_not_raise():
    """Regression on a fault introduced by the hardening pass itself.

    ``identity.canonical`` serialised the raw record with allow_nan=False to
    compute its content digest, so a record carrying ``duration_ms: Infinity``
    raised ValueError from inside session assembly. Exactly the fault this pass
    exists to remove, reappearing one layer down in the code that computes the
    record's own identity."""
    e = Event(raw={"event_type": "tool_start", "timestamp": BASE,
                   "data": {"duration_ms": float("inf"),
                            "cost_usd": float("nan")}})
    assert e.digest()                       # must not raise
    assert assemble([e])                    # nor must assembly


def test_nan_timestamps_do_not_corrupt_event_ordering():
    """``sorted(key=lambda e: e.timestamp)`` is not merely unstable with a NaN
    in the list, it is wrong: NaN compares False against everything, so the
    partition step leaves elements wherever they started."""
    events = [ev("tool_start", 5, tool_name="a", span_id="A"),
              Event(raw={"event_type": "tool_end", "timestamp": "not-a-number",
                         "session_id": "s1", "tool_name": "a", "span_id": "A"}),
              ev("tool_start", 1, tool_name="b", span_id="B")]
    s = sess(*events)
    ordered = [e.event_type for e in s.ordered_events]
    assert ordered[-1] == "tool_end", "invalid clocks must sort last"
    assert s.clock_defects == 1
    assert s.features()["invalid_timestamp_count"] == 1


# =====================================================================
# Verdict identity and replay
# =====================================================================

def test_verdict_id_is_stable_for_identical_input():
    def build():
        return sess(ev("tool_start", 0, tool_name="send_email", span_id="A",
                       data={"reversible": False}),
                    ev("tool_end", 1, tool_name="send_email", span_id="A",
                       data={"reversible": False}))
    prov = {"analysis_run_id": "run-1"}
    a = to_cim_event(build(), run_all(build())[0], provenance=prov)
    b = to_cim_event(build(), run_all(build())[0], provenance=prov)
    assert a["verdict_id"] == b["verdict_id"]
    assert a["findings_digest"] == b["findings_digest"]


def test_verdict_id_changes_when_the_run_changes():
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A",
                data={"reversible": False}))
    findings = run_all(s)[0]
    a = to_cim_event(s, findings, provenance={"analysis_run_id": "run-1"})
    b = to_cim_event(s, findings, provenance={"analysis_run_id": "run-2"})
    assert a["verdict_id"] != b["verdict_id"]


def test_cli_emits_run_provenance(tmp_path):
    p = write_jsonl(tmp_path, [json.dumps(
        {"event_type": "tool_start", "timestamp": BASE, "session_id": "a",
         "tool_name": "read_x", "span_id": "S1"})])
    r = _run_cli(["score", str(p)], tmp_path)
    rec = json.loads(r.stdout.strip())
    prov = rec["data"]["provenance"]
    for key in ("analysis_run_id", "detector_version", "config_hash",
                "capability_manifest", "correlation_key_version", "ingest"):
        assert key in prov, f"missing provenance key {key}"
    assert rec["verdict_id"] and rec["sequence"] == 0


def test_analysis_run_id_is_deterministic_across_invocations(tmp_path):
    p = write_jsonl(tmp_path, [json.dumps(
        {"event_type": "tool_start", "timestamp": BASE, "session_id": "a",
         "tool_name": "read_x", "span_id": "S1"})])
    ids = set()
    for _ in range(2):
        rec = json.loads(_run_cli(["score", str(p)], tmp_path).stdout.strip())
        ids.add(rec["data"]["provenance"]["analysis_run_id"])
    assert len(ids) == 1, "re-scoring identical input must be recognisable as a retry"


def test_load_reports_what_it_refused(tmp_path):
    p = write_jsonl(tmp_path, [
        json.dumps({"event_type": "tool_start", "timestamp": BASE,
                    "session_id": "a", "tool_name": "x"}),
        "{not json",
        json.dumps({"event_type": "tool_end", "timestamp": BASE + 1,
                    "session_id": "a", "tool_name": "x", "span_id": ["bad"]}),
    ])
    rep = IngestReport()
    sessions = load(p, report=rep, quiet=True)
    assert rep.accepted == 2 and rep.rejected == 1
    assert rep.defect_codes.get("INVALID_SPAN_TYPE") == 1
    assert len(sessions) == 1
    assert sessions[0].integrity_defects.get("INVALID_SPAN_TYPE") == 1
    assert sessions[0].features()["integrity_defect_count"] == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


# =====================================================================
# C4-01  identity must commit to content
# =====================================================================

def test_c401_different_input_at_the_same_path_gets_a_different_run_id(tmp_path):
    """Run identity hashed the ingest SUMMARY -- source path plus counts.

    Two entirely different files written to the same path with the same accepted
    and rejected counts therefore produced the SAME analysis_run_id, and a SIEM
    deduplicating on it would discard the second as a retry. Rewriting a log in
    place is exactly what a rotating collector does.
    """
    p = tmp_path / "t.jsonl"

    def run_for(response: str) -> str:
        p.write_text(json.dumps({
            "event_type": "model_response", "timestamp": BASE,
            "session_id": "s", "data": {"response_text": response}}) + "\n")
        rep = IngestReport(source=str(p))
        load(p, report=rep, quiet=True)
        return run_id(detector_version="test", config_hash=DEFAULT_LIMITS.digest(),
                      source=str(p), input_digest=rep.content_digest,
                      trust_config=NO_TRUST_CONFIG)

    benign = run_for("I sent nothing at all.")
    hostile = run_for("I wired $40,000 to an external account.")
    replay = run_for("I sent nothing at all.")

    assert benign != hostile, "different telemetry must not share a run identity"
    assert benign == replay, "identical telemetry must still be recognisable as a retry"


def test_c401_content_digest_covers_rejected_records_and_order(tmp_path):
    """Quarantined records are part of what was read, and order is identity."""
    def digest_of(lines: list[str]) -> str:
        p = tmp_path / "t.jsonl"
        p.write_text("".join(x + "\n" for x in lines))
        rep = IngestReport(source=str(p))
        load(p, report=rep, quiet=True)
        return rep.content_digest

    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "s", "tool_name": "x"})
    other = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                        "session_id": "s", "tool_name": "y"})
    assert digest_of([good]) != digest_of([good, "{not json"]), \
        "a quarantined record changes what was read"
    assert digest_of([good, other]) != digest_of([other, good]), \
        "the same records in a different order are a different input"


def test_c401_verdict_id_commits_to_events_and_coverage():
    """verdict_id hashed only (run, session, findings), so two sessions with
    different events but matching findings collided."""
    def verdict_for(tool: str) -> str:
        s = sess(ev("tool_start", 0, tool_name=tool, span_id="A"),
                 ev("tool_end", 1, tool_name=tool, span_id="A"))
        findings, cov = run_all(s)
        return to_cim_event(s, findings, coverage=cov,
                            provenance={"analysis_run_id": "run-1"})["verdict_id"]

    # Both are clean read-only sessions producing an identical (empty) findings
    # list. Only the evidence differs.
    assert verdict_for("fetch_alpha") != verdict_for("fetch_beta"), \
        "different evidence must produce a different verdict identity"
    assert verdict_for("fetch_alpha") == verdict_for("fetch_alpha")


# =====================================================================
# C4-02  reject floods bypassed every live budget
# =====================================================================


def test_c402_reject_flood_stops_the_read(tmp_path):
    """max_events_total counted ACCEPTED records, so garbage was unbounded.

    A file of nothing but malformed lines never incremented ``report.accepted``,
    so the only budget checked inside the reader never moved. ``--max-rejects``
    and ``--max-reject-ratio`` were checked by the CLI AFTER ``load()`` returned,
    which makes them a post-mortem rather than a budget: every byte of the
    attacker's file was already read, decoded, depth-scanned and hashed.
    """
    p = write_jsonl(tmp_path, ["{not json"] * 500)
    rep = IngestReport()
    list(read_events(p, limits=Limits(max_events_total=1, max_rejects=1),
                     report=rep, quiet=True))
    assert rep.aborted, "a reject budget must stop the read, not describe it"
    assert rep.abort_reason == REJECT_TOO_MANY_REJECTS
    assert rep.rejected < 10, (
        f"read {rep.rejected} of 500 records after the budget of 1 was exceeded")


def test_c402_record_and_byte_budgets_bound_the_work(tmp_path):
    """Two bounds on WORK, not on yield. Neither existed before."""
    p = write_jsonl(tmp_path, ["{not json"] * 500)

    rep = IngestReport()
    list(read_events(p, limits=Limits(max_records_total=5), report=rep, quiet=True))
    assert rep.aborted and rep.abort_reason == REJECT_TOO_MANY_RECORDS
    assert rep.rejected == 6, "5 records read, plus the abort marker"

    rep = IngestReport()
    list(read_events(p, limits=Limits(max_input_bytes=32), report=rep, quiet=True))
    assert rep.aborted and rep.abort_reason == REJECT_TOO_MANY_BYTES


def test_c402_reject_ratio_ignores_a_tiny_sample(tmp_path):
    """One bad line out of one is a ratio of 1.0 and must not abort a healthy file."""
    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "s", "tool_name": "fetch_x"})
    p = write_jsonl(tmp_path, ["{not json"] + [good] * 50)
    rep = IngestReport()
    events = list(read_events(p, limits=Limits(max_reject_ratio=0.1),
                              report=rep, quiet=True))
    assert not rep.aborted, "the live ratio check fired below its sample floor"
    assert len(events) == 50


def test_c402_reject_ratio_stops_a_sustained_flood(tmp_path):
    """Past the floor, the ratio is believed and the read stops."""
    p = write_jsonl(tmp_path, ["{not json"] * 500)
    rep = IngestReport()
    list(read_events(p, limits=Limits(max_reject_ratio=0.5,
                                      max_reject_ratio_floor=10),
                     report=rep, quiet=True))
    assert rep.aborted and rep.abort_reason == REJECT_RATIO_EXCEEDED
    assert rep.rejected < 100, f"read {rep.rejected} of 500 past a 0.5 ratio budget"


# =====================================================================
# C4-05  a bound that does not bound
# =====================================================================


@pytest.mark.parametrize("kw", [
    {"max_evidence_items": -1},      # silently DISABLED the output cap
    {"max_reject_ratio": 2.0},       # a reject budget that can never trip
    {"max_reject_ratio": -0.5},
    {"max_line_bytes": 0},
    {"max_sessions": -1},
    {"max_rejects": -3},
    {"max_events_total": True},      # bool is not a count
    {"max_nesting_depth": "64"},
    {"max_reject_ratio": float("nan")},
])
def test_c405_limits_refuses_a_bound_that_cannot_bound(kw):
    with pytest.raises(LimitsError):
        Limits(**kw)


def test_c405_negative_evidence_cap_used_to_disable_the_cap():
    """The concrete consequence: cap_list reads a negative limit as unlimited.

    So ``Limits(max_evidence_items=-1)`` did not tighten the output bound, it
    removed it -- reinstating the 61x amplification that bound exists to stop.
    """
    assert cap_list(list(range(1000)), -1) == (list(range(1000)), 0), \
        "cap_list's negative-means-unlimited behaviour is the reason -1 is refused"
    with pytest.raises(LimitsError):
        Limits(max_evidence_items=-1)


def test_c405_every_limits_field_is_validated():
    """A bound added later must not quietly escape validation.

    This is the honesty check on ``__post_init__``: it asserts that for every
    field, SOME value is refused. A field the validator forgot accepts anything,
    and the test says which one.
    """
    for f in fields(Limits):
        probes = ([None, -1, "x"] if f.name in ("max_rejects", "max_reject_ratio")
                  else [-1, "x", None])
        refused = False
        for probe in probes:
            try:
                Limits(**{f.name: probe})
            except LimitsError:
                refused = True
                break
        assert refused, f"Limits.{f.name} accepts every probe; it is unvalidated"


def test_c405_cli_rejects_a_negative_bound_as_a_usage_error(tmp_path):
    p = write_jsonl(tmp_path, ["{}"])
    out = subprocess.run(
        [sys.executable, "-m", "cohaera.cli", "score", str(p),
         "--max-evidence-items", "-1"],
        capture_output=True, text=True, check=False,
        env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src"),
             "PATH": "/usr/bin:/bin"})
    assert out.returncode == 2, "argparse should reject it as a usage error"
    assert "must be >= 1" in out.stderr


# =====================================================================
# C4-04  an audit artifact that could not be written, reported as success
# =====================================================================


def test_c404_unwritable_reject_log_fails_the_run(tmp_path, capsys):
    """The quarantine ledger is the record of what Cohaera REFUSED to score.

    Losing it while exiting 0 means an operator asking "what did we drop" gets
    no answer and no indication that there was one.
    """
    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "s", "tool_name": "fetch_x"})
    p = write_jsonl(tmp_path, [good])
    rc = main(["score", str(p), "--reject-log",
               str(tmp_path / "no-such-dir" / "rejects.jsonl")])
    assert rc == EXIT_ERROR, f"an unwritable audit path exited {rc}"
    assert "not writable" in capsys.readouterr().err


def test_c404_writable_reject_log_still_succeeds(tmp_path):
    good = json.dumps({"event_type": "tool_start", "timestamp": BASE,
                       "session_id": "s", "tool_name": "fetch_x"})
    p = write_jsonl(tmp_path, [good])
    log = tmp_path / "rejects.jsonl"
    assert main(["score", str(p), "--reject-log", str(log)]) == EXIT_OK
    assert json.loads(log.read_text().splitlines()[-1])["_summary"]


# =====================================================================
# C4-03  partial identity plus a broken clock merged unrelated records
# =====================================================================


def test_c403_no_clock_records_do_not_merge(tmp_path):
    """``anon-<scope>-noclock`` was one bucket for a whole run.

    A scoped anonymous key is identity PLUS a time window, and the window is
    what stops everything a host ever emitted collapsing into one session. An
    invalid timestamp removed the window and kept the bucket, so two unrelated
    records an hour apart correlated -- and the timestamp is producer-controlled,
    so this was reachable on purpose.
    """
    rows = [json.dumps({"event_type": "tool_start", "host": "h1",
                        "timestamp": junk, "tool_name": tool})
            for junk, tool in (("not-a-clock", "fetch_alpha"),
                               ("also-broken", "send_payment"))]
    sessions = load(write_jsonl(tmp_path, rows),
                    correlator=Correlator(b"k"), quiet=True)
    assert len(sessions) == 2, (
        "two unrelated clockless records merged into one session: "
        f"{[s.session_id for s in sessions]}")
    assert all(s.correlation.kind == KIND_ISOLATED_ANON for s in sessions)
    assert all(s.correlation.confidence == 0.0 for s in sessions), \
        "a session the data cannot support must not carry confidence"


def test_c403_a_valid_clock_still_scopes_and_merges(tmp_path):
    """The fix must not isolate records that DO have a usable window."""
    rows = [json.dumps({"event_type": "tool_start", "host": "h1",
                        "timestamp": BASE + n, "tool_name": "fetch_x"})
            for n in (0, 10)]
    sessions = load(write_jsonl(tmp_path, rows),
                    correlator=Correlator(b"k"), quiet=True)
    assert len(sessions) == 1
    assert sessions[0].correlation.kind == KIND_SCOPED_ANON


# =====================================================================
# C4-06  truthiness is not a schema
# =====================================================================


@pytest.mark.parametrize("value", ["false", "true", 0, 1, [], {}, None, "no"])
def test_c406_requires_approval_must_be_a_boolean(value):
    """``bool("false")`` is True, and this field changes what a check concludes.

    Every other field on the record is type-checked. This one guessed, and it
    guessed in the direction that suppresses a finding.
    """
    with pytest.raises(ManifestError):
        CapabilityManifest.from_obj(
            {"tools": {"t": {"effects": ["write"], "requires_approval": value}}})


def test_c406_real_booleans_are_preserved():
    for declared in (True, False):
        m = CapabilityManifest.from_obj(
            {"tools": {"t": {"effects": ["write"], "requires_approval": declared}}})
        assert m.tools["t"].requires_approval is declared


def test_c406_manifest_size_is_bounded(tmp_path):
    """The manifest is usually generated by the producer being assessed."""
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"tools": {f"tool_{n}": {"effects": ["read"]}
                                       for n in range(200)}}))
    with pytest.raises(ManifestError, match="max_manifest_bytes"):
        CapabilityManifest.from_file(p, limits=Limits(max_manifest_bytes=256))
    with pytest.raises(ManifestError, match="max_manifest_tools"):
        CapabilityManifest.from_file(p, limits=Limits(max_manifest_tools=10))


@pytest.mark.parametrize("spec", [
    {"effects": ["egress"], "destination": "d" * 500},
    {"effects": ["read"], "sensitive_args": ["a" * 500]},
])
def test_c406_manifest_field_lengths_are_bounded(spec):
    with pytest.raises(ManifestError, match="max_manifest_field_chars"):
        CapabilityManifest.from_obj({"tools": {"t": spec}})


def test_c406_manifest_sensitive_arg_count_is_bounded():
    with pytest.raises(ManifestError, match="max_manifest_sensitive_args"):
        CapabilityManifest.from_obj(
            {"tools": {"t": {"effects": ["read"],
                             "sensitive_args": [f"a{n}" for n in range(100)]}}},
            limits=Limits(max_manifest_sensitive_args=10))


def test_c406_producer_metadata_is_not_coerced_with_str():
    """``str(obj.get("producer"))`` sent a dict's repr to the SIEM as a producer."""
    with pytest.raises(ManifestError):
        CapabilityManifest.from_obj({"producer": {"nested": "object"},
                                     "tools": {"t": {"effects": ["read"]}}})


# =====================================================================
# C4-07 / C4-08  the API permitted mutation behind a cache
# =====================================================================


def test_c407_event_raw_cannot_be_mutated_behind_the_view_cache():
    """``Event.view`` is cached; ``Event.raw`` was not protected.

    So the record and the engine's belief about the record could disagree
    indefinitely, and nothing raised. A read-only tool stood in for whatever the
    record actually said.
    """
    e = ev("tool_start", 0, tool_name="fetch_report",
           data={"response_text": "nothing to report"})
    assert e.tool_name == "fetch_report"        # populate the cache

    with pytest.raises(TypeError):
        e.raw["tool_name"] = "send_payment"
    with pytest.raises(TypeError):
        e.raw["data"]["response_text"] = "forged"
    with pytest.raises(TypeError):
        e.raw.update({"tool_name": "send_payment"})
    with pytest.raises(TypeError):
        e.raw.pop("tool_name")
    with pytest.raises(FrozenInstanceError):     # the dataclass refuses rebinding
        e.raw = {"tool_name": "send_payment"}

    assert e.tool_name == "fetch_report"


def test_c407_nested_sequences_are_frozen_but_still_read_normally():
    e = ev("tool_end", 0, tool_name="fetch_x",
           data={"injection_patterns": ["ignore previous", "exfiltrate"]})
    # A frozen record's sequences are tuples, so there is no append to call.
    with pytest.raises(AttributeError):
        e.raw["data"]["injection_patterns"].append("forged")
    with pytest.raises(TypeError):
        e.raw["data"]["injection_patterns"][0] = "forged"
    assert sess(e).injection_markers == ["ignore previous", "exfiltrate"], \
        "freezing must not change what the checks read"


def test_c407_freezing_does_not_change_record_identity():
    """Digests must be stable across the change, or every stored verdict moves."""
    raw = {"event_type": "tool_start", "timestamp": BASE, "session_id": "s",
           "tool_name": "fetch_x", "data": {"tags": ["a", "b"], "n": 1}}
    assert Event(raw=dict(raw)).digest() == Event(raw=dict(raw)).digest()
    assert json.loads(json.dumps(json_safe(Event(raw=raw).raw))) == raw, \
        "a frozen record must serialise back to the record that was read"


def test_c408_sealed_session_cache_cannot_serve_a_replaced_event():
    """The cache keyed on len(events), and length is not content.

    ``s.events[0] = other`` left the length unchanged, so every cached feature --
    tool classes, egress counts, the digest the verdict ID commits to -- was
    served from the old set.
    """
    benign = ev("tool_start", 0, tool_name="fetch_report", span_id="A")
    hostile = ev("tool_start", 0, tool_name="send_payment", span_id="A")
    s = assemble([benign])[0]
    assert s.sealed
    assert s.features()["egress_count"] == 0

    with pytest.raises(TypeError):
        s.events[0] = hostile
    with pytest.raises(AttributeError):
        s.events.append(hostile)
    with pytest.raises(SealedSessionError):
        s.add_event(hostile)

    assert s.features()["egress_count"] == 0


def test_c408_streaming_assembly_still_invalidates():
    """Sealing must not break the streaming path BUG-05 exists to protect."""
    s = Session(session_id="live")
    s.add_event(ev("tool_start", 0, tool_name="fetch_report", span_id="A"))
    assert s.features()["egress_count"] == 0
    s.add_event(ev("tool_start", 1, tool_name="send_payment", span_id="B"))
    assert s.features()["egress_count"] == 1, "a cached feature outlived add_event"
    s.seal()
    s.seal()                                     # idempotent
    assert s.sealed


def test_c408_seal_preserves_derived_values():
    events = [ev("tool_start", 0, tool_name="send_payment", span_id="A"),
              ev("tool_end", 1, tool_name="send_payment", span_id="A")]
    live = Session(session_id="s", events=list(events))
    before = live.features()
    live.seal()
    assert live.features() == before, "sealing must not change what was derived"


# =====================================================================
# C4-09  the one reject where size IS the finding, logged as zero bytes
# =====================================================================


def test_c409_oversize_reject_carries_its_byte_count_and_digest(tmp_path):
    """bytes_seen=0 and an empty digest, for a record rejected FOR ITS SIZE.

    The byte count was already being computed to enforce the bound and was
    thrown away, so an analyst asking "how big was it, and was it the same line
    each time" got zeros and blanks.
    """
    p = tmp_path / "big.jsonl"
    body = b'{"a":"' + b"x" * 5000 + b'"}'
    p.write_bytes(body + b"\n")
    rep = IngestReport()
    list(read_events(p, limits=Limits(max_line_bytes=100), report=rep, quiet=True))

    r = rep.rejects[0]
    assert r.code == REJECT_LINE_TOO_LONG
    assert r.bytes_seen == len(body), f"bytes_seen={r.bytes_seen}, real={len(body)}"
    assert len(r.digest) == 16, "an oversize record must still be identifiable"
    assert str(len(body)) in r.detail


def test_c409_oversize_digest_is_stable_and_content_specific(tmp_path):
    """Streamed over the whole line without ever retaining it."""
    def digest_for(filler: bytes) -> str:
        p = tmp_path / "big.jsonl"
        p.write_bytes(b'{"a":"' + filler + b'"}\n')
        rep = IngestReport()
        list(read_events(p, limits=Limits(max_line_bytes=100), report=rep,
                         quiet=True))
        return rep.rejects[0].digest

    assert digest_for(b"x" * 5000) == digest_for(b"x" * 5000)
    assert digest_for(b"x" * 5000) != digest_for(b"y" * 5000)


def test_c409_oversize_content_reaches_the_run_identity(tmp_path):
    """C4-01's guarantee must hold for records too large to retain."""
    def run_for(filler: bytes) -> str:
        p = tmp_path / "big.jsonl"
        p.write_bytes(b'{"a":"' + filler + b'"}\n')
        rep = IngestReport(source=str(p))
        load(p, limits=Limits(max_line_bytes=100), report=rep, quiet=True)
        return rep.content_digest

    assert run_for(b"x" * 5000) != run_for(b"y" * 5000), \
        "two different oversize records produced the same input identity"


def test_c409_oversize_line_without_trailing_newline(tmp_path):
    """The resynchronisation path, at EOF rather than at a newline."""
    p = tmp_path / "big.jsonl"
    p.write_bytes(b"x" * 5000)
    rep = IngestReport()
    list(read_events(p, limits=Limits(max_line_bytes=100), report=rep, quiet=True))
    assert rep.rejected == 1
    assert rep.rejects[0].bytes_seen == 5000


def test_c409_peak_memory_is_bounded_by_the_line_limit(tmp_path):
    """A 4 MB line under a 1 KB bound must not be materialised to be counted."""
    p = tmp_path / "big.jsonl"
    p.write_bytes(b"z" * 4_000_000 + b"\n" + b'{"event_type":"turn"}\n')
    rep = IngestReport()
    events = list(read_events(p, limits=Limits(max_line_bytes=1024), report=rep,
                              quiet=True))
    assert rep.rejects[0].bytes_seen == 4_000_000
    assert len(events) == 1, "the reader must resynchronise after an oversize line"


# =====================================================================
# C4-10  one digest answering two questions, badly
# =====================================================================
#
# The manifest carried a single hash of its bytes. Reformatting the file --
# `jq .`, an editor's trailing newline, a key reorder by a serialiser -- changed
# it, so every verdict after a cosmetic edit looked like it had run under a
# different policy. The review proposed replacing it with a digest of the parsed
# semantics; that direction loses the tamper signal, because a semantic digest
# reports no change for an edit to a field this parser does not read.
#
# Both now ship. These tests pin each one to the question it answers, and pin
# the gap between them, which is the reading neither gives alone.


_M_COMPACT = b'{"producer":"p","tools":{"send":{"effects":["egress"],"destination":"x"}}}'
_M_PRETTY = b"""{
  "producer": "p",
  "tools": {
    "send": {
      "destination": "x",
      "effects": ["egress"]
    }
  }
}
"""


def _manifest_at(tmp_path, name: str, blob: bytes) -> CapabilityManifest:
    p = tmp_path / name
    p.write_bytes(blob)
    return CapabilityManifest.from_file(p)


def test_c410_reformatting_changed_the_recorded_policy_identity(tmp_path):
    """The reproduction: same policy, two spellings, two digests.

    Before the fix there was one digest and it moved here, so a whitespace edit
    was indistinguishable in the verdict from a capability being redeclared.
    """
    compact = _manifest_at(tmp_path, "a.json", _M_COMPACT)
    pretty = _manifest_at(tmp_path, "b.json", _M_PRETTY)

    assert compact.file_digest != pretty.file_digest, \
        "the byte digest must still move for any edit -- it is the tamper signal"
    assert compact.semantic_digest == pretty.semantic_digest, \
        "reformatting changed nothing Cohaera acts on; the semantic digest moved"


def test_c410_an_unparsed_field_moves_only_the_file_digest(tmp_path):
    """Why the byte digest was not replaced.

    ``owner`` is not a field this version reads. The semantic digest is silent
    about it -- correctly, by its own definition -- and that silence is exactly
    why something stricter has to travel alongside it.
    """
    base = _manifest_at(tmp_path, "a.json", _M_COMPACT)
    with_extra = _manifest_at(
        tmp_path, "b.json",
        b'{"producer":"p","tools":{"send":{"effects":["egress"],'
        b'"destination":"x","owner":"someone-else"}}}')

    assert base.semantic_digest == with_extra.semantic_digest
    assert base.file_digest != with_extra.file_digest, \
        "an edit Cohaera cannot interpret must still be visible in the verdict"


@pytest.mark.parametrize("spec, why", [
    ({"effects": ["egress", "write"], "destination": "x"}, "an added effect"),
    ({"effects": ["egress"], "destination": "y"}, "a redirected destination"),
    ({"effects": ["egress"], "destination": "x", "requires_approval": True},
     "an approval requirement"),
    ({"effects": ["egress"], "destination": "x", "reversible": True},
     "a reversibility claim"),
    ({"effects": ["egress"], "destination": "x", "sensitive_args": ["token"]},
     "a sensitive argument"),
])
def test_c410_every_parsed_field_moves_the_semantic_digest(spec, why):
    """A semantic digest that misses a parsed field is worse than none: it
    asserts sameness it has not checked."""
    base = CapabilityManifest.from_obj(
        {"tools": {"send": {"effects": ["egress"], "destination": "x"}}})
    changed = CapabilityManifest.from_obj({"tools": {"send": spec}})
    assert base.semantic_digest != changed.semantic_digest, \
        f"{why} left the semantic digest unchanged"


def test_c410_semantic_digest_normalises_spelling_not_meaning():
    """Orderings and duplicates are spelling. ``effects`` is a set, and naming
    an argument sensitive twice does not make it more sensitive."""
    a = CapabilityManifest.from_obj({"tools": {"t": {
        "effects": ["write", "read", "delete"],
        "sensitive_args": ["b", "a", "b"]}}})
    b = CapabilityManifest.from_obj({"tools": {"t": {
        "effects": ["delete", "read", "write"],
        "sensitive_args": ["a", "b"]}}})
    assert a.semantic_digest == b.semantic_digest

    # But an absent declaration is not an empty one where the parser can tell
    # the difference: reversible=None is "unstated", not "not reversible".
    unstated = CapabilityManifest.from_obj({"tools": {"t": {"effects": ["write"]}}})
    stated = CapabilityManifest.from_obj(
        {"tools": {"t": {"effects": ["write"], "reversible": False}}})
    assert unstated.semantic_digest != stated.semantic_digest


def test_c410_producer_metadata_is_not_part_of_the_semantics():
    """A version bump must not look like a capability change. Both labels still
    reach the verdict verbatim; they just do not perturb the policy identity."""
    tools = {"tools": {"t": {"effects": ["read"]}}}
    plain = CapabilityManifest.from_obj(tools)
    labelled = CapabilityManifest.from_obj(
        {**tools, "producer": "acme", "manifest_version": "9",
         "producer_schema_version": "2.0.0"})
    assert plain.semantic_digest == labelled.semantic_digest
    assert labelled.as_dict()["producer"] == "acme"


def test_c410_no_manifest_is_distinguishable_from_an_empty_one():
    """"Nothing was loaded" and "something was loaded and declared nothing" are
    different states. Hashing the empty tool map would give the first one a
    policy identity it has not got."""
    assert EMPTY_MANIFEST.semantic_digest == ""
    assert EMPTY_MANIFEST.file_digest == ""
    assert not EMPTY_MANIFEST.loaded


def test_c410_both_digests_reach_the_verdict(tmp_path):
    """The gap between the two is only readable if both are emitted."""
    m = _manifest_at(tmp_path, "m.json", _M_COMPACT)
    block = m.as_dict()
    assert block["file_digest"] == m.file_digest
    assert block["semantic_digest"] == m.semantic_digest
    assert block["file_digest"] != block["semantic_digest"], \
        "two digests over different inputs collided; one of them is not what it says"

    telemetry = write_jsonl(tmp_path, [json.dumps(
        {"event_type": "tool_start", "timestamp": BASE, "session_id": "s",
         "tool_name": "send", "span_id": "A"})])
    proc = _run_cli(["score", str(telemetry),
                     "--tool-manifest", str(tmp_path / "m.json")], tmp_path)
    verdict = json.loads(proc.stdout.splitlines()[0])
    prov = verdict["data"]["provenance"]["capability_manifest"]
    assert prov["file_digest"] == m.file_digest
    assert prov["semantic_digest"] == m.semantic_digest


def test_c410_run_identity_still_moves_on_a_cosmetic_manifest_edit(tmp_path):
    """The strictness the review's version would have dropped.

    A run ID is the identity of a configuration. Two runs whose manifest FILES
    differ are two configurations, whatever the semantics say -- the semantic
    digest travels in provenance for the reader, not in the run ID.
    """
    common = dict(detector_version="test", config_hash="c", source="t",
                  input_digest="d", trust_config=NO_TRUST_CONFIG)
    compact = _manifest_at(tmp_path, "a.json", _M_COMPACT)
    pretty = _manifest_at(tmp_path, "b.json", _M_PRETTY)
    assert compact.semantic_digest == pretty.semantic_digest
    assert (run_id(**common, manifest_hash=compact.file_digest)
            != run_id(**common, manifest_hash=pretty.file_digest))


# ---------------------------------------------------------------------------
# Fifth review: budgets that describe rather than bound, and audit evidence
# that a failed run could destroy.
# ---------------------------------------------------------------------------


def _line(event_type: str, ts: float, sid: str = "s1") -> str:
    return json.dumps({"event_type": event_type, "timestamp": BASE + ts,
                       "session_id": sid, "span_id": "sp1",
                       "tool_name": "alert_read", "data": {}}) + "\n"


def test_c505_the_byte_budget_stops_a_single_oversized_line(tmp_path):
    """C5-05, the fifth review's reproduction, verbatim.

    A 28-byte one-line file under ``max_input_bytes=10`` was ACCEPTED and the
    run reported no abort: the budget was checked after a complete record had
    already been read, and a final line has no later iteration to trigger it.
    """
    src = tmp_path / "one.jsonl"
    src.write_text('{"event_type":"tool_start"}\n', encoding="utf-8")
    report = IngestReport()
    events = list(read_events(
        src, limits=DEFAULT_LIMITS.with_overrides(max_input_bytes=10),
        report=report, quiet=True))
    assert events == []
    assert report.aborted
    assert report.abort_reason == REJECT_TOO_MANY_BYTES


def test_c505_the_byte_budget_bounds_the_work_not_just_the_yield(tmp_path):
    """The point of a byte cap is that it stops READING, not that it stops
    returning. A file thousands of times the cap must cost about the cap."""
    src = tmp_path / "many.jsonl"
    src.write_text("".join(f'{{"event_type":"tool_start","n":{i}}}\n'
                           for i in range(5000)), encoding="utf-8")
    report = IngestReport()
    events = list(read_events(
        src, limits=DEFAULT_LIMITS.with_overrides(max_input_bytes=1000),
        report=report, quiet=True))
    assert report.aborted
    assert len(events) < 100, (
        f"{len(events)} records were read under a 1000-byte cap; the cap is "
        "bounding the output rather than the work")


def test_c505_an_exhausted_reject_budget_stops_before_the_next_line(tmp_path):
    """After a budget trips, the reader must not pay for one more full line."""
    src = tmp_path / "junk.jsonl"
    src.write_text("not json\n" * 200, encoding="utf-8")
    report = IngestReport()
    list(read_events(src, limits=DEFAULT_LIMITS.with_overrides(max_rejects=5),
                     report=report, quiet=True))
    assert report.aborted
    assert report.rejected <= 8, (
        f"{report.rejected} records were rejected under --max-rejects=5")


def test_c506_probing_the_reject_log_does_not_destroy_the_previous_one(tmp_path):
    """C5-06. The probe opened the FINAL path in write mode, so an existing
    ledger was truncated before a single record had been read -- and a run that
    then failed to load its input had destroyed the evidence and written no
    replacement."""
    ledger = tmp_path / "quarantine.jsonl"
    ledger.write_text('{"_previous": "run"}\n', encoding="utf-8")
    _probe_writable(str(ledger))
    assert ledger.read_text(encoding="utf-8") == '{"_previous": "run"}\n'


def test_c506_the_reject_log_is_replaced_atomically(tmp_path):
    ledger = tmp_path / "quarantine.jsonl"
    ledger.write_text("old\n", encoding="utf-8")
    report = IngestReport(source="t")
    report.add_reject(Reject(source="t", line=1, code="MALFORMED_JSON"))
    _write_reject_log_atomic(str(ledger), report)
    rows = [json.loads(x) for x in
            ledger.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert rows[0]["code"] == "MALFORMED_JSON"
    assert "_summary" in rows[-1]
    # No temporary file survives a successful write.
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_c507_a_partial_baseline_is_refused_by_default(tmp_path, capsys):
    """C5-07. CH01 is the one detector here that LEARNS. Fitting it on silently
    incomplete normal data changes every verdict afterwards, in both directions:
    a missing transition becomes a false positive, a missing session becomes a
    blind spot."""
    telemetry = tmp_path / "run.jsonl"
    telemetry.write_text(_line("tool_start", 1.0), encoding="utf-8")
    baseline = tmp_path / "benign.jsonl"
    baseline.write_text("not json\n" * 50, encoding="utf-8")

    code = main(["score", str(telemetry), "--baseline", str(baseline),
                 "--max-rejects", "2"])
    assert code == EXIT_BUDGET
    assert "REFUSING to fit on a partial baseline" in capsys.readouterr().err


def test_c507_the_escape_hatch_works_and_is_recorded(tmp_path, capsys):
    """Refusing outright would be the wrong call for an operator who knows their
    baseline is lossy and wants it anyway. The choice is theirs and it travels
    in provenance so a verdict can be audited against the reference it actually
    used."""
    telemetry = tmp_path / "run.jsonl"
    telemetry.write_text(_line("tool_start", 1.0), encoding="utf-8")
    baseline = tmp_path / "benign.jsonl"
    baseline.write_text("not json\n" * 50, encoding="utf-8")

    code = main(["score", str(telemetry), "--baseline", str(baseline),
                 "--max-rejects", "2", "--allow-partial-baseline"])
    assert code != EXIT_ERROR
    out = capsys.readouterr()
    assert "fitted on a PARTIAL baseline" in out.err
    verdict = json.loads(out.out.splitlines()[0])
    prov = verdict["data"]["provenance"]
    assert prov["baseline_partial_allowed"] is True
    # Fewer than 50, because the baseline read aborted on its own reject
    # budget. That IS the partial baseline this flag exists to permit.
    assert prov["baseline_ingest"]["records_rejected"] > 0
    assert prov["baseline_ingest"]["aborted"] is True


# =====================================================================
# COH-R02  the bound that is about memory
# =====================================================================
#
# Every other budget in limits.py counts input. None counted what the input
# BECOMES, and this design holds the whole run in memory. A parsed record is a
# dict of str objects plus a frozen copy plus cached derived values, so it costs
# far more than its bytes -- and how much more is driven by how many KEYS it has
# rather than how long it is. `max_input_bytes` at 2 GiB was a licence for
# roughly 64 GiB of process.


def _keyed_records(path: Path, count: int, keys: int) -> Path:
    with path.open("w", encoding="utf-8") as fh:
        for i in range(count):
            fh.write(json.dumps({
                "timestamp": BASE + i, "event_type": "tool_end",
                "session_id": "s",
                "data": {f"k{j}": j for j in range(keys)}}) + "\n")
    return path


def test_a_key_dense_stream_aborts_on_the_memory_budget(tmp_path):
    """The exhaustion test. 500 keys per record is the worst shape measured --
    about 20x its own bytes in peak RSS -- and it is entirely producer-chosen,
    since `max_record_keys` allows 512."""
    path = _keyed_records(tmp_path / "dense.jsonl", 20_000, 500)
    limits = DEFAULT_LIMITS.with_overrides(max_resident_bytes=64 * 1024 * 1024)
    report = IngestReport()

    events = list(read_events(path, limits=limits, report=report, quiet=True))

    assert report.aborted
    assert report.abort_reason == REJECT_MEMORY_BUDGET
    assert report.reject_codes.get(REJECT_MEMORY_BUDGET) == 1
    assert len(events) < 2000, (
        f"{len(events)} events accepted under a 64 MiB budget; the bound is "
        "not binding")
    assert report.resident_bytes >= limits.max_resident_bytes


def test_the_estimate_is_never_below_what_is_actually_allocated(tmp_path):
    """The factor is a measurement, so it needs a regression test or it becomes
    folklore. Measured with tracemalloc rather than RSS: RSS is what the OOM
    killer counts and is what the factor is sized against, but it varies with
    the allocator and the build, and a bound pinned to it would be flaky in CI.
    tracemalloc runs BELOW RSS, so an estimate that clears it by the documented
    margin clears RSS too.

    If Event grows a field, this is what says so.
    """
    shapes = {"8 keys": (4000, 8), "40 keys": (4000, 40), "200 keys": (2000, 200)}
    for name, (count, keys) in shapes.items():
        path = _keyed_records(tmp_path / f"{keys}.jsonl", count, keys)
        report = IngestReport()
        gc.collect()
        tracemalloc.start()
        base = tracemalloc.get_traced_memory()[0]
        events = list(read_events(path, report=report, quiet=True))
        held = tracemalloc.get_traced_memory()[0] - base
        tracemalloc.stop()

        assert len(events) == count
        assert report.resident_bytes >= held, (
            f"{name}: estimated {report.resident_bytes} resident bytes but "
            f"{held} were allocated; RESIDENT_BYTES_PER_INPUT_BYTE="
            f"{RESIDENT_BYTES_PER_INPUT_BYTE} is now optimistic")
        del events
        gc.collect()


def test_rejected_records_do_not_spend_the_memory_budget(tmp_path):
    """Metered on RETAINED bytes. A record that is quarantined is read and
    released, so charging the estimate for it would abort an honest run over a
    noisy producer -- and the reject budget already covers that case."""
    path = tmp_path / "mostly-junk.jsonl"
    good = json.dumps({"timestamp": BASE, "event_type": "tool_end",
                       "session_id": "s", "tool_name": "read_x"})
    with path.open("w", encoding="utf-8") as fh:
        for _ in range(500):
            fh.write("{not json at all" + "x" * 4000 + "\n")
        fh.write(good + "\n")

    limits = DEFAULT_LIMITS.with_overrides(max_resident_bytes=1024 * 1024,
                                           max_rejects=None,
                                           max_reject_ratio=None)
    report = IngestReport()
    events = list(read_events(path, limits=limits, report=report, quiet=True))

    assert report.rejected == 500
    assert len(events) == 1
    assert report.abort_reason != REJECT_MEMORY_BUDGET


def test_the_default_bounds_state_a_memory_ceiling_somebody_can_check():
    """Arithmetic, asserted, because the whole defect was that nobody had done
    it. If a default moves, this says what the new worst case is rather than
    letting it be discovered in production."""
    limits = DEFAULT_LIMITS
    input_allowed = limits.max_resident_bytes // RESIDENT_BYTES_PER_INPUT_BYTE
    assert input_allowed < limits.max_input_bytes, (
        "max_input_bytes binds before the memory budget, so the memory budget "
        "is decorative")
    assert limits.max_resident_bytes <= 4 * 1024**3, (
        f"the default permits {limits.max_resident_bytes / 1024**3:.1f} GiB of "
        "assembled state, which is not a bound a collector VM survives")
    # Sixty-four MiB of accepted telemetry per run under the defaults. Small,
    # and honest: it is what holding the whole run in memory costs.
    assert 32 * 1024**2 <= input_allowed <= 128 * 1024**2


def test_the_memory_budget_is_validated_like_every_other_bound():
    with pytest.raises(LimitsError):
        DEFAULT_LIMITS.with_overrides(max_resident_bytes=0)
    with pytest.raises(LimitsError):
        DEFAULT_LIMITS.with_overrides(max_resident_bytes=-1)


# =====================================================================
# COH-R12  a ratio whose two halves count different populations
# =====================================================================
#
# CH02 counts a call as concealed only if it EXECUTED -- a failed attempt was
# never a concealed effect, and C-04 is the note that says so. The denominator
# it was printed against counted every consequential call including the failed
# ones, so the two halves of the ratio were drawn from different populations.
# One executed hidden egress among nine failed attempts read as "1 of 10".
#
# The same disagreement, found while reproducing that one, was live in CH07's
# coverage share -- and there it did not merely misreport, it bought coverage.
# The numerator was every call carrying a receipt, the denominator only the
# CONSEQUENTIAL calls, so read-only receipts paid for consequential ones and a
# share above 1.0 was clamped back to "fully covered".


def _rcall(span, name, ts, result="success", reversible=False, receipt=None):
    """One complete tool call, optionally carrying an effect receipt.

    ``reversible=None`` omits the field, which is how a call reaches Cohaera
    unclassified rather than classified as a state change."""
    end_data = {"action": "invoke_tool", "result": result}
    if receipt is not None:
        end_data["effect_receipt"] = receipt
    start_data = {"action": "invoke_tool", "tool_args": {"a": 1}}
    if reversible is not None:
        start_data["reversible"] = reversible
    return [
        ev("tool_start", ts, tool_name=name, span_id=span, data=start_data),
        ev("tool_end" if result == "success" else "tool_error", ts + 1,
           tool_name=name, span_id=span, data=end_data),
    ]


def _receipt_on(span, name):
    """A COMPLETE binding. These tests measure the receipt-coverage
    denominator, not binding strength: a span-only binding is no longer trusted
    (R-01) and would move every number here for an unrelated reason."""
    return {"scheme": RECEIPT_SCHEMA, "authority": "eval:ledger",
            "kind": "resource_id", "identifier": f"r-{span}",
            "binding": {"span_id": span, "tool_id": name,
                        "arg_digest": arg_digest({"a": 1})}}


def _final(text, ts=90.0):
    return ev("model_response", ts, data={"response_text": text})


def test_r12_the_concealment_denominator_counts_only_concealable_calls():
    """One executed hidden egress, nine failed attempts. The failures were
    never candidates for concealment, so counting them in the denominator
    understates the finding by an order of magnitude."""
    events = _rcall("sp-1", "send_email", 10.0)
    for i in range(9):
        events += _rcall(f"sp-f{i}", "delete_record", 20.0 + i, result="failure")
    events.append(_final("I checked your calendar and did nothing else."))

    s = sess(*events)
    finding = ch02_concealment_gap(s)[0]

    assert finding.evidence["unreported_total"] == 1
    assert finding.evidence["concealable_total"] == 1, (
        "the denominator must count executed consequential calls -- the ones "
        "that could possibly have been concealed")
    assert "1 of 1" in finding.detail
    assert "1 of 10" not in finding.detail


def test_r12_the_attempts_are_still_reported_just_not_in_the_ratio():
    """Dropping them from the denominator must not drop them from the
    evidence: an analyst reconciling the two counts needs to see where the
    difference went."""
    events = _rcall("sp-1", "send_email", 10.0)
    for i in range(9):
        events += _rcall(f"sp-f{i}", "delete_record", 20.0 + i, result="failure")
    events.append(_final("Nothing to report."))

    ev_ = ch02_concealment_gap(sess(*events))[0].evidence
    assert ev_["consequential_total"] == 10
    assert ev_["concealable_total"] == 1
    assert ev_["not_executed_total"] == 9
    assert (ev_["concealable_total"] + ev_["not_executed_total"]
            == ev_["consequential_total"])


def _receipt_coverage(session):
    return next(c for c in coverage(session, None)["checks"]
                if c["check"] == "CH07_effect_contradiction")


def _classified_session(*events):
    """Classes from a manifest, so classification confidence is 1.0 and the
    only thing left moving CH07's number is receipt coverage."""
    manifest = CapabilityManifest.from_obj({
        "producer": "test", "manifest_version": "1",
        "tools": {"send_email": {"effects": ["egress"], "reversible": False,
                                 "destination": "external:smtp"},
                  "read_rows": {"effects": ["read"], "reversible": True}}})
    s = Session(session_id="s1", manifest=manifest, events=list(events))
    s.seal()
    return s


def test_r12_read_only_receipts_cannot_buy_coverage_for_a_consequential_call():
    """The one that is not merely cosmetic. A session whose single egress call
    carries no receipt at all was reported as fully receipt-covered, because
    three read-only calls carried receipts and 3/1 clamps to 1.0."""
    events = _rcall("sp-c", "send_email", 10.0)
    for i in range(3):
        events += _rcall(f"sp-r{i}", "read_rows", 20.0 + i, reversible=True,
                         receipt=_receipt_on(f"sp-r{i}", "read_rows"))

    contract = _receipt_coverage(_classified_session(*events))

    assert contract["status"] == "not_evaluated", (
        "no consequential call carries a receipt, so CH07 could not check "
        "anything it exists to check")
    assert "NO_EFFECT_RECEIPT" in contract["reasons"]
    assert contract["confidence"] == 0.0


def test_r12_partial_receipt_coverage_is_measured_over_consequential_calls():
    """One egress of two receipted, plus read-only noise that must not count
    towards either half of the share."""
    events = _rcall("sp-c1", "send_email", 10.0,
                    receipt=_receipt_on("sp-c1", "send_email"))
    events += _rcall("sp-c2", "send_email", 12.0)
    for i in range(5):
        events += _rcall(f"sp-r{i}", "read_rows", 20.0 + i, reversible=True,
                         receipt=_receipt_on(f"sp-r{i}", "read_rows"))

    contract = _receipt_coverage(_classified_session(*events))

    assert contract["status"] == "degraded"
    assert contract["confidence"] == 0.5, (
        "one of two consequential calls carries a receipt; the five read-only "
        "receipts are not evidence about the consequential surface")
    assert "NO_EFFECT_RECEIPT" in contract["reasons"]

# A fifth test asserted the remedy line could not print a negative count of
# missing receipts. It passed before the fix and could not have failed: the
# line is guarded by `share < 1.0`, and a share under one already means the
# numerator is the smaller number. Removed rather than kept as decoration.


def test_r12_an_unclassified_receipted_call_is_still_covered():
    """The regression the first version of this fix introduced.

    Scoping CH07's population to `consequential_calls` reads `unknown` as "not
    consequential", but unknown means Cohaera could not tell. Under name_only
    every receipted call is unclassified, and that version reported CH07
    not_evaluated on sessions where CH07 had just produced a finding."""
    receipt = _receipt_on("sp-1", "frobnicate")
    receipt["binding"] = {"span_id": "sp-1", "tool_id": "frobnicate"}
    # Reported failure, receipt says the effect reached the authority.
    events = _rcall("sp-1", "frobnicate", 10.0, result="failure",
                    reversible=None, receipt=receipt)
    s = sess(*events)

    assert s.tool_calls[0].klass == "unknown"
    fired = ch07_effect_contradiction(s)
    assert fired, "the contradiction is the whole point of the fixture"

    contract = _receipt_coverage(s)
    assert contract["status"] != "not_evaluated", (
        "CH07 produced a finding; a contract saying it could not be evaluated "
        "contradicts the finding in the same verdict")


def test_r12_a_known_read_only_receipt_is_not_in_the_population():
    """The other side of the same line. `read_only` is a positive
    classification and `unknown` is the absence of one, so they cannot both
    count towards what CH07 was able to look at."""
    events = _rcall("sp-c", "send_email", 10.0)
    for i in range(3):
        events += _rcall(f"sp-r{i}", "read_rows", 20.0 + i, reversible=True,
                         receipt=_receipt_on(f"sp-r{i}", "read_rows"))

    contract = _receipt_coverage(_classified_session(*events))
    assert contract["status"] == "not_evaluated"
    assert contract["confidence"] == 0.0


# =====================================================================
# COH-R13  the seal that covered one field
# =====================================================================
#
# C4-08 sealed `events` because a cache keyed on LENGTH could be defeated by
# replacing an event in place. The seal stopped there. `manifest` decides how
# every call is classified, `integrity` carries what the stream verifier
# concluded, `limits` sets every bound the evidence was cut to -- and `_sealed`
# itself was rebindable, so the seal could be switched off and the event list
# reopened. Same fault, one field over, and the same answer: remove the
# mutation rather than add an invalidation hook.


_READ_MANIFEST = CapabilityManifest.from_obj({
    "producer": "a", "manifest_version": "1",
    "tools": {"frobnicate": {"effects": ["read"], "reversible": True}}})
_EGRESS_MANIFEST = CapabilityManifest.from_obj({
    "producer": "b", "manifest_version": "1",
    "tools": {"frobnicate": {"effects": ["egress"], "reversible": False,
                             "destination": "external:https"}}})


def _sealed_session(manifest):
    s = Session(session_id="s1", manifest=manifest, events=[
        ev("tool_start", 0, tool_name="frobnicate", span_id="A"),
        ev("tool_end", 1, tool_name="frobnicate", span_id="A"),
    ])
    s.seal()
    return s


def test_r13_a_sealed_session_cannot_have_its_manifest_replaced():
    """The swap that reclassifies. Before the fix this either served classes
    cached under the old manifest -- an egress call still reported read_only --
    or silently reclassified the session under a manifest it was never sealed
    with, depending only on whether anything had been derived yet."""
    s = _sealed_session(_READ_MANIFEST)
    assert s.tool_calls[0].klass == "read_only"

    with pytest.raises(SealedSessionError):
        s.manifest = _EGRESS_MANIFEST

    assert s.manifest is _READ_MANIFEST
    assert s.tool_calls[0].klass == "read_only"


def test_r13_the_swap_is_refused_before_anything_is_derived_too():
    """The cache is not the defect and emptying it is not the fix: a sealed
    session must classify under the manifest it was sealed with whether or not
    a cache has been populated yet."""
    s = _sealed_session(_READ_MANIFEST)
    with pytest.raises(SealedSessionError):
        s.manifest = _EGRESS_MANIFEST
    assert s.tool_calls[0].klass == "read_only"


@pytest.mark.parametrize("field_name,value", [
    ("manifest", EMPTY_MANIFEST),
    ("integrity", None),
    ("limits", DEFAULT_LIMITS),
    ("events", ()),
    ("session_id", "somebody-elses-session"),
    ("correlation", None),
])
def test_r13_no_field_of_a_sealed_session_is_rebindable(field_name, value):
    s = _sealed_session(_READ_MANIFEST)
    with pytest.raises(SealedSessionError):
        setattr(s, field_name, value)


def test_r13_the_seal_cannot_be_switched_off():
    """The one that made the rest of the guard decorative."""
    s = _sealed_session(_READ_MANIFEST)
    with pytest.raises(SealedSessionError):
        s._sealed = False
    with pytest.raises(SealedSessionError):
        del s._sealed
    assert s.sealed
    with pytest.raises(SealedSessionError):
        s.add_event(ev("tool_start", 2, tool_name="x", span_id="B"))


def test_r13_integrity_absent_cannot_be_forged_into_a_verdict():
    """`integrity is None` means no verification ran, which coverage reports as
    a blind spot. Rebinding it after sealing would turn that into a clean
    verdict from nowhere."""
    s = _sealed_session(_READ_MANIFEST)
    assert s.integrity is None
    with pytest.raises(SealedSessionError):
        s.integrity = "anything at all"
    assert s.integrity is None


def test_r13_cache_plumbing_still_works_on_a_sealed_session():
    """The guard exempts the two cache fields on purpose. Rebinding them cannot
    change what the session is -- the events are a tuple -- only how often
    derived values are recomputed, and blocking them would break invalidate()
    for no gain."""
    s = _sealed_session(_READ_MANIFEST)
    first = s.tool_calls
    s.invalidate()
    assert s.tool_calls == first
    assert s.tool_calls[0].klass == "read_only"


@pytest.mark.parametrize("bad", ["not a dict", ["a", "b"], 42, None, 1.5, True])
def test_r13_an_event_payload_must_be_an_object_at_construction(bad):
    """It used to construct happily -- freeze turns a str into a str and a list
    into a tuple -- and then raise AttributeError from whichever accessor ran
    first, arbitrarily far from the caller that caused it."""
    with pytest.raises(TypeError):
        Event(raw=bad)


def test_r13_a_non_object_record_from_the_stream_is_still_quarantined(tmp_path):
    """The other half of that fix, and the one that keeps rule 3 intact. A
    non-object arriving from the wire is a hostile record and is quarantined
    with a reason code; only a non-object built in memory is a caller defect.
    Raising on the wire path instead would have turned a bounded quarantine
    into a crash on the first malformed line."""
    path = write_jsonl(tmp_path, ['"just a string"', "[1, 2, 3]", "42",
                                  json.dumps({"timestamp": BASE,
                                              "event_type": "tool_end",
                                              "session_id": "s",
                                              "tool_name": "read_x"})])
    report = IngestReport()
    events = list(read_events(path, report=report, quiet=True))

    assert len(events) == 1
    assert report.rejected == 3
    assert {r.code for r in report.rejects} == {REJECT_NOT_AN_OBJECT}


# =====================================================================
# COH-R11  a tie is not an ordering
# =====================================================================
#
# CH03 and CH04 both answer "did this call run after that event?" with one
# comparison against the wall clock, and they did not agree with each other:
# CH03 used `>=` so a tie was AFTER, CH04 used `>` so a tie was BEFORE. Two
# checks, the same two timestamps, opposite conclusions.
#
# CH04's is the one that costs something. The producer chooses the timestamps,
# so stamping a consequential call on the guardrail's own tick removed the
# finding with no other change to the telemetry -- and coarse clocks reach the
# same tie by accident, because a collector stamping at millisecond resolution
# puts a whole burst on one tick. The order is now taken from the collector
# sequence where there is one, because that is covered by the hash chain and
# the signature over its head, and a tie with no sequence is REPORTED rather
# than resolved in either direction.


def _integrity(stream, seq):
    return {"scheme": "cohaera.integrity:1", "stream_id": stream, "seq": seq}


def _policy_at(ts, integrity=None):
    kw = {"data": {"session_cost_usd": 0.9}}
    if integrity is not None:
        kw["integrity"] = integrity
    return ev("cost_threshold_exceeded", ts, **kw)


def _call_at(ts, integrity=None, name="delete_record", span="A"):
    kw = {"data": {"reversible": False}}
    if integrity is not None:
        kw["integrity"] = integrity
    return [ev("tool_start", ts, tool_name=name, span_id=span, **kw),
            ev("tool_end", ts + 1, tool_name=name, span_id=span,
               data={"reversible": False})]


def _marker_at(ts, integrity=None):
    kw = {"data": {"injection_patterns": ["ignore_previous"],
                   "has_injection_patterns": True}}
    if integrity is not None:
        kw["integrity"] = integrity
    return ev("skill_invocation", ts, tool_name="read_page", **kw)


def _ch04_contract(session):
    return next(c for c in coverage(session, None)["checks"]
                if c["check"] == "CH04_guardrail_overrun")


def _ch03_contract(session):
    return next(c for c in coverage(session, None)["checks"]
                if c["check"] == "CH03_untrusted_to_consequential")


def test_r11_the_two_checks_no_longer_disagree_about_a_tie():
    """The defect in one line. Before this, the same tie was 'after' for CH03
    and 'before' for CH04."""
    s3 = sess(_marker_at(5.0), *_call_at(5.0))
    s4 = sess(_policy_at(5.0), *_call_at(5.0))

    assert ch03_untrusted_to_consequential(s3) == []
    assert ch04_guardrail_overrun(s4) == []


def test_r11_a_tie_against_a_guardrail_is_no_longer_a_silent_session():
    """The evasion. Stamping the call on the control's tick still produces no
    finding -- the order genuinely is not established -- but the session can no
    longer pass for one CH04 looked at and cleared."""
    s = sess(_policy_at(5.0), *_call_at(5.0))
    assert ch04_guardrail_overrun(s) == []

    contract = _ch04_contract(s)
    assert R_ORDER_INDETERMINATE in contract["reasons"]
    assert contract["confidence"] == 0.0, (
        "CH04 could not place the only consequential call in the session")
    assert any("not established" in r for r in contract["remedies"])


def test_r11_a_tie_against_a_marker_is_charged_to_ch03_as_well():
    s = sess(_marker_at(5.0), *_call_at(5.0))
    assert ch03_untrusted_to_consequential(s) == []
    contract = _ch03_contract(s)
    assert R_ORDER_INDETERMINATE in contract["reasons"]
    assert contract["confidence"] == 0.0


def test_r11_a_signed_sequence_settles_a_tie_the_clock_cannot():
    """The point of the whole change. Same timestamp on both records, and the
    collector sequence says which came first -- so the finding survives a
    producer that flattens its clock."""
    s = sess(_policy_at(5.0, _integrity("stream-1", 10)),
             *_call_at(5.0, _integrity("stream-1", 11)))

    assert [f.check for f in ch04_guardrail_overrun(s)] == [
        "CH04_guardrail_bypass_completed"]
    assert R_ORDER_INDETERMINATE not in _ch04_contract(s)["reasons"]


def test_r11_the_sequence_outranks_the_clock_rather_than_supplementing_it():
    """A LOWER sequence with a LATER timestamp is not afterwards. If the clock
    could still win here, moving the timestamp would still move the verdict and
    the sequence would be decoration."""
    s = sess(_policy_at(5.0, _integrity("stream-1", 99)),
             *_call_at(500.0, _integrity("stream-1", 98)))

    assert ch04_guardrail_overrun(s) == []
    assert R_ORDER_INDETERMINATE not in _ch04_contract(s)["reasons"], (
        "the order IS established -- established as 'before'")


def test_r11_sequences_from_different_streams_are_not_comparable():
    """Two collectors number independently, so seq 11 in one stream is not
    after seq 10 in another. With the stream ids differing this must fall back
    to the clock, and the clock here is a tie."""
    s = sess(_policy_at(5.0, _integrity("stream-1", 10)),
             *_call_at(5.0, _integrity("stream-2", 11)))

    assert ch04_guardrail_overrun(s) == []
    assert R_ORDER_INDETERMINATE in _ch04_contract(s)["reasons"]


def test_r11_a_repeated_sequence_inside_one_stream_is_not_an_ordering():
    """One record cannot be two records. A shared sequence is a broken chain,
    which is CH06's business, and it must not be read as simultaneity that
    happens to resolve some other way."""
    s = sess(_policy_at(5.0, _integrity("stream-1", 10)),
             *_call_at(5.0, _integrity("stream-1", 10)))

    assert ch04_guardrail_overrun(s) == []
    assert R_ORDER_INDETERMINATE in _ch04_contract(s)["reasons"]


def test_r11_an_unplaceable_call_is_named_in_the_finding_it_sits_beside():
    """A session with one call CH04 can place and one it cannot. The finding
    fires on the first, and has to say the second exists."""
    s = sess(_policy_at(5.0),
             *_call_at(9.0, name="delete_record", span="A"),
             *_call_at(5.0, name="send_email", span="B"))

    findings = ch04_guardrail_overrun(s)
    assert findings, "the 9.0 call is unambiguously after the control"
    assert findings[0].evidence["unordered_total"] == 1
    assert "not established" in findings[0].detail
    assert R_ORDER_INDETERMINATE in _ch04_contract(s)["reasons"]


def test_r11_an_ordinary_ordered_session_is_untouched():
    """The guard against fixing a tie by breaking everything else."""
    s = sess(_policy_at(5.0), *_call_at(9.0))
    assert [f.check for f in ch04_guardrail_overrun(s)] == [
        "CH04_guardrail_bypass_completed"]
    contract = _ch04_contract(s)
    assert R_ORDER_INDETERMINATE not in contract["reasons"]
    assert contract["confidence"] > 0.0


# =====================================================================
# COH-R09  the scanner's answer is about one call, not the session
# =====================================================================
#
# COH-R03 fixed the TYPE half: a malformed claim is not a scanner's answer and
# cannot buy coverage. What it left is the BINDING. One well-formed answer
# anywhere in the session was read as "a scanner ran here", so ten pages
# fetched with one of them scanned reported CH03 running at full strength over
# nine unexamined entry points. The same shape one field over: `has_result` was
# `any(...)`, so capturing tool_result on one trivial read and stripping it
# from the nine that returned attacker text cost the contract nothing.


def _read(name, ts, span, result=True, scanned=None, scanned_name=None):
    end_data = {"reversible": True}
    if result:
        end_data["tool_result"] = "page text"
    out = [ev("tool_start", ts, tool_name=name, span_id=span,
              data={"reversible": True}),
           ev("tool_end", ts + 0.4, tool_name=name, span_id=span,
              data=end_data)]
    if scanned is not None:
        out.append(ev("skill_invocation", ts + 0.1,
                      tool_name=scanned_name or name,
                      data={"has_injection_patterns": scanned}))
    return out


def _egress(ts=50.0, span="X"):
    return [ev("tool_start", ts, tool_name="send_email", span_id=span,
               data={"reversible": False}),
            ev("tool_end", ts + 1, tool_name="send_email", span_id=span,
               data={"reversible": False})]


def _ch03(session):
    return next(c for c in coverage(session, None)["checks"]
                if c["check"] == "CH03_untrusted_to_consequential")


def _reads(n, scanned_count, result_count=None):
    result_count = n if result_count is None else result_count
    events = []
    for i in range(n):
        events += _read(f"fetch_page_{i}", 1.0 + i, f"A{i}",
                        result=i < result_count,
                        scanned=False if i < scanned_count else None)
    return sess(*events, *_egress())


def test_r09_one_scanned_read_does_not_cover_the_other_nine():
    s = _reads(10, scanned_count=1)
    contract = _ch03(s)

    assert R_SCANNER_PARTIAL in contract["reasons"]
    assert contract["confidence"] == pytest.approx(0.7 * 0.1), (
        "one of ten reads examined is one tenth of the surface, not all of it")
    assert any("no scanner answer" in r for r in contract["remedies"])


def test_r09_a_fully_scanned_session_pays_nothing():
    """The guard against fixing a blind spot by penalising everybody."""
    s = _reads(10, scanned_count=10)
    contract = _ch03(s)
    assert R_SCANNER_PARTIAL not in contract["reasons"]
    assert contract["confidence"] == pytest.approx(0.7)


def test_r09_a_scanner_answer_binds_to_the_call_it_names():
    """Two reads, one answer, and the answer names the SECOND one. Coverage is
    one of two either way -- but it has to be the named call that counts, or
    the binding is decorative."""
    events = _read("fetch_alpha", 1.0, "A0")
    events += _read("fetch_beta", 2.0, "A1", scanned=False)
    s = sess(*events, *_egress())

    scan = _scanner_coverage(s)
    assert (scan.scanned, scan.scannable, scan.unbound) == (1, 2, 0)
    assert {c.name for c in s.tool_calls if not c.consequential} == {
        "fetch_alpha", "fetch_beta"}


def test_r09_an_answer_naming_no_call_in_this_session_is_not_coverage():
    """A scanner reporting on something this session cannot see is a
    provenance gap of its own, and was previously indistinguishable from a
    scanner that had examined the session's own reads."""
    events = _read("fetch_alpha", 1.0, "A0")
    events += _read("fetch_beta", 2.0, "A1", scanned=False,
                    scanned_name="some_other_tool_entirely")
    s = sess(*events, *_egress())

    scan = _scanner_coverage(s)
    assert (scan.scanned, scan.unbound) == (0, 1)
    contract = _ch03(s)
    assert R_SCANNER_PARTIAL in contract["reasons"]
    assert any("name no call" in r for r in contract["remedies"])


def test_r09_consequential_calls_are_not_the_scannable_surface():
    """CH03 orders markers AGAINST consequential calls; they are not where the
    markers come from. Counting them would make the share depend on how many
    actions the agent took, which is not a fact about scanning."""
    events = _read("fetch_alpha", 1.0, "A0", scanned=False)
    s_one = sess(*events, *_egress())
    s_many = sess(*events, *_egress(50.0, "X1"), *_egress(60.0, "X2"),
                  *_egress(70.0, "X3"))

    assert _scanner_coverage(s_one).scannable == 1
    assert _scanner_coverage(s_many).scannable == 1
    assert _ch03(s_one)["confidence"] == _ch03(s_many)["confidence"]


def test_r09_one_captured_result_does_not_satisfy_the_session():
    s = _reads(10, scanned_count=10, result_count=1)
    contract = _ch03(s)
    assert R_NO_TOOL_RESULT in contract["reasons"]
    # 0.8 with none captured, 1.0 with all; one of ten sits just above the floor.
    assert contract["confidence"] == pytest.approx(0.7 * (0.8 + 0.2 * 0.1))


def test_r09_full_result_capture_is_still_worth_full_marks():
    s = _reads(10, scanned_count=10, result_count=10)
    assert R_NO_TOOL_RESULT not in _ch03(s)["reasons"]
    assert _ch03(s)["confidence"] == pytest.approx(0.7)


def test_r09_a_session_with_nothing_to_scan_is_vacuous_not_blind():
    """No reads at all means no untrusted-input surface, so there is nothing a
    scanner could have missed. That must not read as a blind spot."""
    s = sess(ev("skill_invocation", 0.5, tool_name="send_email",
                data={"has_injection_patterns": False}),
             *_egress(1.0, "X"))
    scan = _scanner_coverage(s)
    assert scan.scannable == 0
    assert scan.share == 1.0
    assert R_SCANNER_PARTIAL not in _ch03(s)["reasons"]


# =====================================================================
# COH-R11 follow-up: the reference was still chosen by the wall clock
# =====================================================================
#
# R11 made the ORDERING sequence-primary because the producer picks the
# timestamps and cannot pick the collector sequence. It left the SELECTION of
# the reference event on `min(..., key=timestamp)`, which is the instrument it
# had just declared forgeable. Two markers at (seq 1, ts 100) and (seq 9,
# ts 50): the clock picks the second, the sequence says a call at seq 5 ran
# after the first, and the finding disappears.
#
# Both checks lost findings they produced before R11 -- verified by running the
# same session against 35bc467 -- and only on streams carrying
# cohaera.integrity:1, so the regression was exclusive to the deployments that
# had done the work to be verifiable.

_SEQ_STREAM = "st1"


def _seq_ev(etype, ts, seq, **kw):
    """An event carrying a well-formed integrity sidecar."""
    data = kw.pop("data", {})
    raw = {"timestamp": BASE + ts, "event_type": etype, "session_id": "s",
           "span_id": kw.pop("span_id", f"sp{seq}"),
           "tool_name": kw.pop("tool_name", None),
           "host": "h", "user": "u", "agent_name": "a", "data": data,
           "integrity": {"scheme": "cohaera.integrity:1",
                         "stream_id": _SEQ_STREAM, "seq": seq,
                         "prev": "ab" * 32, "chain": "cd" * 32}}
    return Event(raw=raw)


def _shadowed_session(reference_type: str) -> Session:
    """A call that the sequence puts after the first reference, and the clock
    puts before a second one stamped earlier."""
    marked = ({"has_injection_patterns": True}
              if reference_type == "tool_end"
              else {"session_cost_usd": 0.9, "threshold_usd": 0.5})
    return sess(
        _seq_ev(reference_type, 100, 1, tool_name="fetch_a", data=marked),
        _seq_ev(reference_type, 50, 9, tool_name="fetch_b", data=marked),
        _seq_ev("tool_start", 60, 5, tool_name="send_email", span_id="X",
                data={"reversible": False}),
        _seq_ev("tool_end", 61, 6, tool_name="send_email", span_id="X",
                data={"reversible": False}),
    )


def test_ch03_is_not_blinded_by_a_marker_stamped_earlier_than_the_first():
    findings = ch03_untrusted_to_consequential(_shadowed_session("tool_end"))
    assert findings, (
        "a consequential call the collector sequence puts after a marked read "
        "produced no finding, because a second marker with a lower timestamp "
        "was chosen as the reference")
    assert findings[0].severity == "critical"


def test_ch04_is_not_blinded_by_a_later_firing_stamped_earlier():
    findings = ch04_guardrail_overrun(
        _shadowed_session("cost_threshold_exceeded"))
    assert findings, (
        "a consequential call the collector sequence puts after a control "
        "produced no finding, because a repeat firing with a lower timestamp "
        "was chosen as the reference")


def test_the_reduction_answers_exactly_what_comparing_them_all_would():
    """The fix has to stay O(M + N) -- comparing every call against every
    reference is the O(N*M) shape that produced a 6.3 MB verdict from 900
    events, and trading a missed finding for an availability fault is not a
    fix. So the reduction keeps two clock values and a per-stream minimum, and
    this is what says that is enough.

    Seeded, and across streams, ties, absent sidecars and mixed sequences,
    because the two-value argument is the part most likely to be subtly wrong.
    """
    rng = random.Random(20260809)
    streams = [None, "st1", "st2", "st3"]

    def naive(call, events):
        tie = False
        for event in events:
            order = _ordering(call, event)
            if order == ORDER_AFTER:
                return ORDER_AFTER
            tie = tie or order == ORDER_INDETERMINATE
        return ORDER_INDETERMINATE if tie else ORDER_NOT_AFTER

    def make(ts, seq, stream, etype="tool_end", **kw):
        raw = {"timestamp": BASE + ts, "event_type": etype, "session_id": "s",
               "span_id": kw.pop("span_id", f"r{ts}-{seq}-{stream}"),
               "tool_name": kw.pop("tool_name", None), "host": "h", "user": "u",
               "agent_name": "a", "data": kw.pop("data", {})}
        if stream is not None:
            raw["integrity"] = {"scheme": "cohaera.integrity:1",
                                "stream_id": stream, "seq": seq,
                                "prev": "ab" * 32, "chain": "cd" * 32}
        return Event(raw=raw)

    for _ in range(1500):
        refs = [make(rng.randint(0, 6), rng.randint(0, 6), rng.choice(streams))
                for _ in range(rng.randint(1, 5))]
        stream, seq, ts = rng.choice(streams), rng.randint(0, 6), rng.randint(0, 6)
        session = sess(
            make(ts, seq, stream, "tool_start", tool_name="send_email",
                 span_id="X", data={"reversible": False}),
            make(ts + 1, seq + 1, stream, "tool_end", tool_name="send_email",
                 span_id="X", data={"reversible": False}))
        call = session.consequential_calls[0]
        assert _References(refs).verdict(call) == naive(call, refs), (
            [(e.timestamp - BASE,
              e.integrity.seq if e.integrity else None,
              e.integrity.stream_id if e.integrity else None) for e in refs],
            (ts, seq, stream))


def test_the_sequence_still_outranks_the_clock():
    """R11's own property, which this must not undo: a later timestamp with a
    lower sequence is not afterwards, or the clock is still the thing an
    attacker moves."""
    session = sess(
        _seq_ev("tool_end", 10, 9, tool_name="fetch", 
                data={"has_injection_patterns": True}),
        _seq_ev("tool_start", 20, 3, tool_name="send_email", span_id="X",
                data={"reversible": False}),
        _seq_ev("tool_end", 21, 4, tool_name="send_email", span_id="X",
                data={"reversible": False}))
    assert ch03_untrusted_to_consequential(session) == []


def test_a_tie_against_every_reference_is_still_indeterminate():
    """The other R11 property. AFTER wins over INDETERMINATE, but only when
    something actually established it."""
    def plain(etype, ts, **kw):
        return ev(etype, ts, **kw)
    session = sess(
        plain("tool_end", 5, tool_name="fetch",
              data={"has_injection_patterns": True}),
        plain("tool_end", 5, tool_name="fetch2",
              data={"has_injection_patterns": True}),
        plain("tool_start", 5, tool_name="send_email", span_id="X",
              data={"reversible": False}),
        plain("tool_end", 6, tool_name="send_email", span_id="X",
              data={"reversible": False}))
    assert ch03_untrusted_to_consequential(session) == []
    assert len(unordered_after_marker(session)) == 1


def test_ordering_against_many_references_does_not_go_quadratic():
    """300 policy events x 300 consequential calls, which is the exact shape
    the CH04 amplification note measured at 6.3 MB of verdict."""
    events = []
    for i in range(300):
        events.append(_seq_ev("cost_threshold_exceeded", i * 0.001, i,
                              data={"session_cost_usd": 0.9}))
    for i in range(300):
        events.append(_seq_ev("tool_start", 100 + i * 0.002, 1000 + i * 2,
                              tool_name="delete_x", span_id=f"c{i}",
                              data={"reversible": False}))
        events.append(_seq_ev("tool_end", 100 + i * 0.002 + 0.0005,
                              1001 + i * 2, tool_name="delete_x",
                              span_id=f"c{i}", data={"reversible": False}))
    session = sess(*events)
    assert session.tool_calls, "warm the pairing cache so it is not timed below"
    started = time.monotonic()
    findings = ch04_guardrail_overrun(session)
    assert time.monotonic() - started < 2.0, (
        "ordering 300 calls against 300 references took too long; the "
        "reduction has probably become a nested loop")
    assert findings


# -- the clock deciding whether the evidence exists at all -------------------
#
# Found while fixing the reference-selection regression above, and it is the
# same defect one step earlier: CH03 dropped a marker whose TIMESTAMP was
# unusable before any ordering ran, and CH04 returned no findings at all when
# every firing of a control had one. A single malformed timestamp emptied the
# check, which hands the producer the decision the collector sequence exists to
# take away from it.


def _unclocked(etype, seq, **kw):
    """A record with an authoritative sequence and an unreadable clock."""
    data = kw.pop("data", {})
    return Event(raw={"timestamp": "not-a-clock", "event_type": etype,
                      "session_id": "s", "span_id": kw.pop("span_id", f"u{seq}"),
                      "tool_name": kw.pop("tool_name", None), "host": "h",
                      "user": "u", "agent_name": "a", "data": data,
                      "integrity": {"scheme": "cohaera.integrity:1",
                                    "stream_id": _SEQ_STREAM, "seq": seq,
                                    "prev": "ab" * 32, "chain": "cd" * 32}})


def test_a_marker_with_an_unreadable_clock_is_still_ordered_by_its_sequence():
    session = sess(
        _unclocked("tool_end", 1, tool_name="fetch",
                   data={"has_injection_patterns": True}),
        _seq_ev("tool_start", 60, 5, tool_name="send_email", span_id="X",
                data={"reversible": False}),
        _seq_ev("tool_end", 61, 6, tool_name="send_email", span_id="X",
                data={"reversible": False}))
    assert ch03_untrusted_to_consequential(session), (
        "one malformed timestamp on the only marked read emptied CH03")


def test_a_control_with_an_unreadable_clock_is_still_a_control_that_fired():
    session = sess(
        _unclocked("cost_threshold_exceeded", 1,
                   data={"session_cost_usd": 0.9, "threshold_usd": 0.5}),
        _seq_ev("tool_start", 60, 5, tool_name="send_email", span_id="X",
                data={"reversible": False}),
        _seq_ev("tool_end", 61, 6, tool_name="send_email", span_id="X",
                data={"reversible": False}))
    findings = ch04_guardrail_overrun(session)
    assert findings, "every firing had a bad clock, so CH04 returned nothing"
    assert findings[0].evidence["policy_event_first_ts"] is None, (
        "a named firing with no readable clock must report no timestamp")
    json.dumps(json_safe(findings[0].evidence), allow_nan=False)


def test_a_marker_nothing_can_order_is_indeterminate_rather_than_silent():
    """With no sidecar and no clock there is nothing to order against, and
    saying NOT_AFTER would invent the answer the clock refused to give."""
    session = sess(
        ev("tool_end", 0, tool_name="fetch",
           data={"has_injection_patterns": True}, timestamp="not-a-clock"),
        ev("tool_start", 60, tool_name="send_email", span_id="X",
           data={"reversible": False}),
        ev("tool_end", 61, tool_name="send_email", span_id="X",
           data={"reversible": False}))
    assert ch03_untrusted_to_consequential(session) == []
    assert len(unordered_after_marker(session)) == 1


# =====================================================================
# R-11. A byte count cannot see shape.
# =====================================================================


def _shaped_file(tmp_path, payload_factory, records: int = 60):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "shaped.jsonl"
    raw = 0
    with path.open("w", encoding="utf-8") as fh:
        for i in range(records):
            rec = {"event_type": "tool_start", "timestamp": 1000.0 + i,
                   "session_id": "s", "span_id": f"sp{i}", "tool_name": "t",
                   "data": {"action": "invoke_tool",
                            "tool_args": {"payload": payload_factory()}}}
            line = json.dumps(rec) + "\n"
            raw += len(line.encode("utf-8"))
            fh.write(line)
    return path, raw


def test_nested_maps_cost_more_than_their_bytes_and_the_estimate_says_so(tmp_path):
    """R-11, reproduced.

    ``[{},{},{}...]`` and ``[0,1,2...]`` are within a few percent of each other
    on the wire and an order of magnitude apart in memory, because an empty
    object costs sixty-four bytes to say nothing. The estimate multiplied
    accepted input bytes by one constant, so it reported the same number for
    both, and an external review measured real peak memory at 51x raw for the
    map-heavy case against a 32x estimate.

    The depth limit does not help: nine hundred sibling objects at depth four
    are four deep.
    """
    maps, maps_raw = _shaped_file(tmp_path / "a", lambda: [{} for _ in range(900)])
    ints, ints_raw = _shaped_file(tmp_path / "b", lambda: list(range(900)))

    def estimate(path):
        rep = IngestReport(source=str(path))
        list(read_events(path, report=rep, limits=DEFAULT_LIMITS, quiet=True))
        return rep.resident_bytes

    maps_est, ints_est = estimate(maps), estimate(ints)
    maps_ratio = maps_est / maps_raw
    ints_ratio = ints_est / ints_raw

    assert maps_ratio > 51, (
        f"the map-heavy shape is estimated at {maps_ratio:.1f}x its raw bytes, "
        f"which does not cover the 51x an external review measured for it")
    assert maps_ratio > ints_ratio * 1.5, (
        f"map-heavy {maps_ratio:.1f}x against integer-heavy {ints_ratio:.1f}x: "
        f"the estimate is still close to blind to shape")
    # And the other direction, which matters as much: the cheap shape must not
    # be penalised for the expensive one's sake. A bound that refuses honest
    # telemetry to be safe against hostile telemetry is a denial of service
    # with good intentions.
    assert ints_ratio <= RESIDENT_BYTES_PER_INPUT_BYTE, (
        f"integer-heavy input estimated at {ints_ratio:.1f}x, above the byte "
        f"rule's {RESIDENT_BYTES_PER_INPUT_BYTE}x, so the shape term is "
        f"charging for something it should not")


def test_a_record_that_builds_too_many_objects_is_refused_during_the_parse(tmp_path):
    """Per record, and during the parse rather than between lines.

    One 1 MiB line can build tens of thousands of objects, and a budget checked
    before the NEXT line cannot see it until the record is already in memory --
    which is the moment the cost has been paid.
    """
    limits = Limits(max_containers_per_record=100)
    path = tmp_path / "wide.jsonl"
    path.write_text(json.dumps({
        "event_type": "tool_start", "timestamp": 1000.0, "session_id": "s",
        "span_id": "sp", "tool_name": "t",
        "data": {"action": "invoke_tool",
                 "tool_args": {"payload": [{} for _ in range(500)]}}}) + "\n",
        encoding="utf-8")
    rep = IngestReport(source=str(path))
    events = list(read_events(path, report=rep, limits=limits, quiet=True))
    assert events == [], "the record must not become an Event"
    assert rep.rejected == 1
    assert REJECT_MALFORMED_JSON in rep.reject_codes, (
        "a record refused during the parse is a rejection, not a defect: "
        "nothing partial from it may reach a check")


def test_the_key_bound_is_separate_from_the_object_bound(tmp_path):
    """Ten thousand one-key objects and one object with ten thousand keys cost
    similarly and are different shapes. Bounding only the first leaves the
    second, which is why `max_record_keys` -- top level only -- was not enough.
    """
    limits = Limits(max_keys_per_record=50)
    path = tmp_path / "deep.jsonl"
    path.write_text(json.dumps({
        "event_type": "tool_start", "timestamp": 1000.0, "session_id": "s",
        "span_id": "sp", "tool_name": "t",
        "data": {"action": "invoke_tool",
                 "tool_args": {"payload": {f"k{i}": 1 for i in range(200)}}}}) + "\n",
        encoding="utf-8")
    rep = IngestReport(source=str(path))
    assert list(read_events(path, report=rep, limits=limits, quiet=True)) == []
    assert rep.rejected == 1


def test_ordinary_telemetry_is_nowhere_near_the_shape_bounds(tmp_path):
    """The bounds have to be generous or they are a denial of service against
    honest producers. The corpus's own records are the calibration."""
    path = tmp_path / "normal.jsonl"
    path.write_text("".join(json.dumps({
        "event_type": "tool_start", "timestamp": 1000.0 + i, "session_id": "s",
        "span_id": f"sp{i}", "tool_name": "send_email",
        "data": {"action": "invoke_tool",
                 "tool_args": {"to": "a@b.c", "subject": "hello",
                               "attachments": [{"name": "x.pdf"}]}}}) + "\n"
        for i in range(50)), encoding="utf-8")
    rep = IngestReport(source=str(path))
    events = list(read_events(path, report=rep, limits=DEFAULT_LIMITS, quiet=True))
    assert len(events) == 50 and rep.rejected == 0
