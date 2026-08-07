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

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.capabilities import CapabilityManifest, ManifestError
from cohaera.checks import (
    SequenceGrammar,
    ch02_concealment_gap,
    ch03_untrusted_to_consequential,
    ch04_guardrail_overrun,
    coverage,
    run_all,
)
from cohaera.cli import EXIT_BUDGET, EXIT_OK, EXIT_PARTIAL, EXIT_STRICT_REJECT
from cohaera.identity import Correlator, run_id
from cohaera.ingest import assemble, load, read_events
from cohaera.limits import (
    DEFAULT_LIMITS,
    REJECT_LINE_TOO_LONG,
    REJECT_MALFORMED_JSON,
    REJECT_NESTING_TOO_DEEP,
    REJECT_NOT_AN_OBJECT,
    REJECT_UNDECODABLE,
    Limits,
)
from cohaera.model import Event, Session, to_cim_event
from cohaera.validate import IngestReport, sanitise_display

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
                      source=str(p), input_digest=rep.content_digest)

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
