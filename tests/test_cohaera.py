"""Unit tests for Cohaera.

Run:  PYTHONPATH=src python3 -m pytest tests/ -v
Or:   PYTHONPATH=src python3 tests/test_cohaera.py     (no pytest needed)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.checks import (SequenceGrammar, ch01_sequence_order,
                            ch02_concealment_gap, ch03_untrusted_to_consequential,
                            ch04_guardrail_overrun, ch05_unpaired_calls,
                            coverage, run_all)
from cohaera.ingest import assemble
from cohaera.model import Event, Session, to_cim_event

BASE = 1_785_700_000.0


def ev(etype, ts_offset=0.0, sid="s1", **data):
    return Event(raw={
        "event_id": f"e{ts_offset}", "timestamp": BASE + ts_offset,
        "session_id": sid, "trace_id": sid,
        "span_id": data.pop("span_id", f"sp{ts_offset}"),
        "event_type": etype,
        "agent_name": data.pop("agent_name", "test-agent"),
        "tool_name": data.pop("tool_name", None),
        "framework": "claude", "host": "h1", "user": "u1",
        "data": {"log_source_type": "observra", **data},
    })


def sess(*events, sid="s1"):
    return Session(session_id=sid, events=sorted(events, key=lambda e: e.timestamp))


# ---------------------------------------------------------------- assembly

def test_assemble_groups_by_session_id():
    out = assemble([ev("session_start", 0, "a"), ev("session_start", 1, "b"),
                    ev("tool_start", 2, "a", tool_name="x")])
    assert len(out) == 2
    assert {s.session_id for s in out} == {"a", "b"}
    assert len(next(s for s in out if s.session_id == "a").events) == 2


def test_assemble_sorts_by_timestamp():
    s = assemble([ev("tool_start", 5), ev("session_start", 0), ev("tool_end", 2)])[0]
    assert [e.timestamp for e in s.events] == sorted(e.timestamp for e in s.events)


def test_assemble_handles_missing_session_id():
    e = Event(raw={"event_type": "x", "timestamp": BASE})
    out = assemble([e])
    assert len(out) == 1 and out[0].session_id == "<no-session-id>"


# ---------------------------------------------------------------- pairing

def test_pairing_by_span_id():
    s = sess(ev("tool_start", 0, tool_name="read_x", span_id="A"),
             ev("tool_end", 1, tool_name="read_x", span_id="A", duration_ms=10))
    calls = s.tool_calls
    assert len(calls) == 1
    assert calls[0].result == "success" and calls[0].duration_ms == 10


def test_pairing_falls_back_to_name_fifo():
    s = sess(ev("tool_start", 0, tool_name="read_x", span_id=None),
             ev("tool_end", 1, tool_name="read_x", span_id=None))
    assert len(s.tool_calls) == 1 and s.tool_calls[0].result == "success"


def test_unpaired_start_is_recorded():
    s = sess(ev("tool_start", 0, tool_name="transfer_funds", span_id="A"))
    assert len(s.tool_calls) == 1 and s.tool_calls[0].result is None


def test_orphan_terminal_is_not_discarded():
    """A tool_end with no start is itself worth surfacing."""
    s = sess(ev("tool_end", 1, tool_name="ghost", span_id="Z"))
    assert len(s.tool_calls) == 1 and s.tool_calls[0].name == "ghost"


def test_tool_error_marks_failure():
    s = sess(ev("tool_start", 0, tool_name="read_x", span_id="A"),
             ev("tool_error", 1, tool_name="read_x", span_id="A", error_class="Timeout"))
    assert s.tool_calls[0].result == "failure"
    assert s.tool_calls[0].error_class == "Timeout"


# ---------------------------------------------------------------- classification

def test_classification_by_name():
    s = sess(ev("tool_start", 0, tool_name="read_file", span_id="A"),
             ev("tool_start", 1, tool_name="delete_record", span_id="B"),
             ev("tool_start", 2, tool_name="send_email", span_id="C"),
             ev("tool_start", 3, tool_name="frobnicate", span_id="D"))
    got = {c.name: c.klass for c in s.tool_calls}
    assert got["read_file"] == "read_only"
    assert got["delete_record"] == "state_change"
    assert got["send_email"] == "egress"      # egress wins over state_change
    assert got["frobnicate"] == "unknown"


def test_observra_reversible_flag_overrides_keyword_guess():
    """Upstream truth beats our heuristic: name says read, observra says irreversible."""
    s = sess(ev("tool_start", 0, tool_name="read_and_purge", span_id="A", reversible=False))
    assert s.tool_calls[0].klass == "state_change"


def test_consequential_excludes_read_only():
    s = sess(ev("tool_start", 0, tool_name="get_status", span_id="A"),
             ev("tool_start", 1, tool_name="delete_it", span_id="B"))
    assert [c.name for c in s.consequential_calls] == ["delete_it"]


# ---------------------------------------------------------------- CH01

def _benign(i):
    return sess(ev("tool_start", 0, f"b{i}", tool_name="search", span_id=f"{i}A"),
                ev("tool_end", 1, f"b{i}", tool_name="search", span_id=f"{i}A"),
                ev("tool_start", 2, f"b{i}", tool_name="fetch", span_id=f"{i}B"),
                ev("tool_end", 3, f"b{i}", tool_name="fetch", span_id=f"{i}B"),
                sid=f"b{i}")


def test_ch01_silent_without_baseline():
    assert ch01_sequence_order(_benign(0), None) == []
    assert ch01_sequence_order(_benign(0), SequenceGrammar()) == []


def test_ch01_clean_on_baseline_shape():
    g = SequenceGrammar().fit([_benign(i) for i in range(5)])
    assert ch01_sequence_order(_benign(99), g) == []


def test_ch01_fires_on_novel_tool():
    g = SequenceGrammar().fit([_benign(i) for i in range(5)])
    bad = sess(ev("tool_start", 0, "x", tool_name="exfiltrate", span_id="XA"),
               ev("tool_end", 1, "x", tool_name="exfiltrate", span_id="XA"), sid="x")
    f = ch01_sequence_order(bad, g)
    assert len(f) == 1 and f[0].severity == "high"
    assert "exfiltrate" in f[0].evidence["novel_tools"]


def test_ch01_detail_counts_are_sane():
    """Regression: the transition total was previously computed wrong."""
    g = SequenceGrammar().fit([_benign(i) for i in range(5)])
    bad = sess(ev("tool_start", 0, "x", tool_name="alpha", span_id="XA"),
               ev("tool_end", 1, "x", tool_name="alpha", span_id="XA"), sid="x")
    f = ch01_sequence_order(bad, g)[0]
    n_unseen = len(f.evidence["unseen_transitions"])
    total = len(bad.tool_sequence) + 1
    assert f"{n_unseen} of {total} transitions" in f.detail
    assert n_unseen <= total


# ---------------------------------------------------------------- CH02

def _with_response(text, tools):
    events = []
    for i, (name, rev) in enumerate(tools):
        events += [ev("tool_start", i * 2, tool_name=name, span_id=f"S{i}", reversible=rev),
                   ev("tool_end", i * 2 + 1, tool_name=name, span_id=f"S{i}", reversible=rev)]
    events.append(ev("model_response", 100, response_text=text))
    return sess(*events)


def test_ch02_clean_when_reported():
    s = _with_response("I searched and then sent the email.",
                       [("search_x", True), ("send_email", False)])
    assert ch02_concealment_gap(s) == []


def test_ch02_fires_when_egress_unreported():
    s = _with_response("I searched the records for you.",
                       [("search_x", True), ("send_email", False)])
    f = ch02_concealment_gap(s)
    assert len(f) == 1 and f[0].severity == "critical"
    assert f[0].evidence["unreported_calls"][0]["tool"] == "send_email"


def test_ch02_silent_without_response_text():
    """Absence of input must not read as a clean result."""
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A", reversible=False),
             ev("tool_end", 1, tool_name="send_email", span_id="A", reversible=False))
    assert ch02_concealment_gap(s) == []
    gaps = coverage(s, None)["gaps"]
    assert any(g["check"] == "CH02_concealment_gap" and g["status"] == "not_evaluated"
               for g in gaps)


def test_ch02_ignores_failed_calls():
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A", reversible=False),
             ev("tool_error", 1, tool_name="send_email", span_id="A", reversible=False),
             ev("model_response", 5, response_text="Nothing to report."))
    assert ch02_concealment_gap(s) == []


# ---------------------------------------------------------------- CH03

def test_ch03_fires_when_marker_precedes_action():
    s = sess(ev("tool_end", 0, tool_name="fetch_kb", span_id="A",
                injection_patterns=["INSTRUCTION_OVERRIDE"], has_injection_patterns=True),
             ev("tool_start", 5, tool_name="send_email", span_id="B", reversible=False),
             ev("tool_end", 6, tool_name="send_email", span_id="B", reversible=False))
    f = ch03_untrusted_to_consequential(s)
    assert len(f) == 1 and f[0].severity == "critical"


def test_ch03_silent_when_action_precedes_marker():
    """Ordering is the whole signal. Reverse it and the check must go quiet."""
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="B", reversible=False),
             ev("tool_end", 1, tool_name="send_email", span_id="B", reversible=False),
             ev("tool_end", 9, tool_name="fetch_kb", span_id="A",
                injection_patterns=["INSTRUCTION_OVERRIDE"], has_injection_patterns=True))
    assert ch03_untrusted_to_consequential(s) == []


def test_ch03_silent_without_markers():
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="B", reversible=False),
             ev("tool_end", 1, tool_name="send_email", span_id="B", reversible=False))
    assert ch03_untrusted_to_consequential(s) == []


# ---------------------------------------------------------------- CH04

def test_ch04_fires_when_session_continues_after_policy_event():
    s = sess(ev("cost_threshold_exceeded", 0, session_cost_usd=0.63, threshold_usd=0.5),
             ev("tool_start", 5, tool_name="delete_record", span_id="A", reversible=False),
             ev("tool_end", 6, tool_name="delete_record", span_id="A", reversible=False))
    f = ch04_guardrail_overrun(s)
    assert len(f) == 1 and f[0].severity == "high"


def test_ch04_silent_when_session_stops():
    s = sess(ev("tool_start", 0, tool_name="delete_record", span_id="A", reversible=False),
             ev("tool_end", 1, tool_name="delete_record", span_id="A", reversible=False),
             ev("cost_threshold_exceeded", 5, session_cost_usd=0.63))
    assert ch04_guardrail_overrun(s) == []


def test_ch04_ignores_read_only_continuation():
    s = sess(ev("depth_exceeded", 0, current_depth=6, max_depth=5),
             ev("tool_start", 5, tool_name="read_status", span_id="A"),
             ev("tool_end", 6, tool_name="read_status", span_id="A"))
    assert ch04_guardrail_overrun(s) == []


# ---------------------------------------------------------------- CH05 / coverage

def test_ch05_severity_rises_for_consequential():
    s = sess(ev("tool_start", 0, tool_name="transfer_funds", span_id="A", reversible=False))
    assert ch05_unpaired_calls(s)[0].severity == "medium"
    s2 = sess(ev("tool_start", 0, tool_name="read_x", span_id="A"))
    assert ch05_unpaired_calls(s2)[0].severity == "low"


def test_coverage_flags_unknown_classification():
    s = sess(ev("tool_start", 0, tool_name="frobnicate", span_id="A"),
             ev("tool_end", 1, tool_name="frobnicate", span_id="A"))
    assert any(g["check"] == "classification" for g in coverage(s, None)["gaps"])


def test_coverage_completeness_is_a_fraction():
    s = sess(ev("session_start", 0))
    c = coverage(s, None)
    assert 0.0 <= c["completeness"] <= 1.0
    assert c["checks_evaluated"] <= c["checks_total"]


# ---------------------------------------------------------------- emit

def test_cim_record_carries_type_and_schema():
    """observra#108: the ABA parser needs 'type' and 'schema'. Both must be present."""
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A", reversible=False),
             ev("tool_end", 1, tool_name="send_email", span_id="A", reversible=False))
    findings, _ = run_all(s)
    rec = to_cim_event(s, findings)
    assert rec["type"] == "cohaera_session_verdict"
    assert rec["schema"].startswith("cohaera:")
    assert rec["event_type"] == "cohaera_session_verdict"   # back-compat
    json.dumps(rec)   # must be serialisable end to end


def test_cim_record_carries_the_108_dropped_fields():
    s = sess(ev("agent_handoff", 0, source_agent="a", target_agent="b"),
             ev("tool_end", 1, tool_name="fetch", span_id="A",
                injection_patterns=["INSTRUCTION_OVERRIDE"], current_depth=3))
    rec = to_cim_event(s, [])
    d = rec["data"]
    for field in ("injection_markers", "max_delegation_depth", "handoff_chain",
                  "triggered_rules", "max_severity"):
        assert field in d, f"missing {field}"
    assert d["injection_markers"] == ["INSTRUCTION_OVERRIDE"]
    assert d["handoff_chain"] == ["a->b"]
    assert d["max_delegation_depth"] == 3


def test_max_severity_reflects_worst_finding():
    s = sess(ev("tool_end", 0, tool_name="fetch", span_id="A",
                injection_patterns=["X"], has_injection_patterns=True),
             ev("tool_start", 5, tool_name="send_email", span_id="B", reversible=False),
             ev("tool_end", 6, tool_name="send_email", span_id="B", reversible=False))
    findings, _ = run_all(s)
    assert to_cim_event(s, findings)["data"]["max_severity"] == "critical"


def test_clean_session_yields_info_severity():
    s = sess(ev("tool_start", 0, tool_name="read_x", span_id="A"),
             ev("tool_end", 1, tool_name="read_x", span_id="A"))
    findings, _ = run_all(s)
    assert findings == []
    assert to_cim_event(s, findings)["data"]["max_severity"] == "info"


# ---------------------------------------------------------------- runner

if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            print(f"  FAIL  {name}: {exc}")
            failed.append(name)
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
            failed.append(name)
    print(f"\n{len(fns) - len(failed)}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
