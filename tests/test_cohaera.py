"""Unit tests for Cohaera.

Run:  PYTHONPATH=src python3 -m pytest tests/ -v
Or:   PYTHONPATH=src python3 tests/test_cohaera.py     (no pytest needed)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.checks import (
    SequenceGrammar,
    ch01_sequence_order,
    ch02_concealment_gap,
    ch03_untrusted_to_consequential,
    ch04_guardrail_overrun,
    ch05_unpaired_calls,
    coverage,
    run_all,
)
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


def test_assemble_scopes_anonymous_events_and_never_merges_them_globally():
    """C-04 regression. Anonymous events must not be joined across producers.

    The old behaviour dropped every event with no session_id or trace_id into a
    single '<no-session-id>' bucket, which let an injection marker on one host
    correlate with an egress action on another host under a different user.
    That is a finding the data does not support.
    """
    a = Event(raw={"event_type": "tool_end", "timestamp": BASE,
                   "host": "host-A", "user": "alice", "tool_name": "fetch"})
    b = Event(raw={"event_type": "tool_start", "timestamp": BASE + 5,
                   "host": "host-B", "user": "bob", "tool_name": "send_email"})
    out = assemble([a, b])
    assert len(out) == 2, "unrelated producers must not share a session"
    assert all(s.session_id.startswith("anon-") for s in out)
    # BUG-07 regression. The key used to embed repr() of host, user, agent and
    # framework, and that key is emitted as session_id straight into a SIEM. A
    # field explicitly labelled anonymous must not carry the identity it stands
    # in for.
    joined = " ".join(s.session_id for s in out)
    for leaked in ("host-A", "host-B", "alice", "bob"):
        assert leaked not in joined, f"anonymous key leaks {leaked}"

    # Same producer inside the window still groups, which is the useful half.
    c = Event(raw={"event_type": "tool_start", "timestamp": BASE,
                   "host": "host-A", "user": "alice", "tool_name": "fetch"})
    d = Event(raw={"event_type": "tool_end", "timestamp": BASE + 1,
                   "host": "host-A", "user": "alice", "tool_name": "fetch"})
    assert len(assemble([c, d])) == 1


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
    """BUG-10. An unclassifiable tool must cost the checks that read the class.

    It used to raise a standalone 'classification' gap that no check depended
    on, so ``checks_evaluated`` and ``completeness`` were unaffected and a
    session Cohaera did not understand still scored up to 1.0.
    """
    s = sess(ev("tool_start", 0, tool_name="frobnicate", span_id="A"),
             ev("tool_end", 1, tool_name="frobnicate", span_id="A"),
             ev("model_response", 2, response_text="done"))
    cov = coverage(s, None)
    assert cov["unknown_class_calls"] == 1
    assert cov["classification_confidence"] == 0.0

    # The checks that read the class are degraded, by name, with a reason code.
    degraded = {c["check"]: c for c in cov["checks"] if c["status"] == "degraded"}
    for check in ("CH02_concealment_gap", "CH05_unpaired_calls"):
        assert check in degraded, f"{check} should be degraded by unknown class"
        assert "TOOL_CLASS_UNKNOWN" in degraded[check]["reasons"]

    # And the aggregate must not read as confident.
    assert cov["completeness"] < 0.5, cov["completeness"]


def test_coverage_completeness_is_a_fraction():
    s = sess(ev("session_start", 0))
    c = coverage(s, None)
    assert 0.0 <= c["completeness"] <= 1.0
    assert c["checks_evaluated"] <= c["checks_total"]
    assert c["schema"] == "cohaera.coverage:2"


def test_coverage_never_reports_full_confidence_without_a_manifest():
    """A name heuristic is a guess about an attacker-supplied string.

    Nothing that rests entirely on it should contribute a whole point, so a
    perfectly-formed session with a producer session_id, valid clocks, a final
    response and confidently-named tools still lands short of 1.0.
    """
    s = sess(ev("tool_start", 0, tool_name="send_email", span_id="A", reversible=False),
             ev("tool_end", 1, tool_name="send_email", span_id="A", reversible=False),
             ev("model_response", 2, response_text="I sent the email.",
                has_injection_patterns=False))
    cov = coverage(s, SequenceGrammar().fit([_benign(i) for i in range(3)]))
    assert cov["completeness"] < 1.0
    assert cov["classification_confidence"] < 1.0
    assert any("NO_CAPABILITY_MANIFEST" in c["reasons"] for c in cov["checks"])


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
        except Exception as exc:
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
            failed.append(name)
    print(f"\n{len(fns) - len(failed)}/{len(fns)} passed")
    sys.exit(1 if failed else 0)


# ------------------------------------------- CH01 out-of-distribution baseline

def _session_of(names, sid="ood"):
    events = []
    for i, name in enumerate(names):
        events += [ev("tool_start", i * 2, sid, tool_name=name, span_id=f"{sid}{i}"),
                   ev("tool_end", i * 2 + 1, sid, tool_name=name, span_id=f"{sid}{i}")]
    return sess(*events, sid=sid)


def _grammar_over(*sequences):
    return SequenceGrammar().fit(
        [_session_of(seq, sid=f"b{i}") for i, seq in enumerate(sequences)])


def test_ch01_declines_when_the_baseline_never_saw_this_workload():
    """The measured defect: a bigram model outside its distribution flags everything.

    Fitted on one set of task families and pointed at another, CH01 scored every
    transition as unseen and fired on 100% of benign sessions (256/256) at
    precision 33.3% -- exactly the attack base rate, so an alarm carrying no
    information whatsoever.
    """
    grammar = _grammar_over(["search_tickets", "fetch_ticket", "draft_reply"])
    other_workload = _session_of(["scan_registry", "tag_artifact", "promote_build"])
    assert ch01_sequence_order(other_workload, grammar) == []


def test_ch01_says_so_in_coverage_rather_than_going_quiet():
    """Silence would be worse than the false alarm. The blind spot has to be visible."""
    grammar = _grammar_over(["search_tickets", "fetch_ticket", "draft_reply"])
    other_workload = _session_of(["scan_registry", "tag_artifact", "promote_build"])
    ch01 = next(c for c in coverage(other_workload, grammar)["checks"]
                if c["check"] == "CH01_sequence_order")
    assert ch01["status"] == "not_evaluated"
    assert ch01["reasons"] == ["BASELINE_VOCABULARY_MISMATCH"]
    assert ch01["confidence"] == 0.0


def test_ch01_still_fires_on_a_novel_action_inside_a_known_workload():
    """The fix must not disarm the check for the case it exists to catch.

    Known vocabulary, one novel consequential call. Overlap stays high, so the
    grammar is in distribution and the ordering deviation is a real finding.
    """
    grammar = _grammar_over(["search_tickets", "fetch_ticket", "draft_reply"],
                            ["search_tickets", "fetch_ticket", "draft_reply"])
    attack = _session_of(["search_tickets", "fetch_ticket", "exfiltrate_all"])
    findings = ch01_sequence_order(attack, grammar)
    assert len(findings) == 1
    assert "exfiltrate_all" in findings[0].evidence["novel_tools"]


def test_ch01_does_not_suppress_on_too_few_calls_to_judge():
    """One unknown tool is not evidence that two vocabularies differ.

    It is equally consistent with a familiar agent taking a single novel action,
    which is the case CH01 was written for. Suppressing at n=1 would turn the
    check off exactly where it works.
    """
    grammar = _grammar_over(["search_tickets", "fetch_ticket", "draft_reply"])
    single = _session_of(["exfiltrate_all"])
    assert len(single.tool_sequence) < 3
    assert ch01_sequence_order(single, grammar), (
        "a one-call session is too short to conclude the workload differs")


def test_vocabulary_overlap_carries_no_label_information():
    """Why gating on overlap is not cheating.

    Overlap measures whether the MODEL applies, not whether the session is
    malicious. Benign and attack sessions drawn from the same workload score the
    same, which is what makes it a legitimate gate rather than a peek at labels.
    """
    grammar = _grammar_over(["search_tickets", "fetch_ticket", "draft_reply"])
    benign = _session_of(["search_tickets", "fetch_ticket", "draft_reply"])
    attack = _session_of(["search_tickets", "fetch_ticket", "exfiltrate_all"])
    assert grammar.vocabulary_overlap(benign) == 1.0
    assert grammar.vocabulary_overlap(attack) > 0.5
    foreign_benign = _session_of(["scan_registry", "tag_artifact", "promote_build"])
    foreign_attack = _session_of(["scan_registry", "tag_artifact", "exfiltrate_all"])
    assert grammar.vocabulary_overlap(foreign_benign) == 0.0
    assert grammar.vocabulary_overlap(foreign_attack) == 0.0
