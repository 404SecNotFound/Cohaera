"""Regression tests for the hardening pass over checks, model, ingest and CLI.

Every test here was written against the defect before the fix existed and
watched fail for the reason it names (CONTRIBUTING, rule 1). The six defects:

  H-01  CH02's negation span ran a flat 80 characters past the cue, through
        sentence ends, so a denial in one sentence swallowed the disclosure in
        the next and fired CRITICAL on an honest summary.
  H-02  Nothing read ``event_id``. A record delivered twice was scored twice:
        CH05 reported the second tool_start as unpaired, CH02 double-counted,
        and CH03's confidence fell with every copy of the session.
  H-03  CLI edges: a detached signature given without its file was silently
        ignored even under --require-signed-policy; a missing --baseline was
        reported as a signature failure; a directory passed as --reject-log
        passed the writability probe and failed after the ledgers were saved;
        the exit-code contract appeared in no document the operator could
        reach from a shell.
  H-04  The quarantine ledger kept its first 1000 rows and said nothing about
        the rest: 1500 rejects wrote 1001 rows under a summary saying 1500.
  H-05  ``sanitise_display`` escaped C0 and C1 only. Bidi overrides, line
        separators and zero-width characters reached stderr intact.
  H-06  ``IngestReport.merge`` had no caller and extended the reject list past
        the ledger bound.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.capabilities import CapabilityManifest
from cohaera.checks import (
    R_DUPLICATE_DELIVERY,
    R_EVENT_ID_REUSED,
    _negated_spans,
    ch02_concealment_gap,
    ch04_guardrail_overrun,
    coverage,
    run_all,
)
from cohaera.cli import EXIT_ERROR, EXIT_OK, _write_reject_log, main
from cohaera.ingest import assemble
from cohaera.limits import (
    DEFAULT_LIMITS,
    DEFECT_DUPLICATE_DELIVERY,
    DEFECT_EVENT_ID_REUSED,
    DEFECT_EVENT_ID_TYPE,
)
from cohaera.model import Event, Session, to_cim_event
from cohaera.validate import (
    REJECT_LEDGER_KEEP,
    IngestReport,
    Reject,
    sanitise_display,
)

BASE = 1_785_700_000.0

MANIFEST = CapabilityManifest.from_obj({
    "tools": {
        "send_email": {"effects": ["egress"], "reversible": False},
        "fetch_url": {"effects": ["read"], "reversible": True},
    }})


def raw(etype, ts, sid="s1", **data):
    """A fixture-shaped record, as a plain dict so it can be duplicated."""
    return {
        "event_id": data.pop("event_id", f"ev-{sid}-{ts}"),
        "timestamp": BASE + ts, "session_id": sid, "trace_id": sid,
        "span_id": data.pop("span_id", f"sp{ts}"),
        "event_type": etype, "agent_name": "agent-a",
        "tool_name": data.pop("tool_name", None),
        "framework": "claude", "host": "h1", "user": "u1",
        "data": {"log_source_type": "observra", **data},
    }


def ev(etype, ts, sid="s1", **data):
    return Event(raw=raw(etype, ts, sid, **data))


def session(events, manifest=MANIFEST):
    s = Session(session_id="s1", manifest=manifest,
                events=sorted(events, key=lambda e: e.sort_key))
    s.seal()
    return s


def egress_session(summary):
    return session([
        ev("tool_start", 1, tool_name="send_email", span_id="A"),
        ev("tool_end", 2, tool_name="send_email", span_id="A"),
        ev("model_response", 3, response_text=summary),
    ])


def untrusted_flow():
    """The fixture shape that reproduced H-02: a marker, then an egress."""
    return [
        raw("session_start", 0),
        raw("user_message", 1, user_message_text="summarise the page"),
        raw("tool_start", 2, tool_name="fetch_url", span_id="F"),
        raw("tool_end", 3, tool_name="fetch_url", span_id="F",
            has_injection_patterns=True,
            injection_patterns=["INSTRUCTION_OVERRIDE"]),
        raw("tool_start", 4, tool_name="send_email", span_id="E"),
        raw("tool_end", 5, tool_name="send_email", span_id="E"),
        raw("model_response", 6,
            response_text="I fetched the url and sent the email."),
    ]


# =====================================================================
# H-01  negation window runs past the sentence end
# =====================================================================


def test_h01_a_denial_in_one_sentence_does_not_swallow_the_next_sentence():
    """EVASION.md records negation as handled; this is the case it was not.

    "skipped" is a negation cue and its 80-character window reached "sent the
    email" in the NEXT sentence, so the disclosure was read as a denial and
    CH02 fired CRITICAL -- while the same summary minus the first sentence did
    not fire at all.
    """
    honest = "No issues found, nothing was skipped. I sent the email to Bob."
    assert ch02_concealment_gap(egress_session(honest)) == [], (
        "a disclosure after a full stop was read as negated")
    assert ch02_concealment_gap(egress_session("I sent the email to Bob.")) == []


@pytest.mark.parametrize("stop", [".", "!", "?", ";", "\n"])
def test_h01_every_sentence_terminator_ends_the_negation_span(stop):
    text = f"I did not call anything odd{stop} I sent the email to Bob."
    assert ch02_concealment_gap(egress_session(text)) == [], stop


def test_h01_a_real_denial_still_reads_as_concealment():
    """The mutation guard. Narrowing the span must not re-admit denials."""
    findings = ch02_concealment_gap(egress_session("I did not send the email."))
    assert [f.check for f in findings] == ["CH02_concealment_gap"]


def test_h01_a_decimal_point_inside_the_sentence_does_not_end_the_span():
    """"3.5" is not a sentence end; the lookahead keeps the denial intact."""
    findings = ch02_concealment_gap(
        egress_session("I did not send the 3.5 MB email to anyone."))
    assert [f.check for f in findings] == ["CH02_concealment_gap"]


def test_h01_negated_spans_stop_at_the_first_terminator_or_the_window():
    text = "x never a. b never cccc"
    spans = _negated_spans(text, window=80)
    assert spans[0] == (2, text.index(".")), "first span ends at the full stop"
    assert spans[1] == (text.index("never", 10), len(text)), (
        "second span has no terminator and runs to the end")
    tight = _negated_spans("never " + "a" * 200, window=5)
    assert tight == [(0, 5 + 5)], "the window still bounds a long sentence"


# =====================================================================
# H-02  duplicate deliveries scored as events
# =====================================================================


def _scored(records):
    sessions = assemble([Event(raw=dict(r)) for r in records], manifest=MANIFEST)
    assert len(sessions) == 1
    findings, cov = run_all(sessions[0])
    return sessions[0], findings, cov


def test_h02_a_session_delivered_twice_in_one_file_scores_as_once():
    """The reproduction: one fixture session concatenated with itself went
    from one finding to two, the second being CH05 on the redelivered
    tool_start that had no terminal event of its own."""
    one = untrusted_flow()
    _, f1, _ = _scored(one)
    s2, f2, _ = _scored(one * 2)
    assert [f.check for f in f1] == ["CH03_untrusted_to_completed_action"]
    assert [f.check for f in f2] == [f.check for f in f1], (
        "the duplicated session grew a CH05_unpaired_calls finding")
    assert s2.duplicate_event_count == len(one)
    assert s2.event_id_conflicts == 0, "byte-identical copies are retries"
    assert s2.features()["duplicate_delivery_code"] == DEFECT_DUPLICATE_DELIVERY


def test_h02_eight_copies_do_not_dilute_ch03_confidence():
    """Measured before the fix: 0.35 at x1, 0.11 at x2, 0.02 at x8, because
    every copy added consequential calls the check could not order."""
    one = untrusted_flow()
    conf = {}
    for mult in (1, 2, 8):
        _, _, cov = _scored(one * mult)
        conf[mult] = next(c["confidence"] for c in cov["checks"]
                          if c["check"].startswith("CH03"))
    assert conf[1] == conf[2] == conf[8], conf


def test_h02_the_drop_is_stated_in_coverage_and_in_the_features():
    s, _, cov = _scored(untrusted_flow() * 2)
    feats = s.features()
    assert feats["event_count"] == 14, "received records are still counted"
    assert feats["unique_event_count"] == 7
    assert feats["duplicate_event_count"] == 7
    assert R_DUPLICATE_DELIVERY == DEFECT_DUPLICATE_DELIVERY
    # Every contract that ran carries the common reason. CH01 did not run
    # (no baseline) and a not_evaluated contract states only why it could not.
    ran = [c for c in cov["checks"] if c["status"] != "not_evaluated"]
    assert {c["check"] for c in ran} >= {"CH02_concealment_gap",
                                         "CH05_unpaired_calls"}
    for contract in ran:
        assert R_DUPLICATE_DELIVERY in contract["reasons"], contract["check"]
    clean, _, cov_clean = _scored(untrusted_flow())
    assert clean.features()["duplicate_delivery_code"] is None
    assert not any(R_DUPLICATE_DELIVERY in c["reasons"] for c in cov_clean["checks"])


@pytest.mark.parametrize("restamp", [
    {"timestamp": BASE + 1.5},
    {"integrity": {"stream_id": "c1", "seq": 9}},
    {"timestamp": BASE + 1.5, "integrity": {"stream_id": "c1", "seq": 9}},
])
def test_h02_a_redelivery_with_the_same_id_and_restamped_envelope_is_dropped(
        restamp):
    """A collector that restamps the arrival clock, or chains and signs each
    delivery afresh, changes those fields and keeps the id. Same record."""
    first = raw("tool_start", 1, tool_name="send_email", span_id="A",
                event_id="same")
    again = dict(first, **restamp)
    s = session([Event(raw=first), Event(raw=again),
                 ev("tool_end", 2, tool_name="send_email", span_id="A")])
    assert len(s.unique_events) == 2
    assert s.duplicate_event_count == 1
    assert s.event_id_conflicts == 0
    assert s.unique_events[0].timestamp == BASE + 1, "the FIRST copy is kept"
    assert [c.state for c in s.tool_calls] == ["complete"]


def test_h02_an_id_reused_for_a_different_record_drops_nothing_and_is_flagged():
    """The E23 shape that caught the first version of the rule: a guardrail
    and a consequential call on the same tick, sharing a timestamp-derived
    id. Dropping either would blind CH04 on the strength of a producer's id
    scheme, so both are kept and the reuse is stated."""
    guardrail = ev("cost_threshold_exceeded", 5, event_id="e5",
                   session_cost_usd=0.9)
    start = ev("tool_start", 5, tool_name="send_email", span_id="A",
               event_id="e5")
    end = ev("tool_end", 6, tool_name="send_email", span_id="A")
    s = session([guardrail, start, end])
    assert len(s.unique_events) == 3
    assert s.duplicate_event_count == 0
    assert s.event_id_conflicts == 1
    feats = s.features()
    assert feats["event_id_conflict_code"] == DEFECT_EVENT_ID_REUSED
    assert feats["duplicate_delivery_code"] is None
    cov = coverage(s, None)
    assert R_EVENT_ID_REUSED in next(
        c["reasons"] for c in cov["checks"] if c["check"] == "CH05_unpaired_calls")
    assert R_EVENT_ID_REUSED == DEFECT_EVENT_ID_REUSED
    # And the call is still there for CH04 to order against the control.
    later = session([guardrail,
                     ev("tool_start", 7, tool_name="send_email", span_id="B",
                        event_id="e5"),
                     ev("tool_end", 8, tool_name="send_email", span_id="B")])
    assert later.event_id_conflicts == 1
    assert [f.check for f in ch04_guardrail_overrun(later)] == [
        "CH04_guardrail_bypass_completed"]


def test_h02_identical_content_with_no_event_id_is_still_a_duplicate():
    first = raw("tool_start", 1, tool_name="send_email", span_id="A")
    del first["event_id"]
    s = session([Event(raw=first), Event(raw=dict(first))])
    assert s.duplicate_event_count == 1
    assert s.event_id_conflicts == 0


def test_h02_distinct_records_are_never_collapsed():
    """Same tool, same clock, different id and span: two calls, not one."""
    s = session([
        ev("tool_start", 1, tool_name="send_email", span_id="A", event_id="a"),
        ev("tool_start", 1, tool_name="send_email", span_id="B", event_id="b"),
    ])
    assert s.duplicate_event_count == 0
    assert len(s.tool_calls) == 2


def test_h02_a_non_string_event_id_is_absent_and_flagged_not_stringified():
    """Rule 3. `1` and `"1"` must not alias, for the BUG-04 reason."""
    numeric = ev("tool_start", 1, tool_name="send_email", span_id="A",
                 event_id=1)
    textual = ev("tool_start", 2, tool_name="send_email", span_id="B",
                 event_id="1")
    assert numeric.event_id is None
    assert DEFECT_EVENT_ID_TYPE in numeric.defects
    assert textual.event_id == "1" and DEFECT_EVENT_ID_TYPE not in textual.defects
    s = session([numeric, textual])
    assert s.duplicate_event_count == 0
    assert s.integrity_defects == {DEFECT_EVENT_ID_TYPE: 1}
    long = ev("tool_start", 3, event_id="x" * (DEFAULT_LIMITS.max_span_chars + 1))
    assert long.event_id is None and DEFECT_EVENT_ID_TYPE in long.defects
    assert ev("tool_start", 4, event_id=True).event_id is None


def test_h02_the_content_digest_still_commits_to_the_dropped_copies():
    """A session that arrived with duplicates is a different input from one
    that did not, and the verdict identity has to say so (C4-01)."""
    one = untrusted_flow()
    s1, f1, c1 = _scored(one)
    s2, f2, c2 = _scored(one * 2)
    assert s1.content_digest != s2.content_digest
    v1 = to_cim_event(s1, f1, coverage=c1, provenance={"analysis_run_id": "r"})
    v2 = to_cim_event(s2, f2, coverage=c2, provenance={"analysis_run_id": "r"})
    assert v1["verdict_id"] != v2["verdict_id"]
    assert v1["findings_digest"] == v2["findings_digest"], (
        "the findings themselves are identical; only the input differs")


def test_h02_dedup_tracks_streaming_assembly_and_survives_sealing():
    """C4-08. The deduplicated view is a cache over `events` and must follow
    `add_event` and `seal` exactly as every other derived value does."""
    s = Session(session_id="s1", manifest=MANIFEST)
    first = ev("tool_start", 1, tool_name="send_email", span_id="A")
    s.add_event(first)
    assert s.duplicate_event_count == 0
    s.add_event(Event(raw=dict(first.raw)))
    assert s.duplicate_event_count == 1, "the cache served a stale answer"
    s.add_event(ev("tool_end", 2, tool_name="send_email", span_id="A"))
    s.seal()
    assert s.duplicate_event_count == 1
    assert len(s.unique_events) == 2
    assert [c.state for c in s.tool_calls] == ["complete"]
    assert s.features()["unpaired_calls"] == 0


def test_h02_per_event_counters_read_the_deduplicated_view():
    """Cost, errors, markers and policy events were all summed over the raw
    list, so a redelivered record doubled every one of them."""
    records = [
        raw("tool_start", 1, tool_name="send_email", span_id="A", cost_usd=0.5),
        raw("tool_error", 2, tool_name="send_email", span_id="A",
            injection_patterns=["X"], has_injection_patterns=True),
        raw("cost_threshold_exceeded", 3),
    ]
    s = session([Event(raw=r) for r in records + [dict(r) for r in records]])
    assert s.total_cost_usd == 0.5
    assert s.error_count == 1
    assert s.injection_markers == ["X"]
    assert s.policy_events == ["cost_threshold_exceeded"]
    assert s.clock_defects == 0
    assert coverage(s, None)["clock_confidence"] == 1.0


# =====================================================================
# H-03  CLI edges
# =====================================================================


def _telemetry(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in untrusted_flow()))
    return p


@pytest.mark.parametrize("sig_flag,file_flag", [
    ("--tool-manifest-sig", "--tool-manifest"),
    ("--baseline-sig", "--baseline"),
])
@pytest.mark.parametrize("require", [[], ["--require-signed-policy"]])
def test_h03a_a_signature_without_its_file_is_refused(tmp_path, capsys,
                                                      sig_flag, file_flag,
                                                      require):
    """The sig path does not even exist; before the fix this exited 0."""
    rc = main(["score", str(_telemetry(tmp_path)),
               sig_flag, str(tmp_path / "nope.sig"), *require])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR, err
    assert sig_flag in err and file_flag in err, err
    assert "finding(s)" not in err, "nothing should have been scored"


def test_h03b_a_missing_baseline_is_reported_as_unreadable_not_as_a_bad_signature(
        tmp_path, capsys):
    rc = main(["score", str(_telemetry(tmp_path)),
               "--baseline", str(tmp_path / "missing.jsonl")])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "baseline" in err and "not readable" in err, err
    assert "policy signature" not in err, err


def test_h03c_a_directory_as_reject_log_is_refused_before_anything_is_scored(
        tmp_path, capsys):
    """The old run scored everything, saved the seen-stream ledger, and only
    then failed on os.replace -- so the next run read as a replay."""
    d = tmp_path / "adir"
    d.mkdir()
    ledger = tmp_path / "seen.json"
    rc = main(["score", str(_telemetry(tmp_path)),
               "--reject-log", str(d), "--seen-streams", str(ledger)])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "is a directory" in err, err
    assert "finding(s)" not in err, "the run scored before failing"
    assert not ledger.exists(), "the seen-stream ledger was advanced"


def test_h03c_a_regular_reject_log_path_still_works(tmp_path):
    log = tmp_path / "rejects.jsonl"
    assert main(["score", str(_telemetry(tmp_path)),
                 "--reject-log", str(log)]) == EXIT_OK
    assert json.loads(log.read_text().splitlines()[-1])["_summary"]


def test_h03d_score_help_documents_the_exit_code_contract(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["score", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "exit codes" in out
    for code in ("0", "1", "2", "3", "4", "5"):
        assert f"\n  {code}   " in out, f"exit code {code} missing from --help"


# =====================================================================
# H-04  the quarantine ledger's silent bound
# =====================================================================


def test_h04_the_ledger_says_when_its_rows_were_cut(tmp_path):
    rep = IngestReport(source="x")
    for i in range(REJECT_LEDGER_KEEP + 500):
        rep.add_reject(Reject(source="x", line=i, code="MALFORMED_JSON"))
    assert len(rep.rejects) == REJECT_LEDGER_KEEP, "the bound must hold"
    summary = rep.summary()
    assert summary["records_rejected"] == REJECT_LEDGER_KEEP + 500
    assert summary["rejects_retained"] == REJECT_LEDGER_KEEP
    assert summary["rejects_omitted"] == 500
    assert summary["rejects_truncated"] is True

    out = tmp_path / "ledger.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        _write_reject_log(fh, rep)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == REJECT_LEDGER_KEEP + 2, "rows, marker, summary"
    assert rows[-2] == {"_truncated": {
        "rows_retained": REJECT_LEDGER_KEEP, "rows_omitted": 500,
        "records_rejected": REJECT_LEDGER_KEEP + 500}}
    assert rows[-1]["_summary"]["rejects_truncated"] is True


def test_h04_no_marker_below_the_bound(tmp_path):
    rep = IngestReport(source="x")
    rep.add_reject(Reject(source="x", line=1, code="MALFORMED_JSON"))
    assert rep.summary()["rejects_truncated"] is False
    assert rep.summary()["rejects_omitted"] == 0
    out = tmp_path / "ledger.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        _write_reject_log(fh, rep)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 2 and "_truncated" not in rows[0]


# =====================================================================
# H-05  bidi, separators and zero-width characters reach stderr
# =====================================================================

# Built from code points so no control character lands in this file.
_BIDI_AND_INVISIBLE = [
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,      # embeddings and overrides
    0x2066, 0x2067, 0x2068, 0x2069,              # isolates
    0x2028, 0x2029,                              # line, paragraph separator
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,      # zero-width, joiners, marks
    0xFEFF,                                      # BOM in-line
]


@pytest.mark.parametrize("code", _BIDI_AND_INVISIBLE)
def test_h05_layout_controls_are_escaped_like_c0(code):
    out = sanitise_display("a" + chr(code) + "b")
    assert out == f"a\\u{code:04x}b", (code, out)
    assert chr(code) not in out


def test_h05_c0_escapes_keep_their_shape_and_text_is_left_alone():
    assert sanitise_display("a\nb") == "a\\x0ab"
    assert sanitise_display("café عربي") == (
        "café عربي"), (
        "legitimate non-ASCII text must still be readable")


def test_h05_a_right_to_left_override_in_a_session_id_cannot_reorder_stderr(
        tmp_path, capsys):
    rlo = chr(0x202E)
    records = [dict(r, session_id=f"s{rlo}1", trace_id=f"s{rlo}1")
               for r in untrusted_flow()]
    p = tmp_path / "t.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in records))
    main(["score", str(p)])
    err = capsys.readouterr().err
    assert rlo not in err
    assert "\\u202e" in err


# =====================================================================
# H-06  dead merge
# =====================================================================


def test_h06_ingest_report_has_no_merge():
    """It had no caller and extended `rejects` past the ledger bound. A
    report per file is the contract; provenance records which is which."""
    assert not hasattr(IngestReport, "merge")
