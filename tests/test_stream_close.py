# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""E30: a collector can close a stream, and a verifier can tell a cut from an end.

The chain proves nothing is missing in between and the signatures prove the
collector wrote what remains. Neither said how long the stream was meant to
be, so cutting records off the END of a signed stream left a contiguous,
fully verified prefix and no code of any kind (``tests/test_evasion.py``
E30). The remedy is a signed statement of where the stream ends: the last
record carries ``integrity.final: true`` and the literal ``final`` in its
signing input.

What these tests pin, in order:

1. the wire format: ``final`` is signed, so it cannot be added or removed;
2. the verifier's four codes and which of them are inadmissible;
3. the operator's flag, which is what turns "not closed" into "cut";
4. the seen-stream ledger, which remembers a close across runs;
5. the producer side, ``cohaera.emit``, which refuses to reopen a stream.

Run: PYTHONPATH=src python3 -m pytest tests/test_stream_close.py -v
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera import ed25519, ingest
from cohaera.checks import run_all
from cohaera.cli import EXIT_OK
from cohaera.cli import main as cli_main
from cohaera.emit.keys import KeyPair
from cohaera.emit.stream import StreamClosedError, StreamSigner
from cohaera.evidence import (
    INADMISSIBLE,
    R_CLOSE_UNVERIFIED,
    R_RECORDS_AFTER_CLOSE,
    R_SIGNATURE_INVALID,
    R_STREAM_END_MISSING,
    R_STREAM_NOT_CLOSED,
    Integrity,
    StreamLedger,
    StreamVerifier,
    TrustStore,
    signing_input,
)
from cohaera.identity import trust_config_digest
from cohaera.limits import DEFECT_INTEGRITY_TYPE
from cohaera.model import Event
from tools.collector_sign import key_id_for, keys_document, sign_stream

SECRET = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUBLIC = ed25519.public_key(SECRET)
KEY_ID = key_id_for(PUBLIC)
KEYS = TrustStore.from_obj(keys_document(PUBLIC, KEY_ID))


def _records(n: int, sid: str = "s1") -> list[dict]:
    return [{"event_type": "tool_start", "session_id": sid,
             "timestamp": 1000.0 + i, "span_id": f"sp-{i}",
             "tool_name": "alert_read", "data": {"action": "invoke_tool"}}
            for i in range(n)]


def _closed(n: int = 10) -> list[dict]:
    return sign_stream(_records(n), "stream-a", SECRET, KEY_ID, close=True)


def _open(n: int = 10) -> list[dict]:
    return sign_stream(_records(n), "stream-a", SECRET, KEY_ID)


def _verify(records: list[dict], *, require_closed: bool = False,
            ledger: StreamLedger | None = None, keys: TrustStore = KEYS
            ) -> StreamVerifier:
    v = StreamVerifier(keys=keys, require_closed=require_closed, ledger=ledger,
                       run_id="run")
    for raw in records:
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    return v


def _state(records, **kw):
    return _verify(records, **kw).for_session("s1")


# ---------------------------------------------------------------------------
# 1. The wire format
# ---------------------------------------------------------------------------

def test_final_is_part_of_the_signing_input_and_nothing_else_changed():
    assert signing_input("s", 3, "ab") == b"cohaera.integrity:1\x1fs\x1f3\x1fab"
    assert signing_input("s", 3, "ab", final=True) == (
        b"cohaera.integrity:1\x1fs\x1f3\x1fab\x1ffinal")


def test_a_closed_stream_differs_from_an_open_one_only_in_its_last_record():
    opened, closed = _open(), _closed()
    assert opened[:-1] == closed[:-1]
    assert closed[-1]["integrity"]["final"] is True
    assert "final" not in opened[-1]["integrity"]
    assert closed[-1]["integrity"]["sig"] != opened[-1]["integrity"]["sig"]


def test_final_parses_as_true_or_absent_and_nothing_else():
    base = _closed(2)[-1]["integrity"]
    assert Integrity.parse(base)[0].final is True
    assert Integrity.parse({**base, "final": None})[0].final is False
    for bad in (1, "true", "yes", False, [True], {}):
        parsed, codes = Integrity.parse({**base, "final": bad})
        assert parsed is None and codes == (DEFECT_INTEGRITY_TYPE,), bad


def test_stripping_final_from_a_closing_record_breaks_its_signature():
    """The point of signing the marker: a cut that also strips the word
    "final" from the new last record cannot make it look open."""
    records = _closed()
    del records[-1]["integrity"]["final"]
    state = _state(records)
    assert R_SIGNATURE_INVALID in state.inadmissible
    assert state.as_dict()["unanchored"] == []


def test_adding_final_to_an_ordinary_record_breaks_its_signature():
    records = _open()
    records[4]["integrity"]["final"] = True
    state = _state(records)
    assert R_SIGNATURE_INVALID in state.inadmissible
    assert R_RECORDS_AFTER_CLOSE not in state.codes, (
        "a forged close must not get to charge the genuine records after it")


# ---------------------------------------------------------------------------
# 2. The verifier
# ---------------------------------------------------------------------------

def test_a_closed_intact_stream_is_attested_with_no_closure_code():
    v = _verify(_closed())
    state = v.for_session("s1")
    assert state.attested and not state.inadmissible
    assert not {R_STREAM_NOT_CLOSED, R_STREAM_END_MISSING,
                R_RECORDS_AFTER_CLOSE, R_CLOSE_UNVERIFIED} & set(state.codes)
    assert v.stream_summary()[0]["closed_at"] == 9


def test_an_open_stream_says_its_end_is_unattested_and_stays_admissible():
    """A live tail is the ordinary case. Coverage, never a finding."""
    v = _verify(_open())
    state = v.for_session("s1")
    assert R_STREAM_NOT_CLOSED in state.codes
    assert R_STREAM_NOT_CLOSED not in INADMISSIBLE
    assert state.attested and not state.inadmissible
    assert v.stream_summary()[0]["closed_at"] is None


def test_the_cut_on_a_closed_stream_without_the_flag_is_merely_unclosed():
    """Honest, and not enough: without the operator saying streams close,
    a cut closed stream and a live open one are the same observation."""
    state = _state(_closed()[:7])
    assert R_STREAM_NOT_CLOSED in state.codes
    assert not state.inadmissible
    assert state.attested


def test_records_after_a_verified_close_are_inadmissible():
    closed = _closed()
    more = sign_stream(_records(12), "stream-a", SECRET, KEY_ID)[10:]
    state = _state(closed + more)
    assert R_RECORDS_AFTER_CLOSE in state.inadmissible
    assert R_RECORDS_AFTER_CLOSE in INADMISSIBLE
    assert not state.attested


def test_an_unsigned_final_claim_closes_nothing_and_is_reported():
    records = _open()
    records[-1]["integrity"]["final"] = True
    for k in ("sig", "key_id"):
        records[-1]["integrity"].pop(k)
    v = _verify(records)
    state = v.for_session("s1")
    assert R_CLOSE_UNVERIFIED in state.codes
    assert R_STREAM_NOT_CLOSED in state.codes
    assert v.stream_summary()[0]["closed_at"] is None
    assert R_CLOSE_UNVERIFIED not in INADMISSIBLE


def test_a_final_claim_with_no_keys_loaded_closes_nothing():
    v = _verify(_closed(), keys=TrustStore())
    state = v.for_session("s1")
    assert v.stream_summary()[0]["closed_at"] is None
    assert R_CLOSE_UNVERIFIED in state.codes


def test_the_lowest_verified_close_wins():
    """Two closes on one stream: the earlier one stands and everything past
    it, the second close included, is after-close."""
    first = _closed(5)
    second = sign_stream(_records(8), "stream-a", SECRET, KEY_ID, close=True)[5:]
    state = _state(first + second)
    assert R_RECORDS_AFTER_CLOSE in state.inadmissible


# ---------------------------------------------------------------------------
# 3. The operator's flag
# ---------------------------------------------------------------------------

def test_require_closed_makes_the_cut_inadmissible_and_leaves_the_whole_clean():
    whole = _state(_closed(), require_closed=True)
    assert whole.attested and not whole.inadmissible
    cut = _state(_closed()[:7], require_closed=True)
    assert cut.inadmissible == [R_STREAM_END_MISSING]
    assert R_STREAM_END_MISSING in INADMISSIBLE
    assert not cut.attested


def test_require_closed_refuses_an_open_stream_too():
    """Which is why it is off by default: the flag is a statement about the
    collectors, and a deployment whose collectors do not close streams must
    not set it."""
    state = _state(_open(), require_closed=True)
    assert R_STREAM_END_MISSING in state.inadmissible


def test_a_cut_stream_is_not_remembered_by_the_ledger(tmp_path):
    ledger = StreamLedger(path=tmp_path / "seen.json")
    v = _verify(_closed()[:7], require_closed=True, ledger=ledger)
    assert v.ledger_refusals and R_STREAM_END_MISSING in v.ledger_refusals[0]["reason"]
    assert "stream-a" not in ledger.streams


def test_ch06_explains_a_missing_end(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in _closed()[:7]), encoding="utf-8")
    (s,) = ingest.load(p, keys=KEYS, quiet=True, require_closed_streams=True)
    findings, cov = run_all(s, None)
    (ch06,) = [f for f in findings if f.check.startswith("CH06")]
    assert "without the verified final record" in ch06.detail
    (contract,) = [c for c in cov["checks"] if c["check"].startswith("CH06")]
    assert R_STREAM_END_MISSING in json.dumps(contract)


def test_an_open_stream_degrades_ch06_coverage_with_a_remedy(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in _open()), encoding="utf-8")
    (s,) = ingest.load(p, keys=KEYS, quiet=True)
    _findings, cov = run_all(s, None)
    (contract,) = [c for c in cov["checks"] if c["check"].startswith("CH06")]
    blob = json.dumps(contract)
    assert R_STREAM_NOT_CLOSED in blob
    assert "final=True" in blob


def test_the_run_identity_changes_only_when_the_flag_is_on():
    assert trust_config_digest(require_closed_streams=False) == trust_config_digest()
    assert trust_config_digest(require_closed_streams=True) != trust_config_digest()


def test_cli_flag_reaches_the_verifier_and_the_provenance(tmp_path, capsys):
    p = tmp_path / "t.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in _closed()[:7]), encoding="utf-8")
    ts = tmp_path / "ts.json"
    ts.write_text(json.dumps(keys_document(PUBLIC, KEY_ID)), encoding="utf-8")
    rc = cli_main(["score", str(p), "--trust-store", str(ts),
                   "--require-closed-streams"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    (row,) = [json.loads(line) for line in out.splitlines() if line.strip()]
    assert row["data"]["provenance"]["require_closed_streams"] is True
    assert row["data"]["coverage"]["evidence_status"] == "inadmissible"
    assert R_STREAM_END_MISSING in json.dumps(row)


# ---------------------------------------------------------------------------
# 4. The ledger across runs
# ---------------------------------------------------------------------------

def test_the_ledger_remembers_a_close_and_refuses_a_continuation(tmp_path):
    path = tmp_path / "seen.json"
    first = StreamLedger(path=path)
    _verify(_closed(), ledger=first)
    first.stamp("run-1")
    first.save()
    assert json.loads(path.read_text())["streams"]["stream-a"]["closed"] is True

    second = StreamLedger.load(path)
    assert second.streams["stream-a"].closed is True
    more = sign_stream(_records(12), "stream-a", SECRET, KEY_ID)[10:]
    v = _verify(more, ledger=second)
    state = v.for_session("s1")
    assert R_RECORDS_AFTER_CLOSE in state.inadmissible
    assert second.streams["stream-a"].last_seq == 9, "the close is not advanced past"


def test_a_ledger_written_before_e30_reads_as_open(tmp_path):
    path = tmp_path / "seen.json"
    first = StreamLedger(path=path)
    _verify(_open(), ledger=first)
    first.stamp("run-1")
    first.save()
    raw = json.loads(path.read_text())
    raw["streams"]["stream-a"].pop("closed", None)
    # The ledger digests its own contents against corruption, so a file from
    # before E30 is reproduced faithfully: same shape, digest recomputed.
    payload = json.dumps(raw["streams"], sort_keys=True, separators=(",", ":"))
    raw["digest"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    path.write_text(json.dumps(raw), encoding="utf-8")
    second = StreamLedger.load(path)
    assert second.streams["stream-a"].closed is False
    assert second.state_digest() == first.state_digest()


# ---------------------------------------------------------------------------
# 5. The producer side
# ---------------------------------------------------------------------------

PAIR = KeyPair.from_seed(SECRET)


def test_the_signer_closes_a_stream_and_refuses_to_reopen_it():
    signer = StreamSigner("stream-a", SECRET, PAIR.key_id)
    records = _records(10)
    signed = [signer.sign(r, final=(i == 9)) for i, r in enumerate(records)]
    assert signed == _closed(), "the incremental signer must match the reference"
    assert signer.closed
    with pytest.raises(StreamClosedError):
        signer.sign(_records(11)[10])
    state = signer.state()
    assert state["closed"] is True
    resumed = StreamSigner.resume(state, SECRET)
    assert resumed.closed
    with pytest.raises(StreamClosedError):
        resumed.sign(_records(11)[10])


def test_attest_signs_without_closing():
    signer = StreamSigner("stream-a", SECRET, PAIR.key_id, sign_every=100)
    signed = [signer.sign(r, attest=(i == 9)) for i, r in enumerate(_records(10))]
    assert "sig" in signed[-1]["integrity"] and "final" not in signed[-1]["integrity"]
    assert not signer.closed
    assert signer.state()["closed"] is False
    assert R_STREAM_NOT_CLOSED in _state(signed).codes


def test_a_bad_closed_value_in_state_is_refused():
    signer = StreamSigner("stream-a", SECRET, PAIR.key_id)
    state = {**signer.state(), "closed": "yes"}
    with pytest.raises(Exception, match="closed"):
        StreamSigner.resume(state, SECRET)


def test_the_cli_close_flag_closes_and_a_later_sign_is_refused(tmp_path):
    key = tmp_path / "collector.key"
    out = tmp_path / "signed.jsonl"
    state = tmp_path / "state.json"
    src = tmp_path / "in.jsonl"
    src.write_text("".join(json.dumps(r) + "\n" for r in _records(3)), encoding="utf-8")

    def emit(*argv):
        return subprocess.run(
            [sys.executable, "-m", "cohaera.emit", *argv], check=False,
            capture_output=True, text=True, encoding="utf-8", cwd=tmp_path,
            env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src"),
                 "PATH": "/usr/bin:/bin:/usr/local/bin"})

    assert emit("keygen", "--out", str(key), "--roles", "collector",
                "--trust-store", str(tmp_path / "ts.json")).returncode == 0
    r = emit("sign", "--key", str(key), "--stream-id", "stream-a", "--in", str(src),
             "--out", str(out), "--state", str(state), "--close")
    assert r.returncode == 0, r.stderr
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert rows[-1]["integrity"]["final"] is True
    assert json.loads(state.read_text())["closed"] is True
    again = emit("sign", "--key", str(key), "--stream-id", "stream-a", "--in", str(src),
                 "--out", str(out), "--state", str(state), "--append")
    assert again.returncode != 0
    assert "closed" in again.stderr
    assert len(out.read_text().splitlines()) == 3, "nothing was appended"

    store = TrustStore.from_file(tmp_path / "ts.json")
    v = _verify([{**copy.deepcopy(r)} for r in rows], keys=store, require_closed=True)
    assert v.for_session("s1").attested
    assert v.stream_summary()[0]["closed_at"] == 2
