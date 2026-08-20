#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Run the whole evidence path end to end, locally, and commit what it produced.

    python lab/local/run.py            # run, and write runs/latest/
    python lab/local/run.py --check    # run, and fail if it differs from
                                       # what is committed

WHY THIS EXISTS BESIDE lab/
---------------------------
``LAB.md`` and ``lab/Build-CohaeraLab.ps1`` build four isolated VMs under
VMware. That lab is the one that can answer questions about network isolation,
and it cannot run in CI, on this repository's runners, or on a reviewer's
laptop. Its assertions are therefore text assertions, and the review that
found R-08 was right to say that a lab validated as text is not a lab that
has been built.

This is the other half, and it is deliberately not a substitute. It runs the
part that IS reproducible anywhere Python is: mint a collector key, emit the
same workflow in six states, sign it, score it with the real CLI under a real
trust store and a real ledger, replay it, fork it, and write down exactly what
came out with a digest over every input and output.

It then scores three more sessions TWICE each -- with a capability manifest and
without, signed and merely chained, with a correlation secret and without --
because the equipped configuration is the one the author chose and the empty
one is the one a new operator has. See ``_contract``.

WHAT IT PROVES, AND WHAT IT DOES NOT
------------------------------------
It proves the evidence path works end to end and keeps working: the run
manifest is committed and CI re-runs it, so a change that quietly alters what a
verdict says fails a diff rather than a reviewer's memory. It is a SMOKE TEST
and a REPRODUCIBILITY CHECK.

It is not an evaluation and its output is not a result. It proves nothing about
network isolation, nothing about a real agent, nothing about a real provider's
receipts, and nothing about detection efficacy -- these are nine hand-written
sessions, not a sample of anything. The numbers that speak to efficacy are in
``eval/EVALUATION-CARD.md`` and they are worse than these sessions would
suggest.

DETERMINISM
-----------
Every timestamp derives from a fixed constant, the signing key is a fixed lab
seed, ``--evidence-as-of`` is pinned, and the correlation secret is set by this
file rather than inherited from the shell. No wall clock, no interpreter
version, no hostname, no absolute path and no random value reaches the
manifest, so two runs on two machines produce the same bytes. That is the
property that makes the committed artefact worth committing: if it changes,
something changed. Verified on CPython 3.10, 3.11, 3.12 and 3.13, which is the
whole range ``pyproject.toml`` supports.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))

import scenarios  # noqa: E402

from cohaera import (  # noqa: E402
    __version__,
    ed25519,
)
from cohaera.cli import SECRET_ENV  # noqa: E402
from cohaera.evidence import (  # noqa: E402
    INTEGRITY_FIELD,
    INTEGRITY_SCHEMA,
    ROLE_COLLECTOR,
    TRUST_STORE_SCHEMA,
    body_digest,
    chain_seed,
    chain_step,
    signing_input,
)
from tools.collector_sign import key_id_for, sign_stream  # noqa: E402

# A LAB KEY. It is committed on purpose and it is worth nothing: the whole
# argument for a collector signature is that the key lives somewhere the agent
# cannot reach, and a key in a public repository is reachable by everyone. It
# is here so the run is reproducible, and for no other reason.
LAB_SEED = bytes.fromhex("5c" * 32)

# Likewise worth nothing, and committed for the same reason. A correlation
# secret keys the anonymous session digests so a small identity space cannot be
# enumerated out of the SIEM copy; one published in a repository keys nothing
# against anybody. It is here so the `keyed` half of the 08 pair is
# reproducible, and the lab pins it rather than reading the operator's -- see
# _score.
LAB_CORRELATION_SECRET = "lab-correlation-secret-published-on-purpose"
STREAM = "lab-collector-01"
AS_OF = scenarios.BASE + 10_000.0
MAX_AGE = 86_400.0

MANIFEST = {
    "schema": "cohaera.capabilities:1",
    "tools": {
        scenarios.TOOL_SEARCH: {"effects": ["read"]},
        scenarios.TOOL_READ: {"effects": ["read"]},
        scenarios.TOOL_REFUND: {"effects": ["write"]},
        scenarios.TOOL_EXPORT: {"effects": ["egress"]},
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _jsonl(path: Path, records: list[dict]) -> Path:
    return _write(path, "".join(json.dumps(r, sort_keys=True) + "\n"
                                for r in records))


def _score(work: Path, telemetry: Path, *, store: Path,
           manifest: Path | None = None, ledger: Path | None = None,
           secret: str | None = None) -> tuple[int, list[dict], str]:
    """Run the real CLI, the way an operator would."""
    # Every path is relative to `work`, and the CLI is run FROM there. That is
    # not tidiness: analysis_run_id commits to the source string, so an
    # absolute path would make the run identity depend on where the checkout
    # happens to live, and two machines would produce different verdict IDs for
    # identical evidence. The identity is doing exactly what it should here --
    # the lab has to stop feeding it a machine-specific input.
    argv = [sys.executable, "-m", "cohaera.cli", "score", telemetry.name,
            "--trust-store", store.name,
            "--evidence-max-age", str(MAX_AGE),
            "--evidence-as-of", str(AS_OF)]
    if manifest is not None:
        argv += ["--tool-manifest", manifest.name]
    if ledger is not None:
        argv += ["--seen-streams", ledger.name]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    # THE LAB DECIDES THIS, NOT THE SHELL THE LAB WAS STARTED FROM.
    #
    # `correlation_keyed` and `correlation_key_version` are folded into
    # trust_config_digest and therefore into analysis_run_id and every
    # verdict_id below. Inheriting $COHAERA_CORRELATION_SECRET from the
    # environment made the committed manifest a function of whoever ran it:
    # `python lab/local/run.py --check` passed on a clean shell and failed on
    # an operator's, with a diff full of changed verdict IDs and no clue why.
    # That is the same defect as stamping the interpreter version into the
    # document, arriving through an input rather than through a field.
    env.pop(SECRET_ENV, None)
    if secret is not None:
        env[SECRET_ENV] = secret
    proc = subprocess.run(argv, capture_output=True, text=True, env=env,
                          cwd=str(work), timeout=300, check=False)
    records = [json.loads(line) for line in proc.stdout.splitlines()
               if line.strip()]
    return proc.returncode, records, proc.stderr


def _summarise(record: dict) -> dict:
    data = record["data"]
    findings = data.get("findings", [])
    coverage = data.get("coverage", {})
    correlation = data.get("correlation") or {}
    return {
        "session_id": record["session_id"],
        "verdict_id": record["verdict_id"],
        "schema": record["schema"],
        "max_severity": data.get("max_severity"),
        "triggered_rules": sorted(data.get("triggered_rules", [])),
        # From coverage, not from the findings: a session that triggered
        # nothing still has an answer to "how far was this telemetry
        # established", and the quiet session is where it matters most.
        "evidence_status": coverage.get("evidence_status"),
        "coverage_completeness": coverage.get("completeness"),
        # Per check, because the aggregate hides the thing worth seeing. A
        # check that stops being able to run drops from `evaluated` to
        # `not_evaluated` while the finding list stays empty and the
        # completeness figure moves by a few hundredths -- so before this the
        # committed manifest could not tell "nothing to report" from "nothing
        # I was in a position to report", which is the distinction the whole
        # project is about.
        "checks": {c["check"]: {"status": c["status"],
                                "confidence": round(c["confidence"], 3)}
                   for c in coverage.get("checks", [])},
        # What the session grouping rests on. 1.0 means the producer said
        # where the session began; anything less means Cohaera inferred it.
        "correlation": {"kind": correlation.get("kind"),
                        "confidence": correlation.get("confidence")},
        "finding_count": len(findings),
    }


def _integrity_codes(records: list[dict]) -> list[str]:
    codes: set[str] = set()
    for record in records:
        for finding in record["data"].get("findings", []):
            integrity = finding.get("evidence", {}).get("integrity")
            if isinstance(integrity, dict):
                codes.update(integrity.get("codes", {}))
    return sorted(codes)


def _rechain(records: list[dict], secret: bytes, key_id: str,
             prev_head: str) -> list[dict]:
    """Re-sign an edited stream from a head of the forger's choosing.

    This is the fork: every record verifies, every signature is genuine, and
    the history is not the one that was scored before. It is what an authorised
    collector -- or anyone holding its key -- can do, and it is the case the
    ledger exists to name.
    """
    out = []
    head = prev_head
    for record in records:
        clone = copy.deepcopy(record)
        sidecar = dict(clone[INTEGRITY_FIELD])
        body = body_digest(clone)
        head = chain_step(head, body)
        sidecar["prev"] = clone[INTEGRITY_FIELD]["prev"]
        sidecar["body"] = body
        sidecar["chain"] = head
        sidecar["sig"] = __import__("base64").b64encode(ed25519.sign(
            secret, signing_input(sidecar["stream_id"], sidecar["seq"], head)
        )).decode("ascii")
        clone[INTEGRITY_FIELD] = sidecar
        out.append(clone)
    return out


def _chain_only(records: list[dict], stream_id: str) -> list[dict]:
    """Chain a stream the way a collector with nowhere to keep a key does.

    Not ``sign_stream`` with the signatures deleted afterwards. The chain seed
    is ``H(scheme || stream_id || key_id)`` and the verifier recomputes it from
    the key_id ON THE RECORD, so a stream chained under a real key_id and then
    stripped of it does not chain at all -- it reports INTEGRITY_CHAIN_BROKEN,
    which is a different and much more alarming finding than the one this state
    is about. A keyless collector seeds with the empty string, and this is that
    collector.
    """
    out: list[dict] = []
    head = chain_seed(stream_id, "")
    for seq, record in enumerate(records):
        body = {k: v for k, v in record.items() if k != INTEGRITY_FIELD}
        prev = head
        head = chain_step(prev, body_digest(body))
        out.append({**body, INTEGRITY_FIELD: {
            "scheme": INTEGRITY_SCHEMA, "stream_id": stream_id, "seq": seq,
            "prev": prev, "chain": head}})
    return out


def _pass(label: str, note: str,
          result: tuple[int, list[dict], str]) -> dict:
    """One scoring pass, with the run-level trust configuration it ran under.

    ``correlation`` here is the CORRELATOR's state -- whether a secret was in
    force for this invocation -- and not the session's. The two are separate
    facts and the whole point of the 08 pair is that they move independently.
    """
    code, records, _err = result
    provenance = records[0]["data"]["provenance"] if records else {}
    return {
        "pass": label,
        "note": note,
        "exit_code": code,
        "correlation_key_version": provenance.get("correlation_key_version"),
        "correlation_keyed": provenance.get("correlation_keyed"),
        "verdicts": [_summarise(r) for r in records],
        "integrity_codes": _integrity_codes(records),
    }


def _contract(work: Path, store: Path, manifest: Path, key_id: str,
              inputs: dict[str, str]) -> list[dict]:
    """Three prerequisites the detector needs, each scored with and without.

    Everything above this runs in the configuration the author chose. That is
    the wrong thing to show first: the SHIPPING DEFAULT is no capability
    manifest, no collector key and, in a great many adapters, no producer
    session_id -- and in that configuration large parts of Cohaera decline to
    answer. A new operator should be able to see the tool decline, and read why,
    before deciding whether the equipped case is worth the work.

    Scored in pairs because a blind spot on its own reads as a quiet result.
    """
    out: list[dict] = []

    # ---- 1. The capability manifest ------------------------------------
    key, title, build, question = scenarios.CONTRACT_STATES[0]
    signed = sign_stream(build(), f"{STREAM}-{key}", LAB_SEED, key_id)
    path = _jsonl(work / f"{key}.jsonl", signed)
    inputs[path.name] = _sha256(path)
    out.append({"contract": key, "title": title, "question": question,
                "inputs": [path.name], "passes": [
        _pass("absent", "No --tool-manifest. The default.",
              _score(work, path, store=store)),
        _pass("supplied", "--tool-manifest declares issue_refund a write.",
              _score(work, path, store=store, manifest=manifest)),
    ]})

    # ---- 2. The collector signature -------------------------------------
    key, title, build, question = scenarios.CONTRACT_STATES[1]
    records = build()
    unsigned = _jsonl(work / f"{key}.jsonl",
                      _chain_only(records, f"{STREAM}-{key}"))
    countersigned = _jsonl(work / f"{key}-signed.jsonl",
                           sign_stream(records, f"{STREAM}-{key}-signed",
                                       LAB_SEED, key_id))
    inputs[unsigned.name] = _sha256(unsigned)
    inputs[countersigned.name] = _sha256(countersigned)
    out.append({"contract": key, "title": title, "question": question,
                "inputs": [unsigned.name, countersigned.name], "passes": [
        _pass("chained", "Hash chain, no signature. The first-adoption state.",
              _score(work, unsigned, store=store, manifest=manifest)),
        _pass("signed", "The same records, signed by the same collector.",
              _score(work, countersigned, store=store, manifest=manifest)),
    ]})

    # ---- 3. The correlation key ------------------------------------------
    key, title, build, question = scenarios.CONTRACT_STATES[2]
    signed = sign_stream(build(), f"{STREAM}-{key}", LAB_SEED, key_id)
    path = _jsonl(work / f"{key}.jsonl", signed)
    inputs[path.name] = _sha256(path)
    out.append({"contract": key, "title": title, "question": question,
                "inputs": [path.name], "passes": [
        _pass("unkeyed", f"No ${SECRET_ENV}. The default.",
              _score(work, path, store=store, manifest=manifest)),
        _pass("keyed", f"${SECRET_ENV} set to the committed lab value.",
              _score(work, path, store=store, manifest=manifest,
                     secret=LAB_CORRELATION_SECRET)),
    ]})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=HERE / "runs" / "latest")
    ap.add_argument("--check", action="store_true",
                    help="Fail if the run differs from the committed manifest.")
    args = ap.parse_args(argv)

    started = time.monotonic()
    out = args.out
    work = out / "inputs"
    work.mkdir(parents=True, exist_ok=True)

    public = ed25519.public_key(LAB_SEED)
    key_id = key_id_for(public)
    store = _write(work / "trust-store.json", json.dumps({
        "scheme": TRUST_STORE_SCHEMA,
        "keys": {key_id: {
            "key": __import__("base64").b64encode(public).decode("ascii"),
            "roles": [ROLE_COLLECTOR]}}}, indent=2, sort_keys=True) + "\n")
    manifest = _write(work / "capability-manifest.json",
                      json.dumps(MANIFEST, indent=2, sort_keys=True) + "\n")

    states: list[dict] = []
    verdicts: list[dict] = []
    inputs: dict[str, str] = {}

    for key, title, build, why in scenarios.STATES:
        raw = build()
        # State 5 is the sampled one: a collector under load signing every
        # fourth record, which anchors a prefix and leaves a tail.
        every = 4 if key.startswith("05") else 1
        signed = sign_stream(raw, f"{STREAM}-{key}", LAB_SEED, key_id,
                             sign_every=every)
        if key.startswith("05"):
            # A LIVE TAIL. tools/collector_sign.py always signs the final
            # record, because a collector that has finished writing a stream
            # can afford one more scalar multiplication and `verified_complete`
            # should be reachable for a sampled stream. That is the right
            # behaviour and it means a correctly-behaving signer never produces
            # this state on a stream it has closed.
            #
            # It produces it constantly on a stream it has NOT closed. Scoring
            # a tail that is still being written means the records after the
            # last checkpoint have no signature yet -- not because anything is
            # wrong, but because the collector has not got there. Those records
            # are covered by nobody, they can be replaced and re-chained, and
            # before R-05 the session carrying them reported `verified` at
            # confidence 1.0. So the tail is stripped here, which is what the
            # verifier would have received had it read the file a second early.
            last_checkpoint = max(i for i in range(len(signed))
                                  if i % every == 0)
            for record in signed[last_checkpoint + 1:]:
                record[INTEGRITY_FIELD].pop("sig", None)
                record[INTEGRITY_FIELD].pop("key_id", None)
        if key.startswith("03"):
            # The edit, applied AFTER signing. One character of one result.
            for record in signed:
                if record.get("event_type") == "tool_end":
                    record["data"]["result_text"] = "refunded (adjusted)"
                    break
        path = _jsonl(work / f"{key}.jsonl", signed)
        inputs[path.name] = _sha256(path)
        code, records, _err = _score(work, path, store=store, manifest=manifest)
        verdicts.extend(records)
        states.append({
            "state": key, "title": title, "why": why,
            "exit_code": code,
            "records_in": len(signed),
            "signed_every": every,
            "verdicts": [_summarise(r) for r in records],
            "integrity_codes": _integrity_codes(records),
        })

    # ---- replay and fork, which need a ledger to have an opinion at all ----
    ledger = out / "inputs" / "seen-streams.json"
    ledger.unlink(missing_ok=True)
    normal = work / "01-normal.jsonl"

    first_code, first_records, _ = _score(work, normal, store=store,
                                          manifest=manifest, ledger=ledger)
    replay_code, replay_records, _ = _score(work, normal, store=store,
                                            manifest=manifest, ledger=ledger)

    signed_normal = [json.loads(line) for line in
                     normal.read_text(encoding="utf-8").splitlines()]
    forked = copy.deepcopy(signed_normal)
    for record in forked:
        if record.get("event_type") == "model_response":
            record["data"]["response_text"] = "I did not issue any refund."
            break
    forked = _rechain(forked, LAB_SEED, key_id,
                      signed_normal[0][INTEGRITY_FIELD]["prev"])
    fork_path = _jsonl(work / "01-normal-forked.jsonl", forked)
    inputs[fork_path.name] = _sha256(fork_path)
    fork_code, fork_records, _ = _score(work, fork_path, store=store,
                                        manifest=manifest, ledger=ledger)

    ledger_states = [
        {"pass": "first", "exit_code": first_code,
         "integrity_codes": _integrity_codes(first_records),
         "verdicts": [_summarise(r) for r in first_records]},
        {"pass": "replay", "exit_code": replay_code,
         "integrity_codes": _integrity_codes(replay_records),
         "verdicts": [_summarise(r) for r in replay_records]},
        {"pass": "fork", "exit_code": fork_code,
         "integrity_codes": _integrity_codes(fork_records),
         "verdicts": [_summarise(r) for r in fork_records]},
    ]

    contract = _contract(work, store, manifest, key_id, inputs)

    inputs[store.name] = _sha256(store)
    inputs[manifest.name] = _sha256(manifest)

    document = {
        "schema": "cohaera.lab_run:1",
        "detector_version": __version__,
        # Deliberately NOT the interpreter version. The claim this manifest
        # makes is "these inputs produce these verdicts", and that has to hold
        # on every interpreter the project supports -- CI running a different
        # one from the author is the point of the check, not a discrepancy.
        # Stamping the environment into the compared document turned a real
        # property into a host fact and failed the first time CI ran it on
        # 3.12 against a manifest written on 3.11.
        "signing_key_id": key_id,
        "evidence_as_of": AS_OF,
        "evidence_max_age_s": MAX_AGE,
        "inputs": dict(sorted(inputs.items())),
        "states": states,
        "ledger": ledger_states,
        "contract": contract,
    }

    manifest_path = out / "RUN-MANIFEST.json"
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    elapsed = time.monotonic() - started

    if args.check:
        if not manifest_path.exists():
            print(f"no committed manifest at {manifest_path}", file=sys.stderr)
            return 1
        committed = manifest_path.read_text(encoding="utf-8")
        if committed != text:
            print("the lab run no longer matches the committed manifest.\n"
                  "Re-run `python lab/local/run.py` and read the diff before "
                  "committing it: a change here is a change in what a verdict "
                  "says.", file=sys.stderr)
            return 1
        print(f"lab/local: {len(states)} states, 3 ledger passes and "
              f"{len(contract)} coverage-contract pairs match the committed "
              f"manifest ({elapsed:.1f}s, python "
              f"{sys.version_info.major}.{sys.version_info.minor})")
        return 0

    _write(manifest_path, text)
    _jsonl(out / "verdicts.jsonl", verdicts)
    _write(out / "RESULTS.md", _results_markdown(document))
    # Relative when it can be, absolute when --out points outside the tree.
    # `Path.relative_to` RAISES on a path it cannot express, so a run written
    # to a scratch directory used to die after doing all its work.
    try:
        where: Path | str = manifest_path.relative_to(REPO)
    except ValueError:
        where = manifest_path
    print(f"lab/local: wrote {where} "
          f"({len(states)} states, {len(contract)} contract pairs, "
          f"{elapsed:.1f}s, "
          f"python {sys.version_info.major}.{sys.version_info.minor})")
    return 0


def _cell(entry: dict | None) -> str:
    if entry is None:
        return "—"
    return f"`{entry['status']}` {entry['confidence']}"


def _results_markdown(doc: dict) -> str:
    lines = [
        "<!--",
        "  Copyright 2026 Imran Hafeez",
        "  SPDX-License-Identifier: Apache-2.0",
        "-->",
        "",
        "# Local lab run",
        "",
        "Generated by `python lab/local/run.py`. Do not edit by hand — CI",
        "re-runs it with `--check` and fails on any difference.",
        "",
        f"Detector `{doc['detector_version']}`, "
        f"signing key `{doc['signing_key_id']}`, "
        f"freshness pinned to `{doc['evidence_as_of']}`.",
        "",
        "## The six states of one workflow",
        "",
        "Same agent, same ticket-handling workflow. What differs between rows",
        "is the thing being demonstrated.",
        "",
        "| State | What it is | Fired | Evidence | Severity |",
        "|---|---|---|---|---|",
    ]
    for state in doc["states"]:
        for verdict in state["verdicts"]:
            rules = ", ".join(f"`{r}`" for r in verdict["triggered_rules"]) or "—"
            evidence = f"`{verdict['evidence_status']}`"
            lines.append(
                f"| `{state['state']}` | {state['title']} | {rules} | "
                f"{evidence} | {verdict['max_severity'] or '—'} |")
    lines += [
        "",
        "## Replaying and forking the same stream",
        "",
        "The ledger is the only thing that can tell a stream fed twice from a",
        "stream rewritten. Both pass every other check — the records are",
        "genuine, they are just not new, or not the same history.",
        "",
        "| Pass | Integrity codes |",
        "|---|---|",
    ]
    for entry in doc["ledger"]:
        codes = ", ".join(f"`{c}`" for c in entry["integrity_codes"]) or "—"
        lines.append(f"| {entry['pass']} | {codes} |")
    lines += [
        "",
        "## What it declines to answer, and why",
        "",
        "Three prerequisites the detector needs and that a first deployment",
        "does not have. Each pair is the same telemetry scored twice — once",
        "without the prerequisite and once with it — so the difference between",
        "the two rows is attributable to that one thing.",
        "",
        "| Prerequisite | Configuration | Coverage | Session grouping | Session key | Evidence | Fired |",
        "|---|---|---|---|---|---|---|",
    ]
    for entry in doc["contract"]:
        for p in entry["passes"]:
            for verdict in p["verdicts"]:
                rules = ", ".join(f"`{r}`" for r in verdict["triggered_rules"]) or "—"
                lines.append(
                    f"| {entry['title']} | `{p['pass']}` | "
                    f"{verdict['coverage_completeness']} | "
                    f"{verdict['correlation']['confidence']} "
                    f"(`{verdict['correlation']['kind']}`) | "
                    f"`{p['correlation_key_version']}` | "
                    f"`{verdict['evidence_status']}` | {rules} |")
    lines += [
        "",
        "And per check, which is where it is actually legible. Only the checks",
        "whose contract MOVED are listed: a check that reads the same either",
        "way did not depend on the prerequisite.",
        "",
        "| Prerequisite | Check | Without | With |",
        "|---|---|---|---|",
    ]
    for entry in doc["contract"]:
        before, after = entry["passes"]
        left = before["verdicts"][0]["checks"] if before["verdicts"] else {}
        right = after["verdicts"][0]["checks"] if after["verdicts"] else {}
        for check in sorted(set(left) | set(right)):
            a, b = left.get(check), right.get(check)
            if a == b:
                continue
            lines.append(
                f"| {entry['title']} | `{check}` | "
                f"{_cell(a)} | {_cell(b)} |")
    lines += [
        "",
        "The `absent`, `chained` and `unkeyed` rows are the **shipping default**,",
        "not a misconfiguration. A check reported `degraded` at confidence 0.0",
        "has not run and says so; it is not a check that ran and found nothing.",
        "",
        "The correlation-key pair moves **no** check contract, and that is its",
        "point. Setting `$COHAERA_CORRELATION_SECRET` changes the session key",
        "from an unkeyed digest to an HMAC, so the identity behind it cannot be",
        "enumerated out of the SIEM copy. It does not raise the 0.3: nothing",
        "raises that but a producer emitting a `session_id`. What the missing",
        "`session_id` costs is in the coverage column — the same workflow scores",
        "0.7 with one (the `signed` row) and 0.3 without, because correlation",
        "confidence multiplies through every check that reasons across events.",
        "",
        "## What this does not show",
        "",
        "Six hand-written sessions are not a sample of anything. This run",
        "demonstrates that the evidence path works end to end and keeps",
        "working; it says nothing about how often these checks are right on",
        "real traffic. The numbers that speak to that are in",
        "[`eval/EVALUATION-CARD.md`](../../../eval/EVALUATION-CARD.md), and",
        "they are considerably less flattering than these six sessions.",
        "",
        "It also shows nothing about network isolation. That is the VMware lab",
        "in [`LAB.md`](../../../LAB.md), which has not yet produced a committed",
        "build record.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
