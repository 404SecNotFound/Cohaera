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
same workflow in five states, sign it, score it with the real CLI under a real
trust store and a real ledger, replay it, fork it, and write down exactly what
came out with a digest over every input and output.

WHAT IT PROVES, AND WHAT IT DOES NOT
------------------------------------
It proves the evidence path works end to end and keeps working: the run
manifest is committed and CI re-runs it, so a change that quietly alters what a
verdict says fails a diff rather than a reviewer's memory.

It proves nothing about network isolation, nothing about a real agent, nothing
about a real provider's receipts, and nothing about detection efficacy -- these
are six hand-written sessions, not a sample of anything. The numbers that speak
to efficacy are in ``eval/EVALUATION-CARD.md`` and they are worse than these
six sessions would suggest.

DETERMINISM
-----------
Every timestamp derives from a fixed constant, the signing key is a fixed lab
seed, and ``--evidence-as-of`` is pinned. No wall clock and no random value
reaches the manifest, so two runs on two machines produce the same bytes. That
is the property that makes the committed artefact worth committing: if it
changes, something changed.
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
from cohaera.evidence import (  # noqa: E402
    INTEGRITY_FIELD,
    ROLE_COLLECTOR,
    TRUST_STORE_SCHEMA,
    body_digest,
    chain_step,
    signing_input,
)
from tools.collector_sign import key_id_for, sign_stream  # noqa: E402

# A LAB KEY. It is committed on purpose and it is worth nothing: the whole
# argument for a collector signature is that the key lives somewhere the agent
# cannot reach, and a key in a public repository is reachable by everyone. It
# is here so the run is reproducible, and for no other reason.
LAB_SEED = bytes.fromhex("5c" * 32)
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


def _score(work: Path, telemetry: Path, *, store: Path, manifest: Path,
           ledger: Path | None = None) -> tuple[int, list[dict], str]:
    """Run the real CLI, the way an operator would."""
    # Every path is relative to `work`, and the CLI is run FROM there. That is
    # not tidiness: analysis_run_id commits to the source string, so an
    # absolute path would make the run identity depend on where the checkout
    # happens to live, and two machines would produce different verdict IDs for
    # identical evidence. The identity is doing exactly what it should here --
    # the lab has to stop feeding it a machine-specific input.
    argv = [sys.executable, "-m", "cohaera.cli", "score", telemetry.name,
            "--trust-store", store.name,
            "--tool-manifest", manifest.name,
            "--evidence-max-age", str(MAX_AGE),
            "--evidence-as-of", str(AS_OF)]
    if ledger is not None:
        argv += ["--seen-streams", ledger.name]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    proc = subprocess.run(argv, capture_output=True, text=True, env=env,
                          cwd=str(work), timeout=300, check=False)
    records = [json.loads(line) for line in proc.stdout.splitlines()
               if line.strip()]
    return proc.returncode, records, proc.stderr


def _summarise(record: dict) -> dict:
    data = record["data"]
    findings = data.get("findings", [])
    return {
        "session_id": record["session_id"],
        "verdict_id": record["verdict_id"],
        "schema": record["schema"],
        "max_severity": data.get("max_severity"),
        "triggered_rules": sorted(data.get("triggered_rules", [])),
        # From coverage, not from the findings: a session that triggered
        # nothing still has an answer to "how far was this telemetry
        # established", and the quiet session is where it matters most.
        "evidence_status": data.get("coverage", {}).get("evidence_status"),
        "coverage_completeness": data.get("coverage", {}).get("completeness"),
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

    inputs[store.name] = _sha256(store)
    inputs[manifest.name] = _sha256(manifest)

    document = {
        "schema": "cohaera.lab_run:1",
        "detector_version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "signing_key_id": key_id,
        "evidence_as_of": AS_OF,
        "evidence_max_age_s": MAX_AGE,
        "inputs": dict(sorted(inputs.items())),
        "states": states,
        "ledger": ledger_states,
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
        print(f"lab/local: {len(states)} states + 3 ledger passes match the "
              f"committed manifest ({elapsed:.1f}s)")
        return 0

    _write(manifest_path, text)
    _jsonl(out / "verdicts.jsonl", verdicts)
    _write(out / "RESULTS.md", _results_markdown(document, elapsed))
    print(f"lab/local: wrote {manifest_path.relative_to(REPO)} "
          f"({len(states)} states, {elapsed:.1f}s)")
    return 0


def _results_markdown(doc: dict, elapsed: float) -> str:
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
        "## The five states of one workflow",
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
        f"Run took {elapsed:.1f}s.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
