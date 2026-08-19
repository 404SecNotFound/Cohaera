<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# The local lab

```bash
python lab/local/run.py           # run it, write runs/latest/
python lab/local/run.py --check   # run it, fail on any difference
```

No dependencies, no VMs, no network. About a second.

## Why there are two labs

[`LAB.md`](../../LAB.md) builds four isolated VMs under VMware and is the only
one of the two that can answer a question about network isolation. It cannot
run in CI, on a reviewer's laptop, or anywhere without a Windows host and a
VMware licence — so its properties are asserted as *text*, and an external
review was right to point out that a lab validated as text has not been built.
That build record does not exist yet, and until it does `LAB.md` describes an
intention.

This is the half that *is* reproducible anywhere Python is. It runs the
evidence path end to end against the real CLI: mint a collector key, emit one
workflow in six states, sign it, score it under a real trust store, manifest,
freshness bound and ledger, then replay the stream and fork it.

## What it produces

| File | What it is |
|---|---|
| `runs/latest/RESULTS.md` | The table a human reads in thirty seconds |
| `runs/latest/RUN-MANIFEST.json` | Every input digest, every verdict ID, every integrity code |
| `runs/latest/verdicts.jsonl` | The raw `cohaera_session_verdict` records |
| `runs/latest/inputs/` | The signed telemetry, trust store and manifest that produced them |

All of it is committed, and CI re-runs `--check`. A change that quietly alters
what a verdict *says* fails a diff rather than a reviewer's memory. That is the
whole reason the manifest is worth committing.

## The six states

One agent, one ticket-handling workflow. What differs between states is the
thing being demonstrated, so a difference in the output is attributable.

1. **Normal.** Expected tool, exactly bound approval, effect completes,
   response discloses it. This one has to be boring.
2. **Behaviour change.** Untrusted content, then a first-time tool and a new
   destination. A reason to look, not a verdict.
3. **Evidence failure.** State 1's behaviour with one record edited *after*
   signing. The behaviour is unremarkable; the evidence is inadmissible, and
   the difference between those two sentences is the project.
4. **Outcome contradiction.** The agent reports the refund failed. A receipt
   bound to that exact span, tool and argument digest says it did not.
5. **4b — unbound receipt.** The same claim with an incomplete binding. It
   must **not** contradict. Before R-01 it did, at critical severity, on the
   strength of an identifier that named no call.
6. **Partial attestation.** A live tail, sampled signing, records past the last
   checkpoint covered by nobody. Reports `verified_prefix`. Before R-05 it
   reported `verified` at confidence 1.0.

Then the same stream is fed twice (`INTEGRITY_STREAM_REPLAYED`) and rewritten
with genuine signatures from a false boundary (`INTEGRITY_STREAM_FORKED`).
Every other check passes on both, because the records really were written by
that collector — they are just not new, or not the same history.

## What it is not

Six hand-written sessions are not a sample of anything, and nothing here says
how often these checks are right on traffic somebody else produced. The numbers
that speak to that are in [`eval/EVALUATION-CARD.md`](../../eval/EVALUATION-CARD.md)
and they are considerably less flattering.

## The key

`LAB_SEED` is committed. It is worth nothing: the entire argument for a
collector signature is that the key lives somewhere the agent cannot reach, and
a key in a repository is reachable by everyone. It is there so the run is
reproducible, and for no other reason.
