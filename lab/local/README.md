<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# The local lab

> **Status: EXECUTED, and its output is committed.** Everything on this page
> has been run. [`runs/latest/`](runs/latest/) is what it produced, byte for
> byte, and CI re-runs it on every push and fails if one byte differs.
>
> The four-VM VMware lab described in [`LAB.md`](../../LAB.md) has **not** been
> built. That page now opens by saying so. The two are not the same lab and
> only this one has been run.

No dependencies, no VMs, no network, no API key, no cloud account. About two
seconds.

---

## Five-minute quickstart

Everything below runs on a clean checkout with nothing installed but CPython —
3.10 to 3.13, the range `pyproject.toml` supports. No `pip install`, because
this project has no runtime dependencies. There is one entry point and this
is it.

### 1. Confirm the committed run still reproduces

```bash
git clone https://github.com/404SecNotFound/Cohaera.git
cd Cohaera
python lab/local/run.py --check
```

```
lab/local: 6 states, 3 ledger passes and 3 coverage-contract pairs match the committed manifest (2.0s, python 3.11)
```

The elapsed seconds and the interpreter version are the only parts of that line
that may differ from yours. Nothing else about a passing run is permitted to
vary — not on another machine, not on another interpreter. If the command exits
non-zero, something in the detector changed what a verdict *says*, and the diff
is the report.

### 2. Regenerate it yourself and confirm the tree is clean

```bash
python lab/local/run.py
git status --short
```

```
lab/local: wrote lab/local/runs/latest/RUN-MANIFEST.json (6 states, 3 contract pairs, 2.0s, python 3.11)
```

`git status --short` must print **nothing**. That is the actual claim: a run on
your machine produces the same bytes as the run in the repository.

### 3. Read what it produced

```bash
cat lab/local/runs/latest/RESULTS.md
```

The three tables below are that file. They are reproduced here so you can tell
at a glance whether your run matched, and a test asserts they stay identical to
the generated ones.

**The six states of one workflow.** Same agent, same ticket-handling workflow;
what differs between rows is the thing being demonstrated.

| State | What it is | Fired | Evidence | Severity |
|---|---|---|---|---|
| `01-normal` | Normal | — | `verified_complete` | info |
| `02-behaviour-change` | Behaviour change | `CH03_untrusted_to_completed_action` | `verified_complete` | critical |
| `03-evidence-failure` | Evidence failure | `CH06_evidence_integrity` | `inadmissible` | critical |
| `04-contradiction` | Outcome contradiction | `CH07_reported_failure_with_effect_receipt` | `verified_complete` | high |
| `04b-unbound-receipt` | Unbound receipt | `CH07_effect_receipt_partially_bound` | `verified_complete` | low |
| `05-partial-attestation` | Partial attestation | — | `verified_prefix` | info |

**Replaying and forking the same stream.** The ledger is the only thing that
can tell a stream fed twice from a stream rewritten.

| Pass | Integrity codes |
|---|---|
| first | — |
| replay | `INTEGRITY_STREAM_REPLAYED` |
| fork | `INTEGRITY_CHAIN_BROKEN`, `INTEGRITY_STREAM_FORKED`, `STREAM_LEDGER_NOT_ADVANCED` |

**What it declines to answer, and why.** Three prerequisites the detector needs
and a first deployment does not have, each scored twice on the same telemetry.

| Prerequisite | Configuration | Coverage | Session grouping | Session key | Evidence | Fired |
|---|---|---|---|---|---|---|
| Capability manifest | `absent` | 0.129 | 1.0 (`session_id`) | `sha256-unkeyed-v1` | `verified_complete` | — |
| Capability manifest | `supplied` | 0.7 | 1.0 (`session_id`) | `sha256-unkeyed-v1` | `verified_complete` | `CH03_untrusted_to_completed_action` |
| Collector signature | `chained` | 0.49 | 1.0 (`session_id`) | `sha256-unkeyed-v1` | `chained_unsigned` | — |
| Collector signature | `signed` | 0.557 | 1.0 (`session_id`) | `sha256-unkeyed-v1` | `verified_complete` | — |
| Correlation key | `unkeyed` | 0.257 | 0.3 (`scoped_anonymous`) | `sha256-unkeyed-v1` | `verified_complete` | — |
| Correlation key | `keyed` | 0.257 | 0.3 (`scoped_anonymous`) | `hmac-sha256-v1` | `verified_complete` | — |

| Prerequisite | Check | Without | With |
|---|---|---|---|
| Capability manifest | `CH02_concealment_gap` | `degraded` 0.0 | `evaluated` 1.0 |
| Capability manifest | `CH03_untrusted_to_consequential` | `degraded` 0.0 | `evaluated` 1.0 |
| Capability manifest | `CH04_guardrail_overrun` | `degraded` 0.0 | `evaluated` 1.0 |
| Capability manifest | `CH05_unpaired_calls` | `degraded` 0.0 | `evaluated` 1.0 |
| Capability manifest | `CH07_effect_contradiction` | `degraded` 0.0 | `evaluated` 1.0 |
| Collector signature | `CH06_evidence_integrity` | `degraded` 0.432 | `degraded` 0.9 |

### 4. Watch it decline to answer

The `absent` row above is the **shipping default**: no capability manifest, so
`issue_refund` matches no keyword set and carries no producer hint, so Cohaera
does not know this session contained a consequential action at all. Run the two
passes by hand and read the `[GAP ]` lines on stderr, which is where the
coverage contract actually speaks:

```bash
cd lab/local/runs/latest/inputs
PYTHONPATH=../../../../../src python -m cohaera.cli score 06-no-manifest.jsonl \
    --trust-store trust-store.json \
    --evidence-max-age 86400.0 --evidence-as-of 1785720000.0
```

```
session lab-06-no-manifest  agent=support-agent  tools=2 (ro=1 sc=0 eg=0 ?=1)  cost=$0.11  coverage=0.129  corr=session_id
   [GAP ] CH01_sequence_order not_evaluated: NO_BENIGN_BASELINE_FITTED
   [GAP ] CH02_concealment_gap degraded: TOOL_CLASS_UNKNOWN; TOOL_CLASS_FROM_NAME_HEURISTIC; NO_CAPABILITY_MANIFEST
   [GAP ] CH03_untrusted_to_consequential degraded: TOOL_CLASS_UNKNOWN; TOOL_CLASS_FROM_NAME_HEURISTIC; NO_CAPABILITY_MANIFEST; INJECTION_SCANNER_PARTIAL_COVERAGE
   [GAP ] CH04_guardrail_overrun degraded: TOOL_CLASS_UNKNOWN; TOOL_CLASS_FROM_NAME_HEURISTIC; NO_CAPABILITY_MANIFEST
   [GAP ] CH06_evidence_integrity degraded: NO_STREAM_LEDGER
   [GAP ] CH07_effect_contradiction degraded: TOOL_CLASS_UNKNOWN; TOOL_CLASS_FROM_NAME_HEURISTIC; NO_CAPABILITY_MANIFEST
   [GAP ] CH05_unpaired_calls degraded: TOOL_CLASS_UNKNOWN
[cohaera] 0 finding(s) across 1 session(s); 10 record(s) accepted, 0 quarantined, 0 accepted with field defects
```

`?=1` is the whole story: one of the two calls could not be classified at all,
so nothing fires and seven `[GAP ]` lines say why. Now add the one flag that
changes it, and nothing else:

```bash
PYTHONPATH=../../../../../src python -m cohaera.cli score 06-no-manifest.jsonl \
    --trust-store trust-store.json --tool-manifest capability-manifest.json \
    --evidence-max-age 86400.0 --evidence-as-of 1785720000.0
```

```
session lab-06-no-manifest  agent=support-agent  tools=2 (ro=1 sc=1 eg=0 ?=0)  cost=$0.11  coverage=0.843  corr=session_id
   [HIGH] CH03_untrusted_to_completed_action: Consequential action COMPLETED after observed injection markers  (confidence 1.00)
   [GAP ] CH01_sequence_order not_evaluated: NO_BENIGN_BASELINE_FITTED
   [GAP ] CH06_evidence_integrity degraded: NO_STREAM_LEDGER
[cohaera] 1 finding(s) across 1 session(s); 10 record(s) accepted, 0 quarantined, 0 accepted with field defects
```

Same bytes of telemetry, same digest, one declaration. A check reported
`degraded` at confidence 0.0 **has not run and says so**; it is not a check that
ran and found nothing. That distinction is the entire project, and it is the one
thing worth taking away from five minutes here.

---

## What this establishes, and what it does not

**It is a smoke test and a reproducibility check.** It establishes that the
evidence path works end to end on this checkout — mint a key, sign a stream,
score it under a real trust store, a real capability manifest, a real freshness
bound and a real ledger, replay it, fork it — and that the result has not
silently moved since it was last committed.

**It is not an evaluation and its output is not a result.** Nine hand-written
sessions are not a sample of anything, and nothing here says how often these
checks are right on traffic somebody else produced. The numbers that speak to
that are in [`eval/EVALUATION-CARD.md`](../../eval/EVALUATION-CARD.md), they are
measured against a corpus rather than against nine stories, and they are
considerably less flattering. **If you want to know whether the detector works,
read the evaluation card. This page tells you whether it still does what it did
last week.**

It also establishes nothing about **network** isolation, nothing about a real
agent, and nothing about a real provider's receipts. Network isolation is what
the VMware lab in [`LAB.md`](../../LAB.md) is for, and that lab has not been
built.

---

## Why there are two labs

[`LAB.md`](../../LAB.md) builds four isolated VMs under VMware and is the only
one of the two that can answer a question about network isolation. It cannot run
in CI, on a reviewer's laptop, or anywhere without a Windows host and a VMware
licence — so its properties are asserted as *text*, and an external review was
right to point out that a lab validated as text has not been built. That build
record does not exist. Until it does, `LAB.md` is a design note.

This is the half that *is* reproducible anywhere Python is.

## What it produces

| File | What it is |
|---|---|
| `runs/latest/RESULTS.md` | The tables above, generated |
| `runs/latest/RUN-MANIFEST.json` | Every input digest, every verdict ID, every check's coverage status, every integrity code |
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

## The three coverage-contract pairs

The six states above all run in the configuration the author chose: manifest
supplied, collector key supplied, producer emitting a `session_id`. That is the
wrong thing to show a new operator first, because it is not the configuration
they have. These three are:

1. **Capability manifest, absent and supplied.** Untrusted content, then
   `issue_refund` — a tool the name heuristic returns `unknown` for, on a stream
   carrying no `reversible` hint. Without a manifest, CH02, CH03, CH04, CH05 and
   CH07 all report `degraded` at confidence **0.0** and completeness is 0.129.
   With one, all five reach `evaluated` and CH03 fires.
2. **Collector signature, chained and signed.** The same records with and
   without a signature over the chain. Unsigned reports `chained_unsigned` and
   CH06 at 0.432 rather than `verified_complete` at 0.9. The evaluation card
   calls this the realistic first-adoption state, and most of the evaluation
   corpus is in it.
3. **Correlation key, unkeyed and keyed.** A stream carrying no `session_id`,
   scored with `$COHAERA_CORRELATION_SECRET` unset and then set. Correlation
   drops to `scoped_anonymous` at **0.3** in both, and coverage to 0.3 against
   0.7 for the same workflow with a `session_id`. The secret does **not** raise
   that number — nothing does but a producer-supplied identifier. What it
   changes is the key version, from an unkeyed SHA-256 digest to an HMAC, so
   that a small identity space cannot be enumerated out of the SIEM copy.

## The keys

`LAB_SEED` and `LAB_CORRELATION_SECRET` are committed. They are worth nothing:
the entire argument for a collector signature is that the key lives somewhere
the agent cannot reach, and a key in a repository is reachable by everyone. They
are there so the run is reproducible, and for no other reason.

`run.py` **removes** `$COHAERA_CORRELATION_SECRET` from the environment it hands
the CLI, and sets it only for the pass that is about it. That variable is folded
into `trust_config_digest` and therefore into every `verdict_id` below it, so a
lab that inherited the operator's shell would produce a manifest that depended
on who ran it — which is the same defect as stamping the interpreter version
into the compared document, arriving through an input rather than through a
field.

## Determinism

Two consecutive runs produce identical bytes, and so do runs on CPython 3.10,
3.11, 3.12 and 3.13 — the whole range `pyproject.toml` supports. Every timestamp
derives from a fixed constant, every key is a fixed lab constant,
`--evidence-as-of` is pinned, and the CLI is invoked from inside `runs/latest/inputs/`
with relative paths so that `analysis_run_id` does not commit to where the
checkout happens to live.

`tests/test_lab.py` asserts that no environment fact reaches the compared
document. That test exists because an earlier version stamped the interpreter
version into the manifest, and the first CI run failed on 3.12 against a file
written on 3.11 — a real property turned into a host fact, and a green local
check that meant nothing.
