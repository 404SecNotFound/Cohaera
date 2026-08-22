<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Adapter fixtures — NOT corpus data

Every file under this directory is a **hand-written adapter fixture**. None of
it is real StepShield, ATBench or AgentDojo data, none of it was copied from any
of those corpora, and none of it may be used to compute or quote a detection
number.

`run_external.py` will happily score this directory and print a headline rate.
**That rate is meaningless** — six traces, one of them deliberately refused, and
a bigram baseline fitted on a single session. It is printed because the runner
does not have a special case for fixtures, not because it means anything.

They exist for one purpose: to exercise the adapters' *shape handling* — the
field mapping, the label resolution, the fail-loud paths and the
absent-never-weaker doctrine — without a network or a licence question. Each
record carries a `"_fixture"` key saying so, and every identifier begins with
`ADAPTER-FIXTURE-` so it cannot be mistaken for a corpus id in a log, a
traceback or a scored result.

The real corpora are not vendored here:

| corpus | data location | licence |
|---|---|---|
| StepShield | `github.com/glo26/stepshield`, `data/` | CC BY 4.0 (data), MIT (code) |
| ATBench | Hugging Face `AI45Research/ATBench` only | **none published** |
| AgentDojo | produced locally by running the benchmark | MIT |

See [`docs/EXTERNAL-VALIDATION.md`](../../../docs/EXTERNAL-VALIDATION.md) for
how to fetch them and what was and was not verified about each.

## What each fixture covers

| file | shape it exercises |
|---|---|
| `stepshield/ADAPTER-FIXTURE-INV-001-ROGUE.jsonl` | training-pair shape: no `trajectory_type`, label read from the id suffix; carries an `INV`-labelled step so the CH03 opt-in path is reachable |
| `stepshield/ADAPTER-FIXTURE-INV-001-CLEAN.jsonl` | the matched control — same `task_id` as the rogue above, which is what makes the bootstrap cluster real |
| `stepshield/ADAPTER-FIXTURE-BENIGN-GEN-00001.jsonl` | generated-benign shape: explicit `trajectory_type`, `task_id` and `category`, none of which appear in the corpus's published schema documentation |
| `atbench/ADAPTER-FIXTURE-atbench.jsonl` | the *documented* ATBench shape, under `FIELD_MAP`'s first-choice key names. Since no real ATBench record has been inspected, this fixture proves the adapter is self-consistent — **it does not prove the adapter matches the real data.** |

| `agentdojo/**/none/none.json` (×3) | clean runs — `attack_type` null, no injection task. One of the three uses the **pre-content-block** schema, where `content` is a bare string rather than a list of blocks, because run directories accumulate across releases |
| `agentdojo/.../user-task-1/important_instructions/...injection-1.json` | **compromised**: the injected string is inside a captured tool result and the agent then makes an egress call it omits from its summary |
| `agentdojo/.../user-task-2/important_instructions/...injection-1.json` | **repelled**: the same injected string is present and the agent does the user's task anyway. The one fixture that proves the three-way split is a three-way split |
| `agentdojo/.../user-task-3/important_instructions/...injection-2.json` | an **errored** run, written exactly as `benchmark.py` writes one — `utility=False`, `security=True`, a truncated message list with a dangling tool call. Must be refused at load time |

The ATBench row is the important caveat. A passing ATBench adapter test means the
adapter handles the format it was told about; confirming that format against
the actual download is step one of the runbook, not something these fixtures
can do.

**AgentDojo is the opposite case and should not be confused with it.** Its
fixtures are written against a schema read directly from AgentDojo's source at a
pinned revision, so they match what AgentDojo documents itself as writing. What
they still do not prove is that a real run directory contains no shape these
six files leave out.
