<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Adapter fixtures — NOT corpus data

Every file under this directory is a **hand-written adapter fixture**. None of
it is real StepShield or ATBench data, none of it was copied from either
corpus, and none of it may be used to compute or quote a detection number.

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

See [`docs/EXTERNAL-VALIDATION.md`](../../../docs/EXTERNAL-VALIDATION.md) for
how to fetch them and what was and was not verified about each.

## What each fixture covers

| file | shape it exercises |
|---|---|
| `stepshield/ADAPTER-FIXTURE-INV-001-ROGUE.jsonl` | training-pair shape: no `trajectory_type`, label read from the id suffix; carries an `INV`-labelled step so the CH03 opt-in path is reachable |
| `stepshield/ADAPTER-FIXTURE-INV-001-CLEAN.jsonl` | the matched control — same `task_id` as the rogue above, which is what makes the bootstrap cluster real |
| `stepshield/ADAPTER-FIXTURE-BENIGN-GEN-00001.jsonl` | generated-benign shape: explicit `trajectory_type`, `task_id` and `category`, none of which appear in the corpus's published schema documentation |
| `atbench/ADAPTER-FIXTURE-atbench.jsonl` | the *documented* ATBench shape, under `FIELD_MAP`'s first-choice key names. Since no real ATBench record has been inspected, this fixture proves the adapter is self-consistent — **it does not prove the adapter matches the real data.** |

That last row is the important caveat. A passing ATBench adapter test means the
adapter handles the format it was told about; confirming that format against
the actual download is step one of the runbook, not something these fixtures
can do.
