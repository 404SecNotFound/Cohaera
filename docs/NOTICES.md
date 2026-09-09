<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Notices: `cohaera_notice`

A `cohaera_notice` is one finding, emitted as its own record with its own schema
(`cohaera.notice:1`) and its own routing field. It is the alert stream, kept
apart from the fact stream (`cohaera_tool`, see
[ACTIVITY-RECORDS](ACTIVITY-RECORDS.md)) and the per-session rollup (the
`cohaera_session_verdict`). This is the answer to the review's observation that
"the fact stream and the alert stream have the same schema, the same retention".

## Emitting it

```bash
cohaera score telemetry.jsonl --emit-notice-records > stream.jsonl
```

Off by default, exactly like `--emit-tool-records`: the stdout contract stays one
verdict per session unless asked. With the flag, each session's notices are
written after that session's verdict. Route by `type`. Every notice joins to its
verdict through `verdict_id` and carries a deterministic `notice_id`.

## The grade is the split, and it is not severity

Every notice carries `notice_grade`:

| Grade | Meaning | Route it to |
|---|---|---|
| `alert` | The check is deterministic, evidence-grounded, and measured at **zero benign false positives** on the evaluation card. | The pager. |
| `hunt` | A real observation whose benign rate is either high or unmeasured. | A hunting dataset, a weekly review, a per-agent aggregation. |

`notice_grade` is **not** `severity`. Severity says how bad the finding is if it
is real; grade says whether the check is trusted enough to wake someone. A
hunt-grade notice can be `critical` (CH02 concealment is) and still must not
page, because its benign rate is not established. **A router reads grade, not
severity.**

This is where the corpus's headline noise stops being an alert. The behavioural
checks produce roughly [420 false positives per 1,000 benign sessions](../eval/EVALUATION-CARD.md);
as `hunt`-grade notices they carry no page, while remaining durable, queryable
records. Only the three measured checks are `alert`-grade:

| Check ID | What it establishes |
|---|---|
| `CH04_blocking_control_bypassed` | A declared **blocking** control fired and a consequential action completed with no bound approval. |
| `CH06_evidence_integrity` | Sequence, chain, signature, freshness, replay or fork state is inadmissible. |
| `CH07_reported_failure_with_effect_receipt` | A claimed failure is contradicted by a provider effect receipt that binds to the call. |

Everything else — CH01, CH02, CH03, CH05, and the unmeasured CH04 and CH07
variants — is `hunt`-grade.

### One source of truth

The alert-grade set lives in code as `cohaera.checks.ALERT_GRADE_CHECKS`, and it
is exactly the set of check IDs the **production**-tier Sigma rules select on.
`tests/test_content.py` asserts the two are identical, so the notice grade and
the Sigma deployment tier cannot drift apart: promote or demote a rule and the
code set must move with it, or the test fails.

## Fields

| Field | Meaning |
|---|---|
| `type` / `schema` | `cohaera_notice` / `cohaera.notice:1`. |
| `notice_id` | Deterministic per-finding id: run identity, session, index, check. |
| `verdict_id` | The session verdict this notice belongs to. |
| `sequence` | The finding's ordinal in the session. |
| `session_id` / `agent_name` / `framework` / `host` / `user` | Identity, mirrored so a notice is self-sufficient. |
| `data.check` / `data.family` | The check ID and its coverage family. |
| `data.notice_grade` | `alert` \| `hunt`. |
| `data.severity` | `critical` … `info` — how bad if real, independent of grade. |
| `data.confidence` | The governing coverage contract's confidence in this finding. |
| `data.evidence_status` | How far the telemetry underneath was established. |
| `data.title` / `data.detail` / `data.evidence` | The finding itself. |
| `data.coverage_status` / `data.coverage_confidence` | Copied from the governing check's coverage contract, so a notice read alone still says how much rests on guesswork. |
| `data.provenance` | `analysis_run_id`, `detector_version`, `config_hash`, `verdict_id`. |

## The record family so far

Three record types now share a run and session key, each with a different job,
schema and retention — the separation [DIRECTION](DIRECTION.md) proposes and the
one Zeek keeps between protocol logs and its notice stream:

| Record | Job | Schema |
|---|---|---|
| `cohaera_session_verdict` | Per-session rollup and coverage. | `cohaera:0.3` |
| `cohaera_tool` | One durable fact per tool call. | `cohaera.tool:1` |
| `cohaera_notice` | One finding, graded for routing. | `cohaera.notice:1` |

`cohaera_session`, `cohaera_control`, `cohaera_evidence` and `cohaera_coverage`
are not built yet; the verdict still carries coverage and provenance until they
are.
