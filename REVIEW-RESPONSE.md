<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Response to the external review of `f3acbf53`

An external reviewer read the whole repository at
[`f3acbf53`](https://github.com/404SecNotFound/Cohaera/commit/f3acbf53d364ef6c811b6d7f6cd479f4c0c947cc)
and raised **twenty-one findings**, nine of them High. It scored the project
6.8/10 as a research artifact and 3.5/10 for production readiness, and its most
useful contribution was not a bug: it pointed out that the project's headline
positioning had been overtaken by the market.

This file records what happened to each finding. It is written because a review
that produces a quiet round of commits is indistinguishable from a review that
was ignored, and because three of its recommended remedies were **declined** —
which is worth saying explicitly rather than leaving as a gap somebody else has
to notice.

**Every finding was accepted as real.** Eight of the nine High ones were
reproduced against the working branch before anything was changed. Nothing here
was closed by argument.

## Summary

| | Count |
|---|---:|
| Findings raised | 21 |
| Accepted as real | 21 |
| Closed | 16 |
| Closed in the defect, architecture written down | 4 |
| Deliberately declined, with reasons | 1 |

## The findings

| ID | Sev | Finding | What happened | Commit |
|---|---|---|---|---|
| R-01 | High | Empty and partial receipt bindings are trusted | **Closed.** `BINDING_TRUSTED` is exact-binding only. Span-only is context, never authority. CH07 reports it as `CH07_effect_receipt_partially_bound` — a different fact, not a weaker one | `65b4665` |
| R-02 | High | Ledger continuation does not prove chain continuity | **Closed.** Advancement requires the next exact sequence *and* the predecessor matching the stored head. A gap is discontinuous, a mismatching head is a fork, and neither reads as ordinary advancement | `d9f6fa5` |
| R-03 | High | Invalid, unsigned and unscored records advance the ledger | **Closed in the defect.** Only evidence that held may write. The architecture half — durable sink acknowledgement — is declined and the concept is renamed accordingly; see §"Declined" | `1df8e5a` |
| R-04 | High | Concurrent ledger writes lose valid state | **Closed.** Advisory file locking plus a generation guard; a stale parent cannot overwrite a newer one. Single-host, and the docstring says so | `2835d84` |
| R-05 | High | Any verified signature marks the whole session `verified` | **Closed.** `verified_complete` and `verified_prefix` replace `verified`, which no longer exists as an output value. The signer validates `sign_every` and always signs the final record | `188cf6f` |
| R-06 | High | Run identity omits output-affecting trust configuration | **Closed.** One canonical `trust_config_digest` over trust store, policy attestations, freshness, ledger state and correlation key version, folded into `analysis_run_id` as a required argument | `94065dd` |
| R-07 | High | Policy signature verification is subject to file replacement | **Closed.** Each attested artefact is resolved once; the digest describes the bytes that were parsed | `14974bc` |
| R-08 | High | The lab's required agent-to-collector route is impossible | **Closed.** The probe names the collector's generation-side address, the *negative* property it was standing in front of is now asserted, and `LAB.md`'s third topology is gone. A test requires every `reach` row to be routable from its source | `07260a7` |
| R-09 | High | Evaluation is synthetic, partly circular and operationally noisy | **Accepted, not closed.** See §"Deferred" | — |
| R-10 | Med-High | Span-only approvals suppress CH04 | **Closed.** Same completeness rule as R-01, on the approval side | `65b4665` |
| R-11 | Med | Resident-memory estimate undercounts nested maps | **Closed in the defect.** The parse counts objects and keys at every depth; the estimate is the larger of the byte term and the shape term. Streaming assembly with spill remains future work | `5577b2f` |
| R-12 | Med | Pure-Python signature work is an attacker-controlled CPU budget | **Closed in the defect.** A wall-clock bound beside the count, seconds spent reported, envelope measured and published. The recommended backend swap is declined | `5577b2f` |
| R-13 | Med | Future-dated records extend freshness without a defect | **Closed.** `max_future_skew_s`, `INTEGRITY_EVIDENCE_FROM_FUTURE`, inadmissible past the bound, and `--evidence-as-of` refuses nonfinite values | `ba084a6` |
| R-14 | Med | CH01 fits one global grammar | **Scope named, model deferred.** Every CH01 finding carries `baseline_scope: fleet`. Per-agent and peer-group baselines are a design change and are not pretended | `7f3394e` |
| R-15 | Med | Confidence intervals ignore task and family clustering | **Closed.** Task-cluster bootstrap intervals and macro averages beside the Wilson figures, with the independent-task count published. The bootstrap interval is about twice the width | `33ded88` |
| R-16 | Med | Label and session sets are not enforced one-to-one | **Closed.** Duplicates, orphans, unlabelled sessions and empty sessions are refused by name | `33ded88` |
| R-17 | Med | Receipt adapters mix identifier kinds and accept nonfinite | **Closed.** Every path declares its own kind and assurance level; nonfinite values are not identifiers; authority scope can travel | `bc283ed` |
| R-18 | Med | Release output is not reproducible or attested | **Closed in the defect.** `SOURCE_DATE_EPOCH` makes the wheel a function of the source and the SBOM job proves its rebuild is byte-identical. Attestation and a signed release need a tag this branch cannot cut | `e7d6923` |
| R-19 | Med | Exabeam position and integration proof are behind the market | **Closed.** The positioning is rewritten; see [POSITIONING.md](POSITIONING.md). A live integration is not claimed | `8c8d9f0` |
| R-20 | Low-Med | CLI, schema, version, counts and roadmap text drift | **Closed.** Output schema `cohaera:0.3`, version tied across three files by test, `--max-events` help corrected, `--reuse-generated` fails with an instruction, corpus size corrected in all three places, and the card no longer recommends two different false-positive metrics | `a0f493a`, `7f3394e` |
| R-21 | Low-Med | Core modules are too large for safe evidence changes | **Declined for now.** See §"Declined" | — |

## Declined, with reasons

Saying no to part of a review is worth more than silent compliance, provided
the reason is written down where the next reader will find it.

### Replacing the pure-Python Ed25519 with a maintained backend (R-12's remedy)

The review's own independent cross-check found **no algorithm mismatch in 1,000
randomised valid vectors or 1,000 mutated signatures**, and the verifier rejects
noncanonical `S`, bad encodings and untrusted keys. Zero runtime dependencies is
a CI-enforced property of this project and is what lets the verifier be audited
in one file and installed in an air-gapped analysis VM.

Swapping a demonstrated-correct component for an unproven integration is not a
security improvement. The availability concern is real and is bounded directly
instead: a wall-clock budget, a count budget charged before the work, and the
measured envelope in [SECURITY.md](SECURITY.md). The side-channel argument does
not apply to this code — it is a *verifier* handling public data. The signer
already says on its face that it is not constant-time and is a format reference.

An optional maintained backend behind a flag stays on the roadmap.

### Splitting `checks.py` and `evidence.py` now (R-21's remedy)

The diagnosis is right. Four thousand seven hundred lines across two
trust-bearing modules raises the odds that a new state joins a shared set and
silently gains authority somewhere else — which is exactly the shape of R-01.

That is why it is the wrong change to make in the same window as sixteen
security fixes. A structural split touching every trust constant, with an
evaluation card and thirteen Sigma rules downstream, is the highest-risk
lowest-visible-value work available right now. The R-02 to R-04 work did not
make a ledger module fall out naturally, so it was not forced.

Declined for this round, not disagreed with.

### Making the ledger transactional on output delivery (R-03's full remedy)

Requiring durable sink acknowledgement before ledger commit means an output
transaction across stdout, files and future SIEM sinks. That is a design, and
doing it badly would be worse than not doing it.

The three concrete poisoning paths are closed. What changed instead is the
**claim**: it is an *observation ledger* everywhere in prose and schema, and the
exactly-once-scoring language is gone. The review offered this option in as many
words; it was taken deliberately rather than by omission.

## Deferred, and why it cannot be closed here

### R-09, evaluation validity

The finding is correct and it is the most important one in the review. The
corpus is synthetic, its author wrote the detector, the label assertions import
production detection logic, and no external party has ever run this against
traffic it did not generate.

None of that is closable by editing this repository. It needs real executions
under instrumented runtimes, two or more frameworks, independent double-blind
labels, adaptive attacks written after the detector is frozen, and task, family,
agent and organisation holdouts. That is a research programme, not a commit.

What *was* done is the honest subset: intervals now treat a task as the
independent unit rather than a session (R-15), the corpus must be a bijection
between labels and telemetry (R-16), the card publishes how many independent
tasks and families a cell actually contains, and it names a property of itself
that nobody asked for — every family has an identical benign and attack count
and produces an identical rate, so a family-level interval has zero width. A
family holdout on this corpus therefore tests less than the name suggests, and
the card says so.

The results remain a **deterministic synthetic regression suite**. They are
described that way everywhere, and [POSITIONING.md](POSITIONING.md) bans the
language that would suggest otherwise — enforced by a test.

## What is still open

Named here rather than left to be discovered:

- **No external validation.** R-09, above.
- **No live SIEM integration.** Thirteen Sigma rules validate and convert; no
  parser has been tested against a live product, and no timeline or case has
  ever been produced.
- **No independent reviewer.** The single largest governance gap. Every finding
  in this document was reproduced and fixed by the same person who wrote the
  code it was found in.
- **The isolated lab has never been built.** Its assertions are text assertions.
  [`lab/local/`](lab/local/) is the reproducible half and is explicit that it
  proves nothing about network isolation.
- **No signed release or attestation.** The build is reproducible; nothing signs
  it yet.

## Verifying this document

Every claim above is checkable from the repository:

```bash
python -m pytest -q          # the tests, including one per finding
python eval/run_eval.py      # regenerates the card byte-identically
python lab/local/run.py --check   # re-runs the evidence path end to end
python tools/readme_facts.py --check
```

Each fix landed with a test that fails against the defect it describes. Where a
mutation of the guard still passed the suite, that was treated as a defect in
the test rather than a passing result.
