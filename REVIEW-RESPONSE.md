<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Response to the external reviews

## The first review, of `f3acbf53`

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

| | First review | Second review |
|---|---:|---:|
| Findings raised | 21 | 22 |
| Accepted as real | 21 | 22 |
| Closed | 16 | 19 |
| Closed in the defect, architecture written down | 4 | — |
| Accepted, not closable in this repository | — | 2 |
| Deliberately declined, with reasons | 1 | 1 |

Of the second review's 22, **fourteen were already fixed** by the first
review's work and were invisible because it had not been merged.

## The findings

| ID | Sev | Finding | What happened | Commit |
|---|---|---|---|---|
| R-01 | High | Empty and partial receipt bindings are trusted | **Closed.** `BINDING_TRUSTED` is exact-binding only. Span-only is context, never authority. CH07 reports it as `CH07_effect_receipt_partially_bound` — a different fact, not a weaker one | [`65b4665`](https://github.com/404SecNotFound/Cohaera/commit/65b4665) |
| R-02 | High | Ledger continuation does not prove chain continuity | **Closed.** Advancement requires the next exact sequence *and* the predecessor matching the stored head. A gap is discontinuous, a mismatching head is a fork, and neither reads as ordinary advancement | [`d9f6fa5`](https://github.com/404SecNotFound/Cohaera/commit/d9f6fa5) |
| R-03 | High | Invalid, unsigned and unscored records advance the ledger | **Closed in the defect.** Only evidence that held may write. The architecture half — durable sink acknowledgement — is declined and the concept is renamed accordingly; see §"Declined" | [`1df8e5a`](https://github.com/404SecNotFound/Cohaera/commit/1df8e5a) |
| R-04 | High | Concurrent ledger writes lose valid state | **Closed.** Advisory file locking plus a generation guard; a stale parent cannot overwrite a newer one. Single-host, and the docstring says so | [`2835d84`](https://github.com/404SecNotFound/Cohaera/commit/2835d84) |
| R-05 | High | Any verified signature marks the whole session `verified` | **Closed.** `verified_complete` and `verified_prefix` replace `verified`, which no longer exists as an output value. The signer validates `sign_every` and always signs the final record | [`188cf6f`](https://github.com/404SecNotFound/Cohaera/commit/188cf6f) |
| R-06 | High | Run identity omits output-affecting trust configuration | **Closed.** One canonical `trust_config_digest` over trust store, policy attestations, freshness, ledger state and correlation key version, folded into `analysis_run_id` as a required argument | [`94065dd`](https://github.com/404SecNotFound/Cohaera/commit/94065dd) |
| R-07 | High | Policy signature verification is subject to file replacement | **Closed.** Each attested artefact is resolved once; the digest describes the bytes that were parsed | [`14974bc`](https://github.com/404SecNotFound/Cohaera/commit/14974bc) |
| R-08 | High | The lab's required agent-to-collector route is impossible | **Closed.** The probe names the collector's generation-side address, the *negative* property it was standing in front of is now asserted, and `LAB.md`'s third topology is gone. A test requires every `reach` row to be routable from its source | [`07260a7`](https://github.com/404SecNotFound/Cohaera/commit/07260a7) |
| R-09 | High | Evaluation is synthetic, partly circular and operationally noisy | **Accepted, not closed.** See §"Deferred" | — |
| R-10 | Med-High | Span-only approvals suppress CH04 | **Closed.** Same completeness rule as R-01, on the approval side | [`65b4665`](https://github.com/404SecNotFound/Cohaera/commit/65b4665) |
| R-11 | Med | Resident-memory estimate undercounts nested maps | **Closed in the defect.** The parse counts objects and keys at every depth; the estimate is the larger of the byte term and the shape term. Streaming assembly with spill remains future work | [`5577b2f`](https://github.com/404SecNotFound/Cohaera/commit/5577b2f) |
| R-12 | Med | Pure-Python signature work is an attacker-controlled CPU budget | **Closed in the defect.** A wall-clock bound beside the count, seconds spent reported, envelope measured and published. The recommended backend swap is declined | [`5577b2f`](https://github.com/404SecNotFound/Cohaera/commit/5577b2f) |
| R-13 | Med | Future-dated records extend freshness without a defect | **Closed.** `max_future_skew_s`, `INTEGRITY_EVIDENCE_FROM_FUTURE`, inadmissible past the bound, and `--evidence-as-of` refuses nonfinite values | [`ba084a6`](https://github.com/404SecNotFound/Cohaera/commit/ba084a6) |
| R-14 | Med | CH01 fits one global grammar | **Scope named, model deferred.** Every CH01 finding carries `baseline_scope: fleet`. Per-agent and peer-group baselines are a design change and are not pretended | [`7f3394e`](https://github.com/404SecNotFound/Cohaera/commit/7f3394e) |
| R-15 | Med | Confidence intervals ignore task and family clustering | **Closed.** Task-cluster bootstrap intervals and macro averages beside the Wilson figures, with the independent-task count published. The bootstrap interval is about twice the width | [`33ded88`](https://github.com/404SecNotFound/Cohaera/commit/33ded88) |
| R-16 | Med | Label and session sets are not enforced one-to-one | **Closed.** Duplicates, orphans, unlabelled sessions and empty sessions are refused by name | [`33ded88`](https://github.com/404SecNotFound/Cohaera/commit/33ded88) |
| R-17 | Med | Receipt adapters mix identifier kinds and accept nonfinite | **Closed.** Every path declares its own kind and assurance level; nonfinite values are not identifiers; authority scope can travel | [`bc283ed`](https://github.com/404SecNotFound/Cohaera/commit/bc283ed) |
| R-18 | Med | Release output is not reproducible or attested | **Closed in the defect.** `SOURCE_DATE_EPOCH` makes the wheel a function of the source and the SBOM job proves its rebuild is byte-identical. Attestation and a signed release need a tag this branch cannot cut | [`e7d6923`](https://github.com/404SecNotFound/Cohaera/commit/e7d6923) |
| R-19 | Med | Exabeam position and integration proof are behind the market | **Closed.** The positioning is rewritten; see [POSITIONING.md](POSITIONING.md). A live integration is not claimed | [`8c8d9f0`](https://github.com/404SecNotFound/Cohaera/commit/8c8d9f0) |
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
evaluation card and 15 Sigma rules downstream, is the highest-risk
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
- **No live SIEM integration.** 15 Sigma rules validate and convert; no
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

## The second review, of `main` at `21068b6`

A different reviewer read the default branch six days later and did something
more useful than describing defects: they shipped **eight executable
reproduction probes**. Twenty-two findings, of which thirteen were marked
"Reconfirmed".

They were reconfirmed against a tree that had never received the fix. Every
correction above lived on an unmerged branch, and the reviewer noted the
symptom without being able to see the cause — *"its last four commits only
update CI and development dependencies, so earlier application findings
remain."*

That is not a flaw in the review. It read the default branch, which is the
correct thing to read, and it is the reason this work is now merged: **anything
not on `main` does not exist to a reader.**

The probes were run against the fixed tree rather than reasoned about. Six
reproduced.

| ID | Sev | Finding | What happened |
|---|---|---|---|
| F-01 | High | Declared argument digest overrides captured arguments | **Closed.** The digest over the arguments Cohaera saw is authoritative; a call whose two identities disagree is bindable by nothing |
| F-02 | High | Post-execution approval suppresses CH04 | **Closed.** The approval *record* must be observed before the call starts. An ordering that cannot be established is not permission |
| F-03 | High | Partial unauthenticated sidecar controls ordering | **Closed.** Only a chained sidecar may order events, and `attested` now means a signature verified rather than "a sidecar was present" |
| F-04 | High | Truncated response supports a confidence-1.0 absence claim | **Closed.** Absence abstains with `FINAL_RESPONSE_TRUNCATED`; a disclosure found in a surviving prefix is still sound |
| F-05 | High | Agent-supplied receipt described as provider truth | **Closed** by R-01 and R-17 before this review ran: complete binding required, and each adapter path declares its own assurance level |
| F-06 | High | Continuation does not prove boundary continuity | **Closed** by R-02 |
| F-07 | High | Unverified or unscored records advance ledger state | **Closed** by R-03, in its defect half; the transactional remedy is declined above |
| F-08 | High | Concurrent writers lose updates | **Closed** by R-04 |
| F-09 | High | Sparse signatures label an unsigned tail verified | **Closed** by R-05 |
| F-10 | High | Run ID omits trust configuration | **Closed** by R-06 |
| F-11 | High | Policy signature second-read race | **Closed** by R-07 |
| F-12 | High | Committed topology and tests conflict | **Closed** by R-08 for the topology. A clean-build record still does not exist |
| F-13 | High for claims | Synthetic, partly circular evaluation | **Accepted, not closed.** Same as R-09 |
| F-14 | Med-High | Arbitrary chain strings amplify output 12.14x | **Closed.** `chain` and `prev` must be SHA-256 digests. Measured 12.15x before, 0.17x after |
| F-15 | Med-High | Approval completeness and policy binding are weak | **Closed** by R-10 for completeness and by F-02 for timing. An in-band approval is still reported as a claim, not an authorisation fact |
| F-16 | Med | Coverage promises a local scanner that does not exist | **Closed.** The remedy now says why capturing `tool_result` is not enough. No scanner was added: a detector generating its own taint evidence would be grading its own work |
| F-17 | Med | Memory and signature budgets are miscalibrated | **Closed** by R-11 and R-12 |
| F-18 | Med | Clocks, grammar, clustering and labels distort evidence | **Closed** by R-13, R-14, R-15 and R-16 |
| F-19 | Med | Release is not locked, reproducible or attested | **Closed** by R-18 in its reproducibility half. Attestation and a signed release remain open |
| F-20 | Med | Exabeam proof absent, Observra baseline stale | **Accepted, not closed.** The positioning is corrected; the integration is not built |
| F-21 | Low-Med | Parser, schema, rule count and documents drift | **Closed** by R-20 |
| F-22 | Low-Med | Core trust modules are too large | **Declined**, same as R-21 and for the same reasons |

**Fourteen were already fixed and invisible. Six were real and are fixed here.
Two are accepted and cannot be closed by editing this repository.**

All eight probes are permanent regressions in `tests/test_review_probes.py`.
The condition they are held to is the reviewer's own: every probe fails closed
or returns an explicit non-evaluated state, and no producer-only record can
create a high-confidence contradiction.

### What the six had in common

Four of them were one mistake wearing four faces: **a producer-supplied value
was treated as a fact.** The digest an approval binds to, the moment an
approval was granted, the order events happened in, and whether a response was
complete — each was something the producer said, and each was believed.

F-01 is the one worth dwelling on, because it defeated this project's own
headline fix. R-01 established that an approval must bind completely to the
call. F-01 observed that the producer chooses the value being bound to. A
complete binding to an attacker-chosen digest is not a weaker guarantee than an
incomplete one; it is the same guarantee with a more convincing shape.

F-04 is worth dwelling on for a different reason. It is the objection this
project was founded on — a check that cannot fully run reporting itself as
clean — occurring inside the project, in a check whose entire output is an
absence claim, at full confidence, with the truncation recorded as a defect one
field away and ignored.

### The strategic finding, independently reached twice

Both reviews arrived at the same correction: do not pitch this as a behavioural
detector, because that layer ships. The second added that Uber's ADR now
supplies production sensing and two-tier detection as well.

[POSITIONING.md](POSITIONING.md) was written after the first review and before
the second arrived, and the second's recommended framing is close to
word-for-word what it already says. Two independent reviewers reaching one
conclusion is worth more than either statement of it.

## Verifying this document

**About the commit citations.** Each closed finding above links the commit that
closed it. Those commits were squash-merged into `main` as
[PR #11](https://github.com/404SecNotFound/Cohaera/pull/11), so they are not
ancestors of `main` and a plain `git log` will not show them. They remain
reachable two ways: GitHub keeps a pull request's commits permanently, so every
link above resolves regardless of what happens to any branch; and the branch
`claude/cohaera-third-security-review-oaa6dd` is deliberately left in place,
frozen at the pre-merge head, which is what lets a local clone check them.

That second route is the fragile one, and it is stated rather than relied on
silently. `tests/test_readme.py` checks the citations locally when the objects
are present and reports which route was unavailable when they are not — the
same contract every check in this repository is held to. It does not report a
missing object as a false citation, because "I could not look" and "it is not
there" are different answers.



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
