<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Three role reviews, and what happened to each finding

**Conducted 19 August 2026, against the tree at the time.**

[REVIEW-RESPONSE.md](../REVIEW-RESPONSE.md) records what happened to 43 findings
from two external security reviews. Those reviews read the code. This document
records something different: three reviews that read the *project*, each from a
role that would have to make a decision about it.

- A **chief product officer**, asked whether there is a product here.
- A **principal threat researcher**, asked to attack the threat model and the
  evasion catalogue rather than the code.
- A **principal detection engineer**, asked whether the content is fit to deploy
  in a SOC.

They were run independently. The interesting part is where they converged
without conferring.

---

## The three findings all three reviews reached separately

### 1. The package should be split

Per-check **target precision** — how often a check fires on the attacks it is
actually responsible for, rather than on some other check's attacks — is not
evenly distributed. It is bimodal.

| Check | own attacks | benign hits | target precision |
|---|---|---|---|
| CH04 guardrail overrun | 72 | **0** | 100% |
| CH06 evidence integrity | 56 | **0** | 100% |
| CH07 effect contradiction | 16 | **0** | 100% |
| CH01 sequence order | 72 | 60 | 35.3% |
| CH03 untrusted → consequential | 32 | 48 | 40.0% |
| CH02 concealment gap | 52 | 108 | 27.1% |
| CH05 unpaired calls | **0** | 48 | **0.0%** |

CH04, CH06 and CH07 produce **zero** false positives across every benign
confounder built specifically to break them — properly approved continuations,
re-approved retries, out-of-order stream delivery, and a key rotation with one
session straddling the handover. The entire 420.4 false positives per 1,000
benign sessions comes from the other four.

**One qualification, found while acting on this and not visible in the card's
section 4.** Reading `eval/evaluation-card.json` rather than the rendered table
shows CH06's zero holds only in the `manifest` cells. With no capability
manifest, where tool effects are guessed from names, CH06 records 24 benign hits
on the unseen/task-disjoint cell and 32 on the family-holdout ones. CH04 and
CH07 hold at zero across all eighteen cells. So the deployable set is two checks
unconditionally and a third conditional on `--tool-manifest` — which is the same
prerequisite the third converged finding is about, arriving from a different
direction.

That is not a better-tuned detector. It is a categorically different one: those
three are **deterministic verifiers**. No baseline to fit, no learning period,
no false-positive budget to negotiate. Shipping them fused with the behavioural
checks makes the headline number 420.4 and makes the whole thing undeployable,
when half of it is deployable today.

**Status: acted on.** The Sigma pack now carries an explicit deployment tier
bound by test to the measured per-check evidence — see
[content/README.md](../content/README.md).

### 2. CH05 should not ship as an alert

Zero target precision. `0 of 0` own labels — the corpus contains no attack it is
responsible for, so it has never demonstrated the behaviour it exists to detect.
48 benign hits. In detection-as-code terms it is an untested detection in
production content.

**Status: acted on.** Moved out of the alerting tier with the reasoning recorded
where a deploying engineer sees it before enabling it. Not deleted — the check
may be right and the corpus may simply be missing its attack, which is a
different problem and a fixable one.

### 3. The format is the business

Every check depends on evidence that no deployment currently emits. The
evaluation card already says this about one of them: `attack_omitted_call` is
caught *only* because the stream carries `cohaera.integrity:1`, and strip the
sidecars and those sessions are invisible again — "which is where every
deployment that has not adopted the format already is."

The three reviews put it three ways. The threat researcher: *the realistic
attack on Cohaera is to deploy it the way it ships.* The product officer:
*without adoption of the format, this is an essay.* The detection engineer: *the
capability manifest is a blocking install step, not an enhancement.*

**Status: partly acted on.** The dependency is now stated as a prerequisite
rather than a footnote, and [docs/RESEARCH-2026-08.md](RESEARCH-2026-08.md)
identifies three live standards venues where the formats could land. The
underlying problem — no adopters — is open and is the project's largest
strategic risk.

---

## Product review

**Framing: there is no product here yet. There are three assets in one box with
very different value.** The behavioural checks are research. The evidence-quality
checks are a product. The measurement discipline is the moat and is the least
directly monetisable of the three.

| Finding | Status |
|---|---|
| The strategy document already identifies evidence quality and validation as the defensible rows, but the *packaging* does not reflect it — README, evaluation card and Sigma pack all present seven checks as one detector | **Acted on** in the content pack; the README framing is a larger change and is open |
| This is closer to a data-quality product than a detection product. The buyer is the detection-engineering or security-data-platform team, not the SOC — and "we found problems in your telemetry" is the product working, not failing | **Recorded, not acted on.** A positioning change of this size should be a deliberate decision, not a side effect of a review |
| The `not_evaluated` reason code is a product primitive — an API contract a SIEM can surface to an analyst — and is currently treated as an implementation detail | **Open** |
| The release gate that fails CI when published numbers drift from measured ones is a trust mechanism worth naming explicitly, in a market where every competitor claims high accuracy and none shows a denominator | **Open** |
| The unexecuted five-phase VMware lab plan, shipped alongside working code, makes a reader discount the working code | **Acted on** — see [LAB.md](../LAB.md), which now separates what has been run from what has not |
| Success metric for the next year is not recall or false-positive rate. It is how many collectors emit the sidecar, and how many corpora the detector has run against that its author did not write | **Recorded** |
| Escalated risk: four rounds of real defects were fixed and the evaluation card did not move. The eval is a gate on *claims*, not on *correctness* | **Open, and worth stating in the card itself.** It protects against publishing something false; it is not release QA, and nothing currently distinguishes the two |

---

## Threat research review

**Framing: the catalogue is better than most commercial products publish, and it
was measuring the wrong surface. All 22 entries attacked a *check*. The expected
adversary attacks the *deployment*.**

| Finding | Status |
|---|---|
| Six entries are free, need no access, and still work — between them defeating four of seven checks. The `Cost` column carries this and is unsorted, so it is invisible | **Acted on** — the table is now tiered by adversary capability and the free-tier count is stated in the file's opening |
| The capability manifest is the highest-leverage object in the system (recall 100% with it, 34.7% without) and manifest poisoning is **not in the catalogue**. Change control is documented as an assumption and treated as a control | **Acted on** in [docs/THREAT-MODEL.md](THREAT-MODEL.md) as a named unmodelled attack; the evasion entry and its test remain open |
| `$COHAERA_CORRELATION_SECRET` is named as a risk and never tested as one. Unset, session keys are enumerable from the SIEM-side copy — a de-anonymisation issue and potentially a session-splicing primitive | **Acted on** in the threat model; untested, and named as such |
| E21 is marked `CLOSED` and E13 `half_closed`, both conditional on a *signed* stream — while the evaluation card describes chained-but-unsigned as the realistic first-adoption state. Technically accurate, operationally misleading | **Acted on** — preconditions are now explicit |
| There is no patient adversary anywhere in the model. All corpus attacks are within-session, and the harness scores one run, so cross-session attacks are not merely unmeasured but unmeasurable | **Acted on** as a reclassification to primary known-unmitigated risk. The measurement gap is open and is the hardest item on the list |
| Six evasion classes published in the window are absent from the catalogue | **Acted on** — E24 through E29 |
| Findings carry producer-influenced strings into evidence and ship them to a SIEM increasingly triaged by a language model. Boundary B4 treated this as a rendering concern | **Acted on, and the finding was corrected in the process.** The review asserted that tool *arguments and results* are copied into evidence. They are not: only `arg_digest` and a status word travel, and `Reject` carries a digest rather than the record. What does travel is identifiers, identity strings, marker labels, the tool sequence and handoff chains — enough to matter, and less than was claimed. `sanitise_display` is a terminal control and is applied at two points on the record path, not to session features |

**What the review rated as genuinely strong**, recorded because a review that
only criticises is not calibrated: tests that pass when the evasion succeeds;
the working-evasion count going *up* on discovery and being published as the
worse-looking number; and remedy entries recorded as exercised, including two
labelled unplanned wins — distinguishing a designed defence from a lucky one.

---

## Detection engineering review

**Framing: not fit to deploy as shipped — but three of the seven rules are fit
to deploy today, and the pack did not distinguish them.**

| Finding | Status |
|---|---|
| Triage burden at a realistic base rate is a decommission-on-sight number, and it is entirely attributable to four rules | **Acted on** via tiering |
| CH02 is blind by default and noisy when enabled: `capture_tool_data` defaults off and string values are stripped on the hot path, so an operator must degrade their privacy posture to turn on a check that then returns 27.1% precision | **Acted on** — hunt tier, with the trade stated in the rule itself |
| The Sigma pack is a **routing layer, not analytics**. Every rule matches on `data.triggered_rules`; the detection happens in Python. Consequence a deploying engineer must be told: the pack cannot be backtested against historical logs, because the log source does not exist until Cohaera has run | **Acted on** in `content/README.md` |
| No operator tuning path exists. Thresholds and suppressions require editing Python, which in practice means the pack will be disabled rather than tuned | **Open.** The plumbing exists — `trust_config_digest` already binds configuration into verdict identity, so exposing thresholds as config would give both tuning *and* a tamper-evident record of what was tuned |
| Rules carry an author but no owner and no review cadence | **Acted on** |
| Coverage and correlation confidence per session amounts to an automated telemetry gap assessment — the exercise most programmes do annually in a spreadsheet — and is undersold | **Recorded** |
| Omitted ATT&CK tags are correctly reasoned but mean the pack lands in a SIEM with no technique coverage and will not appear in any coverage dashboard. A real cost, honestly incurred | **Open** |

**The three things the reviewer said they would take back to their own
programme**, recorded because they are the most useful signal in the review:
target-attributable versus any-alert recall as separate columns; `not_evaluated`
with a machine-readable reason code; and an evaluation card that regenerates in
CI with the build failing on any diff.

---

## What none of the three reviews could assess

- Whether any of it works outside the synthetic corpus. All three said so
  independently, and it remains the project's largest open item — see
  [docs/EXTERNAL-VALIDATION.md](EXTERNAL-VALIDATION.md).
- Whether the checks are *correct*, as opposed to well-measured. The reviews
  read the evaluation card and the documentation; four rounds of external code
  review are the record on correctness.
- Anything about operational cost at real volume. No deployment exists.
