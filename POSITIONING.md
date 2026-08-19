<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Where Cohaera sits, and where it does not

This file exists because an external review made a strategic point that was
more useful than any of its bug findings, and the honest response is to write
the correction down rather than quietly adjust the wording.

## The claim that stopped being true

The README opened — and in its narrative sections still opens — with a real
gap: [observra](https://github.com/open-agent-ai-security/observra) evaluates
one event at a time, its own maintainer records that zero correlation rules can
fire, and the signal that matters lives across events. All of that is still
accurate.

What was not accurate was the conclusion drawn from it: that Cohaera is
therefore *the missing behavioural layer* between agent telemetry and a SIEM.

It is not, because that layer now ships. Exabeam's
[Agent Behavior Analytics](https://www.exabeam.com/capabilities/agent-behavior-analytics/)
baselines expected agent behaviour, detects misuse and drift, flags abnormal
tool use and risky access, spots activity outside intended roles, covers MCP
activity, and correlates agents with users, entities, applications and security
events. Sequence context, first-time actions and entity history are exactly
what it is for.

Pitching session correlation as the missing piece to somebody who sells session
correlation is not a differentiator. It is a demonstration that the pitch was
written before the market was checked.

## What is actually differentiated

The gap that has not closed is one layer down. Behavioural analytics reasons
about what an agent did. Almost nothing reasons about whether the record saying
so deserves to be believed — and an agent's telemetry is written, in most
deployments, by an adapter running inside the agent's own process.

> **Agent behaviour analytics needs trustworthy agent identity, complete session
> boundaries, normalised tool semantics, and evidence-quality context. Cohaera
> supplies and tests those inputs.**

Or, in one sentence for a slide:

> Cohaera verifies how trustworthy an agent session is, normalises agent and
> MCP evidence into correlation-ready features, measures where detections fail
> under adversarial telemetry, and feeds those features into behavioural
> analytics.

## The layer table

| Layer | Whose job | What Cohaera contributes |
|---|---|---|
| Collection | observra, OTel collectors, agent sensors | Preserve original events and trusted source identity |
| Semantic normalisation | OTel GenAI, MCP, producer manifests | Canonical agent, session, tool, destination, policy and effect fields |
| **Evidence quality** | **Cohaera** | Chain continuity, key trust, freshness, exact binding, receipt and approval assurance, and explicit gaps where none of it is available |
| **Session feature extraction** | **Cohaera** | Explainable sequence, concealment, influence, guardrail, pairing and contradiction features |
| Long-horizon behaviour | Exabeam ABA and equivalents | Per-agent and peer baselines, first-time activity, drift, risk accumulation |
| Investigation and response | The SIEM | Timelines, cases, rules, risk, dashboards, playbooks |
| **Validation** | **Cohaera** + independent partners | Adversarial corpus, coverage contracts, a published failure catalogue, measured data quality |

The two bolded rows are the ones worth defending. Everything above and below
them is somebody else's product, and building a worse version of it would be
the most expensive way to be second.

## Why this is a stronger position and not a retreat

A behavioural layer competing with ABA has to beat it on baselines, entity
history and risk scoring, using less data and no deployment. It loses.

An evidence layer feeding ABA has properties ABA does not and structurally
cannot get from its own telemetry:

- **A signature over the collector's chain**, so "this record is the one the
  collector wrote" is a checkable statement rather than an assumption — and
  when the key is inside the agent's blast radius, coverage says so instead of
  letting the reader assume otherwise.
- **Exact call binding.** An approval that does not name the arguments cannot
  stop the same approval covering a different call. A receipt that does not
  name the call it belongs to identifies nothing.
- **Effect contradiction.** A provider-minted identifier can falsify a claimed
  failure. No amount of reading the agent's own account of itself can do that,
  because the account is the thing in question.
- **Replay and fork memory across runs**, which is the difference between
  evidence fed twice and evidence rewritten.
- **Coverage contracts.** A check that cannot run says so, with a reason code.
  A confidence number that silently degrades to a guess is worse than an
  absence.
- **A published failure catalogue.** [EVASION.md](EVASION.md) is a list of ways
  to defeat this, kept executable, kept current, and kept public.

None of that competes with a risk engine. All of it changes what a risk engine
should conclude.

## What to say, and what not to

Language is the cheapest place to overstate a result, so this is written down.

**Use**

- "deterministic synthetic regression result"
- "target-attributable recall on this corpus"
- "false positives per 1,000 benign synthetic sessions"
- "signature-verified prefix" / "complete signed checkpoint"
- "provider-returned identifier"
- "temporal association" (CH03 — coexistence is not causation)
- "incomplete observation" (CH05 — a missing terminal is a telemetry fact)
- "feature for behavioural risk" where a signal should not open a case alone

**Do not use**

- "validated detector"
- "production-ready evidence"
- "proof of causation"
- "provider-confirmed effect" — nothing here reconciles an identifier with the
  provider that minted it
- "approved", where the approval is an in-band event the agent could have
  written
- "verified session", where only a prefix is signed
- "the missing behavioural layer"

`tests/test_readme.py` fails on the second list appearing in tracked
documentation. A rule about language that nothing enforces is a preference.

## The honest state

Cohaera is a pre-alpha research artifact with a strong engineering core and no
external validation. On its own synthetic corpus the headline cell reaches full
target-attributable recall at a false-positive rate that would be unusable in
production, and [`eval/EVALUATION-CARD.md`](eval/EVALUATION-CARD.md) prints
both numbers side by side along with what precision would look like at a
realistic base rate. There is no live SIEM integration, no independent labels,
and no second reviewer.

Every one of those is a reason the position above is the right one to hold. An
evidence layer can be judged on whether its guarantees are real, one at a time,
by anyone who reads the tests. A behavioural layer can only be judged on
detection performance against traffic this project does not have.
