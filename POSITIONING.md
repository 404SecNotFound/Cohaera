<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Where Cohaera sits, and where it does not

This file exists because an external review made a strategic point that was
more useful than any of its bug findings, and the honest response is to write
the correction down rather than quietly adjust the wording.
[REVIEW-RESPONSE.md](REVIEW-RESPONSE.md) records what happened to the other
twenty findings.

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
about what an agent did; something else has to reason about whether the record
saying so deserves to be believed, and an agent's telemetry is written, in most
deployments, by an adapter running inside the agent's own process.

### The second claim that stopped being true

This section used to say that *almost nothing* reasons about whether the record
deserves to be believed. That was true when it was written. It is not true now,
and the correction goes here rather than into a quiet rewording, for the same
reason the first one did.

| Project | What it already does | Read? |
|---|---|---|
| [Agent Action Capsule](https://github.com/action-state-group/agent-action-capsule) | An individual IETF SCITT-track draft: content-addressed record ids, parent chaining, COSE_Sign1, an effect that may only be called `confirmed` if it carries a digest over the observed response, and a human-in-the-loop flag true only when a human actually acted. Two of its registries **grade** evidence outright — `effect_attestation` puts `gate_executed` above `runtime_claimed`, and `provenance` ranks `gate` > `runtime` > `collector` | **Read** |
| [halo-record](https://github.com/bkuan001/halo-record) | Apache-2.0, hash-chained tamper-evident runtime records for AI agents, single maintainer. Its verification status `unverified` is documented as "made no determination — distinct from an absent block" | **Read** |
| [MCP SEP-3140](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3140) | A JWS-signed capability manifest bound to a publisher identity, with a signature-covered trust block carrying effect, egress, data sensitivity and reversibility | **Read** |
| *Auditable Agents*, arXiv:2604.05485 | Reported to name **evidence integrity** as one of five dimensions of agent auditability, next to action recoverability, lifecycle coverage, policy checkability and responsibility attribution | Snippet only |
| *From Agent Traces to Trust*, arXiv:2606.04990 | Reported survey formalising execution provenance and evidence tracing | Snippet only |

The last two rows are not verified against their full texts — arxiv.org is not
reachable from the environment this search ran in — and a citation nobody read
is marked as one rather than dressed up.

The honest replacement for "nobody does this" is narrower and survives contact
with that list:

> **Several projects now produce agent records that are worth believing. Few
> grade records they did not produce, and none reports what it could not
> evaluate.**

Producing a trustworthy record and grading somebody else's are different jobs.
Agent Action Capsule and halo-record are producers: the checkability is a
property of the format, and it is unavailable to any deployment that has not
adopted the format. Cohaera is a consumer — it reads whatever a deployment
already emits, including streams carrying no integrity evidence at all, which is
where every deployment starts. [docs/PRIOR-ART.md](docs/PRIOR-ART.md) is the
full search, including the several places where this project comes second.

> **Agent behaviour analytics needs trustworthy agent identity, complete session
> boundaries, normalised tool semantics, and evidence-quality context. Cohaera
> tests all four, and supplies the last one.**

Or, in one sentence for a slide:

> Cohaera verifies how trustworthy an agent session is, extracts
> correlation-ready features from agent and MCP evidence, measures where
> detections fail under adversarial telemetry, and feeds those features into
> behavioural analytics.

## The layer table

| Layer | Whose job | What Cohaera contributes |
|---|---|---|
| Collection | observra, OTel collectors, agent sensors | Preserve original events and trusted source identity |
| Semantic normalisation | OTel GenAI agent spans, MCP conventions, observra, SIEM-side agent tables | Consumes it. This row used to claim canonical fields of its own; see below |
| **Evidence quality** | **Cohaera** | Chain continuity, key trust, freshness, exact binding, receipt and approval assurance, and explicit gaps where none of it is available |
| **Session feature extraction** | **Cohaera** | Explainable sequence, concealment, influence, guardrail, pairing and contradiction features |
| Long-horizon behaviour | Exabeam ABA and equivalents | Per-agent and peer baselines, first-time activity, drift, risk accumulation |
| Investigation and response | The SIEM | Timelines, cases, rules, risk, dashboards, playbooks |
| **Validation** | **Cohaera** + independent partners | Adversarial corpus, coverage contracts, a published failure catalogue, measured data quality |

The two bolded rows are the ones worth defending. Everything above and below
them is somebody else's product, and building a worse version of it would be
the most expensive way to be second.

The normalisation row is the one that moved. It used to claim Cohaera
contributes "canonical agent, session, tool, destination, policy and effect
fields", and that is a fight against three efforts that are already shipping:
OpenTelemetry's GenAI semantic conventions model the agent span tree and carry
MCP conventions alongside it (status *Development*, not stable, and in use),
Exabeam ships observra, and at least one SIEM vendor is landing agent-shaped
tables of its own. Cohaera consumes normalisation and adds fields on top of it.
It does not supply the canonical layer, and the two bolded rows never needed it
to.

One note on that last item, because the temptation is to overstate it: a
Microsoft Sentinel `AIAgentsInfo` table shape is in the public Azure-Sentinel
repository's query-validation fixtures, which is what was actually verified. An
ASIM `AI Agent Events` normalisation schema was reported and could not be found
in that repository, so it is not claimed here.

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
  absence. This one is a **port, not an invention** — MITRE OVAL has had `not
  evaluated` as a distinct result value since the 5.x schema, XCCDF has four
  ways of having no verdict, and a Nagios plugin has exited `UNKNOWN` since
  before any of this. [docs/PRIOR-ART.md](docs/PRIOR-ART.md) §1 is the list,
  and the narrow part that is not a port is §8.
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
