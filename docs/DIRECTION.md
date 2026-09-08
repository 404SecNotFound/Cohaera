<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Project direction: passive security monitoring for AI agents

This page is the decision record for what Cohaera should become. It turns the
“Zeek for AI agents” idea into an engineering boundary, a detection backlog,
and acceptance gates.

## Mission

Cohaera turns exported AI agent activity into security records that analysts
can search, correlate, test, and explain.

Its job is to preserve what happened, state how trustworthy and complete that
record is, derive security-relevant facts across a session or stream, and emit
detections that carry their own coverage limits.

## The boundary

Cohaera runs outside the agent's control path.

It may consume events from an SDK, collector, OpenTelemetry pipeline, gateway,
audit log, or provider receipt. It does not require the agent to call Cohaera
before acting. It never decides whether the action may proceed.

This boundary has operational consequences:

- an unavailable Cohaera instance cannot stop an agent workload;
- historical telemetry can be replayed through a newer detector;
- detections are reproducible against frozen input;
- the same content can run across different runtimes and control planes;
- enforcement remains the responsibility of a gateway, identity system,
  policy engine, or downstream response workflow.

## Why avoid the gateway category

The decision is based on product shape as well as engineering preference. As of
8 September 2026, major security vendors publicly describe agent products that
inspect or enforce actions inline: [Cisco AI Runtime Protection](https://www.cisco.com/site/us/en/products/security/ai-defense/ai-runtime/index.html),
[Check Point AI Agent Security](https://www.checkpoint.com/ai-security/ai-agent-security/),
and [Palo Alto Networks AI Gateway](https://www2.paloaltonetworks.com/ai-security/ai-gateway).

Competing for the control point would require integrations, latency budgets,
availability engineering, policy administration, and enterprise distribution
before Cohaera could prove its detection value. It would also bind the project
to a placement that many organisations will already buy from an incumbent.

Passive analysis is useful on either side of that buying decision. It can read
gateway events when a gateway exists and collector or audit events when one
does not.

## What the Zeek comparison means

The comparison is an operating model, not a claim of feature parity.

1. **Observe out of band.** Security analysis does not become a dependency of
   the system being observed.
2. **Create durable activity records.** Useful telemetry survives even when no
   packaged detection fires.
3. **Separate records from notices.** Facts and alerts have different schemas,
   retention, and tuning needs.
4. **Keep analysis deterministic.** The same input and configuration produce
   the same records.
5. **Make loss visible.** Missing fields, broken ordering, weak identity, and
   untrusted evidence are part of the result.
6. **Let detection engineers extend it.** New security content should not
   require rebuilding the telemetry source.

## Proposed record family

The current `cohaera_session_verdict` is a useful prototype but combines facts,
coverage, provenance, and findings in one large event. A stable 1.0 contract
should separate these concerns while retaining a common run and session key.

| Record | Purpose | Typical retention |
|---|---|---|
| `cohaera_session` | Session identity, actors, timing, cost, tools, handoffs | long |
| `cohaera_tool` | One paired tool action with arguments digest, result, effect, and classification | long |
| `cohaera_control` | Guardrail, approval, policy, and continuation facts | medium |
| `cohaera_evidence` | Chain, signature, receipt, freshness, replay, and fork results | long |
| `cohaera_coverage` | What each detector could evaluate and why | medium |
| `cohaera_notice` | A detection or integrity finding with evidence references | operational |

The migration needs a compatibility period in which the existing session
verdict can still be emitted. Schema work starts only after representative
queries are written against each proposed record; fields without a query or
detection use case should not enter 1.0.

## Detection areas to prioritise

### 1. Evidence suppression and contradiction

- missing starts, terminals, responses, or session endings;
- collector gaps, chain breaks, stale streams, replay, and stream forks;
- tool results that conflict with provider or host evidence;
- a producer claiming stronger scanner or policy coverage than the record
  supports.

This extends CH05–CH07 and builds on the strongest deterministic part of the
current implementation.

### 2. Identity, delegation, and authority

- which user, service, agent, sub-agent, and model acted;
- delegation depth and handoff chains;
- a delegated agent exceeding the parent's authority;
- shared human credentials used by multiple agents;
- identity or role changes inside one campaign.

### 3. Credential and secret use

- an agent reading credentials before an unrelated external action;
- secrets passed as tool arguments or returned in tool output;
- credential access from an unexpected agent or task family;
- a tool call using authority not declared in the capability manifest.

### 4. Data movement and exfiltration paths

- sensitive source read followed by egress;
- aggregation, encoding, staging, and delayed transfer;
- movement across tools or sessions rather than one obvious upload;
- destination, volume, novelty, and effect evidence suitable for a SIEM hunt.

### 5. Tool and MCP supply chain

- a new or changed tool, server, skill, or capability declaration;
- tool identity drift behind a stable display name;
- calls to undeclared tools or endpoints;
- capability expansion after deployment;
- mismatches between a tool declaration and observed effects.

### 6. Cross-session campaigns

- split read-and-act sequences;
- repeated low-severity anomalies by one agent, user, tool, or destination;
- approval or receipt reuse across sessions;
- first-seen relationships and changes over time;
- a chain of agents that collectively completes a prohibited sequence.

These areas need durable state and entity keys. They should follow the record
contract rather than being added as more fields to one batch verdict.

## Milestones and gates

### M0 — Reproducible foundation

**State:** implemented.

- bounded JSONL ingestion and quarantine;
- session assembly and CH01–CH07;
- evidence integrity, receipts, approvals, and ledgers;
- coverage contracts;
- executable local and CH06 labs;
- SIEM content and field conformance tests.

**Gate:** `python tools/verify.py` runs every CI-equivalent check, and the two
local labs reproduce their committed artifacts.

### M1 — Operator path

**State:** current work.

- concise root README;
- one operator guide from clone to an operator-supplied trace;
- a documented verdict triage workflow;
- a small architecture and code tour;
- an explicit passive-only product boundary.

**Gate:** a new operator can reproduce the lab, explain one finding and one
coverage gap, and score a new JSONL file without reading the research archive.

### M2 — Activity record 1.0

- write real hunts and correlations before finalising the fields;
- split activity, evidence, coverage, and notice records;
- publish JSON Schemas and versioning rules;
- retain compatibility with `cohaera_session_verdict` during migration;
- provide a tested Exabeam parser/export package.

**Gate:** every field is generated by a fixture, consumed by a test query or
rule, and documented with provenance and null semantics.

### M3 — Detection content expansion

- add the six priority areas above in thin vertical slices;
- map each detection to a concrete threat hypothesis and required telemetry;
- publish hunt queries alongside alerts;
- grade each rule on benign confounders and evasions;
- keep vendor content generated from one tested logical contract where
  possible.

**Gate:** a new detection ships with attack, benign, missing-evidence, and
evasion fixtures plus a measured false-positive result.

### M4 — Passive streaming and adapters

- incremental session state with watermarks and bounded eviction;
- OpenTelemetry and additional exported-telemetry adapters;
- append-only activity logs suitable for replay;
- no blocking or authorization API.

**Gate:** batch and streaming paths produce equivalent sealed records from the
same ordered stream, and declared late-arrival cases have deterministic results.

### M5 — External operational evidence

- collect independently generated agent traces with the fields the target
  detections require;
- test a live SIEM ingestion and investigation workflow;
- build the native Exabeam comparison for the same scenario;
- obtain a second reviewer for the detector, content, and claims;
- publish per-detection results rather than one aggregate headline.

**Gate:** a reviewer can reproduce the experiment from retained inputs and
explain where Cohaera adds information to the existing stack.

## Explicit non-goals

Cohaera will not become:

- an LLM, MCP, or agent gateway;
- a prompt firewall or content-safety filter;
- an agent runtime or orchestration framework;
- a policy decision point for tool authorization;
- a replacement for identity, EDR, DLP, SIEM, or behavioural analytics;
- another universal telemetry naming standard;
- a closed backend required to use the detection content.

Small helper tools may generate signatures, receipts, manifests, or test
fixtures. They support the evidence format and lab; they do not move Cohaera
into the execution path.

## Decision filter

Before adding a feature, ask:

1. Does it improve a security record, a detection, a hunt, evidence quality, or
   the ability to measure one of those?
2. Can it operate on exported telemetry without authorizing the agent action?
3. Does its output state missing inputs and uncertainty explicitly?
4. Can a detection engineer reproduce and test it with frozen evidence?
5. Does it remain useful across multiple runtimes or collectors?

A feature that fails the first two questions belongs in another project. A
feature that fails the next three needs a stronger design before implementation.

## Readiness for threat-research review

Before presenting Cohaera as more than a research prototype, the repository
should contain:

- a stable activity-record proposal backed by real hunts;
- one independently produced trace set with useful coverage;
- per-detection precision, recall, and benign-confounder results;
- one live SIEM workflow and a like-for-like Exabeam comparison;
- a second technical review with findings and responses recorded;
- an operator who can reproduce the labs, explain the trust boundary, and
  demonstrate both a detection and a deliberate `not_evaluated` result.

The last item is why [OPERATOR-GUIDE.md](OPERATOR-GUIDE.md) exists.
