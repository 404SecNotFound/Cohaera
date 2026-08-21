<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Blueprint review: two strategy documents, and the plan that comes out of them

**The question this answers:** two external strategy documents arrived on
21 August 2026. What in them is true, what is already done, what conflicts,
what should be built, in what order — and what should deliberately not be built?

**Status: plan only. No code is authorised by this document.** Every phase
below ends in a decision point, and the phases are sequenced so that the
cheapest disconfirming evidence arrives first.

---

## 1. What the two documents are, and how they were checked

| Document | Position | Length |
|---|---|---|
| **Cohaera–Exabeam 10x Strategy** | Become the evidence-assurance sidecar *inside* Exabeam's stack | Executive decision, top 10 moves, 90-day sequence |
| **OKComputer Exabeam AI Gap Analysis** | Own the category Exabeam merely instrumented | Top 20 gaps in three tiers, six research dimensions |

**Method.** Claims that could be checked from source were checked from source,
at the commits the documents themselves cite. Claims that could not be checked
are marked. This follows the repository's standing rule: an unverified number is
already wrong.

### 1.1 Verified first-hand

Cloned `open-agent-ai-security/observra` at **`c4d036b`** — the exact commit the
strategy document cites — and read it.

| Claim | Verdict | Evidence |
|---|---|---|
| Observra publishes a stable `StorageBackend` protocol | **VERIFIED** | `src/observra/core/storage.py:16` — `class StorageBackend(Protocol)`, `runtime_checkable`, single `write(event)` method |
| `MultiBackend` supports fan-out without modifying Observra | **VERIFIED** | `src/observra/backends/multi.py` exists alongside jsonl, otel, otel_log, sqlite, webhook |
| Observra has no signing and no hash chaining | **VERIFIED** | The only cryptography in `src/` is `core/encryption.py` — Fernet at rest. That is **confidentiality, not integrity attestation**. No signature, no chain, no attestation key anywhere |
| Observra uses a deliberately lossy drop-oldest queue | **VERIFIED** | `core/queue.py::DropOldestQueue`, wired at `__init__.py:140` |
| Observra is Python-only with ~6 framework adapters | **VERIFIED** | `adapters/`: adk, claude, langchain, litellm, openai, pydantic_ai |
| Observra 1.1.1 released 2026-08-14 | **VERIFIED** | `CHANGELOG.md:15` |
| Star counts: Praxen 59, Observra 21, Socxen 2, Promptfall 6 | **VERIFIED** | GitHub API, 21 Aug 2026 |

**One material discovery neither document states precisely.** Observra already
exposes `drop_count` and an `observra_events_dropped_total` counter
(`observability.py:21`). **The loss is measurable at the source.** That is
exactly the input a coverage contract needs, and it makes "how much of this
session did we actually see" a computable number rather than an assumption. It
is the single most actionable integration hook found in this review.

### 1.2 Could NOT be verified from here

Recorded rather than assumed, because several proposed workstreams rest on them:

- **Observra issue #117, Socxen issues #87, #6, #3, #5.** The session's git proxy
  serves anonymous *git reads* of public repositories but not the GitHub issue
  API for unattached repositories. The issues are cited as justification for the
  approval-record and tool-integrity workstreams. **Read them before committing
  to Phase 3.**
- **Exabeam's 90 commercial detections.** Not public. The gap analysis says so
  itself. Every "Exabeam does not detect X" claim is inference from published
  taxonomy, not observation.
- **Agent Sensor internals.** Distributed as binaries. Integration feasibility is
  assumed, not demonstrated.
- **Socxen as a red-team corpus.** The strategy document proposes running "its
  red-team cases" through Cohaera. Socxen has 2 stars and 32 open issues; whether
  usable trace data exists there is **unconfirmed and is a hard dependency** of
  the flagship demonstration.

### 1.3 Already fixed before the documents landed

The strategy document lists six "immediate public credibility fixes". It was
written against `125c8c8`; **four of the six were merged in PR #34 and earlier**:

- README saying 22 evasions / 20 working — **fixed**, now derived (28 / 26)
- `EVASION.md` disagreeing with the README — **was already correct**
- "No external validation" — **fixed**, now states the StepShield result
- Test count — **stale in the document**, not in the repository

Remaining and real: `docs/EXABEAM-STACK.md` still reflects an older Observra
state and does not mention 1.1.1's parser compatibility fix, SQLite, custom-host
APIs, terminal viewer or LiteLLM support.

---

## 2. The decision that gates everything else

**The two documents recommend opposite strategies, and this is not a
reconcilable difference of emphasis.**

| | Strategy document | Gap analysis |
|---|---|---|
| Relationship to Exabeam | Complement. Feed ABA. Never compete | *"Own the category they merely instrumented"* |
| Schema | *"Do not build a new normalization standard"* | #20: build a vendor-neutral schema — *"the anti-CIM play"* |
| Detection content | Feed ABA with features, don't open high-severity cases | #6: build the *"Sigma for agents"*, community-governed |
| Enforcement | Out of scope — assurance only | #4: kernel enforcement plane; #16 agent SOAR; #19 DoW enforcement |
| Discovery | Consume Observra and Agent Sensor | #1: eBPF shadow-agent discovery, *"prerequisite for everything else"* |

Item 20 of the gap analysis and the "what not to build" section of the strategy
document are direct contradictions. **Both cannot be executed.** Choosing is a
prerequisite to writing any code, which is why this document exists before any.

### 2.1 Recommendation: adopt the strategy document's position, mine the gap analysis for scope

**Reasoning, stated plainly so it can be argued with:**

1. **Capacity.** The gap analysis describes a funded team's roadmap. eBPF
   discovery, a kernel enforcement plane, an identity substrate, an MCP gateway,
   a threat-intel feed and a governed schema body are each a product. This is one
   person. A plan that cannot be executed is not a plan.
2. **The competitive framing costs more than it buys.** "Own the category" makes
   Cohaera a competitor to the organisation whose attention is the actual goal.
   The sidecar framing makes it an asset to them. The technical work overlaps
   heavily; the positioning does not.
3. **The gap analysis's own evidence undercuts its conclusion.** It argues the
   window is open because Observra has 21 stars and staff-only commits. That same
   fact means there is no community to win *from* Exabeam — the gravity it wants
   to capture does not exist yet on either side.
4. **The strategy document is falsifiable and the gap analysis is not.** Its
   success criteria are concrete and checkable. "Own the category" cannot fail in
   any measurable way inside 90 days.

**However, the gap analysis is not to be discarded.** Its technical inventory is
the better of the two, and several items map directly onto Cohaera's existing
evasion catalogue. It should be mined for *scope inside the sidecar position*,
which section 4 does.

### 2.2 What the gap analysis got wrong about Cohaera

Worth stating because it is a positioning asset, not a defect:

- **#2, "tamper-evident, hash-chained, signed telemetry — nobody in the OSS space
  has this, first mover sets the standard."** Cohaera has had it for months.
  `cohaera.integrity:1` is a signed hash chain with verified-to boundaries, a
  trust store, key rotation and revocation. The gap analysis identifies the single
  highest-value unclaimed position in the market and does not notice that this
  repository already occupies it.
- **#13, "BAS-for-agents — no public efficacy benchmark exists; we become the
  benchmark."** `EVASION.md` is 28 constructed evasions, each with an executable
  test that passes *while the evasion works*, tiered by attacker capability. That
  is the harness, built and published.
- **#6, "open detection content."** 14 Sigma rules, tiered by measured evidence,
  conformance-tested in CI.

Three of the gap analysis's twenty items are already delivered here. That is the
headline the strategy document should be making and currently is not.

---

## 3. Verdicts

### 3.1 Strategy document — top 10 moves

| # | Move | Verdict |
|---|---|---|
| 1 | Finish the evidence-trust core (E24, E25, E26, CH07) | **ACCEPT.** CH07 done (#33). E24 half closed. E25/E26 are the remaining free evasions |
| 2 | Out-of-process assurance sidecar | **ACCEPT.** Highest-value architectural change on the list. A collector inside the agent's blast radius is the unmodelled attack in the threat model |
| 3 | First-class Observra integration | **ACCEPT.** Surface verified stable. Lowest-risk high-value work in the document |
| 4 | Agent Sensor integration | **ACCEPT WITH EVIDENCE GATE.** Binaries only; needs a feasibility spike before commitment |
| 5 | Praxen signed runtime manifest | **ACCEPT.** The natural-language-remit-to-signed-manifest boundary is exactly right, and the five runtime statuses are a better vocabulary than the current coverage states |
| 6 | Socxen as flagship integration | **ACCEPT POSITIONING, GATE THE CORPUS.** Digest-only evidence is a genuinely good test. "Run its red-team cases" is unverified |
| 7 | Define `cohaera.assurance:1` | **ACCEPT.** The one deliverable that makes everything else consumable |
| 8 | Cross-framework assurance lab | **ACCEPT, SCOPE DOWN.** The failure-condition list is excellent. The full source × backend × failure matrix is hundreds of cells |
| 9 | Split alerts from behavioural features | **ACCEPT — ALREADY ARGUED INTERNALLY.** Three independent role reviews reached this. It is `docs/REVIEWS-2026-08.md` finding #1 |
| 10 | Prove it in a live Exabeam workflow | **ACCEPT AS DESTINATION, NOT AS PHASE.** Requires a New-Scale instance, independent labellers and two external reviewers — none of which exist yet |

### 3.2 Gap analysis — top 20

**Accept, as scope inside the sidecar position:**

| # | Item | Why it fits |
|---|---|---|
| 5 | MCP tool-definition drift / rug-pull detection | **This is E25.** Already catalogued, already open, named identically |
| 8 | Memory-write-path monitoring | **This is E28.** Already catalogued |
| 9 | A2A and multi-agent collusion | **This is E29** (smuggled delegation turns), partially |
| 11 | Context-window exfiltration | Extends CH03's untrusted-to-consequential path with retrieval provenance |
| 15 | Runtime config-tamper detection | Evidence question, not enforcement. Fits |
| 17 | Forensic session replay and causal graphs | The lab already replays; this is presentation |
| 18 | Edge redaction, sampling, residency | Directly relevant — Socxen's privacy design already forces digest-only evidence |

**Reject, with reasons:**

| # | Item | Why not |
|---|---|---|
| 1 | eBPF shadow-agent discovery | Different product, kernel expertise, contradicts the sidecar position. The gap analysis calls it "a prerequisite for everything else"; it is a prerequisite for *its* strategy, not this one |
| 4 | Runtime enforcement plane | Cohaera's entire doctrine is about what evidence deserves belief. Enforcement is a different risk posture and a different liability |
| 16 | Agent-native SOAR | As above |
| 19 | DoW enforcement | As above. Detection of budget overrun is already CH04's shape |
| 20 | Vendor-neutral anti-CIM schema | Directly contradicts the accepted position. `cohaera.assurance:1` is additive to CIM, not a replacement for it |
| 3 | Identity / SPIFFE substrate | **Defer, not reject.** Valuable and large. Carry delegation chain as *fields* in the assurance event rather than building an identity subsystem |
| 12 | Threat-intel feed | Requires sustained curation capacity that does not exist |
| 14 | Archetype baselining | This is ABA's job. Building it is competing |

**Already delivered here:** #2 (tamper-evident telemetry), #6 (open detection
content), #13 (BAS harness). See section 2.2.

---

## 4. Phases

Sequenced so the cheapest disconfirming evidence arrives first. **Every phase
ends in a decision point.** A phase that fails its exit criterion stops the
sequence rather than proceeding on hope.

### Phase 0 — Resolve the strategic conflict *(no code)*

- [ ] Decide between the sidecar position and the category-ownership position
- [ ] If sidecar: record the decision and its reasoning in `POSITIONING.md`
- [ ] Read Observra #117 and Socxen #87, #6, #3, #5 and confirm they say what the
      strategy document claims
- [ ] Correct `docs/EXABEAM-STACK.md` for Observra 1.1.1

**Exit criterion:** the position is written down and the four issues are read.
**Blocks:** everything.

### Phase 1 — Close the free evasions *(code, small, well understood)*

- [ ] **E25** — bind approvals to tool ID, canonical tool-definition digest, tool
      server identity, argument digest, remit digest
- [ ] **E26** — approval ID, nonce, signed issuer, issue/expiry, exact call
      binding, one-time consumption, cross-session ledger
- [ ] **E24 remaining half** — per-event policy signature schema
      (`cohaera.policy_signature:1` attests a file, which is a different object)

**Exit criterion:** T0 open count drops; each closure has an executable test that
fails when the fix is reverted.
**Why first:** self-contained, no external dependency, and it is the work both
documents independently prioritise.

### Phase 2 — `cohaera.assurance:1` *(schema, no integration yet)*

- [ ] Define the assurance record — evidence status, signature coverage, session
      boundary confidence, drop count, policy digest, tool catalogue digest,
      approval assurance, effect assurance, evaluated/degraded/not-evaluated
      checks, session features
- [ ] Keep the four evidence states distinct; **do not collapse to one score**
- [ ] Keep evidence quality separate from risk, so poor evidence raises a
      monitoring-health condition rather than lowering a risk score and hiding an
      attack
- [ ] Version and conformance-test it

**Exit criterion:** a record emitted from the existing lab, with a schema test.
**Why here:** everything downstream consumes it. Defining it late means rework.

### Phase 3 — Observra integration *(code, verified surface)*

- [ ] `CohaeraBackend` implementing the verified `StorageBackend` protocol
- [ ] Sidecar reading Observra JSONL and SQLite
- [ ] **Consume `drop_count` / `observra_events_dropped_total` as coverage
      evidence** — the discovery from section 1.1
- [ ] Explicit handling for `session_end` and queue drops (issue #117)
- [ ] Pin compatibility to `observra:1.x`
- [ ] Behaviour when redaction removes arguments or results
- [ ] Behaviour when OTel export loses fields

**Exit criterion:** an Observra-instrumented agent produces a Cohaera assurance
record, and every path states which checks were evaluated, degraded or not
evaluated.

### Phase 4 — Out-of-process sidecar *(architecture)*

- [ ] Run outside the monitored agent process
- [ ] Keys, replay ledger and policy material outside the agent's write access
- [ ] In-process development backend must **declare** that collector and agent
      shared a blast radius

**Exit criterion:** a verdict that names its own trust boundary.
**Why after Phase 3:** the integration determines what "out of process" must mean
in practice.

### Phase 5 — Praxen runtime manifest *(schema + integration)*

- [ ] Signed runtime manifest: agent ID, remit ID and version, remit semantic
      digest, tool IDs and definition digests, allowed destinations, sensitive
      data classes, approval-required actions, enforcement modes, signer, validity
- [ ] Per-rule runtime status: `observed_conformant`, `observed_violation`,
      `not_observed`, `not_evaluated`, `evidence_untrusted`
- [ ] **Do not interpret natural-language remit prose in production**

**Exit criterion:** a remit compiles to a signed manifest and produces per-rule
runtime status.

### Phase 6 — Corpus with a content channel *(the gap nothing else covers)*

- [ ] Extend the internal corpus so `tool_result` carries real content — currently
      all 7,156 captured results are the literal string `ok` and the 216
      injection-marked records carry no result at all
- [ ] Re-measure CH03 with a content channel that exists
- [ ] Only then report a content-scanning number

**Exit criterion:** CH03's content path has a measured result rather than a
vacuous zero.
**Why this is here and not in either document:** neither found it. It was found
building E09's scan, and it means **CH03's content story is currently untested by
the evaluation that gates this repository's claims.**

### Phase 7 — Agent Sensor *(gated spike first)*

- [ ] **Spike:** can a binary-only distribution be ingested reliably? Timebox it
- [ ] If yes: ingest JSONL/webhook; treat source metrics, cursor state and drop
      counts as coverage evidence; detect duplicate, missing and fragmented
      session boundaries
- [ ] Record whether the signing key was genuinely outside the monitored process

**Exit criterion:** spike answers yes or no. **A no stops this phase and is a
valid outcome**, not a failure.

### Phase 8 — Cross-framework lab *(scoped down)*

- [ ] Pick **three** sources and **three** delivery paths, not the full matrix
- [ ] Run the failure conditions: queue overflow, exit before flush, missing
      session end, clock skew, duplicates, reordering, dropped terminals, redacted
      arguments, OTel field loss, handoffs, fragmentation, definition changes,
      approval replay, policy fabrication
- [ ] **Measure field survival and check evaluability before recall.** A zero-alert
      result means nothing when zero checks had the evidence to run — which is
      precisely what StepShield already demonstrated

**Exit criterion:** a published compatibility matrix with coverage per cell.

### Phase 9 — External evidence *(the thing that changes what can be claimed)*

- [ ] Independently authored, instrumented corpus with agent, tool-family, task and
      organisation holdouts
- [ ] Freeze the detector before adaptive testing
- [ ] Independent labels
- [ ] Publish misses and not-evaluated outcomes alongside hits

**Exit criterion:** one number about Cohaera that its author did not generate.

### Phase 10 — Live Exabeam workflow *(destination)*

Requires a New-Scale instance, independent labellers and external reviewers.
**Do not start until those exist.** The flagship demonstration — approval replay
plus tool-definition drift on an Exabeam alert closure — is the right shape and
is fully specified in the strategy document.

---

## 5. Cross-cutting, not phased

- [ ] **Require independent review** on trust, crypto and release changes.
      Repository setting; owner-only. Two P0 trust-kernel fixes merged with no
      recorded approval
- [ ] **Split the trust kernel** — `checks.py` and `evidence.py` are each over
      3,000 lines and still growing. A name collision during the last change
      demonstrated the hazard. Characterization tests first
- [ ] **Tier the checks** — CH01/CH02/CH03/CH05 as ABA features; CH04/CH06/CH07 as
      findings, and only where evidence is authenticated. Both documents and three
      role reviews agree

---

## 6. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Socxen has no usable red-team corpus | **High** — flagship demo depends on it | Verify in Phase 0, before Phase 6 planning |
| No Exabeam New-Scale access | **High** — Phase 10 blocked | Treat as destination, not commitment |
| Agent Sensor is binaries-only | Medium | Gated spike, Phase 7 |
| Observra 1.x schema breaks | Medium | Pin to major; compatibility tests |
| Single-maintainer capacity | **High** | Phases are ordered so value lands early and each stops cleanly |
| Doing both strategies at once | **Critical** | Phase 0 exists to prevent it |

---

## 7. What not to build

From the strategy document, endorsed without qualification: more generic
framework adapters, another terminal viewer or dashboard, generic prompt-injection
regexes, another delivery queue or webhook forwarder, another behavioural baseline
engine, a replacement for ABA, a new normalisation standard, large volumes of
synthetic detection content before live compatibility exists.

Added from this review: **no enforcement plane, no eBPF discovery, no identity
substrate, no threat-intel feed.** Each is a separate product, and each converts
Cohaera from an asset into a competitor.
