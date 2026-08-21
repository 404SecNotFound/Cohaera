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
  has this, first mover sets the standard."** ~~Cohaera has had it for months and
  the gap analysis does not notice.~~ **Corrected 22 August 2026 by commissioned
  research: the position is NOT unclaimed.** `obsvr-dev/obsvr-sdk` documents an
  HMAC-SHA256 chain over `session`, `seq_no`, `prev_sig` and content, a
  `obsvr-verify` CLI, optional server countersignature, and a daily Ed25519-signed
  Merkle root anchored off-host. Cohaera's `cohaera.integrity:1` is real and is
  not first. Do not make the first-mover claim.

  Note the name collision: `obsvr-sdk` is **not** Exabeam's Observra. They must
  not be merged without a source citation, and the research explicitly flags this.

  One thing obsvr-sdk has that Cohaera does not, and it is the better design:
  **signed gap markers.** When its queue overflows or ingest rejects a record, it
  emits a signed marker saying so, rather than leaving the consumer to infer loss
  from a sequence hole. Cohaera should adopt this. Observra has no equivalent —
  verified by grep against `c4d036b`.
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

## 3.3 What the commissioned research returned (22 August 2026)

A research brief was issued against the open questions in §1.2. Results below,
split by whether they **confirm**, **disprove** or **complicate** the plan. Two
entries disprove claims made earlier in this document.

### Disproved — stop making these claims

| Claim | Status |
|---|---|
| "Nobody in OSS ships tamper-evident agent telemetry" | **FALSE.** `obsvr-dev/obsvr-sdk` does, with signed gap markers and off-host Merkle anchoring. Still true of *Observra* and *Agent Sensor* as published |
| "Corpus blindness is probably common — a publishable methodology finding" | **LARGELY FALSE, and it inverts.** InjecAgent (1,054 cases) and AgentDojo carry naturalistic tool output with injections spliced in; they were *built* to avoid exactly this. **Cohaera's corpus is the outlier, not the norm.** Not a contribution — a defect the field already solved |
| The EU AI Act sets an evidentiary bar for agent logs | **OVERSTATED.** GPAI Articles 53 and 55 require technical documentation, downstream information, a copyright policy, a training-data summary, and serious-incident reporting "without undue delay". They do **not** require automatic event logs, retention periods, or per-action attributability. Those are **high-risk system** duties (Arts. 12, 19, 26). The six-month and ten-year figures in circulation come from the Code of Practice and commentary, not the Regulation |

### Confirmed — these hold

- **The LogRhythm gap is real.** No public LogRhythm SIEM parser, KB module or AIE
  rule exists for Agent Sensor, Observra or agent-security detection. Agent content
  is New-Scale only. *Caveat: the LogRhythm KB is customer-gated, so absence from
  public documentation is not proof none shipped privately.* Integration point
  identified: LogRhythm Intelligence AIE 1603/1604 correlate Exabeam Cases via Open
  Collector.
- **No peer grades evidence quality per detection.** Closest three are NIST OSCAL
  assessment results, SCAP result states, and SIEM log-source health. None answers
  "could *this* detection run on the evidence that arrived".
- **Agent Sensor is binary-only**, with `~/.agent-sensor/events.jsonl`, a webhook
  sink with bearer auth, a `dlq.jsonl`, cursor inspection and Prometheus metrics.

### Complicates — plan changes required

- **Socxen is NOT a usable external corpus.** Its `security/redteam/attacks/`
  holds **19 `*.attack.json` recipes** — input payloads plus `must_not` assertions
  — and dated markdown trial reports. **There is no published bundle of recorded
  tool-level traces.** The risk flagged in §6 is now confirmed, and the flagship
  demonstration's corpus dependency fails as specified.
- **Observra #117 is an RFE, not a proven bug.** It requests a public
  `shutdown()`/`flush()` so the worker can be drained without touching the private
  `observra._worker._shutdown()`. It does **not** report measured event loss. One
  maintainer comment, no patch. "Events are lost at exit" is a reasonable inference
  from the design and must not be cited as a demonstrated defect.
- **Socxen #6's poisoned tool descriptions are Exabeam's own metadata**, not
  Socxen-authored. Socxen can pin and inventory them; it cannot rewrite them. That
  changes who the remedy is addressed to.
- **Socxen #5 and #87 contradict each other** on whether a structured action log
  exists. #5 (July) says none; #87 (August) cites `plugin/docs/logging.md`. Both
  are open. Resolve before building on either.
- **Agent Sensor exposes no drop-count field to a consumer.** Metrics are a
  Prometheus endpoint; cursor state is a local debug CLI. Neither rides on the
  forwarded event.
- **Observra's `drop_count` is a process-local API, not a stream field.**
  `get_metrics()` returns `drop_count`, `queue_depth`, write latency percentiles and
  backend write success/failure — but a sidecar reading JSONL receives none of it.
  The coverage hook is real and requires the **producer** to emit it. This is a
  correction to §1.1, which implied a consumer could simply read it.
- **Unresolved conflict:** Agent Sensor is described both as emitting the Observra
  schema and as normalising to Exabeam CIM, with no published mapping. A consumer
  cannot treat the two as identical.

### Prior art to cite rather than rediscover

**SCAP result states are the closest existing precedent for `not_evaluated`** —
`pass`, `fail`, `error`, `notchecked`, `notapplicable`, `informational`. `notchecked`
has meant "the probe could not run" in deployed compliance tooling for two decades.
This *strengthens* the position rather than threatening it: the primitive is proven,
and nobody has carried it into agent security. Cite it in `POSITIONING.md` and the
prior-work section.

---

## 3.4 Second brief, first-hand checks, and where the two disagree

A second, more thorough brief arrived the same day. It **corrects the first in
four places and corrects this document in three.** Where the two disagreed on a
countable fact, the fact was counted here rather than arbitrated.

### Counted first-hand, because both briefs got it wrong

Cloned `open-agent-ai-security/socxen` at **`d5b8625`**:

| | Brief 1 | Brief 2 | **Counted** |
|---|---|---|---|
| Attack fixtures | 19 | 21 | **20** |
| Replayable trace files (`.jsonl`) | "none found" | "NOT FOUND" | **0 — confirmed** |
| Grading result documents | "dated markdown" | 15 | **15** |

Both briefs enumerated the identical ranges — `a01–a11`, `b01–b04`, `c01–c02`,
`d01–d03` — which sum to 20, and then both miscounted their own list in opposite
directions. **Two independent research efforts, one countable number, two wrong
answers, one shell command to settle it.** That is precisely the defect class
`tools/readme_facts.py` exists for, arriving from outside the repository.

**Socxen is settled.** `security/redteam/attacks/*.attack.json` carry
`id`, `attack_class`, `technique`, `backend`, `input.payload` and
`expected.must_not`. No `event_type`, no `tool_start`, no recorded tool call
anywhere in the repository. It is a **behavioural test corpus for Socxen the
agent**, and it is genuinely that — not a telemetry corpus a third party can
replay through a detector. Both readings in the briefs are defensible; only one
is useful to us, and it is the pessimistic one.

### Where brief 2 corrects brief 1 — and this document

**Tamper-evidence: the disproof is broader, but a narrowed claim survives and is
worth more than the original.**

Brief 1 found `obsvr-dev/obsvr-sdk`. Brief 2 found five *different* projects and
did not find obsvr-sdk: OpenFang (Merkle chain, Ed25519-signed agent manifests),
MerchantGuard AgentGuard CB (Ed25519-signed chain **plus** offline-verifiable
evidence-pack export), Phionyx Core (signed hash-chained evidence receipts),
`maco144/merkle-audit`, and `Ascendral/codebot-ai`. **No overlap between the two
briefs' counterexamples**, which is itself the finding: the space is fragmented,
nothing is canonical, and no search finds all of it.

The claim that survives, and it should replace the first-mover language
everywhere:

> No mainstream observability platform ships event integrity — OTel GenAI
> conventions, Langfuse, Arize Phoenix, OpenLLMetry, Helicone, AgentOps and
> LangSmith all lack chaining, signing and attestation. And **no single project
> combines signed hash-chained events, per-agent attestation keys, and evidence
> export.**

That is narrower, defensible, and checkable. It is also a roadmap: the
combination is the unclaimed position, not any one component.

**Prior art: the closest analogue is DeTT&CT, not SCAP or OSCAL.**

Brief 1 offered OSCAL, SCAP result states and SIEM log-source health. Brief 2
offers three much closer:

- **DeTT&CT** (Rabobank-CDC) scores data-source quality 1–5 on device
  completeness, field completeness, timeliness, consistency and retention, and
  visibility 0–4, against ATT&CK techniques. *Differs:* manual analyst-entered
  YAML; the unit graded is the technique or data source, not a verdict; it
  measures posture, not per-evaluation sufficiency.
- **MITRE CTID "Summiting the Pyramid" v4** — telemetry-confidence scores for
  log-source-to-technique fit, with machine-readable `stp.*` Sigma tags.
  *Differs:* an authoring-time judgement that assumes the telemetry exists.
- **CardinalOps Detection Posture Management** — audits SIEM rules for missing
  fields and stale sources. *Differs:* binary broken/working, proprietary.

**Cite DeTT&CT rather than SCAP.** SCAP's `notchecked` remains a fair precedent
for the *vocabulary*, but DeTT&CT is the closest thing to the *idea* and a
reader who knows the field will raise it. Brief 2 also surfaces a 2025
Theseus.fi thesis ("Detection Surface Index") concluding that **no unified model
chains coverage → degradation → weighting into one score** — independent
evidence that the gap is recognised and unfilled.

**EU AI Act: the high-risk dates moved, and brief 1 flagged this as disputed.**

Regulation (EU) **2026/1744** ("Digital Omnibus on AI", OJ 24 July 2026, in force
27 July 2026) amends Article 113: Chapter III Sections 1–3 apply from
**2 December 2027** (Annex III) and **2 August 2028** (Annex I). Brief 1 treated
the Omnibus as provisional commentary and said to await a published amending act;
brief 2 reports it verified from EUR-Lex as enacted. **Chapter V (GPAI) is
unchanged and applicable since 2 August 2025.**

Both briefs agree on the only part that matters here: **no GPAI provision
mentions agents, tool calls, or runtime behavioural logging.** Article 54(3)(b)'s
ten years is the sole hard Chapter V retention period and it attaches to
*documentation*. Article 12's logging duty is high-risk-only and now not
applicable until December 2027 at the earliest. Do not build a compliance
argument on it.

**Corpus blindness: there IS a published analogue, and it is by design.**

Brief 2 read raw files across nine corpora. InjecAgent, AgentDojo, AgentHarm,
BIPIA, LLMail-Inject (461,640 submissions), Lakera PINT and WASP all carry real
content. But **Agent Security Bench (ICLR 2025) does not**: its tool corpus is
spec-only, its "Expected Achievements" are canned strings, and success is a
substring match against simulated output — verified from raw
`all_normal_tools.jsonl`.

So the position is: content-vacuous labelled records are **the exception**, this
repository's corpus is still the outlier, and the honest framing is neither
"novel finding" (§3.3 was right to kill that) nor "unique defect". One published
benchmark shares the structural property deliberately. ToolEmu's runtime
synthesis carries related placeholder fragility.

**LogRhythm: confirmed far more strongly than before.**

Brief 2 read LogRhythm SIEM release notes 7.20–7.24 (April 2025 – April 2026).
Post-merger AI work is AI Engine performance fixes, an AIE Admin API, and
parsers for Salesforce, Tenable, O365, Box, Defender, Mimecast, Keeper and
Trend. **No OpenAI, Copilot, Gemini, Claude or MCP parser exists.** The
`LRI`-prefixed AIE rules are **relays** — they alarm on New-Scale detections
ingested via the Exabeam Case Beat, not native detection content. LogRhythm
Intelligence (795 models, 1,800 rules) targets human users and hosts and runs on
New-Scale Fusion, so it is hybrid rather than self-hosted.

Every agentic release — January 2026 ABA and MCP, April 2026 ChatGPT/Copilot/
Gemini expansion, July 2026's fifty new detections and the Observra/Praxen
open-sourcing — is New-Scale only. **The gap is real and it is wide.** The
standing caveat holds: the LogRhythm KB is customer-gated, so a private module
cannot be excluded.

### Still unresolved after both briefs

- **Agent Sensor's schema is "referenced open, not published."** Both briefs
  looked; neither retrieved a schema artifact or a full field list. Brief 2 adds
  that the DLQ with `replay-dlq` means failed deliveries are *recoverable rather
  than silently dropped*, which weakens the loss argument for that path.
- **Socxen #5 versus #87** on whether a structured action log now exists. Brief 2
  did not resolve it either.
- **Whether obsvr-sdk and the five brief-2 projects overlap in approach**, and
  how any of them compares to `cohaera.integrity:1` on the specifics.

---

## 3.5 Third brief — and the workstream it deflates

A third brief, the most careful of the three. It corrects the first two on four
points, and its most important claim was checkable against a repository already
cloned here.

### Verified first-hand: Observra #117 does not say what any of us said it said

Brief 3 claims Observra **already registers an atexit handler**. Checked against
`open-agent-ai-security/observra` at `c4d036b`:

| | |
|---|---|
| `core/worker.py:106` | `atexit.register(self._shutdown)` |
| `core/worker.py:251` | a **public** `shutdown()` delegating to `_shutdown()`, "so external callers don't reach into private internals" |
| `core/worker.py:259+` | the handler sends a shutdown sentinel, joins the worker thread with a **5-second timeout**, then flushes and closes storage |
| `__init__.py` | no top-level `shutdown` / `flush` export |

**Brief 3 is right and the other two are wrong.** What #117 asks for is an
*exported top-level function*, so a custom host does not have to call
`observra._worker._shutdown()`. It is an ergonomics and API-stability request.
The drain already happens on ordinary interpreter exit.

**Consequence for the plan.** "Final audit events are lost at exit" was cited as
justification for a workstream. The real residual risk is narrower: abrupt
termination that bypasses `atexit` (SIGKILL, hard crash), and a worker thread
that fails to finish inside the five-second join — which logs a warning rather
than dropping silently. That is worth handling in Phase 3, and it is **not** the
open wound the summaries implied.

This is the second time a one-line issue summary has survived two research
passes and failed on contact with the source.

### Also verified first-hand: the schema conflict is real

Observra's canonical field is `timestamp: float` (`core/events.py:206`, validated
positive). Agent Sensor's public examples query **`ts`**. Agent Sensor's landing
page says it emits "the same open schema defined by the Observra Open Source
Library."

**Those cannot all be true.** Either the Sensor documentation is wrong or the
event model differs. Since Agent Sensor is closed-source and publishes no binding
schema, **a consumer cannot assume Observra-envelope compatibility.** Phase 7's
spike must establish this before any ingestion code is written.

### The fixture count, now three-way

| | Count |
|---|---|
| Brief 1 | 19 |
| Brief 2 | 21 |
| Brief 3 | 19 |
| **Counted here at `d5b8625`** | **20** |

`a01–a11` (11) + `b01–b04` (4) + `c01–c02` (2) + `d01–d03` (3) = 20. All three
briefs enumerated those exact ranges. **Three independent research efforts, one
`ls | wc -l`, three wrong answers.**

### Where brief 3 corrects briefs 1 and 2 on the issues

- **Socxen #3's deny-list was materially fixed.** Both earlier briefs reported a
  17-tool snippet-only list requiring hand-sync. The 2026-08-13 comment reports
  expansion to **68 rule spellings and namespaces with CI invariant tests** for
  missing or extra entries. The thread also carries a **correction to its own
  body**: an active Claude Code permission configuration *is* a hard,
  harness-enforced gate. The surviving weakness is narrower — the configuration
  is opt-in, and `--dangerously-skip-permissions` disables it.
- **Socxen #5 is stale as summarised, and the §3.3 contradiction resolves.**
  Since v0.6.0 the bridge writes rotating JSONL by default and records every
  bridged call with identifiers, dispositions, timing and guardrail firings. It
  is #87 that is current and #5 whose one-line summary is out of date. Remaining
  gaps: approval state, verdict and confidence, **fail-open logging**, verified
  terminal report creation, and the manual-MCP path.
- **Socxen #6 is partially fixed.** Twenty tools are internally documented and
  tested for name and count drift; `list_tools()` remains a pass-through and
  there is still no live description digest or diff.

### One finding that lands close to home

Brief 3 reports that Socxen's **saved evaluation records carry tool-call names
and arguments but not the corresponding tool-result bodies**, and that a
2026-08-19 residual report states exact per-trial detail could not be recovered
from earlier dated reports.

That is this repository's own corpus pathology, in somebody else's artifacts,
and it sharpens the framing again. Brief 3's version is the best of the three:

> The pathology is not representative of the *benchmarks* — AgentDojo,
> InjecAgent and SCAM all carry real content. It is representative of a
> **result-level** problem: labels and aggregate outcomes survive the export
> while the observation content needed to test a detector does not.

**MCPSecBench** is the clearest published case: `data.json` carries attack name,
prompt and evaluator instruction, but not the tool output supposedly containing
the indirect injection. So the honest statement is not "we are the outlier" and
not "everyone does this" — it is that **executable benchmarks tend to be fine and
their published exports frequently are not.**

Brief 3 also correctly notes it could not verify the 7,156 figure, because that
is our own unpublished measurement.

### Tamper-evidence: three more, still no overlap, and the narrowed claim holds

Brief 3 found **Tamra Agent Ledger**, **Microsoft's Agent Governance Toolkit**
and **Gate OC Audit** — none of which appeared in briefs 1 or 2. Across three
briefs the counterexample lists are **pairwise disjoint**, which by now is the
finding rather than an anecdote.

Two matter:

- **Tamra** is the strongest yet: gap-free SHA-256 chain over LLM, tool,
  retrieval, approval and session events; Ed25519-signed **checkpoints**; a
  `.tamrapatra` evidence bundle with offline verification; published on Maven
  Central. Limits: checkpoints are signed rather than individual events, and the
  key is ledger- or operator-scoped rather than per-agent.
- **Microsoft's toolkit** is the only one reported to create a **distinct Ed25519
  key pair per agent**. But Microsoft's own SOC 2 self-assessment says **three of
  its four audit-chain implementations have integrity defects** and recommends
  relying only on `MerkleAuditChain`, and the example is labelled
  learning/prototyping rather than a production contract.

**Brief 3 reached the narrowed claim independently**, which is the strongest
support it has: no single reviewed project combines automatic agent telemetry,
per-event signatures under pinned per-agent keys, hash chaining, and a mature
portable evidence pack. The swap made in `POSITIONING.md` and
`docs/PRIOR-ART.md` stands.

### Prior art: the closest system is Exabeam's own

**Exabeam Outcomes Navigator** — source-to-detection coverage validation,
log-quality and parsing analysis, rule-activity insight, and "prescriptive
scoring." Brief 3 calls it conceptually the closest thing to Cohaera it found,
and notes no public score schema, API object, failure taxonomy or per-check
"could not evaluate" payload could be located.

**This is strategically the single most important row in any of the three
briefs.** The nearest neighbour to this project is a product belonging to the
organisation it is being positioned toward. That is an argument for the sidecar
framing and against the category-ownership one, and it needs to be understood
before any conversation rather than during one.

Brief 3 also names **Elastic rule-execution status** (machine-readable
`partial failure` / `failed`, with messages like *no matching index*) and
**Microsoft Sentinel `SentinelHealth`** records. Both are already characterised
correctly in `docs/PRIOR-ART.md` §1 and §8 — the repository was ahead of the
brief here, as it was on DeTT&CT and CardinalOps.

### EU AI Act, third pass

Brief 3 confirms brief 2's Digital Omnibus correction against the 2026-07-27
consolidation and adds two precise points: **"agentic AI" is not a substantive
category in the Act** — it appears in Annex XIV as a conformity-assessment
classification code — and Article 12's only attribution provision concerns human
verifiers for certain remote-biometric systems. Three briefs now agree: **no
compliance argument gets built on this.**

### LogRhythm, third pass and strongest yet

Verified through release **7.25.0.1067 (2026-08-17)**: no Agent Sensor, Observra,
Socxen, Claude or MCP material; the August patch addresses AIE regex processing
only. The ExabeamLabs content repository does carry Gemini Enterprise agent-request
parsers — but identifies itself as the **New-Scale** content library.

New and useful: **LogRhythm 7.25 added a synchronization service** copying
New-Scale case summaries, risk, assignment and status into LogRhythm alarms. So a
New-Scale agent-security case *can* surface in LogRhythm — but the detection and
analytics ran in New-Scale. **Relay, not native content.** The gap holds, and the
relay is the integration seam worth designing against.

---

## 3.6 Fourth brief — the one that stopped where it was told

Issued against the questions §3.5 left open. Its most valuable property is that
it **declined two of them** rather than filling the gap with inference.

### Agent Sensor: stopped, correctly

No `LICENSE`, `LICENSE.md` or `COPYING` in the distribution repository (command
given), and the published binaries are macOS and Windows only — no Linux
artifact. With no licence the brief treated execution as not permitted and
stopped, which is what it was asked to do.

**So the `ts` versus `timestamp` conflict is still unresolved**, and Phase 7's
gate stands. What the brief adds is a warning worth keeping: *"prior briefs that
printed a schema without a captured event were guessing."*

### Outcomes Navigator: §8's claim survives, but only the narrow one

Coverage is *"how well your environment is configured"*, 0–100, recalculated at
least daily. The nearest per-detection construct is the Correlation Rules
**"satisfied"** bit — all required fields actively parsed in the past 30 days.

**Rule-level windowed field presence is not a verdict**, and the brief's own
illustration is the sharpest framing anyone has produced for what Cohaera does
differently: *a rule can be satisfied all month and still fire on a truncated
tool body; a rule can be unsatisfied because a parser was quiet for thirty days
while today's event is complete.*

Consequence for `docs/PRIOR-ART.md` §8, now applied: **"nobody scores whether a
rule has the fields it needs" would be false** — Outcomes Navigator does that,
and did it first. What survives is a grade attached to an *individual verdict*.

### Tamra could not be found

Brief 3 reported "Tamra Agent Ledger" with specifics — signed checkpoints, a
`.tamrapatra` bundle, Maven Central. **A second independent search found no such
project**, returning an unrelated coin and an unrelated EDR instead. It is marked
NOT FOUND in prior art rather than deleted, because a specific claim that fails a
second search is itself information. Two real `agentledger` repositories were
found in its place and recorded.

This is the cost of citing unread sources on one brief's word, and the entry now
says so.

### The census: 15–25, and the disjoint lists were a method failure

The fourth brief names the pattern directly: three pairwise-disjoint lists is *a
method failure, not a nine-project universe*. Its estimate is **roughly 15 to 25**
public implementations and drafts, offered as an estimate because its registry
scrape was bot-blocked. Recorded in prior art with that caveat attached.

### obsvr-sdk's gap markers, specified — and where Cohaera is already better

The design, worth copying:

- queue overflow emits a **signed gap marker in the current session**;
- ingest rejection, permanent failure or retry exhaustion starts a **new
  session** whose sequence-1 marker names the reason and the count, because the
  missing signed event cannot honestly continue the old chain;
- the marker is a **first-class chained event**, not an inferred sequence hole;
- `obsvr-verify` exit code **3 = valid but incomplete**, with `--allow-gaps`
  mapping 3 to 0; semantics pinned by a conformance fixture.

Two honest limits the brief supplies. The marker is itself in-memory work, so
process death before delivery leaves only local counters — **the same hole
Cohaera has**, just declared when the process lives long enough to declare it.
And obsvr-sdk's offline verify cannot detect truncation: *"removing a valid
suffix leaves a shorter valid chain."*

**That last point is a place Cohaera is ahead**, and it should be said as
carefully as the places it is behind: CH06 with `--seen-streams` detects a
truncated tail, because the ledger remembers how far the stream previously
reached. Adopt the marker state machine; do not adopt the verifier's blind spot.

### Consumer side: there is no third-party contract

**ABA.** Native collectors, Observra libraries, and custom-agent sidecars
*"currently in active development"*. The Context Management APIs add enrichment
tables, not event streams. **No documented contract exists for "send this JSON
and ABA will treat it as agent context."** A third party emitting Observra-shaped
JSONL to a collector is inference, not a published allow-list. That materially
weakens Phase 3's downstream half and should be resolved before it is built.

**LogRhythm — and the one actionable finding.** 7.25's Sync Service keeps case
status, assignee, risk and MITRE alignment aligned between LogRhythm SIEM and
New-Scale. Case sync, not agent telemetry, exactly as §3.5 concluded.

But custom **MPE rules can leave the gated KB**: the Client Console Rule Builder
exports and imports rule files, and Community Shareables is a distribution
channel. Constraints to design against: importer and exporter console versions
must match, the importing KB version must be at least the exporting one,
imported rules land in Development and need promotion, and system rules are
overwritten on KB update. **AIE packs have no documented out-of-band
distribution format** beyond importing a LogRhythm-authored module.

So the LogRhythm play is buildable on the MPE side and blocked on the AIE side,
which is a sharper statement than "the gap is real."

### Corpus conversion, costed

- **InjecAgent** — static JSONL, no runtime. Convert each case to one synthetic
  session. Estimated **half a day to a day**. Vacuous on timing; useful for
  content checks, which is exactly what CH03 lacks.
- **AgentDojo** — executes tools and holds real return bodies in
  `ChatToolResultMessage`. No exporter shaped like `tool_start`/`tool_end`, so it
  needs a thin tracer around the execution loop. Estimated **two to four days**,
  and it is the one worth having.
- **SCAM** — advertises a raw JSON download; schema unchecked.

Explicit warning: **do not treat official result CSVs as telemetry.** They carry
utility and attack-success bits, not observations.

### Approval prior art, read — and it validates the E26 design

- **Vercel `experimental_toolApprovalSecret`** binds tool name, tool call id and
  canonical input under HMAC-SHA256. **No nonce, no expiry, no approver
  identity.** The tool call id is client-minted, which is a spoofing surface, and
  the default path is unsigned.
- **aiAuthZ** binds user id, session id, a hash of the message content, a
  single-use nonce and a timestamp with a 300-second window — but it authenticates
  **the human message, not the tool call**, and its HMAC is not third-party
  non-repudiable.

**Neither is a complete single-use signed approval over (tool, arguments,
expiry, approver).** Cohaera's E26 work — an Ed25519 issuer signature over a
signing input covering span, tool, argument digest, nonce and a mandatory
expiry — is not behind either of them, and the two failure modes they document
are the two it avoided: a shared long-lived HMAC with no time bound, and
authenticating the wrong object.

### SEP-3140 versus SEP-1766

Verified here by cloning the spec repository at `4e67bdc`: `seps/` holds 43
documents and contains **neither**. `docs/PRIOR-ART.md` was already careful —
it recorded reading 3140 from a pull request's head ref, which is consistent —
and it now says the merged tree was checked.

The new fact is **SEP-1766**, reported as the *tool-definition digest* proposal:
a SHA-256 digest per `tools/list` entry, client MAY pin, mismatch SHOULD warn or
block. **That is E25's remedy, proposed upstream.** Read it before building E25's
fix; if it lands, the digest an approval must bind already exists.

---

## 4. Phases

Sequenced so the cheapest disconfirming evidence arrives first. **Every phase
ends in a decision point.** A phase that fails its exit criterion stops the
sequence rather than proceeding on hope.

### Phase 0 — Resolve the strategic conflict *(no code)*

- [ ] Decide between the sidecar position and the category-ownership position
- [ ] If sidecar: record the decision and its reasoning in `POSITIONING.md`
- [x] Read Observra #117 and Socxen #87, #6, #3, #5 — **done, see §3.3.** All five
      open. #117 is an RFE rather than a measured defect; #5 and #87 contradict each
      other on whether a structured log exists
- [ ] Resolve the #5 / #87 contradiction by reading the current
      `plugin/docs/logging.md`
- [ ] Correct `docs/EXABEAM-STACK.md` for Observra 1.1.1
- [x] Remove the first-mover tamper-evidence claim wherever it appears — **done.**
      It turned out the repository never made it: `POSITIONING.md` had already
      retracted "nobody does this" and `docs/PRIOR-ART.md` already documented
      DeTT&CT and CardinalOps. The claim came from the external gap analysis and
      from this document repeating it. The narrowed claim now stands in both
- [ ] Drop the EU AI Act evidentiary-bar argument (§3.3, §3.4)

**Exit criterion:** the position is written down and the corrections are made.
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

- [ ] Evaluate against **InjecAgent** (1,054 cases, templated but real hostile
      tool bodies) and **AgentDojo** (stateful environments, tools return real
      object text). Both are externally authored and both carry the content
      channel this corpus lacks

**Exit criterion:** CH03's content path has a measured result rather than a
vacuous zero.
**Why this is here, and the framing has changed.** It was found building E09's
scan and it does mean CH03's content story is untested by the evaluation gating
this repository's claims. What it is **not** is a novel finding about the field:
the commissioned research established that the flagship benches carry real tool
content precisely because IPI evaluation is vacuous without it. **This repository
is behind the established practice, not ahead of it**, and the remedy is to adopt
corpora that already solved it rather than to publish the observation.

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
      organisation holdouts. **Named candidates, verified to carry tool content:**
      InjecAgent and AgentDojo. Socxen is **not** one — see §3.3
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
| ~~Socxen has no usable red-team corpus~~ **SETTLED: 20 attack recipes, 0 traces** (counted at `d5b8625`) | **High** — the flagship demo's corpus dependency fails as specified | Use InjecAgent / AgentDojo for evaluation; keep Socxen for the *narrative* demo only, with fixtures we author |
| First-mover tamper-evidence claim is false | Medium — credibility, if repeated to a reviewer who knows obsvr-sdk | Remove the claim; run an honest differential against obsvr-sdk |
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
