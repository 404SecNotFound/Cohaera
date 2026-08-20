<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

<h1 align="center">Cohaera</h1>

<p align="center"><b>Evidence quality for agent telemetry.</b></p>

<p align="center">
  <i>From Latin <b>cohaerere</b>, to hang together.<br/>
  Does the agent's behaviour hang together &mdash; and can you trust<br/>
  the record that says so?</i>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-Apache_2.0-blue.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime_deps-0-brightgreen.svg">
  <img alt="Status" src="https://img.shields.io/badge/status-pre--alpha-orange.svg">
</p>

---

## What this is, in one screen

Cohaera reads agent telemetry and answers a question most detection layers skip:
**is the record trustworthy enough to draw a conclusion from?** It verifies
collector signatures and chain continuity, checks that approvals and provider
receipts bind to the exact call they claim, and — when it cannot establish
something — says which check could not run and why, instead of reporting clean.

It is **pre-alpha research software**. Read the numbers before the prose:

| | |
|---|---|
| What is measured | A synthetic corpus, written by the detector's author |
| Target-attributable recall | 100% on the headline cell |
| False positives | **420.4 per 1,000 benign sessions** |
| Projected precision at 0.1% attack prevalence | **0.238%** |
| Known ways to defeat it | 22 catalogued, 20 still working, each with a test |
| External validation | **None.** No live SIEM, no independent labels, no second reviewer |

That false-positive rate is not a typo and it is not buried. At a realistic base
rate almost every alert this produces is benign. The checks that fire cleanly
are the evidence-integrity ones; the behavioural ones are noisy and
[the card says exactly which and why](eval/EVALUATION-CARD.md).

### Where to start

| If you are… | Read |
|---|---|
| Deciding whether the thinking is any good | [The night watchman](#the-night-watchman) below, then [EVASION.md](EVASION.md) — the catalogue of ways to beat it |
| Evaluating it as a detection layer | [POSITIONING.md](POSITIONING.md), then the [evaluation card](eval/EVALUATION-CARD.md) |
| Trying to run it | [Quick start](#quick-start) — about two minutes |
| Auditing the security claims | [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [docs/EVIDENCE-TRUST.md](docs/EVIDENCE-TRUST.md) |
| Checking how it responds to criticism | [REVIEW-RESPONSE.md](REVIEW-RESPONSE.md) — 43 external findings across two reviews |
| Looking for everything else | [docs/README.md](docs/README.md) — the full map |

---

## The pitch

Two versions, for when somebody asks what this is and you have a lift ride to
answer in. Every number below is derived from the evaluation card by
`tools/readme_facts.py` and fails CI if it drifts, which is itself the argument.

**Fifteen seconds.**

> Agent telemetry is becoming a security data source. Several projects are now
> building agent records that are worth believing; almost nothing grades the
> records a deployment already has. Cohaera grades the evidence before anything
> correlates on it — verified, partially verified, or inadmissible. And when a
> check cannot run, it says *not evaluated* with a reason code instead of
> reporting clean. Silence is not safety.

**Forty-five seconds, for a detection team.**

> Every agent framework now emits logs, and SIEMs are starting to ingest them.
> But those logs are written by the thing being monitored: an agent can truncate
> its own transcript, replay a stale approval, or claim a tool call it never
> made. Cohaera is an evidence-quality layer that sits in front of correlation.
> It verifies signature chains, binds tool arguments to what actually executed,
> and extracts correlation-ready features from agent and MCP evidence.
>
> The part that matters most is the coverage contract. A check that lacks the
> evidence to run is *forbidden* from returning clean — it returns
> `not_evaluated` with a machine-readable reason. That is the failure mode this
> was built against: a green dashboard that means "we did not look."
>
> And it grades itself by the same rule. The repository ships an evaluation card,
> regenerated on every commit with CI failing on any diff, and it leads with the
> number most detection projects bury — 420.4 false positives per 1,000 benign
> sessions, and 0.238% precision at a 0.1% attack base rate. 22 evasions
> constructed, 20 still working, every one of them a permanent test. It is
> pre-alpha, the corpus is synthetic and its author wrote the detector too, and
> nobody outside this repository has validated any of it. All of which is on the
> first screen rather than discovered later.

**The honest framing, if you only keep one line.** The measurement discipline is
the artefact here, not the detector. A detection release that reports only
recall is a marketing document. Everything above is an argument about what a
security research output should look like, made by building one that has to live
with it.

---

## The night watchman

Imagine a night watchman. Very diligent. Every time something happens in the
building he writes a note and drops it in a box. "Door opened." "Alarm sounded."
"Van left the loading bay." He never misses anything.

But he has one problem. He has no memory. Each note is written by a man who has
just woken up: he looks at the one thing in front of him, decides whether it is
alarming *by itself*, writes it down, and forgets.

So he catches "the alarm sounded," because that is alarming on its own. He can
never catch "the alarm sounded, **and then** the van left," because noticing that
means holding two notes at the same time, and nobody in the building is doing
that.

That is agent telemetry today. The rule function is literally
`evaluate_rules(event_type, data)`. One event, one dictionary, then gone. Nine
rules ship upstream and every one of them asks a question about one note.

Here is the part that makes this a finding rather than a complaint. **On the side
of the box, somebody wrote instructions.** The upstream parser file declares
correlation keys, with this description: *"Use session_id to group all events in
a conversation."* Somebody knew the story lives across the notes. They wrote it
down. Nothing in the system ever picks up the box and sorts it.

**Cohaera is the person who reads the box.**

That is the whole idea. It is not clever. It is the sort of thing that looks
obvious once someone says it out loud, which is usually a good sign rather than
a bad one.

When we picked up the upstream project's own demo box and sorted it, we found:
the cost guardrail went off at `t=915.750`, and eight seconds later the agent
sent an email it could not take back. Both notes were in the box the whole time.
Nobody had put them next to each other.

**Now the part that matters more than the finding.** This shows the detector
*fires*. It does not show the detector is *good*. Those are completely different
claims and it is very easy to confuse them, especially when the thing you built
has just done something impressive. Twelve clean sessions producing zero alerts
sounds like a false positive rate of zero; it is not, because the baseline was
fitted on those same twelve near-identical sessions. That is a smoke test wearing
a lab coat.

So there is a file in this repository called [EVASION.md](EVASION.md) whose
entire job is to break this one. 22 constructed evasions, 20 of them still
working, each backed by a test that passes when the evasion succeeds. Read it
before you trust anything else here — including the entry for the one that has
been closed, which cost 36 new false positives and says so.

> The first principle is that you must not fool yourself, and you are the
> easiest person to fool.

### One correction to the story above

The box is real and nobody is reading it. That part holds.

What does not hold is the conclusion this project drew from it for its first
year: that reading the box is the *missing layer*. It is not missing any more.
Exabeam's [Agent Behavior Analytics](https://www.exabeam.com/capabilities/agent-behavior-analytics/)
baselines agent behaviour, tracks first-time actions and role drift, covers MCP
activity, and correlates agents with the users and entities around them. Sold
to that audience, "somebody should read the box" is a description of their
product.

The gap that has *not* closed is one layer down, and it is the more interesting
one. Whoever reads the box is trusting that the notes are the notes the
watchman wrote. In agent telemetry the watchman usually runs inside the process
he is watching.

**So: Cohaera's job is not to be the reader. It is to make the notes worth
reading — and to say so out loud when they are not.** Signed collector chains,
exact call binding, provider receipts that can falsify a claimed failure,
replay and fork memory, and a coverage contract on every check that cannot run.
Those become inputs to a behavioural engine rather than a competitor to one.

[**POSITIONING.md**](POSITIONING.md) has the layer table, the claim language
this project holds itself to, and the honest statement of what is not
validated.

---

## Contents

- [The pitch](#the-pitch)
- [The night watchman](#the-night-watchman)
- [The problem in one page](#the-problem-in-one-page)
- [Solution architecture](#solution-architecture)
- [It fires on observra's own demo data](#it-fires-on-observras-own-demo-data)
- [The checks](#the-checks)
- [How session assembly works](#how-session-assembly-works)
- [Quick start](#quick-start)
- [The lab](#the-lab)
- [Lab build, step by step](#lab-build-step-by-step)
- [Experiment protocol](#experiment-protocol)
- [Design decisions](#design-decisions)
- [Prior work](#prior-work)
- [Roadmap](#roadmap)
- [Known limitations](#known-limitations)
- [Relationship to the upstream projects](#relationship-to-the-upstream-projects)

**Other documents** — [docs/README.md](docs/README.md) maps all sixteen by the
question each one answers. The four read most often:

| | |
|---|---|
| [EVASION.md](EVASION.md) | 22 ways to defeat this, 20 still working, each with a test |
| [POSITIONING.md](POSITIONING.md) | What layer this is, what it is not, and the language it will not use |
| [REVIEW-RESPONSE.md](REVIEW-RESPONSE.md) | Two external reviews, 43 findings, what happened to each |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | What it trusts, and what survives a hostile producer |

---

## The problem in one page

[observra](https://github.com/open-agent-ai-security/observra) captures agent
telemetry and normalises it to a Common Information Model. It is good at that.
Its rule engine signature is:

```python
evaluate_rules(event_type: str, data: dict) -> list[str]
```

Stateless. Single event. **No rule can see two events at once.**

The consequence is recorded by the maintainer in observra issue
[#108](https://github.com/open-agent-ai-security/observra/issues/108),
opened 4 August 2026 and still open:

> 28/34 AI analytics rules work today. **Zero correlation rules can fire.**

One day later, TEN18 by Exabeam published
[*What Makes Agent Activity Harder to Detect*](https://www.exabeam.com/blog/security-operations-center/what-makes-agent-activity-harder-to-detect/):

> Risk emerges through sequences, first-time actions, and behavioral drift.
> **The signal doesn't exist within a single event.**

Both statements are true at the same time. The telemetry layer emits per-event
records; the threat model says the signal lives across events. **Cohaera is the
piece between them.**

### Why this is not solved by "just add rules"

| Question a SOC needs to answer | Events required | Can observra express it? |
|---|---|---|
| Did the cost guardrail fire and get ignored? | 2+ | No |
| Did a state change follow untrusted content? | 2+ | No |
| Is this tool ordering novel for this agent? | whole session | No |
| Did the agent report what it actually did? | tool log + final message | No |
| Did a tool start and never finish? | 2 | No |
| Did this single call exceed 10,000 tokens? | 1 | **Yes** |

Every row except the last needs state. That is the whole gap.

---

## Solution architecture

```mermaid
flowchart TB
    subgraph L1["LAYER 1 · AGENT RUNTIME"]
        direction LR
        AG1["Claude Agent SDK"]
        AG2["LangChain / LangGraph"]
        AG3["socxen<br/>SOC analyst agent"]
        AG4["custom agent<br/>emit or webhook"]
    end

    subgraph L2["LAYER 2 · CAPTURE · observra 1.1, upstream and unmodified"]
        direction TB
        CAP["adapters<br/>tool_start · tool_end · model_response · policy_event"]
        NORM["CIM normalise<br/>27 event types · ULID trace/session/span"]
        PIPE["redact · dedup · cost accounting"]
        SR["rules.py<br/>evaluate_rules event_type, data<br/>STATELESS · SINGLE EVENT"]
        CAP --> NORM --> PIPE --> SR
    end

    subgraph L3["LAYER 3 · CORRELATE · COHAERA, this project"]
        direction TB
        FW["schema firewall<br/>bounded size · depth · types · quarantine ledger"]
        ASM["session assembler<br/>session_id · trace_id · HMAC anon · isolate"]
        FEAT["feature derivation<br/>tool sequence · call class · timing · cost · depth"]
        CAPM["capability manifest<br/>exact tool ID, declared effects"]
        GRAM["sequence grammar<br/>bigram model fitted on benign corpus"]
        EVID["evidence verifier<br/>integrity chain · effect receipts · approval binding"]
        CHK["CH01 order · CH02 concealment<br/>CH03 taint completed/attempted<br/>CH04 guardrail completed/attempted/bypassed · CH05 unpaired<br/>CH06 evidence integrity · CH07 effect contradiction"]
        COV["coverage contracts<br/>per check: what could NOT be evaluated, and why"]
        FW --> ASM --> FEAT --> CAPM --> GRAM --> EVID --> CHK --> COV
    end

    subgraph L4["LAYER 4 · ANALYTICS AND SOC"]
        direction LR
        ABA["Exabeam ABA<br/>New-Scale Analytics"]
        AIE["LogRhythm AIE<br/>correlation rules"]
        SIG["Sigma<br/>portable content"]
    end

    L1 ==> L2
    SR ==>|"per-event JSONL · webhook · OTel<br/>the stream that exists today"| L3
    COV ==>|"cohaera_session_verdict<br/>type + schema + verdict_id + triggered_rules<br/>+ max_severity + coverage + provenance<br/>ONE record per session"| L4

    style L3 fill:#0f2b46,stroke:#4a9eff,stroke-width:3px,color:#ffffff
    style SR fill:#5a1e1e,stroke:#ff6b6b,color:#ffffff
    style FW fill:#4a3a10,stroke:#e0a800,color:#ffffff
    style COV fill:#1e4620,stroke:#5cb85c,color:#ffffff
```

**Read it in one line:** observra hands over a flat stream, Cohaera gives it a
shape, and the SIEM finally has something with more than one event in it to
write a rule against.

Cohaera does not replace behavioural analytics. **It feeds it.**

---

## It fires on observra's own demo data

No tuning. No baseline. `demo/data.jsonl` exactly as distributed in the
observra repo:

```
session 01KZ21ZR6B9X78G6BYWSMXYHQ1  agent=kb-research-agent  cost=$0.6413
   [CRIT] CH03_untrusted_to_completed_action
   [HIGH] CH04_guardrail_bypass_completed: Consequential action COMPLETED
          after cost_threshold_exceeded
```

Here is the CH04 detection drawn out. Every timestamp and field below is
verbatim from the shipped file.

```mermaid
sequenceDiagram
    autonumber
    participant U as Analyst
    participant A as kb-research-agent
    participant T as Tools
    participant O as observra
    participant C as Cohaera

    U->>A: "Pull the KB article on VPN cert renewal"
    A->>T: web_fetch_knowledge_base_article
    T-->>A: KB-1183 ... plus hidden embedded instruction
    O->>O: t=...870.601 tool_end<br/>injection_patterns: INSTRUCTION_OVERRIDE<br/>max_severity: high

    Note over O: Event 1 logged. Rule fires.<br/>Then the event is forgotten.

    A->>A: model_response, cost_usd 0.624
    O->>O: t=...915.750 cost_threshold_exceeded<br/>session_cost_usd 0.6311 vs threshold 0.5

    Note over O: Event 2 logged. Rule fires.<br/>Then this event is forgotten too.

    A->>T: t=...923.776 send_email_followup<br/>reversible: false
    T-->>A: sent

    Note over O: Event 3 logged.<br/>observra cannot relate it to events 1 or 2.<br/>evaluate_rules sees one dict at a time.

    C->>C: assemble all 20 events into one Session
    C-->>U: CH04 CRITICAL PATH<br/>guardrail fired at 915.750,<br/>irreversible action at 923.776,<br/>8.0 seconds later
```

**CH04 is the clean, unarguable one.** The cost guardrail fired, wrote a log
line that looks like a control, and the session went on to take an irreversible
action eight seconds later. That is not expressible upstream, because expressing
it requires holding two events at once.

**CH03 carries a caveat, stated up front.** It fired because injection markers
appear on a `tool_end` and a consequential call ran afterwards. In this demo the
agent behaved **correctly**: the case note reads *"flagged suspicious KB content,
did not act on embedded instructions"* and the email result reads *"sent
legitimate KB steps; ignored the embedded instructions"*. So CH03 is a true
positive for **"this session needs review"** and a false positive for **"this
agent was compromised"**. The check's own output says exactly that. See
[FINDINGS.md](FINDINGS.md).

### Measured results

There is now a labelled corpus and an evaluation harness. **The numbers are in
[`eval/EVALUATION-CARD.md`](eval/EVALUATION-CARD.md)**, they are generated
deterministically by `python eval/run_eval.py`, and they are not flattering.

1824 sessions per condition, 456 tasks across 8 task families, splits by task and
never at random, and seven in ten benign sessions are deliberate confounders —
sessions that are genuinely benign and genuinely look like the attack they sit
next to. Headline, `task_disjoint` with a capability manifest:

| | |
|---|---|
| recall | **100%** (all 10 attack shapes caught) |
| false positive rate | **42.0%** |
| false positives per 1000 **benign** sessions | **420.4** |
| projected precision at 0.1% attack prevalence | **0.238%** |
| false positives on *plain* benign sessions | **0 / 96** |

The third row used to read "false positives per 1000 sessions | 284", which is
a different and friendlier number: it divides by a population that is a third
attacks, because this corpus needs enough of them to measure. It moves with a
prevalence no deployment has. The evaluation card says in as many words never
to plan against it, and the README published it anyway — derived and checked,
so nothing flagged it. A checker enforcing the wrong number is worse than no
checker.

The fourth row is the one to read twice. Recall is not the product.

Both halves matter. Cohaera separates clean benign traffic from everything else
perfectly, and cannot separate a hard benign session from an attack at all: every
false positive comes from a confounder, and every confounder trips exactly the
check it was built to trip. **Cohaera is not noisy. It cannot distinguish intent
from sequence**, which is a different and less fixable problem.

Two results worth pulling out:

- **With tool names the classifier's keyword lists already know, the name
  heuristic alone scores identically to a full capability manifest.** That is
  what the twelve fixtures below always measured — the keyword list checking
  itself. Swap in a realistic vocabulary the heuristic has never seen and its
  classification accuracy is **0% of 34 tools**, and recall falls to 34.7%.
- **Under `family_holdout`, where the baseline never saw the test workload, the
  false positive rate is 34.2%** and recall drops to 79.0%, because CH01 declines
  to judge a workload it was not fitted on and CH01 is the only check that
  catches a diluted attack. CH01 does not transfer across task families. Fitting
  one baseline across a fleet of differently-tasked agents buys silence where it
  used to buy a paging storm, and silence is not detection either.

The card also measures the split-leakage inflation the citation below asserts,
rather than repeating the citation, and states what it does not measure: the
corpus is synthetic, attack prevalence is an absurd 33%, and exactly one of the
catalogued evasions in [EVASION.md](EVASION.md) appears in it — E02, which is
there because the fix for it could not otherwise be graded.

### Fixture results

The original fixtures remain as unit tests. They are a **smoke test, not a
measurement**, and are kept only because the unit suite asserts against them.

| Corpus | Sessions | Findings |
|---|---|---|
| 12 benign fixture sessions, grammar fitted on themselves | 12 | **0** |
| 4 suspect fixture sessions | 4 | 9 across CH01 to CH05 |

---

## The checks

| ID | Check | Question it answers | Events needed |
|---|---|---|---|
| **CH01** | `sequence_order` | Does the tool ordering match a grammar mined from benign sessions — either in aggregate, or on the route into a consequential call? | whole session |
| **CH02** | `concealment_gap` | Did a consequential call succeed without appearing in the agent's final message to the human? | tool log + final response |
| **CH03** | `untrusted_to_completed_action`<br/>`untrusted_to_attempted_action` | Did a state change follow observed injection markers in the same session — and did it *complete*, or only get *attempted*? | 2+ ordered |
| **CH04** | `guardrail_bypass_completed`<br/>`post_guardrail_attempt`<br/>`blocking_control_bypassed` | Did a policy event fire and the session carry on doing consequential work anyway — completed, or attempted? And where the control is *declared blocking* and no approval binds to the work, was it **bypassed**? | 2+ ordered |
| **CH05** | `unpaired_calls` | Did a tool start and never terminate, meaning the session is incompletely observed? | 2 paired |
| **CH06** | `evidence_integrity` | Do these records verify against what the collector attested to — sequence, hash chain, signature? | whole stream |
| **CH07** | `reported_failure_with_effect_receipt`<br/>`effect_receipt_does_not_bind` | Did a call report failure while carrying a receipt minted by the system the action happened to? | 2 paired |

### CH06 and CH07 are not checks about the agent

The first five ask what an agent did. Every one of them is a sound argument over
its input and every one is conditional on the input being a faithful record —
and until [P1](docs/EVIDENCE-TRUST.md), nothing established that. Cohaera could
tell a malformed record from a well-formed one and could not tell a true record
from a false one.

**CH06** asks whether the evidence is admissible at all. Against a stream
carrying `cohaera.integrity:1`, deleting a record is a detected and localised
sequence gap, and modifying one is a chain break naming the record that moved.
Every other finding in the session is stamped with `evidence_status`, so a
verdict built on a stream somebody could have edited does not arrive looking
like one that verified. Five values, and the first two used to be one:

| `evidence_status` | means |
|---|---|
| `verified_complete` | a verified signature reaches the last record of every stream |
| `verified_prefix` | signatures verified, and they stop short — the tail is chained and attested by nobody |
| `chained_unsigned` | internally consistent, with nothing to check it against |
| `unattested` | no integrity sidecars at all |
| `inadmissible` | a gap, a break, a bad signature, a replay |

The default value is `unattested`, which is where every deployment starts and
which means *tampering was not ruled out*, not *tampering was ruled out*.

**CH07** is the only detection here that catches a lying emitter rather than
routing around one. A receipt is an identifier minted by the system the action
happened to — an SMTP `Message-ID`, an object version ID — drawn from a
namespace the agent does not control. A call whose terminal event says failure
while carrying a receipt bound to that exact call and those exact arguments is a
contradiction *inside the record*: the action took effect and the telemetry says
it did not.

Note the asymmetry, because it is the whole reason to collect receipts.
**Receipts do not make `success` more believable.** A success with no receipt is
exactly as unfalsifiable as it always was, and is reported through coverage
(`NO_EFFECT_RECEIPT`) rather than as an alert. What they make falsifiable is
failure and silence.

### Why CH03 and CH04 are each two checks

They were each one check until an external review pointed out what the merged
wording asserted. A session where the only candidate call had **errored** was
reported at the same severity, with the same title, as one where an irreversible
action actually happened — and CH04's detail said *"the control produced a log
line but did not stop the behaviour"* about a call that never completed.

That sentence has two unsupported halves. The action did not happen. And nothing
in the telemetry says which of the guardrail, the tool, the model or an unrelated
failure prevented it, so the control being ignored is one reading and the control
**working correctly** is another.

An attempt and an effect are different facts and an analyst acts on them
differently, so they are now different check IDs at different levels with
different Sigma rules. `data.triggered_families` still carries the family name
for content that wants either.

### Coverage is a capability contract, not a score

`coverage()` reports **what could not be evaluated and why**. A check that
silently cannot run is a false negative wearing a green tick. observra's own
`examples/siem_parser.json` carries a `telemetry_completeness` field described as
*"Use to weight anomaly detection confidence"*. This is that idea, made concrete
per check.

Each check declares the **surfaces** it needs, which were present, which were
missing, stable **reason codes**, remedies, and the assumptions it is making.
`completeness` is the mean confidence across checks, and confidence multiplies in
three things the previous version ignored:

- **correlation quality** — 1.0 for a producer-supplied `session_id`, 0.3 for a
  scoped anonymous bucket, 0.0 for a record with no identity at all;
- **classification quality** — whether each tool's effect was *declared* in a
  capability manifest or *guessed* from its name;
- **clock quality** — the fraction of events with a usable timestamp, since CH03
  and CH04 are ordering checks and cannot see an event without one.

The practical consequence: **a session whose tools Cohaera cannot classify no
longer scores 1.0.** Under the old count-based score it did, because unknown
classification raised a gap that no check depended on.

### Call classification

Every tool call is classified `read_only`, `state_change`, `egress`, or
`unknown`. Egress wins over state change, because data leaving the trust
boundary is the more consequential property for a concealment check.

Precedence, highest first:

1. an exact-tool-ID **capability manifest**, if one is supplied;
2. egress by name;
3. observra's per-call `reversible` flag, authoritative in both directions;
4. the name heuristic, whose keyword sets come from observra's own
   `schema/cim_schema.toml` rather than a parallel taxonomy invented here.

The manifest outranks `reversible` deliberately: that flag arrives **on the
event**, in band, from the same path an attacker would use to hide an action. The
manifest is loaded out of band from a path the operator chose.

It is not signed — that needs a key distribution story this project does not have
— so every verdict instead carries two digests of it in
`provenance.capability_manifest`. `file_digest` covers the exact bytes and moves
for any edit at all, including one to a field this version does not parse.
`semantic_digest` covers the declarations Cohaera parsed out of them and moves
only when the meaning changes. Matching semantics with differing bytes is a
reformat; differing semantics means verdicts either side of the edit are
answering different questions.

Steps 2 to 4 are all guesses about an attacker-supplied string, and the heuristic
has been wrong in both directions in every review round so far — `budget_report`
read as read-only because `get` is inside `budget`, `postmortem_read` read as
egress because `post` is inside `postmortem`. Whole-token matching fixed those.
It cannot fix the general case: `sync_to_partner` is egress and `sync_local_cache`
is not, and no lexical rule separates them. See
[`content/manifest/`](content/manifest/example_capability_manifest.json).

**The deployed taxonomy exists. It is untrusted by default, and it is unsigned.**
This section used to rest on the premise that no deployment has adopted a
declared tool-capability or effect taxonomy. That premise is wrong. MCP's
`ToolAnnotations` are in the **stable** protocol schema —
`schema/2025-11-25/schema.ts`, the revision the specification repository's own
README points at — and carry `readOnlyHint`, `destructiveHint`, `idempotentHint`
and `openWorldHint`. That is a tool-capability and effect taxonomy, normatively
specified, and therefore present in every conformant SDK.

The schema's own note on that type is where the premise moves to:

> NOTE: all properties in ToolAnnotations are **hints**.
> They are not guaranteed to provide a faithful description of
> tool behavior (including descriptive properties like `title`).
>
> Clients should never make tool use decisions based on ToolAnnotations
> received from untrusted servers.

The restated claim is true, checkable, and stronger than the one it replaces.
The specification conditions the annotations on server trust and supplies no
mechanism for establishing it: searching the whole stable schema for
`signature`, `attestation`, `provenance`, `digest`, `hash` or `integrity`
returns nothing relevant — not on `ToolAnnotations`, not on `Tool`, not
anywhere. There is no publisher identity, no manifest digest, and nothing that
binds a declaration to the party that made it. This is the same objection
Cohaera already makes to `reversible` arriving on the event, and it is why the
manifest is loaded out of band: the operator chose the file, and nobody chose
the hint.

**The manifest itself is not novel either.** MCP SEP-3140 proposes a JWS-signed
capability manifest bound to a discoverable publisher identity, with a
signature-covered trust block carrying effect, egress, data sensitivity and
reversibility per tool. That is this feature, proposed into the protocol, by a
vendor, with a proof of concept in the same pull request. If it lands, the right
move for this project is to consume it rather than compete with it.
[docs/PRIOR-ART.md](docs/PRIOR-ART.md) §6 has the comparison and the two
differences that are real rather than a maturity gap.

---

## How session assembly works

```mermaid
flowchart LR
    subgraph IN["observra JSONL, flat and unordered"]
        E1["tool_start<br/>span=A"]
        E2["model_response"]
        E3["tool_end<br/>span=A"]
        E4["cost_threshold_exceeded"]
        E5["tool_start<br/>span=B"]
    end

    subgraph ASM["Cohaera assembly"]
        F["schema firewall<br/>bounded size · depth · types<br/>reject or flag, never guess"]
        G["group by session_id<br/>trace_id · scoped anon · isolate"]
        S["sort by timestamp"]
        P["pair tool_start to terminal<br/>by span_id, then FIFO by name"]
        F --> G --> S --> P
    end

    subgraph OUT["Session object"]
        TC["tool_calls: ToolCall<br/>name · class · result · duration · reversible"]
        SQ["tool_sequence: list of str"]
        MK["injection_markers · policy_events<br/>handoffs · delegation depth · cost"]
        FR["final_response<br/>if the adapter captured it"]
    end

    IN ==> ASM ==> OUT
    OUT ==>|"features()"| V["feature vector + coverage contract<br/>+ verdict identity, ready for a SIEM"]
```

An unpaired `tool_end` is still recorded rather than discarded, because a
terminal event with no start is itself worth surfacing.

### The correlation key comes from the thing being observed

This is the deepest weakness in the design and it should be said before anything
else about deployment. Cohaera groups by a `session_id` the agent supplies. Give
every event its own and there are no sessions, so there is no cross-event state,
so every check goes quiet at once ([EVASION.md](EVASION.md) E12).

What the assembler *can* do is be honest about which key it used. Every session
carries `data.correlation.kind` — `session_id`, `trace_id`, `scoped_anonymous`
or `isolated_anonymous` — and a confidence that flows into every check's
coverage. Two specifics worth knowing:

- **Records with no identity at all** — no session, no trace, no host, no user,
  no agent, no framework — are **isolated**, not bucketed by time. They used to
  merge, which let an injection marker and an egress call that shared nothing but
  an arrival time produce a critical finding.
- **Anonymous keys are HMACs**, not the identity they stand in for. The old key
  embedded `repr()` of host, user, agent and framework, and that key is emitted
  as `session_id` straight into a SIEM. Set `$COHAERA_CORRELATION_SECRET`; without
  it the key is an unkeyed digest and the record says so via
  `data.correlation.keyed`, because a few thousand hostnames are trivially
  enumerable.

### The input boundary

Everything crossing it is produced by the system Cohaera is meant to assess, so
every dimension of it is attacker-controlled: line length, nesting depth, event
count, string length, how many calls share a name. The reader bounds all of them
and **quarantines** what it refuses rather than coercing it into something
plausible — a malformed tool name that becomes `<unnamed>` classifies as
`unknown`, which is not consequential, which removes a malicious action from
CH02, CH03 and CH04 at once.

Fields that survive but are the wrong type are treated as **absent and flagged**,
never guessed. The reason codes travel with the session in
`data.integrity_defects` and lower the confidence of the checks that needed them.

Every bound is validated at construction, because a bound that does not bound is
worse than no bound: the operator believes it is there.
`Limits(max_evidence_items=-1)` used to construct happily and then *disable* the
output cap, so tightening a limit by typo removed it (C4-05). Records are frozen
once read and batch-assembled sessions are sealed, so the derived values every
check reads cannot be changed behind their caches (C4-07, C4-08).

---

## Quick start

```bash
git clone https://github.com/404SecNotFound/Cohaera.git && cd Cohaera
python3 tests/make_fixtures.py

# fit a grammar on benign sessions, score the suspect ones
PYTHONPATH=src python3 -m cohaera.cli score tests/fixtures/suspect.jsonl \
    --baseline tests/fixtures/benign.jsonl
```

Against real telemetry:

```bash
export COHAERA_CORRELATION_SECRET='...'   # HMAC key for anonymous session keys

PYTHONPATH=src python3 -m cohaera.cli score ~/.observra/telemetry.jsonl \
    --baseline benign-corpus.jsonl \
    --tool-manifest my-agent-capabilities.json \
    --reject-log quarantine.jsonl \
    --max-reject-ratio 0.01 > verdicts.jsonl
```

**Exit codes**, because a pipeline that loses records must not report success:

| Code | Meaning |
|---|---|
| `0` | every record was accepted |
| `3` | partial success — some records were quarantined |
| `4` | `--strict` was set and at least one record was quarantined |
| `5` | a reject budget or resource bound was exceeded; **output is incomplete** |
| `1` | the run could not be completed as asked — a bound that is not a bound, a manifest that is not a manifest, a `--reject-log` that could not be written, or an unexpected error |
| `2` | usage error, including a bound outside its valid range |

Every budget is enforced **per record, inside the reader**. `--max-rejects` and
`--max-reject-ratio` used to be evaluated after the whole file had been read,
which makes them a post-mortem rather than a budget: a file of pure garbage was
bounded by its own size (C4-02). `--reject-log` is checked for writability
before scoring starts, because losing the record of what was quarantined while
exiting `0` is the same silent data loss the exit codes exist to prevent.

`--tool-manifest` replaces the name heuristic with a per-tool declaration and is
the single biggest lever on coverage confidence. See
[`content/manifest/`](content/manifest/example_capability_manifest.json). Its
`policies` section declares whether a guardrail is advisory or blocking, and it
outranks the same declaration on the event — the operator chose the file, the
agent wrote the event ([EVASION.md](EVASION.md) E20).

`--trust-store` supplies the public keys that `cohaera.integrity:1` signatures
verify against, loaded out of band exactly as the manifest is. Without it, signed
records are parsed and **not** verified, and the verdict says so with
`NO_COLLECTOR_KEYS` rather than treating a signature it never checked as if it
had passed. A stream carrying no integrity evidence at all reports
`NO_INTEGRITY_EVIDENCE` and stamps every finding `evidence_status: unattested`,
which is the state every deployment starts in.
[`tools/collector_sign.py`](tools/collector_sign.py) is the reference producer —
a format with no reference implementation is a specification nobody can build
against.

A key in the store carries what it is authorised to attest (`collector` for
telemetry, `policy` for the operator's own files), a validity window, and whether
it has been revoked. Rotation is `not_after` on the outgoing key and `not_before`
on its replacement; revocation is a separate field because it means something
different, and Cohaera treats it differently — a window is judged against the
timestamp the collector signed, a revocation is judged against nothing, because
believing a compromised key's clock is how a revoked key keeps working.
[EVIDENCE-TRUST §2a](docs/EVIDENCE-TRUST.md) is the argument, §9 is the list of
what the store is still not, and `--collector-keys` still accepts the older flat
`cohaera.collector_keys:1` file.

`--tool-manifest-sig` and `--baseline-sig` verify a detached
`cohaera.policy_signature:1` over those two files. They are the files that decide
how every record is *read* — the manifest says which tools are consequential, the
baseline teaches CH01 what normal looks like — and until they were signed both
were trusted for being on disk. A supplied signature that fails is a **refusal to
score**; `--require-signed-policy` makes a missing one a refusal too.
[`tools/policy_sign.py`](tools/policy_sign.py) is the reference producer. This
closes half of [E03](EVASION.md): editing the baseline is now detectable, and
influencing what goes into it before it is signed is not.

`--evidence-max-age` and `--seen-streams` are the two controls that see a
replayed stream, and they see different ones. Every other check passes on a
captured stream re-fed later — contiguous sequence, intact chain, valid
signatures — because it really was written by that collector.

`--evidence-max-age` bounds how **old** a stream may be, judged from the
timestamp the collector signed: a replayer can re-send the bytes and cannot
re-date them. `--seen-streams` bounds how many **times** one is scored, and it
is the only thing that catches a stream re-fed an hour later, still inside any
sane window. It is a small JSON ledger — stream id, sequence range, chain head —
and it is the first state Cohaera keeps between runs.

The chain head is what separates a replay from a collector restart: the same
records rebuild the same chain, new records over the same sequence numbers do
not. Same position and same head is `INTEGRITY_STREAM_REPLAYED`; same position
and a *different* head is `INTEGRITY_STREAM_FORKED`, which is worse — two
mutually exclusive versions of one stream, both signed.

Both are off by default and coverage says so (`NO_FRESHNESS_BOUND`,
`NO_STREAM_LEDGER`). The ledger is unsigned local state by necessity — signing
it would be Cohaera attesting to its own attestations — so deleting the file
defeats it, which is [EVASION.md](EVASION.md) E22.

Human summary goes to **stderr**, escaped: a producer that puts a newline and an
ANSI sequence in a `session_id` could otherwise forge a convincing `0 finding(s)`
line and clear the screen above it. CIM records go to **stdout** as JSONL, so it
pipes straight into a collector:

```bash
PYTHONPATH=src python3 -m cohaera.cli score run.jsonl 2>/dev/null \
  | curl -s -X POST -H 'Content-Type: application/json' \
         -H "Authorization: Bearer $TOKEN" --data-binary @- \
         https://collector.internal/v1/events
```

Zero runtime dependencies. Standard library only, so it runs on a locked-down
collector VM with no package install and in an air-gapped lab.

---

## The lab

Four VMs. The segmentation is not decoration: **the network policy is part of
the instrument.** CH02 and CH03 classify calls as `egress`. If `agent-01` can
reach the whole internet freely, "egress" stops meaning anything.

```mermaid
flowchart TB
    subgraph HOST["HOME LAB HYPERVISOR · Proxmox, ESXi, Hyper-V or VirtualBox"]

        subgraph SEG1["10.10.10.0/24 · GENERATION (dirty)"]
            AGENT["<b>agent-01</b><br/>Ubuntu 24.04 · 4 vCPU · 8 GB · 40 GB<br/>AgentDojo suites<br/>observra pip install<br/>agent under test"]
        end

        subgraph SEG2["10.10.20.0/24 · COLLECTION"]
            COLL["<b>collector-01</b><br/>Ubuntu 24.04 · 2 vCPU · 4 GB · 100 GB<br/>observra webhook receiver<br/>OTel collector<br/>JSONL archive + rotation"]
        end

        subgraph SEG3["10.10.30.0/24 · ANALYSIS (clean, no internet)"]
            ANA["<b>analysis-01</b><br/>Ubuntu 24.04 · 4 vCPU · 16 GB · 100 GB<br/>Cohaera<br/>corpus labelling<br/>scoring notebooks"]
        end

        subgraph SEG4["10.10.40.0/24 · CONTENT (phase 5, optional)"]
            SIEM["<b>siem-01</b><br/>4 vCPU · 16 GB · 200 GB<br/>rule authoring and replay<br/>Sigma / AIE testing"]
        end
    end

    LLM(["hosted LLM API<br/>api.anthropic.com<br/>api.openai.com"])

    AGENT -->|"HTTPS 443<br/>ALLOWLIST ONLY"| LLM
    AGENT -->|"HTTP 8080<br/>telemetry"| COLL
    COLL -->|"read-only<br/>rsync / NFS ro"| ANA
    ANA -->|"corpus replay"| SIEM

    AGENT -.->|"DENY ALL<br/>everything else"| X(("blocked"))
    ANA -.->|"NO ROUTE<br/>prevents corpus contamination"| AGENT

    style SEG1 fill:#3d1f1f,stroke:#ff6b6b,stroke-width:2px,color:#ffffff
    style SEG3 fill:#1e3d20,stroke:#5cb85c,stroke-width:2px,color:#ffffff
    style AGENT fill:#5a2828,stroke:#ff8888,color:#ffffff
    style ANA fill:#284a2a,stroke:#88cc88,color:#ffffff
```

### Why each rule exists

| Rule | Reason |
|---|---|
| `agent-01` egress allowlisted to LLM API and collector only | Makes "unexpected outbound connection" an observable event instead of background noise. Without it, `egress` classification is meaningless. |
| `analysis-01` has **no route** to `agent-01` | Stops accidental contamination of the labelled corpus. Analysis reads from the collector only. |
| Snapshot `agent-01` clean, restore between run sets | Non-negotiable for run-to-run comparability. Same discipline as any controlled experiment. |
| Hard spend cap set at the API provider | Runaway agent loops are a real failure mode. Unbounded consumption is literally LLM10 in the OWASP Top 10. |
| Everything simulated | AgentDojo's tool domains are simulated services, not real ones. Nothing external is touched. |

---

## Lab build, step by step

**Automated:** `lab/Build-CohaeraLab.ps1` builds all four VMs unattended on
VMware Workstation Pro 17. You supply the Ubuntu ISO. See [lab/README.md](lab/README.md).

Full commands, verification gates and troubleshooting are in **[LAB.md](LAB.md)**.
This is the shape of it.

```mermaid
flowchart LR
    P0["<b>PHASE 0</b><br/>Verify the gap<br/><i>1 evening</i>"]
    P1["<b>PHASE 1</b><br/>Build VMs<br/>+ segmentation<br/><i>1 evening</i>"]
    P2["<b>PHASE 2</b><br/>Instrument<br/>+ smoke test<br/><i>2 hours</i>"]
    P3["<b>PHASE 3</b><br/>Corpus generation<br/>25 attempts/scenario<br/><i>1 weekend, unattended</i>"]
    P4["<b>PHASE 4</b><br/>Measure TPR/FPR<br/>task-disjoint splits<br/><i>2 evenings</i>"]
    P5["<b>PHASE 5</b><br/>Sigma + AIE<br/>content pack<br/><i>2 evenings</i>"]

    P0 --> P1 --> P2 --> P3 --> P4 --> P5

    P0 -.->|"gate: is the gap real?"| G0{{"if observra has<br/>baselining code,<br/>RESCOPE"}}
    P3 -.->|"gate: cost"| G3{{"measure 1 suite first,<br/>extrapolate,<br/>THEN commit"}}

    style P0 fill:#4a3d1e,stroke:#ffcc44,color:#ffffff
    style P3 fill:#4a3d1e,stroke:#ffcc44,color:#ffffff
    style P4 fill:#1e3d4a,stroke:#44aaff,color:#ffffff
```

### Phase 0 · Verify the gap before building anything

The central claim is that observra has no correlation or baselining layer. That
started as an inference from the README. Prove it from source before you build
on it.

```bash
git clone --depth 1 https://github.com/open-agent-ai-security/observra.git
cd observra

# 1. Is there any behavioural analytics?
grep -ril -E 'baseline|anomal|deviation|drift|zscore|percentile' src/ | grep -v test
find . -iname '*analytic*' -o -iname '*detect*' -o -iname '*profil*'

# 2. Is the rule engine really single-event?
grep -n "def evaluate_rules" src/observra/core/rules.py

# 3. Is detect_suspicious_sequence actually called anywhere?
grep -rn "detect_suspicious_sequence" . --include='*.py'

# 4. Where does injection scanning actually run?
grep -rn "detect_injection_patterns(" src/observra --include='*.py' | grep -v /tests/

# 5. Read the architecture pipeline
cat docs/architecture.md docs/event-schema.md
```

**Gate:** if a baselining module exists, stop and rescope honestly. If it does
not, you now have evidence rather than an inference, and everything downstream
is stronger. Record the output.

### Phase 1 · Build the VMs

```bash
# on each VM
sudo apt update && sudo apt install -y python3.11 python3.11-venv git jq auditd
python3.11 -m venv ~/venv && source ~/venv/bin/activate
```

Segmentation on `agent-01` (adjust interface and gateway to your lab):

```bash
sudo apt install -y nftables
sudo tee /etc/nftables.conf > /dev/null << 'EOF'
table inet filter {
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oif "lo" accept
    # DNS to the lab resolver only
    ip daddr 10.10.10.1 udp dport 53 accept
    # collector
    ip daddr 10.10.20.10 tcp dport 8080 accept
    # hosted LLM API, resolved and pinned at build time
    ip daddr @llm_api tcp dport 443 accept
    # everything else is dropped and logged: that is the point
    log prefix "COHAERA-LAB-BLOCKED: " counter drop
  }
}
EOF
sudo systemctl enable --now nftables
```

Every blocked packet is now a log line. An agent trying to reach somewhere it
should not is visible at the network layer, independently of the telemetry.

### Phase 2 · Instrument and smoke test

```bash
pip install "observra[all]"
```

```python
import observra
observra.initialize(backend="jsonl", path="/var/log/observra/run.jsonl")
```

Confirm the exact `initialize()` signature against `docs/getting-started/`
before relying on this. Then tag every run so the corpus is joinable later:

```
run_id · suite · user_task_id · injection_task_id · attempt_n · condition · git_sha
```

That tuple is what turns a pile of JSONL into a dataset.

Smoke test the whole chain end to end:

```bash
PYTHONPATH=src python3 -m cohaera.cli score /var/log/observra/run.jsonl
```

### Phase 3 · Corpus generation

```bash
git clone https://github.com/ethz-spylab/agentdojo.git
git clone https://github.com/usnistgov/agentdojo-inspect.git   # NIST CAISI extension
```

**Do not launch the full matrix.** Four suites by 629 security cases by 25
attempts is a large number of multi-turn agent runs.

1. Run one suite, five scenarios, five attempts.
2. Read the cost from observra's own cost tracking, which is a shipped feature
   and exactly what it is for.
3. Extrapolate. Write the number down.
4. Reduce **scenarios** before you reduce **attempts**. Fewer scenarios at 25
   attempts is defensible; many scenarios at 3 attempts is not.

### Phase 4 · Measure

Paired, within-subject design. Each (user task, injection task) pair runs under
both conditions, same model, same snapshot state.

- **Control:** observra instrumentation only
- **Treatment:** observra plus Cohaera

### Phase 5 · Content pack

Sigma and LogRhythm AIE rules over `cohaera_session_verdict` events, plus the
Exabeam parser field mapping for the nine security fields issue #108 records as
dropped.

---

## Experiment protocol

**25 attempts per scenario.** NIST CAISI found average attack success rate moved
from 57% to 80% between one attempt and 25. A single attempt is not a
measurement.

**Report per-task, not aggregate.** CAISI again: impact varies enormously by
task and aggregates hide it.

**Task-disjoint splits, never random.** MCPShield
([arXiv:2605.11053](https://arxiv.org/abs/2605.11053)) measured that naive
random splits inflate AUROC by **up to 26 points**. If you use random splits
your numbers are wrong and someone will notice. This is no longer advice here:
`eval/harness.py` raises `LeakageError` rather than return a split whose train
and test sides share a task, and the card reports the inflation measured on this
corpus rather than citing someone else's figure for it.

**Fix the model tier.** Praxen's own documentation warns that scores are only
comparable within a fixed model tier. State the model and version explicitly.

**Report effect size, not just p.**

| Metric | Definition | Reported as |
|---|---|---|
| Detection rate (TPR) | deviations flagged / deviations that occurred | per-task, then aggregate |
| False positive rate | benign runs flagged / total benign runs | with confidence interval |
| Utility retention | benign tasks still completed | AgentDojo's own utility score |
| Concealment gap rate | sessions with a consequential call absent from the summary | count and rate |
| Coverage | fraction of checks that could actually run | per session |

---

## Design decisions

**It emits `type` and `schema`, not just `event_type`.** observra issue #108
records that the Exabeam sender emits `event_type` where the published ABA parser
expects `type`, and never emits `schema`, so nothing matches. Cohaera emits all
three.

**It carries the fields the parser drops.** Per #108: `injection_patterns`,
`triggered_rules`, `max_severity`, `source_agent`, `target_agent`,
`current_depth`, `max_depth`, `skill_name`, `has_injection`. Cohaera puts them in
the session verdict where a correlation rule can reach them.

**It prefers observra's own vocabulary** over inventing a parallel taxonomy.

**It reports its own blind spots.** `capture_tool_data` defaults to `False` and
`core/hot_cold.py` strips strings on the hot path, so `tool_result` and
`response_text` are frequently absent. When that happens CH02 returns
`not_evaluated` with a reason and a remedy, rather than returning clean.

**Detection, not prevention.** *The Attacker Moves Second*
([arXiv:2510.09023](https://arxiv.org/abs/2510.09023)) bypassed 12 published
defences at over 90% attack success rate, most of which originally reported near
zero. A detection claim degrades gracefully under an adaptive attacker; a
prevention claim collapses.

---

## Prior work

Two tables, because for a long time there was only one and it cited nine papers
and zero specifications. That imbalance was itself a claim — that the ideas here
came out of research rather than out of decades of security tooling — and it was
the wrong one. [docs/PRIOR-ART.md](docs/PRIOR-ART.md) is the full search, with
what was read marked separately from what was only cited.

| Idea borrowed | Source |
|---|---|
| Two-axis anomaly split: order violation vs semantic drift | TraceAegis, [arXiv:2510.11203](https://arxiv.org/abs/2510.11203) |
| Policy predicates evaluated over execution traces at runtime | C-Trace, [arXiv:2606.19242](https://arxiv.org/abs/2606.19242) |
| Concealment as a distinct dimension of the threat | IPI Arena, [arXiv:2603.15714](https://arxiv.org/abs/2603.15714) |
| Independent utility and security scoring, labelled ground truth | AgentDojo, [arXiv:2406.13352](https://arxiv.org/abs/2406.13352) |
| Per-task ASR across N attempts | NIST CAISI, *Strengthening AI Agent Hijacking Evaluations* |
| Capability labels checked at tool-call time | CaMeL, [arXiv:2503.18813](https://arxiv.org/abs/2503.18813) |
| Attempted privilege expansion as a detection signal | Progent, [arXiv:2504.11703](https://arxiv.org/abs/2504.11703) |
| Task-disjoint evaluation splits | MCPShield, [arXiv:2605.11053](https://arxiv.org/abs/2605.11053) |
| Hash-chained tamper-evident audit trail | AEGIS, [arXiv:2603.12621](https://arxiv.org/abs/2603.12621) |

And the half that is a port rather than a contribution:

| Idea that already existed | Where |
|---|---|
| `not evaluated` as a result value distinct from clean, and from inapplicable | MITRE / CIS OVAL results schema, `ResultEnumeration` |
| Four distinct ways of having no verdict, with `notchecked` excluded from scoring and `unknown` not | XCCDF 1.2, NISTIR 7275 Rev 4 |
| A machine-readable "could not evaluate, because X" on the finding itself | AWS Security Hub `Compliance.Status` and `StatusReasons[].ReasonCode` |
| `UNKNOWN` as a peer of `OK` rather than a variety of it | Nagios, now Monitoring Plugins, exit code 3 |
| A first-class "not known yet" carried alongside the assertions | OpenVEX `under_investigation` |
| A rule declaring the fields it needs in order to mean anything | Elastic Security `required_fields`, `related_integrations` |
| "This rule could not fully run" as an execution state | Elastic `partial failure`; Microsoft Sentinel `SentinelHealth`; Google SecOps rule health |
| A mandatory blind-spots section in every detection | [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework) |
| Data-source quality dimensions rolled into a confidence score | [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) |
| An "insufficient data" verdict on a finding's evidence | OCSF `verdict_id: 7` |
| A card reporting intended use, evaluation data and caveats | Model cards, Mitchell et al., [arXiv:1810.03993](https://arxiv.org/abs/1810.03993) |
| Precision at a realistic base rate as the headline number | Axelsson, the base-rate fallacy, DOI 10.1145/357830.357849 |
| The pitfall list the evaluation card is trying to satisfy | Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, DOI 10.1145/3643456 |
| Abstention as a first-class classifier behaviour | Chow 1970; Geifman and El-Yaniv, [arXiv:1705.08500](https://arxiv.org/abs/1705.08500); Transcend and Transcendent |
| A graded certainty scale for digital evidence | Casey 2002, the C-Scale |
| `verified_prefix` is a **consistency proof** | Crosby and Wallach 2009; RFC 9162 |
| A signed, per-tool declaration of effect, egress and reversibility | [MCP SEP-3140](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3140) |
| Grading a record by how it was obtained | [Agent Action Capsule](https://github.com/action-state-group/agent-action-capsule), the `effect_attestation` and `provenance` registries |

---

## Roadmap

- [x] Session assembly from observra JSONL
- [x] CH01 to CH07
- [x] Coverage reporting
- [x] CIM emit with `type` and `schema`
- [x] Fires on observra's shipped demo data
- [x] Labelled corpus, task families, benign-hard confounders and an evaluation card ([eval/](eval/))
- [ ] AgentDojo corpus under observra instrumentation, 25 attempts per scenario
- [x] Measured TPR and FPR with task-disjoint splits ([eval/](eval/EVALUATION-CARD.md))
- [ ] CH02 semantic matching, currently lexical and its weakest point
- [ ] Praxen Worker Remit compiler, remit sections to runtime predicates
- [x] Sigma content pack, 14 rules, validated and **conformance-tested** ([content/sigma](content/sigma))
- [x] LogRhythm AIE rule specifications ([content/aie](content/aie))
- [x] Exabeam parser field map and #108 analysis ([content/parser](content/parser))
- [x] Tests, 982 passing across unit, hostile-input and content conformance
- [x] Phase 0 verification captured ([docs/PHASE0-VERIFICATION.md](docs/PHASE0-VERIFICATION.md))
- [x] Adversarial self-test, 26 evasions ([EVASION.md](EVASION.md))
- [x] Schema firewall, resource bounds and quarantine ledger
- [x] Typed capability manifests per producer, replacing name heuristics
- [x] Stable verdict, run and config identity for replay and dedup
- [x] Per-check coverage capability contracts (`cohaera.coverage:2`)
- [x] CI with lint, fuzz smoke, Sigma validation, conversion and wheel install
- [x] Eleven defects from the third external review, fixed with regression tests
- [x] Eleven defects from the fourth external review, fixed with regression tests
- [x] Supply chain: SHA-pinned actions, Dependabot, [SECURITY.md](SECURITY.md), [threat model](docs/THREAT-MODEL.md)
- [ ] Static analysis (CodeQL). Configured and clean, but code scanning needs GitHub Code Security on a private personal-account repository, so it was removed rather than left permanently red. Free the moment this repository is public
- [ ] Signed releases with an SBOM attested to the released artefact, not a 90-day CI artefact
- [ ] Cohaera schema 1.0 plus a tested Exabeam exporter and parser package
- [x] Automated VMware Workstation lab build ([lab/](lab/))
- [ ] Streaming state with watermarks, replacing batch load
- [x] Evidence-trust design: wire formats, verification and staging for all three P1 items ([docs/EVIDENCE-TRUST.md](docs/EVIDENCE-TRUST.md))
- [x] Independent effect receipts, so a logged success can be checked — `cohaera.receipt:1`, CH07, and `tools/receipt_adapters.py`. A receipt falsifies a claimed FAILURE; it still does not confirm a success, and nothing reconciles the identifier with the provider that minted it
- [x] Collector-side signing and hash chaining, AEGIS pattern — `cohaera.integrity:1`, CH06, `tools/collector_sign.py`, with key roles, rotation, revocation, freshness and a cross-run ledger
- [x] Approval and policy binding, so a continuation can be called a bypass — `cohaera.approval:1` and the CH04 advisory/blocking split. An in-band approval is reported as a CLAIM, not an authorisation fact
- [ ] Validate content against a live SIEM
- [ ] Build AIE-COHAERA-001 natively and compare against the Cohaera-fed version

---

## Known limitations

Stated up front, because a limitation you declare is a limitation, and one you
hide is a defect.

- **CH02 matching is lexical, not semantic.** An agent that says "I have emailed
  the report" without naming `send_email` reads as a concealment gap. v2 needs an
  LLM judge and will inherit the judge's error rate. C-Trace measured exactly
  this: monitor accuracy is bounded by the field extractor.
- **CH03 proves coexistence, not causation.** It marks sessions for review.
- **CH01 needs a real baseline**, and cannot verify that the baseline is benign.
  A grammar fitted on 12 identical sessions learns 5 transitions and flags
  anything novel. A poisoned corpus defines normal ([EVASION.md](EVASION.md) E03).
- **Tool classification is a keyword guess** unless you supply a capability
  manifest. It has been wrong in both directions in every review round. The
  manifest is the fix; without one, `coverage.classification_confidence` says how
  much of the verdict rests on the guess. MCP's stable schema already carries
  `readOnlyHint`, `destructiveHint`, `idempotentHint` and `openWorldHint`, and
  Cohaera does not read them — they arrive from the server being classified, and
  the schema itself says clients should never make tool use decisions on
  annotations from untrusted servers. Consuming them in band at the same
  precedence as observra's `reversible` flag, with a coverage code of their own,
  is the obvious next step and is not built.
- **The coverage contract is a port, not an invention.** `not evaluated` has
  been a distinct result value in MITRE OVAL's results schema since the 5.x
  line, XCCDF enumerates four different ways of having no verdict, AWS Security
  Hub ships `NOT_AVAILABLE` with a reason code, and a Nagios plugin has exited
  `UNKNOWN` for decades. [docs/PRIOR-ART.md](docs/PRIOR-ART.md) is the search,
  and its last section bounds what is actually new here to three narrow things,
  none of them a research contribution.
- **CH04 cannot distinguish an ignored guardrail from an enforced one unless
  something declares which it is.** With no declaration the session reports
  `POLICY_SEMANTICS_UNDECLARED` and the finding claims only the sequence. With
  one — on the event, or better, in the capability manifest — CH04 splits into a
  bypass it can name and an advisory continuation it stays quiet about. Declaring
  it *on the event* is believing the thing being watched, which suppresses a
  finding and is catalogued as [EVASION.md](EVASION.md) E20; the manifest
  overrides it for exactly that reason.
- **The correlation key comes from the observed system.** Fragment `session_id`
  on call boundaries and every check goes quiet at once. Cohaera can only be
  honest about which key it used, not fix the key.
- **A logged success is still not a verified effect**, and this is the limit that
  moved most. With `cohaera.integrity:1` on the stream, deleting or modifying a
  record is detected rather than noticed by accident; with `cohaera.receipt:1` on
  a call, a reported *failure* contradicted by a real effect is detected. Neither
  makes a reported *success* checkable, and all of it is conditional on a
  producer emitting evidence that today's producers do not. Where the collector
  runs inside the agent's own process, the agent can reach the signing key and
  none of it buys anything — CH06 says so rather than showing a green tick.
  Cohaera remains an assurance control first: it answers "is this agent doing its
  job" well, and "is this agent lying to me" only where somebody outside the
  agent has signed for the answer.
- **The labelled corpus is synthetic and written by the same author as the
  detector.** It is a large improvement on twelve near-identical fixtures — task
  families, task-disjoint splits, an unseen tool vocabulary, and benign-hard
  confounders that are genuinely indistinguishable from the attacks they sit
  next to — and it is still not real agent traffic. Every number in
  [`eval/EVALUATION-CARD.md`](eval/EVALUATION-CARD.md) is an upper bound on a
  lower bound.
- **Most of the false-positive improvement is not a better detector.** The
  headline rate fell from 61.8% to 44.3% when P1 landed, and the largest single
  contributor is CH04 no longer firing on advisory thresholds. CH04 did not get
  cleverer; a field appeared saying whether the control was advisory or blocking,
  and a check that had been reporting a sequence because it could not report a
  bypass stopped having to. The four genuinely new detections — deletion from a
  chained stream, a denied effect contradicted by a receipt, an approval reused
  for different arguments, a stream signed by a revoked key — are all conditional
  on producers emitting evidence they do not emit today.
- **And the current headline is not comparable to that 44.3% either.** The
  trust-store corpus kinds grew the corpus from 1632 sessions per vocabulary to
  1824, so the split and the test population both changed; the rate now reads
  42.0% because a different set of sessions was scored, not because anything got
  better. [EVIDENCE-TRUST §8](docs/EVIDENCE-TRUST.md) states what stage 4 is
  actually entitled to claim, which is one benign row: a correctly performed key
  rotation produces 0 false positives out of 72.

---

## Repository map

```
src/cohaera/          the library, 0 runtime dependencies
  limits.py           every resource bound, and the digest of the set in force
  validate.py         the schema firewall: what a field is allowed to be
  identity.py         correlation keys (HMAC) and stable verdict/run identity
  capabilities.py     exact per-tool capability manifests, and policy semantics
  evidence.py         the P1 sidecars: integrity chain, receipts, approvals
  ed25519.py          RFC 8032 verification, because there are no dependencies
  model.py            Session, ToolCall, Finding, CIM emit
  ingest.py           observra JSONL to Sessions, bounded and quarantining
  checks.py           CH01 to CH07 plus per-check coverage contracts
  cli.py              cohaera score, with exit codes that mean something

content/              detection content
  sigma/              13 validated Sigma rules
  manifest/           example capability manifest
  aie/                LogRhythm AIE specs + correlate-in-SIEM vs upstream comparison
  parser/             Exabeam field map + observra#108 analysis

docs/
  EVIDENCE-TRUST.md        the P1 design, the wire formats, and what they bought
  THREAT-MODEL.md          who this defends against, and who it does not
  PHASE0-VERIFICATION.md   raw command output backing every claim in this README

tests/
  test_cohaera.py     unit tests, no pytest required to run
  test_hostile.py     one regression per reproduced defect: malformed types,
                      resource amplification, correlation forgery, exit codes
  test_content.py     asserts every field the Sigma pack names exists in a real
                      record. Sigma validation cannot check this.
  test_evasion.py     26 adversarial tests that PASS when an evasion works
  test_evidence.py    the P1 mechanisms, attacked: RFC 8032 vectors, forged
                      signatures, deletion, modification, replay, reorder,
                      approval substitution and receipt copying
  fuzz_smoke.py       seeded malformed-input fuzz, runs in CI
  make_fixtures.py    labelled benign and suspect telemetry

.github/workflows/    CI: lint, tests, fuzz, Sigma validation + conversion,
                      wheel build and clean-environment install, SBOM

FINDINGS.md           three source-verified observations against observra v1.1.0
LAB.md                full lab build, VM topology, experiment protocol
```

Run the tests without installing anything:

```bash
PYTHONPATH=src python3 tests/test_cohaera.py     # no pytest needed
PYTHONPATH=src python3 tests/test_evasion.py     # PASS means the evasion works
PYTHONPATH=src python3 tests/fuzz_smoke.py 20000 # seeded, reproducible

PYTHONPATH=src python3 -m pytest tests/ -q       # everything, needs pytest
```

---

## Relationship to the upstream projects

Cohaera is an independent downstream consumer of observra's public JSONL output.
It is **not a fork**, does not modify observra, and has no runtime dependency on
it.

Findings against observra are recorded in [FINDINGS.md](FINDINGS.md) and are
intended for **coordinated disclosure through the upstream `SECURITY.md`**, not
for publication. Search upstream closed issues before reporting anything.

observra, Praxen and socxen are Apache-2.0 projects of the
[Open Agent and AI Security Community](https://github.com/open-agent-ai-security),
sponsored by Exabeam.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
