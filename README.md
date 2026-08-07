<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

<h1 align="center">Cohaera</h1>

<p align="center"><b>The correlation layer for agent telemetry.</b></p>

<p align="center">
  <i>From Latin <b>cohaerere</b>, to hang together.<br/>
  Does the agent's behaviour hang together?</i>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-Apache_2.0-blue.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime_deps-0-brightgreen.svg">
  <img alt="Status" src="https://img.shields.io/badge/status-pre--alpha-orange.svg">
</p>

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
entire job is to break this one. Fifteen constructed evasions, all currently
working, each backed by a test that passes when the evasion succeeds. Read it
before you trust anything else here.

> The first principle is that you must not fool yourself, and you are the
> easiest person to fool.

---

## Contents

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
- [Known evasions](EVASION.md)
- [Relationship to the upstream projects](#relationship-to-the-upstream-projects)

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
        ASM["session assembler<br/>group by session_id, fall back to trace_id"]
        FEAT["feature derivation<br/>tool sequence · call class · timing · cost · depth"]
        GRAM["sequence grammar<br/>bigram model fitted on benign corpus"]
        CHK["CH01 order · CH02 concealment · CH03 taint order<br/>CH04 guardrail overrun · CH05 unpaired"]
        COV["coverage<br/>what could NOT be evaluated, and why"]
        ASM --> FEAT --> GRAM --> CHK --> COV
    end

    subgraph L4["LAYER 4 · ANALYTICS AND SOC"]
        direction LR
        ABA["Exabeam ABA<br/>New-Scale Analytics"]
        AIE["LogRhythm AIE<br/>correlation rules"]
        SIG["Sigma<br/>portable content"]
    end

    L1 ==> L2
    SR ==>|"per-event JSONL · webhook · OTel<br/>the stream that exists today"| L3
    COV ==>|"cohaera_session_verdict<br/>type + schema + triggered_rules + max_severity<br/>ONE record per session"| L4

    style L3 fill:#0f2b46,stroke:#4a9eff,stroke-width:3px,color:#ffffff
    style SR fill:#5a1e1e,stroke:#ff6b6b,color:#ffffff
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
   [CRIT] CH03_untrusted_to_consequential
   [HIGH] CH04_guardrail_overrun: Session continued with consequential actions
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

### Fixture results

| Corpus | Sessions | Findings |
|---|---|---|
| 12 benign fixture sessions, grammar fitted on themselves | 12 | **0** |
| 4 suspect fixture sessions | 4 | 9 across CH01 to CH05 |

Zero false positives on benign is a **smoke test, not a measurement**. The
grammar was fitted on near-identical sessions. Real numbers need the AgentDojo
corpus with task-disjoint splits. That is what the lab below is for.

---

## The checks

| ID | Check | Question it answers | Events needed |
|---|---|---|---|
| **CH01** | `sequence_order` | Does the tool ordering match a grammar mined from benign sessions? | whole session |
| **CH02** | `concealment_gap` | Did a consequential call succeed without appearing in the agent's final message to the human? | tool log + final response |
| **CH03** | `untrusted_to_consequential` | Did a state change follow observed injection markers in the same session? | 2+ ordered |
| **CH04** | `guardrail_overrun` | Did a policy event fire and the session carry on doing consequential work anyway? | 2+ ordered |
| **CH05** | `unpaired_calls` | Did a tool start and never terminate, meaning the session is incompletely observed? | 2 paired |

Plus `coverage()`, which reports **what could not be evaluated and why**. A check
that silently cannot run is a false negative wearing a green tick. observra's own
`examples/siem_parser.json` carries a `telemetry_completeness` field described as
*"Use to weight anomaly detection confidence"*. This is that idea, made concrete
per check.

### Call classification

Every tool call is classified `read_only`, `state_change`, `egress`, or
`unknown`. Egress wins over state change, because data leaving the trust
boundary is the more consequential property for a concealment check. The keyword
sets come from observra's own `schema/cim_schema.toml` rather than a parallel
taxonomy invented here, and observra's `reversible` flag overrides the keyword
guess when present.

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
        G["group by session_id<br/>fall back to trace_id"]
        S["sort by timestamp"]
        P["pair tool_start to terminal<br/>by span_id, then FIFO by name"]
        G --> S --> P
    end

    subgraph OUT["Session object"]
        TC["tool_calls: ToolCall<br/>name · class · result · duration · reversible"]
        SQ["tool_sequence: list of str"]
        MK["injection_markers · policy_events<br/>handoffs · delegation depth · cost"]
        FR["final_response<br/>if the adapter captured it"]
    end

    IN ==> ASM ==> OUT
    OUT ==>|"features()"| V["23-field feature vector<br/>ready for a SIEM"]
```

An unpaired `tool_end` is still recorded rather than discarded, because a
terminal event with no start is itself worth surfacing.

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
PYTHONPATH=src python3 -m cohaera.cli score ~/.observra/telemetry.jsonl \
    --baseline benign-corpus.jsonl > verdicts.jsonl
```

Human summary goes to **stderr**. CIM records go to **stdout** as JSONL, so it
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
your numbers are wrong and someone will notice.

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

---

## Roadmap

- [x] Session assembly from observra JSONL
- [x] CH01 to CH05
- [x] Coverage reporting
- [x] CIM emit with `type` and `schema`
- [x] Fires on observra's shipped demo data
- [ ] AgentDojo corpus under observra instrumentation, 25 attempts per scenario
- [ ] Measured TPR and FPR with task-disjoint splits
- [ ] CH02 semantic matching, currently lexical and its weakest point
- [ ] Praxen Worker Remit compiler, remit sections to runtime predicates
- [x] Sigma content pack, 6 rules, validated ([content/sigma](content/sigma))
- [x] LogRhythm AIE rule specifications ([content/aie](content/aie))
- [x] Exabeam parser field map and #108 analysis ([content/parser](content/parser))
- [x] Unit tests, 32 passing ([tests/test_cohaera.py](tests/test_cohaera.py))
- [x] Phase 0 verification captured ([docs/PHASE0-VERIFICATION.md](docs/PHASE0-VERIFICATION.md))
- [x] Adversarial self-test, 15 evasions ([EVASION.md](EVASION.md))
- [x] Six correctness defects from external review, fixed with regression tests
- [ ] Typed capability manifests per producer, replacing name heuristics
- [ ] Cohaera schema 1.0 plus a tested Exabeam exporter and parser package
- [x] Automated VMware Workstation lab build ([lab/](lab/))
- [ ] Streaming state with watermarks, replacing batch load
- [ ] CH02 semantic matching
- [ ] Validate content against a live SIEM
- [ ] Build AIE-COHAERA-001 natively and compare against the Cohaera-fed version
- [ ] Hash-chained verdict log, AEGIS pattern

---

## Known limitations

Stated up front, because a limitation you declare is a limitation, and one you
hide is a defect.

- **CH02 matching is lexical, not semantic.** An agent that says "I have emailed
  the report" without naming `send_email` reads as a concealment gap. v2 needs an
  LLM judge and will inherit the judge's error rate. C-Trace measured exactly
  this: monitor accuracy is bounded by the field extractor.
- **CH03 proves coexistence, not causation.** It marks sessions for review.
- **CH01 needs a real baseline.** A grammar fitted on 12 identical sessions
  learns 5 transitions and flags anything novel.
- **Tool classification is keyword-based** with observra's `reversible` flag as a
  tiebreak. Unknown-class calls are counted and reported in coverage.
- **Nothing here has been measured against a labelled corpus yet.** The fixture
  numbers are a smoke test.

---

## Repository map

```
src/cohaera/          the library, 0 runtime dependencies
  model.py            Session, ToolCall, Finding, CIM emit
  ingest.py           observra JSONL to Sessions
  checks.py           CH01 to CH05 plus coverage()
  cli.py              cohaera score

content/              detection content
  sigma/              6 validated Sigma rules
  aie/                LogRhythm AIE specs + correlate-in-SIEM vs upstream comparison
  parser/             Exabeam field map + observra#108 analysis

docs/
  PHASE0-VERIFICATION.md   raw command output backing every claim in this README

tests/
  test_cohaera.py     32 unit tests, no pytest required to run
  test_evasion.py     15 adversarial tests that PASS when an evasion works
  make_fixtures.py    labelled benign and suspect telemetry

FINDINGS.md           three source-verified observations against observra v1.1.0
LAB.md                full lab build, VM topology, experiment protocol
```

Run the tests without installing anything:

```bash
PYTHONPATH=src python3 tests/test_cohaera.py
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
