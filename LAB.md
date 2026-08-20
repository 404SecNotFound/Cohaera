<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Cohaera lab build — a design note, not a build record

> ## None of the VMware phases on this page have been executed.
>
> No VM has been created. No corpus has been generated. No measurement
> described below has been taken. What follows is a **design**: a topology, an
> experiment protocol and a cost model, written down so the intent is on the
> record and so that somebody — me later, or you — can run it and report what
> actually happened. Every phase carries its status in the table below and
> again at its own heading. Read the page as a plan.
>
> Three external reviews made the same point, and they were right: shipping an
> unexecuted five-phase build plan beside working code makes a reader discount
> the working code. The plan is kept because it is a real design and it
> documents intent. It is labelled because it is not evidence.
>
> **If you want something that runs today, it is
> [`lab/local/`](lab/local/README.md)** — no VMs, no cloud account, no API key,
> no dependencies, about two seconds, and its output is committed and re-run by
> CI on every push:
>
> ```bash
> python lab/local/run.py --check
> ```

**Constraint set this design is written for:** VMs on a home hypervisor, no GPU,
hosted LLM API keys. Every step respects that.

---

## Status of every phase

Three values only. **Executed** means it has been run and there is a record in
this repository you can re-check. **Partially executed** means some of it has.
**Not built** means nobody has run it and no artefact from it exists.

| Phase | What it would establish | Status |
|---|---|---|
| **0 · Verify the gap** | observra has no correlation or baselining layer | **EXECUTED, off-lab.** Run on 2026-08-07 against observra at `202683a0`, off the lab because this phase needs no VM. The raw output of every command below is captured verbatim in [docs/PHASE0-VERIFICATION.md](docs/PHASE0-VERIFICATION.md), and the findings drawn from it are [FINDINGS.md](FINDINGS.md) F-01 to F-03, each citing a file and a line. **The gate passed**: the gap is real. |
| **1 · Build and segment the VMs** | Network isolation, without which `egress` has no boundary to cross and means nothing | **Not built.** No VM exists. [`lab/Build-CohaeraLab.ps1`](lab/README.md) would build them unattended and has never been run either; its own page says so in its second paragraph. |
| **2 · Instrument and smoke test** | Telemetry travelling from an instrumented agent to a collector to a scoring host | **Not built.** One step of it is reproducible on any machine and is exercised on every CI run: 2.2, which installs Cohaera and scores the generated fixtures. Everything involving observra, AgentDojo or a VM is not. |
| **3 · Generate the corpus** | A labelled corpus of real agent runs under attack | **Not built.** No agent run has been recorded, and `tools/label_corpus.py` — which this page's own step 3.3 calls — does not exist. |
| **4 · Measure** | Detection rate and false positive rate on real traffic, paired, per task | **Not built.** A weaker and entirely different measurement does exist, in [`eval/EVALUATION-CARD.md`](eval/EVALUATION-CARD.md): a synthetic corpus generated from a seed, not agent runs, and the card is explicit about what that does and does not support. Nothing in the protocol below has been executed. |
| **5 · Detection content** | Sigma, AIE and parser content whose rule-level false positive rate has been measured | **Partially executed.** The content exists in `content/` and `tests/test_content.py` asserts every field it references appears in a real verdict record. It has **not** been tested by replaying a labelled corpus, because phase 3 has not run — so its false positive rate is unmeasured. |

## Status of every artefact

| Artefact | Status |
|---|---|
| [`lab/Build-CohaeraLab.ps1`](lab/Build-CohaeraLab.ps1) | **Written, never executed.** No PowerShell interpreter in the environment it was authored in. Its safety properties are asserted against its source as text in `tests/test_lab.py`, which is strictly weaker than running it and strictly stronger than nothing. |
| [`lab/lab.config.psd1`](lab/lab.config.psd1) | **Written, never executed.** The addressing and the `Reachability` matrix are the single source of truth for the topology, and the table further down this page is checked against it by a test. |
| [`lab/local/run.py`](lab/local/run.py) | **Executed. Committed. Re-run by CI on every push**, and byte-identical on CPython 3.10 through 3.13. |
| [`lab/local/runs/latest/`](lab/local/runs/latest/) | **Executed output**, produced by the file above and diffed against a fresh run in CI. |
| `tools/label_corpus.py` | **Does not exist.** Step 3.3 calls it. It is the next thing to build if phase 3 is ever attempted. |
| `content/sigma`, `content/aie`, `content/parser` | **Exist, conformance-tested, not corpus-tested.** See phase 5. |

---

## Contents

- [Status of every phase](#status-of-every-phase)
- [Before you start](#before-you-start)
- [Hardware and hypervisor](#hardware-and-hypervisor)
- [Phase 0 · Verify the gap](#phase-0--verify-the-gap)
- [Phase 1 · Build and segment the VMs](#phase-1--build-and-segment-the-vms)
- [Phase 2 · Instrument and smoke test](#phase-2--instrument-and-smoke-test)
- [Phase 3 · Generate the corpus](#phase-3--generate-the-corpus)
- [Phase 4 · Measure](#phase-4--measure)
- [Phase 5 · Detection content](#phase-5--detection-content)
- [Cost control](#cost-control)
- [Troubleshooting](#troubleshooting)
- [Safety and scope](#safety-and-scope)

---

## Before you start

None of this is needed to exercise Cohaera. It is needed to answer questions
about **network isolation** and about **real agent traffic**, and nothing else
on this page or in this repository can answer those. If that is not the question
you have, close this file and run
[`python lab/local/run.py`](lab/local/README.md).

| Prerequisite | Detail |
|---|---|
| Hypervisor | Proxmox VE, ESXi, Hyper-V or VirtualBox. Any will do. |
| Host resources | 16 vCPU and 48 GB RAM total across the four VMs. 12 GB RAM works if you drop `siem-01` until phase 5. |
| Disk | 440 GB total. Corpus JSONL is the bulk of it. |
| API key | Anthropic or OpenAI, with a **hard spend cap already set** at the provider. |
| Time | Roughly 5 evenings plus 1 weekend of mostly unattended runtime. |

**Read this first:** phase 0 is a gate. If it fails, the project rescopes. Do not
build VMs before running it.

---

## Hardware and hypervisor

| VM | Role | vCPU | RAM | Disk | Network |
|---|---|---:|---:|---:|---|
| `agent-01` | Runs the instrumented agent and AgentDojo suites | 4 | 8 GB | 40 GB | NAT + 10.10.10.10/24 (generation), egress allowlisted |
| `collector-01` | observra webhook receiver, OTel collector, JSONL archive | 2 | 4 GB | 100 GB | 10.10.10.20/24 (generation) **and** 10.10.20.10/24 (collection) |
| `analysis-01` | Cohaera, corpus labelling, scoring | 4 | 16 GB | 100 GB | 10.10.20.30/24 (collection), no internet |
| `siem-01` | Rule authoring and replay. Phase 5 only. | 4 | 16 GB | 200 GB | 10.10.30.10/24 (analysis) |

> **These addresses are the ones in `lab/lab.config.psd1`, and that file is the
> only place they are decided.** R-08: this table used to describe a different
> lab — collector on 10.10.20.10 alone, analysis on 10.10.30.10, SIEM on
> 10.10.40.10 — and the commands below followed it. An operator working from
> this page configured endpoints the built lab does not have, watched a
> scenario produce nothing, and had no way to tell a broken network from a
> detector that declined to fire. Two addresses that disagree are worse than
> one address that is wrong.
>
> **Why the collector has two.** It is the boundary between generation and
> collection, and a boundary needs a foot on each side. `agent-01` ships
> telemetry to **10.10.10.20**, the generation-side address — it has no route
> to the collection segment and must not have one. `analysis-01` pulls from
> **10.10.20.10**, the collection-side address. IP forwarding is off on the
> collector, so nothing reaches through it; the archive is handed across, not
> routed across.

Base image: Ubuntu Server 24.04 LTS on all four. Ubuntu 22.04 also works.

### Why the segmentation matters

This is the part people skip, and skipping it invalidates the results.

CH02 and CH03 classify tool calls as `egress`. **If `agent-01` can reach the
whole internet, "egress" stops meaning anything**, because there is no boundary
for data to cross. The network policy is not hardening around the experiment, it
is part of the instrument.

Likewise `analysis-01` having no route back to `agent-01` is not paranoia. It
stops a labelled corpus being accidentally contaminated by a run that reached
back into the analysis host.

---

## Phase 0 · Verify the gap

> **Status: EXECUTED, off-lab.** This is the one phase that needs no lab. It was
> run on 2026-08-07 against observra at commit `202683a0`, v1.1.0, and the raw
> output of the commands below is captured verbatim in
> [docs/PHASE0-VERIFICATION.md](docs/PHASE0-VERIFICATION.md) so anyone can
> re-run them and compare. The findings drawn from it are
> [FINDINGS.md](FINDINGS.md) F-01 to F-03.
>
> **The gate passed**: no behavioural analytics, a single-event rule engine,
> `detect_suspicious_sequence` unreachable, and injection scanning nowhere near
> `tool_result`. Upstream moves — re-run against a current checkout before
> quoting any of it.

**Time: 1 evening. This is a gate.**

The central claim is that observra has no correlation or baselining layer. Prove
it from source before building anything on top of it.

```bash
git clone --depth 1 https://github.com/open-agent-ai-security/observra.git
cd observra
```

### 0.1 Is there any behavioural analytics?

```bash
grep -ril -E 'baseline|anomal|deviation|drift|zscore|percentile|outlier' src/ | grep -v test
find . -iname '*analytic*' -o -iname '*detect*' -o -iname '*profil*'
```

Expected at HEAD 2026-08-06: hits only in `core/metrics.py` and
`observability.py`, both computing percentiles of
`observra_write_latency_seconds`, which is the telemetry writer measuring its own
disk I/O. Nothing about agent behaviour.

### 0.2 Is the rule engine really single-event?

```bash
grep -n "def evaluate_rules" src/observra/core/rules.py
```

Expected: `def evaluate_rules(event_type: str, data: dict)`. One event type, one
data dict. No session, no history, no state.

### 0.3 Is `detect_suspicious_sequence` ever called?

```bash
grep -rn "detect_suspicious_sequence" . --include='*.py'
```

Expected: exactly one hit, the definition at `src/observra/core/sequences.py:73`.
If that is still the case, the `"Suspicious Tool Sequence"` rule in `rules.py`
cannot fire.

### 0.4 Where does injection scanning actually run?

```bash
grep -rn "detect_injection_patterns(" src/observra --include='*.py' | grep -v /tests/
```

Expected: four call sites, all receiving user input
(`adapters/adk/plugin.py:240`, `adapters/litellm/adapter.py:87`,
`log.py:452`, `log.py:502`). None receiving `tool_result`.

### 0.5 Read the architecture

```bash
cat docs/architecture.md docs/event-schema.md
grep -n "capture_tool_data" -r src/ | head
sed -n '1,40p' src/observra/core/hot_cold.py
```

The pipeline is `CIM normalization → dedup → redaction → cost`. Note that
`capture_tool_data` defaults to `False` and `hot_cold.py` strips string values on
the hot path. Both matter for CH02.

### Gate

- **Gap confirmed** → continue to phase 1.
- **Baselining code found** → stop. Rescope from "the analytics layer is missing"
  to "detection content on top of existing analytics", and update FINDINGS.md
  before going further.

Record the raw output. It converts the strongest claim in the project from an
inference into evidence.

---

## Phase 1 · Build and segment the VMs

> **Status: NOT BUILT.** No VM has been created and none of the commands below
> has been run. The nftables ruleset, the audit rules and the verification gate
> are a design. `lab/Build-CohaeraLab.ps1` automates most of this and has not
> been run either.

**Time: 1 evening.**

### 1.1 Base install, all four VMs

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3.11-venv python3-pip git jq curl \
                    auditd nftables tmux
python3.11 -m venv ~/venv
echo 'source ~/venv/bin/activate' >> ~/.bashrc
source ~/venv/bin/activate
```

### 1.2 Network segmentation on `agent-01`

Resolve and pin the LLM API addresses at build time, then allowlist them.

```bash
# resolve once, pin the result
dig +short api.anthropic.com | tee /tmp/llm_ips
```

```bash
sudo tee /etc/nftables.conf > /dev/null << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  set llm_api {
    type ipv4_addr
    flags interval
    # populate from /tmp/llm_ips, re-check periodically as CDNs rotate
    elements = { 160.79.104.0/23 }
  }

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    ip saddr 10.10.0.0/16 tcp dport 22 accept
  }

  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oif "lo" accept

    # DNS to the lab resolver only
    ip daddr 10.10.10.1 udp dport 53 accept

    # telemetry to the collector
    ip daddr 10.10.10.20 tcp dport 8080 accept

    # hosted LLM API
    ip daddr @llm_api tcp dport 443 accept

    # everything else: drop AND log. This is the point of the exercise.
    log prefix "COHAERA-LAB-BLOCKED: " level warn counter drop
  }
}
EOF

sudo systemctl enable --now nftables
sudo nft list ruleset | head -30
```

Every blocked packet now produces a syslog line. An agent trying to reach
somewhere it should not is visible at the network layer, independently of
whatever the telemetry says. That independence is worth a lot when you are
arguing about whether a detection is real.

### 1.3 Host-level audit on `agent-01`

Gives you the effect side to pair against the intent side, which is the
AgentSight boundary-tracing idea ([arXiv:2508.02736](https://arxiv.org/abs/2508.02736))
without writing any eBPF.

```bash
sudo tee -a /etc/audit/rules.d/cohaera.rules > /dev/null << 'EOF'
-a always,exit -F arch=b64 -S execve -k cohaera_exec
-a always,exit -F arch=b64 -S connect -k cohaera_net
-w /tmp -p wa -k cohaera_write
-w /home -p wa -k cohaera_write
EOF
sudo augenrules --load && sudo systemctl restart auditd
```

### 1.4 Snapshot

```bash
# Proxmox example
qm snapshot 101 clean-baseline --description "pre-run, phase 1 complete"
```

**Restore to this snapshot between run sets.** Run-to-run comparability depends
on it, and a research audience will ask.

### 1.5 Verification gate

```bash
# from agent-01: should SUCCEED
curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/v1/messages
nc -zv 10.10.10.20 8080   # the collector's GENERATION-side address

# from agent-01: should FAIL. The agent has no business on the
# collection segment, and if it can reach it the boundary is decorative.
nc -zv -w2 10.10.20.10 8080 ; echo "exit=$?"

# from agent-01: should FAIL and appear in the log
curl -m 5 https://example.com ; echo "exit=$?"
sudo journalctl -k | grep COHAERA-LAB-BLOCKED | tail -3

# from analysis-01: should FAIL (no route to agent-01)
ping -c1 -W2 10.10.10.10 ; echo "exit=$?"
```

Do not proceed until the blocked case is actually blocked and actually logged.

These are the same properties the builder's `verify` stage now asserts from the
`Reachability` matrix in `lab.config.psd1` (COH-R18), so once phase 2 is done
`.\Build-CohaeraLab.ps1 -Stage verify` should come back clean — and will fail
the run if it does not. Run it by hand here anyway: the kernel-log half above
is the part the probes do not check, and a blocked packet nobody logged is a
control you cannot audit after the fact.

---

## Phase 2 · Instrument and smoke test

> **Status: NOT BUILT, except 2.2.** Nothing has been installed on a VM, no
> telemetry has been shipped anywhere and the gate at 2.5 has never been run.
> **Step 2.2 is the exception**: installing Cohaera and scoring the generated
> fixtures needs no lab, runs anywhere, and is exercised on every CI run
> against a wheel installed into a clean virtualenv. Its expected output below
> is checked by `tests/test_lab.py`.

**Time: 2 hours.**

### 2.1 Install on `agent-01`

```bash
pip install "observra[all]"
git clone https://github.com/ethz-spylab/agentdojo.git
git clone https://github.com/usnistgov/agentdojo-inspect.git
```

### 2.2 Install Cohaera on `analysis-01`

**This step needs no lab.** It is the one thing on this page you can run right
now, and the fastest way to tell whether the detector is working at all.

```bash
git clone https://github.com/404SecNotFound/Cohaera.git && cd Cohaera
python3 tests/make_fixtures.py
PYTHONPATH=src python3 -m cohaera.cli score tests/fixtures/suspect.jsonl \
    --baseline tests/fixtures/benign.jsonl
```

Seven findings across four suspect sessions, zero on the twelve benign ones.
If that reproduces, Cohaera is working. `tests/test_lab.py` derives both counts
from the fixtures and fails if this page disagrees with them, because a number
in the documentation that nothing keeps true is the one defect this repository
cannot afford.

For the evidence path — signing, trust stores, freshness, the ledger, and what
the checks say when a prerequisite is missing — run the local lab instead. It
is a superset of this step and takes about two seconds:

```bash
python lab/local/run.py --check
```

### 2.3 Wire the telemetry

```python
import observra

observra.initialize(backend="jsonl", path="/var/log/observra/run.jsonl")
```

**Confirm the exact `initialize()` signature against `docs/getting-started/`
before relying on this.** The README shows the JSONL form, and constructs
`MultiBackend` directly in Python rather than through a config dict. Fan-out to
the collector as well once the single-backend case works.

For CH02 you need the text surfaces, which are off by default:

```python
# lab only. Never in production: this captures tool results verbatim.
plugin = observra.create_plugin("claude", capture_tool_data=True)
```

### 2.4 Tag every run

Wrap each run so the corpus is joinable later. Emit this tuple with every
session:

```
run_id · suite · user_task_id · injection_task_id · attempt_n · condition · model · git_sha
```

`condition` is `control` (observra only) or `treatment` (observra plus Cohaera).
That tuple is what turns a pile of JSONL into a dataset.

### 2.5 End-to-end smoke test

```bash
# on agent-01: one scenario, one attempt
python -m agentdojo.scripts.benchmark --suite workspace --limit 1

# ship it
scp /var/log/observra/run.jsonl analyst@10.10.20.30:~/corpus/smoke.jsonl

# on analysis-01
PYTHONPATH=src python3 -m cohaera.cli score ~/corpus/smoke.jsonl
```

**Gate:** the coverage report should show CH02 as evaluated, not
`not_evaluated`. If it says "No response_text on any model_response", the text
capture is not wired up and CH02 will be blind for the whole corpus. Fix it now,
not after a weekend of runs.

---

## Phase 3 · Generate the corpus

> **Status: NOT BUILT.** No agent run has been recorded, no API spend has been
> incurred, and the calibration gate at 3.1 has never been executed. Step 3.3
> calls `tools/label_corpus.py`, **which does not exist**. Everything below is
> the plan, including the cost discipline, which is the part most worth keeping.

**Time: 1 weekend, mostly unattended. This phase has a cost gate.**

### 3.1 Calibrate before committing

**Do not launch the full matrix.** Four suites by 629 security cases by 25
attempts is a large number of multi-turn agent runs.

```bash
# step 1: one suite, five scenarios, five attempts
python -m agentdojo.scripts.benchmark --suite workspace --limit 5 --attempts 5
```

```bash
# step 2: read the actual spend from observra's own cost tracking
jq -s 'map(.data.session_cost_usd // empty) | add' /var/log/observra/run.jsonl
```

Step 3: extrapolate to the full matrix. **Write the number down.**

Step 4: decide what you can afford, then **reduce scenarios before you reduce
attempts**. Fewer scenarios at 25 attempts is a defensible result. Many scenarios
at 3 attempts is not, per the NIST CAISI finding that average attack success rate
moves from 57% to 80% between 1 attempt and 25.

### 3.2 Run

```bash
tmux new -s corpus
for suite in workspace banking travel slack; do
  for attempt in $(seq 1 25); do
    python -m agentdojo.scripts.benchmark \
      --suite "$suite" \
      --attempts 1 \
      --output "/var/log/observra/${suite}-a${attempt}.jsonl"
  done
done
```

### 3.3 Label

Each AgentDojo test is a (user task, injection task) pair and the harness scores
utility and security independently. Join the harness verdict back onto the
session by `run_id` to produce the ground truth column.

```bash
python3 tools/label_corpus.py \
  --telemetry /var/log/observra/ \
  --harness-results agentdojo-results/ \
  --out ~/corpus/labelled.jsonl
```

`tools/label_corpus.py` is not written yet. It is the next thing to build.

---

## Phase 4 · Measure

> **Status: NOT BUILT.** No paired comparison has been run, no statistic below
> has been computed, and there is no number anywhere in this repository that
> came from this protocol.
>
> **Do not read the shipped evaluation as this phase's output.**
> [`eval/EVALUATION-CARD.md`](eval/EVALUATION-CARD.md) measures the detector
> against a **synthetic corpus generated from a fixed seed** — not agent runs,
> not AgentDojo, no control-versus-treatment pairing and no model in the loop.
> It is the honest number this project has, it is considerably less flattering
> than the local lab looks, and it is a different measurement from the one
> designed here.

**Time: 2 evenings.**

### Design

Paired, within-subject. Each scenario runs under both conditions with the same
model, same snapshot state.

- **Control:** observra instrumentation only
- **Treatment:** observra plus Cohaera

### Rules, and why each one is there

| Rule | Source | Consequence of ignoring it |
|---|---|---|
| 25 attempts per scenario | NIST CAISI: average ASR moved 57% to 80% from 1 to 25 attempts | A single attempt is not a measurement |
| Report per-task, not aggregate | NIST CAISI: impact varies enormously by task | Aggregates hide the tasks that matter |
| Task-disjoint splits, never random | MCPShield [arXiv:2605.11053](https://arxiv.org/abs/2605.11053): random splits inflate AUROC by up to 26 points | Your numbers are wrong and someone will notice |
| Fix the model tier | Praxen's own documentation: scores comparable only within a fixed tier | Cross-tier comparisons are meaningless |
| Report effect size, not just p | Standard practice | A significant result with a trivial effect is not a result |

### Metrics

| Metric | Definition | Reported as |
|---|---|---|
| Detection rate (TPR) | deviations flagged / deviations that occurred | per-task, then aggregate |
| False positive rate | benign runs flagged / total benign runs | with confidence interval |
| Utility retention | benign tasks still completed | AgentDojo's own utility score |
| Concealment gap rate | sessions with a consequential call absent from the summary | count and rate |
| Coverage | fraction of checks that could actually run | per session |

### Statistics

Paired test across scenarios. Wilcoxon signed-rank if normality fails, which it
usually does on attack-success-rate data. **Pre-register the number of scenarios
before running**, so the analysis is not fishing.

---

## Phase 5 · Detection content

> **Status: PARTIALLY EXECUTED.** All three artefacts exist in `content/`, and
> `tests/test_content.py` asserts that every field the Sigma pack references
> appears in a real verdict record — so the content cannot reference a field the
> detector does not emit. CI additionally validates the rules with `sigma check`
> and converts them to a Splunk backend, which proves a backend can turn them
> into a query.
>
> **What has not happened is the last line of this section.** No rule has been
> replayed against a labelled corpus, because phase 3 has not run, so the
> rule-level false positive rate is **unmeasured**. A rule that validates,
> converts and has never been fired at real traffic is content, not a detection.

**Time: 2 evenings.**

Three artefacts, all over `cohaera_session_verdict` events:

1. **Sigma rules** in `content/sigma/`, portable across platforms.
2. **LogRhythm AIE correlation rules** in `content/aie/`.
3. **Exabeam parser field mapping** in `content/parser/`, covering the nine
   security fields observra issue #108 records as dropped by the published ABA
   parser: `has_injection`, `injection_patterns`, `current_depth`, `max_depth`,
   `source_agent`, `target_agent`, `skill_name`, `triggered_rules`,
   `max_severity`.

Test by replaying the phase 3 corpus and measuring the rule-level false positive
rate against the labels.

---

## Cost control

The single biggest way to waste money here is a runaway agent loop.

1. **Set a hard spend cap at the API provider before the first run.** Not a
   budget alert, a hard cap.
2. **Use observra's own cost tracking.** It is a shipped feature and this is
   exactly what it is for. `cost_threshold_exceeded` fires and Cohaera's CH04
   tells you whether the run kept going afterwards.
3. **Calibrate on one suite first.** See 3.1.
4. **Cap tokens per run** in the agent config.
5. **Watch for the guardrail overrun pattern in your own lab.** If CH04 fires on
   your own runs, your cost controls are producing log lines and not stopping
   anything. That is worth knowing before the bill arrives.

Unbounded consumption is LLM10 in the OWASP Top 10 for LLM Applications, and it
applies to your own lab as much as to production.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| CH02 always `not_evaluated` | `response_text` absent | Text capture not wired. See 2.3. `hot_cold.py` strips strings on the hot path and `response_text` is a claude-adapter extra. |
| `tool_results_captured: 0` | `capture_tool_data` defaults to `False` | Set it `True`, lab only. |
| CH01 never fires | Grammar not fitted | Pass `--baseline`. Without it CH01 returns nothing and coverage says so. |
| CH01 fires on everything | Baseline too narrow | A grammar fitted on near-identical sessions learns very few transitions. Fit on real variety. |
| Many `unknown_class_count` | Tool names not matching the keyword sets | Extend the classification map in `model.py`. Coverage reports the count. |
| Sessions split across files | Grouping by file rather than `session_id` | Cohaera groups by `session_id` across all input. Concatenate the files. |
| Everything blocked on `agent-01` | LLM API IPs rotated | Re-resolve and update the nftables set. CDN ranges move. |
| Cohaera reports 0 events | JSONL malformed | Cohaera prints a line number for every malformed record rather than dropping silently. Read stderr. |

---

## Safety and scope

This is defensive control validation on open-source software, in an isolated
lab, against a public academic benchmark built for exactly this purpose.

- **All targets are your own VMs** or AgentDojo's **simulated** tool suites.
  Nothing external is touched.
- **No attack payloads are stored in this repository.** The fixture generator
  emits observra's pattern *names* (for example `INSTRUCTION_OVERRIDE`), which is
  what the real pipeline records after classification. No prompt text is
  reproduced.
- **Do not point socxen at real alerts.** Its own README says so: do not rely on
  it for production SOC operations or point it at alerts whose disposition
  matters without a human reviewing every action. Staging only, with sign-off.
- **Findings against upstream go through `SECURITY.md`.** Coordinated
  disclosure, not a demo slide. Doing that correctly will impress a threat
  research audience considerably more than the finding itself.
- **Search upstream closed issues before reporting anything.** Being second is
  fine. Presenting something already tracked as a discovery is not.
