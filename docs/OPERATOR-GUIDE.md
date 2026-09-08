<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Operator guide

This guide takes you from a clean checkout to understanding the data path,
running the labs, reading a verdict, and scoring your own telemetry. It is the
shortest route to being able to demonstrate Cohaera without relying on the
README's claims.

## The mental model

Cohaera is a passive command-line analyser:

```text
JSONL events
  -> bounded reader and schema firewall
  -> quarantine invalid records
  -> correlate events into sessions
  -> derive tool calls, sequences, effects, controls, and handoffs
  -> assess signatures, chains, receipts, approvals, and replay state
  -> run CH01-CH07
  -> emit one JSONL session verdict plus human stderr
```

Three distinctions matter throughout the project:

1. **Observed is not trusted.** A valid JSON field is still a producer claim
   unless independent evidence supports it.
2. **No finding is not clean.** Read each check's coverage status before
   interpreting silence.
3. **Attempted is not completed.** A tool start, a terminal failure, and a
   receipt-backed effect are different facts.

## 1. Reproduce the executed local lab

From the repository root:

```bash
python3 lab/local/run.py --check
```

Expected shape:

```text
lab/local: 6 states, 3 ledger passes and 3 coverage-contract pairs match the committed manifest (...s, python 3.x)
```

Read the compact report:

```bash
cat lab/local/runs/latest/RESULTS.md
```

Do not begin with the four-VM lab. It has not been executed. The local lab is
the reproducible foundation and covers the complete implemented evidence path.

### What to be able to explain

After this step, explain these rows without notes:

- `01-normal`: no bundled finding and complete signed evidence;
- `02-behaviour-change`: untrusted content followed by a completed state
  change;
- `03-evidence-failure`: the record itself is inadmissible;
- `04-contradiction`: a reported failure conflicts with an effect receipt;
- `04b-unbound-receipt`: a receipt exists but is not fully bound;
- `05-partial-attestation`: signatures cover a prefix rather than the complete
  stream.

## 2. Inspect the input and output

The lab keeps its exact inputs and verdicts:

```bash
head -n 1 lab/local/runs/latest/inputs/02-behaviour-change.jsonl \
  | python3 -m json.tool

head -n 1 lab/local/runs/latest/verdicts.jsonl \
  | python3 -m json.tool
```

JSONL files may contain several records. Repeat with `sed -n '2p'`, `3p`, and
so on to inspect later lines without treating the whole file as one JSON value.

In a verdict, find these fields in this order:

1. `session_id`, `agent_name`, `trace_id`, and `verdict_id` identify the unit
   being investigated.
2. `data.tool_sequence`, counts, handoffs, cost, and timing describe the
   reconstructed activity.
3. `data.findings` contains the notices and their supporting evidence.
4. `data.coverage.evidence_status` states the overall evidence condition.
5. `data.coverage.checks` states whether each check ran and why it degraded or
   declined.
6. `data.provenance` records the detector version, configuration, input,
   manifests, trust store, and ledger state used.

## 3. See coverage change with one operator input

Score the same signed session first without and then with a capability
manifest. Keep stdout and stderr separate:

```bash
PYTHONPATH=src python3 -m cohaera.cli score \
  lab/local/runs/latest/inputs/06-no-manifest.jsonl \
  --trust-store lab/local/runs/latest/inputs/trust-store.json \
  --evidence-max-age 86400 \
  --evidence-as-of 1785720000 \
  > /tmp/cohaera-without-manifest.jsonl \
  2> /tmp/cohaera-without-manifest.txt

PYTHONPATH=src python3 -m cohaera.cli score \
  lab/local/runs/latest/inputs/06-no-manifest.jsonl \
  --trust-store lab/local/runs/latest/inputs/trust-store.json \
  --tool-manifest lab/local/runs/latest/inputs/capability-manifest.json \
  --evidence-max-age 86400 \
  --evidence-as-of 1785720000 \
  > /tmp/cohaera-with-manifest.jsonl \
  2> /tmp/cohaera-with-manifest.txt

diff -u /tmp/cohaera-without-manifest.txt /tmp/cohaera-with-manifest.txt
```

The manifest is operator-supplied context. It tells Cohaera what exact tool IDs
can change state, cross an egress boundary, or perform irreversible work.
Without it, name heuristics can leave a call unknown and several checks must
degrade. The correct result is a visible coverage gap.

## 4. Attack the evidence checker

Run the CH06 matrix:

```bash
python3 lab/ch06/run.py --check
cat lab/ch06/runs/latest/RESULTS.md
```

Open the cases beside the pristine signed stream:

```bash
diff -u \
  lab/ch06/fixtures/source/canonical.signed.jsonl \
  lab/ch06/fixtures/cases/modified.jsonl

diff -u \
  lab/ch06/fixtures/source/canonical.signed.jsonl \
  lab/ch06/fixtures/cases/deleted.jsonl
```

Be able to distinguish:

- deletion from modification;
- benign record delivery reordering from a sequence gap;
- a verified prefix from a complete stream;
- a replay from a fork;
- a chained stream from a signature checked against an authorised public key.

The expectations are hand-written in `lab/ch06/expectations.json`. The runner
does not generate them, and both implementations parse the committed case
bytes.

## 5. Run the two narrative demos

```bash
python3 demo/phantom-guardrail/run.py
python3 demo/approval-replay/run.py
```

The first shows an agent citing a control that does not exist. The second shows
why an approval needs exact action binding, expiry, and replay state.

Treat the demos as explanations of a failure mode. Treat the labs as the
reproducible evidence that a declared input produces a declared result.

## 6. Score your own trace

Cohaera currently consumes observra-shaped JSONL. Start with a copy of a lab
input and replace records incrementally so schema problems are easy to locate.

Install the CLI:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Minimum run:

```bash
cohaera score my-agent.jsonl \
  --reject-log my-agent-rejected.jsonl \
  --max-reject-ratio 0.01 \
  > my-agent-verdicts.jsonl
```

At this stage, expect degraded or `not_evaluated` checks. Add inputs one at a
time:

1. a benign baseline for CH01;
2. a capability manifest for exact tool semantics;
3. a correlation secret for anonymous-session keys;
4. collector signatures and a trust store for CH06;
5. a freshness window and retained stream ledger for replay;
6. effect receipts for CH07;
7. signed approvals and the approval ledger for blocking-control conclusions.

Full lab-style run:

```bash
export COHAERA_CORRELATION_SECRET='replace-with-a-lab-secret'

cohaera score my-agent.jsonl \
  --baseline my-benign.jsonl \
  --tool-manifest my-capabilities.json \
  --trust-store my-trust-store.json \
  --seen-streams my-seen-streams.json \
  --seen-approvals my-seen-approvals.json \
  --evidence-max-age 3600 \
  --reject-log my-agent-rejected.jsonl \
  --max-reject-ratio 0.01 \
  > my-agent-verdicts.jsonl
```

Do not add a trust store merely to remove a warning. It is a security input: it
names keys and the roles they are authorised to attest. The reference signing
tools under `tools/` are for controlled tests and format integration.

## 7. Triage a verdict

Use this order during an investigation:

1. **Ingest:** Were records rejected or accepted with field defects? If output
   is incomplete, stop drawing session conclusions.
2. **Correlation:** Did the session use a producer ID, trace ID, or a weak
   anonymous fallback?
3. **Evidence:** Is the status complete, prefix-only, chained without a checked
   signature, unattested, or inadmissible?
4. **Coverage:** Which checks were evaluated, degraded, or not evaluated, and
   which reason codes explain that state?
5. **Findings:** Which exact records support the notice, and does it describe
   an attempt, a completed effect, or a contradiction?
6. **Provenance:** Which baseline, manifest, trust store, freshness setting,
   and ledger state produced this answer?
7. **Source data:** Return to the raw records before escalating. A derived
   verdict is an index into evidence, not a replacement for it.

## 8. Follow the code path

Read these files in order:

| File | Responsibility |
|---|---|
| `src/cohaera/cli.py` | arguments, file handling, outputs, and exit codes |
| `src/cohaera/ingest.py` | bounded JSONL reading, validation, quarantine, session assembly |
| `src/cohaera/model.py` | immutable session, call, feature, coverage, and verdict types |
| `src/cohaera/capabilities.py` | exact tool semantics and policy declarations |
| `src/cohaera/evidence.py` | chains, signatures, receipts, approvals, trust, ledgers |
| `src/cohaera/checks.py` | CH01–CH07 and their coverage contracts |
| `src/cohaera/limits.py` | resource bounds applied to hostile input |
| `src/cohaera/identity.py` | correlation, stable run identity, and deduplication keys |

Then read one vertical slice: choose a finding in `checks.py`, find its model
fields, find the ingest path that populates them, and find its attack, benign,
missing-input, and evasion tests.

## 9. Verify before a change or demonstration

Run the two fast contracts while editing:

```bash
python3 lab/local/run.py --check
python3 lab/ch06/run.py --check
```

Run the full CI-equivalent verifier before a pull request or demonstration:

```bash
python3 tools/verify.py
```

A complete result reports every gate passed with none failed or not evaluated.
This includes tests, lint, type checking, fuzzing, Sigma validation and
conversion, content conformance, evaluation-card reproduction, labs, release
consistency, performance, and clean wheel installation.

## 10. Prepare the threat-research walkthrough

The walkthrough should demonstrate four things in this order:

1. a normal session with no findings and explicit coverage;
2. a deterministic security finding with its supporting records;
3. a tampered or incomplete stream that changes evidence admissibility;
4. a missing prerequisite that produces `not_evaluated` rather than a clean
   answer.

Then present the weak result: the current behavioural false-positive rate and
the external corpus on which no detection fired. That keeps the discussion on
the research questions Cohaera can answer next rather than on a product claim
the evidence does not support.

Use [DIRECTION.md](DIRECTION.md) for the proposed record model and delivery
gates, [THREAT-MODEL.md](THREAT-MODEL.md) for trust boundaries, and
[../eval/EVALUATION-CARD.md](../eval/EVALUATION-CARD.md) for current measured
performance.
