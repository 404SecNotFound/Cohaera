<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# External validation

**The question this answers:** Cohaera's entire evaluation runs on a synthetic
corpus written by the detector's own author. What can be validated against
somebody else's data, what cannot, and how do I run it?

**The short answer:** three of the seven checks can be validated externally
today. One partially. Three cannot be validated externally *at all* — not
"not yet", but *not by any public corpus that exists*, because the evidence
they read is produced by a control plane and no public agent-trace corpus has
one.

Nothing in this page reports a detection result. No external corpus has been
scored yet — the data could not be downloaded from the network this harness was
built on. What is delivered is the harness, the adapters, the scope statement
and the runbook, plus what was verified about each corpus along the way.

---

## 1. The scope statement

This is the part the README currently understates. Today the README folds
external validation into a general "the corpus is synthetic" caveat, which
reads as a task merely undone. For three checks that is not the situation.

| check | externally validatable? | why |
|---|---|---|
| `CH01_sequence_order` | **yes** | Needs a benign baseline, tool lifecycle, correlation key. A trace corpus supplies the lifecycle; its own benign split fits the baseline. |
| `CH02_concealment_gap` | **yes** | Needs a final response and tool class. Both target corpora carry a final agent response. |
| `CH03_untrusted_to_consequential` | **partial** | Needs injection-scanner evidence, which no public corpus produces. Reachable only where a corpus annotates the step at which content the agent did not author entered the trajectory — StepShield does, behind an explicit opt-in; ATBench does not. |
| `CH04_guardrail_overrun` | **no** | Needs policy semantics and approval binding. No public corpus records the decisions of a policy engine or approvals bound to call arguments. |
| `CH05_unpaired_calls` | **yes** | Needs tool lifecycle and a correlation key. Any corpus with tool calls has both. |
| `CH06_evidence_integrity` | **no** | Needs a signed or hash-chained event stream. Corpora ship as JSON files: no collector signature to verify, no sequence to break. |
| `CH07_effect_contradiction` | **no** | Needs provider effect receipts. Nothing public attests that a call reached an authority, so there is no claimed effect to contradict. |

**The three that cannot be validated are not a random three.** CH04 and CH06
are the two the project's positioning leans on hardest, precisely because they
read the control plane rather than the agent's own chatter. That is also
exactly why no public corpus carries their evidence: these benchmarks are
generated or replayed traces, and the artefacts CH04, CH06 and CH07 consume are
emitted by the surrounding system, not by the agent.

Collecting a corpus that could validate them means instrumenting a real
deployment — a policy engine that logs its decisions, approvals bound to
arguments, a collector that signs its stream. It is not a download.

This table is not prose that can drift. It lives in
[`eval/external/scope.py`](../eval/external/scope.py) and
[`tests/test_external.py`](../tests/test_external.py) derives the answer from
the engine's own coverage contracts run over a real adapted session. If an
adapter starts supplying a surface, or a check changes what it requires, the
test fails and this page gets corrected.

---

## 2. What was actually verified about each corpus

Cohaera's standing rule is that an unverified number is already wrong. Both
corpora were checked first-hand on **2026-08-19** rather than taken from their
papers, and both briefs turned out to contain a wrong figure.

### StepShield — `github.com/glo26/stepshield`

Data present and inspectable. Real records were fetched and the adapter was
written against them.

| claim | status | evidence |
|---|---|---|
| Data licensed CC BY 4.0 | **verified** | Stated in `README.md` and `data/README.md`. Code is separately MIT — `LICENSE` fetched and read. |
| Inter-annotator agreement κ = 0.82 | **verified as stated** | `README.md` and `data/README.md` both state κ = 0.82 (Cohen's kappa) on the held-out set, four annotators plus a resolver. This is the repository's claim; the underlying annotations were not re-scored. |
| ~6,657 generated benign trajectories | **REFUTED — the real number is 2,514** | See below. |

**The benign count is 2,514, not 6,657.** The repository's top-level README and
the composition table in `data/README.md` both say 6,657. That number is not in
the repository. Three independent checks:

1. **File probing.** `data/generated_benign/BENIGN-GEN-02514.jsonl` returns
   HTTP 200; `BENIGN-GEN-02515.jsonl` returns 404, as does `BENIGN-GEN-06657`.
2. **The repository's own `CHANGELOG.md`:** "Released 2,514 generated benign
   trajectories for false positive rate calibration."
3. **`data/README.md` contradicts itself.** Its directory-layout section says
   `generated_benign/ # 2,514 benign trajectories for PPV calibration`, four
   paragraphs below the composition table claiming 6,657.

6,657 appears to describe a test split that exists in the paper rather than in
the published data. **Any false-positive-per-1,000-benign figure from this
corpus rests on a denominator of 2,514.**

**The published schema is also incomplete**, which matters more than it sounds.
`data/README.md` documents one record shape; the repository ships two. The
generated-benign records carry three fields that appear nowhere in the
documentation — `trajectory_type`, `task_id` and `category`. The documented id
format is `CATEGORY-SEVERITY-NUMBER-TYPE`, so an adapter written from the
documentation reads the label off the id suffix, gets `00001` from
`BENIGN-GEN-00001`, and **rejects the entire benign population** — the whole
denominator of the headline metric. The adapter here prefers the explicit
fields and falls back to the documented id format.

One genuine strength: StepShield **pairs**. `SEC-L2-001-ROGUE` and
`SEC-L2-001-CLEAN` are one task rendered two ways — confirmed by fetching both
and finding the same task title. That makes a task a real cluster, which is
what the bootstrap interval needs and what R-15 argued for internally.

### ATBench — `github.com/LiYu0524/ATbench`

**No ATBench record has been inspected. Every figure below is a project claim
about data nobody here could open.**

The GitHub repository **contains no trajectory data**. It is a pointer
repository. Verified by direct fetch: `assets/teaser.png` returns 200 — proving
raw fetching works against this repo — while `data/ATBench.json`,
`ATBench.jsonl` and `data/README.md` all return 404. A placeholder file named
`ATBench Engine Coming Soon` returns 200. The data is distributed only through
Hugging Face (`AI45Research/ATBench`), which this environment's proxy blocks
with a 403 CONNECT tunnel failure.

| claim | status |
|---|---|
| ~1,000 trajectories, 503 safe / 497 unsafe | **unverified project claim** (README) |
| Human-audited | **unverified project claim** — README says "rule-based filtering, LLM-based filtering, and full human audit" |
| Contains user request, agent response, tool calls, environment feedback | **unverified project claim** — README's shared task definition |
| **LICENSE file exists** | **REFUTED — there is none** |

**There is no licence.** `LICENSE`, `LICENSE.md`, `LICENSE.txt`, `COPYING` and
`license` all return 404 on the `main` ref while `README.md` on the same ref
returns 200, so the absence is real rather than a fetch failure. The README
grants no licence in prose either. Consequence: **nothing in this repository
redistributes ATBench data and nothing should** until the authors state terms.
"Publicly downloadable" is not a licence.

**Task pools: the safe and unsafe sets do not appear to share one, and that
confounds task-disjoint splitting by construction.** StepShield explicitly
pairs 639 rogue/clean trajectories on shared tasks. ATBench claims no such
pairing anywhere. Its documented generation pipeline runs *sampled risks and
candidate tool pools → blueprint → query generation, risk injection, tool call
simulation, tool response simulation, agent response generation*, which
produces a trajectory per sampled risk rather than a safe and unsafe rendering
of a shared task.

If that reading is right, no task appears on both sides of the label boundary,
so on ATBench **a task-disjoint split is also a label-disjoint split**. It buys
none of the leakage protection it buys on a paired corpus, and any measured
difference between splits confounds task identity with label. Task clustering
degenerates to session clustering, the bootstrap collapses to a session-level
interval, and the runner reports that rather than presenting a task-level
interval that is secretly nothing of the kind.

This is a documentation-derived conclusion, not a data-derived one. **Confirm
it against the real download before relying on it.**

---

## 3. A finding about Cohaera itself: CH04's coverage contract

Pointing the detector at data with no control plane surfaced a defect that the
internal corpus cannot, because the internal corpus always emits policy events.

**On a session with a consequential call and no policy events at all, CH04
reports `evaluated` at confidence 1.0, with no missing surfaces and no reason
codes.**

Measured, not inferred. With a capability manifest supplied so tool
classification is certain, an adapted session containing a `send_email` egress
call, zero policy events and zero approvals produces:

```
CH04_guardrail_overrun  evaluated  conf=1.0
  required = ['tool_class', 'event_clock', 'correlation_key']
  missing  = []      reasons = []
```

The mechanism is in `checks.coverage`: CH04's required-surface list gains
`policy_semantics` and `approval_binding` only `if has_policy` — that is, only
if the session *already contains policy events*. So the one state that costs
CH04 nothing is the state where no guardrail evidence exists whatsoever.

That is inverted. The most alarming situation — a consequential action with no
policy plane in evidence — is the situation the contract treats as
unremarkable, and it is the state every public corpus and every uninstrumented
deployment is in. CH06 and CH07 behave correctly by contrast: both decline at
100% and name `event_integrity` and `effect_receipt` as missing.

**Found here, fixed in the engine.** The behaviour above is what this harness
measured before the fix. `coverage()` now adds both surfaces unconditionally,
and a session with no policy evidence anywhere declines at zero confidence with
reason `NO_POLICY_EVIDENCE`, naming `policy_semantics` and `approval_binding` as
missing — the same shape CH06 and CH07 already had.

The pinning test was worded so that fixing the engine would break it, and it
did. The instruction it carried was followed rather than the assertion being
reversed to keep it green: it is now
`test_ch04_now_charges_for_absent_guardrail_evidence`, asserting the corrected
contract, and `test_the_runner_no_longer_flags_the_ch04_gap` asserts the audit
has gone quiet — which is only worth anything because the first test fails if
it goes quiet for the wrong reason.

One nuance the fix had to preserve. Silence in the event stream cannot separate
"governed, and nothing tripped" from "no policy instrumentation at all". The
only thing that can is the operator's capability manifest, so a manifest
declaring a `policies` section keeps CH04 `evaluated` on a quiet session, with
an assumption recorded; nothing declaring a control anywhere declines. On a
public corpus, which declares nothing, CH04 declines — so **it remains
un-validatable externally**, and the table in section 1 is unchanged.

---

## 4. The adapter doctrine: absent, never weaker

An adapter is the most dangerous file in this directory, because it is where
optimism creeps in. When a corpus lacks a field, the tempting move is to write
a plausible value so the run produces numbers instead of declines. Every such
value propagates into every figure downstream.

So: **a field the source corpus does not carry is omitted from the adapted
session and recorded in an absence ledger. It is never defaulted to something
benign-looking.** This is enforced at adapt time by
`assert_no_fabricated_evidence`, not left to review — the adapters call it on
their own output, so the doctrine holds at runtime and not merely in tests.

Three defaults would each invalidate the harness, and all three are one
keystroke away:

- **`reversible: true`** — measured on the fixtures, this flips two of four
  calls from `unknown` to `read_only`. Tools the keyword lists already read as
  egress survive, so the consequential population does not empty; the damage is
  subtler. Unrecognised state-changing tools read as harmless reads, and
  removing `unknown` removes the coverage penalty, so the run reports itself
  *better-evidenced than it is*. A default of `false` is no better — it
  manufactures alerts instead of suppressing them.
- **`has_injection_patterns: false`** — the subtlest of the three. This is a
  *real answer* to Cohaera: it means "a scanner ran and found nothing", which
  is why `scanner_reported` returns True for it. Writing it for a corpus that
  never ran a scanner **buys CH03 coverage with an answer nobody gave**.
- **`effect_receipt` / `approval` stubs** — an attestation from an authority
  that was never asked, converting CH06 and CH07 from a measurement into a
  tautology.

The single permitted exception is explicit and narrow: StepShield's opt-in
untrusted marking passes `sourced={injection_scanner}` at the call site, and
only when the corpus's own per-step annotation actually marked a step. There is
no global setting and no default, because the failure being designed against is
a surface becoming permanently permitted after one legitimate use.

---

## 5. How to run this tomorrow

Nothing is vendored. Both corpora must be fetched on a network that can reach
the hosts this environment blocks.

### StepShield — works today, licence is clear

```bash
# 1. Fetch. Needs github.com. CC BY 4.0: use it, attribute it, do not re-publish it here.
git clone https://github.com/glo26/stepshield.git /tmp/stepshield

# 2. The benign denominator: 2,514 trajectories, the real false-positive population.
python eval/external/run_external.py \
    --stepshield /tmp/stepshield/data/generated_benign \
    --json /tmp/stepshield-benign.json

# 3. The paired rogue/clean training split, where a task is a real cluster
#    and the bootstrap interval means something.
python eval/external/run_external.py \
    --stepshield /tmp/stepshield/data/train \
    --json /tmp/stepshield-pairs.json

# 4. Optional: give CH03 its one partial surface. Read §1 before believing it —
#    this makes the run label-dependent.
python eval/external/run_external.py \
    --stepshield /tmp/stepshield/data/train \
    --stepshield-mark-untrusted
```

**Read the output in this order.** The coverage-contract table first — it says
which checks could do anything at all, and a false-positive rate over a corpus
where four of seven checks never ran is a false-positive rate for three checks.
Then the scope audit, which flags the CH04 gap in §3. Only then the headline,
and only the **per-1,000-benign** figure: the per-1,000-sessions number moves
with the corpus's attack prevalence, which is a property of whoever built the
corpus. Evaluation card §5 makes the argument at length.

### ATBench — expect to do schema work first

```bash
# 1. Fetch. Needs huggingface.co. NO LICENCE IS PUBLISHED — check terms
#    with the authors before using this for anything you publish.
python -c "
from datasets import load_dataset
load_dataset('AI45Research/ATBench', 'ATBench', split='test').to_json('/tmp/atbench.jsonl')"

# 2. Run. This will probably fail the first time, on purpose.
python eval/external/run_external.py --atbench /tmp/atbench.jsonl
```

**The first run is expected to fail with an `AdapterError` naming the keys it
actually found.** ATBench's key names could not be verified — the data is on a
blocked host — so `FIELD_MAP` in
[`eval/external/adapters/atbench.py`](../eval/external/adapters/atbench.py)
carries best-guess spellings marked UNVERIFIED. Correct it there, in one place;
the error message tells you what to put in. The adapter deliberately does *not*
guess across spellings and quietly succeed on whichever hits, because an
adapter that half-recognises a schema produces a false-positive rate over a
population nobody can describe.

StepShield is the warning, not the reassurance: its *published* documentation
omitted three fields its actual records carry. Expect the same here.

Then check two things against the real data before trusting any number:

1. **Whether safe and unsafe trajectories share a task pool** (§2). If they do,
   give `AdaptedSession.task_id` the shared identifier and the bootstrap
   becomes meaningful. If they do not, the degenerate-clustering note in the
   report is the correct reading.
2. **Whether the trajectories carry anything marking untrusted content.** If
   they do, CH03 moves from "declines outright" to partial, as on StepShield.

### The gates

```bash
python -m pytest -q                    # includes tests/test_external.py
python tools/readme_facts.py --check
ruff check .
```

---

## 6. What this still does not measure

- **No external corpus has been scored.** The harness runs, on adapter
  fixtures. The numbers it will produce tomorrow do not exist yet.
- **Three checks remain unvalidatable by any public data**, and no amount of
  additional corpora fixes that — it needs an instrumented deployment.
- **CH02 is measured against tool output, not an agent summary.** StepShield
  has no dedicated final-answer field, so the last step's observation stands
  in. CH02 measures concealment in a summary; this is a weaker substitute and
  the adapter records the substitution on every session it makes it on.
- **Timestamps are synthetic.** Neither corpus carries a wall clock. The
  adapters emit a monotonic one-second-per-step ordering purely to preserve the
  step order the corpora *do* state. Any timing-sensitive conclusion is an
  artefact of that choice, not a measurement.
- **The fixtures are not data.** Everything under
  `eval/external/fixtures/` is hand-written to exercise adapter shape handling.
  Every record carries a `_fixture` key and every id begins with
  `ADAPTER-FIXTURE-`. No number computed from them means anything.
