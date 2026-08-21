# Detection content

Rules and mappings that consume `cohaera_session_verdict` records.

```
content/
  sigma/     14 Sigma rules, tiered: 7 production, 5 hunt, 2 dashboard
  manifest/  example capability manifest: exact tool ID -> declared effects
  aie/       LogRhythm AIE rule specifications + the build-vs-buy comparison
  parser/    Exabeam field map + notes on observra issue #108
```

---

## Read this before you deploy any of it

### The pack is not fit to deploy as one thing, and three of its checks are

Cohaera's own [evaluation card](../eval/EVALUATION-CARD.md) measures each check
against the attacks it is responsible for. Three checks fire on **zero** benign
sessions across every confounder built specifically to trip them. Four produce
essentially all of the corpus's **420.4 false positives per 1,000 benign
sessions**. Shipping those seven behind one sentence — "Sigma content pack, 14
rules, validated" — hands a deploying engineer 14 rules that look alike
and behave nothing alike.

So every rule now declares a **deployment tier**, and the tier is derived from
that measurement rather than from anyone's confidence in the rule. See
[Deployment tiers](#deployment-tiers) below.

### These rules re-emit verdicts. They do not perform analytics.

Every rule here has the same log source and the same shape:

```yaml
logsource:
    product: cohaera
    service: session_verdict
detection:
    selection:
        type: 'cohaera_session_verdict'
        data.triggered_rules|contains: 'CH04_guardrail_bypass_completed'
```

The detection happens in Python, in [`src/cohaera/checks.py`](../src/cohaera).
The Sigma rule matches a field that says the Python already decided. That is a
legitimate pattern — it is how most vendor content for a scoring engine works —
but it has three consequences that a phrase like "Sigma content pack" does not
communicate, and all three are load-bearing:

1. **You cannot backtest this pack.** There is no `cohaera_session_verdict` in
   your historical logs, because the log source does not exist until Cohaera has
   run over them. The normal first move with new Sigma content — replay ninety
   days and count the alerts — is unavailable. To estimate volume you have to
   run Cohaera over the raw agent telemetry first, and then you are measuring
   the detector, not the content.
2. **`sigma convert` portability is real and empty.** The pack converts to any
   backend, and the query it produces will match nothing on any platform that is
   not already receiving Cohaera verdicts. Portable syntax is not portable
   detection.
3. **Tuning a rule here tunes nothing.** The precision numbers below are
   properties of the Python checks. Narrowing a Sigma selection changes which
   verdicts reach the analyst; it does not change which sessions Cohaera flags,
   and the flagged-and-suppressed ones will not appear anywhere.

What the pack *is* worth: it is the routing and documentation layer. It carries
the field lists, the false-positive analysis, the severity split between an
attempt and a completion, and now the tier — all of which are the things a SOC
needs and none of which the JSON verdict carries on its own.

---

## Deployment tiers

Three tiers. The boundary between the first and the other two is a measured
number, not a judgement.

| Tier | What it means | Route it to |
|---|---|---|
| `production` | Deployable. **May page.** Zero benign hits on the evaluation card's headline cell, across every confounder built to trip the check | Alert queue, at whatever the rule's `level` says |
| `hunt` | **Never an alert.** Investigation surface only | A hunting dataset, a weekly review, a per-agent aggregation over a long window |
| `dashboard` | A configuration state rather than an event. Fires on ordinary sessions by design | A panel. Alert on a **change** in it, never on the state |

### Tier gates deployment; `level` gates volume

They are different questions and the pack keeps them apart.
`cohaera_post_guardrail_attempt.yml` is `production` at `informational`: CH04's
measured benign rate is zero, so the rule is trustworthy, and its own
`falsepositives` block explains that a correctly enforced guardrail looks exactly
like it, so it must not page. Production means *you may deploy this*, not *this
should wake somebody*.

The reverse constraint is enforced. A `hunt` rule may not carry `level: high` or
`level: critical`, because `level` is what every downstream router actually
reads, and a hunt rule at high is an alert with a disclaimer nobody sees.

### What each tier rests on

| Check | Rules | Tier | Own attacks caught | Benign hits | Target precision |
|---|---|---|---|---|---|
| `CH04_guardrail_overrun` | 3 | `production` | 72 of 72 | **0** | **100.0%** |
| `CH06_evidence_integrity` | 1 | `production` | 56 of 56 | **0** | **100.0%** |
| `CH07_effect_contradiction` | 3 | `production` | 16 of 16 | **0** | **100.0%** |
| `CH03_untrusted_to_consequential` | 2 | `hunt` | 32 of 32 | 48 | 40.0% |
| `CH01_sequence_order` | 1 | `hunt` | 72 of 72 | 60 | 35.3% |
| `CH02_concealment_gap` | 1 | `hunt` | 52 of 52 | 108 | 27.1% |
| `CH05_unpaired_calls` | 1 | `hunt` (quarantined) | **0 of 0** | 48 | **0.0%** |
| *(no check)* | 2 | `dashboard` | — | — | not scored |

Target precision, not any-attack precision. A check that fires on an attack
belonging to a different check has helped somebody; it has not shown that it can
do its own job, and counting those as hits is what made the previous per-check
table wrong in the flattering direction. Section 4 of the
[evaluation card](../eval/EVALUATION-CARD.md) has both columns.

**The three production checks are not merely quiet.** Each was measured against
benign confounders written specifically to break it: CH04 against 48 sessions
that continue past an *advisory* threshold, 28 properly approved continuations
and 28 re-approved retries; CH06 against 24 out-of-order stream deliveries and
72 sessions straddling a collector key rotation. Zero of those fire. That is the
evidence, and it is why those three are the ones that may page.

**One caveat on CH06, because it is the only one that moves.** The zero holds in
the `manifest` cells. In the `name_only` ablation — no capability manifest, tool
effects guessed from names — CH06 records 24 benign hits in the same split
(`unseen|task_disjoint|name_only` in `eval/evaluation-card.json`). CH04 and CH07
hold at zero in every cell. If you deploy without `--tool-manifest`, CH06's
production tier is not the tier you measured.

### How the tier is recorded, and why not as a tag

Sigma has no deployment-tier field. The three available mechanisms and why one
of them won:

- **`tags:`** — rejected, twice over. The pack already records that Sigma
  validation refuses private namespaces (`owasp.*`, `cohaera.*`), which is why
  the OWASP mapping lives in a comment rather than a tag. The second reason is
  worse and was found while writing this: adding *any* `tags:` key makes
  `sigma check` load the MITRE ATT&CK tactic list, which it fetches over the
  network. On a build host without egress the command does not warn, it
  tracebacks. A tier field that turns rule validation into a network operation
  is not a tier field.
- **`status:`** — rejected. `status` is a lifecycle value with a fixed
  vocabulary (`stable`, `test`, `experimental`, `deprecated`, `unsupported`) and
  it already carries a meaning: everything here is `experimental` because the
  detector is pre-alpha. Overloading it to mean "safe to page on" would make a
  rule that is both experimental and deployable inexpressible, and every rule in
  this pack is exactly that.
- **`custom:`** — chosen. Unrecognised top-level keys are pySigma's documented
  extension point; they land in `SigmaRule.custom_attributes` and survive
  conversion. `sigma check content/sigma/` reports **0 errors, 0 condition
  errors and 0 issues** with the block present, and `sigma convert -t splunk`
  produces the same queries it did before. It is a custom field and it is a
  custom field *on purpose*: it does not pretend to be a standard one, so nobody
  downstream will mistake it for something their platform already understands.

Each rule's block looks like this, near the top of the file where somebody
enabling it will read it before the description:

```yaml
custom:
    deployment_tier: production
    tier_rationale: >-
        CH04 fires on 72 of its own labelled attacks and on 0 benign sessions...
    owner: '@404SecNotFound'
    last_reviewed: 2026-08-19
    review_cadence_days: 90
    next_review: 2026-11-17
    evidence:
        source: eval/evaluation-card.json
        card_cell: 'unseen|task_disjoint|manifest'
        check: CH04_guardrail_overrun
        labelled: 72
        on_target_attacks: 72
        on_benign: 0
        target_precision_pct: 100.0
```

### The tier is tested against the evidence, not against the author

`tests/test_content.py` re-reads `eval/evaluation-card.json` on every test run
and asserts:

- every rule declares a tier from the three, and a rationale for it;
- no `hunt` rule carries `level: high` or `level: critical`;
- **no rule is `production` unless the card records zero benign hits for the
  check it fires on** — and the check is derived from the rule's own detection
  through the engine's `CHECK_FAMILIES`, so a rule cannot quote a different
  check's numbers;
- every figure in an `evidence:` block equals the card's;
- the corpus digest still matches the one the tiers were decided against, so a
  regenerated corpus forces a re-read rather than being inherited silently;
- this README lists every rule at the tier the rule declares.

That last set is the point. "Deployable" is the most consequential claim this
pack makes and until now the only thing behind it was that the author believed
it. It is the same failure `tools/readme_facts.py` exists to prevent, applied to
a tier instead of a count: a claim in a committed file that nothing recomputes is
a claim that is already drifting.

### Ownership and review

Every rule now carries `owner`, `last_reviewed`, `review_cadence_days: 90` and
`next_review`, checked for arithmetic on every test run. `author` records who
wrote a rule; `owner` records who answers for it now and mirrors
[`.github/CODEOWNERS`](../.github/CODEOWNERS). They are different questions and
only the second one decays.

**The review is not a calendar formality, it is two specific reads.** At each
review, for every rule: does the `evidence:` block still match section 4 of the
card, and does the tier still follow from it? The test enforces the first and
cannot enforce the second, because moving a rule from `hunt` to `production`
after the numbers improve is a decision, not a derivation.

**A regenerated corpus is an out-of-cycle review of the whole pack.** Every tier
in this directory is a statement about one measurement; replacing the
measurement invalidates all 14 statements at once. The digest assertion in
`tests/test_content.py` makes that impossible to skip.

---

## CH05, and why a rule with 0.0% precision is still in the pack

`cohaera_unpaired_consequential_call.yml` is `hunt`, quarantined, and it is the
one rule here that should be read before it is enabled rather than after.

**It has never demonstrated the behaviour it exists to detect.** The card
records 48 benign hits, 0.0% target precision, and — this is the part that
matters — **0 labelled attacks**. It did not miss them. The corpus contains no
attack CH05 is the target check for, so the denominator is zero. "0 of 0" is not
a pass on an easy test; it is a test that was never set. Every attack CH05 has
ever fired on belonged to some other check.

In detection-as-code terms that is an untested detection shipping in production
content, and it has been in this pack since the pack existed.

**Why not delete it.** `tests/test_content.py` asserts in both directions: every
check ID a rule selects on is one the engine emits, *and* every check the engine
emits has a rule. Deleting the CH05 rule would satisfy the pack and leave the
engine emitting a finding nobody receives — a detection with no content, which
is the failure that reverse assertion exists to catch. Quarantining keeps the
gap visible. Deleting would make it invisible, which is worse than either
shipping it or fixing it.

**What would actually move it.** Not tuning; there is nothing to tune towards
without a true positive. It needs an attack fixture in `eval/corpus` that CH05 is
the *target* check for. The nearest existing shape is `attack_omitted_call`, and
that one belongs to CH06 — the deletion is caught by a hole in the collector's
signed sequence, not by the call pairing that CH05 does. Until such a fixture
exists, CH05's tier is a statement about an absence of evidence and the rule says
so in its own first paragraph.

---

## CH02, and the trade nobody should make by accident

`cohaera_concealment_gap.yml` is `hunt`, and it is the worst trade in the pack in
both directions at once.

**Blind by default.** observra's `capture_tool_data` defaults to `False` and
`core/hot_cold.py` strips string values on the hot path, so `response_text` is
usually absent. Cohaera reports CH02 as `not_evaluated` rather than clean — which
is the right behaviour and is exactly why `cohaera_coverage_degraded.yml` exists
— but the operational fact is that on a default deployment this rule is
decoration. It appears deployed, it counts as concealment coverage in a review,
and it cannot fire.

**Expensive when it is not blind.** Enabling capture means retaining the agent's
user-facing text, which is a deliberate downgrade of the operator's privacy
posture. What that buys, measured: **27.1% target precision and 108 benign
hits**, the highest benign count of any check here, from honest-but-paraphrased
summaries (`benign_hard_terse_summary`) and honest summaries that also state what
the agent did *not* do (`benign_hard_honest_denial`).

So the choice on offer is between a check that cannot fire and a check that is
wrong roughly three times in four while you are retaining text you were not
retaining before. Neither branch is an alert. The rule says all of this in its
own `description` and `falsepositives`; it is repeated here because the decision
to enable capture is usually taken by somebody who is not reading rule YAML.

The roadmap item that changes this is a semantic disclosure judge. Nothing an
operator can configure gets there from token overlap.

---

## The point of this directory

Every one of observra's nine shipped detection rules references exactly one
event. Verbatim from its own `examples/siem_parser.json`:

| Severity | Rule | Condition |
|---|---|---|
| high | Prompt Injection Detected | `has_injection_patterns == true` |
| medium | Cost Threshold Exceeded | `event_type == 'cost_threshold_exceeded'` |
| medium | Agent Depth Exceeded | `event_type == 'depth_exceeded'` |
| low | Model Error, Rate Limited | `event_type == 'model_error' AND error_class == 'rate_limit'` |
| high | Model Error, Auth Failure | `event_type == 'model_error' AND error_class == 'auth'` |
| low | Tool Error | `event_type == 'tool_error'` |
| medium | Agent Handoff Error | `event_type == 'agent_handoff_error'` |
| low | High Token Usage | `event_type == 'model_response' AND total_tokens > 10000` |
| medium | High Single-Call Cost | `event_type == 'model_response' AND cost_usd > 0.50` |

Every rule in **this** directory references session state. That is the whole
difference.

The same parser file declares correlation keys and then never uses them:

> "Use session_id to group all events in a conversation. Use trace_id to
> correlate events across agent delegations within a single request."

Nine rules. Zero use those keys. Which is why issue #108 can say *"28/34 AI
analytics rules work today. Zero correlation rules can fire."*

---

## Sigma

Every rule validates against the required-field set with real UUIDs. Sorted by
tier, because that is the order somebody enabling them should work in.

| Rule | Tier | Level | Check | Expressible upstream? |
|---|---|---|---|---|
| `cohaera_guardrail_bypass_completed.yml` | `production` | high | CH04 completed, semantics undeclared | No |
| `cohaera_blocking_control_bypassed.yml` | `production` | high | CH04 declared blocking, no bound approval | No |
| `cohaera_post_guardrail_attempt.yml` | `production` | informational | CH04 attempted | No |
| `cohaera_evidence_integrity_failed.yml` | `production` | critical | CH06 | No |
| `cohaera_reported_failure_with_effect_receipt.yml` | `production` | high | CH07 contradiction | No |
| `cohaera_effect_receipt_unbound.yml` | `production` | medium | CH07 binding guard | No |
| `cohaera_effect_receipt_partially_bound.yml` | `production` | low | CH07 partial binding | No |
| `cohaera_sequence_order_violation.yml` | `hunt` | medium | CH01 | No |
| `cohaera_concealment_gap.yml` | `hunt` | medium | CH02 | No |
| `cohaera_untrusted_to_completed_action.yml` | `hunt` | medium | CH03 completed | No |
| `cohaera_untrusted_to_attempted_action.yml` | `hunt` | low | CH03 attempted | No |
| `cohaera_unpaired_consequential_call.yml` | `hunt` | low | CH05 — **quarantined**, see above | No |
| `cohaera_coverage_degraded.yml` | `dashboard` | informational | coverage | No |
| `cohaera_telemetry_integrity_defects.yml` | `dashboard` | low | field-level defects | No |

The two `dashboard` rules select no `CHxx` check — they match on
`data.coverage.completeness` and `data.integrity_defect_count` directly — so the
evaluation card does not score them and no measured benign rate exists for
either. A rule with no measurement cannot be `production` in this pack, and the
test enforces that rather than trusting it.

Convert with `sigma convert -t <backend>`. Every rule converts; see
[the note above](#these-rules-re-emit-verdicts-they-do-not-perform-analytics) on
what that portability is and is not worth.

### Two rules named "integrity", and they are about different things

`cohaera_telemetry_integrity_defects.yml` is about **fields**: a record arrived
with a span that was a list, or a timestamp that was a string, and the schema
firewall dropped the field and labelled it. It says the producer's serialiser is
wrong.

`cohaera_evidence_integrity_failed.yml` is about **records**: what arrived is not
what the collector signed for. A sequence gap, a chain break, a signature that
did not verify. It says somebody edited the stream, and it is the only rule in
this pack whose subject is the telemetry rather than the agent — which is why
every other finding in the same verdict carries `evidence_status` saying how far
the evidence underneath it was established: `verified_complete`,
`verified_prefix`, `chained_unsigned`, `unattested` or `inadmissible`.

`verified_prefix` is worth a rule of its own attention. It means signatures
verified and stopped short of the last record — a signature covers the chain
head at its own sequence, so a collector sampling every hundredth record leaves
everything after the last signing position attested by nobody. There was no such
value before: it reported as `verified`, which is what an analyst reads as
settled. A rule matching on the old literal `verified` will now match nothing,
which is deliberate — it should fail loudly rather than quietly stop firing.

### The pairs, and why they are pairs

`CH03` and `CH04` are each two rules because a **completed** action and an
**attempted** one are different facts. They were one rule each until an external
review pointed out that a session whose only candidate call had *errored* was
being reported at the same severity, with the same wording, as one where an
irreversible action actually happened — and that CH04's shared detail text
asserted *"the control did not stop the behaviour"* about a call that never
completed. Nothing in the telemetry says whether the guardrail, the tool, the
model or an unrelated failure prevented it, so the attempt rules make no claim
about enforcement and sit at low or informational.

Match `data.triggered_families` to catch either; match `data.triggered_rules` to
distinguish them.

### What "validated" does and does not mean here

`sigma check` proves a rule is well-formed YAML that a converter accepts. It does
**not** prove the rule can ever match, because the converter has never seen the
log source. A rule selecting on `data.tool_seq` when Cohaera emits
`data.tool_sequence` validates cleanly, converts cleanly, deploys cleanly and
fires never — which is the worst failure available to detection content, because
it counts as coverage in a review and produces nothing.

So the pack is checked three ways in CI:

1. `sigma check content/sigma/` — 0 errors, 0 condition errors, 0 issues;
2. `sigma convert -t splunk` — every rule produces a real query;
3. `tests/test_content.py` — generates a **real verdict record** from a real
   session and asserts that every field every rule references resolves against
   it, that every check ID a rule selects on is one the engine can emit, and
   that every check the engine emits has a rule. That last one is the reverse
   direction: a detection nobody receives.
4. `tests/test_content.py` again — asserts every rule's **deployment tier**
   against `eval/evaluation-card.json`, so `production` is a measurement and not
   an opinion. See
   [The tier is tested against the evidence](#the-tier-is-tested-against-the-evidence-not-against-the-author).

None of the four tell you what the pack will do on your traffic, and the third
section of this file says why that is structural rather than an oversight.

**Read the `falsepositives` blocks before deploying any of them.** They are not
boilerplate. Five of the 14 have a false positive rate that is material
enough to state plainly, and four of those five are why the `hunt` tier exists:

- **CH02** (`hunt`) uses lexical matching. An agent that says "I have emailed the
  report" without naming `send_email` will be flagged. 27.1% target precision,
  108 benign hits, and blind under default privacy settings. See
  [CH02, and the trade nobody should make by accident](#ch02-and-the-trade-nobody-should-make-by-accident).
- **CH03 completed** (`hunt`) fires on correctly-behaving agents that read
  hostile content and ignore it. That is the check working as designed, not a
  defect, and it is still 48 benign hits at 40.0% precision. Review trigger,
  never an automated action.
- **CH01** (`hunt`) fires on legitimate but rare orderings: 60 benign hits at
  35.3%. Its `falsepositives` block says which of its two triggers to triage on,
  and that matters more than the violation rate.
- **CH05** (`hunt`, quarantined) has 48 benign hits, 0.0% precision and no
  labelled attack in the corpus at all. Do not enable it as an alert; see
  [CH05](#ch05-and-why-a-rule-with-00-precision-is-still-in-the-pack).
- **CH04 attempted** (`production`, `informational`) fires on a guardrail that is
  **working**: if your policy layer refuses the call and the refusal surfaces as
  a `tool_error`, this is what it looks like. Its check is measured at zero
  benign hits, which is why it is production; it ships at informational, and the
  rule refuses to describe it as a bypass, which is why it must not page.
- **Coverage** (`dashboard`) fires on every session under default privacy
  settings and without a capability manifest. Dashboard, not alert. The alertable
  event is a **drop** in completeness for an agent that previously scored higher:
  that means the agent's observability regressed.

**Tagging note.** Tags use an `owasp.llm*` namespace mapped to the OWASP Top 10
for LLM Applications 2025 category names, which were read directly off
genai.owasp.org. MITRE ATLAS technique IDs were deliberately **left out** rather
than guessed. If you want ATLAS tags, verify each ID against the current matrix
before adding it.

---

## LogRhythm AIE

See [`aie/README.md`](aie/README.md). Five rule specifications, plus the part
worth reading first: a straight comparison of correlating **in AIE** using
compound followed-by rules versus correlating **upstream** in Cohaera.

The honest conclusion in that document is that AIE can do CH03, CH04 and CH05
natively. It cannot do CH01, which needs a fitted baseline, or CH02, which needs
a text comparison. **If the ordering checks are all you want, build them in AIE
and skip Cohaera.** Running that comparison is a useful result either way.

These are specifications, not exported rules. A fabricated `.xml` would be worse
than useless. Verify rule block types and metadata field availability against
your platform version.

---

## Exabeam parser

[`parser/cohaera_field_map.json`](parser/cohaera_field_map.json) maps the verdict
record, modelled on the structure of observra's own `examples/siem_parser.json`
so it reads familiar.

[`parser/OBSERVRA-108-GAP.md`](parser/OBSERVRA-108-GAP.md) works through the nine
security fields #108 records as dropped by the published ABA parser, what each
one costs when it goes missing, and three ways to close the correlation half of
the problem.

**The key argument in that document:** fixing the field extraction is necessary
and not sufficient. Even with all nine fields landing correctly, zero correlation
rules would fire, because the constraint is the single-event rule engine, not the
parser. Those are two adjacent problems and conflating them would be wrong.

---

## Status

**Nothing here has been tested against a live SIEM.** The Sigma rules validate
structurally. The AIE specifications are built from documented rule block
behaviour, not from a deployment. The parser map is modelled on the upstream
example, not confirmed against an Exabeam parser.

**Step 1 of the old test order has been run, and it is where the tiers came
from.** It was "replay a labelled corpus through the Sigma rules, measure
per-rule false positive rate against the labels", and the honest version of that
sentence is that the corpus was replayed through the **Python checks** — the
Sigma rules only re-emit what those decided, so there is nothing separate to
measure. `eval/run_eval.py` does it, section 4 of the
[evaluation card](../eval/EVALUATION-CARD.md) publishes it, and this directory's
`custom.deployment_tier` fields are read out of it.

What that leaves outstanding:

1. Replay against **real agent traffic**, not a synthetic corpus written by the
   detector's own author. Every number in this file is from the latter and
   `eval/EVALUATION-CARD.md` says so at length. The tiers are as good as that
   corpus and no better.
2. Build AIE-COHAERA-001 both ways, native compound rule and Cohaera-fed, and
   compare rule count, AI Engine load, and detection latency.
3. Only then validate the parser map end to end.
