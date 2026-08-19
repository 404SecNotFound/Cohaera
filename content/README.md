# Detection content

Rules and mappings that consume `cohaera_session_verdict` records.

```
content/
  sigma/     13 Sigma rules, validated, converted and conformance-tested
  manifest/  example capability manifest: exact tool ID -> declared effects
  aie/       LogRhythm AIE rule specifications + the build-vs-buy comparison
  parser/    Exabeam field map + notes on observra issue #108
```

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

Thirteen rules, all validating against the required-field set with real UUIDs.

| Rule | Level | Check | Expressible upstream? |
|---|---|---|---|
| `cohaera_guardrail_bypass_completed.yml` | high | CH04 completed, semantics undeclared | No |
| `cohaera_blocking_control_bypassed.yml` | high | CH04 declared blocking, no bound approval | No |
| `cohaera_post_guardrail_attempt.yml` | informational | CH04 attempted | No |
| `cohaera_concealment_gap.yml` | medium | CH02 | No |
| `cohaera_untrusted_to_completed_action.yml` | medium | CH03 completed | No |
| `cohaera_untrusted_to_attempted_action.yml` | low | CH03 attempted | No |
| `cohaera_sequence_order_violation.yml` | medium | CH01 | No |
| `cohaera_unpaired_consequential_call.yml` | low | CH05 | No |
| `cohaera_evidence_integrity_failed.yml` | critical | CH06 | No |
| `cohaera_reported_failure_with_effect_receipt.yml` | high | CH07 contradiction | No |
| `cohaera_effect_receipt_unbound.yml` | medium | CH07 binding guard | No |
| `cohaera_coverage_degraded.yml` | informational | coverage | No |
| `cohaera_telemetry_integrity_defects.yml` | low | field-level defects | No |

Convert with `sigma convert -t <backend>`.

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

**Read the `falsepositives` blocks before deploying any of them.** They are not
boilerplate. Four of the nine have a genuinely material false positive rate that
is stated plainly:

- **CH02** uses lexical matching. An agent that says "I have emailed the
  report" without naming `send_email` will be flagged. Baseline before alerting.
- **CH03 completed** fires on correctly-behaving agents that read hostile content
  and ignore it. That is the check working as designed, not a defect. Review
  trigger, never an automated action.
- **CH04 attempted** fires on a guardrail that is **working**: if your policy
  layer refuses the call and the refusal surfaces as a `tool_error`, this is what
  it looks like. That is why it ships at informational and why the rule refuses
  to describe it as a bypass.
- **Coverage** fires on every session under default privacy settings and without
  a capability manifest. Dashboard, not alert. The alertable event is a **drop**
  in completeness for an agent that previously scored higher: that means the
  agent's observability regressed.

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

Test order when you get platform access:

1. Replay a labelled corpus through the Sigma rules, measure per-rule false
   positive rate against the labels.
2. Build AIE-COHAERA-001 both ways, native compound rule and Cohaera-fed, and
   compare rule count, AI Engine load, and detection latency.
3. Only then validate the parser map end to end.
