# Detection content

Rules and mappings that consume `cohaera_session_verdict` records.

```
content/
  sigma/     6 Sigma rules, validated, portable
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

Six rules, all validating against the required-field set with real UUIDs.

| Rule | Level | Check | Expressible upstream? |
|---|---|---|---|
| `cohaera_guardrail_overrun.yml` | high | CH04 | No |
| `cohaera_concealment_gap.yml` | medium | CH02 | No |
| `cohaera_untrusted_to_consequential.yml` | medium | CH03 | No |
| `cohaera_sequence_order_violation.yml` | medium | CH01 | No |
| `cohaera_unpaired_consequential_call.yml` | low | CH05 | No |
| `cohaera_coverage_degraded.yml` | informational | coverage | No |

Convert with `sigma convert -t <backend>`.

**Read the `falsepositives` blocks before deploying any of them.** They are not
boilerplate. Three of the six have a genuinely material false positive rate that
is stated plainly:

- **CH02** uses lexical matching in v0.1. An agent that says "I have emailed the
  report" without naming `send_email` will be flagged. Baseline before alerting.
- **CH03** fires on correctly-behaving agents that read hostile content and
  ignore it. That is the check working as designed, not a defect. Review
  trigger, never an automated action.
- **Coverage** fires on every session under default privacy settings. Dashboard,
  not alert.

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
