# LogRhythm AIE rule specifications

**These are specifications, not exported rules.** AIE rules are built in the
Rule Wizard against a specific platform version and Data Processor
configuration. A fabricated `.xml` export would be worse than useless. What is
here is precise enough to build from in an afternoon.

**Verify against your platform version before building.** Rule block types,
available metadata fields, and Log Source Type behaviour differ across
LogRhythm SIEM releases. I have not tested any of this on a live deployment.

---

## The architectural question worth asking first

There are two ways to detect the guardrail-overrun pattern, and the comparison
is the interesting part.

### Option A: correlate in AIE, no Cohaera

Ingest observra's per-event JSONL directly. Build a **compound rule** with two
rule blocks in a followed-by relationship:

```
Block 1  Log Observed
         Log Source Type = observra agent telemetry
         event_type = cost_threshold_exceeded
         Group By: session_id

    FOLLOWED BY (within 300 seconds)

Block 2  Log Observed
         Log Source Type = observra agent telemetry
         event_type = tool_start
         reversible = false
         Group By: session_id
```

**Costs of this approach:**

| Cost | Detail |
|---|---|
| Rule count | One compound rule per correlation pattern. Five checks becomes five compound rules, each with 2 to 3 blocks. |
| Field availability | Every field a block references must survive MPE parsing into a queryable metadata field. `reversible` lives inside the nested `data` object. |
| AIE load | Compound rules with followed-by hold state per group-by key on the AI Engine. Session volume drives memory. |
| Window tuning | You must pick a followed-by window per rule. Too short misses slow sessions, too long inflates state. |
| Portability | None. Rebuild the logic for every SIEM. |
| Baselining | Not expressible. CH01 needs a grammar mined from a corpus, which is not an AIE construct. |

### Option B: correlate in Cohaera, alert in AIE

Cohaera assembles the session, runs the checks, emits **one verdict record per
session**. AIE then needs only a simple Log Observed rule:

```
Block 1  Log Observed
         Log Source Type = cohaera session verdict
         triggered_rules contains CH04_guardrail_bypass_completed
```

**What this buys:**

- One rule block instead of a compound rule, per detection.
- No followed-by state on the AI Engine at all.
- No window tuning. The session boundary is the window.
- The same verdict record feeds Exabeam ABA, LogRhythm AIE and Sigma without
  rewriting the logic three times.
- CH01 baselining becomes possible, because the grammar is fitted upstream where
  a corpus can be held.
- The verdict carries `coverage`, so an analyst can see whether a clean result
  means "checked and clean" or "could not check".

**What it costs:**

- Another moving part in the pipeline.
- Detection latency moves from streaming to session close. For an agent session
  measured in seconds to minutes this is usually acceptable; for a long-running
  agent it is not. **Say this out loud rather than hiding it.**
- If Cohaera is wrong, AIE inherits the error. The verdict is only as good as
  the check.

**Honest position:** Option A is viable for CH03, CH04 and CH05, which are
ordering checks over two events. It is not viable for CH01, which needs a fitted
baseline, or CH02, which needs a text comparison. If you only ever want the
ordering checks, do it in AIE and skip Cohaera. **Build Option A for CH04 first
and compare.** That comparison is a genuinely useful result either way, and it
is the kind of thing worth writing up.

---

## Rule specifications

### AIE-COHAERA-001 · Guardrail Overrun

| Field | Value |
|---|---|
| Rule Name | Agent Guardrail Fired And Session Continued |
| Common Event | Suspicious Activity (map to your taxonomy) |
| Risk Rating | 7 |
| Rule Block | Log Observed |
| Log Source Type | Cohaera Session Verdict |
| Primary Criteria | `triggered_rules` contains `CH04_guardrail_bypass_completed` |
| Group By | `session_id`, `agent_name` |
| Suppression | 60 minutes per `agent_name` |
| Notify | SOC queue |

**Analyst guidance:** confirm from `policy_events` which control fired, then read
`findings[].evidence.calls_after` for what ran afterwards. If any of those calls
are class `egress`, escalate. This has no benign explanation at volume; a single
occurrence may be an advisory threshold by design, so confirm intent with the
agent owner on first sighting.

### AIE-COHAERA-002 · Untrusted Content Then Consequential Action

| Field | Value |
|---|---|
| Rule Name | Agent Consequential Action After Injection Markers |
| Risk Rating | 6 |
| Rule Block | Log Observed |
| Primary Criteria | `triggered_rules` contains `CH03_untrusted_to_completed_action` |
| Group By | `session_id`, `agent_name`, `user` |
| Suppression | 30 minutes per `agent_name` |

**Analyst guidance: this is a review trigger, not a verdict.** A correct agent
that reads hostile content, ignores it, and does its job will fire this. Read
`findings[].evidence.calls_after` and the agent's own case notes before acting.
Do not attach an automated containment SmartResponse.

**Tuning:** if `injection_markers` contains only `BASE64_BLOB`, downgrade. That
pattern is `[A-Za-z0-9+/]{20,}` upstream and matches any hash or token.

### AIE-COHAERA-003 · Concealment Gap

| Field | Value |
|---|---|
| Rule Name | Agent Action Not Reported To Human |
| Risk Rating | 6, raise to 8 when `egress_count` >= 1 |
| Rule Block | Log Observed |
| Primary Criteria | `triggered_rules` contains `CH02_concealment_gap` |
| Group By | `session_id`, `agent_name` |

**Baseline before alerting.** The v0.1 matcher is lexical and will produce false
positives on agents whose summaries describe actions in different words from the
tool names. Run in report-only mode for two weeks first.

### AIE-COHAERA-004 · Sequence Order Violation

| Field | Value |
|---|---|
| Rule Name | Agent Tool Ordering Deviates From Baseline |
| Risk Rating | 5 |
| Rule Block | Log Observed |
| Primary Criteria | `triggered_rules` contains `CH01_sequence_order` |
| Group By | `agent_name` |

Consider a **Threshold Observed** variant instead: N sessions from the same
`agent_name` violating within a window is a stronger drift signal than one
session. A single novel ordering is usually a new feature; a sustained shift is
behavioural drift.

### AIE-COHAERA-005 · Monitoring Coverage Degraded

| Field | Value |
|---|---|
| Rule Name | Agent Monitoring Coverage Below Threshold |
| Risk Rating | 2 |
| Rule Block | Log Observed |
| Primary Criteria | `coverage.completeness` < 0.8 |
| Group By | `agent_name` |

**Dashboard, not alert.** With default privacy settings this fires on every
session. Use it to show which agents are actually being checked and which only
appear to be. Alert only on a *decrease* for an agent that previously scored
higher, which indicates a configuration regression.

---

## MPE parsing

Cohaera emits newline-delimited JSON. Two routes:

**Preferred: JSON parsing.** Newer LogRhythm SIEM versions parse JSON log
sources natively without regex. Map the fields per
[`../parser/cohaera_field_map.json`](../parser/cohaera_field_map.json). Confirm
your version supports it before writing regex you do not need.

**Fallback: regex base rule.** If you must regex it, the fields worth lifting
into metadata are the ones a rule references. Everything else can stay in the
message body.

```
# .NET regex, base rule. Anchored on the schema marker to avoid matching
# observra's own records, which carry event_type but not schema.
"schema"\s*:\s*"cohaera:[^"]*".*?
"session_id"\s*:\s*"(?<session>[^"]+)".*?
"agent_name"\s*:\s*"(?<process>[^"]*)".*?
"max_severity"\s*:\s*"(?<severity>[^"]+)"
```

**Untested.** Validate in the Regex Tester against a real record before
deploying, and check the ReDoS profile of the `.*?` spans on long records. A
verdict record with a large `findings` array can be several kilobytes.

**Tag mapping suggestion:**

| Cohaera field | LogRhythm metadata field | Note |
|---|---|---|
| `session_id` | Session | Primary correlation key |
| `agent_name` | Process Name | Treat the agent as the acting process |
| `user` | User (Origin) | The service account the agent runs as |
| `host` | Host (Impacted) | |
| `data.max_severity` | Severity | |
| `data.triggered_rules` | Object | The check IDs, needed by every rule above |
| `data.total_cost_usd` | Quantity | |
| `data.tool_call_count` | Amount | |

Confirm these against your Data Dictionary. Field availability and indexing
behaviour vary by version, and the mapping above is a suggestion rather than a
tested configuration.
