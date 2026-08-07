# Observra issue #108: the nine dropped fields

Notes toward workstream 2 of [observra#108](https://github.com/open-agent-ai-security/observra/issues/108),
which the issue describes as "a parser-side extraction gap owned by a content team".

**Status: unsolicited. Ask before assuming this is yours to do.** The issue says
a content team owns it. This is analysis offered, not work claimed.

---

## What #108 says

Opened 4 August 2026 by maintainer `virtualsteve-exa`. Title: *No current output
mode matches the published Exabeam ABA parser's conditions (native/webhook/
sender/sensor all miss)*.

Two workstreams:

1. **Library fix.** `senders/exabeam.py` emits `"event_type":` where the parser
   expects `"type":`, and never emits `"schema":`. `EXABEAM_FIELD_*` overrides
   cannot fix it. Open PR #115 addresses this.
2. **Parser-side extraction gap.** The published parser drops nine security
   fields.

And the line that matters:

> 28/34 AI analytics rules work today. **Zero correlation rules can fire.**

---

## The nine dropped fields, and what each one costs

| Field | Type | What is lost when it is dropped |
|---|---|---|
| `has_injection` | bool | The boolean flag itself. Without it there is no cheap index for "did anything trip the injection scanner in this session". |
| `injection_patterns` | list | Which marker fired. `BASE64_BLOB` and `INSTRUCTION_OVERRIDE` are not the same signal and should not carry the same weight. Without this you cannot tune, only turn off. |
| `current_depth` | int | Delegation depth at the time of the event. Depth is the agent equivalent of a call stack. |
| `max_depth` | int | The configured ceiling. Without both numbers you cannot tell 3-of-5 from 3-of-3. |
| `source_agent` | str | Which agent handed off. |
| `target_agent` | str | Which agent received. Without the pair there is no delegation graph, and multi-agent lateral movement is invisible by construction. |
| `skill_name` | str | Which skill was invoked. The attribution unit for MCP-style tool use. |
| `triggered_rules` | list | Which of observra's own rules fired. Dropping this discards the library's entire detection output at the parser boundary. |
| `max_severity` | enum | The severity observra already computed. Dropping it means the SIEM re-derives severity from raw fields, or does not. |

**The pattern:** the fields that survive are the operational ones (tokens, cost,
duration, errors). The fields that get dropped are the security ones. A parser
built for cost observability, extended to a security use case, will do exactly
this.

---

## Why fixing the extraction alone does not enable correlation

Suppose all nine fields land correctly tomorrow. **Zero correlation rules would
still fire**, because the constraint is not in the parser.

Evidence, from `docs/PHASE0-VERIFICATION.md` in this repo:

1. `evaluate_rules(event_type: str, data: dict | None)` is single-event by
   signature and is called per event from `create_event()`.
2. All nine shipped rules in `examples/siem_parser.json` reference exactly one
   event. Not one relates two.
3. `examples/siem_parser.json` **declares** `correlation_keys`:

   > "Use session_id to group all events in a conversation. Use trace_id to
   > correlate events across agent delegations within a single request."

   The keys are published and documented. Nothing uses them.

So the parser gap and the correlation gap are two different problems that happen
to sit next to each other. Fixing extraction is necessary and not sufficient.
**Say this clearly if you raise it, because conflating the two would be wrong
and someone will notice.**

---

## Three ways to close the correlation half

**Option 1: correlate in the SIEM.** Compound rules with followed-by logic over
`session_id`. Works for ordering checks. Cannot express a fitted baseline, so
CH01 is out. Costs AI Engine state per session. See `../aie/README.md` for the
full comparison.

**Option 2: correlate in the library.** Give observra a stateful mode with a
session accumulator. Cleanest conceptually, largest change to upstream, and it
would push observra beyond the scope it currently declares.

**Option 3: correlate between them.** A downstream consumer reads the JSONL,
assembles sessions, emits one verdict record. No upstream change, no SIEM state,
portable across platforms. This is what Cohaera does.

Option 3 is the one implemented here, and its honest cost is detection latency:
the verdict lands at session close rather than streaming. For sessions measured
in seconds to minutes that is fine. For a long-running agent it is not.

---

## Field map

The concrete mapping is in [`cohaera_field_map.json`](cohaera_field_map.json).
It covers all nine fields plus the session-level features Cohaera derives.

**Untested against a live Exabeam parser.** Modelled on the structure of
observra's own `examples/siem_parser.json`. Validate before deploying.

---

## Before raising any of this

1. **Read #108 and PR #115 in full.** They may have moved since 6 August 2026.
2. **Ask whether the content team wants input** before sending analysis.
3. **Do not present the correlation gap as a defect.** It is a scope boundary,
   and the maintainers describe it as one. The useful contribution is a way to
   close it, not a complaint that it is open.
