<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Activity records: `cohaera_tool`

The session verdict answers "was anything wrong, and could we tell?". It is a
notice. It is not the place to hunt, because it carries no row for an individual
tool call: a SOC that wants to ask "show me every consequential action this
agent took last week" has nothing to query.

`cohaera_tool` is that row. One record per assembled tool call, emitted as a
durable fact independent of whether any detection fired. It is to the verdict
what Zeek's `conn.log` is to `notice.log`: the activity survives even when no
rule fires, it is cheap to retain, and it is queryable on its own.

This is the first record of the activity family in
[DIRECTION](DIRECTION.md); `cohaera_session`, `cohaera_control`,
`cohaera_evidence`, `cohaera_coverage` and `cohaera_notice` are not built yet.

## Emitting it

```bash
cohaera score telemetry.jsonl --emit-tool-records > stream.jsonl
```

Off by default: the stdout contract stays one `cohaera_session_verdict` per
session unless `--emit-tool-records` is set. With it, each session's tool rows
are written to the same stdout JSONL stream after that session's verdict. Route
by the `type` field. `schema` is `cohaera.tool:1`, versioned separately from the
verdict (`cohaera:0.3`) so a consumer of one is not forced to re-parse the other
when either moves.

## Joining to the verdict

Every row is self-sufficient for correlation: it carries `session_id`,
`trace_id`, `agent_name`, `framework`, `host` and `user`. It joins to its
session verdict through `verdict_id`, and `tool_event_id` is its own stable key.
`tool_event_id` is deterministic: the same input under the same run identity
produces the same id, so a re-score is recognisable rather than duplicated.

## Fields

Top level carries identity; `data` carries the call.

| Field | Source | Meaning and null semantics |
|---|---|---|
| `type` | fixed | `cohaera_tool`. |
| `schema` | fixed | `cohaera.tool:1`. |
| `tool_event_id` | derived | Deterministic per-call id: run identity, session, call index, span, name, start. |
| `verdict_id` | join | The session verdict this call belongs to. |
| `sequence` | derived | The call's ordinal in the session, so rows order even when clocks tie. |
| `session_id` / `trace_id` | producer | Session identity. |
| `agent_name` / `framework` / `host` / `user` | producer | Actor identity; any may be null when the producer omitted it. |
| `data.tool` | producer | Tool name, display-sanitised. |
| `data.class` | derived | `read_only` \| `state_change` \| `egress` \| `unknown`. `unknown` when nothing established it. |
| `data.class_source` | derived | `manifest` \| `name_heuristic` \| `producer_reversible_flag` \| `unclassified` — which decided the class. Only `manifest` is a statement of fact. |
| `data.consequential` | derived | True when class is `state_change` or `egress`. |
| `data.state` | derived | `open` (start, no terminal) \| `complete` \| `orphan_end` \| `mismatched_end` \| `duplicate_end`. |
| `data.result` | producer | `success` \| `failure` \| **null for an unpaired call** — absence of a terminal is not a failure. |
| `data.executed` | derived | True only for `complete` + `success`. A started-but-failed call is not an executed action. |
| `data.started_at` / `data.ended_at` | producer | Epoch seconds, or **null** when the clock was unreadable or the call never terminated. Never 0. |
| `data.duration_ms` | producer | Null when not supplied. |
| `data.span_id` | producer | The call's span, or null. |
| `data.error_class` | producer | Populated on a `tool_error`. |
| `data.had_args` / `data.had_result` | producer | Whether arguments / result were captured at all. observra strips arguments on the hot path, so `had_args` is usually false. |
| `data.reversible` | producer | The producer's reversibility flag, or **null** when never declared — never defaulted to a class. |
| `data.arg_digest_source` | derived | `none` \| `producer_declared` \| `recomputed` \| `declared_and_recomputed` \| `producer_contradicted`. |
| `data.arg_digest_disagrees` | derived | True when the producer's declared digest contradicts the arguments it emitted. |
| `data.approval_state` | derived | `covered` (an ALLOW that bound exactly and was observed before the call) \| `presented_not_binding` (an approval named the span but did not cover it) \| `none`. |
| `data.receipt_present` | producer | Whether the call carried an effect receipt at all. |
| `data.receipt_binding` | derived | `bound` \| `bound_span_only` \| `arg_mismatch` \| `unbound`. `unbound` covers both "no receipt" and "a receipt naming no call"; `receipt_present` separates them. |
| `data.start_stream` / `data.start_seq` | producer | The collector stream and sequence the start event carried, when it had a `cohaera.integrity:1` sidecar. |
| `data.provenance` | derived | `analysis_run_id`, `detector_version`, `config_hash`, `verdict_id`. |

## Hunts it answers

These three are asserted as executable queries in `tests/test_tool_records.py`;
a field with no hunt is a field nobody asked for. Expressed here as the
predicate a SIEM search encodes.

1. **Unapproved consequential action.** `data.consequential` and
   `data.executed` and `data.approval_state != "covered"`. A state-changing or
   egress call that completed with no approval bound to it.
2. **Success without a bound receipt.** `data.consequential` and
   `data.result == "success"` and `data.receipt_binding != "bound"`. The
   agent's own word for what it did, unverifiable against the target system.
3. **Unpaired consequential call.** `data.consequential` and
   `data.state == "open"`. A consequential call that started and never
   terminated — the per-call view of the CH05 surface, now hunt-queryable
   rather than only a session-level finding.

## What this record is not

It is not a notice. None of these fields is a detection; `approval_state` of
`none` and `receipt_binding` of `unbound` are the ordinary shape of most agent
telemetry, not alerts. The hunts above are questions, and the answers are
starting points for an analyst, not pages. The behavioural detections still live
in the session verdict and carry their own coverage and false-positive cost.
