# Phase 0 verification: raw output

The README claims observra has no cross-event correlation. This file is the
evidence, captured verbatim so anyone can rerun it and get the same result.

```
REPO    open-agent-ai-security/observra
COMMIT  202683a0e40c656f834c5d022b517cf6cdc9da6f
DATE    2026-08-06 00:08:47 +0000
SUBJECT docs: rebuild guide/ + guide/api/ + sitemap.xml from v1.1.0
RUN AT  2026-08-07
```

Rerun with `git clone --depth 1 https://github.com/open-agent-ai-security/observra.git`.
If the repo has moved on, re-verify before quoting any of this.

---

## 0.1 Behavioural analytics: none exists

```console
$ grep -ril -E 'baseline|anomal|deviation|drift|zscore|percentile|outlier' src/ | grep -v test
src/observra/core/metrics.py
src/observra/observability.py

$ grep -rn -E 'percentile|stddev|z_score|outlier' src/ | grep -v test
src/observra/core/metrics.py:51:    def percentile(self, p: float) -> float | None:
src/observra/core/metrics.py:52:        """Compute the p-th percentile from current samples.
src/observra/core/metrics.py:58:            The computed percentile value, or None if the buffer is empty.
src/observra/observability.py:24:      - write_latency_p99: float | None -- 99th percentile write latency
src/observra/observability.py:25:      - write_latency_p999: float | None -- 99.9th percentile write latency
src/observra/observability.py:38:        "write_latency_p50": hist.percentile(50),
src/observra/observability.py:39:        "write_latency_p99": hist.percentile(99),
src/observra/observability.py:40:        "write_latency_p999": hist.percentile(99.9),
```

Two files, and both are the telemetry writer measuring **its own disk latency**.
Nothing computes a baseline over agent behaviour.

## 0.2 The rule engine is single-event by signature

```console
$ grep -n -A4 "^def evaluate_rules" src/observra/core/rules.py
91:def evaluate_rules(event_type: str, data: dict[str, Any] | None) -> dict[str, Any]:
92-    """Evaluate all detection rules against an event and return matched annotations.
93-
94-    Called by ``create_event()`` against the *unredacted* merged data dict so
95-    that boolean/numeric fields (``has_injection_patterns``, ``error_class``,
```

One event type, one data dict, called per event from `create_event()`. There is
no session parameter, no history, no accumulator. A rule cannot reference a
prior event because it is never given one.

## 0.3 `detect_suspicious_sequence()` is unreachable

```console
$ grep -rn 'detect_suspicious_sequence' . --include='*.py'
./src/observra/core/sequences.py:73:def detect_suspicious_sequence(tool_names: list[str]) -> bool:
```

One hit across the entire repository: the definition. It is never called.

The rule that depends on it:

```console
$ grep -n -B2 -A4 "suspicious_sequence" src/observra/core/rules.py
84-        "name": "Suspicious Tool Sequence",
85-        "severity": "medium",
86:        "check": lambda et, d: d.get("suspicious_sequence") is True,
87-    },
```

Nothing populates `suspicious_sequence`, so this rule cannot fire.

## 0.4 Injection scanning runs on user input only

```console
$ grep -rn "detect_injection_patterns(" src/observra --include='*.py' | grep -v /tests/
src/observra/adapters/adk/plugin.py:240:   injection_patterns = detect_injection_patterns(message_text)
src/observra/adapters/litellm/adapter.py:87:  patterns = detect_injection_patterns(content)
src/observra/log.py:452:                     injection_patterns = detect_injection_patterns(text)
src/observra/log.py:502:                     patterns = detect_injection_patterns(text)
```

Four call sites, excluding the definition itself:

| Site | Argument |
|---|---|
| `adapters/adk/plugin.py:240` | `message_text`, the user's message |
| `adapters/litellm/adapter.py:87` | `msg.get("content")` from request `messages` |
| `log.py:452` | `text` in the `USER_MESSAGE` emit path |
| `log.py:502` | `data.get("user_message_text")` |

**No call site receives `tool_result`.** The claude, langchain and openai
adapters never import the detector.

Corroborated by observra's own parser example, which describes the rule as
firing on user input:

> "Prompt Injection Detected" ... "User input matched known prompt injection
> patterns"

That description is correct about the code. It is inconsistent with
`demo/data.jsonl`, which shows the same marker on a `tool_end`. See
[FINDINGS.md](../FINDINGS.md) F-01.

## 0.5 The architecture has no analysis stage

From `docs/architecture.md`, verbatim:

```
┌─────────────────────────────────────────────────┐
│              Core Pipeline                      │
│  CIM normalization → dedup → redaction → cost   │
└─────────────────────┬───────────────────────────┘
```

Four stages. None of them analyses.

---

## 0.6 The strongest single piece of evidence

`examples/siem_parser.json` ships nine detection rules. Here is every one, with
its condition, verbatim:

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

**Every condition references exactly one event.** Not one of them relates two
events, and none of them could, given the engine signature in 0.2.

Now the part that makes this a gap rather than a design choice. The same file
declares correlation keys:

```json
"correlation_keys": {
  "session": "session_id",
  "trace": "trace_id",
  "description": "Use session_id to group all events in a conversation. Use trace_id to correlate events across agent delegations within a single request."
}
```

**The schema anticipates correlation. Nothing performs it.** The keys are
published, documented, and unused by every one of the nine shipped rules.

That is precisely the seam Cohaera occupies, and it is the reason issue #108
can say "28/34 AI analytics rules work today. Zero correlation rules can fire."

---

## Still unverified, and it matters

**I could not check whether these findings are already tracked upstream.**
GitHub's issue search returns an empty body to the fetch method available here.

Before presenting F-01 or F-02 as a discovery, search manually:

- `https://github.com/open-agent-ai-security/observra/issues?q=is%3Aissue+is%3Aclosed+sequence`
- `https://github.com/open-agent-ai-security/observra/issues?q=is%3Aissue+injection+tool_result`
- `https://github.com/open-agent-ai-security/observra/pulls?q=is%3Apr+is%3Aclosed+suspicious`

Being second is fine. Presenting something already tracked as new is not.
