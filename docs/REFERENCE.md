<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Reference: input, output, exit codes, flags

This page lists what `cohaera score` reads, what it writes, how it exits, and
every flag it accepts. Each statement is taken from the source file named
beside it. Where the code is the contract, the code wins; a mismatch here is a
documentation defect, so report it.

## 1. Input format

Input today is observra-shaped JSONL: one JSON object per line, one event per
object. There is no other adapter yet; OpenTelemetry and further exported
formats are milestone M4 in [DIRECTION.md](DIRECTION.md).

### Parsing rules

`src/cohaera/validate.py` decodes each line with a strict parser. A record is
**rejected** (quarantined with a reason code and a digest, never scored) when:

- it is not valid JSON, or an object repeats a key;
- it contains `NaN`, `Infinity`, `-Infinity`, or a float that overflows;
- it contains an integer with more than 1024 digits;
- it exceeds `--max-line-bytes` or nests deeper than `--max-nesting-depth`;
- it builds more objects or keys than the resident-memory bound allows.

A record that parses but carries a field of the wrong type survives with a
**defect** code: the bad field is treated as absent, never coerced, and the
defect code lowers the confidence of the checks that needed it. Identity
fields that are too long are rejected rather than truncated, because a
truncated identity is a forged one.

### Envelope fields

`validate.view` reads these top-level fields:

| Field | Type read | Notes |
|---|---|---|
| `event_type` | string | empty or wrong type records a defect and the event has no type |
| `session_id` | string | primary correlation key |
| `trace_id` | string | secondary correlation key |
| `span_id` | string | pairs `tool_start` with its terminal event; a boolean or number is a defect |
| `tool_name` | string | the name the heuristic classifier reads when no manifest entry matches |
| `timestamp` | finite positive number, or a numeric string | epoch seconds; anything else records a defect and the event sorts last |
| `host`, `user`, `agent_name`, `framework` | string | identity and attribution |
| `data` | object | the data bag below; a non-object is a defect and reads as empty |
| `integrity` | object | the `cohaera.integrity:1` sidecar, read by `src/cohaera/evidence.py` |

A record with none of `session_id`, `trace_id`, `host`, `user`, `agent_name`
and `framework` has no identity and is not assembled into a session.

### Event types with meaning

`src/cohaera/model.py` gives these `event_type` values a role:

- `tool_start`, `tool_end`, `tool_error`: open and close a tool call by
  `span_id`;
- `model_response`: carries the final response text CH02 reads;
- `model_error`, `turn`, `agent_end`: terminal events for pairing and error
  counts;
- `agent_handoff`, `agent_handoff_error`: delegation edges;
- `user_message`: the user's text;
- `cost_threshold_exceeded`, `depth_exceeded`: policy events, which may carry
  an approval.

Other values are kept in the session and counted, and nothing else reads them.

### `data.*` fields

| Field | Read by | Meaning |
|---|---|---|
| `tool_args` | `model.py` | the call's arguments; their digest is the authoritative argument identity |
| `arg_digest` | `model.py` | the producer's declared `sha256:` digest, compared with the computed one |
| `reversible` | `model.py` | boolean only; any other type is a defect |
| `tool_result` | `model.py`, `content_scan.py` | presence sets `had_result`; the local content scan reads its text |
| `duration_ms` | `model.py` | finite number |
| `error_class`, `error_type_name` | `model.py` | error attribution on a terminal event |
| `response_text` | `model.py` | the agent's final account, on `model_response`; truncated at a bound and the truncation recorded |
| `user_message_text` | `model.py` | on `user_message` |
| `has_injection_patterns` | `model.py`, `checks.py` | boolean only; the upstream scanner's verdict |
| `injection_patterns` | `model.py` | list of non-empty strings, all or nothing |
| `current_depth` | `model.py` | integer delegation depth |
| `source_agent`, `target_agent` | `model.py` | on handoff events |
| `session_cost_usd`, `cost_usd` | `model.py` | the session maximum wins; otherwise per-call costs are summed |
| `policy_id`, `enforcement` | `checks.py`, `evidence.py` | on policy events; `enforcement` is `blocking` or `advisory`, anything else reads as undeclared |
| `effect_receipt` | `evidence.py` | the `cohaera.receipt:1` sidecar |
| `approval` | `evidence.py` | the `cohaera.approval:1` sidecar |

### The three sidecars

Defined in `src/cohaera/evidence.py`; wire formats and what each proves are
in [EVIDENCE-TRUST.md](EVIDENCE-TRUST.md).

| Sidecar | Where | Fields read |
|---|---|---|
| `cohaera.integrity:1` | top-level `integrity` | `scheme`, `stream_id`, `seq`, `prev`, `chain`, `key_id`, `sig` |
| `cohaera.receipt:1` | `data.effect_receipt` | `scheme`, `authority`, `kind`, `identifier`, `binding{span_id, tool_id, arg_digest}`, `observed_at` |
| `cohaera.approval:1` | `data.approval` | `scheme`, `decision`, `subject{span_id, tool_id, arg_digest}`, `granted_by`, `granted_at`, `expires_at`, `policy_id`, `policy_digest`, `enforcement`, `nonce`, `signature{key_id, sig}` |

A sidecar with the wrong `scheme` or a malformed required field is dropped
with a defect code; the record itself survives.

## 2. Output record

`cohaera score` writes one JSON object per assembled session to stdout
(`to_cim_event` in `src/cohaera/model.py`). Human-readable findings and
coverage gaps go to stderr, sanitised against control characters.

### Top-level fields

| Field | Value | Null semantics |
|---|---|---|
| `type` | `cohaera_session_verdict` | never null |
| `schema` | `cohaera:0.3` | never null |
| `event_type` | `cohaera_session_verdict` | kept for parsers that read `event_type` |
| `timestamp` | the latest valid event timestamp in the session | `0.0` when no event carried a valid clock |
| `session_id` | the session key | never null |
| `trace_id` | the same value as `session_id` | never null |
| `agent_name` | the first agent name seen | `null` when no event carried one |
| `framework` | the first framework seen | the string `unknown` when none was seen, not null |
| `host`, `user` | the first value seen | `null` when none was seen |
| `log_source_type` | `cohaera` | never null |
| `verdict_id` | digest of run identity, session, findings, session content and coverage | never null; identical input and configuration reproduce it |
| `findings_digest` | digest of the findings list | never null |
| `sequence` | 0-based position of this verdict in the run | `null` when the record is built outside the CLI |
| `data` | the body below | never null |

### `data` body

- the session feature vector: identity, `started_at`, `duration_s`, counts
  of calls by class, `tool_sequence` (capped at `--max-evidence-items`, with
  `tool_sequence_truncated` saying whether it was), pairing counts, handoffs,
  policy events, cost, `has_final_response_text`, `tool_results_captured`,
  `correlation`, `integrity_defects` and `invalid_timestamp_count`;
- `triggered_rules`: sorted check ids that fired; `triggered_families`;
- `max_severity`: `info` when nothing fired;
- `finding_count` and `findings`, each finding carrying `check`, `severity`,
  `title`, `detail`, `evidence`, `family`, `confidence` and
  `evidence_status`;
- `provenance`: `analysis_run_id`, `detector_version`, `config_hash`,
  `trust_config_digest`, baseline, manifest, trust-store, policy-attestation,
  freshness, ledger, stream and ingest summaries;
- `coverage` (`cohaera.coverage:2`, from `src/cohaera/checks.py`):
  `evidence_status`, one of `unattested`, `chained`, `verified_prefix`,
  `verified_complete` or `inadmissible`; `checks_total`, `checks_evaluated`,
  `checks_degraded`, `checks_not_evaluated`; `completeness` (confidence
  weighted, not a count); correlation, classification and clock confidences;
  `checks`, one contract per check with status, confidence, surfaces,
  reasons, remedies and assumptions; and `gaps`, the flat list of every check
  that was not fully evaluated.

Any non-finite number anywhere in the record is replaced by
`{"_invalid_number": "<repr>"}` so the line stays valid JSON.

## 3. Exit codes

From `EXIT_*` in `src/cohaera/cli.py`:

| Code | Name | Meaning |
|---|---|---|
| `0` | `EXIT_OK` | every record was accepted and every verdict was written |
| `1` | `EXIT_ERROR` | the run could not be completed as requested: a bound that is not a bound, a manifest, trust store, policy signature or ledger that was rejected, a signature that was supplied and failed, an audit artefact that could not be written, or an unexpected `OSError` |
| `2` | usage error | argparse: an unknown flag or a bound outside its valid range |
| `3` | `EXIT_PARTIAL` | some records were quarantined and the run was not strict; the verdicts written are complete for the records accepted |
| `4` | `EXIT_STRICT_REJECT` | `--strict` was given and at least one record was quarantined |
| `5` | `EXIT_BUDGET` | a reject budget or resource bound was exceeded, or the baseline was partial without `--allow-partial-baseline`; output is incomplete |

Verdicts are printed before the exit code is decided, so a `3` or `5` still
leaves the accepted verdicts on stdout.

## 4. Environment variables

`cli.py` reads one environment variable:

| Variable | Read when | Effect |
|---|---|---|
| `COHAERA_CORRELATION_SECRET` | every run, unless `--correlation-secret-env NAME` names another variable | HMAC key for anonymous session keys. Unset, the keys are plain SHA-256 digests, a warning goes to stderr, and `correlation_keyed` is `false` in provenance |

## 5. `cohaera score` flags

Grouped by purpose; the text of each is from `cohaera score --help`. The only
subcommand is `score`. There is no `--version` flag; read
`cohaera.__version__` or `pip show cohaera`.

### Inputs

| Flag | Purpose |
|---|---|
| `telemetry` | positional: the observra JSONL file to score |
| `--baseline BASELINE` | benign JSONL to fit the CH01 sequence grammar |
| `--tool-manifest PATH` | capability manifest keyed on exact tool id; declared capabilities outrank the name heuristic and the producer's `reversible` flag |
| `--allow-partial-baseline` | fit the grammar even when the baseline was partially read or quarantined; off by default, recorded in provenance |

### Keys and policy signatures

| Flag | Purpose |
|---|---|
| `--trust-store PATH` | `cohaera.trust_store:1`: public keys, roles, validity windows, revocation. Without it signed records are parsed and not verified, and coverage says `NO_COLLECTOR_KEYS` |
| `--collector-keys PATH` | superseded name for `--trust-store`; a `cohaera.collector_keys:1` file loads as collector-role keys only |
| `--tool-manifest-sig PATH` | detached `cohaera.policy_signature:1` over the manifest; supplied and failing is a refusal to score |
| `--baseline-sig PATH` | detached `cohaera.policy_signature:1` over the baseline |
| `--require-signed-policy` | refuse to run unless every supplied policy file carries a signature that verified; off by default |

### Approvals

| Flag | Purpose |
|---|---|
| `--seen-approvals PATH` | ledger of spent approval nonces, kept between runs; unsigned, per host |
| `--require-signed-approvals` | an approval no issuer signed does not cover a call; off by default because a deployment with no approval keys would read every authorised action as a bypass |

### Freshness and replay

| Flag | Purpose |
|---|---|
| `--seen-streams PATH` | observation ledger of collector streams already scored, kept between runs; detects a stream re-fed inside the freshness window |
| `--evidence-max-age SECONDS` | report signed records older than this as `INTEGRITY_EVIDENCE_STALE`; off by default, and coverage says `NO_FRESHNESS_BOUND` |
| `--evidence-as-of EPOCH` | the instant the age is measured from; defaults to the wall clock, must be finite |
| `--max-future-skew SECONDS` | how far after `--evidence-as-of` a verified record may be dated before it is inadmissible (default 300) |

### Correlation

| Flag | Purpose |
|---|---|
| `--correlation-secret-env NAME` | environment variable holding the HMAC key (default `COHAERA_CORRELATION_SECRET`) |

### Quarantine and exit behaviour

| Flag | Purpose |
|---|---|
| `--strict` | exit 4 if any record is quarantined |
| `--max-rejects N` | exit 5 if more than N records are quarantined |
| `--max-reject-ratio F` | exit 5 if the quarantined fraction exceeds F |
| `--reject-log PATH` | write the quarantine ledger as JSONL; an unwritable path is exit 1 |

### Resource bounds

| Flag | Purpose |
|---|---|
| `--max-line-bytes N` | bytes per JSONL record (default 1048576) |
| `--max-nesting-depth N` | JSON container depth (default 64) |
| `--max-events N` | accepted events per run (default 2000000); records read are bounded separately at 4000000 |
| `--max-sessions N` | sessions assembled per run (default 100000) |
| `--max-evidence-items N` | rows carried in any one evidence field (default 50) |

Every bound is folded into `config_hash`, so two runs with different bounds
have different run identities.
