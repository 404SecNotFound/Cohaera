# CH06 conformance results

Every case is derived from the same pristine signed stream. `PASS`
means both Cohaera and the independent baseline matched the
predeclared expectations in `expectations.json`.

| Case | Condition | Cohaera evidence (target / other) | CH06 (target / other) | Baseline | Result |
|---|---|---|---|---|---|
| `intact` | `intact` | `verified_complete / verified_complete` | `evaluated / evaluated` | `verified_complete` | **PASS** |
| `deleted` | `manipulated` | `inadmissible / inadmissible` | `degraded / degraded` | `inadmissible` | **PASS** |
| `modified` | `manipulated` | `inadmissible / verified_complete` | `degraded / evaluated` | `inadmissible` | **PASS** |
| `stripped` | `manipulated` | `inadmissible / inadmissible` | `degraded / degraded` | `inadmissible` | **PASS** |
| `reordered` | `benign_transport` | `verified_complete / verified_complete` | `evaluated / evaluated` | `verified_complete` | **PASS** |
| `truncated` | `incomplete` | `verified_prefix / chained_unsigned` | `degraded / degraded` | `verified_prefix` | **PASS** |
| `replayed` | `manipulated` | `inadmissible / inadmissible` | `degraded / degraded` | `replayed` | **PASS** |
| `no_key` | `missing_prerequisite` | `chained_unsigned / chained_unsigned` | `degraded / degraded` | `chained_unsigned` | **PASS** |
| `unsupported` | `unsupported` | `unattested / unattested` | `not_evaluated / not_evaluated` | `not_evaluated` | **PASS** |

## Acceptance checks

- Expectations met: **9 of 9**
- Manipulated affected sessions reported `verified_complete`: **0**
- Intact or reorder-only sessions reported inadmissible: **0**
- Missing or unsupported cases explicitly declined/degraded: **2 of 2**
