<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Changelog

Notable changes to Cohaera. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html) — with the caveat
that **0.x means the detector's output is not stable**. A patch release can
change which sessions alert, because that is what fixing a detector does. The
things that are stable within 0.x are the record schema, the check IDs and the
exit codes; the SIEM content pack depends on those and nothing else.

Every release states the false-positive rate. A detection release that only
reports recall is a marketing document.

## [Unreleased]

Pre-alpha. The evaluation card is regenerated on every change and CI fails on
any diff, so the numbers below are derived rather than claimed.

### Added

- **Evidence trust (P1).** Three sidecar schemas the collector can emit and
  Cohaera verifies out of band: `cohaera.integrity:1` (hash chain plus Ed25519
  over the chain head), `cohaera.receipt:1` (effect receipts binding a claimed
  action to an identifier the target system minted), and `cohaera.approval:1`
  (an approval bound to a specific call by span, tool and argument digest).
  Verified against a `cohaera.trust_store:1` with roles, validity windows,
  revocation and rotation chains.
- **A seen-stream ledger** (`--seen-streams`), which catches a stream replayed
  inside the freshness window and tells a replay apart from a fork — the same
  sequence carrying different, validly signed records.
- **CH06** (collector integrity) and **CH07** (a reported failure contradicted
  by an effect receipt).
- **Policy declarations in the capability manifest**, so a producer can say
  whether a control was advisory or blocking. This is the remedy for EVASION.md
  E20, where an in-band `advisory` claim silenced CH04.
- **Governance and release surfaces**: this file, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `CITATION.cff`, `CODEOWNERS`, issue forms and a pull
  request template.

### Changed

- **CH04 split** into a bypass of a *blocking* control and a continuation past
  an *advisory* one. Precision on the corpus went from 50% to 100%, and most of
  that is not a better detector: the check stopped being asked a question it
  could not answer.
- **Evaluation methodology.** Two recall columns — attributable (the check the
  corpus holds responsible fired) and any-alert — because reporting only the
  second published a check at full recall that had declined every one of its
  own labelled examples. False positives per 1,000 **benign** sessions rather
  than per 1,000 of a mixture whose prevalence is an artefact. A base-rate
  projection table. Coverage-weighted recall demoted to a diagnostic and
  renamed, because weighting a denominator by the detector's own completeness
  estimate lets a blind detector discount what it missed.
- **Classification confidence is worst-case, not the mean** over a session's
  calls. A mean is diluted by adding calls and the producer decides how many
  there are (COH-R07).
- **Verification is 3.76× faster** — a precomputed comb for `s · G`, a sliding
  window for `k · A`, and a per-key comb for signers that repeat. Signing keeps
  plain double-and-add: its scalars are secret and a table indexed by a secret's
  digits is a cache-timing channel.
- **The test suite runs in ~1m30s**, down from 7m28s, by caching the corpus's
  Ed25519 signatures (content-addressed, so there is no stale state) and by not
  re-assembling the same corpus once per regime.

### Fixed

- **COH-R01** — the input byte budget was checked after a whole physical record
  had been read and hashed, so a record with no newline could not be stopped
  while it was arriving.
- **COH-R02** — none of the declared bounds bounded *memory*. Every one counted
  input; this design holds the whole run in memory, and a parsed record costs
  about 32× its own bytes because the cost is driven by how many keys it has,
  not how long it is. `max_input_bytes` at 2 GiB was a licence for roughly
  64 GiB of process. There is now a `max_resident_bytes` budget, metered on
  retained bytes, enforced per record, reported in the ingest summary, and
  regression-tested against `tracemalloc` so the factor cannot become folklore.
  Under the defaults memory binds first, at about 64 MiB of accepted input.
  **This is a budget, not an architecture** — see *Known limitations*.
- **COH-R03** — CH03 read the scanner's `has_injection_patterns` with
  truthiness. `"false"` is a truthy string, so a scanner reporting it found
  *nothing* produced a critical finding. Both scanner fields now go through the
  schema firewall, and a malformed claim can neither fire the check nor buy its
  coverage.
- **COH-R04** — an aborted or truncated baseline could be fitted and used, with
  the run still exiting 0. It now fails closed, with `--allow-partial-baseline`
  as the explicit escape and the choice recorded in provenance.
- **COH-R05** — `CapabilityManifest` was a frozen dataclass around a mutable
  dict, so a tool's declared effects could be changed after both digests were
  taken. The mappings are copied and sealed at construction.
- **COH-R06** — `effects: [{}]` raised `TypeError: unhashable type` out of the
  manifest loader (membership tested before type), and
  `sensitive_args: 0` was silently read as "none declared".
- **COH-R07** — see *Changed*.
- **COH-R08** — the CLI's writeability probe opened the reject ledger in `w`
  mode before scoring, destroying the previous ledger; the write was also not
  atomic. Probe and write are both fixed.
- **COH-R10** — `json.loads` accepted duplicate object keys (a parser
  differential: last-wins here, first-wins elsewhere), `NaN`/`Infinity`, and
  floats that overflow to `inf`. All five parse sites now use a strict loader.
  Also: an integer too long for CPython to stringify raised a bare `ValueError`
  that the manifest and trust-store loaders did not catch, and ended the run.
- **COH-R12** — two ratios whose halves counted different populations. CH02
  counts a call as concealed only if it *executed*, but printed that count
  against every consequential call including the ones that failed, so one
  hidden egress among nine failed attempts read as "1 of 10". The attempts are
  still reported; they are no longer the denominator of a rate they could not
  contribute to. The same disagreement was live in CH07's coverage share and
  there it bought coverage rather than merely misreporting: the numerator was
  every call carrying a receipt, the denominator only the consequential ones,
  so a share above 1.0 clamped back to "fully covered" and a session whose only
  egress call had no receipt at all was reported evaluated at confidence 1.0.
  CH07's population is now every call that is consequential **or unclassified**
  — `read_only` is a positive classification, `unknown` is the absence of one,
  and scoping it to consequential calls alone made CH07 declare itself blind on
  64 corpus sessions where it had just produced a finding.
- **COH-R14 / COH-R16** — the direct evasion runner missed a test defined after
  its `__main__` block, and CI actions were not pinned to commit SHAs.
- **E02** — a diluted attack is no longer a quiet session; **E16** — a
  shared-prefix tool mention is no longer read as disclosure.

### Known limitations

- The corpus is synthetic, written by the detector's author, at an attack
  prevalence of 33%. There is no adaptive attacker and no real agent traffic.
- The corpus grades the *checks*. It does not grade the schema firewall, the
  coverage arithmetic or the manifest loader — two real defects (COH-R03,
  COH-R07) were fixed in this cycle with the card unmoved, because every corpus
  session is well-formed and homogeneous in the ways those defects needed. Half
  of COH-R12 is the one exception, and it reached the card only as a side
  effect of the `producer_flag` ablation rather than by design; see
  `eval/README.md`.
- **20 constructed evasions are catalogued and 19 still work**, on purpose:
  `tests/test_evasion.py` asserts they do, so that closing one without updating
  the catalogue fails the build.
- **Cohaera still holds the whole run in memory.** `load` materialises every
  event, groups them, and returns every session at once. COH-R02 added a budget
  so that exceeding it is a reported abort with a reason code rather than the
  kernel choosing which process dies — but the ceiling it enforces is low
  (about 64 MiB of accepted telemetry per run under the defaults) because that
  is what this design actually costs. Bounded session windows, a spool and
  external sorting are the fix; they are not built.

## [0.2.0]

First tagged version, and the first with an evaluation card. See
[`eval/EVALUATION-CARD.md`](eval/EVALUATION-CARD.md) for the numbers, which
include a false-positive rate that is not usable in a SOC and a name-only
condition where recall falls by 46.7 points.

[Unreleased]: https://github.com/404SecNotFound/Cohaera/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/404SecNotFound/Cohaera/releases/tag/v0.2.0
