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
  **This is a budget, not an architecture** — see *Known limitations*, and
  `docs/BOUNDED-SESSIONS.md` for the scoping of the architecture half, which is
  proposed rather than built because it needs a session-completion rule and
  that is a semantics decision that changes what the corpus measures.
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
- **COH-R09** — a scanner's answer is evidence about the call it names, and it
  was being read as evidence about the session. COH-R03 fixed the *type* half
  (a malformed claim buys nothing); this is the *binding*. One well-formed
  answer anywhere made CH03's contract report a scanner as having run, so ten
  pages fetched with one of them scanned reported the check at full strength
  over nine unexamined entry points. `has_result` had the same shape — `any()`
  over the session — so capturing `tool_result` on one trivial read and
  stripping it from the nine that returned attacker-controlled text cost
  nothing either. Both are now shares over the calls that can bring untrusted
  content in, with answers bound to a call by span where the span names one and
  by tool name otherwise; an answer naming no call in the session is counted
  and reported rather than dropped. Consequential calls are excluded from that
  surface, because they are what CH03 orders the markers *against*.
  **This moved the card**: self-reported coverage on the headline manifest rows
  went 0.77 → 0.76, `mean_coverage_completeness` fell by 0.004–0.008 in every
  cell, and `weighted_detected_mass` by 0.0013 in the family-holdout cells,
  the last only because it is weighted by completeness. Every recall, precision
  and false-positive figure is unchanged to the digit, because no finding
  changed — 168 of 1,824 corpus sessions scan one read of two or one of three,
  and the card now says so instead of scoring them as fully examined.
- **COH-R11** — CH03 and CH04 each decided "did this call run after that
  event?" with one comparison against the wall clock, and they disagreed with
  each other: CH03 used `>=` so a tie was *after*, CH04 used `>` so a tie was
  *before* and the call was dropped. CH04's reading was purchasable — the
  producer emits both timestamps, so stamping a consequential call on the
  guardrail's own tick silenced the check with no other change to the session,
  and a collector stamping at millisecond resolution reaches the same tie by
  accident. Ordering is now three-valued and shared by both checks: the
  `cohaera.integrity:1` sequence decides it where both records carry one from
  the same stream, because that sequence is covered by the hash chain and the
  signature over its head; the clock decides it where it is strictly unequal;
  and a tie with neither is **indeterminate**, counted in the finding's
  evidence and charged against the check's coverage as
  `EVENT_ORDER_INDETERMINATE`, rather than resolved in either direction.
  Catalogued as **E23**, because the finding is still suppressed by a tie — a
  tie genuinely does not establish an order — and what changed is that the
  silence is now visible. Emitting the integrity sidecar closes it outright.

  **A follow-up in the same cycle fixed a regression this first version
  introduced.** Ordering became sequence-primary, but the *reference event* was
  still chosen by `min(timestamp)` — the instrument the same change had just
  declared forgeable. With markers at (seq 1, ts 100) and (seq 9, ts 50), the
  clock picks the second, the sequence says a call at seq 5 ran after the
  first, and the finding disappears; both CH03 and CH04 lost findings they had
  produced before R11, and only on streams carrying `cohaera.integrity:1`, so
  the regression was exclusive to deployments that had done the work to be
  verifiable. The ordering question is existential — untrusted content was
  read, or a control fired, and then a call ran — so it is now asked against
  every reference, with AFTER winning. Kept O(M + N): comparing every call
  against every reference is the O(N*M) shape documented on
  `ch04_guardrail_overrun`, and trading a missed finding for an availability
  fault is not a fix.
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
- **COH-R13** — `seal()` froze a session's event list and nothing else. The
  fault C4-08 closed was still open one field over: `manifest` decides how every
  call is classified, so rebinding it after sealing either served classes cached
  under the previous manifest — an egress call still reported `read_only` — or
  silently reclassified the session under a manifest it was never sealed with.
  `integrity` was rebindable too, where `None` means no verification ran and
  must not be forgeable into a verdict, and so was `_sealed` itself, so the seal
  could be switched off and the event list reopened. A sealed session is now
  read-only in every field except its two cache slots. Separately,
  `Event(raw=...)` accepted a non-object and raised `AttributeError` from
  whichever accessor ran first; it now rejects at construction. A non-object
  from the wire is still quarantined as `NOT_A_JSON_OBJECT` rather than raising
  — that path is rule 3 and stays rule 3.
- **COH-R15** — the project shipped annotations that nothing checked and that no
  downstream consumer could read. `mypy` is now in the dev extra with an upper
  bound, configured in `pyproject.toml` so the gate means the same thing
  everywhere, and run in CI; the 24 errors it found on first run are fixed. Two
  of its flags are deliberately off with the reasoning recorded beside them --
  `warn_unreachable` fires only on defensive `isinstance` guards the schema
  firewall makes on purpose, and `warn_unused_ignores` disagrees with itself
  across the supported mypy range. `py.typed` now ships in the wheel, checked on
  the *installed* package: present in `src/` and missing from the wheel means
  every downstream type checker silently reads `import cohaera` as `Any`, and
  nothing in the repository looks wrong.
- **COH-R17** — the `sbom` job ran `cyclonedx-py environment` against the
  runner's own interpreter and uploaded the result under a step named "Generate
  an SBOM for the built artefact". It was an SBOM of the build machine: 94
  components when reproduced here — pip, build, cyclonedx-bom, setuptools and
  whatever the image ships — with cohaera the subject of none of them. The SBOM
  is now taken of a virtualenv containing only the installed wheel, so it
  describes the artefact's real dependency closure, and it is **asserted on**
  rather than only uploaded: the document's subject must be cohaera, and the
  closure must be empty. That second assertion re-derives the zero-dependency
  claim from the installed closure, independently of the distribution metadata
  the test job reads.
- **COH-R18** — the lab's isolation was asserted in prose and tested by nobody.
  Three things that looked like checks and were not. `Invoke-Tool` declared a
  `-TimeoutSec` parameter its body never read, so the call sites that passed one
  got no deadline while the signature said otherwise — and packer, vmrun and
  vnetlib64 are tools that *hang* rather than fail. A missing ISO checksum was a
  warning, so the build proceeded from an unverified image, which makes every
  isolation property downstream unfalsifiable; it now fails closed with an
  `-AllowUnverifiedIso` escape, on the COH-R04 pattern, and a checksum that *is*
  set is compared against the file at preflight rather than by Packer forty
  minutes in. And the `verify` stage printed the isolation checks for the
  operator to run by hand: they are now a declarative `Reachability` matrix in
  `lab.config.psd1`, executed on the guests over SSH, failing the run on any
  disagreement — with a probe that could not run counted as a failure rather
  than a pass, and `collector-01` separately checked not to forward between its
  segments. `tests/test_lab.py` pins all of it. **The script itself is still
  unexecuted**: it is PowerShell for VMware Workstation, there is no interpreter
  or hypervisor in the environment it was authored in, and those tests read it
  as text. Weaker than running it; stronger than nothing.
- **COH-R14 / COH-R16** — the direct evasion runner missed a test defined after
  its `__main__` block, and CI actions were not pinned to commit SHAs.
- **E02** — a diluted attack is no longer a quiet session; **E16** — a
  shared-prefix tool mention is no longer read as disclosure.

### Known limitations

- The corpus is synthetic, written by the detector's author, at an attack
  prevalence of 33%. There is no adaptive attacker and no real agent traffic.
- The corpus grades the *checks*. It does not grade the schema firewall, the
  coverage arithmetic or the manifest loader — three real defects (COH-R03,
  COH-R07, COH-R13) were fixed in this cycle with the card unmoved, because
  every corpus session is well-formed and homogeneous in the ways those defects
  needed, and because a corpus measures what the code does rather than what its
  API permits. Half
  of COH-R12 is the one exception, and it reached the card only as a side
  effect of the `producer_flag` ablation rather than by design; see
  `eval/README.md`.
- **21 constructed evasions are catalogued and 20 still work**, on purpose:
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
