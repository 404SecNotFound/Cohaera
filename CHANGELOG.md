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
- **Receipts and approvals that bound to almost nothing were trusted as if they
  bound to everything (R-01, R-10).** `BINDING_TRUSTED` contained
  `bound_span_only`, and `Binding.parse` accepted `{}` as a binding. Together
  that meant a receipt carrying a valid authority, kind and identifier and an
  empty `binding` object produced a **critical** CH07 contradiction on a failed
  egress call — a critical detection resting on a check that had never run — and
  an approval naming the span and the tool but not the argument digest
  suppressed CH04 outright, so a bypass approved on evidence the schema was not
  designed to carry reported as nothing at all. The `Binding` docstring had said
  for two releases that `arg_digest` "is the only one of the three that
  constrains what the call actually DID"; the code disagreed with it.

  All three fields must now be present and all three must match for a binding to
  be trusted. `bound_span_only` moved to a new `BINDING_CONTEXT` set that may be
  shown to an analyst and may never gate a trust decision, and an empty binding
  object is rejected as a defect rather than accepted as a weak binding.
  Verified over all seven proper subsets of {span, tool, arg}, on both paths.

  **Breaking for content, and additive for the record.** A new check ID
  `CH07_effect_receipt_partially_bound` (`low`) reports a receipt that omits a
  field on a call that did not report success — kept distinct from
  `CH07_effect_receipt_does_not_bind`, which is a receipt that names a
  *different* call, because omission and disagreement are different facts and
  only the second looks like a copied receipt. A new CH04 approval state
  `approval_not_argument_bound`. A new CH07 coverage reason
  `RECEIPT_BOUND_BY_SPAN_ONLY`, which costs half a loose receipt's worth of
  confidence — degraded rather than blind, because CH07 still reads and reports
  those receipts. New Sigma rule `cohaera_effect_receipt_partially_bound.yml`.
  **No evaluation-card number moved**: the corpus emits complete bindings on
  every receipt and approval, so the fix changes what would happen to a
  real producer's partial evidence and changes nothing about the measurement.
- **A freshness window only bounded one direction, and one CLI argument switched
  it off in silence (R-13).** `Freshness.stale` reported a future-dated record as
  not stale and computed nothing else, so a signed record dated a year ahead read
  in the verdict exactly like one written a second ago: a collector with a wrong
  clock, or one an attacker holds, bought unlimited freshness by adding to a
  number. The docstring called clock skew "somebody else's finding" and nobody
  else made it. A signed record dated more than `--max-future-skew` seconds past
  `--evidence-as-of` is now `INTEGRITY_EVIDENCE_FROM_FUTURE` and **inadmissible**
  — the whole argument for trusting the timestamp is that a replayer can re-send
  bytes and cannot re-date them, and a record dated after the instant it was
  scored breaks that argument at the root. It is a separate code from
  `INTEGRITY_EVIDENCE_STALE` because the remedies differ. Default tolerance 300s,
  the same reason Kerberos uses it: it absorbs ordinary NTP disagreement and
  nothing more.

  Separately, `--evidence-as-of` was `type=float` and `float("nan")` succeeds, so
  `--evidence-as-of nan` disabled the freshness bound entirely — `enabled` went
  false, the bound line never printed, and the run exited **zero** having skipped
  the check it was asked for. It now goes through a finite-float validator and
  exits 2 as a usage error, as does `--max-future-skew`; `Limits` refuses a
  non-finite or negative value directly, since the CLI is one door of several.

  Additive: `max_future_skew_s` in `Limits` and in the `evidence_freshness`
  provenance block, `furthest_future_s` in the integrity evidence, and the
  `--max-future-skew` flag. **The evaluation card's `config_hash` moves** — a new
  bound joined the set, so two runs either side of this are correctly reported as
  not comparable in configuration. No detection number moved.
- **A policy file could be swapped between the read that parsed it and the read
  that hashed it (R-07).** `CapabilityManifest.from_file` resolved the path and
  parsed it; the CLI then resolved the same path again to hash it for the
  signature, and the baseline was hashed by path and reopened by `load`. A path
  is not bytes: an atomic rename in that window left Cohaera scoring one file and
  attesting the digest of another, with the signature still holding, so the
  verdict carried `POLICY_SIGNATURE_VERIFIED` for a file that had not been used.

  Each artefact is resolved once now. `CapabilityManifest.from_bytes` parses and
  digests a single buffer and `from_file` is a bounded read in front of it; the
  manifest carries `file_sha256` over exactly those bytes and `_attest_policy`
  takes a digest instead of a path, so it can no longer reach the filesystem.
  The baseline keeps its streaming read — it is telemetry and may be large — and
  is instead opened once, hashed through the new `stream_sha256`, rewound and
  handed to the reader, since an open descriptor keeps its inode whatever
  happens to the path. `load` and `read_events` take an optional descriptor for
  that. The baseline is hashed only when `--baseline-sig` was supplied, so an
  oversize baseline is still truncated by the reader's budget rather than
  refused. Additive: `file_sha256` in the manifest's provenance block.
- **`approved` in a verdict was an authorization fact and is now an approval
  claim.** Every approval Cohaera can parse arrives in band, on the stream the
  agent produces. Approvals now carry `approval_origin` (`in_band`), CH04
  findings carry `approval_origins`, and `policy_engine` is defined for an
  out-of-band attested decision that nothing emits yet.
- **A signature forgery in the bundled Ed25519 verifier, reported by a seventh
  review and reproduced here.** Verification checks `[s]G == R + [k]A`. Supply
  the identity point as `A` and the `[k]A` term vanishes, so any `R = [s]G`
  satisfies the equation **for every message** — one 64-byte string that
  verifies anything, under a key that has never signed anything. Three of the
  eight canonical small-order encodings reached that outcome. RFC 8032 does not
  require rejecting these; every serious implementation does it anyway.
  Two layers now do: `verify` rejects small-order `A` and `R` for three point
  doublings, and the trust store refuses any key that is not a canonical point
  of order L, which is the full check and is affordable once per key at load
  rather than once per signature. The subgroup test alone is *not* sufficient —
  `[L]·identity == identity`, so a check that forgets to exclude the torsion
  subgroup readmits the exact key the forgery used.
  The review's wider recommendation — drop the hand-written verifier for
  libsodium or `cryptography` — is a live question this does not settle. It
  trades the zero-dependency commitment for not owning cryptographic code, and
  that is a project decision rather than a defect fix.
- **The clock could decide whether the evidence existed at all.** CH03 dropped
  a marked read whose timestamp was unparseable before any ordering ran, so one
  malformed field on the only marked read emptied the check; CH04 returned
  nothing when every firing of a control had one. Both are the producer
  deciding what Cohaera may look at, which is what the collector sequence
  exists to take away from it. Markers and firings are now kept regardless of
  their clock and ordered by sequence where one exists; a reference nothing can
  order is reported as indeterminate rather than dropped. A named firing with
  no readable clock reports `policy_event_first_ts: null` — not `NaN`, which
  the CLI's `allow_nan=False` would refuse to serialise.

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
