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

### Added

- **Approvals can now be signed, bounded and spent once** — EVASION.md E26, half
  closed. An approval was previously plain JSON on a stream the agent writes:
  rewriting one field, `subject.span_id`, moved a real approval onto a call it
  was never issued for, and nothing recorded it as used or made it expire.

  `cohaera.approval:1` gains a `nonce` and a detached issuer `signature`. The
  trust store gains an **`approval` role**, so the party issuing approvals is
  not the party signing telemetry — a deployment where one key does both is
  exactly the arrangement the signature exists to rule out. `--seen-approvals`
  keeps a ledger of spent nonces that survives across runs, and
  `--require-signed-approvals` decides whether an unverified approval still
  covers a call.

  Assurance is **tiered** the way receipt trust is: `claimed`, `bound`,
  `authenticated`, `single_use`. Unlike the receipt tiers, the top two are
  reachable — the schema has a signature field and the store has a role.

  Three design points, each a place this could have been theatre. **The signing
  input covers the span**, so the edit that defeats binding breaks the
  signature; it is a fixed field list joined by `\x1f` rather than canonical
  JSON, because canonicalisation problems are where signature bugs live. **The
  signature covers and requires `expires_at`**, so an issuer cannot mint an
  eternal signed approval — that closes the window problem by construction
  rather than by a flag. And **a nonce counts only on an approval whose
  signature verified**, because an attacker who can rewrite the span can rewrite
  the nonce in the same edit; that invariant survived a mutation run until a
  test was written specifically for it.

  **The default deployment is unchanged, deliberately.** Requiring signatures
  unconditionally would make every authorised action in every keyless deployment
  look like a bypass. So E26 is `half_closed` with precondition *signed
  approvals*, exactly as E13 and E21 are conditional on a signed stream.

  **The ledger inherits E22 whole**, stated here rather than discovered later:
  it is a local file that cannot be signed by anyone but the host holding it,
  so deleting it restores the replay, and it is per-host so a second collector
  never saw it.

  `Limits` gains `max_approval_nonces`, so **every `verdict_id` and
  `config_hash` changes** again.


- **A check that asks whether a cited control ever existed, and E24 half closed**
  (`CH04_undeclared_control_cited`). A consequential call fails for an ordinary
  infrastructure reason; the producer emits a policy event attributing the
  failure to a control; the response cites the policy. The session now carries a
  documented refusal that nothing refused, and an incident review reading it
  concludes the guardrails worked.

  Every check was looking elsewhere, each for a good reason. CH04 asks what
  happened *after* a control fired, and here nothing did. CH07 falsifies a
  reported failure carrying an effect receipt, and here the failure is genuine
  with no receipt. **Nothing asked the prior question.** A policy event was
  accepted as a control on the strength of its own `policy_id`.

  It now raises a `medium` finding carrying both lists — cited and declared.
  Three deliberate limits: it does not fire where the manifest declares no
  `policies` section (silence is not a denial, and reading it as one would fire
  on nearly every deployment); it is `medium` rather than high because an
  out-of-date manifest produces the identical verdict and Cohaera cannot tell
  them apart; and it is **not scored by the evaluation card**, because no corpus
  session pairs a declared-policies manifest with an outside citation.

  **Half of E24 remains open, which is the half that matters.** An attacker who
  reads the manifest and cites a control that IS declared produces no finding,
  because nothing signs a policy event —
  `cohaera.policy_signature:1` attests a file, not an event. The cost went from
  "one event" to "one event naming a declared control", which raises nothing
  against an attacker who can read the manifest. `test_evasion_24` now runs both
  shapes and asserts exactly that.

### Changed

- **The content pack can say a check ID is unmeasured** (`unscored_check_id`).
  The evaluation card scores per coverage *family*, so a check ID added after
  its family was measured inherits numbers taken without it. Quoting them is the
  laundering `test_the_check_a_rule_claims_evidence_for_is_the_one_it_selects_on`
  exists to stop; dropping the family loses the link. A rule may now declare the
  gap instead, which bars the `production` tier and forbids every numeric
  evidence key. `CH04_guardrail_overrun` is consequently the first family to
  span two deployment tiers, and the inventory test records why.

- **`content/README.md`'s false-positive count is derived.** It read "Five of
  the 14" over a list of six bullets — defensible only if the dashboard entry
  was not meant to count, and unknowable to a reader either way. It is now two
  derived claims over the bullets themselves, which also forced the prose to
  stop drawing a distinction it never explained. That number is the one telling
  a deploying engineer what will page them, and nothing recomputed it.


- **A second opinion on captured tool output, and E09 half closed with it**
  (`src/cohaera/content_scan.py`). CH03's detection ceiling is set by the
  upstream scanner's pattern list, so an attacker who stays below it evades the
  check entirely — EVASION.md E09, the most important entry in that file.

  E09's remedy line said "scan `tool_result` inside Cohaera". Finding F-16 had
  already refused exactly that, in a code comment and a passing test, because a
  detector generating its own taint evidence grades its own work. **Both
  documents were in the tree, giving opposite instructions, for two revisions.**
  The drift was in the reasoning rather than in a count, and counts are the only
  thing this repository recomputes.

  Resolved by tiering the evidence the way CH07's effect receipts are tiered. An
  upstream answer is evidence about *content*; a local pass is evidence about
  *the scanner*. The local pass therefore cannot behave like a marker: it never
  makes `scanner_marked` true, so **no CH03 finding is ever built on it**; it
  never moves CH03 off `not_evaluated`; and it can only lower a confidence or
  add a remedy, never raise one. No content buys a session a cleaner report.

  Two new reason codes carry it. `UNSCANNED_CONTENT_CARRIES_MARKERS` — content
  was captured, nothing upstream examined it, and it matches Cohaera's patterns.
  `SCANNER_ANSWER_CONTRADICTED_BY_CONTENT` — a scanner examined the call, called
  it clean, and Cohaera's patterns disagree. The second is E09 made visible, and
  it costs CH03 half the confidence of the disputed share rather than all of it,
  because a disagreement between two regex lists may be Cohaera's error.

  **The ceiling is not closed and the entry says so.** An attacker below both
  pattern lists is where E09 left them, with one more list to evade.

  **Not measured, stated plainly.** The evaluation corpus cannot exercise this
  in either direction: its 216 injection-marked records carry no `tool_result`,
  and all 7,156 captured results in it are the literal string `ok`. Zero false
  positives and zero true positives, neither meaning anything. That the corpus
  has no content channel at all is the larger finding, and it is now recorded
  against the external-corpus item in `docs/OUTSTANDING.md`.

  `Limits` gains `max_scanned_result_chars` (64 KiB), so **every `verdict_id`
  and `config_hash` changes** — the bounds digest binds configuration into
  verdict identity, and a new bound is a configuration change. A SIEM
  deduplicating on those IDs will see all-new ones after this release.

### Fixed

- **CH04's coverage contract, which was inverted.** `coverage()` added
  `policy_semantics` and `approval_binding` to CH04's required surfaces only
  `if has_policy` — only once policy events already existed. So the one state
  that cost CH04 nothing was the state where it had no guardrail evidence
  whatsoever: a session with a consequential egress call, zero policy events
  and zero approval records reported `evaluated` at confidence **1.0**, with an
  empty `missing_surfaces` and no reason codes. Full confidence precisely where
  there was nothing to be confident about, and not a rare corner — it is every
  public trace corpus and every deployment that has not wired a policy engine
  to its telemetry. CH06 and CH07 have always declined in the equivalent state
  and named the surface they were short of.

  The required list is now unconditional, and a session with no policy evidence
  reports `not_evaluated` with the new reason code `NO_POLICY_EVIDENCE`. Two
  different worlds produce a session with no firing — a governed agent that
  stayed inside its limits, and an agent with no limits at all — and the event
  stream cannot tell them apart, because both are an absence. The operator's
  capability manifest can: a `policies` section declares that the controls
  exist, and with one, silence is a control that did not trip and CH04 reports
  `evaluated`. Found by pointing the detector at traces with no control plane,
  which is something the internal corpus cannot do: it always emits policy
  events.

  **No finding moved**, on any corpus session, in either direction. CH04 could
  not fire on a session with no policy event before the change either.
  `mean_coverage_completeness` falls in every cell of the evaluation grid —
  0.76 to 0.65 on the headline cell — which is the contract working rather
  than a regression. Recall, false-positive rate, precision and per-check
  alert precision are unchanged to the session, and the three benign kinds
  that exercise a control firing on correct behaviour
  (`benign_hard_advisory_threshold`, `benign_hard_approved_continuation`,
  `benign_hard_reapproved_retry`) stay at zero false positives.

## [0.3.0] — 2026-08-19

Pre-alpha. The evaluation card is regenerated on every change and CI fails on
any diff, so the numbers below are derived rather than claimed.

### What this release measures

Stated first, because this file's own preamble says a detection release that
only reports recall is a marketing document.

| | |
|---|---|
| Corpus | Synthetic, written by the detector's author. Not validation. |
| Target-attributable recall | 100% on the unseen / task-disjoint / manifest cell |
| False positives | **420.4 per 1,000 benign sessions** |
| Projected precision at 0.1% attack prevalence | **0.238%** |
| Known evasions | 22 constructed, 20 still working, each with a test |
| Independent validation | None |

At a realistic base rate almost every alert this release produces is benign.
The checks that fire cleanly are the evidence-integrity ones; the behavioural
ones are noisy, and the card names which and why.

**Two external reviews were closed in this release** — 43 findings between
them, accounted for one by one in [REVIEW-RESPONSE.md](REVIEW-RESPONSE.md),
including the three recommended remedies that were declined and why.

### Breaking — the output contract moved to `cohaera:0.3`

An external review of the merged branch raised twenty-one findings. Closing the
evidence-layer ones changed what a verdict *says*, not only whether it fires,
so the schema version moves with them. A parser or rule built against
`cohaera:0.2` will not break loudly — it will read absent fields and report
empty — which is precisely why the version has to move.

- **`evidence_status` no longer emits `verified`.** It emits
  `verified_complete` when a signature verified through the final accepted
  record, and `verified_prefix` when it did not. A signature covers the chain
  head at its own sequence, so a collector signing every hundredth record left
  everything after the last signing position attested by nobody — and the old
  vocabulary reported that session exactly like a fully signed one, at
  confidence 1.0 (R-05). Content matching the literal `verified` now matches
  nothing, deliberately.
- **A receipt or an approval must bind completely to be trusted.** Span, tool
  *and* argument digest. A receipt naming only a span was in the trusted set,
  so an unbound identifier could support a critical CH07 contradiction — a
  finding framed as evidence-backed, resting on evidence that identified no
  call. Span-only is now context, never authority, and CH07 reports it as
  `CH07_effect_receipt_partially_bound` (R-01, R-10).
- **`analysis_run_id` and `verdict_id` change for the same input** when the
  trust configuration differs, because provenance now carries a
  `trust_config_digest` that the run identity commits to (R-06).
- **`stream_ledger` provenance gained `generation_read` and
  `state_digest_read`** — the ledger state this run's replay and fork verdicts
  were actually judged against.

### Fixed — a second external review, with executable proofs

A second reviewer read `main` and shipped eight reproduction probes rather
than eight assertions. Six reproduced. Four of the six are one root cause:
**a producer-supplied value was being treated as a fact.**

- **Captured arguments are authoritative** (F-01). An event carries both
  `tool_args` and `arg_digest`, and the declared digest won whenever it was
  present — the disagreement was recorded as a flag nothing acted on. A call
  sending to an attacker, declaring the digest of a send to Alice, inherited
  Alice's approval and CH04 said nothing. This defeated the whole point of
  requiring a complete binding: the producer chose the value being bound to.
  The digest over the arguments Cohaera saw now wins, and a call whose two
  identities disagree is bindable by nothing.
- **An approval must be observed before the call it covers** (F-02).
  `granted_at` is a number the producer writes, so an approval emitted after
  the call completed and backdated to before it satisfied the freshness window
  perfectly and silenced the bypass.
- **Only a chained sidecar may order events** (F-03). `stream_id` and `seq`
  with no `prev` and no `chain` are two numbers the producer wrote, and they
  were deciding whether a consequential call happened before or after the
  control governing it. `attested` also stops meaning "every record carried a
  sidecar" — a much weaker question, published under the stronger one's name.
  That question is now `sidecars_complete`.
- **An absence claim abstains on truncated text** (F-04). This one is this
  project's founding objection appearing inside the project. A response cut at
  the cap was recorded as a defect and the defect was then ignored, so CH02
  concluded "the agent did not disclose" from text it had not finished
  reading, at confidence 1.0 and severity critical. A disclosure found in a
  surviving prefix is still sound; only the absence conclusion is not.
- **`chain` and `prev` must be SHA-256 digests** (F-14). Any length of hex was
  accepted and copied into the verdict, so twelve records carrying 64 KiB each
  turned 788 KB of input into 9.58 MB of output at exit code zero. Now 0.17x.
- **CH03 no longer promises a scanner that does not exist** (F-16). It told
  operators to capture `tool_result` "so Cohaera can scan locally". Cohaera
  does not scan locally, and an operator who captured it got the same verdict
  and the same remedy with no way to learn why.

All eight probes are permanent regressions in `tests/test_review_probes.py`,
which is the reviewer's own success condition: every probe fails closed or
returns an explicit non-evaluated state.

### Fixed — the rest of the external review

Twenty-one findings were raised against the merged branch. The four that
change the output contract are above; these change behaviour, bounds or
claims. [REVIEW-RESPONSE.md](REVIEW-RESPONSE.md) accounts for all of them,
including the three recommended remedies that were declined.

- **The ledger now proves continuity** (R-02). Advancement requires the next
  exact sequence *and* the predecessor matching the stored head. A gap is
  discontinuous and a mismatching head is a fork; neither reads as ordinary
  advancement, which is what a collector omitting a batch boundary used to get.
- **Only evidence that held may write to it** (R-03), it is transactional
  against concurrent runs (R-04), and it is called an *observation ledger*
  rather than claiming exactly-once scoring.
- **Attested files are resolved once** (R-07), so the digest describes the
  bytes that were parsed rather than whatever a second `open()` found.
- **Freshness is bounded at both ends** (R-13). A record dated past
  `max_future_skew_s` is inadmissible, and `--evidence-as-of` refuses `nan`,
  which silently disabled the whole bound.
- **Record shape is metered during the parse** (R-11). The resident estimate is
  the larger of a byte term and a container/key term, because arrays of empty
  maps and arrays of integers are the same size on the wire and an order of
  magnitude apart in memory.
- **Signature work has a wall clock as well as a count** (R-12), and
  `SECURITY.md` publishes the measured envelope.
- **CH01 findings say whose normal they were measured against** (R-14):
  `baseline_scope: fleet`. One grammar over every training session, which the
  documentation had been describing as an agent's own history.
- **Receipt adapters give each path its own kind and assurance** (R-17). A
  Kubernetes `uid` is no longer reported as a `resourceVersion`, and `nan` is
  not an identifier.
- **The lab's required probe targets an address the agent can reach** (R-08),
  the negative property it was standing in front of is asserted, and `LAB.md`
  no longer describes a third topology.
- **The evaluation card reports task-cluster intervals** (R-15) and the corpus
  must be a bijection between labels and telemetry (R-16). It also names a
  property of itself: every family has identical counts and produces an
  identical rate, so a family holdout here tests less than the name suggests.
- **Counts are derived from a declared status column** (R-20). The file said
  20 of 21 constructed evasions work and, separately, that two are closed —
  which cannot both be true. Two inferences were wrong: an id ending in a
  letter was read as "remedy", hiding an open evasion, and a cell had to say
  exactly `CLOSED`, missing one that says `CLOSED` followed by a clause. The
  truth is 22 constructed, 2 closed, 20 working.
- **The wheel is a function of the source** (R-18). `SOURCE_DATE_EPOCH` makes
  two builds of one commit byte-identical, which the SBOM job now proves.
  `requires-python` is bounded above, and the classifiers name every version CI
  runs.

### Changed — what this project claims to be

- **The positioning is corrected** (R-19). Agent behaviour analytics ships;
  pitching session correlation as the missing layer was late. Cohaera is the
  evidence-quality layer that feeds one. See
  [POSITIONING.md](POSITIONING.md), which also carries the language this
  project will not use about its own results — enforced by a test.
- **A local lab** ([`lab/local/`](lab/local/)) runs the evidence path end to
  end in about a second and commits what it produced. CI re-runs it, so a
  change in what a verdict *says* fails a diff.

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
- **A stream signed at its start was reported `verified` however much of it went
  unsigned (R-05).** `evidence_status` returned `verified` whenever
  `signatures_verified > 0` — a fact about whether signing happened at all, not
  about what it covered. A signature covers the chain head at its own sequence,
  so it attests every record up to that point and **none after it**. The
  review's fixture — 150 records signed at sequence 0 and 100 — reported
  `verified` with 49 records chained and attested by nobody, and with freshness
  and a ledger in force CH06 scored it exactly **1.0**.

  **Breaking, and schema-visible.** `verified` is gone as an output value,
  replaced by `verified_complete` (a verified signature reaches the last record
  of *every* stream feeding the session) and `verified_prefix` (signatures
  verified and stop short). Every stream, not most: a session assembled from two
  streams is only as attested as its weaker half. A rule matching the old
  literal `verified` now matches nothing, which is deliberate — it should fail
  loudly rather than quietly stop firing. CH06's own finding is stamped
  `not_applicable` rather than `verified`; its subject *is* the integrity
  evidence, so the question is a category error, and that was the one place the
  old vocabulary said something false rather than merely incomplete.

  Additive: `signature_ranges` (`stream_id`, `first_seq`, `last_seq`,
  `verified_to`), `signature_coverage` and `signature_covers_final` in the
  integrity evidence; `INTEGRITY_SIGNATURE_COVERS_PREFIX_ONLY` as a CH06
  coverage reason, with confidence multiplied by the record-weighted share
  actually reached.

  **`tools/collector_sign.py`:** `sign_every` must now be an integer ≥ 1. `0`
  emitted a stream with no signature on any record and reported success — `if
  sign_every and seq % sign_every == 0` short-circuits, so the ZeroDivisionError
  never arrived to give it away — and `-1` signed everything, since `seq % -1 ==
  0` always. The signer also always signs the **final** record now, without
  which `verified_complete` is unreachable for any sampled stream whose batch
  does not end on a signing position.
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
- **Anything with a sequence number could write to the ledger that says what was
  scored (R-03, scoped).** `record` was called for every stream that had a first
  and a last sequence, with no requirement that any of it verified. Three
  poisoning paths, all reproduced: (1) under a **loaded** trust store a
  chained-but-unsigned stream — which needs no key, since chaining is arithmetic —
  was recorded with its head, so the genuine signed stream at the same positions
  then read as `forked`, turning a squatted stream id into a critical finding
  against the real collector; (2) assembly drops events past `max_sessions` and
  `max_events_per_session`, and the ledger advanced across their positions
  anyway, so records nobody scored were marked as already seen and can never be
  scored; (3) a broken chain, invalid signature, revoked or unauthorised key, or
  stale record did not stop the position being committed as a scored fact.

  A stream is now written only if every record it carried reached a scored
  session, none of its own evidence was inadmissible, and — when a trust store is
  loaded — at least one record carried a signature that store accepts. The trust
  store is the switch on the last rule deliberately: an operator who loaded no
  keys has said nothing about who may attest, and requiring a signature would
  turn the ledger off for every unsigned deployment. A refused stream is reported
  as the new `STREAM_LEDGER_NOT_ADVANCED` and named in the new
  `stream_ledger_refusals` summary field, because a stream absent from the ledger
  looks exactly like one never seen. A refused stream is never created, so it
  cannot spend `max_ledger_streams` either.

  Evidence codes are now tracked per stream as well as per session. A session is
  fed by many streams, so judging stream A on a code raised by stream B would
  refuse to advance for an unrelated reason and make the next run read A as a
  replay.

  **`cohaera score` now writes the ledger AFTER emitting verdicts**, reversing
  the previous ordering and its stated reasoning. Saving first advanced past
  findings nobody ever saw, so re-running reported a replay and the findings were
  gone; saving last means a run that dies mid-emission is re-scored and may
  duplicate. A duplicate alert is noise an analyst dismisses; a missed one is
  what this project exists to prevent.

  **Renamed in concept to an observation ledger, and the exactly-once-scoring
  implication is withdrawn.** It records what Cohaera observed and scored, not
  what any sink durably received. A transactional version needs durable sink
  acknowledgement across stdout, files and future SIEM sinks — a design, not a
  patch — and is deliberately not attempted here. The on-disk
  `cohaera.stream_ledger:1` identifier is unchanged for now so existing ledgers
  keep loading; the schema-visible rename belongs with the version bump, where
  everything downstream regenerates once.
- **Two runs sharing a ledger silently discarded each other's work (R-04).**
  `save()` was atomic — mkstemp, fsync, `os.replace` — and the read-modify-write
  around it was not. Two processes on one host each loaded, each scored, and each
  replaced; the file left behind had no record of whichever finished first. A
  two-process test loses an update on most runs, and which one it loses is a coin
  flip. A stream missing from the ledger is a stream whose next replay is
  undetectable, and both runs exited zero.

  `StreamLedger.locked()` holds an exclusive `flock` on a `<ledger>.lock` sidecar
  from load until the run finishes. A sidecar because `os.replace` swaps the
  inode, so a lock on the ledger's own descriptor protects a file that is no
  longer at that name. **Held for the whole run, not just the write**, and the
  cost is deliberate: locking only the write would stop updates being lost and
  would not stop the thing the ledger exists to catch, since two runs scoring the
  same stream would each read the position before the other wrote it and neither
  would see the replay. Runs sharing a ledger now serialise. The wait is bounded
  (30s) and ends in a refusal rather than a hang.

  A monotonic `generation` is the backstop for when the lock was not taken or is
  not honoured — `flock` is advisory, local, and does not travel over NFS. A save
  whose parent generation is not what is on disk is **refused**, loudly, rather
  than merged: a merge would have to guess which of two disagreeing histories for
  a stream is real, and guessing wrong writes the wrong reference for every run
  afterwards. The generation sits outside the digest on purpose, so ledgers
  written before this version still load — folding it in would force every
  upgrading deployment to delete its replay memory.

  `os.replace` is now followed by an fsync of the containing directory, so a
  crash cannot leave the directory entry pointing at the old ledger.
  **Single host only**, stated in the docstring: this is a file lock, not a
  distributed transaction, and a second Cohaera host with its own ledger is
  unchanged and still catalogued in `EVASION.md`.
- **A stream could be continued from a boundary nothing had ever scored, and
  the fabrication became the reference (R-02).** `StreamLedger.compare` judged a
  continuation with one test — `first_seq > previous.last_seq` — which
  establishes that the new records came *after* the old ones and never that they
  came *from* them. Somebody holding a collector key could mint a second,
  mutually exclusive history, start it at exactly `last_seq + 1`, declare a
  predecessor the ledger had never recorded, and have it read as ordinary
  advancement. Every signature verifies and the chain within the run is perfect,
  so nothing inside a single run can see it — which is the entire class of attack
  the ledger exists for. `record` then advanced on `advanced`, so the fabricated
  head became the reference every later run was measured against.

  `compare` now asks three questions in order. Sequence contiguity first, because
  across a gap there is no stored head at the boundary to compare against, so
  calling a gap a fork would invent an answer. Then the declared predecessor.
  Only a continuation that is both contiguous **and** joins onto the stored head
  is `advanced`.

  New status `discontinuous` for a gap — it keeps `INTEGRITY_STREAM_RECORDS_NEVER_SCORED`
  and stays non-inadmissible, since an operator scoring a subset on purpose is
  the same input, but it no longer calls itself ordinary advancement. A
  contiguous continuation onto a different history is `forked` and inadmissible,
  and does not advance the ledger. A first record that declares no predecessor
  still advances — refusing would break every collector that omits the field —
  but carries the new non-inadmissible `INTEGRITY_STREAM_BOUNDARY_UNVERIFIED`
  and a `boundary` of `unstated`, never `match`.

  Additive: `boundary`, `declared_prev` and `previous_head` on the stream
  verdict, and `first_prev` in `stream_summary`.
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
- **28 constructed evasions are catalogued and 26 still work**, on purpose:
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

[Unreleased]: https://github.com/404SecNotFound/Cohaera/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/404SecNotFound/Cohaera/releases/tag/v0.3.0
[0.2.0]: https://github.com/404SecNotFound/Cohaera/releases/tag/v0.2.0
