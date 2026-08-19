<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Security policy

## Status: pre-alpha. Read this before deploying anything.

Cohaera is a **research prototype**. It has never been run against real agent
traffic, its numbers come from a synthetic corpus written by its own author, and
[EVASION.md](EVASION.md) catalogues 22 constructed ways to defeat its checks, 20
of which currently work.

The single most important thing to know is not a vulnerability, it is a design
boundary:

> **Cohaera reads telemetry the observed agent chose to emit.** An agent that
> controls its own instrumentation can omit, fabricate or fragment what Cohaera
> sees. It is an assurance control — *is this agent doing its job* — not an
> adversarial one — *is this agent lying to me*.

That is [EVASION.md E13](EVASION.md), it is not closable at this layer, and it
is not a bug report. Reports that reduce to "the agent can lie to you" will be
answered with this paragraph.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository
(*Security → Report a vulnerability*). It creates a private advisory only the
maintainer can see, and it is preferred over email because it keeps the report,
the fix and the disclosure in one place.

If private reporting is unavailable, open a normal issue **without a working
exploit** and say that you have details to share privately.

Please include:

- what you attacked — a check, the ingest path, the CLI, the emitted record;
- a **reproduction**. This project reproduces every reported defect before
  fixing it, and several have turned out to be real for a different reason
  than the reporter gave, with one aimed at the wrong function entirely. A
  reproduction is not bureaucracy here, it is the step that catches that.
  (R-20: this sentence used to carry a running total of defects fixed. Nothing
  derived it, nothing could, and it was wrong within a week of being written.
  A number that cannot be checked should not be published — which is the
  argument this whole file makes about detector results.);
- what an attacker gains. "Cohaera crashes" and "Cohaera reports a session as
  clean" are different severities and the second is usually worse.

**Response targets.** Acknowledgement within 7 days, an assessment within 30.
This is one maintainer working on a research project, not a vendor with an
on-call rota; if those slip, the delay is capacity rather than disagreement.

**Disclosure.** Coordinated, 90 days by default, sooner if a fix ships sooner.
Credit in the advisory and in [EVASION.md](EVASION.md) unless you ask otherwise.

## What is in scope

| In scope | Why |
|---|---|
| A crafted telemetry record that crashes, hangs or exhausts memory in `read_events`, `assemble` or any check | Ingest is a trust boundary. Denial of service against the detector is evasion of the whole control, not of one check |
| A session Cohaera reports as **clean or fully covered** when a check could not actually evaluate it | The project's central claim is that a check which silently cannot run is a false negative wearing a green tick. A counter-example to that is the most valuable report you can send |
| Identity collisions — two different inputs producing the same `verdict_id` or `analysis_run_id` | A SIEM deduplicates on these. A collision silently discards a verdict |
| Information disclosure in an emitted record: a field documented as anonymous that carries recoverable identity | Fixed once already as BUG-07; the class is live |
| Resource amplification — bounded input producing unbounded output | Fixed several times; every bound is a claim until it is measured |
| A supply-chain weakness in the build, the workflows or the published artefacts | See below |

## What is out of scope

Not because these do not matter, but because they are **already written down**
and a report restating them tells nobody anything new:

- **Anything in [EVASION.md](EVASION.md).** 22 constructed evasions, each with
  an executable test that passes while the case behaves as the file records it.
  A *new* evasion is very much in scope. Adding detail to a catalogued one — a cheaper variant,
  a case where the stated cost is wrong — is welcome as an issue.
- **Lexical false positives in CH02.** An honest paraphrase reads as
  concealment. That is E04, it is measured on the corpus, and it is the check's
  known ceiling.
- **CH03 inheriting the upstream scanner's blind spots.** E09, and
  [FINDINGS.md](FINDINGS.md) F-01.
- **The benign baseline being unattested.** Cohaera learns "normal" from
  whatever corpus it is handed. E03, and a process control rather than a code
  one.
- **Findings from a scanner with no reproduction.** Send the reproduction.

## The cost of verifying a signature, measured

R-12. Cohaera's Ed25519 verifier is pure Python and has no runtime
dependencies, which is a deliberate trade and is stated here rather than
discovered. A signature that is structurally well-formed, carries a **trusted**
key id, and does not verify costs a full scalar multiplication: the answer is
not known until the work is done, and the producer decides how many such
records arrive.

Measured on the development host, Python 3.11, after the fixed-base and
variable-base comb work:

| | |
|---|---|
| one full invalid verification | ~0.5 ms |
| `max_signature_verifications` (default 100,000) | ~50 s of CPU |
| `max_signature_seconds` (default 30.0) | the bound that holds on a slow host |

An external review measured about three minutes for the same count bound on a
slower machine, which is the reason there are two bounds rather than one: a
count is not a time, and the cost of one verification is a property of the host
and not of this repository.

Unauthorised keys are rejected **before** any scalar work, so the vector needs
a key the operator has already trusted. Exhausting either budget is not a crash
and not a silent pass: the session reports
`INTEGRITY_SIGNATURE_BUDGET_EXHAUSTED`, its evidence status says the
attestation was not established through the final record, and the run's report
carries the seconds actually spent so the bound can be tuned against a
measurement rather than a guess.

The verifier handles public data and is not a signing oracle, so the usual
constant-time concern does not apply to it. `tools/collector_sign.py` says on
its face that it is not constant-time and is a format reference rather than a
signing service; a production collector should sign with a maintained backend,
an OS key store, an HSM or a KMS.

## Supply chain

What this repository does, so you can check whether it is still true:

- **Zero runtime dependencies**, asserted in CI from the *installed distribution
  metadata* rather than from `pyproject.toml`, because the metadata is the
  outcome and the manifest is a claim.
- **Every GitHub Action pinned to a commit SHA**, not a tag, with the version in
  a trailing comment. `tests/test_ci_config.py` fails if any `uses:` is not a
  40-character SHA, so an unpinned action cannot arrive unnoticed.
- **Dependabot** opens a pull request when a pinned action or dev dependency
  moves, so an update is reviewed rather than absent.
- **Static analysis (CodeQL): NOT RUNNING, deliberately.** It was configured and
  its analysis ran clean, but this is a private repository on a personal account,
  where code scanning requires GitHub Code Security. Every run therefore ended at
  the upload step with `Code scanning is not enabled for this repository`. It was
  removed rather than left permanently red, because it was also a *required*
  status check and a required check that can never report success blocks every
  pull request forever. `tests/test_ci_config.py` pins the removal as a matched
  pair and documents how to restore it -- making the repository public, where
  code scanning is free, is the cheapest route.
- **`main` is protected by a committed ruleset** — squash-only merges, required
  status checks, no force-push, no deletion — and
  `tests/test_ci_config.py` asserts the ruleset's required checks match the CI
  jobs that report them, because a required check no job reports blocks every
  pull request forever with no error message anywhere.
- **An SBOM (CycloneDX) is generated in CI** for the built wheel.

What it does **not** do yet, stated because an unstated gap is worse than a
listed one:

- **Releases are not signed and the SBOM is not attested.** The SBOM is a CI
  artefact, which means it is retained for 90 days and is not bound to a
  released artefact. Until that changes, an SBOM downloaded from a run is
  evidence about that run and nothing more. Tracked in the roadmap.
- **No published release exists.** Install from source.
- **Secret scanning and push protection are repository settings** and cannot be
  committed to a file. See
  [`.github/rulesets/README.md`](.github/rulesets/README.md) for what should be
  enabled and how to check.

## Threat model

[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) states what Cohaera trusts, what
it does not, and which of its own guarantees survive an attacker who controls
the telemetry. Read it before deciding what to report — most of the interesting
questions are already answered there, with their answers labelled honestly.
