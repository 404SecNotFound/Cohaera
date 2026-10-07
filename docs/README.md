<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Documentation map

38 documents, about 127,000 words. This page exists so you never have to
guess which one answers your question.

Each row says what question the document answers, not what it contains.

## Start here

| Document | The question it answers |
|---|---|
| [README](../README.md) | What is this, what does it measure, and how do I run it? |
| [OPERATOR-GUIDE](OPERATOR-GUIDE.md) | How do I reproduce the labs, read a verdict, score my own telemetry, and learn the code path? |
| [DIRECTION](DIRECTION.md) | What is the position, the passive-only boundary, the roadmap with its gates, the non-goals, and the claims policy? This is the one strategy document. |
| [evaluation card](../eval/EVALUATION-CARD.md) | How well does it actually work, and on what? Generated, never hand-written. |

## If you are integrating it

| Document | The question it answers |
|---|---|
| [REFERENCE](REFERENCE.md) | What fields does it read, what does the output record contain, what do the exit codes mean, and what does every `cohaera score` flag do? |
| [EMITTING](EMITTING.md) | How does a runtime or collector emit telemetry Cohaera can verify, with `cohaera.emit`, from key generation to a `verified_complete` verdict? |
| [EVIDENCE-TRUST](EVIDENCE-TRUST.md) | What are the wire formats, from collector integrity through effect receipts, approval binding, the trust store and signed policy files, and what does each actually establish? |
| [content/README](../content/README.md) | What SIEM content ships, what tier is each rule, and what does each rule mean? |
| [content/aie/README](../content/aie/README.md) | How would the same detections be built as LogRhythm AIE rules, and what is the build-versus-buy comparison? |
| [BOUNDED-SESSIONS](BOUNDED-SESSIONS.md) | How does session assembly stay bounded against a hostile producer? |
| [CHANGELOG](../CHANGELOG.md) | What changed, what broke, and which release states the false-positive rate? |

## If you are assessing whether to trust it

| Document | The question it answers |
|---|---|
| [EVASION](../EVASION.md) | How do I defeat this? 29 constructed evasions, 27 still working, each with an executable test that passes while the evasion does. |
| [THREAT-MODEL](THREAT-MODEL.md) | What does it trust, and what survives an attacker who controls the telemetry? |
| [SECURITY](../SECURITY.md) | How do I report something, what is in scope, and what does the supply chain look like? |
| [EXTERNAL-RESULTS](EXTERNAL-RESULTS.md) | It was run against somebody else's data. What happened? Zero detections across 375 attack sessions, and a computed bound on what any structure-reading detector could have scored there. |
| [EXTERNAL-VALIDATION](EXTERNAL-VALIDATION.md) | The evaluation is synthetic and self-authored. What can be checked against someone else's data, and what cannot be checked by any public corpus? |
| [PRIOR-ART](PRIOR-ART.md) | Who did all of this first? The coverage contract is a port, the evaluation card is a model card, and the last section bounds what is actually new. |
| [EXABEAM-STACK](EXABEAM-STACK.md) | Where does this sit against Exabeam's agent-monitoring products and the open-source projects it sponsors, and what is verified from GitHub versus taken on report? |
| [OUTSTANDING](OUTSTANDING.md) | Everything is merged and green, so what is actually left, who owns it, and what should be done first? |

## If you are running experiments

| Document | The question it answers |
|---|---|
| [eval/README](../eval/README.md) | How is the corpus built, how are the splits enforced, and where is it circular? |
| [eval/external/fixtures/README](../eval/external/fixtures/README.md) | What are the hand-written adapter fixtures for the external runner, and why must no number be quoted from them? |
| [lab/local/README](../lab/local/README.md) | How do I run the whole evidence path end to end in about a second, and what does the committed output prove? |
| [lab/ch06/README](../lab/ch06/README.md) | How does the frozen evidence-integrity matrix compare Cohaera with an independent verifier on the same committed bytes? |
| [demo/phantom-guardrail/README](../demo/phantom-guardrail/README.md) | What does it look like when an agent cites a control that does not exist, and what does a capability manifest change? |
| [demo/approval-replay/README](../demo/approval-replay/README.md) | What is one approval worth after it is replayed, and what does the default deployment still let through? |
| [lab/README](../lab/README.md) | What would the unattended VMware builder do, and why has it never been run? |
| [LAB](../LAB.md) | How would the isolated four-VM lab be built? (It has never been built. The page says so.) |
| [PHASE0-VERIFICATION](PHASE0-VERIFICATION.md) | What had to be true before any of this was worth building? |

## If you are contributing

| Document | The question it answers |
|---|---|
| [CONTRIBUTING](../CONTRIBUTING.md) | What are the standards a change is held to, and why is "reproduce it first" not negotiable? |
| [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) | How do people here treat each other? |
| [.github/rulesets/README](../.github/rulesets/README.md) | What is the committed branch protection, and how is it applied? |

## If you care about the upstream projects

Cohaera exists because of a gap in [observra](https://github.com/open-agent-ai-security/observra).
Two documents look outward rather than inward, and both are careful about the
difference between analysis offered and work claimed.

| Document | The question it answers |
|---|---|
| [archive/FINDINGS](archive/FINDINGS.md) | What did reading observra's source turn up, as of v1.1.0? Source-verified, every finding citing a file and line. **None of it is reported yet**, and the document says why. Archived; not re-checked against later releases. |
| [OBSERVRA-108-GAP](../content/parser/OBSERVRA-108-GAP.md) | What exactly are the nine dropped fields behind observra#108, and what would closing them take? **Unsolicited**: the issue says a content team owns it, so this is analysis offered, not work claimed. |

## Archive

Dated records, superseded by [DIRECTION](DIRECTION.md). Each opens with a
header saying what date it reflects. They are kept because reviews, findings
and corrections are part of the evidence; they are not kept current.

| Document | The question it answered |
|---|---|
| [archive/POSITIONING](archive/POSITIONING.md) | What layer did the project say it was in August 2026, and what did it refuse to say about itself? The claims policy moved into DIRECTION. |
| [archive/BLUEPRINT-2026-08](archive/BLUEPRINT-2026-08.md) | Two external strategy documents recommended opposite things. What in them was true, and what was the plan at the time? The decision went to passive monitoring. |
| [archive/REVIEW-RESPONSE](archive/REVIEW-RESPONSE.md) | Two external code reviews raised 43 findings. What happened to every one, and which recommendations were declined and why? |
| [archive/REVIEWS-2026-08](archive/REVIEWS-2026-08.md) | Three role reviews read the project rather than the code. What did each find, and where did they converge? |
| [archive/RESEARCH-2026-08](archive/RESEARCH-2026-08.md) | What did the field do in the twelve months to August 2026, which claims were falsified, and what could not be verified? |

## Two conventions worth knowing before you read anything

**A check that cannot run says so.** Nothing in this project reports "clean"
when it means "I could not look". Every check publishes a coverage contract
naming what it needed, what it got, and what it therefore could not conclude.
If you see `not_evaluated` with a reason code, that is the system working.

**Many counts are derived, not typed.** [`tools/readme_facts.py`](../tools/readme_facts.py)
checks a declared list of claims against the repository on every test run:
the test count, the Sigma rule and tier counts, the evasion counts, the
headline evaluation-card figures, the external-run figures, the counts on this
page and on OUTSTANDING.md, and a few others named in that file. A number
outside that list was typed by hand and can drift. If you find one wrong, the
fix is a claim in `readme_facts.py`, not a corrected digit. The project has
published wrong numbers before; the checker exists because of it.
