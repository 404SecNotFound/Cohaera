<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Documentation map

24 documents, about 89,000 words. This page exists so you never have to
guess which one answers your question.

Each row says what question the document answers, not what it contains.

## Start here

| Document | The question it answers |
|---|---|
| [README](../README.md) | What is this, what does it measure, and how do I run it? |
| [POSITIONING](../POSITIONING.md) | What layer is this, what is it *not*, and what language does the project refuse to use about its own results? |
| [evaluation card](../eval/EVALUATION-CARD.md) | How well does it actually work, and on what? Generated, never hand-written. |
| [EXABEAM-STACK](EXABEAM-STACK.md) | Where does this sit against Exabeam's agent-monitoring products and the open-source projects it sponsors — and what is verified from GitHub versus taken on report? |

## If you are assessing whether to trust it

| Document | The question it answers |
|---|---|
| [EVASION](../EVASION.md) | How do I defeat this? 22 constructed evasions, 20 still working, each with an executable test that passes while the evasion does. |
| [THREAT-MODEL](THREAT-MODEL.md) | What does it trust, and what survives an attacker who controls the telemetry? |
| [SECURITY](../SECURITY.md) | How do I report something, what is in scope, and what does the supply chain look like? |
| [REVIEW-RESPONSE](../REVIEW-RESPONSE.md) | Two external reviews raised 43 findings. What happened to every one, and which recommendations were declined and why? |
| [REVIEWS-2026-08](REVIEWS-2026-08.md) | Three reviews read the *project* rather than the code — product, threat research, detection engineering. What did they each find, where did they converge without conferring, and what happened to every finding? |
| [RESEARCH-2026-08](RESEARCH-2026-08.md) | What did the field do while this was being built? Twelve months surveyed: which of this project's claims were falsified, which prior art it should have been citing, and what it could not verify. |
| [EXTERNAL-VALIDATION](EXTERNAL-VALIDATION.md) | The evaluation is all synthetic and self-authored. What can be checked against someone else's data? Three of seven checks — and three cannot be, by any public corpus that exists. |
| [PRIOR-ART](PRIOR-ART.md) | Who did all of this first? The coverage contract is a port, the evaluation card is a model card, and the last section bounds what is actually new to three narrow things. |

## If you are integrating it

| Document | The question it answers |
|---|---|
| [EVIDENCE-TRUST](EVIDENCE-TRUST.md) | What are the wire formats — collector integrity, effect receipts, approval binding, the trust store, signed policy files — and what does each actually establish? |
| [content/README](../content/README.md) | What SIEM content ships, and what does each rule mean? |
| [BOUNDED-SESSIONS](BOUNDED-SESSIONS.md) | How does session assembly stay bounded against a hostile producer? |
| [CHANGELOG](../CHANGELOG.md) | What changed, what broke, and which release states the false-positive rate? |

## If you are running experiments

| Document | The question it answers |
|---|---|
| [eval/README](../eval/README.md) | How is the corpus built, how are the splits enforced, and where is it circular? |
| [lab/local/README](../lab/local/README.md) | How do I run the whole evidence path end to end in about a second, and what does the committed output prove? |
| [LAB](../LAB.md) | How do I build the isolated four-VM lab? (It has never been built. The page says so.) |
| [PHASE0-VERIFICATION](PHASE0-VERIFICATION.md) | What had to be true before any of this was worth building? |

## If you are contributing

| Document | The question it answers |
|---|---|
| [CONTRIBUTING](../CONTRIBUTING.md) | What are the five standards a change is held to, and why is "reproduce it first" not negotiable? |
| [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) | How do people here treat each other? |

## If you care about the upstream projects

Cohaera exists because of a gap in [observra](https://github.com/open-agent-ai-security/observra).
Two documents look outward rather than inward, and both are careful about the
difference between analysis offered and work claimed.

| Document | The question it answers |
|---|---|
| [FINDINGS](../FINDINGS.md) | What did reading observra's source turn up? Source-verified, every finding citing a file and line. **None of it is reported yet** — the document says why, and which one should go through a security policy rather than a slide. |
| [OBSERVRA-108-GAP](../content/parser/OBSERVRA-108-GAP.md) | What exactly are the nine dropped fields behind observra#108, and what would closing them take? **Unsolicited** — the issue says a content team owns it, so this is analysis offered, not work claimed. |

## Two conventions worth knowing before you read anything

**A check that cannot run says so.** Nothing in this project reports "clean"
when it means "I could not look". Every check publishes a coverage contract
naming what it needed, what it got, and what it therefore could not conclude.
If you see `not_evaluated` with a reason code, that is the system working.

**Numbers are derived, not typed.** Every count in this documentation — tests,
evasions, rules, recall, false-positive rates — is generated from the
repository by [`tools/readme_facts.py`](../tools/readme_facts.py) and checked in
CI. If a number here is wrong, that is a bug with a failing test, not a typo.
The project has published a wrong number before; the checker exists because of
it.
