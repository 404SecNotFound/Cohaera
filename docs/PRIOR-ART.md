<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Prior art

This project has two ideas it is willing to defend. Neither of them is new.

The coverage contract — a check that cannot run reports `not_evaluated` with a
machine-readable reason code, and is forbidden from reporting clean — is a
**port**. The pattern was in configuration-assessment schemas long before agent
frameworks existed, was in infrastructure monitoring before that, and ships
today in static analysis, vulnerability disclosure and at least one mainstream
cloud product. The evaluation card is a **model card** for a detection corpus.
The verdict ladder is a **consistency proof** with a security-engineering name
bolted on.

Saying so is stronger than claiming novelty, for the reason [EVASION.md](../EVASION.md)
is stronger than a feature list: a claim of novelty is one literature search
away from being embarrassing, and a claim of *derivation* survives the search.
It also tells an implementer where to look when this project's version of the
idea turns out to be worse than the original, which on present evidence is the
way to bet.

This file is the search. It ends with a short section listing the three narrow
things that do appear to be new, and stating plainly that none of them is a
research contribution.

---

## How to read the citations

Most of the research literature in this file could not be fetched from the
environment this document was written in: arxiv.org, doi.org, usenix.org,
csrc.nist.gov, docs.aws.amazon.com and most vendor documentation hosts return
403 at the egress proxy. github.com raw content does not.

So every source below carries one of three markers, and the marker is not
decoration. **Read** means the primary source was fetched and the quotations in
this file were copied out of it. **Reported** means a separate verification pass
supplied the reading and this document did not confirm it. **Unread** means only
the identifier is asserted — the work exists under that identifier and is
relevant, and nothing here is a claim about its contents beyond what its title
and abstract carry.

Nothing in this file is quoted from memory. Where there is no quotation, it is
because there was no readable source.

---

## 1. The coverage contract is a port

### The pattern, in five standards

| Source | The value | What it means there | Read? |
|---|---|---|---|
| OVAL results schema | `not evaluated` | a choice was made not to evaluate; the true result is unknown | **Read** |
| XCCDF 1.2 | `notchecked`, `unknown`, `error`, `notapplicable` | four different reasons a rule has no verdict | **Read** |
| SARIF v2.1.0 | `result.kind: notApplicable` + `toolExecutionNotifications` | does not apply, plus a separate stream for runtime conditions | **Read** |
| OpenVEX | `under_investigation` | not yet known whether the product is affected | **Read** |
| Monitoring Plugins | `STATE_UNKNOWN` | the check did not produce a usable answer | **Read** |
| AWS Security Hub | `Compliance.Status: NOT_AVAILABLE` | could not be performed — *or* did not apply | Reported |

Every one of these predates agent telemetry, most of them by decades. The idea
that an unevaluable check must be distinguishable from a passing one is not a
contribution; it is a thing security tooling learned once, wrote into its
schemas, and then mostly stopped talking about.

### OVAL, and why the mapping is not one-to-one

**Read.** OVAL Language repository, `docs/oval-results-schema.md`, the
`ResultEnumeration` type. The schema file itself is Core Results 5.11.2 dated 30
November 2016; the namespace is still `oval.mitre.org/XMLSchema/oval-results-5`,
while the schema's own annotation points maintenance at the OVAL Community and
`oval.cisecurity.org`, so "MITRE OVAL" is fair for the 5.x lineage but is not
how the schema describes itself today.

OVAL does not have one non-result. It has three, and the distinctions are the
interesting part:

> **not evaluated** — "a result value of 'not evaluated' means that a choice was
> made not to evaluate the given definition or test. The actual result is not
> known since if evaluation had occurred the result could have been either true
> or false."

> **unknown** — "the characteristics being evaluated cannot be found in the
> system characteristic document (or the characteristics can be found but
> collected object flag is 'not collected')."

> **not applicable** — "the definition or test being evaluated is not valid on
> the given platform."

Cohaera's single `not_evaluated` **spans OVAL's `not evaluated` and its
`unknown`**. Cohaera's fires overwhelmingly on absent evidence surfaces — no
injection-scanner field on the stream, no collector keys, no receipt — and in
OVAL's taxonomy an absent characteristic routes to `unknown`, not to `not
evaluated`. It is the same word doing a wider job.

So the prior art here is not a value mapping. It is the **three-way refusal**:
OVAL will not collapse "nobody looked", "we looked and the data was not there",
and "this does not apply to you" into each other, and it will not collapse any
of them into `false`. That refusal is the whole design, and it is theirs.

Cohaera's reason codes are, at best, a fourth axis on the same idea — *why* the
data was not there, in a vocabulary specific to agent sessions. That is a
narrower contribution than a new result state, and it is the honest one.

### XCCDF, stated precisely, because the loose version is wrong

**Read.** `xccdf_1.2.xsd` (schema version 1.2.1) as shipped in the OpenSCAP
repository; its own annotation names the specification as *NIST Interagency
Report 7275 Revision 4*. NIST's own copy could not be fetched from here.

`resultEnumType` carries eight values. Four of them are ways of not having an
answer, and each is a different way:

| Value | The schema's own words |
|---|---|
| `notchecked` | "The Rule was not evaluated by the checking engine. This status is designed for Rule elements that have no check." |
| `notapplicable` | "The Rule was not applicable to the target of the test." |
| `unknown` | "The testing tool encountered some problem and the result is unknown." |
| `error` | "The checking engine could not complete the evaluation; therefore the status of the target's compliance with the Rule is not certain. This could happen, for example, if a testing tool was run with insufficient privileges and could not gather all of the necessary information." |

It is tempting to summarise this as "XCCDF forbids scoring an unevaluated rule",
and that summary is half right in a way that matters. **Read.** OpenSCAP's
implementation of the XCCDF scoring models, `src/XCCDF/result_scoring.c`,
excludes exactly four results from scoring:

```c
/* Ignore these rules */
if ((xccdf_rule_result_get_result(rule_result) == XCCDF_RESULT_NOT_SELECTED) ||
        (xccdf_rule_result_get_result(rule_result) == XCCDF_RESULT_NOT_APPLICABLE) ||
        (xccdf_rule_result_get_result(rule_result) == XCCDF_RESULT_INFORMATIONAL) ||
        (xccdf_rule_result_get_result(rule_result) == XCCDF_RESULT_NOT_CHECKED))
    return NULL;
```

`unknown` and `error` are **not** in that set. They fall through to the branch
that assigns 100 for a pass and zero for everything else — so a rule the tool
could not evaluate because it lacked privileges scores **zero**, which is
arithmetically identical to a rule that failed.

That is worth sitting with, because it is the same defect as reporting clean,
pointed the other way. Both take "I could not look" and convert it into a
number that means something else. XCCDF converts it into *fail*, which is
conservative and therefore easier to defend, and still wrong for the reason the
schema itself gives: the compliance status "is not certain".

So the precedent XCCDF actually supplies is narrower than the one this project
would like it to supply. It is: **a standards body enumerated four distinct
ways of having no verdict, and mandated that the ones designed for absent checks
never contribute to a score.** That is real, it is checkable, and it is not
"results with such status must never be scored".

### AWS Security Hub, and the collapse Cohaera is trying to avoid

**Reported**, not read — docs.aws.amazon.com is unreachable from here. The
`Compliance` object's `Status` takes `PASSED | WARNING | FAILED |
NOT_AVAILABLE`, and `NOT_AVAILABLE` is documented as

> "Check could not be performed due to a service outage, API error, or because
> the result of the Config evaluation was NOT_APPLICABLE."

Read that twice. `NOT_AVAILABLE` means *the check broke* **or** *the check did
not apply* — one value for two facts that a consumer must act on differently.
It is precisely the collapse OVAL spends three enum values avoiding, shipping in
a mainstream product, and it is the single most useful thing in this section for
explaining what Cohaera's coverage contract is for.

The `Compliance.StatusReasons[].ReasonCode` field is the closest thing in wide
production to Cohaera's reason codes: a machine-readable "could not evaluate,
because X", attached to the finding itself rather than to a health stream. One
nuance worth recording: `ReasonCode` is typed as a non-empty string rather than
a closed enum, so its machine-readability rests on a documented table rather
than on schema enforcement. Cohaera's codes are constants in
`src/cohaera/evidence.py` and `src/cohaera/checks.py` and are asserted by tests,
which is a stronger guarantee about a much smaller vocabulary.

### SARIF, and the out-of-band pattern

**Read.** `sarif-schema-2.1.0.json` from the OASIS TC repository. `result.kind`
is "A value that categorizes results by evaluation state", with the enum
`notApplicable | pass | fail | review | open | informational` and a default of
`fail`.

`notApplicable` is *does not apply*, not *could not evaluate*. The
"could-not-evaluate" signal in SARIF lives somewhere else entirely:
`invocation.toolExecutionNotifications`, "A list of runtime conditions detected
by the tool during the analysis."

That split — verdict in one place, why-the-verdict-is-missing in another — is
the pattern this project is arguing against, and SARIF is the cleanest example
of it because both halves are in the same file and still addressed to different
readers.

### OpenVEX

**Read.** `OPENVEX-SPEC.md`. `under_investigation` is a first-class status:

> "It is not yet known whether these product versions are affected by the
> vulnerability. Updates should be provided in further VEX documents as
> knowledge evolves."

A first-class "we do not know yet", carried in the same document as the
assertions, with machine-readable justifications for the negative statuses. The
closest structural relative of a coverage contract in this table.

### Monitoring Plugins, formerly Nagios Plugins

**Read.** `lib/states.h`:

```c
typedef enum state_enum {
	STATE_OK,
	STATE_WARNING,
	STATE_CRITICAL,
	STATE_UNKNOWN,
} mp_state_enum;
```

Ordinal 3 is the plugin's exit code. `UNKNOWN` is a peer of `OK`, not a variety
of it, and has been since long before any of this. The convention is inherited
from the Nagios plugin API; the exact year is not asserted here because the
source that would establish it was not fetched.

### OCSF: closer than it looks, and narrower than it looks

**Read.** `ocsf/ocsf-schema`, `dictionary.json`. OCSF's `verdict_id` enum
includes:

> **7 — Insufficient Data.** "The incident has insufficient data to make a
> verdict."

That attribute is carried by the `evidences` (Evidence Artifacts) object, which
Detection Finding does include, and by Incident Finding and the incident
profile. So the flat claim "OCSF has no way to say it could not decide" is
false, and this document does not make it.

What OCSF does not have is the *per-analytic* form. `objects/analytic.json`
carries `state_id` with exactly three values — Active, Suppressed, Experimental
— and nothing at all about whether the analytic had the inputs it needed on this
event. The honest statement is therefore narrow: **OCSF can express an
insufficient-data verdict on a finding's evidence; it cannot express which
analytic could not run, or why.** That is the gap Cohaera's per-check contract
sits in, and it is a small one, and it will close the moment somebody proposes
the attribute.

### Where the detection platforms put it: out of band

Three production platforms already know when a rule could not run. In all three
the signal exists and is addressed to the **platform operator**, in a health
stream, rather than to the **correlation consumer**, in the record.

**Read.** Elastic Security's rule execution status is an enum of five values —
`going to run`, `running`, `partial failure`, `failed`, `succeeded` — and the
schema's own gloss on the third is exactly the failure mode this project cares
about:

> "Rule can partially fail for various reasons either in the middle of an
> execution ... A typical reason for a partial failure: not all the indices that
> the rule searches over actually exist."

A rule searching an index that does not exist is a rule that cannot fire, and
Elastic knows it, and says so — in `RuleExecutionStatus`, not in the alert.

**Read.** Elastic rules also declare their inputs. `detection_rules/rule.py`
carries `required_fields` (name, type, whether it is ECS) and
`related_integrations` (package, version, integration), both minimum-compatible
with 8.3.0. That is a rule declaring what it needs in order to mean anything —
the same move as a Cohaera check declaring its surfaces. Elastic got there
first and did it for a much larger rule corpus.

**Reported**, not read: Microsoft Sentinel's `SentinelHealth` table and Google
SecOps rule health both carry equivalent per-rule execution signals. Vendor
documentation hosts are unreachable from here and no primary source was fetched
for either, so nothing beyond their existence is asserted.

The difference Cohaera is claiming against all three is a matter of *addressing*,
not of insight. Health telemetry answers "is my detection platform working" for
somebody who can fix it. A coverage contract answers "how much of this verdict
should you believe" for the thing consuming the verdict, which is usually a
correlation engine and not a person. Whether that is worth a separate mechanism
is a legitimate design argument, and this project does not get to declare it
settled.

---

## 2. Detection engineering already had the idea, in prose

### Palantir's ADS Framework

**Read.** `palantir/alerting-detection-strategy-framework`, README and
`ADS-Framework.md`; the repository carries a 2017 copyright. Every alerting and
detection strategy must complete nine sections before production, one of which
is **Blind Spots and Assumptions**:

> "Blind Spots and Assumptions are the recognized issues, assumptions, and areas
> where an ADS may not fire. No ADS is perfect and identifying assumptions and
> blind spots can help other engineers understand how an ADS may fail to fire or
> be defeated by an adversary."

That is the coverage contract, written by a human, once, at authoring time.
Cohaera's contract is the machine-readable version evaluated per session — and
"machine-readable version of an existing human practice" is the correct
description of it. The insight belongs to the ADS framework. What is different
is only that a blind spot in a wiki page cannot be routed on, and one in the
verdict record can.

The same repository is also the reason [EVASION.md](../EVASION.md) has the shape
it has.

### DeTT&CT

**Read.** `rabobank-cdc/DeTTECT`. The project "aims to assist blue teams in
using ATT&CK to score and compare data log source quality, visibility coverage,
detection coverage and threat actor behaviours". Its data-quality model has five
dimensions, verified in `generic.py`: `device_completeness`,
`data_field_completeness`, `timeliness`, `consistency` and `retention`. Those
roll up into per-technique visibility scores.

Cohaera's `coverage.completeness` multiplier — correlation quality,
classification quality, clock quality — is the same construction one abstraction
level down: per check and per session rather than per data source and per
technique. `timeliness` and `clock quality` are close to the same measurement.
The idea that evidence quality is a *multiplier on confidence* rather than a
separate report is DeTT&CT's, and this project reached it independently and
later, which is not the same as reaching it first.

### MITRE CTID, Summiting the Pyramid

**Unread; reported by commissioned research, 22 August 2026.** The Center for
Threat-Informed Defense's v4 work is reported to carry *telemetry confidence
scores* for how well a log source supports detecting a given technique, minimum
telemetry requirements for ambiguous techniques, and machine-readable `stp.*`
robustness tags carried on Sigma rules.

If that is accurate it is the closest thing in this file to a machine-readable
statement about evidence adequacy travelling with a detection. The difference is
when it is decided: `stp.*` is an **authoring-time** judgement about a rule's
source-to-technique fit and its robustness against evasion, and it assumes the
telemetry arrived. Cohaera's contract is a **runtime** statement about one
session. Those are different claims and the second does not supersede the first.

Read it before repeating this characterisation.

### CardinalOps, State of SIEM

**Unread.** The annual report is cited here for one claim only — that a
substantial share of production SIEM rules are broken and will never fire — and
the figure is deliberately not quoted, because the report could not be fetched
and a number nothing derives is a number that is already wrong. The
directionally relevant point is available without it: broken detections are a
known, measured, industry-wide condition, not a hypothetical this project
invented in order to have something to solve.

---

## 3. The evaluation card is a model card

[`eval/EVALUATION-CARD.md`](../eval/EVALUATION-CARD.md) is a **model card**
(Mitchell et al., *Model Cards for Model Reporting*, FAT\* 2019,
arXiv:1810.03993 — **unread**) applied to a detection corpus rather than to a
model. Intended use, out-of-scope use, the evaluation data, disaggregated
results, and the caveats, in a fixed structure, generated rather than written.
The structure is theirs.

The specific reason the card leads with precision at a realistic base rate
rather than with recall is the **base-rate fallacy in intrusion detection**,
Axelsson, 1999 and 2000 (DOI 10.1145/357830.357849 — **unread**). It is
reinforced by Sommer and Paxson, *Outside the Closed World* (2010 — **unread**)
on why machine learning underperforms in intrusion detection specifically, and
by **TESSERACT** (Pendlebury et al., USENIX Security 2019 — **unread**) on
temporal and spatial bias in malware classifier evaluation, which is where the
project's insistence on task-disjoint rather than random splits comes from — a
line it shares with MCPShield, already cited in the README.

The strongest single framing is **Arp et al., "Dos and Don'ts of Machine
Learning in Computer Security"** (USENIX Security 2022; CACM 2024, DOI
10.1145/3643456 — **unread**). The evaluation card should be read as an attempt
to satisfy that paper's pitfall list: sampling bias, label inaccuracy, spurious
correlations, biased parameter selection, inappropriate baselines, inappropriate
performance measures, base-rate fallacy, lab-only evaluation. The card does not
clear all of them. It is synthetic data labelled by the author of the detector,
which is two of the pitfalls in one sentence, and it says so at the top.

Framing the card as an attempt to satisfy an existing checklist is more useful
than framing it as a contribution, because it gives a reader a fixed external
standard to mark it against rather than a standard this project set for itself.

---

## 4. Abstention has a literature, and a vocabulary collision

A detector that declines to answer is **selective classification**, and the
prior work on it goes back to 1970.

- **Chow, 1970**, the error–reject tradeoff — **unread**. The original result
  that a classifier permitted to abstain trades coverage for accuracy along a
  characterisable curve.
- **Geifman and El-Yaniv, 2017**, *Selective Classification for Deep Neural
  Networks*, arXiv:1705.08500 — **unread**. The modern framing: a selective
  model is a (predictor, selection function) pair with a guaranteed risk at a
  chosen coverage.
- In security ML specifically, **Transcend** (USENIX Security 2017 — **unread**)
  and **Transcendent** (IEEE S&P 2022, arXiv:2010.03856 — **unread**) build
  conformal-evaluation rejection for drifting malware classifiers: reject the
  samples the model has no business classifying, rather than classify them
  badly.

Cohaera's `not_evaluated` is not the same mechanism. Selective classification
abstains on the basis of a *confidence estimate over the input*; Cohaera
abstains on the basis of a *structural fact about the evidence* — a required
surface is absent, so the check's argument does not have premises. It is closer
to a precondition failing than to a rejection region. But the literature is the
right place to look for what to do next, particularly for the question this
project has not answered: what the correct operating point is, and how to choose
it.

**The name collides, and it collides backwards.** In selective prediction,
*coverage* is the fraction of inputs the model **did** answer. In Cohaera,
*coverage* is a report about what the checks **could not** answer. A reader
arriving from the selective-prediction literature will read
`coverage.completeness` as the fraction of sessions that got an answer, which is
close enough to the intended meaning to be dangerous and is not the same
quantity. Recorded here rather than fixed; see §7.

---

## 5. The verdict ladder is a consistency proof

`evidence_status` runs `verified_complete`, `verified_prefix`,
`chained_unsigned`, `unattested`, `inadmissible`. Two lineages.

**Casey, 2002, "Error, Uncertainty and Loss in Digital Evidence"** — **unread**
— introduced the C-Scale, an ordinal certainty scale for digital evidence
running from evidence that contradicts known facts up to evidence that is
tamper-proof or independently verified. A graded ladder of how much a record
deserves to be believed, in digital forensics, in 2002. The ladder is the same
idea; Cohaera's rungs are defined by what a verifier can mechanically establish
rather than by an examiner's judgement, which is a narrowing, not an advance.

**`verified_prefix` is a consistency proof, and saying so is better than
explaining it.** The construction — an append-only hash-chained log where a
verifier can be shown that one state is an extension of an earlier one, and
where a signature covering a prefix says nothing about the tail — is history
trees, **Crosby and Wallach, 2009** (**unread**), and it is standardised as
Certificate Transparency in **RFC 9162** (**unread**; the RFC Editor is
unreachable from here). Calling `verified_prefix` a *consistency proof* ties it
to a specification an implementer already knows, and drops the implication that
this project invented a way of describing a partly-signed log.

What Cohaera adds here is not the proof. It is the decision to carry the
proof's *outcome* on every finding derived from the stream, so that a verdict
built on an unattested tail does not arrive looking like one built on a
verified prefix. That is plumbing, and it is the useful part.

---

## 6. Contemporaries: agent evidence, 2026

This is the section that retired a claim. Until this file existed,
[POSITIONING.md](../POSITIONING.md) said that almost nothing reasons about
whether an agent's record deserves to be believed. That was true when it was
written and it is not true now.

### Agent Action Capsule — **Read**

An individual IETF Internet-Draft on the SCITT track,
`draft-mih-scitt-agent-action-capsule`, source at
[action-state-group/agent-action-capsule](https://github.com/action-state-group/agent-action-capsule).
Read here at revision `-02` plus `spec/REGISTRY.md`. It is not a Working Group
document and claims no RFC number, and its own README says so first.

It is the closest thing to this project's design goals that exists, and in
several places it is further along:

- **Content-addressed record identity.** `capsule_id` is a digest of the
  canonical capsule form; the reference verifier rejects a tampered capsule
  because the recomputed id no longer matches.
- **Parent chaining** via a `chain` block of `{parent_capsule_id, relation}`,
  with `relation` a governed vocabulary (`confirms`, `supersedes`,
  `epoch_opens`).
- **COSE_Sign1 signed statements**, registered in a SCITT Transparency Service.
- **The confirmed-effect invariant.** `effect.status: "confirmed"` requires a
  `response_digest` over the actually observed response, and "A verifier MUST
  treat `confirmed` with a missing response_digest as a verification failure."
  This is Cohaera's CH07 asymmetry, expressed as a format constraint rather than
  as a detection: a success that nothing observed cannot be spelled.
- **An honest human-in-the-loop flag.** `disposition.human_disposed` is "true
  ONLY when a human actually acted. A policy auto-approval is false", and true
  requires `approver: "human"`.
- **Evidence grading, explicitly.** The `effect_attestation` registry
  distinguishes `gate_executed` ("the engine observed the effect boundary
  directly") from `runtime_claimed` ("the executing runtime asserted completion;
  the capsule records that claim, not an observation"), with a grade-floor rule
  that an unrecognised value is treated as no stronger than `runtime_claimed`.
  The `provenance` registry ranks `gate` > `runtime` > `collector` and resolves
  duplicates by rank.

That last pair is *grading a record by how it was obtained*, which is the thing
this project claims as its layer. It is prior art in the strongest sense: same
problem, published, with a reference implementation and conformance vectors.

The draft also has a near neighbour of `not_evaluated` that is worth naming
rather than ignoring: `verdict_class: engine_failure`, "The engine could not
evaluate the action." It is a gate-side state about a policy decision, not a
consumer-side statement about evidence sufficiency, so the two are not the same
construct — but a document claiming that nobody carries an in-band "could not
evaluate" for agent actions would be wrong, and this one does not.

### halo-record — **Read**

[bkuan001/halo-record](https://github.com/bkuan001/halo-record), Apache-2.0, a
single-maintainer project. Hash-chained tamper-evident runtime records for AI
agents: "the audit trail the vendor runs but cannot silently edit." Zero runtime
dependencies, an optional witness and RFC 3161 timestamp path, a self-verifying
HTML report, and — its README's own figure — "~4,800 lines of Python."

Two things in it are directly relevant here. First, the optional `verification`
block records a gate's verdict sealed into the chain — and its `unverified`
status is documented as

> "it ran (or was consulted) but made no determination — distinct from an absent
> block, which means no verification claim was made at all"

which is the exact distinction Cohaera draws between `not_evaluated` with a
reason code and a check that is simply not present. Second, the project is
scrupulous about what sealing buys: the block "records what it reports the gate
said ... Sealing proves the status was not edited after the fact; it does not
prove the check occurred, that the verdict was correct, or that a blocked action
did not execute. This is not independent verification." That is the same posture
Cohaera takes toward in-band approvals, arrived at independently.

halo-record also stamps each record with a `source` tag disclosing how the
evidence was collected — captured at the boundary versus ingested from existing
telemetry — which is a coarser cousin of Agent Action Capsule's `provenance`
rank and of Cohaera's classification-quality term.

### MCP SEP-3140 — **Read**

[modelcontextprotocol/modelcontextprotocol#3140](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3140),
*Signed Capability Declarations & Trustworthy Trust Labels*. Read from the pull
request's head ref; the document records **Created: 2026-07-27**, Status
`draft`, Type Standards Track, author Omkar Parkhe (Microsoft). The pull
request's own status metadata could not be read — the GitHub API is not
reachable from this environment — so nothing is asserted here about its
sponsorship or review state beyond what the checked-in document says.

**This retires the novelty of Cohaera's capability manifest, and the concession
should be made without hedging.** SEP-3140 proposes a JWS-signed capability
manifest bound to a discoverable publisher identity, carrying a
signature-covered `trust` block per tool declaration:

```json
"trust": {
  "effect": "destructive",           // read-only | writes-data | destructive
  "egress": "external",              // none | internal | external
  "dataSensitivity": "confidential", // public | internal | confidential | secret
  "reversible": false,
  "idempotent": false,
  "capabilities": { ... }
}
```

Effect class, egress, reversibility, data sensitivity, signed, per exact tool.
That is Cohaera's `--tool-manifest`, proposed into the protocol, by a vendor,
with a proof-of-concept in the same pull request. The differences left over are
small and worth stating exactly:

| | SEP-3140 | Cohaera's manifest |
|---|---|---|
| Signed | JWS, bound to publisher identity | Not signed; two digests in `provenance.capability_manifest`, or a detached `cohaera.policy_signature:1` |
| Who declares | the server, about itself | the operator, out of band, about somebody else's tools |
| On an unknown value | "treated as most-restrictive by the client" | contributes `TOOL_CLASS_UNKNOWN` to coverage and lowers confidence |
| Purpose | gate the call before it happens | grade the record after it happened |

The "who declares" row is the only one that is a real design difference rather
than a maturity gap, and it cuts both ways: a publisher signature is a much
better provenance story than an operator-chosen file, and an operator-chosen
file is not written by the party whose behaviour is in question. If SEP-3140 or
a successor lands, the right move for this project is to consume it, not to
compete with it.

### Signed and hash-chained agent telemetry — **Unread, six projects**

Two commissioned research briefs went looking for open-source projects shipping
tamper-evident agent telemetry. Both found some. **Neither found the other's**,
and that non-overlap is the most useful thing either returned: the space is
fragmented, nothing in it is canonical, and no single search enumerates it.

Reported, none read here:

| Project | Reported to ship |
|---|---|
| `obsvr-dev/obsvr-sdk` | HMAC-SHA256 chain over session, sequence number, previous signature and content; a verify CLI; optional server countersignature; a daily Ed25519-signed Merkle root anchored off-host; **signed gap markers** on queue overflow |
| `RightNow-AI/openfang` | Merkle hash-chain audit trail, SHA-256 previous-hash linkage per action, Ed25519-signed agent manifests |
| `@merchantguard/agentguard-cb` | Ed25519-signed, SHA-256 hash-chained audit log, with an offline-verifiable evidence pack |
| `phionyx-core` | Signed, hash-chained, offline-checkable evidence receipt per governed turn |
| `maco144/merkle-audit` | SHA-256 chain plus MMR root per tool call |
| `Ascendral/codebot-ai` | SHA-256 hash-chained audit log per tool call |

**`obsvr-sdk` is not Exabeam's Observra.** The names are close enough to merge by
accident and the two are unrelated; a citation that conflates them is wrong.

**One of these is better than Cohaera at something specific.** `obsvr-sdk`'s
*signed gap markers* emit a signed record when the queue overflows, instead of
leaving a consumer to infer loss from a hole in the sequence. Cohaera infers.
Observra has no equivalent either — grepped against `c4d036b`. This belongs on
the roadmap rather than in a comparison table.

**What survives as a claim, and it is narrower than the one it replaces.** An
external gap analysis asserted that nobody ships tamper-evident agent telemetry
and that the first mover would set the standard regulators cite. That is false
twice over: the six rows above, and the regulatory half is addressed in
[BLUEPRINT-2026-08](BLUEPRINT-2026-08.md) §3.4. What is left is checkable:

> No **mainstream observability platform** ships event integrity — OTel GenAI
> conventions, Langfuse, Arize Phoenix, OpenLLMetry, Helicone, AgentOps and
> LangSmith are all reported to lack chaining, signing and attestation. And **no
> single project combines signed hash-chained events, per-agent attestation
> keys, and evidence export.**

Cohaera does not combine all three either. It has the first, it has key roles
and rotation in a trust store rather than per-agent attestation, and it has no
evidence-pack export at all. The narrowed claim is a description of an open
position, not of an occupied one.

### Auditable Agents and From Agent Traces to Trust — **Unread**

Two 2026 papers were reported as directly on point and could not be fetched:

- *Auditable Agents*, arXiv:2604.05485 (April 2026), reported to name **evidence
  integrity** as one of five dimensions of agent auditability, alongside action
  recoverability, lifecycle coverage, policy checkability and responsibility
  attribution.
- *From Agent Traces to Trust*, arXiv:2606.04990 (June 2026), reported to be a
  survey formalising execution provenance and evidence tracing.

Snippet-level only. arxiv.org returns 403 at this environment's egress proxy,
nothing here is verified against either full text, and the five-dimension list
above should be treated as a pointer to check rather than as a quotation. If
either paper is what it is reported to be, the first of them has already named
this project's layer, which is a good outcome and not a bad one.

---

## 7. Two names this project should change, and one it should not

These are recommendations. **No code is renamed by this document**, and none
should be renamed as a consequence of it without a deprecation path — a reason
code is a wire contract and a SIEM rule somewhere is matching on the string.

**`inadmissible` is a bad name.** Admissibility is a determination a court
makes, about a particular item, in a particular proceeding, under rules of
evidence. A detection tool asserting that a record is inadmissible is claiming
an authority it does not have and cannot have, and the claim is the kind that
gets quoted back at a project in a context it did not choose.
[POSITIONING.md](../POSITIONING.md) already keeps a list of words this project
refuses to use about its own results; this one belongs on it and is not on it
yet. `inconclusive` says what the value means — the chain does not support a
conclusion. `broken_chain` says what actually happened, which is better still
for the sequence-gap and chain-break cases, and slightly worse for the bad
signature and replay cases. Either is preferable to borrowing a legal term of
art.

**`coverage` collides with selective prediction, backwards** (§4). This one is
harder, because "coverage" in the detection-engineering sense — which technique
or which surface is watched — is the sense the intended reader has, and it is
the sense DeTT&CT and Elastic's `required_fields` use. The collision is with a
different field, and the term is probably right for the audience. Recorded so
that a reader arriving from the machine-learning side is not silently misled.

**`not_evaluated` should stay exactly as it is**, and specifically should not be
renamed to something more precise. It is OVAL's term, spelled OVAL's way, and
the twenty-year-old term that a reader may already know is worth more than a
better-fitting new one.

---

## 8. What is actually new here

Three things, and the list is deliberately short. **None of them is a research
contribution**, and this section exists to bound the claim rather than to make
one.

**1. In-band carriage, addressed to the consumer.** The systems in §1 that carry
the unevaluated state in the result — OVAL, XCCDF, VEX, Security Hub — are
assessment and disclosure tools, and their reader is a person or a compliance
report. The systems whose output feeds a correlation engine — Elastic, Sentinel,
Google SecOps — all know when a rule could not run and all put it in a
platform-health stream addressed to the operator instead. Cohaera puts the
reason code in the same record as the finding, on the assumption that the reader
is the correlation consumer rather than the person who maintains the pipeline.
That is a routing decision, not an idea, and it may well turn out to be the
wrong one.

**2. Per-check binding.** DeTT&CT binds evidence quality to a data source and
rolls it up per technique. Elastic binds `required_fields` to a rule. AWS binds
a reason code to a control. Cohaera binds a contract to each individual check's
evaluation of each individual session, so two checks over the same session can
disagree about how much of it they were able to see. This is a finer grain on an
existing construction and nothing more.

**3. A reason-code taxonomy for agent and MCP session evidence.** The specific
vocabulary — `NO_INJECTION_SCANNER_EVIDENCE`, `NO_COLLECTOR_KEYS`,
`POLICY_SEMANTICS_UNDECLARED`, `CORRELATION_KEY_NOT_PRODUCER_SUPPLIED`,
`TOOL_CLASS_FROM_NAME_HEURISTIC` and the rest — does not appear to exist
elsewhere. It is new **only because the substrate is new**. It will stop being
new the moment OCSF adds a per-analytic coverage construct to sit next to
`verdict_id: Insufficient Data`, or OpenTelemetry's GenAI conventions add an
equivalent to their agent spans, and the correct response at that point is to
map onto whichever of them lands rather than to defend this vocabulary.

A 2025 Theseus.fi master's thesis, *Detection Surface Index* — **unread,
reported** — is said to conclude that no unified model chains coverage,
degradation and weighting into a single score. If so it is independent evidence
that the gap is recognised and unfilled, which is a weaker and more useful thing
than novelty: somebody else named the problem first.

Everything else in this repository that looks like an idea is in this file,
under somebody else's name.
