<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Cohaera threat model

What this component trusts, what it does not, and which of its guarantees
survive an attacker who controls the input. Written to be falsifiable: every
claim below either names the code that enforces it and the test that pins it, or
says plainly that nothing does.

The short version, and the only sentence that matters if you read no further:

> **Cohaera's input is supplied by the system it is judging.** Every guarantee
> here is conditional on that input being a faithful record. Cohaera can detect
> that a record is *malformed*. It cannot detect that a record is *untrue*.

---

## 1. What Cohaera is

A batch or streaming analyser that reads observra-normalised agent telemetry as
JSONL, groups events into sessions, runs seven correlation checks, and emits one
verdict record per session for a SIEM.

It has **no network listener, no database, no credentials, no write access to
anything it observes, and zero runtime dependencies.** It reads files and writes
JSON to stdout. That is a deliberately small attack surface and it is most of
this document's good news.

```
    agent runtime  ──►  observra  ──►  JSONL  ──►  COHAERA  ──►  stdout  ──►  SIEM
     (untrusted)      (untrusted)   (untrusted)   (this)                    (trusted)
```

Everything to the left of Cohaera is outside its trust boundary. Everything to
the right inherits whatever Cohaera got right.

## 2. Assets

| Asset | Why an attacker wants it |
|---|---|
| **The verdict stream** | It is what a SOC acts on. A verdict that says "clean" is a decision not to investigate |
| **Coverage / `completeness`** | It is what a SOC *routes* on. A blind spot reported as full confidence is worse than a blind spot reported as a blind spot |
| **`verdict_id` / `analysis_run_id`** | A SIEM deduplicates on these. Two verdicts colliding means one is silently discarded |
| **Availability of the analyser** | Crashing the detector evades every check at once, which is cheaper than evading any one of them |
| **The host running Cohaera** | It is typically a collection VM with reach into telemetry infrastructure |
| **The benign baseline** | It defines "normal". Whoever writes it decides what is anomalous |

## 3. Actors

| Actor | Capability assumed | Notes |
|---|---|---|
| **A1. Compromised or misaligned agent** | Chooses its own actions; its telemetry is emitted honestly by an uncompromised adapter | The threat Cohaera is *for* |
| **A2. Prompt injection via tool output** | Controls text the agent reads, therefore influences A1's actions | Cohaera sees the consequences, not the injection |
| **A3. Agent controlling its own emitter** | Chooses what telemetry exists at all: omit, fabricate, fragment, re-key | **Defeats Cohaera**, unless the collector signs outside the agent's reach. E11, E12, E13, and §5 |
| **A4. Attacker on the telemetry path** | Modifies records in flight or at rest before Cohaera reads them | **Detected** on a stream carrying `cohaera.integrity:1` — deletion, modification and selective stripping all leave evidence. Undetectable without it, which is every deployment today |
| **A5. Attacker supplying malformed input** | Writes arbitrary bytes into the JSONL | The ingest trust boundary. Twenty-two defects fixed here |
| **A6. Baseline poisoner** | Influences the corpus the grammar is fitted on | E03. Process control, not a code control |
| **A7. Supply chain** | Compromises a dependency, a GitHub Action, or a published artefact | See §7 |

**Not modelled:** an attacker with code execution on the Cohaera host. At that
point they can rewrite the verdicts, and nothing in a userspace analyser is a
control against its own host.

## 4. Trust boundaries, and what is enforced at each

### B1. The telemetry file → the reader

The only boundary where Cohaera has real authority, and the one that has cost
the most defects.

| Enforced | Where | Pinned by |
|---|---|---|
| Bounded line size, nesting depth, record count, byte total, reject count and reject ratio, all checked **per record inside the reader** | `ingest.read_events`, `limits.py` | `test_hostile.py` C4-02 |
| Bounds validated at construction; a negative cap cannot silently disable a cap | `Limits.__post_init__` | C4-05, and a test asserting *every* field has a rule |
| Every field type-checked; no truthiness coercion | `validate.py`, `capabilities.py` | BUG-01/02/04, C4-06 |
| Malformed records quarantined with a reason code and a digest, never dropped silently | `IngestReport`, `--reject-log` | BUG-11, C4-04 |
| Records frozen after validation, so a cache cannot go stale against a mutated payload | `model.Event`, `Session.seal` | C4-07, C4-08 |
| Oversize records counted and digested without being retained | `_bounded_lines` | C4-09 |

**Residual risk.** These make Cohaera *robust*, not *correct*: a well-formed lie
passes every one of them. That is by construction — see §5.

### B2. The producer's claims → the classifier

A tool's effect class decides whether a call is consequential, and three checks
depend on it.

Precedence, strongest first: an out-of-band **capability manifest** keyed on the
exact tool ID; egress by name; the producer's in-band `reversible` flag; the
name heuristic.

The manifest outranks `reversible` **because `reversible` arrives on the event**,
from the same path an attacker uses to hide an action, while the manifest is
loaded from a path the operator chose. Both manifest digests — over the file's
bytes and over the parsed declarations — travel in every verdict, so two runs
that disagree about what a tool does are distinguishable after the fact.

**Residual risk.** With no manifest, classification is a guess about an
attacker-supplied string, and the evaluation corpus measures that guess at **0%
on realistic enterprise tool identifiers**. The manifest is not signed; signing
needs a key distribution story this project does not have.

### B3. The correlation key → session assembly

Sessions are assembled on a key the observed system supplies. With no
`session_id` or `trace_id`, Cohaera falls back to an HMAC of the identity fields
plus a time window, and with **no identity at all it isolates the record rather
than bucketing it by clock** — because two unrelated records that merely arrived
together are not a session, and a fabricated correlation manufactures findings
(BUG-06, C4-03).

Every verdict states which of the four key kinds it used and how much confidence
that carries (1.0 / 0.9 / 0.3 / 0.0).

**Residual risk.** A3 and A4 defeat this outright by giving every event its own
key. E12.

### B4. Cohaera → the SIEM

Verdicts carry content-derived identity (`analysis_run_id`, `verdict_id`,
`findings_digest`), a provenance block naming the detector version, bounds
digest, baseline hash and both manifest digests, and a per-check coverage
contract. Text emitted into a record is sanitised for display.

**Residual risk.** These digests prove *Cohaera saw this input*. They prove
nothing about whether the input was true.

## 5. The central limitation

Everything above secures the boundary between Cohaera and its input. **None of
it secures the boundary between the input and reality.**

An agent that controls its instrumentation, or an attacker on the telemetry
path, can:

- **omit** a call — no event, no session member, no finding (E13);
- **fabricate** a terminal event, so an unpaired call looks complete (E11);
- **fragment** a session by re-keying, so no cross-event check has state (E12);
- **misreport** `reversible`, if no manifest overrides it.

There is no defence against this inside Cohaera, and building one that *looked*
like a defence would be worse than the gap. What Cohaera does instead is
**refuse to report confidence it has not earned**: coverage is a per-check
capability contract, and a check that could not evaluate a session reports
`not_evaluated` with a reason code rather than contributing a silent pass. A
session assembled from telemetry with no scanner evidence, no manifest and an
anonymous key scores around 0.68, not 1.0.

That is a smaller thing than detection and a real one: the blind spot becomes
routable instead of invisible.

### What P1 evidence trust changed, and for whom

Closing this needs evidence Cohaera cannot generate — kernel or network
observation of the agent's actual syscalls
([AgentSight, arXiv:2508.02736](https://arxiv.org/abs/2508.02736)), or a
tamper-evident signed log at the point of emission
([AEGIS, arXiv:2603.12621](https://arxiv.org/abs/2603.12621)). Both are
collector-side. **The second is now built** — see
[EVIDENCE-TRUST.md](EVIDENCE-TRUST.md) — and it changes the actor table rather
than the limitation:

| Actor | Before | After, on a stream carrying `cohaera.integrity:1` |
|---|---|---|
| **A4. Attacker on the telemetry path** | Undetectable | **Detected.** Deleting a record leaves a sequence gap; modifying one breaks the chain; stripping the sidecar from the record you edited leaves a session that is partly attested, which is itself reported (E21) |
| **A3. Agent controlling its own emitter** | Defeats Cohaera | Defeats Cohaera *unless the collector is outside its reach*. The signing key is the whole of the difference, and where the adapter runs in-process the agent holds it |

So A4 moves and A3 does not, and the distinction is the one to hold on to. What
P1 buys is **a lie now costs a signing key the agent does not hold**, or a
receipt bound to the exact call and the exact arguments. Where the agent does
hold the key, a perfectly verified chain is a perfectly verified chain of
whatever it chose to say, and CH06's coverage contract states that as an
assumption on every session it evaluates rather than letting the green tick
imply otherwise.

One narrow new detection cuts against A3 directly, and it is worth naming
because it is the only one: a call whose terminal event reports **failure**
while carrying an effect receipt bound to it is a contradiction inside the
record, and the receipt is drawn from a namespace the agent does not control
(CH07). It does not make a reported *success* checkable. Nothing here does.

## 6. What the checks can and cannot conclude

Stated per check, because "CH03 fired" means something narrower than it sounds.

| Check | Concludes | Explicitly does **not** conclude |
|---|---|---|
| **CH01** sequence order | This ordering, or this route into a consequential call, is not in the fitted benign grammar | That the session is malicious. A legitimate rare action produces the same shape. Reports `not_evaluated` rather than firing when the baseline was fitted on a different workload |
| **CH02** concealment | A consequential call succeeded and the final response does not name it | That the agent lied. An honest paraphrase reads identically (E04). A mention that cannot be told apart from a sibling tool's is reported as *ambiguous*, not as clean (E16) |
| **CH03** taint | An injection marker was recorded before a consequential call, in the same session | Information flow. It is an ordering, not a taint trace, and it inherits the upstream scanner's blind spots (E09) |
| **CH04** guardrail | A policy event fired and consequential work continued — and, where the control is *declared blocking* and no approval binds to that work, that it was **bypassed** | That the guardrail was ignored, where nothing declares advisory versus blocking. A declaration read off the event is the agent's own claim and suppresses the check when it says `advisory` (E20); the manifest overrides it |
| **CH05** unpaired | A call started and no terminal event was recorded | That the call ran. A timeout, a dropped event and a deleted event are indistinguishable here |
| **CH06** evidence integrity | These records do not verify against what the collector attested to: a sequence gap, a chain break, a bad signature, an unsupplied key | Who did it. A collector holding the signing key can produce a perfectly chained stream of lies, and where the adapter runs in the agent's process that is the normal configuration, not a compromise |
| **CH07** effect contradiction | A call reported failure while carrying a receipt bound to that exact call and those exact arguments | That the receipt is genuine. Cohaera is offline and cannot ask the authority. It checks that the receipt **binds**, not that it is real — and it makes no claim at all about a reported *success* |

Every one of those "does not conclude" columns is a measured false positive
source in [`eval/EVALUATION-CARD.md`](../eval/EVALUATION-CARD.md) §3, not a
disclaimer.

## 7. Supply chain

| Control | State |
|---|---|
| Zero runtime dependencies | Enforced in CI from installed distribution metadata |
| Actions pinned to commit SHAs | Enforced by `tests/test_ci_config.py` |
| Dependabot on actions and dev extras | `.github/dependabot.yml` |
| CodeQL, `security-extended`, per PR and weekly | `.github/workflows/codeql.yml` |
| `main` protected: squash-only, required checks, no force-push | `.github/rulesets/main.json`, asserted against the CI jobs |
| SBOM (CycloneDX) generated per run | `sbom` job |
| **Signed releases** | **Not implemented** |
| **SBOM attested and bound to a released artefact** | **Not implemented.** The SBOM is a 90-day CI artefact |
| **Secret scanning and push protection** | Repository settings; cannot be committed. See `.github/rulesets/README.md` |

The squash-only rule is a signing control rather than a style preference: GitHub
signs the commit it creates on a squash merge, so contributions land `Verified`
even when the contributor cannot sign locally. A merge commit is signed too —
and preserves the unsigned branch commits underneath it, which is how this
repository once took `main` from one unverified commit to five.

## 8. Deployment assumptions

Cohaera is correct only if these hold. They are the operator's, not the code's.

1. **The host is trusted and isolated.** Cohaera has no controls against its own
   host.
2. **`$COHAERA_CORRELATION_SECRET` is set**, from the deployment rather than from
   the telemetry. Without it, anonymous session keys are unkeyed digests over a
   small identity space, which is enumerable from the SIEM copy. The record says
   which it is via `correlation.keyed`; nothing forces the secret.
3. **The capability manifest is under change control.** It is configuration that
   changes verdicts, it is not signed, and both its digests are recorded so a
   change is visible after the fact rather than prevented.
4. **The benign baseline is actually benign, and is this agent's own.** Cohaera
   cannot verify the first (E03) and measurably does not transfer across
   workloads without the second — it declines rather than flagging, which costs
   recall and says so.
5. **Verdicts are treated as leads.** At the corpus's absurd 33% attack
   prevalence, precision is 44%. At a realistic base rate it is far lower;
   `false_positives_per_1000_sessions` is the number to plan capacity against.

## 9. Known unknowns

Things that would change this document and have not been done.

- **No real-traffic evaluation.** Every number is from a synthetic corpus
  written by the detector's author.
- **No adaptive attacker in the corpus.** Exactly one of seventeen catalogued
  evasions appears in it, and only because a fix could not be graded otherwise.
- **No fuzzing of the CLI argument surface**, only of the record surface.
- **No measurement of Cohaera under concurrent or streaming load.** The
  amplification bounds are measured batch.
- **The Sigma content and the field map are untested against a live
  Exabeam or LogRhythm parser.** The Sigma rules pass Sigma CLI validation and
  every field they name is asserted to exist in a real emitted record; that is
  not the same as a deployed parser accepting them.
