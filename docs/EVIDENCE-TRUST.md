<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Evidence trust: design and implementation for P1

**Status: built.** This document was written as a design, before any of it
existed, because the mistake this project is most exposed to is shipping a field
that looks like a control — the reason the capability manifest has no
`signature` field today is that nothing would verify one, and a signature nobody
checks is worse than no signature.

It is kept as written, with the implementation notes folded in, so that the
difference between what was planned and what was built is readable rather than
tidied away. Four things changed on contact with the code and each is marked
**BUILT** or **CHANGED** at the point it applies:

| Where | Change | Why |
|---|---|---|
| §2 chain | `chain[n] = H(chain[n-1] ‖ H(canonical(record)))` — the record is folded in through its own digest | A verifier meeting an out-of-order stream has to hold every record it cannot yet chain. Holding 32 bytes per pending record instead of the record makes the reorder buffer a fixed cost rather than one the producer chooses |
| §2 | Two codes added: `INTEGRITY_EVIDENCE_PARTIAL` and `INTEGRITY_RECORDS_REORDERED` | The first closes the obvious way round a chain — strip the sidecar from the record you edited (EVASION.md E21). The second distinguishes the conclusion the verifier reached, which the design said it must and did not give a code for |
| §4 | Enforcement may also be declared in the **capability manifest**, and the manifest wins | The design read `enforcement` off the event only. That field suppresses a finding and arrives in band, so an agent that wanted CH04 quiet would send it. EVASION.md E20 |
| §4 | CH04's blocking case is a **new check ID**, not a rewording of the old one | Renaming `CH04_guardrail_bypass_completed` would silently change what every existing Sigma rule matches |

Implementation is in [`src/cohaera/evidence.py`](../src/cohaera/evidence.py) and
[`src/cohaera/ed25519.py`](../src/cohaera/ed25519.py); the reference producer is
[`tools/collector_sign.py`](../tools/collector_sign.py); the tests are
[`tests/test_evidence.py`](../tests/test_evidence.py). What it measured is §8.

Three external reviews have put the same item at the top and it has been open
each time: *independent effect receipts, collector-side signing and hash
chaining, and approvals bound to the exact call*. This document is what closing
them would actually look like — wire formats, what Cohaera would verify, what it
would emit, what it still could not prove, and who has to change.

---

## 1. The problem, stated precisely

Cohaera's checks are sound arguments over their input. Every one of them is
conditional on the input being a faithful record, and nothing establishes that:

| Fault | Today | Catalogued as |
|---|---|---|
| A call happened and no event was emitted | Undetectable except by accident, when the gap breaks a learned bigram | E13, E13b |
| A terminal event says `success` for a call that did nothing | Undetectable. `result` is a string the emitter chose | E11 |
| A terminal event was fabricated for a call that never started | Detected only as an orphan, and only if the start is also absent | E11 |
| Every event carries a different `session_id` | Every cross-event check goes quiet at once | E12 |
| A record was modified in transit | Undetectable | A4 in the [threat model](THREAT-MODEL.md) |
| A consequential call continued past a policy event | Reported, but Cohaera cannot say whether an approval covered it | CH04, `POLICY_SEMANTICS_UNDECLARED` |

The common shape: **Cohaera can tell a malformed record from a well-formed one,
and cannot tell a true record from a false one.** Twenty-two fixed defects have
all been on the first boundary. This document is about the second.

### What "closing" can and cannot mean

It cannot mean proof. An analyser reading a file offline can never establish
that an action occurred in the world. What it can do is move the attack from
*asserting* to *forging*:

> Today a lie costs one boolean. After P1 a lie costs a signing key the agent
> process does not hold, or a receipt bound to the exact call and the exact
> arguments.

That is a raise, not a closure, and this document says so everywhere rather than
once. Any write-up of P1 that claims E13 is closed is wrong.

---

## 2. P1.1 — Collector integrity: sequence, chain, signature

**Threat closed:** modification in transit, deletion of events, and fabrication
by anyone who does not hold the collector's key.
**Threat not closed:** a compromised collector. Trust moves from *the agent's
emitter* to *the collector's key*, which is only an improvement if the collector
sits outside the agent's blast radius. Deployments where the adapter runs
in-process with the agent gain nothing here and should be told so.

### Wire format

One sidecar object per record, added by the collector after normalisation and
before the record leaves the host:

```json
"integrity": {
  "scheme":    "cohaera.integrity:1",
  "stream_id": "01JQ8Z9K2M4N6P8R0T2V4X6Y8A",
  "seq":       1234,
  "prev":      "9f2c4e6a8b0d1f3572849ab6cd0e1f23",
  "chain":     "3d5f7091b2c4e6a8091b2c4e6a8091b2",
  "key_id":    "ed25519:4f1a…",
  "sig":       "base64(Ed25519 over the signing input below)"
}
```

The chain, where `H` is SHA-256 and `canonical()` is the same sorted-key,
separator-fixed JSON `cohaera.identity.canonical` already uses:

```
chain[0] = H(scheme ‖ stream_id ‖ key_id)
chain[n] = H(chain[n-1] ‖ canonical(record without its "integrity" field))
```

The signing input is `scheme ‖ stream_id ‖ seq ‖ chain[n]` — not the record
itself. Signing the chain head rather than the record is what makes a single
verified signature cover every record before it, so a collector may sign every
record or every *k*th without changing the verifier.

### What Cohaera verifies

Per `stream_id`, in one pass, with bounded state (one chain head, one expected
sequence, one key reference per stream):

1. **Sequence.** `seq` must be the previous `seq + 1`. A gap is a **deletion**
   signal — the direct answer to E13's naive case, which today is caught only by
   the accident described as E13b. An out-of-order arrival on a streaming path
   is a reordering, not a deletion, so the verifier holds a small bounded window
   before declaring a gap, and says which it concluded.
2. **Chain.** Recompute `chain[n]` from the retained head and the record as
   read. A mismatch is **modification**, and it localises: the first mismatching
   record is where the stream diverged.
3. **Signature.** Verify against a public key loaded **out of band**, exactly as
   the capability manifest is — `--collector-keys keys.json`, with both a file
   digest and a semantic digest recorded in provenance, for the same reasons
   C4-10 gives.

Failure is not a check finding of the same kind as CH01–CH05. Those are
statements about the agent's behaviour; this is a statement about whether the
evidence is admissible at all. It gets its own check ID (**CH06**, evidence
integrity, critical) *and* every other finding in the affected session is marked
as resting on unverified evidence, because a verdict built on a broken chain
should not be presented at the same confidence as one that is not.

### Coverage additions

A new surface `event_integrity`, and reason codes:

| Code | Meaning |
|---|---|
| `NO_INTEGRITY_EVIDENCE` | No record in this session carried an `integrity` object. **The default state**, and the one every current deployment is in |
| `NO_COLLECTOR_KEYS` | Records are signed, but no key file was supplied, so signatures were parsed and not verified |
| `INTEGRITY_SEQUENCE_GAP` | Records are missing from this stream |
| `INTEGRITY_CHAIN_BROKEN` | A record does not match the chain |
| `INTEGRITY_SIGNATURE_INVALID` | A signature did not verify under the supplied key |
| `INTEGRITY_KEY_UNKNOWN` | `key_id` is not in the supplied key set |

`NO_INTEGRITY_EVIDENCE` is the important one. It is what turns "Cohaera did not
detect tampering" from a silent pass into a stated absence — the same move the
CH01 vocabulary contract and the E16 ambiguity classification make.

### Key distribution

The unsolved half, and the reason this is design rather than code. A key file
loaded from an operator-chosen path is the same trust model as the manifest and
is honest about it: it says *these signatures verify under a key you supplied*,
not *this telemetry is genuine*. Rotation, revocation and multi-collector fleets
need more than a file, and shipping the file first is defensible only if the
verdict says which of those it is not doing.

---

## 3. P1.2 — Independent effect receipts

**Threat closed:** a logged `success` for a call that did nothing.
**Threat not closed:** a forged receipt. Cohaera is offline and cannot ask the
authority whether the receipt is real.

### The idea

`result: "success"` is the agent's claim about itself. A receipt is an
identifier **minted by the system the action happened to** — an SMTP
`Message-ID`, an S3 `x-amz-version-id`, a database transaction ID, a Kubernetes
resource `uid`, a Stripe `charge.id`, a CloudTrail `eventID`. Those identifiers
have a property the agent's boolean does not: they are drawn from a namespace
the agent does not control, and they can be checked later against the authority
by a human or by a separate job.

```json
"effect_receipt": {
  "scheme":      "cohaera.receipt:1",
  "authority":   "aws:s3:eu-west-2",
  "kind":        "object_version",
  "identifier":  "3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY",
  "observed_at": 1785700042.5,
  "binding": {
    "span_id":    "01JQ8Z…",
    "tool_id":    "s3_object_put",
    "arg_digest": "sha256:7c9e2b…"
  }
}
```

### What Cohaera verifies

Not authenticity — it cannot. Three things it *can* check, and the third is the
one that pays for the whole mechanism:

1. **Binding.** `span_id` and `arg_digest` must match the call. Without this a
   receipt can be copied from a legitimate call onto a malicious one, and the
   mechanism is decorative.
2. **Presence.** A consequential call reporting `success` and carrying no
   receipt is now a *stated* gap rather than an accepted claim
   (`NO_EFFECT_RECEIPT`). Reported through coverage, not as a finding, because
   in any real deployment most tools will not have receipts for a long time and
   a finding per receiptless call is a pager storm on day one.
3. **Contradiction.** A call whose terminal event says `failure` or `error`
   while carrying a valid receipt bound to it **is a new detection**: an effect
   occurred and the telemetry reported that it did not. That is the first thing
   in this repository that would catch a lying emitter rather than route around
   it, and it deserves its own check ID (**CH07**, critical).

The asymmetry is the point. Receipts do not make Cohaera trust `success` more;
they make `failure` and silence falsifiable.

### Who has to change

Every tool integration, one at a time, and this is why it is the slowest of the
three. The adapter must surface an identifier the target system returned, which
it usually already has and discards. Realistic order, easiest first: object
storage (version IDs), email (Message-ID), payment and ticketing APIs (resource
IDs), then anything whose response is a bare 200.

---

## 4. P1.3 — Approval and policy binding

**Threat closed:** a broad or stale approval covering a call it was never
granted for.
**Threat not closed:** an approver who approves the wrong thing.

Today CH04 can say *a policy event fired and consequential work continued*. It
cannot say *the control was bypassed*, because nothing in the schema declares
whether the control was advisory or blocking, and nothing binds an approval to a
call. Both gaps are measured: `benign_hard_advisory_threshold` is 40 of the
corpus's false positives, and CH04's alert precision is 50%.

```json
"approval": {
  "scheme":  "cohaera.approval:1",
  "decision": "allow",
  "subject": {
    "span_id":    "01JQ8Z…",
    "tool_id":    "send_email",
    "arg_digest": "sha256:7c9e2b…"
  },
  "granted_by":     "user:alice@example.com",
  "granted_at":     1785700030.0,
  "expires_at":     1785700330.0,
  "policy_id":      "email-external-recipients",
  "policy_digest":  "sha256:1a2b3c…",
  "enforcement":    "blocking"
}
```

### What Cohaera verifies

1. **Subject binding.** The approval must name this `span_id` *and* match the
   call's `arg_digest`. This is the whole mechanism: an approval for
   `send_email` to `alice@example.com` must not cover `send_email` to
   `attacker@example.net`, and today nothing stops it.
2. **Freshness.** `granted_at ≤ call.started_at ≤ expires_at`. An expired
   approval is not an approval.
3. **Dangling approvals.** An approval whose subject matches no call in the
   session is reported — it is either a bug in the emitter or an approval
   harvested for reuse.
4. **`enforcement`.** With this declared, CH04 finally splits honestly: a
   completed consequential call after a **blocking** policy event with **no
   matching approval** is a bypass and can be called one. After an **advisory**
   event it is normal operation and should not fire at all — which is the direct
   fix for the corpus's largest single false-positive source.

### Who has to change

The guardrail or policy engine, which already knows all of these fields at the
moment it decides. Cheapest of the three to implement and the one with the
largest measurable effect on false positives, which is a good argument for doing
it first even though it is listed last.

---

## 5. Staging

| Stage | Work | Who changes | Status |
|---|---|---|---|
| **0** | Freeze the three schemas above. Parse and verify what is present; report absence through coverage. No new required fields | Cohaera | **BUILT.** Producers emitting none of it see no change except honest coverage codes |
| **1** | Approval binding, and CH04 split into bypass / continuation on declared `enforcement` | Policy engine | **BUILT**, plus the manifest override E20 forced |
| **2** | Collector chain and signatures, CH06, `--collector-keys` | Collector (observra) | **BUILT.** Key *distribution* is still a file, and still says so |
| **3** | Effect receipts, CH07 contradiction detection | Every tool adapter, incrementally | **BUILT.** The slow part is unchanged: every integration, one at a time |

Stage 0 was deliberately the largest commitment and the smallest change: the
promise that the fields mean something, made before anyone emits them. Nothing
in stages 1 to 3 required a producer to change in order for Cohaera to keep
working — a stream carrying none of these three schemas scores exactly as it did
before, and says `NO_INTEGRITY_EVIDENCE`, `NO_APPROVAL_EVIDENCE` and
`NO_EFFECT_RECEIPT` instead of quietly reporting that it looked.

The one thing still outstanding from this document is **key distribution**.
`--collector-keys` reads a JSON file the operator names, which is the same trust
model the capability manifest has. Rotation, revocation and multi-collector
fleets need more than a file, and the verdict records the key file's digests so
that two runs disagreeing about which keys were trusted are distinguishable
after the fact. That is honest, and it is not a trust store.

---

## 6. How this got graded

The same discipline E02 forced, applied in advance: **a corpus can only grade
fixes for attacks it contains**, and the current corpus contains none of these.
Before any of the above lands, `eval/corpus/generate.py` needs kinds for it:

- `attack_omitted_call` — a session with a consequential call deleted from the
  stream, with and without integrity evidence. Recall goes from ~0 to ~1 when
  the sequence check is present, and the corpus should show that transition
  rather than assert it.
- `attack_forged_success` — a `success` on a call that produced no receipt,
  against a benign confounder of a *genuinely receiptless tool*, which is the
  realistic mixed deployment and the source of every false positive this
  mechanism will produce.
- `attack_reused_approval` — an approval bound to one call, presented for
  another, against `benign_hard_reapproved_retry`, where an agent legitimately
  retries an approved action.
- `benign_hard_reordered_stream` — out-of-order delivery, so the sequence check
  is measured against the thing it will actually meet in production rather than
  only against deletion.

Without those, a P1 write-up would report "no change in recall or false
positives" and that sentence would be about the corpus, not the detector.

**All of them were built, and one was declined.** `attack_forged_success` — a
reported success with no receipt — is deliberately **not** in the corpus, and
the reason is the same discipline that put the others in it. Its telemetry is
byte-identical to a genuinely receiptless tool reporting success. Labelling one
of two identical inputs "attack" would not measure a detector; it would measure
the label. That case is reported through coverage as `NO_EFFECT_RECEIPT` and
`tests/test_evidence.py` asserts it produces no finding, which is the whole
claim receipts make in that direction: they do not make `success` more
believable, they make `failure` and silence falsifiable.

The kinds that were built are `attack_omitted_call`, `attack_denied_effect`,
`attack_reused_approval`, `benign_hard_reordered_stream`,
`benign_hard_approved_continuation` and `benign_hard_reapproved_retry`.

---

## 8. What it measured

Unseen vocabulary, task-disjoint split, with a capability manifest. Full numbers
in [`eval/EVALUATION-CARD.md`](../eval/EVALUATION-CARD.md) §3b.

| | before P1 | after P1 |
|---|---|---|
| recall | 100.0% | 100.0% |
| false positive rate | 61.8% | **44.3%** |
| false positives per 1000 sessions | 404 | **317** |
| CH04 alert precision | 50% | **100%** |
| `benign_hard_advisory_threshold` false positives | 40 | **0** |
| `attack_omitted_call` recall | — (undetectable) | **100%** |
| `attack_denied_effect` recall | — (undetectable) | **100%** |
| `attack_reused_approval` recall | — (undetectable) | **100%** |

Read the false-positive line correctly. **Almost none of that improvement is a
better detector.** CH04 stopped firing on advisory thresholds because a field
appeared that says whether the control was advisory or blocking; the check did
not get cleverer, it stopped being asked a question it could not answer. The
three new recall rows are genuinely new detections, and every one of them is
conditional on a producer emitting something it does not emit today.

One detector change did come out of this, and it came from a confounder rather
than from design. A retry of a failed call produces a novel `X -> X` transition
into a consequential destination, so CH01's dilution-resistant count trigger
fired on 8 of 32 `benign_hard_reapproved_retry` sessions — the most ordinary
thing a governed agent does. Same tool, same argument digest, previous attempt
unsuccessful is now not a novel route, which took CH01 from 77.8% to 81.1% alert
precision and cannot launder an attack: the failed first copy sits at the end of
the same novel transition and is still counted.

---

## 7. What P1 is worth, honestly

The fourth review holds this project at 3.5/10 largely on this item. Completing
all three stages does not make the telemetry trustworthy. It makes the following
statements true — **against a stream that carries the evidence**, which is the
clause that does all the work and which no deployment satisfies by default:

- deleting an event from a signed stream is **detectable**, not merely
  occasionally unlucky;
- modifying a record in transit is **detectable**;
- a `success` with no receipt is **stated**, and a `failure` contradicted by a
  receipt is **detected**;
- a continuation past a blocking control with no bound approval can be called a
  **bypass** rather than a coincidence;
- and every one of those, when the evidence is absent, is reported as absent
  rather than passed over.

An attacker who holds the collector's signing key, or who compromises the
collector process, defeats all of it. That attacker is strictly more expensive
than today's, which requires only that the agent emit whatever it likes. Raising
the price is what a control at this layer can do; anything stronger has to come
from outside the agent, and that is [E13](../EVASION.md) and stays open.

And the price is only raised where the collector sits outside the agent's blast
radius. Where the adapter runs in-process — which is how observra is most often
deployed — the agent can reach the signing key, and a perfectly verified chain
is a perfectly verified chain of whatever the agent chose to say. CH06's
coverage contract states that as an assumption on every session it evaluates,
rather than letting a green tick imply otherwise.
