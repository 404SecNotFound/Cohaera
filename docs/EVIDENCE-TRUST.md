<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Evidence trust: design and implementation for P1

**Status: built.** This document was written as a design, before any of it
existed, because the mistake this project is most exposed to is shipping a field
that looks like a control. When it was written the capability manifest had no
`signature` field, for exactly that reason: nothing would have verified one, and
a signature nobody checks is worse than no signature. Stage 4 built the thing
that verifies it, so §2b is the field, arriving after the verifier rather than
before it.

It is kept as written, with the implementation notes folded in, so that the
difference between what was planned and what was built is readable rather than
tidied away. Seven things changed on contact with the code and each is marked
**BUILT** or **CHANGED** at the point it applies:

| Where | Change | Why |
|---|---|---|
| §2 chain | `chain[n] = H(chain[n-1] ‖ H(canonical(record)))` — the record is folded in through its own digest | A verifier meeting an out-of-order stream has to hold every record it cannot yet chain. Holding 32 bytes per pending record instead of the record makes the reorder buffer a fixed cost rather than one the producer chooses |
| §2 | Two codes added: `INTEGRITY_EVIDENCE_PARTIAL` and `INTEGRITY_RECORDS_REORDERED` | The first closes the obvious way round a chain — strip the sidecar from the record you edited (EVASION.md E21). The second distinguishes the conclusion the verifier reached, which the design said it must and did not give a code for |
| §4 | Enforcement may also be declared in the **capability manifest**, and the manifest wins | The design read `enforcement` off the event only. That field suppresses a finding and arrives in band, so an agent that wanted CH04 quiet would send it. EVASION.md E20 |
| §4 | CH04's blocking case is a **new check ID**, not a rewording of the old one | Renaming `CH04_guardrail_bypass_completed` would silently change what every existing Sigma rule matches |
| §2 keys | The key file became a **trust store** with roles, windows and revocation (§2a), and the two policy files got signatures of their own (§2b) | "Rotation, revocation and multi-collector fleets need more than a file" was written here three times as a known gap. It was also what `capabilities.py` said manifest signing was blocked on, so the two were one piece of work |
| §2 | A **freshness bound** (§2c), because every check in §2 passes on a replayed stream | A captured stream re-fed next month has a contiguous sequence, an intact chain and valid signatures — it really was written by that collector. Replay is a different attack from tampering and nothing here saw it |
| §2 | A **seen-stream ledger** (§2d), the first state Cohaera has ever kept between runs | A freshness bound can only ask how *old* a stream is, so a stream replayed an hour after it was scored passes it — correctly, and unavoidably. Answering *have I seen this before* needs memory, and nothing else in this design has any |

Implementation is in [`src/cohaera/evidence.py`](../src/cohaera/evidence.py) and
[`src/cohaera/ed25519.py`](../src/cohaera/ed25519.py); the reference producers are
[`tools/collector_sign.py`](../tools/collector_sign.py) (telemetry) and
[`tools/policy_sign.py`](../tools/policy_sign.py) (manifest and baseline); the
tests are [`tests/test_evidence.py`](../tests/test_evidence.py). What it measured
is §8, and §9 is what stage 4 is still not.

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

### How far the attestation reached

A signature covers the **chain head at its own sequence**, which is what lets
one verified signature stand for every record before it — and is why
`sign_every` exists at all. The corollary went unwritten until R-05: it stands
for nothing *after* it. A collector signing every hundredth record of a
150-record batch leaves 49 records chained and attested by nobody.

`evidence_status` used to answer this with `signatures_verified > 0` and return
`verified`, which is a fact about whether signing happened rather than about
what it covered. That fixture reported `verified` at CH06 confidence **1.0**.
The state is now split:

| value | condition |
|---|---|
| `verified_complete` | a verified signature reaches the last record of **every** stream feeding the session |
| `verified_prefix` | signatures verified and stop short; `signature_ranges` carries where |

Every stream, not most — a session assembled from two streams is only as
attested as its weaker half, and averaging would report the better one. The
verdict carries `signature_ranges` (`stream_id`, `first_seq`, `last_seq`,
`verified_to`) rather than a boolean, because *"signed to 100 of 149"* is the
finding and an analyst asked to trust a session needs to see where the
attestation stopped. CH06's confidence is multiplied by the record-weighted
share actually reached, and the contract carries
`INTEGRITY_SIGNATURE_COVERS_PREFIX_ONLY`.

Two changes on the producer side follow from the same sentence. The reference
signer now **always signs the final record** — one extra scalar multiplication
per stream, and without it `verified_complete` is unreachable for any sampled
stream whose batch does not happen to end on a signing position. And
`sign_every` must be an integer ≥ 1: `0` used to emit a stream with no signature
on any record and report success, because `if sign_every and seq % sign_every`
short-circuits before the modulo could raise, and `-1` signed everything since
`seq % -1 == 0` always. An operator tuning a sampling rate must not be able to
switch signing off by typing a number.

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

**BUILT, as `cohaera.trust_store:1`.** The flat map of key id to bytes became a
document where a key carries four more things, and each one is a deployment
rather than a hypothetical: `roles` (a collector key attests telemetry, an
operator key attests policy, and one key doing both hands the watched thing
authority over the rules), `not_before`/`not_after` (rotation), `revoked_at`
(compromise), and `replaces` (succession, so an auditor can reconstruct a
rotation rather than infer it). `cohaera.collector_keys:1` still loads, as
collector-role keys with no window, because deployments wrote one.

Two decisions in there are worth arguing with, so §2a states them rather than
leaving them in a docstring. What it is still **not** is enumerated on
`TrustStore` and repeated in §9: no online revocation check, no key
transparency, no quorum, no hardware binding, no automatic anything.

---

## 2a. What a validity window is judged against, and why revocation is not

A window check needs a clock, and the only clock available offline is the one
written on the record — which is producer-controlled, and this codebase treats
producer-controlled fields as claims rather than facts everywhere else. So the
window check has to justify itself.

It is sound, and only in one position. The chain covers the record including its
timestamp; the signature covers the chain; and the window is evaluated **only
after that signature verifies**. The key vouches for the timestamp, and a key
that is not compromised does not lie about when it signed. `_check_signature`
enforces the ordering and `tests/test_evidence.py` asserts it: a record with a
broken signature *and* a timestamp outside the window reports the signature,
because the clock underneath a bad signature is a number the producer chose.

Revocation breaks exactly that premise, and so it is treated differently.
Revoking a key is the operator stating that somebody else holds it, so a
signature made by that somebody proves nothing about the timestamp underneath —
they would simply write a date inside the window. Revocation is therefore **not
evaluated against any clock**: a key with `revoked_at` set is refused for every
record, whatever the record claims.

The cost is real and is not hidden. An archive legitimately signed last month by
a key revoked yesterday can no longer be verified, because separating it from a
forgery needs a trusted timestamp and Cohaera has none. An operator who means
*this key was good until Tuesday* is describing rotation and should write
`not_after`, which **is** judged against the record.

The same three-step ordering — store first, signature second, clock last —
governs `cohaera.policy_signature:1`, where the attested clock is the `signed_at`
inside the signature rather than a timestamp on a record.

---

## 2b. P1.4 — Signing the two files that decide how records are read

**Threat closed:** editing the capability manifest or the baseline.
**Threat not closed:** an operator who signs the wrong file, and anyone who
controls what goes *into* the baseline before it is signed.

P1.1 signed the stream and left both files that decide how the stream is *read*
unsigned, which is the wrong way round for at least one of them:

| File | What editing it buys | Catalogued as |
|---|---|---|
| capability manifest | An egress tool declared `read_only`. CH02, CH03 and CH04 all go quiet on it, and not one telemetry record changed | SEC-03's cousin |
| baseline | CH01 is the only detector here that **learns**. Add sessions to the baseline and it learns that the attack is normal | [E03](../EVASION.md) |

```json
{
  "scheme":      "cohaera.policy_signature:1",
  "artifact":    "capability_manifest",
  "file_sha256": "7c9e2b…",
  "signed_at":   1785700000,
  "key_id":      "ed25519:4f1a…",
  "sig":         "base64(Ed25519 over scheme ‖ artifact ‖ file_sha256 ‖ signed_at)"
}
```

Detached, over the file's exact bytes, for the same reason `capabilities.py`
keeps *both* digests: a signature over parsed semantics verifies happily after an
edit that adds a field this version does not read, and *did this file change at
all* is what a tamper signal has to answer strictly. Detached also leaves the
manifest a plain JSON document every other tool can read.

Domain separated twice. The scheme prefix stops a policy signature being
presented as a `cohaera.integrity:1` signature or the reverse; the artifact tag
stops a signature over a baseline being presented as cover for a swapped
manifest. The tag is *inside* the signed message as well as beside it, so
relabelling the `.sig` file breaks the signature rather than the comparison.

`--tool-manifest-sig` and `--baseline-sig` verify it. A supplied signature that
fails is a **refusal to score**, not a warning, because an operator who passed
the flag asked for the file to be checked. `--require-signed-policy` turns the
option into a control: refuse to run unless every supplied policy file carries a
signature that held. Off by default, because on by default would break every
existing deployment on the day it shipped.

### One resolution per artefact

A signature is over *bytes*, and a path is not bytes. Until R-07 Cohaera
resolved each of these files twice — `CapabilityManifest.from_file` opened the
path and parsed it, then the CLI opened the same path again to hash it for the
signature; the baseline was hashed by path and then reopened by `load`. An
atomic rename in the window between the two reads left Cohaera **scoring one
file and attesting the digest of another**, with the signature holding, because
it was checked against whichever bytes the second read happened to find. The
verdict then carried a `POLICY_SIGNATURE_VERIFIED` attestation for a file that
had not been used — which is worse than no attestation at all, because it is an
assurance pointing at the wrong thing.

Each artefact is now resolved once, and the two files are handled differently
because they are different sizes:

- **The manifest** is small and already read whole under `max_manifest_bytes`.
  `CapabilityManifest.from_bytes` parses and digests one buffer, `from_file` is a
  thin bounded read in front of it, and the manifest carries the full SHA-256 of
  the bytes it was parsed from. Nothing downstream touches the path again.
- **The baseline** is telemetry and may be large, so it is *not* read into
  memory — that would give up the bounded-memory property `_bounded_lines`
  exists to hold. Instead the descriptor is opened once, hashed by streaming,
  rewound and handed to the reader. An open descriptor keeps its inode whatever
  happens to the path, which closes the same window without the copy. The CLI
  owns that descriptor for the run so every early return still releases it.

The baseline is hashed only when `--baseline-sig` was supplied. Without a
signature there is nothing for a second read to disagree with, and hashing
unconditionally would turn an oversize baseline — which the reader's own budget
handles by stopping early — into a refusal.

---

## 2c. P1.5 — Freshness, and the replay every other check is blind to

**Threat closed:** re-feeding a captured stream from outside the bound.
**Threat not closed:** re-feeding one from inside it.

`INTEGRITY_SEQUENCE_REPLAY` catches a record replayed inside one run, because its
sequence position is already filled. It says nothing about the other replay:
capture a signed stream, keep it, and re-feed the whole thing next month. Every
check in §2 passes on that input — contiguous sequence, intact chain, valid
signatures — and they pass *because the stream really was written by that
collector*. It is just not this month's stream. That is what makes replay a
different attack from tampering.

The anchor is the same one §2a justifies: a replayer can re-send the bytes and
cannot re-date them, so `--evidence-max-age` ages records **whose signature
verified**, measured from `--evidence-as-of` (defaulting to the wall clock).
A chained-but-unsigned record's timestamp is a number the producer chose, and
aging it would be aging the attacker's own claim, so a session with no verified
signature reports `INTEGRITY_FRESHNESS_UNVERIFIABLE` rather than *fresh*.

Off by default, and coverage says `NO_FRESHNESS_BOUND` when it is off, because
the honest default is unknowable: an hour is right for a live tail and wrong for
a nightly batch, and a bound guessed wrong turns every scheduled run critical.

### The other end of the window

A freshness bound is one-sided by construction: it asks how OLD a record is.
Until R-13 a record dated *after* `--evidence-as-of` returned "not stale" and
nothing else — which was the right answer to the wrong question, and the code
said so in a docstring that called clock skew "somebody else's finding" while
nobody else made it. A collector whose clock is wrong, or one an attacker holds,
bought itself unlimited freshness by adding to a number.

A signed record dated more than `--max-future-skew` seconds past `as_of` is now
`INTEGRITY_EVIDENCE_FROM_FUTURE`, and it is **inadmissible**, not a warning. The
severity follows from what freshness *is*: the entire argument for trusting the
timestamp is that it is covered by the chain, the chain by the signature, and a
replayer holds neither key — they can re-send the bytes and cannot re-date them.
A record dated after the instant it was scored breaks that argument at the root.
Whatever produced it was not reading the same clock as the rest of the evidence,
so every age computed against it is a guess, including the ones that came back
clean.

It is a separate reason code from `INTEGRITY_EVIDENCE_STALE` because the two
have different remedies — one is "you are re-feeding an archive", the other is
"fix NTP on the collector, or find out why it thinks it is next year" — and a
shared code makes both unguessable.

The default tolerance is 300 seconds, which is what Kerberos has used for
decades for the same purpose: it absorbs ordinary NTP disagreement between two
hosts and nothing more. Zero would make every slightly-fast collector
inadmissible, which is a time-synchronisation problem delivered as a tampering
alert; an hour would let a wrong clock buy an hour of unearned freshness. Like
the window itself, it only applies to signature-verified records, and it answers
`None` rather than `False` when freshness is off — not checked is not "checked
and fine".

`--evidence-as-of` takes a **finite** float. It used to be `type=float`, and
`float("nan")` succeeds, so `--evidence-as-of nan` silently switched the whole
freshness bound off: every comparison against a NaN is false, `enabled` went
false, the "freshness bound" line never printed, and the run exited zero having
skipped the one check the operator had gone out of their way to ask for. An
argument value must never be able to turn a control off quietly — the same
argument C4-05 made for `positive_int`. `--max-future-skew` is validated the
same way, and `Limits` refuses a non-finite or negative value directly, because
the CLI is only one of the doors into it.

**This lowers CH06's coverage confidence on every existing deployment, and that
is the intended reading.** A session with integrity evidence and no freshness
bound now reports `degraded` rather than `evaluated`, because replay was not
considered. Nothing about those sessions changed; what changed is that the
verdict stopped implying a question had been asked. That is the same move
`NO_INTEGRITY_EVIDENCE` and the CH01 vocabulary contract make, and it is why the
number an operator sees goes down after a commit that added a control.

---

## 2d. P1.6 — The observation ledger, and replay inside the window

**Threat closed:** re-feeding a stream this host has already scored, at any age.
**Threat not closed:** re-feeding it to a *different* Cohaera host, or deleting
the ledger first.

A freshness bound can only ask how OLD a stream is. Replay it an hour after it
was scored and the answer is "an hour", which is inside any sane window — so
§2c passes it, correctly, and cannot do otherwise. The two inputs are identical.

Answering *have I seen this before* needs memory between runs, which is the one
thing Cohaera has never had. `--seen-streams` is that memory, and it is
deliberately small:

```json
{
  "scheme": "cohaera.stream_ledger:1",
  "digest": "<sha256 of the streams object>",
  "streams": {
    "collector-01": {"first_seq": 0, "last_seq": 812,
                     "head": "<chain head at 812>", "runs": 3,
                     "last_run_id": "…", "last_seen_at": 1786000000.0,
                     "key_ids": ["ed25519:…"]}
  }
}
```

**Why it stores a chain head and not just a sequence number.** A collector
restart and a replay both re-send seq 0, and conflating them would make every
restart a critical finding. The chain separates them, because a replay re-sends
the *same* records and rebuilds the *same* chain, while a restart writes new
records over the same positions:

| At a shared sequence | Meaning | Code |
|---|---|---|
| head matches | the same records, fed twice | `INTEGRITY_STREAM_REPLAYED` |
| head differs | two mutually exclusive versions, both signed | `INTEGRITY_STREAM_FORKED` |
| never reached | this run ended before the recorded position | reported as `not_reached` |

The fork is the more serious of the two and is not a replay at all: it means
somebody holding a valid collector key produced a second version of the same
history. No check inside a single run can see that, because each version is
internally perfect.

### What earns a stream a place in the ledger

This file is worth exactly as much as the weakest thing allowed to write to it,
and until R-03 anything with a sequence number could. `record` was called for
every stream that had a first and a last sequence, with no requirement that any
of it verified. Three ways that poisoned the file it exists to protect, all
reproduced against the code:

1. **Unsigned admission.** Under a *loaded* trust store, a chained-but-unsigned
   stream was recorded with its head. Chaining is arithmetic — nothing signs it
   and nothing needs to — so anyone who can append to the input can produce one.
   The genuine signed stream then arrived at the same positions with a different
   head and read as `forked`. Squatting a stream id turned into a critical
   finding *against the real collector*, and the real collector was the one that
   looked like the rewrite.
2. **Unscored admission.** Assembly drops events past `max_sessions` and
   `max_events_per_session`, and the verifier had already recorded their
   positions — correctly, since a dropped record still occupies one and omitting
   it would manufacture a gap out of Cohaera's own budget. Committing that
   extent was the error: with `--max-sessions 1` over two sessions the ledger
   advanced across all six records, so the three belonging to the session nobody
   scored were marked as already seen and can now never be scored at all.
3. **Evidence that did not hold.** A broken chain, an invalid signature, a
   revoked or unauthorised key, a stale or future-dated record — none of it
   stopped the position being committed as a scored fact.

A stream is now written to the ledger only if every record it carried reached a
scored session, none of its own evidence was inadmissible, and — **when a trust
store is loaded** — at least one of its records carried a signature that store
accepts. The refusal is reported as `STREAM_LEDGER_NOT_ADVANCED` and named in
`stream_ledger_refusals`, because a stream absent from the ledger looks exactly
like one never seen.

The trust store is the switch on the first rule and that placement is
deliberate. An operator who has loaded no keys has told Cohaera nothing about
who may attest, so requiring a verified signature would turn the ledger off for
every unsigned deployment — most of them, today — and the replay it catches is
worth having even on evidence nobody signed. Once keys *are* loaded, an unsigned
record is not evidence, and the ledger is the last place that should treat it as
any. A refused stream is also never created, so it cannot spend
`max_ledger_streams`: a producer minting a stream id per record could otherwise
exhaust the budget with streams it never signed, and eviction is what makes an
earlier stream's replay undetectable.

### Concurrency, and what a file lock is

Two runs sharing one ledger used to discard each other's work. The write was
atomic — mkstemp, fsync, `os.replace` — and the read-modify-write around it was
not, so both loaded, both scored, and the file left behind held one of the two.
A two-process test loses an update on most runs.

Runs now take an exclusive `flock` on a `<ledger>.lock` sidecar and hold it for
the whole run. A sidecar because `os.replace` swaps the inode, so a lock on the
ledger's own descriptor protects a file that is no longer at that name. For the
whole run, not just the write, because locking only the write would stop updates
being lost and would *not* stop the thing the ledger exists to catch — two runs
scoring the same stream would each read the position before the other wrote it,
and neither would see the replay. Runs sharing a ledger serialise; a ledger is a
serialisation point. The wait is bounded and ends in a refusal, because a
scheduled run that never returns is worse than one that fails.

A monotonic `generation` is the backstop for a lock that was not taken or is not
honoured — `flock` is advisory, local, and does not travel over NFS. A save
whose parent generation is not what is on disk is refused rather than merged: a
merge would have to guess which of two disagreeing histories is real, and
guessing wrong writes the wrong reference for every run afterwards. **This is a
single-host file lock, not a distributed transaction.**

### It is an observation ledger, and the name is the claim

It records what Cohaera **observed and scored**. It does not record what any
downstream sink durably received, and it does **not** provide exactly-once
scoring. `cohaera score` writes it *after* emitting verdicts, so a run that dies
mid-emission leaves it unadvanced and re-running re-scores and re-emits —
duplicates are possible. The reverse ordering was tried first and is worse: it
advanced past findings nobody ever saw, so re-running reported a replay and the
findings were simply gone. A duplicate alert is noise an analyst dismisses in
seconds; a missed one is what this project exists to prevent. Neither ordering
is exactly-once, and a version that was would need durable sink acknowledgement
across stdout, files and future SIEM sinks — a design, not a patch, and one that
is worse done badly than not done. It is named for what it does instead.

**Neither outcome advances the ledger.** Recording a replay's extent would move
the reference to exactly where the attacker's copy ends, so re-feeding it again
would read as a continuation; adopting a fork's head would make the rewritten
history the reference every future run is measured against. Nothing legitimate
was scored, so nothing is recorded but the attempt — and the attempt is counted,
so `runs` climbs.

**What it is not, stated because the alternative is an operator assuming a fleet
is covered.** The ledger is unsigned local state and has to be: signing it would
be Cohaera attesting to its own attestations, the thing that keeps signing in
`tools/collector_sign.py` and out of `src/cohaera`. Its `digest` field catches a
truncated or half-written file — a real failure mode, refused rather than
half-trusted — and catches nothing deliberate, because anything that can rewrite
the body can recompute the digest. Deleting the file removes the detection
(EVASION.md E22) and replaying to a second Cohaera host was never in its scope
(E22b). What changed is the price: replay inside the window used to cost an
attacker nothing at all, and now costs write access to the Cohaera host.

A missing ledger is a first run and is not an error. A ledger that exists and
does not parse **is** an error, because scoring everything as new is precisely
what deleting it achieves, and doing that quietly would hide the deletion.

`collector_streams` stays in every verdict regardless — it is what makes a
replay auditable for a deployment running without a ledger, and a SIEM rule over
the field is a place state survives that this process does not control.

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

1. **Binding.** `span_id`, `tool_id` **and** `arg_digest` must all be present on
   the receipt and all three must match the call. Without this a receipt can be
   copied from a legitimate call onto a malicious one, and the mechanism is
   decorative.

   All three, and the word *present* is the load-bearing one. Until R-01 the
   trusted set contained `bound_span_only`, so a receipt that named two of the
   three fields — or, through an empty `binding: {}` object, none of them —
   carried exactly the authority of one bound to the exact call and the exact
   arguments. A failed egress call with an empty binding produced a **critical**
   contradiction resting on a check that had never run. Three outcomes now,
   and they are different facts rather than degrees of one:

   | Outcome | What it means | What it can do |
   |---|---|---|
   | `bound` | all three named and all three matched | may carry the CH07 contradiction |
   | `unbound` / `arg_mismatch` | names a *different* span, tool or digest | `CH07_effect_receipt_does_not_bind` |
   | `bound_span_only` | *declines to name* one of the three | `CH07_effect_receipt_partially_bound`, and never a contradiction |

   The second and third rows are separated on purpose. A receipt that disagrees
   with the call it arrived on is what a copied receipt looks like. A receipt
   that omits a field disagrees with nothing — it constrains nothing — and
   reporting the second as the first would accuse every adapter that has not
   implemented argument digests yet. Absent is not weaker; it is a different
   fact. The partial case is reported only on calls that did **not** report
   success, and the cost of a loose binding is carried in CH07's coverage
   contract as `RECEIPT_BOUND_BY_SPAN_ONLY` rather than as a finding per call.
2. **Presence.** A consequential call reporting `success` and carrying no
   receipt is now a *stated* gap rather than an accepted claim
   (`NO_EFFECT_RECEIPT`). Reported through coverage, not as a finding, because
   in any real deployment most tools will not have receipts for a long time and
   a finding per receiptless call is a pager storm on day one.

   The population that gap is measured against is every call that is
   consequential **or unclassified**, and both halves are load-bearing
   (COH-R12). Measuring it against receipted calls of *any* class let a
   read-only receipt pay for a consequential call that had none, and a session
   whose only egress carried no receipt at all was reported fully covered.
   Measuring it against consequential calls alone is the opposite error:
   `unknown` is not a statement that a call was harmless, it is the absence of
   one, and excluding it made CH07 declare itself blind on sessions where it
   had just produced a finding. `read_only` is excluded because it is a
   positive classification.
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

1. **Subject binding.** The approval must name this `span_id`, this `tool_id`
   *and* match the call's `arg_digest`. This is the whole mechanism: an approval
   for `send_email` to `alice@example.com` must not cover `send_email` to
   `attacker@example.net`.

   The same completeness rule as receipts, and it was the same defect (R-10). A
   subject naming the span and the tool but not the digest used to *cover* the
   call, which meant one field the producer could omit switched CH04 off for it
   entirely — the check reported nothing at all rather than reporting a bypass
   approved on weaker evidence than the schema was built to carry. An
   incompletely bound approval is now the state `approval_not_argument_bound`:
   it is still reported, because "an approval was presented and did not
   constrain this call" is a stronger statement than "no approval was
   presented", but it suppresses nothing. It also no longer overrides an
   **advisory** control the way an exactly-bound `deny` does — a refusal that
   does not say what it refused cannot outrank the control's own semantics.
2. **Freshness.** `granted_at ≤ call.started_at ≤ expires_at`. An expired
   approval is not an approval.
3. **Dangling approvals.** An approval whose subject matches no call in the
   session is reported — it is either a bug in the emitter or an approval
   harvested for reuse.
3a. **Origin, and what `approved` in a verdict actually asserts.** Every
   approval Cohaera can parse today arrives **in band**, on the same event
   stream the agent produces. So an approved continuation is an approval
   *claim* — the producer's assertion that a decision was made — and not an
   authorization fact Cohaera established. `granted_by` is a string the producer
   chose. The verdict carries `approval_origin` (`in_band`) on the approval and
   `approval_origins` on the CH04 finding so an analyst can see which, without
   having to know this paragraph. `policy_engine` is defined and emitted by
   nothing: an out-of-band attested decision is a path that does not exist yet,
   and it is named for the same reason the unemitted surfaces in `checks.py`
   are — so an operator can ask whether any of their approvals arrive that way
   rather than discovering after an incident that none of them do.
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
| **2** | Collector chain and signatures, CH06, `--collector-keys` | Collector (observra) | **BUILT.** Key *distribution* was a flat file; stage 4 replaced it |
| **3** | Effect receipts, CH07 contradiction detection | Every tool adapter, incrementally | **BUILT.** The slow part is unchanged: every integration, one at a time |
| **4** | Trust store (§2/§2a), signed manifest and baseline (§2b), freshness (§2c) | Operator | **BUILT.** §9 lists what the store still is not |

Stage 0 was deliberately the largest commitment and the smallest change: the
promise that the fields mean something, made before anyone emits them. Nothing
in stages 1 to 3 required a producer to change in order for Cohaera to keep
working — a stream carrying none of these three schemas scores exactly as it did
before, and says `NO_INTEGRITY_EVIDENCE`, `NO_APPROVAL_EVIDENCE` and
`NO_EFFECT_RECEIPT` instead of quietly reporting that it looked.

Key distribution was the one thing outstanding from this document, and stage 4
closed it as far as an offline verifier can. `--trust-store` reads a
`cohaera.trust_store:1` document: which keys, authorised for what, valid when,
revoked or not. That is enough to sign the manifest and the baseline, which is
what `capabilities.py` said signing was blocked on.

It is still a file the operator names, which is still the capability manifest's
trust model. Section 9 says what that leaves open, and it is a list rather than a
sentence because the gap between this and a trust store somebody runs a fleet on
is exactly the sort of thing a green tick hides.

Stage 5 added the seen-stream ledger (§2d) and closed the last item this document
listed as open — replay *inside* the freshness window. It is also the first state
Cohaera keeps between runs, which is a genuinely new kind of thing for it to
have, and §2d is explicit about what that state cannot do: it is unsigned by
necessity, it is per-host, and deleting it is the whole of EVASION.md E22. What
moved is the price of a replay, from nothing at all to write access on the
Cohaera host.

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

| | before P1 | after P1 (1632-session corpus) |
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

### Stage 4, and why its headline numbers are not comparable to the above

The trust-store kinds grew the corpus from 1632 sessions per vocabulary to 1824,
so the split changed and the test population changed with it. The headline
false-positive rate reads **42.0%** on the new corpus against 44.3% on the old
one, and **that difference is not a result**. It is two numbers measured on
different populations, put next to each other. Anyone quoting it as a 2.3-point
improvement is quoting arithmetic.

What *is* attributable to stage 4 is one row and one non-row:

| | after stage 4 |
|---|---|
| `benign_hard_rotated_key` false positives | **0 of 72** |
| `attack_revoked_key_stream` recall | **100%** |

And the order those go in matters. The recall row is close to a tautology: the
verifier reads a `key_id`, looks it up in a file the operator wrote, and finds
`revoked_at` set. Nothing there could plausibly have failed. The benign row is
the one that could have — a rotation is the most routine thing a key-using
deployment ever does, one session per vocabulary has records on both sides of
the handover signed by two different keys, and a verifier that called that
tampering would teach operators to rotate less often. That is a security control
making security worse, and 0 of 72 is the statement that it does not happen here.

Nothing in stage 4 improved a detector, and the card says so in §3b rather than
letting the corpus growth read as progress.

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

---

## 9. What the trust store is not

Stage 4 replaced a flat key file with something that can express rotation and
revocation. It did not build a PKI, and the difference matters most to whoever
reads a verdict and concludes that the keys were fine.

- **No online status check.** No OCSP, no CRL fetch, no directory lookup, because
  Cohaera is offline by construction. A key revoked five minutes ago is revoked
  here only once somebody edits the file and re-runs.
- **No key transparency.** Nothing proves the store you loaded is the store your
  organisation published. Two hosts can hold different files and both produce
  confident verdicts. The pair of digests in provenance makes that *detectable*
  by comparing verdicts after the fact; it does not prevent it.
- **No quorum, no threshold.** One signature is the whole decision, so one
  compromised key is a full compromise of whatever it was authorised for.
- **No hardware binding.** Nothing establishes that a private key lives in an HSM
  rather than in a file beside the collector — and where the collector runs
  in-process with the agent, the agent can read it, which is the deployment §2
  says gains nothing from any of this.
- **No automatic rotation.** `not_after` and `replaces` let an operator *describe*
  a rotation they performed. Nothing performs one. The store does report the
  failure that actually happens — a key superseded by a live one and left with no
  `not_after` and no `revoked_at`, so the rotation exists in the file and not in
  the verifier — as `TRUST_STORE_SUPERSEDED_KEY_STILL_OPEN`.
- **No trusted clock.** Everything time-dependent here rests on a timestamp some
  key signed. §2a is the argument for why that is admissible for windows and
  freshness and inadmissible for revocation; there is no fourth option in which
  Cohaera knows what time it is in a way an attacker cannot influence.
- **Signing the baseline is not the same as trusting it.** A signature proves the
  file was not edited after the operator signed it. It says nothing about what
  went into it, so E03's other half — poisoning the sessions *before* the
  baseline is assembled — is untouched and stays open.
