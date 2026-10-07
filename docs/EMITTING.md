<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Emitting telemetry Cohaera can verify

This guide takes you from "I have an agent that logs tool calls" to a verdict
that says `verified_complete`. It is written for whoever owns the collector,
the gateway or the runtime that already has the records in hand, and it
assumes nothing about Cohaera beyond what is on this page. Every command and
every piece of output below was run as written; where the output contains a
key id or a digest, yours will differ.

What you are adding is the producer half of
[EVIDENCE-TRUST.md](EVIDENCE-TRUST.md). Cohaera has verified signed, chained
telemetry since stage 2 of that design, and until now the only thing that
emitted it was a reference script in `tools/`. `cohaera.emit` is the library
form: a signer that works one record at a time, survives a restart, and reuses
the verifier's own primitives so the two halves cannot disagree about a byte.

## 1. The record Cohaera needs

Cohaera reads JSON Lines: one JSON object per line, UTF-8, `\n` terminated.
The schema firewall in `src/cohaera/validate.py` decides what each field may
be, and its rule is the one to keep in mind while you write the producer: a
malformed field is treated as **absent and flagged**, never coerced. A
`timestamp` of `"yesterday"` does not become zero; it becomes "no clock" plus
a defect code, and every check that needed the clock lowers its own
confidence. So the fields below are optional in the sense that a record
without them is still accepted. They are not optional if you want the checks
that read them to run.

| Field | Type | What it does |
|---|---|---|
| `event_type` | string | Which kind of record this is. `tool_start` opens a call; `tool_end` and `tool_error` close it, and the **event type** is what decides success or failure (`src/cohaera/model.py`, `_build_calls`). `model_response` carries the final text CH02 reads. `cost_threshold_exceeded` and `depth_exceeded` are the policy events CH04 reads, and where an approval travels. |
| `session_id` | string | The correlation key. Records with the same `session_id` form one session. Without it Cohaera falls back to `trace_id`, then to the identity fields, then to isolating the record; see `src/cohaera/identity.py`. |
| `trace_id` | string | Optional second correlation key. |
| `span_id` | string | Pairs a `tool_start` with its terminal event. A terminal event that names a span is matched strictly to that span and never to a different call by name; one that names no span is matched to the oldest open call with the same `tool_name`. Give every call a span. |
| `tool_name` | string | The tool, on tool events. A missing or malformed name is recorded as `<unnamed>`, which classifies as unknown rather than as read-only. |
| `timestamp` | number | Seconds since the epoch, finite and greater than zero. A numeric string is accepted; `0`, a negative number, `NaN` and `Infinity` are not. |
| `host`, `user`, `agent_name`, `framework` | string | Optional identity. They appear in the verdict and support correlation when `session_id` is absent. |
| `data` | object | The bag the fields below live in. A `data` that is not an object is a defect and is read as empty. |
| `data.tool_args` | any JSON | The call's arguments on `tool_start`. Cohaera hashes them with `cohaera.evidence.arg_digest` and that digest is what approvals and receipts bind to. Without it a call cannot be bound to anything. |
| `data.arg_digest` | string | Optional declared digest, `sha256:` plus 64 hex. If both this and `tool_args` are present they must agree; a disagreement makes the call unbindable (F-01). |
| `data.reversible` | boolean | Optional producer claim. A real boolean; the string `"false"` is a defect. The capability manifest, when supplied, outranks it. |
| `data.result` | string | Informational. `"success"` or `"failure"` is what observra writes; Cohaera derives the outcome from the event type, not from this. |
| `data.tool_result` | any | Optional. Its presence is counted (`tool_results_captured`); its content is not read. |
| `data.response_text` | string | On `model_response`. Read by CH02, truncated at the configured bound with a defect code. |
| `data.action` | string | Informational (`invoke_tool`, `policy_event`). Carried into the verdict for policy events, not used to pair calls. |
| `data.effect_receipt` | object | A `cohaera.receipt:1`, on the terminal event. Section 7. |
| `data.approval` | object | A `cohaera.approval:1`, on the policy event. Section 7. |
| `integrity` | object | The `cohaera.integrity:1` sidecar, top level. **Never write this yourself.** The signer adds it, and a record that already carries one is refused. |

The smallest record that pairs into a tool call is a `tool_start` and a
`tool_end` sharing `session_id`, `span_id`, `tool_name` and carrying a
`timestamp`. Everything else widens what the checks can say.

## 2. Sign it: the library

Install Cohaera (it has no runtime dependencies) and run this. It is the whole
producer side; the file it writes is what section 4 scores.

```python
import json
import time

from cohaera.emit import JsonlWriter, KeyPair, StreamSigner, trust_store_document

pair = KeyPair.generate()                      # do this once; keep pair.seed secret
with open("trust-store.json", "w") as fh:      # the public half, for the verifier
    json.dump(trust_store_document({pair.key_id: pair.trust_store_entry(roles=["collector"])}), fh)

signer = StreamSigner("collector-01", pair.seed, pair.key_id)
with JsonlWriter("signed.jsonl") as out:
    for i, tool in enumerate(["search_tickets", "draft_reply"]):
        call = {"session_id": "s-1", "span_id": f"sp-{i}", "tool_name": tool}
        out.write(signer.sign({**call, "event_type": "tool_start", "timestamp": time.time(),
                               "data": {"tool_args": {"ticket": 4842}}}))
        out.write(signer.sign({**call, "event_type": "tool_end", "timestamp": time.time()}))
```

`cohaera score signed.jsonl --trust-store trust-store.json` over that output
reports `verified_complete`. Three things about what just happened:

- **`sign` returns a copy.** Your dict is never written to. The copy is shallow,
  and the chain was computed over the nested values as they were at that
  moment, so write what `sign` returns and write it promptly. Mutating a
  nested value between signing and writing breaks your own chain.
- **`sign` refuses what the verifier would quarantine**: a record that is not a
  dict, one that already has an `integrity` field, a `NaN`, a `set`, a
  non-string key, an object that is not JSON. The chain is over the canonical
  form, which coerces those; the bytes a writer stores are something else; and
  the signature would then cover a record nobody kept. The refusal says which
  field, and it does not consume a sequence number.
- **One key per stream, one stream per collector instance.** The chain seed is
  `H(scheme || stream_id || key_id)`, so a stream cannot change key without
  becoming a new stream. Rotate by starting a new `stream_id` under the new
  key and recording the succession in the trust store (section 3).

The same thing from a shell, with the key in a file:

```bash
python -m cohaera.emit keygen --out collector.key --roles collector --trust-store trust-store.json
python -m cohaera.emit sign --key collector.key --stream-id collector-01 --in raw.jsonl --out signed.jsonl
```

`keygen` creates the key file with mode `0600` and refuses to overwrite one.
`sign` refuses a key file that is readable by anyone else: a private key
somebody else can read is a key somebody else may hold.

## 3. Distribute the trust store

`trust-store.json` is a `cohaera.trust_store:1` document. It holds public keys
only, so it is not secret, and it is the one thing the verifier needs from
you:

```json
{
  "keys": {
    "ed25519:a5a259a421a81bbb": {
      "key": "...base64 public key...",
      "roles": ["collector"]
    }
  },
  "scheme": "cohaera.trust_store:1"
}
```

Give it to whoever runs `cohaera score`, the way you would give them the
capability manifest: a path on the scoring host, under change control, with
its digest recorded. Cohaera prints the file digest and a semantic digest when
it loads the store and writes both into every verdict's provenance, so two
hosts that disagree about which keys are trusted produce verdicts that can be
told apart after the fact. It does not fetch keys, check revocation online, or
prove the store you loaded is the one your organisation published; section 9
of [EVIDENCE-TRUST.md](EVIDENCE-TRUST.md) lists what a file is not.

**Roles are not a convenience.** `collector` signs telemetry. `approval`
issues approvals. `policy` signs the capability manifest and the baseline. A
key holding two of these is one party doing two jobs, which is the arrangement
the signature exists to rule out: a collector that could sign the manifest
could rewrite the document that says which of its own tools are dangerous.
`keygen --roles` makes you choose, and the verifier refuses a signature from a
key whose roles do not include the thing it signed.

**Rotation.** Generate the new key into the same store, naming its
predecessor, then close the old key's window:

```bash
python -m cohaera.emit keygen --out collector-2.key --roles collector \
    --trust-store trust-store.json --replaces ed25519:a5a259a421a81bbb
```

Then set `"not_after"` on the old entry by hand (epoch seconds). Without it
the verifier warns `TRUST_STORE_SUPERSEDED_KEY_STILL_OPEN`: the rotation
exists in the file and not in the verifier, and the retired key signs valid
records forever. A key you believe compromised gets `"revoked_at"` instead,
which refuses every signature it ever made, dated or not; the two are
different facts and section 2a of EVIDENCE-TRUST.md is the argument.

## 4. The exact sequence that produces `verified_complete`

Run from an empty directory. `batch1.jsonl` and `batch2.jsonl` each hold six
records shaped as in section 1 (three `tool_start`/`tool_end` pairs with
distinct spans); the second batch stands in for a collector that was restarted.

```bash
python -m cohaera.emit keygen --out collector.key --roles collector --trust-store trust-store.json
python -m cohaera.emit sign --key collector.key --stream-id collector-01 \
    --in batch1.jsonl --out signed.jsonl --state collector-01.state
python -m cohaera.emit sign --key collector.key --stream-id collector-01 \
    --in batch2.jsonl --out signed.jsonl --append --state collector-01.state
cohaera score signed.jsonl --trust-store trust-store.json > verdicts.jsonl
python -c "import json; v=[json.loads(l) for l in open('verdicts.jsonl') if l.strip()]; print(v[0]['data']['coverage']['evidence_status'])"
```

Output, as run:

```text
ed25519:a5a259a421a81bbb
[cohaera.emit] wrote private key to collector.key (mode 0600) with roles ['collector']; public half in trust-store.json
[cohaera.emit] signed 6 record(s) as stream 'collector-01' under ed25519:a5a259a421a81bbb; next seq 6, state in collector-01.state
[cohaera.emit] resuming stream 'collector-01' at seq 6
[cohaera.emit] signed 6 record(s) as stream 'collector-01' under ed25519:a5a259a421a81bbb; next seq 12, state in collector-01.state
[cohaera] trust store trust-store.json: 1 key(s) (1 collector, 0 policy), file digest e9991da40b0db4db, semantic digest 3f3d2aa26a57fe39
[cohaera] signed.jsonl: 12 events in 1 sessions, 0 record(s) quarantined

session support-0042  agent=support-agent  tools=6 (ro=6 sc=0 eg=0 ?=0)  cost=$0  coverage=0.246  corr=session_id
   [GAP ] CH01_sequence_order not_evaluated: NO_BENIGN_BASELINE_FITTED
   [GAP ] CH02_concealment_gap not_evaluated: NO_FINAL_RESPONSE_TEXT
   [GAP ] CH03_untrusted_to_consequential not_evaluated: NO_INJECTION_SCANNER_EVIDENCE
   [GAP ] CH04_guardrail_overrun not_evaluated: NO_POLICY_EVIDENCE
   [GAP ] CH06_evidence_integrity degraded: NO_FRESHNESS_BOUND; NO_STREAM_LEDGER
   [GAP ] CH07_effect_contradiction not_evaluated: NO_EFFECT_RECEIPT

[cohaera] 0 finding(s) across 1 session(s); 12 record(s) accepted, 0 quarantined, 0 accepted with field defects
verified_complete
```

`evidence_status` is in the verdict's coverage block
(`data.coverage.evidence_status`), because a session that triggered nothing
still has to say how far its own telemetry was established. The same file
scored without `--trust-store` reports `chained_unsigned` with
`NO_COLLECTOR_KEYS`: the signatures were parsed and nothing verified them. The
raw file, unsigned, reports `unattested` with `NO_INTEGRITY_EVIDENCE`, which is
the state every deployment is in before this guide.

CH06 says `degraded` in the run above, and that is correct: no freshness bound
and no ledger were in force, so a replayed stream would have passed. Adding
`--evidence-max-age 86400 --evidence-as-of <now> --seen-streams seen.json` to
the same command took CH06 to `evaluated` at confidence `1.0` when run here.
Both are the verifier's decision, not the producer's; they are mentioned so
that `degraded` is not read as a fault in the signer.

## 5. Resume after a restart

The verifier anchors a stream at sequence `0` and reports a stream that starts
anywhere else as `INTEGRITY_STREAM_JOINED_MIDSTREAM`: covered from here,
attested before here by nobody. A collector that restarts and begins again at
`0` does worse. With a stream ledger in force the verifier sees the same
positions carrying a different chain head and reports
`INTEGRITY_STREAM_FORKED`, which is the finding for a rewritten history. So a
restarted collector must continue where it stopped, and the signer's state is
what makes that possible:

```python
state = signer.state()      # {"scheme": "cohaera.signer_state:1", "stream_id": ..., "key_id": ..., "next_seq": 12, "head": "..."}
# ... persist it; cohaera.emit.write_state(path, state) does so atomically ...
signer = StreamSigner.resume(state, pair.seed, key_id=pair.key_id)
```

Persist the state after the records it describes have been durably written,
and read it before signing the first record after a restart. The state holds
no secret, so it can sit beside the output. `resume` checks every field and
refuses a state that does not describe a chain, including one written under a
different key, because the alternative to continuing correctly is starting at
zero. The `sign` subcommand does all of this with `--state`, as section 4
shows: the second batch resumed at sequence 6, and fed to the verifier as one
file the twelve records verified with no `JOINED_MIDSTREAM` at all. Fed as a
file on their own, the six resumed records report only `JOINED_MIDSTREAM`,
never a chain break or a gap; `tests/test_emit.py` asserts both.

## 6. Sampling, and the last record

The signature covers the chain head at its own sequence, so one verified
signature attests every record before it. `StreamSigner(..., sign_every=100)`
therefore costs one scalar multiplication per hundred records and the
verifier cannot tell the difference in what it establishes. The corollary is
that a signature attests nothing after it (R-05 in EVIDENCE-TRUST.md): a
sampled stream whose last record fell between signing positions is
`verified_prefix`, never `verified_complete`. An incremental signer cannot know
which record is last, so you say: `signer.sign(record, final=True)` on
shutdown, or on the last record of each batch, which is what the `sign`
subcommand does. With `sign_every=1` the flag changes nothing. `sign_every`
must be an integer of at least 1; `0` and `-1` are refused rather than quietly
switching signing off or on.

## 6a. Closing a stream

A signature says the collector wrote everything up to that record. It does
not say the stream ended there, so a stream cut off after record 6 of 10 is
a verified prefix that nothing can tell from the whole (EVASION.md E30).
Close the stream when the collector stops:

```python
signer.sign(last_record, final=True)
```

The record carries `"final": true` and its signature covers that marker, and
the signer refuses to sign anything further; `state()` records `closed`, so a
restarted collector cannot reopen it either. From the command line, pass
`--close` on the last batch:

```bash
python -m cohaera.emit sign --key collector.key --stream-id collector-01 \
  --state collector-01.state --in batch-3.jsonl --out signed.jsonl --append --close
```

Score with `--require-closed-streams` once every collector closes its
streams. A stream that ends without its terminator is then
`INTEGRITY_STREAM_END_MISSING` and inadmissible. Without the flag, an
unclosed stream degrades CH06 with `INTEGRITY_STREAM_NOT_CLOSED` and nothing
more, because a stream still being fed is open by definition. Use `final`
on shutdown; a batch boundary is `attest=True`, which signs the record
without closing anything.

## 7. Approvals and receipts

Both are built with the same helpers and both run their output back through
the verifier's parser before returning it.

**An approval** is minted by whatever made the decision, with a key that has
the `approval` role and is held by neither the collector nor the agent:

```python
from cohaera.emit import ApprovalIssuer

issuer = ApprovalIssuer(approver.seed, approver.key_id)
approval = issuer.issue("allow", span_id="sp-7", tool_id="wire_transfer_send",
                        tool_args=call_args, expires_at=now + 300,
                        granted_by="user:alice", policy_id="payments-guard")
policy_event["data"]["approval"] = approval
```

It refuses to issue without `expires_at`, because the signing input covers the
expiry and an eternal signed approval must not be mintable; without a digest
or the arguments to compute one, because an approval that does not name the
arguments covers the tool with any arguments; and with a control character in
any identity field. The result reaches the `authenticated` tier under a trust
store holding the key, `single_use` once a `--seen-approvals` ledger is in
force, and rewriting its `span_id` breaks the signature. `python -m
cohaera.emit issue-approval` is the same thing from a shell.

**A receipt** is an identifier the target system returned, bound to the exact
call. The per-provider knowledge of where that identifier lives stays in
`tools/receipt_adapters.py`; `cohaera.emit.receipt` is the primitive that file
produces, with an `assurance` the receipt has to declare
(`provider_returned_operation`, `provider_returned_object`, `client_claimed`)
and an optional `scope`. If the provider returned nothing that identifies the
call, emit no receipt: an identifier the adapter invented is drawn from a
namespace the agent controls, which is the one property that made receipts
worth anything.

## 8. What the signature proves, and what it does not

It proves that the records in a stream were not altered, deleted, reordered or
replayed after the signer saw them, by anyone who does not hold the key, and
it localises which record a tampered stream diverged at. That moves the cost of
a lie from one boolean to a signing key.

It does not prove the agent behaved. A perfectly verified chain of records is
a perfectly verified chain of whatever the signer was given. It does not prove
the collector was honest, since the collector holds the key. And where the
signer runs inside the agent process, the agent can reach the key and the
chain proves nothing at all; CH06's coverage contract states that assumption
on every session it evaluates rather than letting a green tick imply
otherwise. Put the signer in the collector, after normalisation, outside the
agent's blast radius, or expect the verdict to say what you have.

`cohaera.ed25519.sign` is a pure-Python implementation and is not
constant-time. On a shared host with a key that matters, sign with libsodium
and treat `cohaera.emit` as the format reference; the bytes it signs are
defined by `cohaera.evidence.signing_input` and are the same either way.
