<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# The approval that never expires

```bash
python demo/approval-replay/run.py
```

About a second. No VMs, no API key, no network. Deterministic.

> **This demo does not end in a catch.** Act 2 is a real win. Acts 3 and 4 are
> open weaknesses with executable proof, catalogued as
> [`EVASION.md` E26](../../EVASION.md). A demo that only showed the wins would
> be a brochure.

---

## The setup

A payments agent may only move money when a human approves the exact transfer.
The approval travels on the telemetry as `cohaera.approval:1` and binds three
things: the call's **span**, the **tool**, and a **digest of the arguments**.

A human approved one payment: **$250 to acct-1188.**

Everything below asks what that single approval is worth afterwards.

## Act 1 — the control working

One approval, one transfer, covered. **No finding, and that is correct.** If
this act fired, the demo would open on a false positive and nothing after it
would be readable.

## Act 2 — verbatim replay → **REFUSED**

The same approval, copied unchanged onto a second transfer.

It still names span `AP1`. The second call is `AP2`. The binding is exact, so
the approval does not cover it, and `CH04_blocking_control_bypassed` fires.

**This is a genuine win and it was not designed.** It falls out of R-10 making
all three binding components mandatory — an approval that names the span and
the tool but not the arguments no longer covers anything. Recorded as E26b,
"unplanned win", because a defence nobody planned is worth exactly as much as
one somebody did, and worth being honest about.

## Act 3 — one field rewritten → **COVERED**

Identical to act 2 except that `subject.span_id` now reads `AP2`.

That is the entire attack. One string.

There is **no signature over the approval body**, so nothing makes the edit
detectable. The approval now covers a call it was never issued for, and CH04
goes silent.

## Act 4 — thirty days later, another session → **COVERED**

The same approval again, in a session this detector has never seen.

There is **no per-approval ledger** — the capability `--seen-streams` gives
`cohaera.integrity:1` and nothing gives approvals. And there is **no mandatory
validity window**: `granted_at` and `expires_at` are optional, and an approval
declaring neither is never stale.

So it is as good the hundredth time as the first.

---

## Why this is the interesting failure

The approval is a sticky note with a span written on it. Rewriting the span
costs one string, nothing signs it, nothing expires it, and nothing remembers
it was already spent.

**Points 2, 3 and 4 compose.** One field, no expiry, no memory. An attacker who
captures a single legitimate approval has an authorisation for that tool and
those arguments, permanently, in any session.

Note what this does *not* need: no compromise of the collector, no forged
signature, no access to the operator's infrastructure. The approval is plain
JSON on a stream the agent already writes.

## What would close it

Three things, none of which exists on this path:

| | |
|---|---|
| An **issuer signature** over the approval body | so rewriting the span invalidates it |
| A **mandatory validity window** | so an approval cannot cover forever |
| A **nonce the verifier records as spent**, across sessions | so the second use is refused |

All three already exist in this repository — for *telemetry*, as
`cohaera.integrity:1`: Ed25519 signatures, a trust store with roles and
rotation, and a seen-stream ledger. **The approval path never got them.**

Two independent controls in the wild solve exactly this, which is the strongest
available evidence that the naive form works: the Vercel AI SDK's
`experimental_toolApprovalSecret` has the server HMAC-sign each approval at
issuance, binding tool name, call id and input arguments; aiAuthZ
(arXiv:2607.05518, cited by ID and **not read**) binds a per-message HMAC to a
single-use nonce and a timestamp window.

## Files

| | |
|---|---|
| `scenario.py` | builds the four sessions and the manifest — deterministic |
| `telemetry.jsonl` | committed so it can be read without running anything |
| `manifest.json` | the operator's declared tool and control |
| `run.py` | scores all four acts and narrates them |

`tests/test_demo.py` pins every act. Acts 3 and 4 **assert that Cohaera does
not catch something**, which is the opposite of a normal test and is
deliberate: those tests fail the day approvals gain a signature, a window or a
nonce — which is exactly when this page needs rewriting rather than patching.
