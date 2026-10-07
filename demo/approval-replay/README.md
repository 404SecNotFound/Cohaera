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
> weaknesses of the **default deployment**, with executable proof, catalogued
> as [`EVASION.md` E26](../../EVASION.md). The controls that close them exist
> and are opt-in; the demo runs with them off because that is how every
> deployment starts. A demo that only showed the wins would be a brochure.

---

## The setup

A payments agent may only move money when a human approves the exact transfer.
The approval travels on the telemetry as `cohaera.approval:1` and binds three
things: the call's **span**, the **tool**, and a **digest of the arguments**.

A human approved one payment: **$250 to acct-1188.**

Everything below asks what that single approval is worth afterwards, in a
deployment that has issued no approval keys, keeps no approval ledger, and has
not turned on `--require-signed-approvals`.

## Act 1: the control working

One approval, one transfer, covered. **No finding, and that is correct.** If
this act fired, the demo would open on a false positive and nothing after it
would be readable.

## Act 2: verbatim replay, REFUSED

The same approval, copied unchanged onto a second transfer.

It still names span `AP1`. The second call is `AP2`. The binding is exact, so
the approval does not cover it, and `CH04_blocking_control_bypassed` fires.

**This is a genuine win and it was not designed.** It falls out of R-10 making
all three binding components mandatory: an approval that names the span and
the tool but not the arguments no longer covers anything. Recorded as E26b,
"unplanned win", because a defence nobody planned is worth exactly as much as
one somebody did, and worth being honest about.

## Act 3: one field rewritten, COVERED

Identical to act 2 except that `subject.span_id` now reads `AP2`.

That is the entire attack. One string.

The fixture carries **no issuer signature**, so nothing makes the edit
detectable. The approval now covers a call it was never issued for, and CH04
goes silent. The verdict does record the approval's assurance tier as `bound`
rather than `authenticated`; in the default deployment that tier is reported
and does not gate.

## Act 4: thirty days later, another session, COVERED

The same approval again, in a session this detector has never seen.

No `--seen-approvals` ledger is in use, so nothing remembers the approval was
spent, and the fixture declares **no validity window**: `granted_at` and
`expires_at` are optional on an unsigned approval, and one declaring neither is
never stale.

So it is as good the hundredth time as the first.

---

## Why this is the interesting failure

In the default deployment the approval is a sticky note with a span written on
it. Rewriting the span costs one string, nothing signs it, nothing expires it,
and nothing remembers it was already spent.

**Points 2, 3 and 4 compose.** One field, no expiry, no memory. An attacker who
captures a single legitimate approval has an authorisation for that tool and
those arguments, permanently, in any session.

Note what this does *not* need: no compromise of the collector, no forged
signature, no access to the operator's infrastructure. The approval is plain
JSON on a stream the agent already writes.

## What closes it, and why it is off

Three controls, all built and all opt-in:

| Control | What it does | How it is turned on |
|---|---|---|
| An **issuer signature** over the approval body, covering the span | rewriting the span invalidates the signature | a trust-store key with the `approval` role, and `--require-signed-approvals` so an unsigned approval stops covering |
| A **mandatory validity window** for signed approvals | the signing input covers `expires_at` and requires it, so an issuer cannot sign an eternal approval | automatic once approvals are signed |
| A **nonce the verifier records as spent**, across sessions | the second use of a nonce falls back from `single_use` to `authenticated` and, with the flag on, is refused | `--seen-approvals PATH` |

They are off by default because turning `--require-signed-approvals` on in a
deployment that has issued no approval keys makes every authorised action look
like a bypass. The ledger is a local, unsigned, per-host file, which is E22
again. And there is **no approval-signing helper under `tools/`**: an issuer has
to produce the signature described in
[`docs/EVIDENCE-TRUST.md`](../../docs/EVIDENCE-TRUST.md) §4 itself, so in
practice the default is what a deployment gets today.

Two independent controls in the wild solve the same problem, which is the
strongest available evidence that the naive form works: the Vercel AI SDK's
`experimental_toolApprovalSecret` has the server HMAC-sign each approval at
issuance, binding tool name, call id and input arguments; aiAuthZ
(arXiv:2607.05518, cited by ID and **not read**) binds a per-message HMAC to a
single-use nonce and a timestamp window.

## Files

| | |
|---|---|
| `scenario.py` | builds the four sessions and the manifest, deterministically |
| `telemetry.jsonl` | committed so it can be read without running anything |
| `manifest.json` | the operator's declared tool and control |
| `run.py` | scores all four acts and narrates them |

`tests/test_demo.py` pins every act. Acts 3 and 4 **assert that Cohaera does
not catch something** in the default configuration, which is the opposite of a
normal test and is deliberate. A separate test asserts that the fixture still
carries no signature, no nonce and no window, so the demo keeps showing the gap
rather than the remedy; `tests/test_approval_trust.py` is where the remedy is
proved.
