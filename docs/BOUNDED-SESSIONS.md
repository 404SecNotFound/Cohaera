<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Bounded sessions: a proposal, not a change

**Status: proposed. Nothing in this document is implemented.**

COH-R02 was closed in two halves and this is the second one. The first half is
shipped: `max_resident_bytes` is a real budget, metered on retained bytes,
enforced per record, and regression-tested against `tracemalloc` so its
amplification factor cannot become folklore. It is also, deliberately, **a
budget rather than an architecture** — it makes the ceiling visible and refuses
to cross it. It does not raise it.

This document is about raising it, and about the reason that is not a
refactor. Cohaera holds an entire run in memory because correlation is a
whole-input property, and the thing standing between it and a streaming design
is not a data structure. It is a question nobody has answered: **when is a
session over?**

That question is a semantics decision. It changes what the corpus measures,
which changes every published number. `CONTRIBUTING.md` says to propose such a
change rather than make it inside another one. This is the proposal.

## What the bound costs today

Derived from `src/cohaera/limits.py`; the numbers are read from the defaults
rather than typed here.

| Quantity | Default |
|---|---|
| `max_resident_bytes` | 2 GiB of assembled state |
| `RESIDENT_BYTES_PER_INPUT_BYTE` | 32 |
| Accepted input before the budget binds | ~64 MiB |
| `max_input_bytes` | 2 GiB (does not bind first) |

Sixty-four megabytes of accepted telemetry per run. That is honest — it is what
holding the whole run in memory costs — and for a collector VM scoring an
hour's traffic it is enough. For a day of a busy fleet it is not, and the
operator's only options today are to shard the input by hand or to raise a
budget they have been told is load-bearing.

The 32× factor is not waste to be optimised away. A parsed record is a dict of
interned-ish strings, plus a frozen copy for immutability (C4-07), plus cached
derived values, and the cost is driven by **key count** rather than payload
length. Shaving it might buy 2×. It does not change the shape of the problem.

## Why this is not just a spool

The mechanical parts are ordinary and are not what makes this hard:

- **Bounded session windows** — evict a session once it can no longer change.
- **A spool** — page cold sessions to disk instead of holding them.
- **External sorting** — `assemble` currently sorts each session's events in
  memory, which is fine per session and not fine across a run.

Every one of those needs to know when a session is *finished*. Cohaera has no
such concept. `Session.seal()` is called by `assemble` when the **input** ends,
not when the session does — which is exactly right for batch scoring and says
nothing at all in a stream.

Worse, the checks are not incremental in the way a naive window assumes:

- **CH02** compares consequential calls against the *final* response. Any rule
  that closes a session early can cut the response off it, and CH02's failure
  mode when it loses the response is to report a blind spot — a *correct* one,
  but a session that would have been evaluated is now not evaluated.
- **CH01** scores a whole tool sequence against a grammar. A truncated sequence
  is a different sequence, and its bigrams are unseen ones.
- **CH03** and **CH04** order calls against a marker or a policy event that may
  arrive arbitrarily later. COH-R11 gave them a three-valued ordering; a window
  boundary adds a fourth case — "the other record may simply not have arrived
  yet" — which is *not* the same as indeterminate and must not be reported as
  it.
- **CH05** exists to find unpaired calls. Every session evicted mid-call
  produces one, so a completion rule that is even slightly wrong manufactures
  CH05 findings at exactly the rate it is wrong.

That last one is the trap. **A bad completion rule does not degrade coverage
quietly; it fabricates findings.** It would be the first change in this project
capable of raising recall by breaking something.

## The candidate rules

### 1. Idle timeout

Close a session after *T* with no events. Simple, and every log pipeline does
it.

- Needs a trusted clock, and the clock is the producer's. E23 in `EVASION.md`
  is already the finding that a producer-chosen timestamp is not evidence; an
  eviction rule keyed on the same field lets a producer split one session into
  two by stalling, which is E12 (fragment `session_id`) reached through a
  different door and for free.
- Arrival-time is a defensible substitute and is not the same quantity. It
  would need to be recorded at ingest, which today it is not.

### 2. Explicit terminal event

Close on `agent_end`, or on `model_response` with no open calls.

- Cheap and correct when it fires; the producer decides whether it ever does.
  An agent that never emits `agent_end` is never evicted, which is the memory
  problem back again with an extra mechanism.
- Cannot stand alone. Needs a timeout behind it, which means it inherits (1).

### 3. Sequence-gap eviction on a signed stream

Close a session when the collector sequence has advanced past it by *N*
records with nothing new for it.

- This is the only rule here whose input a producer cannot forge, because
  inside one `stream_id` the sequence is covered by the hash chain and the
  signature over its head. It is the same property COH-R11 leans on for
  ordering.
- Only available on streams carrying `cohaera.integrity:1`, which is the
  minority of deployments today. It would have to be the *preferred* rule with
  (1) as the fallback, and the verdict would have to say which one applied —
  the two are not equally trustworthy and a coverage contract that hid the
  difference would be the R09 defect again.

### 4. Do not evict; page instead

Keep every session logically open, spool cold ones to disk, and accept that a
run's state is bounded by disk rather than RAM.

- **No semantics change at all**, which is its whole appeal: the checks see
  exactly what they see today and no published number moves.
- Bounded by disk instead of memory, so it raises the ceiling by perhaps two
  orders of magnitude without removing it.
- Costs a serialisation format for a sealed session, and sealing is now load-
  bearing for correctness (COH-R13), so the spool must round-trip the seal
  rather than reconstruct a mutable session from bytes.

## Recommendation

**Do (4) first, and treat (1)–(3) as a separate decision after it.**

Paging buys most of the headroom for none of the semantic risk. It is the only
option on this list that cannot fabricate a CH05 finding, cannot truncate a
CH01 sequence, and cannot move the evaluation card — because the checks still
see whole sessions. It is a memory-management change, which is what the
original finding was about.

Eviction is a different project with a different justification. It is what an
*unbounded* stream needs, and Cohaera does not currently claim to serve one; the
review's Stage 1 OTLP ingestion work is where that claim would first be made,
and the completion rule belongs to it rather than to R02.

## What building (4) requires

1. A round-trippable representation of a **sealed** session, with a test that a
   spooled-and-restored session is `==` to the original *and* still sealed —
   COH-R13 exists because a session that can be reopened is a session whose
   cached verdicts can go stale.
2. A spill policy with its own bound, and the bound stated in the ingest
   summary next to `max_resident_bytes`, because an unbounded spool is the same
   defect one storage layer down.
3. `tracemalloc` regression tests of the same shape as
   `test_the_default_bounds_state_a_memory_ceiling_somebody_can_check`, since
   the whole point is a ceiling somebody can check.
4. A statement of what happens when the *disk* budget is exhausted. Failing
   closed is the precedent (COH-R04); a partial run must not exit 0.

## What building (1)–(3) would require, if it is ever taken up

Everything above, plus:

- A `session_completion` field in the verdict naming the rule that closed it,
  because a session closed by a producer's own timestamp and one closed by a
  signed sequence are different evidence and must not read alike.
- A coverage reason for "this session may be incomplete", charged to CH01,
  CH02, CH03 and CH04, since all four read whole sessions.
- **A corpus change**, and this is the part that makes it a proposal rather
  than a task. Grading a completion rule needs sessions that are genuinely
  incomplete at the input boundary — interleaved, straddling, abandoned — and
  no such kind exists today. Adding one moves prevalence and therefore every
  published number in `eval/EVALUATION-CARD.md`. Per `eval/README.md`, that is
  a decision to take deliberately and in its own change, with before-and-after
  numbers, and not a gap to quietly plug.

## Prior art worth reading first

Streaming systems have solved the completion problem and have been explicit
that it is not solvable exactly: watermarks and allowed-lateness in the Dataflow
model, and the general result that a watermark is a heuristic about
completeness rather than a fact. Cohaera's version of that heuristic has to be
one a *detector* can defend, which is a stricter bar than a metrics pipeline
needs — a late record that drops a value from an average is a rounding error,
and a late record that drops a tool call from a session is a false negative.
