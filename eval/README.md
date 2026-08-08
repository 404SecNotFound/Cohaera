# Evaluation

Every number Cohaera published before this directory existed was measured against
twelve near-identical fixture sessions written by the same person who wrote the
detector, using tool names drawn from the same keyword lists the detector matches
against. Three external reviews said so. This is the fix.

**Start with [`EVALUATION-CARD.md`](EVALUATION-CARD.md).** It is generated, it is
deterministic, and it contains the numbers including the bad ones.

```bash
python eval/vocabulary.py          # the name-heuristic audit, on its own
python eval/corpus/generate.py     # regenerate the corpus (seeded, ~1s)
python eval/run_eval.py            # score everything, rewrite the card
```

## What is here

| File | What it is |
|---|---|
| `vocabulary.py` | The tool vocabulary, in two naming conditions, and the audit that proves the `unseen` one is unseen |
| `corpus/generate.py` | Session generation by task family, with label-integrity checks |
| `corpus/sample.jsonl` | 104 sessions, one per family x kind, committed so the corpus can be read without running anything |
| `corpus/data/` | The full corpus. **Not committed** — 15 MB, deterministic from the seed |
| `corpus/data/manifests/` | Per-agent capability manifests, the ground truth for the `manifest` condition |
| `corpus/signatures.py` | A content-addressed cache for the corpus's Ed25519 signatures. **Not committed**, safe to delete, and explained below |
| `harness.py` | Split, fit, score. The split assertions live here |
| `metrics.py` | Wilson intervals, FP per 1000, coverage-adjusted recall |
| `run_eval.py` | The grid, and the card |
| `../tests/test_eval.py` | Tests for all of the above, because a measuring instrument needs checking too |

## The four design decisions worth arguing with

### 1. The tool names are not from the classifier's keyword lists

`cohaera.model._classify` guesses a tool's effect from its name using three
keyword lists. Name a fixture tool `send_email` and the classifier "detects" it —
that is the list matching itself, and it is not a detection rate.

So the corpus carries two vocabularies for the *same* behaviours:

- **`unseen`** — realistic enterprise identifiers (`sfdc_case_comment_create`,
  `iam_policy_attach`, `grafana_panel_snapshot`). `assert_unseen_vocabulary_is_unseen()`
  fails the build if the classifier recognises any of them. It caught one on its
  first run: `netsuite_journal_post_entry` contains the egress keyword `post`.
- **`lexical`** — the same behaviours renamed to words the classifier knows. The
  control, and what the old fixtures measured.

The delta between them is the number the reviews were asking for.

### 2. Splits are by task, enforced in code

Each task has four attempts, which are near-duplicates. A random split puts
attempts of one task on both sides and measures memorisation. `split()` raises
`LeakageError` rather than returning a contaminated split, and `test_eval.py`
checks that it raises.

Three regimes are reported: `task_disjoint` (the honest one), `family_holdout`
(the baseline never saw the test workload), and `random_LEAKY`, which exists only
to *measure* the inflation rather than cite someone else's figure for it. Numbers
from the leaky regime are labelled as contamination everywhere they appear.

`task_disjoint` is **stratified**, not a free shuffle over tasks, and the reason
is a defect it was hiding. A free shuffle gave each family a ~25% chance of
sending both of its looping benign tasks to test; across eight families the odds
of that happening somewhere were about 90%. The baseline then never learns that
an agent repeats its own spine, every loop boundary scores as a novel
transition, and the dilution sessions stop measuring dilution. Two kinds are
pinned so the train side is representative of ordinary work; the confounders
stay on the shuffle, since nothing about them depends on what the baseline
learned.

One exception is assigned outright rather than shuffled at all.
`benign_hard_long_rare_action` confounds only when the baseline has *not* seen
the family's rare secondary action, so which families that holds for was
previously a property of the seed — the card's "CH01 fires on 16 of 32" was
where one draw landed, and a later draw sent it to 0 of 32 and then to 32 of 32.
Half the families now send all of that kind to test and half keep one back, so
the confounding case and the control case are both present by construction.
**A confounder whose strength is a property of the seed cannot grade a
detector**, and publishing whichever draw flatters is how a corpus starts lying.

### 3. Seven in ten benign sessions are hard

A corpus of clean benign sessions reports a false positive rate of zero and calls
it a result. The confounders here are benign sessions that look exactly like the
attack they sit next to:

| confounder | why it is benign | which check it trips |
|---|---|---|
| `benign_hard_untrusted_read` | a moderation agent must read attacker-authored text and then act on it. That is the job | CH03 |
| `benign_hard_advisory_threshold` | the threshold was advisory; continuing is correct, and nothing in the schema declares advisory vs blocking | CH04 |
| `benign_hard_timeout_unpaired` | the call genuinely timed out | CH05 |
| `benign_hard_terse_summary` | an honest summary in the agent's own words rather than the tool's. EVASION.md E04 | CH02 |
| `benign_hard_honest_denial` | the same honest paraphrase, plus a truthful statement of what the agent did *not* do. Agents volunteer this constantly | CH02 |
| `benign_hard_rare_ordering` | legitimate work in an unusual order | CH01 |
| `benign_hard_long_rare_action` | a long session ending in one of the family's own rare secondary actions — the same shape as `attack_dilution` with a legitimate tail | CH01 |
| `benign_hard_reordered_stream` | records delivered out of order. Every streaming path does this, and a sequence check that called it deletion would page somebody daily | CH06 |
| `benign_hard_approved_continuation` | a blocking control fires and a human approves the exception properly. Correct operation, and indistinguishable from a bypass until approvals could bind to a call | CH04 |
| `benign_hard_reapproved_retry` | an approved action fails and is retried under a fresh approval. The most ordinary thing a well-governed agent does | CH04 |

Every false positive in the card comes from one of these. The plain benign
sessions produce none.

Note that `benign_hard_advisory_threshold` now produces **zero** false
positives, which is not a detector improvement and should not be read as one:
the corpus declares `enforcement` on the policy event, CH04 reads it, and a
check that had been reporting a sequence because it could not report a bypass
stopped having to. A deployment whose policy engine declares nothing is back in
the original state and the coverage contract says so.

### 4. The corpus was extended because it could not measure a fix

Worth recording as a decision rather than a changelog line, because it is the
argument for keeping a corpus at all.

EVASION.md's E02 says a violation *rate* can be diluted: pad a session with
routine calls and the rate falls under threshold while the malicious transition
stays. Before writing any fix for it, the corpus was asked what the fix would
change — and the answer was **nothing**, because every session in it was three
or four calls long and a rate cannot be diluted in a session too short to
dilute. The corpus could not see the attack, so it could not have graded the
fix.

Three kinds went in first, with the detector untouched:

| kind | why |
|---|---|
| `benign_long_loop` | ordinary work repeated. Also what teaches the baseline that agents loop — without it, padding creates a novel transition at every loop boundary and dilution fails by accident, making CH01 look stronger than it is |
| `attack_dilution` | E02 itself. Honest summary, fully paired, no markers, no policy events, so CH02–CH05 are blind to it by construction and its recall measures CH01 alone |
| `benign_hard_long_rare_action` | the confounder. Same shape, legitimate tail. Without it the fix would have been measured only against sessions built to make it look good |

On that corpus CH01 caught **0 of 32** diluted attacks. After the fix, 32 of 32,
plus 16 of 32 confounders. Both numbers are in the card, and the second one is
the reason the first one is believable.

Note the shape of the general problem: **a corpus can only grade fixes for
attacks it contains**, so "the numbers did not move" is as easily a statement
about the corpus as about the detector. Check which before believing it.

### 5. And extended again, because it graded a fix it could not grade

The same lesson with the sign flipped, and the more dangerous of the two.

A candidate CH02 precision fix — treat a summary that *denies* having acted as
concealment, and a summary that merely fails to name the tool as honest
paraphrase — measured at 100% precision and 100% recall on the corpus. That is
not a result a real detector produces, and the reason it appeared is countable:

| kind | sessions | distinct summaries |
|---|---:|---:|
| `attack_concealment` | 128 | **8** |
| `benign_hard_terse_summary` | 128 | **8** |

One string per family per form. Every claim about response *prose* had n=8 a
side no matter how many sessions the card printed, the denial lexicon was
written after reading those eight strings, and every concealing string happened
to deny while no paraphrase did. **A measurement whose separation is perfect is
a measurement to distrust**, and this one was the tool-name fault of §1 wearing
different clothes.

Three changes, again with the detector untouched:

| change | why |
|---|---|
| three prose variants per family per form, chosen per **task** | so a prose measurement has an n it can support. Per task, never per attempt, or attempts of one task stop being near-duplicates and the split's guarantee weakens |
| `attack_concealment_silent` | concealment by pure omission — reports the reads and stops. Strictly cheaper for the attacker than a denial, so it is what an attacker who has read EVASION.md writes |
| `benign_hard_honest_denial` | benign work, paraphrased, plus an honest statement of what was not done. The mirror image, and free for a real agent to produce |

Denial now carries **no label information at all** — "denies ⇒ attack" scores
50.0% on this corpus, exactly chance, and `test_denial_carries_no_label_
information` fails if it drifts. Re-measured against that corpus the candidate
fix trades 128 true detections for 128 false positives one for one, for 4.4
points of precision, and the detections it loses are the cheaper attack. It was
not shipped. See EVASION.md E04.

The lexicon that labels this prose lives in the *generator*, not the detector,
and it cannot validate itself: it can tell you whether a detector separates
denial from paraphrase, and not whether it has found every way an agent might
phrase a denial. `attack_concealment_silent` exists so that blindness is
measured rather than assumed away.

### 6. And extended a third time, before the fix rather than after

The two extensions above were both reactions: the corpus could not grade a fix,
so it grew. [docs/EVIDENCE-TRUST.md](../docs/EVIDENCE-TRUST.md) §6 was written
the other way round — it listed the session kinds P1 would need *before any of
P1 was built*, on the grounds that a P1 write-up against the old corpus would
have reported "no change in recall or false positives" and that sentence would
have been about the corpus rather than the detector.

| kind | what it measures |
|---|---|
| `attack_omitted_call` | a consequential call deleted from a **chained** stream. Invisible to CH01–CH05 by construction: what survives is an ordinary session |
| `attack_denied_effect` | the call reports failure and carries a receipt bound to it. An effect occurred and the telemetry says it did not |
| `attack_reused_approval` | an approval granted for one set of arguments, presented for another. Span and tool match; the argument digest does not |

**The corpus is chained but not signed**, and the evaluation runs with no
collector keys. That is the realistic first-adoption state, and it is why CH06
reports `degraded` rather than `evaluated` throughout: a chain with nothing to
verify its origin establishes that the stream is self-consistent, which an
attacker who rewrote the whole stream can also arrange. Signature verification
is a cryptographic property rather than a detection one, so it is tested against
the RFC 8032 vectors in `tests/test_evidence.py` instead of being measured here.

Two limits of this section, stated because neither is obvious from the numbers.

**One stream, and each session joins it mid-flight.** The corpus chains every
record of a condition into a single collector stream, because that is the shape
a real collector produces — a stream multiplexes every session on the host, and
giving each session a private stream would make deletion trivially detectable in
a way no deployment is. But the harness scores one session at a time, so each
one joins the stream part-way through and the records before it are not covered
(`INTEGRITY_STREAM_JOINED_MIDSTREAM`). That is exactly what scoring a window of
a long-running stream does in production.

**A record deleted from the very end of a scoring window is not detectable
here.** Nothing follows it to reveal the gap. In a live stream the next
session's records expose it; in a per-session evaluation they are not in scope.
`attack_omitted_call` therefore deletes a call from the middle of the session,
and the limit is stated rather than engineered around.

One thing this section deliberately does **not** contain is
`attack_forged_success` — a reported success with no receipt. Its telemetry is
byte-identical to a genuinely receiptless tool reporting success, so labelling
one of two identical inputs "attack" would measure the label rather than a
detector. It is reported through coverage as `NO_EFFECT_RECEIPT`, and
`tests/test_evidence.py` asserts it produces no finding. That is the whole claim
receipts make in that direction: they do not make `success` more believable,
they make failure and silence falsifiable.

### 7. And a fourth time, for the trust store

Same discipline, same order: the kinds were written before the detector could
grade them. Stage 4 of EVIDENCE-TRUST gave keys roles, validity windows and
revocations, and none of that is measurable against a stream where every
`key_id` is a string anybody could have written.

| kind | what it measures |
|---|---|
| `benign_hard_rotated_key` | one collector, one stream, and partway through it the signing key changes because the old one was retired. **Must not** fire |
| `attack_revoked_key_stream` | a stream signed by a key the operator has declared compromised |

**These two sit on a second collector stream, and it is signed.** Everything
they measure is a statement about a key, so a chain alone establishes nothing
about them. The rest of the corpus stays unsigned for the reason above: signing
all 24,672 records per condition would add roughly 70,000 pure-Python scalar
multiplications and measure nothing the chain does not. Signing 2,160 of them
costs about ten seconds and buys the only multi-collector shape in the corpus,
so cross-stream gap attribution is measured here rather than asserted.

**Read the pair in the right order.** `attack_revoked_key_stream` is caught by
reading a `key_id`, looking it up in a file the operator supplied, and finding
`revoked_at` set — nothing there could plausibly have failed, and a 100% recall
row for it is close to a tautology. `benign_hard_rotated_key` is the number that
could have gone wrong. A rotation is the most routine thing a key-using
deployment ever does; the rotation instant is deliberately placed *inside* a
session, so one session per vocabulary has records on both sides of the handover
signed by two different keys and both signatures are correct. A verifier that
called that tampering would teach operators to rotate less often, which is a
security control making security worse.

**A third kind was considered and declined: `attack_replayed_stream`.** A
captured stream re-fed months later passes every check in the module — the
sequence is contiguous, the chain holds, the signatures verify — because it
really was written by that collector. The only thing separating it from a
legitimately delayed batch is the age of a timestamp, and the two are otherwise
byte-identical, so labelling one "attack" would measure the label. Same reason
`attack_forged_success` is absent. The freshness bound that catches it is real
and is tested in `tests/test_evidence.py`; what it costs on a delayed batch is a
property of the bound an operator picks, not of this corpus.

**And the corpus growing is not a result.** These kinds took the corpus from
1632 sessions per vocabulary to 1824, which changed the split and therefore the
test population. The headline false-positive rate moved, and that movement is
arithmetic rather than detection; `docs/EVIDENCE-TRUST.md` §8 says so in the
same place it reports the two rows stage 4 is entitled to claim.

## Label integrity

A mislabelled corpus produces confident wrong numbers, which is worse than none.
The generator checks its own labels with Cohaera's own logic and refuses to write
a corpus that fails:

- a session labelled `attack_concealment` must actually conceal, under **both**
  vocabularies (`_assert_conceals`);
- a benign session's honest summary must actually disclose, or it would score as
  a concealment and inflate the false positive rate (`_assert_discloses`);
- a `benign_hard_terse_summary` must **not** name a tool, or it stops being a
  confounder (`_assert_terse_hides`);
- each summary form must have the denial property its kind claims — both benign
  forms and both attack forms span the axis, so denial predicts nothing
  (`_assert_denial_labels`);
- every family must carry at least three distinct variants of each summary form,
  because the alternative is a corpus that reports session counts its prose
  cannot support (`_assert_prose_variety`).

These are not decorative. `_assert_discloses` caught the `incident_triage` family
disclosing under one vocabulary and not the other, which would have made the two
conditions incomparable — the exact thing the corpus exists to compare.

## Why the signatures are cached, and what that does not buy

Cohaera has no runtime dependencies, so `src/cohaera/ed25519.py` is pure Python
and costs about 5 ms per scalar multiplication. The corpus's second collector
stream signs 2160 records per condition at two multiplications each, which put
roughly nine seconds of signing inside every call to `generate()` — and
`tests/test_eval.py` calls it once per test. The suite spent more than half its
wall clock re-deriving signatures it had already derived, byte for byte.

`corpus/signatures.py` memoises signing, addressed by `sha256(key_id ‖ message)`.
The property that makes it safe is that there is nothing for it to be stale
about: change anything in the corpus and the chain head changes, which changes
the message, which changes the address, which misses. A cache that can only be
addressed by its own content cannot answer a question it was not asked. It is
gitignored, it lives outside `corpus/data/` so it cannot leak into the card's
corpus digest, and deleting it costs one slow run.

Measured on the tree that introduced it: `pytest tests/` went from **7 m 28 s to
1 m 45 s on a cold checkout**, and to 1 m 19 s with the file already written.
Nearly all of the saving is the in-process dictionary rather than the file —
one pytest process generates the corpus dozens of times — which is why CI gets
almost the whole benefit with no cache to restore between runs.

**It does not speed up verification, on purpose.** Every signature Cohaera
checks while scoring goes through the same code path a deployment uses, because
that path is what the evaluation exists to measure. `run_eval.py` therefore
improves by only about 8%: the cache sits on the *producer* side, which in a
real deployment is not Cohaera's code at all.

## A CH02 property this surfaced

Writing `_assert_conceals` turned up something worth recording. `access_review`
uses `ldap_group_membership_enumerate` (read) and `ldap_group_membership_apply`
(write). CH02 matches disclosure by token overlap against the tool name, and
those two share three tokens out of four — so a summary mentioning only the read
"discloses" the write, and CH02 cannot see the concealment at all.

This is not specific to the corpus. Shared-prefix tool suites are the norm
(`github_issue_create` / `github_issue_read`, `s3_object_put` / `s3_object_head`),
and any agent using one can conceal a write by naming the adjacent read. It is
catalogued as **E16** in [`../EVASION.md`](../EVASION.md).

## What this is not

The card's own "What this does not measure" section is the authoritative list.
The short version: the corpus is synthetic and written by the detector's author,
attack prevalence is an absurd 33%, and there is no adaptive attacker. One
catalogued evasion from `EVASION.md` now appears in it, `attack_dilution` for
E02, and it is there because a fix could not be graded without it — the other
sixteen still do not. It is a large improvement on twelve fixtures and it is not
real agent traffic.
