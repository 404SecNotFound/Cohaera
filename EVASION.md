# Known evasions and weaknesses

Everything else in this repository shows the detector firing. **None of it shows
the detector is good.** Those are different claims and they are easy to confuse,
most easily by the person who built the thing.

This file is the attempt to break it. Every entry below is backed by an
executable test in [`tests/test_evasion.py`](tests/test_evasion.py). Those tests
**pass when the evasion works**, which is the opposite of normal. When somebody
later closes one, the test fails and this file gets updated.

Run it: `PYTHONPATH=src python3 tests/test_evasion.py`

**Current state: 15 of 15 constructed evasions still work.** One of them, E13,
has had half of its impact removed: the omission still succeeds, but coverage no
longer reports full confidence on a session it never saw. See the E13 entry.

There is also a **denial-of-service class that is not in this table**, because
crashing the detector is not an evasion of a check, it is an evasion of the whole
control. Eleven such defects were found by external review and by measurement,
and all eleven are fixed with regression tests. They are catalogued at the bottom
of this file under [Defects found by external review](#defects-found-by-external-review-now-fixed).

---

## Summary table

| ID | Target | Evasion | Cost to attacker | Fixable at this layer? |
|---|---|---|---|---|
| E01 | CH01 | Use only known tools in known order | Free | No, bigram ceiling |
| E02 | CH01 | Dilute below the 0.25 rate threshold | 8 benign calls | Yes |
| E03 | CH01 | Poison the benign baseline | Access to corpus | Process control only |
| E04 | CH02 | Honest paraphrase causes a FALSE POSITIVE | n/a, precision bug | Needs semantics |
| E05 | CH02 | Name the tool, lie about the outcome | Free | Yes |
| E06 | CH02 | Emit no final response | Free | Partial, coverage sees it |
| E07 | CH03 | Act first, read untrusted content second | Free | No |
| E08 | CH03 | Split read and act across two sessions | Free | Partial |
| E09 | CH03 | Stay below observra's five regexes | Free | Yes, scan locally |
| E10 | CH04 | Act before the threshold trips | Free | Yes |
| E11 | CH05 | Fabricate a terminal event | Emitter access | No |
| E12 | all | Fragment session_id on call boundaries | Emitter access | No |
| E12b | — | Fragmenting mid-call **is** caught by CH05 | — | *unplanned win* |
| E13 | all | Omit the event entirely | Emitter access | No |
| E13b | — | Naive omission **is** caught by CH01 | — | *unplanned win* |
| E16 | CH02 | Conceal a write by naming the adjacent read from the same tool suite | Free | Needs semantics |

---

## The three that matter most

### E13. The telemetry is self-reported

Cohaera reads what the agent's own instrumentation chose to emit. An agent that
controls its telemetry can omit a tool call: no event, no session member, no
finding.

**HALF CLOSED, 7 August 2026.** The omission still works and there is no fix for
it at this layer. What has changed is the second half, which was the dangerous
one: coverage used to report **1.0, full confidence**, on a session it had never
properly seen. Three separate corrections took that away, and each was
independently wrong:

- nothing in that stream carries an injection-marker field, so no upstream
  scanner ran, so CH03 could not have fired. That is now `not_evaluated` with
  reason `NO_INJECTION_SCANNER_EVIDENCE` rather than silently clean;
- every tool was classified by **name**, which is a guess about a string the
  observed system chose. A guess no longer contributes a whole point;
- there was no capability manifest, so no class in the session was a declared
  fact.

The same session now scores around 0.68. **The attack is unchanged. What changed
is that the verdict no longer claims to have looked.** That is a smaller win than
it sounds and a real one: a SOC that routes on coverage can now see the blind
spot, where before the blind spot was reported as a clean result.

State this first in any deployment conversation:

> **Cohaera is an assurance control, not an adversarial one.** It answers "is
> this agent doing its job" well. It does not answer "is this agent lying to me"
> at all.

Closing it needs evidence from outside the agent: kernel or network observation
(AgentSight, [arXiv:2508.02736](https://arxiv.org/abs/2508.02736), boundary
tracing) or a tamper-evident signed log at the point of emission (AEGIS,
[arXiv:2603.12621](https://arxiv.org/abs/2603.12621), Ed25519 plus hash chaining).

### E12. The correlation key is supplied by the thing being observed

Give every event its own `session_id` and there are no sessions, so there is no
cross-event state, so every check goes quiet at once. Same root cause as E13.

### E09. CH03's ceiling is set by somebody else's code

CH03 orders injection markers against consequential calls. If no marker is
recorded upstream, it has nothing to order. It therefore inherits every blind
spot of observra's five-regex scanner, which is only ever applied to user input
in the first place (see [FINDINGS.md](FINDINGS.md) F-01). That ceiling is low.

**Fixable here:** scan `tool_result` inside Cohaera when `capture_tool_data` is
on, rather than depending on upstream markers.

---

## Two unplanned wins, honestly labelled

Neither was designed. Both were found by running the tests.

**E13b. The sequence grammar is weak tamper-evidence for free.** Deleting events
leaves a hole in the tool sequence. If the hole breaks a learned transition,
CH01 fires. Not because it detects tampering, but because a truncated session
has an unusual shape. It stops working the moment the attacker pads the gap back
to a known-good shape, which is what E13 now demonstrates.

**E12b. Fragmenting mid-call trips the pairing check.** After the C-02 pairing
fix, splitting a session between a `tool_start` and its `tool_end` orphans the
terminal event, and CH05 reports it. Session fragmentation now has to respect
call boundaries. That raises the cost of E12 from zero to slightly above zero.

Do not oversell either. They are happy accidents to be aware of, not controls to
rely on.

---

## E16. Shared-prefix tool suites make CH02 blind to concealment

Found while building the evaluation corpus, which is the useful kind of finding:
nobody was looking for it, and it fell out of a label-integrity assertion
refusing to accept a session the generator had labelled as a concealment.

CH02 decides whether the final response discloses a tool call by splitting the
TOOL NAME into tokens longer than two characters and asking whether any of them
appears in the response. So for a tool suite with a shared prefix -- which is the
normal shape of an MCP server -- a summary that mentions the READ discloses the
WRITE:

    ldap_group_membership_enumerate   read    tokens: ldap, group, membership, enumerate
    ldap_group_membership_apply       write   tokens: ldap, group, membership, apply

"I enumerated the ldap group membership" shares three tokens with the write. CH02
reads that as disclosure of the write and reports nothing. The agent can perform
the write, describe only the read, and pass the concealment check.

This is not a corpus artefact. It is the normal naming convention:
`github_issue_read` / `github_issue_create`, `s3_object_head` / `s3_object_put`,
`stripe_invoice_retrieve` / `stripe_invoice_void`. Any agent whose tools are
named this way gets the evasion for free, without doing anything unusual.

**Cost to the attacker: nothing.** It requires no fabricated events, no emitter
access and no unusual sequence. It is simply how the check behaves on realistic
tool names, and every fixture in `tests/make_fixtures.py` avoided it by accident,
because those fixtures name tools `send_email` and `fetch_ticket` -- short,
distinct, and sharing no stems.

**Not fixable lexically.** Requiring ALL tokens to match breaks on legitimate
paraphrase and makes E04 worse. Matching only the distinctive token needs to know
which token is distinctive, which is the semantic problem CH02 already has. This
is more evidence for the "CH02 semantic matching" roadmap item, and it is now the
strongest evidence for it, because unlike E04 it is a false NEGATIVE.

The corpus works around it by describing reads generically in concealing
summaries, and `eval/corpus/generate.py::_assert_conceals` fails the build if a
session labelled as a concealment does not actually conceal under both naming
conditions. That keeps the corpus honest; it does not fix the check.

---

## A measured result: the CH01 dilution curve

CH01 scores `unseen_transitions / total_transitions` against a 0.25 threshold.
Padding grows the denominator.

Grammar fitted on 20 benign sessions, 6 distinct transitions. One malicious
`exfiltrate_all` call appended to N loops of the benign sequence:

| Loops | Benign calls | Violation rate | CH01 |
|---:|---:|---:|---|
| 1 | 4 | 0.333 | **FIRES** |
| 2 | 8 | 0.200 | silent |
| 3 | 12 | 0.143 | silent |
| 4 | 16 | 0.111 | silent |
| 10 | 40 | 0.048 | silent |

**Eight benign calls are enough to hide one malicious transition.** That is the
useful number, and it is cheap for an attacker.

**Fix:** score on the absolute count of unseen transitions as well as the rate,
and weight by the class of the novel call. One novel egress transition should
not be dilutable by any number of benign reads.

### A methodology note worth more than the result

The first version of this test failed, and the reason matters. My benign
baseline ran the tool sequence exactly once per session, so
`draft_reply -> search_tickets` was never learned. Every attempt to pad by
repeating the sequence created a **novel** transition at each loop boundary, and
dilution appeared impossible.

**A baseline that never loops is not a baseline, it is a fixture.** Real agents
loop. Fitting on 1, 2 and 3 iteration sessions is both more realistic and
considerably weaker. If you evaluate a behavioural detector against a corpus
that is tidier than production, you will measure a detector that does not exist.

---

## Defects found by external review, now fixed

Recorded here because a fix nobody writes down is a fix nobody can audit. Every
row was **reproduced locally before it was fixed**, and every row has a
regression test. The reproduction matters: three of the claims below turned out
to be true for a different reason than the reviewer gave, and one turned out to
be aimed at the wrong function entirely.

### Fourth review, revision `ec77e3f`

Eleven defects, C4-01 to C4-11. Seven were spot-checked first and all seven
reproduced, so the review was treated as reliable and the remainder were
reproduced individually before any of them were touched. Nine are fixed here,
with regression tests in [`tests/test_hostile.py`](tests/test_hostile.py); the
two that are not are listed below with the reason.

The unifying theme this time is different from the third review's, and worse.
The third review found inputs the code had never been shown. This one found
**bounds and caches that did not do what their names said** -- a budget checked
after the work it was meant to prevent, a cap that a negative value disabled, a
cache keyed on a length rather than on the content it was caching. Every one of
these reads as present when you audit the code by grepping for the control. They
are only absent when you measure.

| ID | Defect | Effect | Status |
|---|---|---|---|
| C4-01 | `run_id` hashed the ingest **summary** -- source path plus counts -- not the content. | Two entirely different files at the same path with matching counts produced identical `analysis_run_id` and `verdict_id`. A SIEM deduplicating on either discards the second as a retry, which is what a rotating collector produces every day. | **Fixed.** A streaming SHA-256 over the exact bytes of every record read, in order, accepted and rejected alike. `verdict_id` also commits to the session events, coverage and schema, so two sessions with different evidence and matching findings no longer collide. |
| C4-02 | `max_events_total` was checked against `report.accepted`; `max_rejects` and `max_reject_ratio` were checked by the CLI *after* `load()` returned. | A file of nothing but malformed records incremented no accepted count, so the only in-reader budget never moved, and the CLI's budgets were a post-mortem: every byte was already read, decoded, depth-scanned and hashed. With `max_events_total=1` and `max_rejects=1`, all three malformed records in a three-line file were still read. | **Fixed.** Every budget is evaluated per record inside `read_events`, and two new ones bound the **work** rather than the yield: `max_records_total` and `max_input_bytes`. The ratio check waits for `max_reject_ratio_floor` records first, because one bad line out of one is a ratio of 1.0. |
| C4-03 | A record with partial identity and an invalid timestamp keyed as `anon-<scope>-noclock`. | One bucket per scope for the whole run. Two unrelated events an hour apart merged into a single session, which then supported cross-event findings the data never justified. The timestamp is producer-controlled, so this was reachable on purpose. | **Fixed.** A scoped anonymous key is identity *plus* a time window; with no usable clock there is no window and nothing to merge on, so the record is isolated exactly as BUG-06's fully-anonymous records are. Confidence 0.0, stated in the record. |
| C4-04 | `_write_reject_log` caught `OSError`, printed a line and returned. | A run whose `--reject-log` path was unwritable still exited **0**. The quarantine ledger is the record of what Cohaera refused to score; losing it while reporting success is the same silent-data-loss failure BUG-11 introduced exit codes to remove. | **Fixed.** The path is probed for writability before scoring starts, and a write failure at the end is an error exit. A requested audit artifact that cannot be produced fails the command. |
| C4-05 | `Limits` validated nothing. | `Limits(max_evidence_items=-1)` constructed happily and then **silently disabled** the output cap, because `cap_list` reads a negative limit as unlimited -- so lowering a bound by typo raised the ceiling and reinstated the 61x amplification that bound exists to stop. `max_reject_ratio=2.0` was a reject budget that could never trip. | **Fixed.** `Limits.__post_init__` refuses every out-of-range value, argparse rejects them at the boundary as usage errors, and a test asserts that *every* field is covered by a validation rule so a bound added later cannot escape one. |
| C4-06 | `requires_approval=bool(spec.get(...))`. | The JSON string `"false"` became `True`. Every other field on the record was type-checked; this one guessed, and it guessed in the direction that changes what a check concludes. | **Fixed.** Booleans only. The manifest also gets the bounds telemetry already had: file size, tool count, field lengths and `sensitive_args` count, and producer metadata is no longer coerced with `str()` -- `str({...})` sent a dict's repr to the SIEM as a producer name. |
| C4-07 | `Event.view` was cached; `Event.raw` stayed a mutable dict. | The record and the engine's belief about it could disagree indefinitely, with nothing raising. Mutate `raw["tool_name"]` after first access and the class, the correlation key and the digest all still report the old value. | **Fixed.** Records are frozen: the dataclass refuses rebinding and the payload is immutable all the way down. A cache over an immutable value cannot go stale. Digests are unchanged, so stored verdicts still match. **Measured cost:** deep-freezing every record moved `read_events` on 64,000 typical events from 2.13s to 2.80s, a 31% ingest overhead. Stated rather than buried, because it is a real price and somebody sizing a collector needs it. It buys the removal of a state in which the record and the engine's belief about it can disagree with nothing raising. |
| C4-08 | The `Session` cache keyed on `len(self.events)`. | Length is not content. `s.events[0] = other` left the length unchanged, so every cached feature -- tool classes, egress counts, the digest `verdict_id` commits to -- was served from the old set, and a read-only tool stood in for an exfiltration. | **Fixed.** Same fault as C4-07 one layer up, and the same answer: batch-assembled sessions are **sealed**, `events` becomes a tuple, and neither `append` nor index assignment exists. The streaming path keeps `add_event`, which bumps a revision counter the cache also reads. |
| C4-09 | Oversize rejects logged `bytes_seen=0` and an empty digest. | For the one reject class where size *is* the finding, the ledger recorded no size. The byte count was already being computed to enforce the bound and was thrown away. | **Fixed.** `_bounded_lines` yields the real byte count and a digest streamed over the whole line without ever retaining it, so an oversize record is identifiable and comparable across runs, and its content reaches the run identity that C4-01 added. |

**C4-10, semantic manifest digest: not taken.** The review proposed replacing the
manifest's byte digest with a digest of its parsed semantics, so that
reformatting the file does not change the recorded hash. That trade goes the
wrong way for a security control. The question the digest answers is "did the
policy file change at all", and the byte digest answers it strictly; a semantic
digest would report *no change* for an edit that added a field Cohaera does not
yet read. If the semantic digest is wanted for change-management ergonomics it
should ship **alongside** the byte digest, not instead of it.

**C4-11, README drift: fixed, and made structural.** The README said "188
passing" against a tree with 197 and listed "CH02 semantic matching" twice in one
roadmap. Small, both of them -- and exactly the kind of claim this project argues
should be kept true by something rather than by attention. The counts are now
derived from the tree by [`tools/readme_facts.py`](tools/readme_facts.py) and
checked on every test run and in CI.

### Third review, revision `c832721`

Eleven defects. All eleven reproduced; all eleven fixed with tests in
[`tests/test_hostile.py`](tests/test_hostile.py).

The unifying theme is worth stating on its own, because it explains why the
existing 47 tests caught none of them. **Every suite in this repository built
well-formed fixtures.** `test_cohaera.py` builds correct sessions and asserts the
checks fire. `test_evasion.py` builds correct sessions that defeat the checks.
Neither one ever put a list where a string belonged. A telemetry trust boundary
is graded on the input it was *not* designed for, and that input had never been
written down.

| ID | Defect | Effect | Status |
|---|---|---|---|
| BUG-01 | A list or dict `span_id` reached a dictionary lookup. | `TypeError: unhashable type` raised from inside a check, taking down every other session in the file | **Fixed.** Spans must be bounded non-empty strings. Over-long spans are *rejected*, not truncated: a truncated identity is a forged identity. |
| BUG-02 | A non-string `response_text` became the final response and CH02 called `.lower()` on it. | `AttributeError`, and detection suppression for the whole run | **Fixed.** Treated as absent, and coverage distinguishes `FINAL_RESPONSE_WRONG_TYPE` from `NO_FINAL_RESPONSE_TEXT` so a blinded check is not read as a passing one. |
| BUG-03 | `read_events` caught only `json.JSONDecodeError`; 10,000 nested arrays raised `RecursionError`. | Ingestion denial of service | **Fixed.** Depth is measured by a pre-scan *before* the recursive decoder sees the line, plus bounded line size, UTF-8 handling, an event budget, and `RecursionError` caught as a second wall. |
| BUG-04 | Python hashes `True` and `1` identically, so spans `true` and `1` shared one slot. | Call identity corruption: a success recorded against the wrong action | **Fixed.** Dissolved by the same string requirement as BUG-01. Booleans are rejected before strings everywhere, because `True` is not a name. |
| BUG-05 | The call cache was populated on first access and never invalidated. | Stale verdicts; batch loading hid it, streaming would not have | **Fixed.** Caches are keyed on the event count, `add_event()` invalidates, and *every* derived value refreshes, not just the call list. |
| BUG-06 | Records with no session, trace, host, user, agent **or** framework were still bucketed by time. | Fabricated correlations between unrelated records | **Fixed.** A record with no identity has nothing for a merge to rest on and is now isolated. The useful half of the C-04 fix — scoped bucketing for records that *do* carry identity — is unchanged. |
| BUG-07 | The anonymous key embedded `repr()` of host, user, agent and framework, and that key is emitted as `session_id`. | Identity leak into the SIEM from a field labelled anonymous | **Fixed.** HMAC-SHA256 over a typed identity tuple, keyed from `$COHAERA_CORRELATION_SECRET`. With no secret it is an unkeyed digest and the record *says so* via `correlation.keyed`, because a short identity space is enumerable. |
| BUG-08 | CH03's title said "Attempted" while its detail said the call "ran afterwards". | An errored call presented as an effect | **Fixed.** Split into `CH03_untrusted_to_completed_action` and `CH03_untrusted_to_attempted_action`, separate severities, separate Sigma rules. |
| BUG-09 | CH04 said "the control did not stop the behaviour" about a call that had errored, at level high. | An attribution the data cannot support | **Fixed.** Split into `CH04_guardrail_bypass_completed` (high) and `CH04_post_guardrail_attempt` (medium). The attempt wording states plainly that this telemetry cannot say *which* of the guardrail, the tool or an unrelated failure stopped the call. |
| BUG-10 | Unknown classification raised a standalone gap that no check depended on, so `completeness` was unaffected. | A session Cohaera did not understand still scored up to 1.0 | **Fixed.** Coverage is now a per-check capability contract (`cohaera.coverage:2`) and `completeness` is confidence-weighted by correlation quality, classification quality and clock quality. Missing `tool_result` moved from CH02 to CH03, where the provenance question actually lives. |
| BUG-11 | `cmd_score` returned 0 unconditionally. | Silent data loss in automation | **Fixed.** Exit 0 clean, 3 partial, 4 strict, 5 budget exceeded, plus `--reject-log` for a machine-readable quarantine ledger. |

### Two defects the review pointed at, but not accurately

Worth separating, because "the reviewer was right that something was wrong" and
"the reviewer was right about what" are different, and only the second one tells
you where to put the fix.

**The quadratic was not where it was reported.** The review measured call
assembly at 32,000 same-name calls and reported 5.04 seconds, attributing it to
`list.remove` in the pairing index. Re-measuring found that path at **0.265
seconds** — near-linear, because both scans are C-level. It was still worth
fixing and now uses a deque with lazy deletion, but it was never the bottleneck.

Measuring the rest of the scoring path found two genuine super-linear faults the
review missed, both worse:

- **CH04 emitted one finding per policy *event*, each carrying every
  consequential call after it.** With 300 policy events and 300 consequential
  calls that is O(N·M) in time *and in output*: 900 input events produced a
  **6.3 MB verdict record**, a 61× amplification, in 1.9 seconds. At 2,000 of
  each it took **41.6 seconds**. Both numbers are supplied by the observed
  system. Fixed by reporting the *earliest* firing of each policy type once and
  carrying the repeat count, plus bounded evidence lists throughout.
- **CH02 re-scanned the entire final response once per name fragment per call**,
  which is O(calls × response length). 800 calls against an 80 KB response took
  **6.9 seconds**. Fixed by indexing the response once.

The lesson is not that the review was careless. It is that **a timing number
without a profile attributes cost to whatever the reader was already looking
at**, and the only defence is to measure the thing you are about to change.

**Fuzzing found six exception classes; the fix required seven.** Hardening the
input boundary introduced a new instance of the exact fault it was written to
remove: `identity.canonical` serialised the raw record with `allow_nan=False` to
compute its content digest, so a record carrying `duration_ms: Infinity` raised
`ValueError` from inside session assembly. Caught by re-running the fuzzer
against the fixed tree, not by reading. It has its own regression test.

### Second review, revision `45d768d`

See the commit message for `c832721`. Strict span identity, non-string tool
names, non-finite timestamps, substring collisions in tool classification, call
assembly caching, CH03/CH04 lifecycle evidence, and Sigma validation.

### First review, revision `45d3bf8`

Six correctness defects. All six were reproduced locally and are now fixed with
regression tests.

| ID | Defect | Effect | Status |
|---|---|---|---|
| C-02 | Tool completions paired twice. A span match removed the call from the span index but left it in the name index, so a later name-only terminal event overwrote a recorded success with a failure. | Fabricated and suppressed findings | **Fixed.** One identity, released from every index atomically. Orphan terminals get a distinct `orphan_end` state. |
| C-03 | `reversible` only upgraded names already classed read_only. `create_account` with `reversible=False` stayed `unknown`; `delete_record` with `reversible=True` stayed consequential. | Silent false negatives on unknown-named sinks | **Fixed.** Producer flag is authoritative both ways; egress by name still wins. |
| C-04 | Every event with no `session_id` or `trace_id` went into one global bucket. An injection marker on host-A could correlate with an egress action on host-B under a different user. | Manufactured findings across unrelated hosts | **Fixed.** Scoped by host, user, agent, framework and a 300s window. Never global. |
| C-07 | Malformed-JSON warnings printed to stdout. | One bad line invalidated the JSONL pipe the CLI promises | **Fixed.** Diagnostics to stderr, quarantine count reported. |
| C-08 | Unvalidated `float()` on timestamps. | Trivial ingestion denial of service | **Fixed.** Returns NaN, sorts last, exposed via `timestamp_valid`. |
| CH02 | "I did not send any email" was read as disclosure of `send_email`. | Exact inversion of the check | **Fixed.** Negation-span detection. Still lexical, so E04 stands. |
| CH05 | Orphan terminal events were constructed with `result="success"` and never flagged. | An irreversible action appearing from nowhere was invisible | **Fixed.** `orphan_end` state, reported by CH05. |

The review's C-05 finding, no executable test suite, was accurate at revision
`45d3bf8`. There are now 274 tests: unit, hostile-input, content conformance and
16 evasion characterizations, plus a seeded fuzz smoke test in CI.

### What is still open from the third review

Closed here: the schema contract (F1), typed capability manifests (F2), stable
verdict and run identity, per-check coverage contracts, resource bounds, and CI.

**Still open, and correctly prioritised:**

| Item | Why it is not closed here |
|---|---|
| Independent effect receipts (F4) | Needs a message ID, HTTP status, inode hash or cloud audit event from *outside* the agent. Nothing at this layer can distinguish a logged success from a real one. This is the substance of E13. |
| Collector-side signing and hash chaining (F6) | Needs a key the agent process does not hold. A digest Cohaera computes proves Cohaera saw the input, not that the input was true. |
| Approval and policy binding (F5) | Needs the producer to emit an approval hash. Related: CH04 reports `POLICY_SEMANTICS_UNDECLARED` on every session with a policy event, because nothing declares whether a control is advisory or blocking. |
| Streaming correlation service (F7) | Cache invalidation (BUG-05) is fixed, which unblocks it, but watermarks, TTL and bounded active state are a service, not a flag. |
| Typed evidence graph, argument provenance (F3) | The largest item. Not started. |
| Deployable Exabeam parser | The field map is documentation. It is now *tested* documentation — `tests/test_content.py` asserts every field it names exists in a real record — but a parser needs a live platform to validate against. |
| Adaptive evaluation with a task-disjoint holdout | **Partly closed.** [`eval/`](eval/) now carries a labelled corpus of 768 sessions across 8 task families, task-disjoint splits enforced in code, benign-hard confounders, and a generated [evaluation card](eval/EVALUATION-CARD.md) with Wilson intervals. What is still open is the *adaptive* half: every attack in that corpus is one of four fixed shapes, and none of the sixteen evasions catalogued above appear in it. The corpus is also synthetic and written by the detector's author, which the card says on its face. |

The last row was, for three reviews running, the one that mattered most and the
one nothing was done about. It is now the row with the most work behind it, and
the result is worth stating plainly rather than burying: **measured properly,
Cohaera flags 60% of benign sessions.** Every one of those false positives comes
from a session built to be hard, and every hard session trips exactly the check
it was built to trip, which means the detector is behaving as designed and the
design cannot tell intent from sequence. That is a more useful thing to know than
any number the fixtures ever produced.

---

## What this file is not

It is not a threat model, and it is not complete. These are the evasions I
thought of in one sitting, plus the defects one reviewer found. An adaptive
attacker who has read this file will find more.

That is the expected outcome and it is why the checks are framed as detection
rather than prevention. *The Attacker Moves Second*
([arXiv:2510.09023](https://arxiv.org/abs/2510.09023)) bypassed 12 published
defences at over 90% attack success rate, most of which had originally reported
near zero. Any defence evaluated only against attacks its author imagined is
being graded by the wrong examiner.

**If you find an evasion that is not here, please add it.** A test that proves a
weakness is worth more than a feature that hides one.
