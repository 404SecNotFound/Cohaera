<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# Contributing to Cohaera

Cohaera is a detection engine, which means the usual contribution advice is not
enough. A web framework that merges a plausible-looking patch gets a bug. A
detector that merges a plausible-looking patch gets a **green tick over a false
negative**, and nobody finds out until it matters.

So the standards below are about evidence rather than style. They are the ones
the existing code was held to; every one of them exists because something got
past an earlier version of this file.

## Before anything else

Set the environment up once, then verify with one command:

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev,content]" build
python tools/verify.py
```

That replays **every gate CI runs** — 15 of them — and prints which passed,
which failed, and which could not run. It takes about four minutes cold.
`--fast` skips the slow ones; `--only lab readme-facts` runs a subset; `--list`
prints each gate and why it exists.

**`pytest` alone is not the build, and believing otherwise has cost this project
two red pipelines.** Both were generated artefacts going stale — the evaluation
card quotes the evasion count, the lab manifest records coverage states — and no
unit test can see either. 12 of the 15 gates are things `pytest` does not
run.

**A gate that cannot run reports `not_evaluated`, and the run does not come out
green.** If `sigma` or `mypy` or `build` is missing, you get a reason code and a
non-zero exit, not a quiet tick over an unexamined gate. Pass `--allow-skips` to
accept a hole deliberately. This is the same rule the detector holds itself to,
applied to the thing that checks the checker.

The individual commands, if you want them one at a time:

```bash
python -m pytest tests/ -q          # ~1m50s cold
python tests/test_evasion.py        # the catalogued evasions must still work
ruff check src tests eval tools
python tools/readme_facts.py --check
python lab/local/run.py --check
```

`tests/fixtures/*.jsonl` and `eval/corpus/data/` are generated and gitignored.
`python tests/make_fixtures.py` and `python eval/corpus/generate.py` produce
them. If a test reads a file that is not committed, that test passes on your
machine and fails on a fresh clone — this has happened, and it is why the
in-memory helpers in `tests/test_eval.py` exist.

## The five rules

### 1. Reproduce the defect before you fix it

Every test in `tests/test_hostile.py` corresponds to a defect that was
reproduced against a specific revision *before* the fix existed. Write the
failing test first, watch it fail for the reason you think it fails, then fix
it. A test written after the fix tests your fix; a test written before it tests
the defect.

If you are closing a finding from a review, cite it — `COH-R03`, `C5-05`,
`BUG-07` — in the test and in the code comment. The identifiers are how a reader
connects a strange-looking line of code to the reason it is strange.

### 2. Mutate your own test before you trust it

Break the fix on purpose and confirm the test fails. If it still passes, the
test is decorative. This catches more than you would expect: a mutation of the
per-key comb's odd-multiple index turned out not to be a mutation at all,
because the digit is always odd and `d // 2` and `(d - 1) // 2` are the same
expression. Better to learn that from a mutation run than from a reviewer.

Say in the pull request which mutations you tried and which failed.

### 3. Malformed input is *absent and flagged*, never coerced

`src/cohaera/validate.py` is the schema firewall and it holds the whole
doctrine. Two failure modes, kept apart:

- **Rejection** — the record is not a record. It never becomes an `Event`; it
  goes to the quarantine ledger with a reason code and a digest.
- **Defect** — the record is a record but a field is not what it claims. The
  record survives, the field is treated as **absent**, and a defect code travels
  with the `Event` so coverage can lower confidence for the checks that needed
  it.

Never coerce. A malformed tool name became `<unnamed>`, which classified as
`unknown`, which is not consequential — and a malicious action with a hostile
name became invisible to three checks at once. `"false"` is a truthy string.
Truthiness is not a schema.

New field? Add its type rule to `validate.py`, a defect code to `limits.py`, and
a case to the hostile suite. Do not type-check it at the point of use.

### 4. A check that cannot run must say so

The worst output this project can produce is a clean verdict over evidence it
never had. Every check declares the surfaces it needs; missing decisive evidence
is `not_evaluated` with a reason code, never a pass.

Two consequences that catch people out:

- **Confidence is worst-case, not average.** A mean over a session's calls is
  diluted by adding calls, and the producer decides how many calls there are.
- **Absence of a signal is not evidence of absence.** If a mechanism was not
  configured, the verdict says which — `NO_STREAM_LEDGER`, `NO_COLLECTOR_KEYS`,
  `POLICY_SIGNATURE_ABSENT`.

### 5. Numbers in documents are derived, not typed

`tools/readme_facts.py --check` runs in CI. Test counts, evasion counts and the
headline metrics in `README.md`, `EVASION.md` and `SECURITY.md` are read from
the repository and the evaluation card. Never hand-edit one; run
`python tools/readme_facts.py --write`.

If you add a counted claim to a document, add it to `CLAIMS` in that file too. A
number nothing keeps true is the one kind of defect this project cannot ship,
and it has shipped twice.

## Changing a check

Detection changes need evidence that they detect. In the pull request:

1. Run the evaluation — `python eval/run_eval.py` — and include the before and
   after. It regenerates `eval/EVALUATION-CARD.md` and CI fails on any diff, so
   a detection change **must** come with a regenerated card.
2. Say which way the false-positive rate moved and why. An improvement that
   comes from a check going *blind* is not an improvement; the card has a
   worked example of exactly that under `name_only`.
3. If the corpus cannot grade your change, say so and stop. Twice now a real
   defect has been fixed with the card unmoved, because every corpus session was
   well-formed in the way the defect needed. Adding a confounder kind changes
   prevalence and every published number, so propose it rather than doing it
   inside another change.

## Closing an evasion

`EVASION.md` is a catalogue of ways to defeat these checks, and
`tests/test_evasion.py` asserts they **still work**. A failure there is not a
regression — it means somebody closed a weakness without updating the catalogue.

To close one: change the detector, flip the row in `EVASION.md`, change the
test from an evasion to a regression, and regenerate the counts. All four, in
one change.

Found a new one? A pull request adding it to `EVASION.md` and to the self-test,
with no fix at all, is a genuinely valuable contribution and is the easiest
useful thing to send.

## Dependencies

**The runtime has none, and this is checked in CI.** Not "few" — none. It is
what lets Cohaera run on a locked-down collector VM and in an air-gapped lab,
and it is why there is a hand-written Ed25519 in `src/cohaera/ed25519.py`.

Dev and content extras are fine. A runtime dependency needs a case made in the
issue before the pull request.

## Style

`ruff check src tests eval tools` is the gate; the rule set is pinned in
`pyproject.toml`. Beyond that:

- Comments explain **why**, and especially why something looks wrong. The
  codebase is full of "this used to be X, and here is the input that broke it".
  That is deliberate. A reviewer who cannot see why a line is defensive will
  eventually simplify it away.
- Test names are sentences. `test_a_replay_does_not_advance_the_ledger`, not
  `test_ledger_3`.
- No emoji, no decorative formatting in code or docs.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md), which also
explains the one report that will be closed on sight: Cohaera reads telemetry
the observed agent chose to emit, so "the agent can lie to you" is a documented
design boundary rather than a vulnerability.

## Licence

Contributions are accepted under [Apache-2.0](LICENSE), the project's licence.
