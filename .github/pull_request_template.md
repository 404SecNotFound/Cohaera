## What this changes, and why

<!-- One paragraph. If it closes a review finding or an evasion, cite the id. -->

## Evidence

<!-- Delete the rows that do not apply, but do not delete a row because it is
     inconvenient -- say "n/a, because ..." instead. -->

- [ ] The defect was **reproduced first**, and the test that reproduces it is in
      this change.
- [ ] I **mutated the fix** and the test failed. Mutations tried:
- [ ] `python -m pytest tests/ -q` passes.
- [ ] `python tests/test_evasion.py` still reports every catalogued evasion as
      working. (A failure here means an evasion was closed without updating
      `EVASION.md`.)
- [ ] `ruff check src tests eval tools` passes.
- [ ] `python tools/readme_facts.py --check` passes — no hand-typed counts.

## If this changes detection

- [ ] `python eval/run_eval.py` re-run and the card regenerated.
- Recall and false-positive rate, before → after:
- Which way the FPR moved, and **why**. If it improved because a check stopped
  being able to run, say that — it is not an improvement:

## If this changes an evasion

- [ ] `EVASION.md` row updated, the self-test converted from evasion to
      regression, and the counts regenerated.

## Anything a reviewer should push back on

<!-- Trade-offs you took, bounds you chose, things you were unsure about. -->
