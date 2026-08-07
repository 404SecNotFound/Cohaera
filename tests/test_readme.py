"""The README's counted claims must match the repository.

C4-11. The README said "Tests, 188 passing" against a tree with 197, and listed
"CH02 semantic matching" twice in the same roadmap. Small, both of them. But
this project's entire argument is that a number you publish should be a number
something keeps true, and the README is where every reader starts.

The counts are derived in ``tools/readme_facts.py``. This is the release check:
it runs on every test run, so a stale claim survives exactly as long as it takes
to run the suite once.

Same pattern as ``tests/test_ci_config.py``, which asserts the branch ruleset's
required status checks match the CI jobs that report them, and
``tests/test_content.py``, which asserts every field the Sigma pack references
exists in a real verdict record. Committed text that names something gets
checked against the thing it names.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import readme_facts


def test_readme_counted_claims_are_true():
    """Fails with the claim, the stated number and the real one."""
    found = readme_facts.problems()
    assert not found, (
        "the README disagrees with the repository:\n  "
        + "\n  ".join(found)
        + "\n\nRun: python tools/readme_facts.py --write")


def test_roadmap_has_no_duplicate_entries():
    dupes = readme_facts.duplicate_roadmap_entries()
    assert not dupes, f"roadmap lists these more than once: {dupes}"


def test_every_claim_pattern_still_matches_the_readme():
    """A reworded sentence must fail loudly rather than stop being checked.

    A regex that matches nothing reports no mismatch, which would turn this
    whole file into a test that always passes -- the exact failure mode it
    exists to prevent, one level up.
    """
    for claim in readme_facts.CLAIMS:
        assert claim.stated() is not None, (
            f"no sentence in {claim.path.name} matches the {claim.name} claim "
            f"({claim.pattern.pattern!r}); the claim is no longer being checked")


def test_derived_facts_are_plausible():
    """Guards against a derivation that silently returns zero."""
    assert readme_facts.count_tests() > 100
    assert readme_facts.count_sigma_rules() == 9
    assert readme_facts.count_evasions() >= 13
    assert readme_facts.count_checks() == 5
