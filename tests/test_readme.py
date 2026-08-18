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
    assert readme_facts.count_sigma_rules() == 13
    assert readme_facts.count_evasions() >= 13
    # CH01..CH07. CH06 and CH07 arrived with P1 evidence trust and are the
    # first two checks here that read something other than agent behaviour:
    # one asks whether the telemetry verified, the other whether it contradicts
    # itself. See docs/EVIDENCE-TRUST.md.
    assert readme_facts.count_checks() == 7
    assert readme_facts.count_evasion_tests() >= readme_facts.count_evasions() - 2


def test_the_evasion_counts_are_consistent_with_each_other():
    """Every row is a constructed evasion or an unplanned win, and every working
    evasion is a constructed one. If these ever disagree the headline sentence
    is describing a different set of rows than the table under it."""
    assert (readme_facts.count_constructed_evasions()
            <= readme_facts.count_evasions())
    assert (readme_facts.count_working_evasions()
            <= readme_facts.count_constructed_evasions())


def test_only_an_exact_closed_marker_counts_as_closed():
    """A substring test read "Half closed, coverage sees it" as a closure and
    reported one fewer working evasion than the table listed -- the count moving
    in the flattering direction because of a word in a sentence.

    Asserted against the real table rather than a fixture: the point is that the
    rows actually in EVASION.md are classified correctly.
    """
    rows = readme_facts._evasion_rows()
    closed = {e for e, fix in rows.items()
              if not e[-1].isalpha() and fix.strip().strip("*").upper() == "CLOSED"}
    partial = {e for e, fix in rows.items()
               if not e[-1].isalpha() and e not in closed
               and "closed" in fix.lower()}
    assert closed, "no evasion is marked CLOSED; has the table format changed?"
    assert partial, (
        "no evasion is marked as partially closed, so this test is no longer "
        "guarding anything; if that is genuinely the state, delete it")
    assert not (closed & partial)
    assert readme_facts.count_working_evasions() == (
        readme_facts.count_constructed_evasions() - len(closed))


# ---------------------------------------------------------------------------
# COH-R19: the release surface
# ---------------------------------------------------------------------------
#
# A private repository with no governance files cannot become a project anybody
# else contributes to, and the sixth review scored that 2/10. These are cheap to
# add and cheap to delete by accident, so they are asserted like anything else
# this project publishes.

REPO = Path(__file__).resolve().parent.parent

_REQUIRED_DOCS = {
    "SECURITY.md": "how to report a vulnerability privately",
    "CONTRIBUTING.md": "the standards a change is held to",
    "CODE_OF_CONDUCT.md": "conduct, and its enforcement route",
    "CHANGELOG.md": "what changed, and the false-positive rate each release",
    "CITATION.cff": "how to cite this in academic work",
    "LICENSE": "the licence",
    ".github/CODEOWNERS": "who reviews the files a mistake hides in",
    ".github/pull_request_template.md": "the evidence a change has to bring",
    ".github/ISSUE_TEMPLATE/defect.yml": "a defect form that asks for a repro",
    ".github/ISSUE_TEMPLATE/evasion.yml": "an evasion form, because those are "
                                          "contributions rather than bugs",
    ".github/ISSUE_TEMPLATE/config.yml": "the pointer away from public issues "
                                         "for security reports",
}


def test_the_release_surface_exists():
    missing = [f"{name} ({why})" for name, why in _REQUIRED_DOCS.items()
               if not (REPO / name).is_file()]
    assert not missing, "missing release surface:\n  " + "\n  ".join(missing)


def test_the_release_surface_is_not_a_stub():
    """A placeholder file satisfies a checklist and helps nobody."""
    thin = [name for name in _REQUIRED_DOCS
            if len((REPO / name).read_text(encoding="utf-8").split()) < 60]
    assert not thin, f"suspiciously short for what they promise: {thin}"


def test_security_reporting_never_points_at_a_public_issue():
    """The one thing these files must not get wrong. A security policy that
    routes a report into a public tracker publishes the vulnerability."""
    config = (REPO / ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")
    assert "blank_issues_enabled: false" in config, (
        "a blank issue bypasses the forms, including the security routing")
    assert "security/advisories/new" in config
    security = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    assert "private vulnerability reporting" in security.lower()
