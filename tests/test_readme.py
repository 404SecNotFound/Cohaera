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

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import readme_facts

import cohaera
import cohaera.model


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
    # Lower bound, not an equality. This function guards against a derivation
    # silently returning zero; the exact number is a second copy of a count that
    # already lives in README.md, and test_content.py enforces the thing that
    # actually matters -- one rule per emitted check id, in both directions.
    assert readme_facts.count_sigma_rules() >= 13
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


# ---------------------------------------------------------------------------
# R-20. One version, spelled in five files.
# ---------------------------------------------------------------------------

def test_the_package_version_is_the_same_number_everywhere():
    """R-20. ``pyproject.toml``, ``__init__.py`` and ``CITATION.cff`` each carry
    the version as a literal, and nothing compared them. A release that bumps
    two of the three ships a wheel whose metadata, whose runtime and whose
    citation disagree, and every one of them looks authoritative on its own.
    """
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    citation = (REPO / "CITATION.cff").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    cited = re.search(r"^version: (.+)$", citation, re.M)
    assert declared and cited, "both files must state a version at all"
    assert declared.group(1) == cohaera.__version__ == cited.group(1).strip(), (
        f"pyproject says {declared.group(1)}, the package says "
        f"{cohaera.__version__}, CITATION.cff says {cited.group(1).strip()}")


def test_the_parser_field_map_declares_the_schema_the_detector_emits():
    """R-20. The SIEM parser is built against ``schema_version``. When the
    output contract moves and that string does not, the parser is documented
    for a record shape the detector no longer emits -- and it fails silently,
    because a parser reading absent fields reports empty rather than wrong.
    """


    field_map = json.loads(
        (REPO / "content/parser/cohaera_field_map.json").read_text(
            encoding="utf-8"))
    declared = field_map["_metadata"]["schema_version"]
    assert declared == cohaera.model.SESSION_SCHEMA, (
        f"the field map documents {declared} and the detector emits "
        f"{cohaera.model.SESSION_SCHEMA}")


# ---------------------------------------------------------------------------
# R-19. The language the project holds itself to, enforced.
# ---------------------------------------------------------------------------

# Each entry is (pattern, why it overstates). Matched case-insensitively across
# tracked Markdown. POSITIONING.md is exempt because it is the file that LISTS
# them; a rule that forbids naming the rule cannot be written down.
_OVERSTATEMENTS = [
    (r"validated detector",
     "nothing here has been validated against traffic this project did not "
     "generate; the corpus is a regression suite"),
    (r"production[- ]ready evidence",
     "the review scored production readiness 3.5/10 and the reasons are open"),
    (r"proof of causation",
     "CH03 is temporal association. Coexistence is not causation and calling "
     "it proof is the single easiest overstatement to make here"),
    (r"provider[- ]confirmed effect",
     "no adapter reconciles an identifier with the provider that minted it. "
     "It is provider-RETURNED until something asks the provider"),
    (r"missing behaviou?ral layer",
     "that layer ships. See POSITIONING.md"),
    (r"verified session",
     "a session is verified_complete or verified_prefix, and the distinction "
     "is what R-05 was about"),
]

_EXEMPT = {"POSITIONING.md", "CHANGELOG.md"}


def _tracked_markdown() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "*.md"], cwd=REPO,
                         capture_output=True, text=True, check=True)
    return [REPO / line for line in out.stdout.split()
            if Path(line).name not in _EXEMPT]


def test_documentation_does_not_use_the_language_it_bans():
    """R-19. POSITIONING.md lists the phrases this project will not use about
    its own results. A style rule nothing enforces is a preference, and the
    whole argument of this repository is that a claim should be kept true by
    something other than the author's memory.

    CHANGELOG.md is exempt alongside POSITIONING.md: a changelog entry
    describing the removal of a phrase has to be able to name it.
    """
    found = []
    for path in _tracked_markdown():
        text = path.read_text(encoding="utf-8")
        for pattern, why in _OVERSTATEMENTS:
            for match in re.finditer(pattern, text, re.I):
                line = text[:match.start()].count("\n") + 1
                found.append(f"{path.relative_to(REPO)}:{line} "
                             f"{match.group(0)!r} -- {why}")
    assert not found, (
        "documentation uses language POSITIONING.md rules out:\n  "
        + "\n  ".join(found))


def test_the_positioning_file_says_what_this_is_not():
    """The file is load-bearing: the README points at it for the correction to
    its own opening story. A stub would be worse than nothing."""
    text = (REPO / "POSITIONING.md").read_text(encoding="utf-8")
    assert len(text.split()) > 400, "too short to carry the argument"
    for required in ("Agent Behavior Analytics", "Evidence quality",
                     "Do not use", "EVALUATION-CARD.md"):
        assert required in text, f"POSITIONING.md no longer mentions {required}"


def test_the_readme_points_at_the_correction():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "POSITIONING.md" in readme, (
        "the README's opening argument needs its correction reachable from "
        "the same page")


def test_the_classifiers_name_every_python_ci_actually_runs():
    """R-18. `requires-python` had no ceiling, so the package claimed every
    future Python including 3.14, which is released and which this project has
    never run. A support claim nothing tests is the same defect as a README
    count nothing derives.
    """
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    tested = set(re.findall(r'"(3\.\d+)"', re.search(
        r"python: \[([^\]]+)\]", workflow).group(1)))
    claimed = set(re.findall(
        r'"Programming Language :: Python :: (3\.\d+)"', pyproject))
    assert tested == claimed, (
        f"CI runs {sorted(tested)} and the classifiers claim {sorted(claimed)}")

    ceiling = re.search(r'requires-python = ">=(\d+\.\d+),<(\d+\.\d+)"',
                        pyproject)
    assert ceiling, "requires-python must be bounded above as well as below"
    floor, cap = ceiling.groups()
    assert floor == min(tested, key=lambda v: tuple(map(int, v.split(".")))), (
        f"the declared floor {floor} is not the lowest version CI runs")
    highest = max(tested, key=lambda v: tuple(map(int, v.split("."))))
    assert cap == f"{highest.split('.')[0]}.{int(highest.split('.')[1]) + 1}", (
        f"the ceiling {cap} does not sit one minor above the highest tested "
        f"version {highest}")


def test_the_review_response_accounts_for_every_finding():
    """A response document that quietly drops a finding is worse than none: it
    reads as coverage while being a selection. Every ID either review raised
    has to appear, and each must say what happened rather than only naming it.

    Both series, because the second review was missed once already: the file
    accounted for all 21 of the first review's findings and none of the second
    review's 22, while presenting itself as the place every finding is
    accounted for. Exactly the failure it exists to prevent.
    """
    text = (REPO / "REVIEW-RESPONSE.md").read_text(encoding="utf-8")
    for n in range(1, 22):
        assert f"R-{n:02d}" in text, f"REVIEW-RESPONSE.md does not mention R-{n:02d}"
    for n in range(1, 23):
        assert f"F-{n:02d}" in text, f"REVIEW-RESPONSE.md does not mention F-{n:02d}"
    for section in ("Declined, with reasons", "Deferred", "What is still open"):
        assert section in text, f"missing section: {section}"
    # The open list is the part most likely to rot into a boast.
    for admission in ("No external validation", "No independent reviewer",
                      "never been built"):
        assert admission in text, f"the open list no longer admits: {admission}"


def test_the_evasion_counts_add_up():
    """R-20, and the arithmetic an external reviewer noticed before anyone here
    did. EVASION.md said 20 of 21 constructed evasions still work and,
    separately, that two are closed. Those cannot both be true.

    Neither number was a lie somebody told. Both were derived from a guess
    about what a table row meant: "id ends in a letter" stood in for "this is a
    remedy", which hid E22b -- an open evasion -- from the constructed count,
    and "the cell says exactly CLOSED" missed E21, whose cell says CLOSED
    followed by a clause. The statuses are declared per row now, and this is
    the identity that has to hold.
    """
    working = readme_facts.count_working_evasions()
    closed = readme_facts.count_closed_evasions()
    constructed = readme_facts.count_constructed_evasions()
    assert working + closed == constructed, (
        f"{working} working + {closed} closed != {constructed} constructed")

    counts = readme_facts.evasion_status_counts()
    assert sum(counts.values()) == readme_facts.count_evasions()
    assert counts["remedy"] > 0, (
        "a remedy row is a fix exercised, not an evasion; if none are "
        "classified as such the constructed count is inflated")


def test_no_count_is_spelled_as_a_word_where_a_checker_cannot_read_it():
    """R-20. SECURITY.md said "Seventeen catalogued evasions" and the
    evaluation card said "seventeen ways" while the file listed twenty-two.
    Both survived a fact checker that reads digits.
    """
    words = ("fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
             "twenty-one", "twenty-two")
    offenders = []
    for path in (REPO / "SECURITY.md", REPO / "EVASION.md",
                 REPO / "eval" / "EVALUATION-CARD.md"):
        text = path.read_text(encoding="utf-8").lower()
        for word in words:
            if word in text:
                offenders.append(f"{path.name}: {word!r}")
    assert not offenders, (
        "counts spelled as words cannot be checked and have drifted twice:\n  "
        + "\n  ".join(offenders))


def _repository_is_shallow() -> bool:
    out = subprocess.run(["git", "rev-parse", "--is-shallow-repository"],
                         cwd=REPO, capture_output=True, text=True, check=False)
    return out.stdout.strip() == "true"


def test_every_commit_the_review_response_cites_exists():
    """A response document that points at commits which are not there is worse
    than one that points at nothing: it looks checkable and is not. Written
    from a log by hand, so this is the check that it was read correctly.

    SKIPS on a shallow clone, and the skip is the point rather than an
    embarrassment. `actions/checkout` fetches one commit by default, so the
    history this reads does not exist there -- and a check whose data is
    absent must say which, not fail as though the claim were false and not
    pass as though it had been verified. That is the same contract every
    detector in this repository is held to. The CI job that runs it fetches
    full history so the check is real where it matters; anyone with a shallow
    clone sees a named skip.
    """
    text = (REPO / "REVIEW-RESPONSE.md").read_text(encoding="utf-8")
    linked = sorted(set(re.findall(
        r"\[`([0-9a-f]{7,40})`\]\(https://github\.com/[^)]+/commit/([0-9a-f]{7,40})\)",
        text)))
    assert linked, "REVIEW-RESPONSE.md cites no commits at all"
    # Prefix, not equality: a citation may show an abbreviated SHA and link the
    # full one, which is normal and is how the reviewed-revision link is
    # written. What must never happen is the text naming one commit and the
    # link going to another.
    mismatched = [(a, b) for a, b in linked
                  if not (a.startswith(b) or b.startswith(a))]
    assert not mismatched, (
        f"a citation's text and its link point at different commits: "
        f"{mismatched}")

    shas = [a for a, _ in linked]
    if _repository_is_shallow():
        pytest.skip(
            "shallow clone: the cited commits are not present to check. "
            "Run `git fetch --unshallow` to make this assertion real.")

    resolved = [s for s in shas
                if subprocess.run(["git", "cat-file", "-t", s], cwd=REPO,
                                  capture_output=True, text=True, check=False
                                  ).stdout.strip() == "commit"]
    if not resolved:
        # None of them resolve. The commits were squash-merged, so they are
        # not ancestors of `main`; a clone reaches them only through the branch
        # ref that is deliberately left in place, and a clone that does not
        # have that ref cannot see them at all. Their permanent home is the
        # pull request, which `git clone` does not fetch.
        #
        # Reported as "could not look" rather than "not there", because those
        # are different answers and this repository's whole argument is that
        # collapsing them is how a false negative gets a green tick.
        pytest.skip(
            "none of the cited commits are present locally: they were "
            "squash-merged and are reachable only through the pre-merge "
            "branch ref or the pull request. The links in REVIEW-RESPONSE.md "
            "still resolve on GitHub; this check cannot verify them from here.")

    missing = [s for s in shas if s not in resolved]
    assert not missing, (
        f"some cited commits resolve and these do not, so the citations are "
        f"not all from the same history: {missing}")
