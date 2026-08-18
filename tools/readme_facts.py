#!/usr/bin/env python3
"""Derive the counted claims in README.md, EVASION.md, SECURITY.md, CHANGELOG.md.

C4-11. The README said "Tests, 188 passing" against a tree with 197, and listed
"CH02 semantic matching" twice in the same roadmap. Neither is dangerous on its
own. Both are the same failure, and it is the one failure this project cannot
afford: a number in the documentation that nothing keeps true.

The repository already treats committed configuration that NAMES something as
something to check against the thing it names -- ``tests/test_content.py``
asserts every field the Sigma pack references exists in a real verdict record,
``tests/test_ci_config.py`` asserts the branch ruleset's required checks match
the CI jobs that report them. A claim about how many tests pass is the same kind
of statement and gets the same treatment.

So the counts are DERIVED here and the documents are checked against them:

    python tools/readme_facts.py            # print the derived facts
    python tools/readme_facts.py --check    # exit 1 if a document disagrees
    python tools/readme_facts.py --write    # update the counts in place

``tests/test_readme.py`` runs ``--check`` on every test run, so the claim cannot
drift for longer than it takes to run the suite once. Prose stays prose: each
claim is a regex with one capture group over the sentence a human wrote, not a
generated block, because a generated block is a thing people learn to skip.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
EVASION = REPO / "EVASION.md"
SECURITY = REPO / "SECURITY.md"
CHANGELOG = REPO / "CHANGELOG.md"
SIGMA = REPO / "content" / "sigma"
CHECKS = REPO / "src" / "cohaera" / "checks.py"

_COLLECTED = re.compile(r"(\d+) tests? collected")
_EVASION_ID = re.compile(r"E\d+[a-z]?")
_CHECK_ID = re.compile(r'"(CH\d+)_[a-z_]+"')
_EVASION_TEST = re.compile(r"^def (test_evasion_\w+)\(", re.MULTILINE)


# ---------------------------------------------------------------------------
# The facts, each derived from the tree rather than from another document
# ---------------------------------------------------------------------------


def count_tests() -> int:
    """Collected tests, which is what "N passing" means when the suite is green.

    Collection rather than execution: it is the same number, it takes a tenth of
    the time, and it does not recurse when this runs from inside a test.
    """
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=REPO, capture_output=True, text=True, check=False)
    hit = _COLLECTED.search(out.stdout)
    if not hit:
        raise RuntimeError(
            "could not read a test count from pytest --collect-only:\n"
            f"{out.stdout[-2000:]}\n{out.stderr[-2000:]}")
    return int(hit.group(1))


def count_sigma_rules() -> int:
    return len([p for p in SIGMA.glob("*.yml")] + [p for p in SIGMA.glob("*.yaml")])


def _evasion_rows() -> dict[str, str]:
    """``{id: last cell}`` for every row of EVASION.md's summary table.

    The last cell is the fixability column, and it is where a closed evasion is
    marked. Read from the table rather than from a list kept here, so adding a
    row is the only thing anyone has to remember to do.
    """
    rows: dict[str, str] = {}
    for line in EVASION.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and _EVASION_ID.fullmatch(cells[0]):
            rows[cells[0]] = cells[-1]
    return rows


def count_evasions() -> int:
    """Rows in EVASION.md's summary table, including the two unplanned wins."""
    return len(_evasion_rows())


def count_constructed_evasions() -> int:
    """Rows that are an attack somebody wrote, so not the ``E12b``-style wins."""
    return len([e for e in _evasion_rows() if not e[-1].isalpha()])


def count_working_evasions() -> int:
    """Constructed evasions that have not been closed.

    Only a cell that says exactly CLOSED counts as closed. A substring test read
    "Half closed, coverage sees it" as a closure and quietly reported one fewer
    working evasion than the file listed -- the number moving in the flattering
    direction because of a word in a sentence, which is the drift this whole
    module exists to prevent.

    This number is supposed to be able to go UP. An evasion catalogue whose
    headline count only ever falls is a catalogue nobody is adding to.
    """
    return len([e for e, fix in _evasion_rows().items()
                if not e[-1].isalpha() and fix.strip().strip("*").upper() != "CLOSED"])


def count_evasion_tests() -> int:
    """Test functions in tests/test_evasion.py."""
    path = REPO / "tests" / "test_evasion.py"
    return len(_EVASION_TEST.findall(path.read_text(encoding="utf-8")))


# ---- numbers the README quotes from the evaluation card -------------------
#
# The README's "Measured results" table is a hand-copy of one cell of
# eval/evaluation-card.json, and by the time anyone checked, every figure in it
# was from a corpus revision two changes back: 768 sessions when there were 960,
# a 60.6% false positive rate when the card said 63.7%. The card is generated
# and the README is not, so the card is the truth and these read it.

CARD = REPO / "eval" / "evaluation-card.json"
HEADLINE = "unseen|task_disjoint|manifest"


def _card() -> dict:
    return json.loads(CARD.read_text(encoding="utf-8"))


def _metrics(cell: str = HEADLINE) -> dict:
    return _card()["cells"][cell]["metrics"]


def card_sessions_per_condition() -> int:
    return int(_card()["corpus"]["conditions"]["unseen"]["sessions"])


def card_tasks() -> int:
    return int(_card()["corpus"]["conditions"]["unseen"]["tasks"])


def card_headline_recall_pct() -> str:
    """The ATTRIBUTABLE figure, after C5-01.

    ``recall`` counts an attack as caught when anything fired; this counts it
    only when the check the corpus holds responsible for that behaviour fired.
    On the headline cell the two agree, and on family_holdout they do not,
    which is exactly why the README has to quote the stricter one.
    """
    return f"{_metrics()['target_attributable_recall']['value']:.0%}".rstrip("%")


def card_headline_fpr_pct() -> str:
    return f"{_metrics()['false_positive_rate']['value'] * 100:.1f}"


def card_headline_fp_per_1000() -> str:
    return f"{_metrics()['false_positives_per_1000_sessions']:.0f}"


def card_name_only_recall_pct() -> str:
    m = _metrics("unseen|task_disjoint|name_only")
    return f"{m['target_attributable_recall']['value'] * 100:.1f}"


def card_family_holdout_fpr_pct() -> str:
    m = _metrics("unseen|family_holdout|manifest")
    return f"{m['false_positive_rate']['value'] * 100:.1f}"


def card_family_holdout_recall_pct() -> str:
    """Attributable, and this is the claim the fifth review corrected.

    Any-alert recall in this regime reads 88.2% because CH02 and CH05 fire on
    attacks CH01 declined. Quoting that would say CH01 kept its recall after
    switching itself off.
    """
    m = _metrics("unseen|family_holdout|manifest")
    return f"{m['target_attributable_recall']['value'] * 100:.1f}"


def card_e02_confounder_cost() -> int:
    """False positives the closed E02 fix costs, on the kind it costs them on.

    The README summarises the one closed evasion as costing N new false
    positives. That N is a measured figure that moves with the corpus -- it has
    already gone 16 -> 32 -- and prose is where measured figures go to rot.
    """
    return int(_card()["cells"][HEADLINE]["by_kind"]
               ["benign_hard_long_rare_action"]["flagged"])


def corpus_attack_shapes() -> int:
    """How many distinct attack kinds the corpus actually generates.

    Hand-written as "all five attack shapes caught" and left at five when a
    sixth was added. It is the same fault as the "15 of 15" over a 19-row table:
    a count in prose that nothing recomputes is a count that will be wrong the
    first time the thing it counts changes.

    Read off the card rather than imported from the generator, so this module
    keeps needing nothing but the JSON on disk.
    """
    by_kind = _card()["cells"][HEADLINE]["by_kind"]
    return sum(1 for kind in by_kind if kind.startswith("attack"))


def _plain_benign() -> tuple[int, int]:
    """(flagged, total) over the benign kinds that are NOT confounders.

    Keyed on the corpus's own naming convention -- ``benign_hard_*`` is a
    confounder, anything else beginning ``benign`` is a control -- so adding a
    control kind updates this without anyone remembering to. The claim it backs
    is the strongest single sentence the README makes about false positives, and
    it is the one most worth catching if it stops being true.
    """
    by_kind = _card()["cells"][HEADLINE]["by_kind"]
    plain = [v for k, v in by_kind.items()
             if k.startswith("benign") and "hard" not in k]
    return sum(v["flagged"] for v in plain), sum(v["sessions"] for v in plain)


def card_plain_benign_flagged() -> int:
    return _plain_benign()[0]


def card_plain_benign_total() -> int:
    return _plain_benign()[1]


def count_checks() -> int:
    """Distinct CH-prefixed check families implemented in checks.py."""
    return len(set(_CHECK_ID.findall(CHECKS.read_text(encoding="utf-8"))))


@dataclass(frozen=True)
class Claim:
    """One counted statement in a committed document, and where the truth is.

    ``truth`` returns whatever the number is; comparison and rewriting are on
    its string form. That is what lets a claim be ``63.7`` as easily as ``294``,
    which matters because the README's headline results are percentages copied
    out of the evaluation card by hand, and every one of them was stale.
    """

    name: str
    path: Path
    pattern: re.Pattern[str]        # exactly one group, capturing the number
    truth: Callable[[], object]

    def text(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def stated(self, text: str | None = None) -> str | None:
        hit = self.pattern.search(self.text() if text is None else text)
        return hit.group(1) if hit else None

    def actual(self) -> str:
        return str(self.truth())


CLAIMS = (
    Claim("README tests passing", README,
          re.compile(r"Tests, (\d+) passing across unit"), count_tests),
    Claim("README Sigma rules", README,
          re.compile(r"Sigma content pack, (\d+) rules"), count_sigma_rules),
    Claim("README catalogued evasions", README,
          re.compile(r"Adversarial self-test, (\d+) evasions"), count_evasions),
    # EVASION.md carries the same count in prose and drifted the same way.
    Claim("EVASION.md tests", EVASION,
          re.compile(r"There are now (\d+) tests"), count_tests),
    Claim("EVASION.md evasion characterizations", EVASION,
          re.compile(r"(\d+) evasion characterizations"), count_evasions),
    # The headline of the whole file, and until now nothing kept it true: it
    # still read "15 of 15" with nineteen rows in the table under it. Two
    # claims because the sentence carries two numbers and each has its own
    # source.
    Claim("EVASION.md working evasions", EVASION,
          re.compile(r"Current state: (\d+) of \d+ constructed evasions"),
          count_working_evasions),
    Claim("EVASION.md constructed evasions", EVASION,
          re.compile(r"Current state: \d+ of (\d+) constructed evasions"),
          count_constructed_evasions),
    Claim("README constructed evasions", README,
          re.compile(r"(\d+) constructed evasions"), count_constructed_evasions),
    # SECURITY.md carried the same two numbers in words -- "seventeen ways ...
    # sixteen of which" -- against a tree with twenty and nineteen. Words are
    # why it was not caught: nothing here can check a claim spelled out in
    # prose, so the sentence now uses digits and joins the table. The lesson is
    # the C4-11 one for the third time: a number in a document that nothing
    # derives is a number that is already wrong.
    Claim("SECURITY.md constructed evasions", SECURITY,
          re.compile(r"catalogues (\d+) constructed ways"),
          count_constructed_evasions),
    Claim("CHANGELOG constructed evasions", CHANGELOG,
          re.compile(r"\*\*(\d+) constructed evasions are catalogued"),
          count_constructed_evasions),
    Claim("CHANGELOG working evasions", CHANGELOG,
          re.compile(r"constructed evasions are catalogued and (\d+) still work"),
          count_working_evasions),
    Claim("SECURITY.md working evasions", SECURITY,
          re.compile(r"catalogues \d+ constructed ways to defeat its checks,\s+(\d+)\s+of which currently work"),
          count_working_evasions),
    # \s+ rather than a literal space: these sentences are hard-wrapped prose and
    # a claim that stops matching when somebody rewraps a paragraph is a claim
    # that silently stops being checked.
    Claim("README working evasions", README,
          re.compile(r"(\d+) of them still\s+working"), count_working_evasions),
    # COH-R19 again, in the file that is most about being honest. This sentence
    # spelled its number in words and read "Twenty" against a real count of 19.
    Claim("EVASION.md working evasions in prose", EVASION,
          re.compile(r"(\d+)\s+working evasions is a worse-looking number"),
          count_working_evasions),
    Claim("README evasion test count", README,
          re.compile(r"test_evasion\.py\s+(\d+) adversarial tests"),
          count_evasion_tests),
    # The headline results, read out of the generated card rather than retyped.
    Claim("README corpus sessions", README,
          re.compile(r"(\d+) sessions per condition"), card_sessions_per_condition),
    Claim("README corpus tasks", README,
          re.compile(r"(\d+) tasks across 8 task families"), card_tasks),
    Claim("README headline recall", README,
          re.compile(r"\| recall \| \*\*(\d+)%\*\*"), card_headline_recall_pct),
    Claim("README headline false positive rate", README,
          re.compile(r"\| false positive rate \| \*\*([\d.]+)%\*\*"),
          card_headline_fpr_pct),
    Claim("README headline FP per 1000", README,
          re.compile(r"\| false positives per 1000 sessions \| \*\*(\d+)\*\*"),
          card_headline_fp_per_1000),
    Claim("README name-only recall", README,
          re.compile(r"recall falls to ([\d.]+)%"), card_name_only_recall_pct),
    Claim("README family_holdout false positive rate", README,
          re.compile(r"the\s+false positive rate is ([\d.]+)%"),
          card_family_holdout_fpr_pct),
    Claim("README E02 confounder cost", README,
          re.compile(r"which cost (\d+) new false positives"),
          card_e02_confounder_cost),
    Claim("README family_holdout recall", README,
          re.compile(r"recall drops to ([\d.]+)%"), card_family_holdout_recall_pct),
    Claim("README attack shapes", README,
          re.compile(r"all (\d+) attack shapes caught"), corpus_attack_shapes),
    Claim("README plain-benign false positives", README,
          re.compile(r"\*plain\* benign sessions \| \*\*(\d+) / \d+\*\*"),
          card_plain_benign_flagged),
    Claim("README plain-benign session count", README,
          re.compile(r"\*plain\* benign sessions \| \*\*\d+ / (\d+)\*\*"),
          card_plain_benign_total),
)


# ---------------------------------------------------------------------------
# Structural checks that are not counts
# ---------------------------------------------------------------------------


def roadmap_entries() -> list[str]:
    """Every roadmap line, normalised to its text so duplicates are visible."""
    text = README.read_text(encoding="utf-8")
    start = text.find("\n## Roadmap")
    if start < 0:
        raise RuntimeError("README has no '## Roadmap' section")
    end = text.find("\n## ", start + 1)
    body = text[start:end if end > 0 else len(text)]
    out = []
    for line in body.splitlines():
        hit = re.match(r"- \[[ x]\] (.+)", line.strip())
        if hit:
            # Compare on the claim itself, not on the links or emphasis around
            # it: "CH02 semantic matching, currently lexical..." and "CH02
            # semantic matching" are the same roadmap item stated twice.
            out.append(hit.group(1).split(",")[0].split("(")[0].strip().rstrip("*."))
    return out


def duplicate_roadmap_entries() -> list[str]:
    seen: dict[str, int] = {}
    for entry in roadmap_entries():
        seen[entry.lower()] = seen.get(entry.lower(), 0) + 1
    return sorted(k for k, n in seen.items() if n > 1)


# ---------------------------------------------------------------------------


def problems() -> list[str]:
    """Every way the committed documents currently disagree with the repository."""
    out = []
    for claim in CLAIMS:
        stated, actual = claim.stated(), claim.actual()
        if stated is None:
            out.append(f"{claim.name}: no sentence matching "
                       f"{claim.pattern.pattern!r} found in {claim.path.name}")
        elif stated != actual:
            out.append(f"{claim.name}: {claim.path.name} says {stated}, "
                       f"repository has {actual}")
    for dupe in duplicate_roadmap_entries():
        out.append(f"roadmap: {dupe!r} is listed more than once")
    return out


def write() -> list[str]:
    """Rewrite the counted claims in place. Structural problems are not fixable."""
    changed = []
    for claim in CLAIMS:
        text = claim.text()
        stated, actual = claim.stated(text), claim.actual()
        if stated is None or stated == actual:
            continue
        hit = claim.pattern.search(text)
        assert hit is not None
        lo, hi = hit.span(1)
        claim.path.write_text(text[:lo] + actual + text[hi:], encoding="utf-8")
        changed.append(f"{claim.name}: {stated} -> {actual}")
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if a document disagrees with the repository")
    ap.add_argument("--write", action="store_true",
                    help="update the counted claims in place")
    args = ap.parse_args(argv)

    if args.write:
        for line in write() or ["nothing to update"]:
            print(line)
        remaining = [p for p in problems()]
        for line in remaining:
            print(f"STILL WRONG (not auto-fixable): {line}")
        return 1 if remaining else 0

    found = problems()
    if args.check:
        for line in found:
            print(f"documentation is out of date: {line}", file=sys.stderr)
        if found:
            print("\nRun: python tools/readme_facts.py --write", file=sys.stderr)
        return 1 if found else 0

    for claim in CLAIMS:
        print(f"{claim.name}: {claim.truth()}")
    print(f"check families: {count_checks()}")
    for line in found:
        print(f"  MISMATCH: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
