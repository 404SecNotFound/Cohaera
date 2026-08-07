#!/usr/bin/env python3
"""Derive the counted claims in README.md and EVASION.md, and check them.

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
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
EVASION = REPO / "EVASION.md"
SIGMA = REPO / "content" / "sigma"
CHECKS = REPO / "src" / "cohaera" / "checks.py"

_COLLECTED = re.compile(r"(\d+) tests? collected")
_EVASION_ROW = re.compile(r"^\|\s*(E\d+[a-z]?)\s*\|", re.MULTILINE)
_CHECK_ID = re.compile(r'"(CH\d+)_[a-z_]+"')


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


def count_evasions() -> int:
    """Rows in EVASION.md's summary table, including the two unplanned wins."""
    return len(set(_EVASION_ROW.findall(EVASION.read_text(encoding="utf-8"))))


def count_checks() -> int:
    """Distinct CH-prefixed check families implemented in checks.py."""
    return len(set(_CHECK_ID.findall(CHECKS.read_text(encoding="utf-8"))))


@dataclass(frozen=True)
class Claim:
    """One counted statement in a committed document, and where the truth is."""

    name: str
    path: Path
    pattern: re.Pattern[str]        # exactly one group, capturing the number
    truth: Callable[[], int]

    def text(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def stated(self, text: str | None = None) -> int | None:
        hit = self.pattern.search(self.text() if text is None else text)
        return int(hit.group(1)) if hit else None


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
        stated, actual = claim.stated(), claim.truth()
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
        stated, actual = claim.stated(text), claim.truth()
        if stated is None or stated == actual:
            continue
        hit = claim.pattern.search(text)
        assert hit is not None
        lo, hi = hit.span(1)
        claim.path.write_text(text[:lo] + str(actual) + text[hi:], encoding="utf-8")
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
