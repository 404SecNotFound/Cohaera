#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Refuse a release whose parts disagree about which release it is.

    python tools/release_gate.py            # check the working tree
    python tools/release_gate.py --tag v0.3.0   # and that a tag matches it

WHY THIS EXISTS
---------------
R-18, the half that a reproducible build does not cover. `SOURCE_DATE_EPOCH`
makes the wheel a function of the source, so two builds of one commit are
byte-identical. It says nothing about whether that commit is internally
consistent about its own version.

Five places name a version and nothing compared them:

    pyproject.toml          what pip installs
    src/cohaera/__init__.py what the running code reports
    CITATION.cff            what a citation resolves to
    CHANGELOG.md            what a human reads to decide whether to upgrade
    the git tag             what everything else is fetched by

A release where four agree and one does not is worse than one where all five
are wrong, because the disagreement is invisible until somebody is debugging
production against the wrong changelog.

The OUTPUT schema is checked separately and deliberately does not have to match
the package version -- they move for different reasons, and conflating them
would force a schema bump on every patch release. What is checked is that the
changelog SAYS which schema this release emits, so a SIEM operator reading it
learns whether their parser still works.

Exit 0 if everything agrees, 1 with the disagreement named otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from cohaera import __version__ as RUNTIME_VERSION  # noqa: E402
from cohaera.model import SESSION_SCHEMA  # noqa: E402


def _search(path: Path, pattern: str) -> str | None:
    hit = re.search(pattern, path.read_text(encoding="utf-8"), re.M)
    return hit.group(1).strip() if hit else None


def problems(tag: str | None = None) -> list[str]:
    found: list[str] = []

    declared = {
        "pyproject.toml": _search(REPO / "pyproject.toml",
                                  r'^version = "([^"]+)"'),
        "src/cohaera/__init__.py": RUNTIME_VERSION,
        "CITATION.cff": _search(REPO / "CITATION.cff", r"^version: (.+)$"),
    }
    missing = [k for k, v in declared.items() if not v]
    if missing:
        found.append(f"no version found in: {', '.join(missing)}")
        return found

    if len(set(declared.values())) != 1:
        found.append("the sources disagree about the version: "
                     + ", ".join(f"{k} says {v}" for k, v in declared.items()))
        return found

    version = next(iter(declared.values()))

    # The changelog has to carry a section for this exact version, and it must
    # not still be sitting under Unreleased -- which is the state every one of
    # these files was in for the whole of 0.3.0's development.
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{version}]" not in changelog:
        found.append(
            f"CHANGELOG.md has no `## [{version}]` section, so this release "
            f"has no notes. If the work is still in progress it should not be "
            f"tagged; if it is done, move it out of Unreleased.")
    if f"[{version}]: https://" not in changelog:
        found.append(f"CHANGELOG.md has no link definition for [{version}]")

    # A detection release states its false-positive rate. The file's own
    # preamble promises this, and a promise nothing checks is a preference.
    section = changelog.split(f"## [{version}]", 1)[-1].split("\n## [", 1)[0]
    if "per 1,000 benign" not in section and "per 1000 benign" not in section:
        found.append(
            f"the [{version}] section does not state a false-positive rate per "
            f"1,000 BENIGN sessions. This file's preamble says a detection "
            f"release that only reports recall is a marketing document.")

    # The output contract is what a SIEM parser is built against. It need not
    # match the package version; it must be stated.
    if SESSION_SCHEMA not in changelog:
        found.append(
            f"CHANGELOG.md never names the output schema {SESSION_SCHEMA!r}, "
            f"so a parser author cannot tell from it whether their integration "
            f"still works")

    if tag is not None:
        if not tag.startswith("v"):
            found.append(f"tag {tag!r} does not start with 'v'")
        elif tag[1:] != version:
            found.append(f"tag {tag!r} does not match the declared version "
                         f"{version}")

    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", help="the tag about to be created, e.g. v0.3.0")
    args = ap.parse_args(argv)

    found = problems(args.tag)
    if found:
        print("this release is not internally consistent:", file=sys.stderr)
        for line in found:
            print(f"  - {line}", file=sys.stderr)
        return 1
    version = _search(REPO / "pyproject.toml", r'^version = "([^"]+)"')
    print(f"release {version} is consistent across pyproject, the package, "
          f"CITATION.cff and CHANGELOG.md"
          + (f", and matches tag {args.tag}" if args.tag else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
