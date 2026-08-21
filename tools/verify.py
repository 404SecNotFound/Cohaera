#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Run every gate CI runs, locally, and refuse to call a skipped gate a pass.

``pytest`` is not the build. CI gates on fifteen things and only one of them is
the test suite, so a green ``pytest`` has twice in this repository's history sat
on top of a red CI:

  - the evaluation card quotes the evasion count, so adding evasions left the
    committed card stale while every test passed;
  - the lab manifest records coverage states, so changing a coverage contract
    left the committed manifest stale while every test passed.

Both were generated artefacts going out of date, which no unit test can see.
Neither was a test failure. Both were found by CI after the push, which is the
slowest possible place to find them.

This script is the local replay of that pipeline. Run it before pushing and CI
should hold no surprises.

THE PART THAT MATTERS
---------------------
A gate this script cannot run reports ``not_evaluated`` with a reason, and the
run does **not** come out green. That is the same rule the detector holds itself
to -- a check that cannot run says so, and silence is never scored as clean --
applied to the thing that checks the checker. A verification tool that quietly
skips the four gates whose tools are missing, and then prints a tick, is a false
negative wearing a green tick, which is the failure mode this whole project is
named after.

So: ``ok`` means the gate ran and passed. ``FAIL`` means it ran and failed.
``not_evaluated`` means it did not run, and it is a non-zero exit unless you
pass ``--allow-skips`` and thereby say out loud that you accept the hole.

Usage::

    python tools/verify.py              # every gate
    python tools/verify.py --fast       # skip the slow ones, HONESTLY
    python tools/verify.py --list       # what would run, and why each exists
    python tools/verify.py --only lab readme-facts

The gate list is asserted against ``.github/workflows/ci.yml`` by
``tests/test_verify.py``: a CI step added without a gate here fails the suite.
Without that test this file would drift from CI and become a comfortable lie,
which is worse than not existing.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.metadata
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

PASS = "ok"
FAIL = "FAIL"
SKIP = "not_evaluated"


@dataclasses.dataclass(frozen=True)
class Gate:
    """One CI step, runnable here.

    ``ci_step`` is the ``name:`` of the step in ci.yml this mirrors. It is the
    join key the drift test uses, so it must match that file exactly.
    """

    key: str
    ci_job: str
    ci_step: str
    why: str
    command: list[str]
    requires: tuple[str, ...] = ()
    requires_dists: tuple[str, ...] = ()
    slow: bool = False
    shell: str | None = None


RUNTIME_DEPS_PROBE = """
import importlib.metadata as md
reqs = md.requires("cohaera") or []
runtime = [r for r in reqs if "extra ==" not in r]
assert not runtime, f"runtime dependencies appeared: {runtime}"
print(f"runtime dependencies: 0 ({len(reqs)} optional, all extras)")
"""

GATES: tuple[Gate, ...] = (
    Gate("runtime-deps", "tests", "Runtime dependency check",
         "Zero runtime dependencies is a design commitment. Assert it rather "
         "than hoping. Read from installed metadata, not pyproject.",
         [sys.executable, "-c", RUNTIME_DEPS_PROBE],
         # The probe reads cohaera's INSTALLED metadata, so an uninstalled
         # working copy cannot answer it. Without this line the gate raised
         # PackageNotFoundError and was scored FAIL -- reporting "runtime
         # dependencies appeared" when the truth was "I could not look".
         # That is the precise confusion this repository exists to refuse,
         # committed by the tool that polices it. Declared, it reports
         # not_evaluated:DIST_ABSENT:cohaera and still refuses to pass.
         requires_dists=("cohaera",)),
    Gate("lint", "tests", "Lint",
         "The rule set is pinned in pyproject, so a version bump cannot "
         "silently change what this gate means.",
         ["ruff", "check", "src", "tests", "eval", "tools"],
         requires=("ruff",)),
    Gate("typecheck", "tests", "Type check",
         "src only. The hostile suite constructs ill-typed values by the "
         "hundred; type checking it would prove nothing about the package.",
         ["mypy"], requires=("mypy",)),
    Gate("tests", "tests", "Unit and hostile tests",
         "The suite. Necessary, and on its own not sufficient -- see this "
         "file's docstring for the two defects it cannot see.",
         [sys.executable, "-m", "pytest", "tests/", "-q"], slow=True),
    Gate("evasion", "tests", "Adversarial self-test",
         "Passes when the catalogued evasions still WORK. A failure means "
         "somebody closed a known weakness without updating EVASION.md.",
         [sys.executable, "tests/test_evasion.py"]),
    Gate("fuzz", "malformed-input fuzz", "Fuzz smoke test",
         "A small version of the 50,000-case run that found six exception "
         "classes in the record surface.",
         [sys.executable, "tests/fuzz_smoke.py", "4000"], slow=True),
    Gate("sigma-validate", "sigma validation and conformance",
         "Sigma rule validation",
         "Proves the YAML is well-formed. Says nothing about whether a "
         "backend can compile it -- that is the next gate.",
         ["sigma", "check", "content/sigma/"], requires=("sigma",)),
    Gate("sigma-convert", "sigma validation and conformance",
         "Sigma converts to a real backend",
         "Proves a backend turns the rules into a query. Needs the splunk "
         "plugin: `sigma plugin install splunk`.",
         ["sigma", "convert", "-t", "splunk", "--without-pipeline",
          "content/sigma/"], requires=("sigma",)),
    Gate("content-tests", "sigma validation and conformance",
         "Content conformance",
         "Catches a renamed check ID, which Sigma validation alone cannot.",
         [sys.executable, "-m", "pytest", "tests/test_content.py", "-q"]),
    Gate("eval-card", "sigma validation and conformance",
         "Evaluation corpus regenerates and the card is current",
         "THE FIRST GATE PYTEST CANNOT SEE. The card quotes counts; adding "
         "evasions leaves it stale with every test still passing.",
         [], slow=True,
         shell=("python eval/vocabulary.py && python eval/run_eval.py && "
                "git diff --exit-code -- eval/EVALUATION-CARD.md "
                "eval/evaluation-card.json eval/corpus/sample.jsonl "
                "eval/corpus/sample.labels.jsonl")),
    Gate("demo", "tests", "The demo still demonstrates what it claims",
         "A demo is shown to people and re-run by nobody. If the phantom "
         "guardrail stops being caught, the story is wrong in front of an "
         "audience rather than in CI.",
         [sys.executable, "-m", "pytest", "tests/test_demo.py", "-q"]),
    Gate("lab", "sigma validation and conformance",
         "The local lab still produces what is committed",
         "THE SECOND GATE PYTEST CANNOT SEE. The manifest records coverage "
         "states; changing a contract leaves it stale, silently.",
         [sys.executable, "lab/local/run.py", "--check"]),
    Gate("release-gate", "sigma validation and conformance",
         "The release is internally consistent",
         "Five places name a version. Four agreeing and one not is worse "
         "than five wrong, because the disagreement stays invisible.",
         [sys.executable, "tools/release_gate.py"]),
    Gate("readme-facts", "sigma validation and conformance",
         "README claims match the repository",
         "A number nothing keeps true is the defect class this project "
         "cannot ship. Eight instances found so far.",
         [sys.executable, "tools/readme_facts.py", "--check"]),
    Gate("perf", "amplification regression", "Resource bounds",
         "An amplification regression is an availability fault and would "
         "otherwise only show up in production.",
         [sys.executable, "-m", "pytest", "tests/test_hostile.py", "-q", "-k",
          "amplify or linear or quadratic or bounded"], slow=True),
    Gate("wheel", "build and install the wheel",
         "Install the wheel into a clean environment and run it",
         "Proves the shipped artefact runs, pulls in nothing, and carries "
         "its PEP 561 marker -- none of which the source tree can show.",
         [sys.executable, "tools/verify_wheel.py"],
         requires_dists=("build",), slow=True),
)


def _missing(gate: Gate) -> str | None:
    for tool in gate.requires:
        if shutil.which(tool) is None:
            return f"TOOL_ABSENT:{tool}"
    for dist in gate.requires_dists:
        # Asked of the INSTALLED DISTRIBUTIONS, not by importing. Importing
        # `build` from the repository root succeeds whenever a gitignored
        # `build/` directory is lying around, because `-c` and `-m` put the
        # working directory on sys.path -- so an import probe reports the
        # package present when only a stale output directory is. Distribution
        # metadata cannot be spoofed by a directory name.
        try:
            importlib.metadata.distribution(dist)
        except importlib.metadata.PackageNotFoundError:
            return f"DIST_ABSENT:{dist}"
    return None


def run_gate(gate: Gate, *, fast: bool) -> tuple[str, str, float]:
    """Run one gate. Returns (outcome, detail, seconds)."""
    if fast and gate.slow:
        return SKIP, "SKIPPED_BY_FAST_FLAG", 0.0
    reason = _missing(gate)
    if reason:
        return SKIP, reason, 0.0

    started = time.monotonic()
    if gate.shell:
        proc = subprocess.run(gate.shell, cwd=REPO, shell=True,
                              capture_output=True, text=True, check=False)
    else:
        proc = subprocess.run(gate.command, cwd=REPO,
                              capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - started

    if proc.returncode == 0:
        return PASS, "", elapsed
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    detail = tail[-1][:200] if tail else f"exit {proc.returncode}"
    return FAIL, detail, elapsed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fast", action="store_true",
                    help="Skip the slow gates. They report not_evaluated, not "
                         "passed, and the run is still non-zero without "
                         "--allow-skips.")
    ap.add_argument("--allow-skips", action="store_true",
                    help="Exit 0 even when gates could not run. Say this out "
                         "loud rather than reading a hole as a green build.")
    ap.add_argument("--only", nargs="+", metavar="KEY",
                    help="Run only these gates, by key.")
    ap.add_argument("--list", action="store_true",
                    help="Print the gates and why each exists, and stop.")
    args = ap.parse_args(argv)

    gates = GATES
    if args.only:
        unknown = set(args.only) - {g.key for g in GATES}
        if unknown:
            print(f"unknown gate(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"known: {', '.join(g.key for g in GATES)}", file=sys.stderr)
            return 2
        gates = tuple(g for g in GATES if g.key in set(args.only))

    if args.list:
        for gate in gates:
            mark = " [slow]" if gate.slow else ""
            print(f"{gate.key}{mark}\n    ci: {gate.ci_job} / {gate.ci_step}"
                  f"\n    {gate.why}\n")
        return 0

    print(f"verifying {len(gates)} gate(s) against the CI pipeline\n")
    results: list[tuple[Gate, str, str, float]] = []
    for gate in gates:
        print(f"  {gate.key:<15} ", end="", flush=True)
        outcome, detail, elapsed = run_gate(gate, fast=args.fast)
        suffix = f"  ({elapsed:.1f}s)" if elapsed else ""
        print(f"{outcome}{suffix}" + (f"  {detail}" if detail and outcome == FAIL
                                      else f"  {detail}" if detail else ""))
        results.append((gate, outcome, detail, elapsed))

    failed = [r for r in results if r[1] == FAIL]
    skipped = [r for r in results if r[1] == SKIP]
    passed = [r for r in results if r[1] == PASS]

    print(f"\n{len(passed)} passed, {len(failed)} failed, "
          f"{len(skipped)} not evaluated")

    if failed:
        print("\nFAILED:")
        for gate, _, detail, _ in failed:
            print(f"  {gate.key} -- mirrors CI step "
                  f"{gate.ci_job!r} / {gate.ci_step!r}")
            print(f"      {detail}")

    if skipped:
        print("\nNOT EVALUATED -- these gates did not run, so this is not a "
              "green build:")
        for gate, _, reason, _ in skipped:
            print(f"  {gate.key:<15} {reason}")

    if failed:
        return 1
    if skipped and not args.allow_skips:
        print("\nExiting non-zero because a gate could not run. Pass "
              "--allow-skips to accept the hole deliberately.")
        return 1
    print("\nEvery gate that ran, passed." if skipped
          else "\nEvery CI gate passed locally.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
