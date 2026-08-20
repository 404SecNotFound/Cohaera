# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""The local verifier must not drift from the pipeline it claims to replay.

``tools/verify.py`` exists so a developer can run what CI runs before pushing.
That promise has a decay mode: somebody adds a CI step, does not add a gate,
and the local run keeps printing a tick while CI gains a check nobody replays.
The tool is then worse than absent, because absent tools do not reassure.

So the join is asserted here. Every named step in ``.github/workflows/ci.yml``
must either be mirrored by a gate or be named in ``NOT_A_LOCAL_GATE`` with a
reason. A new step matching neither fails this test, and the failure names the
step.

The workflow is read with a regex rather than a YAML parser on purpose: PyYAML
lives in the ``content`` extra, and the job that runs this file installs only
``dev``. A test that silently skips when a parser is missing is exactly the
failure mode this repository is about, so the dependency is removed instead.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from verify import GATES, Gate, _missing  # noqa: E402

CI = REPO / ".github" / "workflows" / "ci.yml"

# Steps that are real CI work but cannot or should not be a local gate. Each
# entry carries the reason; an entry without one is not allowed to exist.
NOT_A_LOCAL_GATE = {
    "Install":
        "Environment setup, not a gate. Locally this is your virtualenv.",
    "Build, reproducibly, and record what was built":
        "Subsumed by the 'wheel' gate, which builds with the same pinned "
        "SOURCE_DATE_EPOCH before installing what it built.",
    "Generate fixtures":
        "Subsumed by the 'wheel' gate, which generates fixtures before "
        "scoring one with the installed entry point.",
    "The installed package carries its PEP 561 marker":
        "Subsumed by the 'wheel' gate, which probes py.typed on the "
        "installed package as its final step.",
    "Generate an SBOM for the built artefact":
        "Requires the CI artefact-upload path and a release context. The "
        "property it protects -- that the SBOM describes the wheel that "
        "shipped -- is not reproducible from a working tree.",
    "The SBOM describes the wheel, and the wheel has no dependencies":
        "Same. Its zero-dependency half is covered locally by the "
        "'runtime-deps' gate and by the 'wheel' gate's install probe.",
}


def _ci_step_names() -> list[str]:
    text = CI.read_text(encoding="utf-8")
    return re.findall(r"^\s+- name: (.+)$", text, re.M)


def test_the_workflow_is_readable_and_has_steps():
    """A control. If the regex stops matching, every assertion below passes
    vacuously and this file becomes decoration."""
    names = _ci_step_names()
    assert len(names) >= 15, f"only found {len(names)} CI steps; parser broke"


def test_every_ci_step_is_mirrored_by_a_gate_or_explained():
    mirrored = {g.ci_step for g in GATES}
    unexplained = [n for n in _ci_step_names()
                   if n not in mirrored and n not in NOT_A_LOCAL_GATE]
    assert not unexplained, (
        "CI steps with no local gate and no recorded reason: "
        f"{unexplained}. Add a Gate to tools/verify.py, or add the step to "
        "NOT_A_LOCAL_GATE with why it cannot run locally.")


def test_no_gate_claims_a_ci_step_that_does_not_exist():
    """The other direction. A renamed CI step must not leave a gate pointing
    at nothing, because such a gate silently stops corresponding to anything
    while continuing to run and pass."""
    names = set(_ci_step_names())
    orphans = [g.key for g in GATES if g.ci_step not in names]
    assert not orphans, (
        f"gates naming a CI step that no longer exists: {orphans}")


def test_gate_keys_are_unique():
    keys = [g.key for g in GATES]
    assert len(keys) == len(set(keys)), f"duplicate gate keys in {keys}"


def test_every_gate_records_why_it_exists():
    """A gate without a reason is a command somebody will delete."""
    for gate in GATES:
        assert len(gate.why) > 40, f"{gate.key}: 'why' is too thin to be useful"


def test_a_gate_is_either_a_command_or_a_shell_line_but_not_neither():
    for gate in GATES:
        assert gate.command or gate.shell, f"{gate.key}: nothing to run"


def test_the_exemption_list_carries_no_dead_entries():
    """An exemption for a step that no longer exists hides the next one.

    If a CI step is renamed and its stale exemption stays, a genuinely new
    step can inherit the old name and be exempted by accident.
    """
    names = set(_ci_step_names())
    dead = sorted(set(NOT_A_LOCAL_GATE) - names)
    assert not dead, f"exemptions for CI steps that no longer exist: {dead}"


def test_a_missing_tool_is_not_evaluated_rather_than_passed():
    """The doctrine, applied to the verifier.

    A gate whose tool is absent must report a reason, never silently succeed.
    Asserted on a synthetic gate so the test does not depend on which tools
    happen to be installed on the machine running it.
    """
    absent_binary = Gate("synthetic", "job", "step", "x" * 50,
                         ["definitely-not-a-real-binary"],
                         requires=("definitely-not-a-real-binary",))
    assert _missing(absent_binary) == "TOOL_ABSENT:definitely-not-a-real-binary"

    absent_dist = Gate("synthetic", "job", "step", "x" * 50, ["true"],
                       requires_dists=("definitely-not-a-real-distribution",))
    assert _missing(absent_dist) == (
        "DIST_ABSENT:definitely-not-a-real-distribution")

    satisfiable = Gate("synthetic", "job", "step", "x" * 50, ["true"])
    assert _missing(satisfiable) is None


def test_a_present_directory_does_not_count_as_an_installed_distribution():
    """Regression, and the reason ``requires_dists`` is not an import probe.

    A gitignored ``build/`` directory in the repository root makes
    ``import build`` succeed from the working tree, because ``-c`` and ``-m``
    put the working directory on ``sys.path``. An import-based probe therefore
    reports pypa/build present when only a stale output directory is, and the
    wheel gate then fails with "'build' is a package and cannot be directly
    executed" -- a message naming neither the shadowing nor the cause.

    Distribution metadata is not fooled by a directory, which is why the check
    asks that instead.
    """
    fake_dist = Gate("synthetic", "job", "step", "x" * 50, ["true"],
                     requires_dists=("build-directory-not-a-distribution",))
    assert _missing(fake_dist) is not None


@pytest.mark.parametrize("gate", GATES, ids=lambda g: g.key)
def test_each_gate_names_a_real_ci_job(gate: Gate):
    text = CI.read_text(encoding="utf-8")
    assert f"name: {gate.ci_job}" in text, (
        f"{gate.key} claims CI job {gate.ci_job!r}, which is not in ci.yml")


def test_the_lint_gate_covers_what_contributing_says_it_covers():
    """A documented gate that CI does not run is a promise nothing keeps.

    CONTRIBUTING names `ruff check src tests eval tools` as the gate. CI ran
    `ruff check src tests` for long enough that `eval/` and `tools/` -- the
    evaluation harness, the release gate, the claims checker -- were documented
    as linted and were not. Nothing looked wrong, because the document was
    describing an intention and the workflow was describing behaviour.

    Asserting the two against each other is cheaper than noticing.
    """
    ci = CI.read_text(encoding="utf-8")
    contributing = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")

    ci_lint = re.search(r"^\s+ruff check (.+)$", ci, re.M)
    assert ci_lint, "no `ruff check` line in ci.yml"
    ci_paths = set(ci_lint.group(1).split())

    doc_lint = re.search(r"ruff check ([\w/ ]+)", contributing)
    assert doc_lint, "no `ruff check` line in CONTRIBUTING.md"
    doc_paths = set(doc_lint.group(1).split())

    assert ci_paths == doc_paths, (
        f"CI lints {sorted(ci_paths)} but CONTRIBUTING promises "
        f"{sorted(doc_paths)}")

    gate = next(g for g in GATES if g.key == "lint")
    assert set(gate.command[2:]) == ci_paths, (
        f"the local lint gate covers {sorted(set(gate.command[2:]))}, CI "
        f"covers {sorted(ci_paths)}")
