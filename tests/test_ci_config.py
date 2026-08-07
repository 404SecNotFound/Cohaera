"""The committed branch ruleset must match the CI jobs it names.

`.github/rulesets/main.json` lists nine required status checks by name. Those
names come from `.github/workflows/ci.yml`, with the test matrix expanded. There
is nothing on either side that keeps them in step.

The failure is silent and points the wrong way. A required status check that no
job ever reports does NOT error and does NOT get skipped: it stays permanently
pending, so every pull request is blocked forever, and the reason is invisible
unless you already know the ruleset exists. Rename a CI job and you have locked
the repository with no error message anywhere.

So this asserts the two agree. Same idea as tests/test_content.py, which asserts
every field the Sigma pack references exists in a real verdict record: committed
configuration that names something should be checked against the thing it names,
because the alternative is finding out from a symptom rather than from a test.

Requires PyYAML, a dev dependency. The runtime still has none.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML is a dev dependency")

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
RULESET = REPO / ".github" / "rulesets" / "main.json"

_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")


def load_workflow() -> dict:
    # "on:" is parsed by YAML 1.1 as the boolean True, which is a wart rather
    # than a problem here: nothing below touches it.
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def load_ruleset() -> dict:
    return json.loads(RULESET.read_text(encoding="utf-8"))


def expected_check_names(workflow: dict) -> set[str]:
    """The check-run names GitHub will report for this workflow.

    Expands single-axis matrices, which is all ci.yml uses. A multi-axis matrix
    would need the cartesian product; rather than half-implement that and quietly
    produce wrong names, this fails loudly so whoever adds one updates this
    function deliberately.
    """
    names: set[str] = set()
    for job_id, job in (workflow.get("jobs") or {}).items():
        template = job.get("name", job_id)
        matrix = ((job.get("strategy") or {}).get("matrix")) or {}
        axes = {k: v for k, v in matrix.items()
                if k not in ("include", "exclude") and isinstance(v, list)}

        referenced = set(_MATRIX_REF.findall(str(template)))
        if not referenced:
            names.add(template)
            continue

        assert len(referenced) == 1, (
            f"job {job_id!r} interpolates {len(referenced)} matrix axes into its "
            "name; expected_check_names() only expands one. Extend it.")
        axis = referenced.pop()
        assert axis in axes, (
            f"job {job_id!r} name references matrix.{axis}, which the matrix "
            f"does not define. Defined axes: {sorted(axes)}")
        for value in axes[axis]:
            names.add(_MATRIX_REF.sub(str(value), template))
    return names


def required_contexts(ruleset: dict) -> set[str]:
    for rule in ruleset.get("rules", []):
        if rule.get("type") == "required_status_checks":
            params = rule.get("parameters") or {}
            return {c["context"] for c in params.get("required_status_checks", [])}
    return set()


# ---------------------------------------------------------------------------

def test_ruleset_and_workflow_both_parse():
    assert WORKFLOW.is_file(), f"missing {WORKFLOW}"
    assert RULESET.is_file(), f"missing {RULESET}"
    assert load_workflow().get("jobs"), "ci.yml defines no jobs"
    assert load_ruleset().get("rules"), "ruleset defines no rules"


def test_required_checks_match_the_ci_jobs_exactly():
    """The assertion this file exists for.

    Both directions matter. A required check with no job blocks every PR
    forever; a job with no required check runs and is then ignored, which is a
    gate that reports without gating.
    """
    expected = expected_check_names(load_workflow())
    required = required_contexts(load_ruleset())

    missing = expected - required          # job exists, nothing requires it
    unknown = required - expected          # required, but no job reports it

    assert not unknown, (
        "the ruleset requires status checks that no CI job reports, which blocks "
        f"every pull request indefinitely: {sorted(unknown)}. "
        f"Job names are: {sorted(expected)}")
    assert not missing, (
        "these CI jobs run but are not required by the ruleset, so a red result "
        f"would not block a merge: {sorted(missing)}")


def test_matrix_covers_the_declared_python_floor():
    """The floor in pyproject must actually be tested.

    Not cosmetic. requires-python said >=3.10 while CI's dependency-check step
    used tomllib, which is 3.11+, so the 3.10 job died before pytest ever ran and
    the floor was a claim rather than a fact for two CI runs.
    """
    workflow = load_workflow()
    matrix = ((workflow["jobs"]["test"].get("strategy") or {}).get("matrix")) or {}
    versions = [str(v) for v in matrix.get("python", [])]
    assert versions, "the test job declares no python matrix"

    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'requires-python\s*=\s*"[^0-9]*([0-9]+\.[0-9]+)"', pyproject)
    assert m, "could not read requires-python from pyproject.toml"
    floor = m.group(1)
    assert floor in versions, (
        f"pyproject declares requires-python >={floor}, but the CI matrix tests "
        f"{versions}. An untested floor is a claim, not a fact.")


def test_ruleset_blocks_the_things_it_should():
    rules = {r["type"] for r in load_ruleset()["rules"]}
    for required in ("deletion", "non_fast_forward", "pull_request",
                     "required_status_checks"):
        assert required in rules, f"ruleset does not enforce {required}"


def test_squash_is_the_only_allowed_merge_method():
    """A signing control, not a style preference.

    GitHub signs commits it creates server-side. A squash merge is one such
    commit, so it lands Verified even when the contributor cannot sign locally.
    A merge commit is signed too -- but it PRESERVES the branch commits beneath
    it, unsigned and all.

    This repository paid for that distinction. PR #3 merged with a merge commit
    and four unsigned commits survived under a Verified merge commit, taking
    main from one unverified commit to five. Clearing them cost a history
    rewrite, a force push, and taking the ruleset down and back up.

    Allowing `merge` again silently re-opens it, so assert the setting rather
    than trusting whoever next edits this file to remember why.
    """
    for rule in load_ruleset()["rules"]:
        if rule["type"] == "pull_request":
            methods = rule["parameters"].get("allowed_merge_methods")
            assert methods == ["squash"], (
                f"allowed_merge_methods is {methods!r}; must be ['squash'] so "
                "unsigned branch commits cannot survive a merge onto main")
            return
    pytest.fail("no pull_request rule in the ruleset")


def test_ruleset_targets_main_and_is_active():
    ruleset = load_ruleset()
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active", (
        "a ruleset in 'evaluate' mode reports what it would have blocked and "
        "blocks nothing")
    assert ruleset["conditions"]["ref_name"]["include"] == ["refs/heads/main"]


def test_status_checks_are_strict():
    """Without this, a PR can pass CI against a stale base and merge something
    that was never tested against what it actually lands on."""
    for rule in load_ruleset()["rules"]:
        if rule["type"] == "required_status_checks":
            assert rule["parameters"]["strict_required_status_checks_policy"] is True
            return
    pytest.fail("no required_status_checks rule")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
