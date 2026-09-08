# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""The CH06 matrix is frozen evidence, not a README-only demonstration."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "lab" / "ch06"
CASES = {
    "intact", "deleted", "modified", "stripped", "reordered",
    "truncated", "replayed", "no_key", "unsupported",
}


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_ch06_lab_reproduces_the_committed_matrix():
    result = subprocess.run(
        [sys.executable, "lab/ch06/run.py", "--check"], cwd=REPO,
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "9/9 cases matches the committed matrix" in result.stdout


def test_expectations_and_results_cover_the_exact_frozen_case_set():
    expectations = _json(LAB / "expectations.json")
    results = _json(LAB / "runs" / "latest" / "results.json")
    fixture_names = {
        path.stem for path in (LAB / "fixtures" / "cases").glob("*.jsonl")
    }
    assert set(expectations["cases"]) == CASES
    assert set(results["cases"]) == CASES
    assert fixture_names == CASES
    assert results["summary"]["expectations_met"] == len(CASES)


def test_mutation_specific_diagnoses_match_the_declared_contract():
    expectations = _json(LAB / "expectations.json")["cases"]
    results = _json(LAB / "runs" / "latest" / "results.json")["cases"]

    for case in CASES:
        expected = expectations[case]
        actual = results[case]
        assert actual["baseline"]["issues"] == expected["baseline"]["issues"]
        assert (
            actual["baseline"]["records_reordered"]
            == expected["baseline"]["records_reordered"]
        )
        required_reasons = expected["cohaera"].get("required_reasons", {})
        for session_id, reasons in required_reasons.items():
            actual_reasons = actual["cohaera"]["sessions"][session_id][
                "ch06_reasons"
            ]
            assert set(reasons).issubset(actual_reasons)


def test_mutations_are_applied_to_the_frozen_signed_stream():
    source = _jsonl(LAB / "fixtures" / "source" / "canonical.signed.jsonl")
    modified = _jsonl(LAB / "fixtures" / "cases" / "modified.jsonl")
    stripped = _jsonl(LAB / "fixtures" / "cases" / "stripped.jsonl")

    assert source[2]["data"] != modified[2]["data"]
    assert source[2]["integrity"] == modified[2]["integrity"], (
        "the modified case was re-signed instead of changed after signing"
    )
    assert stripped[2]["data"] == modified[2]["data"]
    assert "prev" not in stripped[2]["integrity"]
    assert "chain" not in stripped[2]["integrity"]


def test_acceptance_counts_are_mechanical_and_zero_where_required():
    summary = _json(LAB / "runs" / "latest" / "results.json")["summary"]
    assert summary == {
        "benign_inadmissible": 0,
        "cases": 9,
        "expectations_met": 9,
        "explicit_declines": 2,
        "manipulated_verified_complete": 0,
    }


def test_baseline_imports_no_product_code():
    tree = ast.parse((LAB / "baseline.py").read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module or "" for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(
        name == "cohaera" or name.startswith(("cohaera.", "tools."))
        for name in imports
    ), imports
