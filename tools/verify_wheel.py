#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Build the wheel, install it somewhere clean, and make it do work.

The local half of CI's ``build and install the wheel`` job. Three things are
only observable on the shipped artefact and are invisible in the source tree:

  1. **It runs at all.** An entry point that resolves in an editable install
     can fail in a wheel, because an editable install has the whole repository
     on the path and a wheel has only what was packaged.
  2. **It pulls in nothing.** The zero-runtime-dependency claim is about the
     distribution, so it has to be checked after a real install into an
     environment with nothing else in it.
  3. **It carries ``py.typed``.** Present in ``src/`` and missing from the
     wheel means every downstream type checker silently reads ``import
     cohaera`` as ``Any``, and nothing in the repository looks wrong. This is
     the failure that motivated the check (COH-R15).

``SOURCE_DATE_EPOCH`` is pinned to the commit timestamp, as CI does. Without it
two builds of the same commit produce two different SHA-256 digests, which
makes the wheel a function of the build rather than of the source.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXPECTED_VERDICTS = 4

PY_TYPED_PROBE = """
import importlib.util, pathlib
spec = importlib.util.find_spec("cohaera")
root = pathlib.Path(spec.origin).parent
marker = root / "py.typed"
assert marker.is_file(), (
    f"py.typed is not in the installed package at {root}; the annotations "
    "ship but no downstream checker will read them")
print(f"PEP 561 marker present at {marker}")
"""


def _run(cmd: list[str] | str, *, cwd: Path = REPO, **kw: object
         ) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          shell=isinstance(cmd, str), check=False, **kw)  # type: ignore[call-overload]
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"failed: {cmd}")
    return proc


def main() -> int:
    stamp = _run(["git", "log", "-1", "--format=%ct"]).stdout.strip()

    with tempfile.TemporaryDirectory(prefix="cohaera-wheel-") as tmp:
        work = Path(tmp)
        dist = work / "dist"

        print("building (SOURCE_DATE_EPOCH pinned to the commit)...")
        # Run from the temporary directory with the repository passed as the
        # source argument, NOT from the repository with an implicit source.
        #
        # `python -m` puts the working directory on sys.path, and a local
        # `build/` directory -- gitignored, and left behind by any previous
        # build -- then shadows pypa/build. The failure reads "'build' is a
        # package and cannot be directly executed", which names neither the
        # shadowing nor the directory causing it. CI never sees this because a
        # fresh checkout has no build/; every developer machine that has ever
        # built does. A local gate that only works on a clean tree is not a
        # local gate.
        _run([sys.executable, "-m", "build", "--outdir", str(dist), str(REPO)],
             cwd=work,
             env={**__import__("os").environ, "SOURCE_DATE_EPOCH": stamp})

        wheels = sorted(dist.glob("*.whl"))
        if len(wheels) != 1:
            raise SystemExit(f"expected exactly one wheel, got {wheels}")
        print(f"built {wheels[0].name}")

        print("generating fixtures (gitignored: generated output)...")
        _run([sys.executable, "tests/make_fixtures.py"])

        print("installing into a clean virtual environment...")
        venv = work / "venv"
        _run([sys.executable, "-m", "venv", str(venv)])
        pip = venv / "bin" / "pip"
        _run([str(pip), "install", "-q", str(wheels[0])])

        frozen = _run([str(pip), "list", "--format=freeze"]).stdout.split()
        strays = [line for line in frozen
                  if not line.lower().startswith(("cohaera", "pip", "setuptools",
                                                  "wheel", "pkg-resources"))]
        if strays:
            raise SystemExit(
                "the wheel pulled in dependencies, breaking the "
                f"zero-runtime-dependency claim: {strays}")
        print("installed with zero runtime dependencies")

        print("scoring a fixture with the INSTALLED entry point...")
        scored = _run([str(venv / "bin" / "cohaera"), "score",
                       "tests/fixtures/suspect.jsonl",
                       "--baseline", "tests/fixtures/benign.jsonl"])
        rows = [json.loads(line) for line in scored.stdout.splitlines() if line]
        if len(rows) != EXPECTED_VERDICTS:
            raise SystemExit(
                f"expected {EXPECTED_VERDICTS} verdict records, got {len(rows)}")
        if not all(r["type"] == "cohaera_session_verdict" for r in rows):
            raise SystemExit("a row is not a session verdict")
        if not all(r["verdict_id"] for r in rows):
            raise SystemExit("a verdict carries no verdict_id")
        print(f"{len(rows)} verdict record(s) emitted from the installed wheel")

        _run([str(venv / "bin" / "python"), "-c", PY_TYPED_PROBE])

    print("wheel gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
