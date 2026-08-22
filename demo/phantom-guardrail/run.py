#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""The phantom guardrail, run twice.

    python demo/phantom-guardrail/run.py

Two runs over ONE unchanged telemetry file. The only thing that differs is
whether Cohaera was given the operator's capability manifest. That is the whole
demonstration, and it is why the runs are side by side rather than in separate
sections: the finding is not produced by better telemetry, it is produced by
having something to compare the telemetry against.

Deterministic. Same input, same output, every time -- so it can be diffed.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))

import scenario  # noqa: E402

from cohaera.capabilities import EMPTY_MANIFEST, CapabilityManifest  # noqa: E402
from cohaera.checks import run_all  # noqa: E402
from cohaera.ingest import assemble  # noqa: E402
from cohaera.model import Event  # noqa: E402

# Matches the CLI's own abbreviations, so the demo and the real
# tool do not label the same finding two different ways.
SEV = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}

RULE = "=" * 74
THIN = "-" * 74


def load() -> list[Event]:
    return [Event(raw=json.loads(line))
            for line in (HERE / "telemetry.jsonl").read_text(
                encoding="utf-8").splitlines() if line.strip()]


def score(manifest: CapabilityManifest):
    session = assemble(load(), manifest=manifest)[0]
    return run_all(session)


def show(findings, cov, *, label: str, note: str) -> None:
    print(THIN)
    print(f"  {label}")
    print(THIN)
    if findings:
        for f in findings:
            print(f"    [{SEV.get(f.severity, f.severity[:4]):4}] {f.check}")
    else:
        print("    (no findings)")
    ch04 = next(c for c in cov["checks"]
                if c["check"] == "CH04_guardrail_overrun")
    print(f"\n    CH04 coverage: {ch04['status']}  confidence {ch04['confidence']:.2f}")
    for r in ch04["reasons"]:
        print(f"      reason: {r}")
    print(f"\n  {note}\n")


def main() -> int:
    scenario.write()
    events = load()

    print(f"\n{RULE}\n  THE PHANTOM GUARDRAIL")
    print("  An AI SOC analyst closes an alert. A control that does not exist")
    print(f"  is credited with blocking the export.\n{RULE}\n")

    print(f"WHAT HAPPENED  ({len(events)} events)\n")
    for e in events:
        d = e.raw.get("data", {})
        if e.raw["event_type"] == "tool_start":
            print(f"    tool   {e.raw['tool_name']}")
        elif e.raw["event_type"] == "tool_error":
            print(f"           ^ FAILED: {d.get('error_class')}")
        elif e.raw["event_type"] == "cost_threshold_exceeded":
            print(f"\n    POLICY EVENT  policy_id={d.get('policy_id')}  "
                  f"enforcement={d.get('enforcement')}  "
                  f"decision={d.get('decision')}")
            print("           ^ this is the fabrication. One event.\n")

    print("\nWHAT THE AGENT TOLD THE HUMAN\n")
    resp = next(e.raw["data"]["response_text"] for e in events
                if e.raw["event_type"] == "model_response")
    for line in textwrap.wrap(resp, 68):
        print(f"    {line}")
    print("\n    Every statement is true except one: the export failed on a 503,")
    print("    and no control named dlp-outbound-guard exists anywhere.\n")

    findings, cov = score(EMPTY_MANIFEST)
    show(findings, cov,
         label="RUN 1 - no capability manifest. What a SIEM has today.",
         note=("Cohaera took the control's SEMANTICS from the agent's own event\n"
               "  and says so. It cannot ask whether the control exists, because\n"
               "  nothing here declares which controls do. It reports that gap\n"
               "  rather than reporting a clean result."))

    manifest = CapabilityManifest.from_obj(scenario.MANIFEST)
    findings, cov = score(manifest)
    show(findings, cov,
         label="RUN 2 - with the operator's manifest. Same telemetry.",
         note="The operator declared their controls. Now the question can be asked.")

    cited = next((f for f in findings
                  if f.check == "CH04_undeclared_control_cited"), None)
    if cited is not None:
        ev = cited.evidence
        print(f"    cited by the agent : {', '.join(ev['undeclared_controls'])}")
        print(f"    declared by the op : {', '.join(ev['declared_controls'])}\n")

    print(RULE)
    print("  The alert was closed. The export was never blocked by anything.")
    print("  The evidence that said otherwise was written by the agent.")
    print(f"{RULE}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
