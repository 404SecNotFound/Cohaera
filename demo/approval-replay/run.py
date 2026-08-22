#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""The approval that never expires.

    python demo/approval-replay/run.py

Four acts over one telemetry file. Unlike the phantom-guardrail demo, this one
does NOT end in a catch. Act 2 is a real and unplanned win; acts 3 and 4 are
open weaknesses with executable proof, catalogued as EVASION.md E26.

A demo that only shows the wins is a brochure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
sys.path.insert(0, str(HERE))

import scenario  # noqa: E402

from cohaera.capabilities import CapabilityManifest  # noqa: E402
from cohaera.checks import ch04_guardrail_overrun  # noqa: E402
from cohaera.ingest import assemble  # noqa: E402
from cohaera.model import Event  # noqa: E402

RULE = "=" * 74
NOTES = {
    "pay-01": ("THE CONTROL WORKING",
               "A human approved one transfer. It ran. Nothing fires, and that\n"
               "  is correct -- this is what an authorised payment looks like."),
    "pay-02": ("VERBATIM REPLAY  ->  REFUSED",
               "The same approval, copied unchanged onto a SECOND transfer. It\n"
               "  still names span AP1; the second call is AP2, so it does not\n"
               "  cover it and CH04 fires. This is a real win and it was not\n"
               "  planned -- see EVASION.md E26b."),
    "pay-03": ("ONE FIELD REWRITTEN  ->  COVERED",
               "Identical to act 2 except subject.span_id now reads AP2.\n"
               "  One string. Nothing signs the approval body, so nothing makes\n"
               "  the edit detectable. CH04 goes silent."),
    "pay-04": ("THIRTY DAYS LATER, ANOTHER SESSION  ->  COVERED",
               "The same approval again, in a session this detector has never\n"
               "  seen. No per-approval ledger and no validity window, so it is\n"
               "  as good the hundredth time as the first."),
}


def main() -> int:
    scenario.write()
    manifest = CapabilityManifest.from_obj(scenario.MANIFEST)
    events = [Event(raw=json.loads(line)) for line in scenario.session_lines()]
    sessions = {s.session_id: s for s in assemble(events, manifest=manifest)}

    print(f"\n{RULE}\n  THE APPROVAL THAT NEVER EXPIRES")
    print("  A human approved ONE payment: $250 to acct-1188.")
    print(f"  Here is what that approval is worth afterwards.\n{RULE}")

    for sid, _, _ in scenario.ACTS:
        session = sessions[sid]
        title, note = NOTES[sid]
        calls = session.consequential_calls
        findings = [f.check for f in ch04_guardrail_overrun(session)]

        print(f"\n  {title}")
        print("  " + "-" * 70)
        for call in calls:
            covered = session.covering_approval(call) is not None
            mark = "covered by an approval" if covered else "NOT COVERED"
            print(f"    transfer span={call.span_id:4} $250 -> acct-1188   {mark}")
        print(f"\n    Cohaera: {', '.join(findings) if findings else 'no finding'}")
        print(f"\n  {note}")

    print(f"\n{RULE}")
    print("  The approval is a sticky note with a span written on it.")
    print("  Rewriting the span costs one string. Nothing signs it, nothing")
    print("  expires it, and nothing remembers it was already spent.")
    print()
    print("  What would close it, and none of it exists on this path yet:")
    print("    - an issuer signature over the approval body")
    print("    - a mandatory validity window")
    print("    - a nonce the verifier records as spent, across sessions")
    print()
    print("  All three already exist for TELEMETRY as cohaera.integrity:1.")
    print(f"  The approval path never got them.  See EVASION.md E26.\n{RULE}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
