"""Cohaera command line.

    python -m cohaera.cli score <telemetry.jsonl> [--baseline benign.jsonl]

Prints a human summary to stderr and emits one correlation-grade CIM record per
session as JSONL on stdout, so it pipes straight into a collector:

    python -m cohaera.cli score run.jsonl | curl -X POST --data-binary @- ...
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import SequenceGrammar, run_all
from .ingest import load
from .model import to_cim_event

_SEV_MARK = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
             "low": "[LOW ]", "info": "[INFO]"}


def cmd_score(args: argparse.Namespace) -> int:
    grammar = None
    if args.baseline:
        benign = load(args.baseline)
        grammar = SequenceGrammar().fit(benign)
        print(f"[cohaera] fitted grammar on {grammar.sessions_fitted} benign sessions, "
              f"{len(grammar.bigrams)} distinct transitions", file=sys.stderr)

    sessions = load(args.telemetry)
    print(f"[cohaera] {args.telemetry}: {sum(len(s.events) for s in sessions)} events "
          f"in {len(sessions)} sessions\n", file=sys.stderr)

    total_findings = 0
    for s in sessions:
        findings, cov = run_all(s, grammar)
        total_findings += len(findings)
        record = to_cim_event(s, findings)
        record["data"]["coverage"] = cov
        print(json.dumps(record))

        f = s.features()
        agents = ", ".join(s.agent_names) or "?"
        print(f"session {s.session_id}  agent={agents}  "
              f"tools={f['tool_call_count']} "
              f"(ro={f['read_only_count']} sc={f['state_change_count']} "
              f"eg={f['egress_count']} ?={f['unknown_class_count']})  "
              f"cost=${f['total_cost_usd']}  coverage={cov['completeness']}",
              file=sys.stderr)
        for fi in sorted(findings, key=lambda x: -x.rank):
            print(f"   {_SEV_MARK[fi.severity]} {fi.check}: {fi.title}", file=sys.stderr)
            print(f"          {fi.detail}", file=sys.stderr)
        for gap in cov["gaps"]:
            print(f"   [GAP ] {gap['check']} {gap['status']}: {gap['reason']}",
                  file=sys.stderr)
        print(file=sys.stderr)

    print(f"[cohaera] {total_findings} finding(s) across {len(sessions)} session(s)",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cohaera")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("score", help="score observra telemetry")
    sc.add_argument("telemetry", help="observra JSONL file")
    sc.add_argument("--baseline", help="benign JSONL to fit the sequence grammar")
    sc.set_defaults(func=cmd_score)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
