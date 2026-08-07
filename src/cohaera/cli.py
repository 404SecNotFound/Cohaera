"""Cohaera command line.

    python -m cohaera.cli score <telemetry.jsonl> [--baseline benign.jsonl]

Prints a human summary to stderr and emits one correlation-grade CIM record per
session as JSONL on stdout, so it pipes straight into a collector:

    python -m cohaera.cli score run.jsonl | curl -X POST --data-binary @- ...

EXIT CODES
    0   every record was accepted
    3   partial success: some records were quarantined (permissive mode)
    4   strict mode, and at least one record was quarantined
    5   a reject budget or a resource bound was exceeded; output is incomplete
    1   an unexpected error; nothing should be trusted
    2   usage error (argparse)

Before this, ``cmd_score`` returned 0 unconditionally. A pipeline could lose
every record but one to malformed JSON and still be marked successful, which is
silent data loss in automation and the exact failure a security control must not
have.

Everything written to stderr goes through ``sanitise_display``. The JSON on
stdout was always escaped correctly; the human-readable half was not, and a
producer could put a newline plus an ANSI sequence in a session_id to forge a
convincing "0 finding(s)" line and then clear the screen above it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .capabilities import EMPTY_MANIFEST, CapabilityManifest, ManifestError
from .checks import SequenceGrammar, run_all
from .identity import Correlator, digest, run_id
from .ingest import load
from .limits import DEFAULT_LIMITS, Limits
from .model import json_safe, to_cim_event
from .validate import IngestReport, sanitise_display

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PARTIAL = 3
EXIT_STRICT_REJECT = 4
EXIT_BUDGET = 5

_SEV_MARK = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
             "low": "[LOW ]", "info": "[INFO]"}

SECRET_ENV = "COHAERA_CORRELATION_SECRET"


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _limits_from(args: argparse.Namespace) -> Limits:
    return DEFAULT_LIMITS.with_overrides(
        max_line_bytes=args.max_line_bytes,
        max_nesting_depth=args.max_nesting_depth,
        max_events_total=args.max_events,
        max_sessions=args.max_sessions,
        max_evidence_items=args.max_evidence_items,
        max_rejects=args.max_rejects,
        max_reject_ratio=args.max_reject_ratio,
    )


def _load_manifest(path: str | None) -> CapabilityManifest:
    if not path:
        return EMPTY_MANIFEST
    manifest = CapabilityManifest.from_file(path)
    _err(f"[cohaera] capability manifest {sanitise_display(path, 160)}: "
         f"{len(manifest.tools)} tool(s), digest {manifest.digest}, "
         f"producer {sanitise_display(manifest.producer or '?', 80)}")
    return manifest


def _correlator(args: argparse.Namespace, limits: Limits) -> Correlator:
    secret = os.environ.get(args.correlation_secret_env or SECRET_ENV)
    if not secret:
        _err("[cohaera] WARNING: no correlation secret set. Anonymous session keys "
             f"will be unkeyed SHA-256 digests. Set ${args.correlation_secret_env or SECRET_ENV} "
             "so a small identity space cannot be enumerated from the SIEM copy.")
        return Correlator(None, limits=limits)
    return Correlator(secret.encode("utf-8"), limits=limits)


def _budget_exceeded(report: IngestReport, limits: Limits) -> str:
    if limits.max_rejects is not None and report.rejected > limits.max_rejects:
        return (f"{report.rejected} rejected record(s) exceeds "
                f"--max-rejects={limits.max_rejects}")
    if (limits.max_reject_ratio is not None
            and report.total and report.reject_ratio > limits.max_reject_ratio):
        return (f"reject ratio {report.reject_ratio:.4f} exceeds "
                f"--max-reject-ratio={limits.max_reject_ratio}")
    if report.aborted:
        return f"ingestion aborted: {report.abort_reason}"
    return ""


def cmd_score(args: argparse.Namespace) -> int:
    limits = _limits_from(args)
    try:
        manifest = _load_manifest(args.tool_manifest)
    except (ManifestError, OSError) as exc:
        _err(f"[cohaera] capability manifest rejected: {sanitise_display(str(exc), 300)}")
        return EXIT_ERROR

    report = IngestReport(source=str(args.telemetry))
    correlator = _correlator(args, limits)

    grammar = None
    baseline_hash = ""
    if args.baseline:
        baseline_report = IngestReport(source=str(args.baseline))
        benign = load(args.baseline, limits=limits,
                      correlator=Correlator(None, limits=limits),
                      manifest=manifest, report=baseline_report)
        grammar = SequenceGrammar().fit(benign)
        baseline_hash = grammar.fingerprint()
        _err(f"[cohaera] fitted grammar on {grammar.sessions_fitted} benign sessions, "
             f"{len(grammar.bigrams)} distinct transitions, baseline_hash "
             f"{baseline_hash or 'none'}")
        if baseline_report.rejected:
            _err(f"[cohaera] WARNING: {baseline_report.rejected} baseline record(s) "
                 "were quarantined. A baseline assembled from partial data teaches "
                 "a partial normal.")

    sessions = load(args.telemetry, limits=limits, correlator=correlator,
                    manifest=manifest, report=report)
    _err(f"[cohaera] {sanitise_display(str(args.telemetry), 160)}: "
         f"{sum(len(s.events) for s in sessions)} events in {len(sessions)} sessions, "
         f"{report.rejected} record(s) quarantined\n")

    run = run_id(
        detector_version=__version__,
        config_hash=limits.digest(),
        source=str(args.telemetry),
        input_digest=digest(report.summary(), 16),
        baseline_hash=baseline_hash,
        manifest_hash=manifest.digest,
    )
    provenance = {
        "analysis_run_id": run,
        "detector_version": __version__,
        "config_hash": limits.digest(),
        "baseline_hash": baseline_hash,
        "capability_manifest": manifest.as_dict(),
        "correlation_key_version": correlator.key_version,
        "correlation_keyed": correlator.keyed,
        "ingest": report.summary(),
    }

    total_findings = 0
    for seq, s in enumerate(sessions):
        findings, cov = run_all(s, grammar, limits=limits)
        total_findings += len(findings)
        record = to_cim_event(s, findings, coverage=cov, provenance=provenance,
                              sequence=seq)
        print(json.dumps(json_safe(record), allow_nan=False, default=str))

        f = s.features()
        agents = ", ".join(sanitise_display(a, 60) for a in s.agent_names) or "?"
        _err(f"session {sanitise_display(s.session_id, 120)}  agent={agents}  "
             f"tools={f['tool_call_count']} "
             f"(ro={f['read_only_count']} sc={f['state_change_count']} "
             f"eg={f['egress_count']} ?={f['unknown_class_count']})  "
             f"cost=${f['total_cost_usd']}  coverage={cov['completeness']}  "
             f"corr={cov['correlation_kind']}")
        for fi in sorted(findings, key=lambda x: -x.rank):
            mark = _SEV_MARK.get(fi.severity, "[????]")
            _err(f"   {mark} {sanitise_display(fi.check, 80)}: "
                 f"{sanitise_display(fi.title, 200)}  (confidence "
                 f"{fi.confidence:.2f})")
            _err(f"          {sanitise_display(fi.detail, 600)}")
        for gap in cov["gaps"]:
            _err(f"   [GAP ] {sanitise_display(gap['check'], 60)} {gap['status']}: "
                 f"{sanitise_display(gap['reason'], 300)}")
        _err("")

    _err(f"[cohaera] {total_findings} finding(s) across {len(sessions)} session(s); "
         f"{report.accepted} record(s) accepted, {report.rejected} quarantined, "
         f"{report.defective} accepted with field defects")

    if args.reject_log:
        _write_reject_log(args.reject_log, report)

    budget = _budget_exceeded(report, limits)
    if budget:
        _err(f"[cohaera] ABORT: {budget}")
        return EXIT_BUDGET
    if report.rejected:
        if args.strict:
            _err("[cohaera] strict mode: quarantined records are a failure")
            return EXIT_STRICT_REJECT
        _err("[cohaera] partial success: some records were not scored")
        return EXIT_PARTIAL
    return EXIT_OK


def _write_reject_log(path: str, report: IngestReport) -> None:
    """Machine-readable quarantine ledger, one JSON object per rejected record."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for r in report.rejects:
                fh.write(json.dumps(r.as_dict(), sort_keys=True) + "\n")
            fh.write(json.dumps({"_summary": report.summary()}, sort_keys=True) + "\n")
    except OSError as exc:
        _err(f"[cohaera] could not write reject log: {sanitise_display(str(exc), 200)}")


def _add_common(p: argparse._ActionsContainer) -> None:
    p.add_argument("--tool-manifest", metavar="PATH",
                   help="JSON capability manifest keyed on exact tool ID. Declared "
                        "capabilities outrank the name heuristic and the producer's "
                        "reversible flag.")
    p.add_argument("--correlation-secret-env", metavar="NAME", default=SECRET_ENV,
                   help=f"Environment variable holding the HMAC key for anonymous "
                        f"correlation keys (default {SECRET_ENV}).")
    p.add_argument("--strict", action="store_true",
                   help="Exit non-zero if any record is quarantined.")
    p.add_argument("--max-rejects", type=int, metavar="N",
                   help="Abort with exit 5 if more than N records are quarantined.")
    p.add_argument("--max-reject-ratio", type=float, metavar="F",
                   help="Abort with exit 5 if the quarantined fraction exceeds F.")
    p.add_argument("--reject-log", metavar="PATH",
                   help="Write the quarantine ledger as JSONL to PATH.")
    p.add_argument("--max-line-bytes", type=int, metavar="N",
                   help=f"Maximum bytes per JSONL record "
                        f"(default {DEFAULT_LIMITS.max_line_bytes}).")
    p.add_argument("--max-nesting-depth", type=int, metavar="N",
                   help=f"Maximum JSON container depth "
                        f"(default {DEFAULT_LIMITS.max_nesting_depth}).")
    p.add_argument("--max-events", type=int, metavar="N",
                   help=f"Maximum records read per run "
                        f"(default {DEFAULT_LIMITS.max_events_total}).")
    p.add_argument("--max-sessions", type=int, metavar="N",
                   help=f"Maximum sessions assembled per run "
                        f"(default {DEFAULT_LIMITS.max_sessions}).")
    p.add_argument("--max-evidence-items", type=int, metavar="N",
                   help=f"Maximum rows carried in any one evidence field "
                        f"(default {DEFAULT_LIMITS.max_evidence_items}).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cohaera")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("score", help="score observra telemetry")
    sc.add_argument("telemetry", help="observra JSONL file")
    sc.add_argument("--baseline", help="benign JSONL to fit the sequence grammar")
    _add_common(sc)
    sc.set_defaults(func=cmd_score)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:                       # pragma: no cover
        _err("[cohaera] interrupted")
        return EXIT_ERROR
    except OSError as exc:
        _err(f"[cohaera] {sanitise_display(str(exc), 300)}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
