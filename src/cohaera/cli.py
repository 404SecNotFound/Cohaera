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
    1   the run could not be completed as requested: a bound that is not a
        bound, a manifest that is not a manifest, an audit artifact that could
        not be written (C4-04), or an unexpected error
    2   usage error (argparse), including a bound outside its valid range

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
import contextlib
import json
import math
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__
from .capabilities import EMPTY_MANIFEST, CapabilityManifest, ManifestError
from .checks import SequenceGrammar, run_all
from .evidence import (
    EMPTY_STORE,
    P_ABSENT,
    POLICY_ARTIFACT_BASELINE,
    POLICY_ARTIFACT_MANIFEST,
    Freshness,
    LedgerError,
    PolicyAttestation,
    PolicySignature,
    PolicySignatureError,
    StreamLedger,
    TrustStore,
    TrustStoreError,
    stream_sha256,
    verify_policy_signature,
)
from .identity import Correlator, run_id, trust_config_digest
from .ingest import load
from .limits import DEFAULT_LIMITS, Limits, LimitsError
from .model import SESSION_SCHEMA, json_safe, to_cim_event
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


def positive_int(text: str) -> int:
    """An argparse type for a bound that must actually bound.

    C4-05. ``type=int`` accepted ``--max-evidence-items -1``, which reached
    ``cap_list`` and DISABLED the output cap: an operator tightening a bound
    removed it, and nothing said so. Rejected at the boundary, with exit 2,
    because a usage error should read as a usage error rather than as a
    traceback or as a silently different policy.
    """
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {value}")
    return value


def non_negative_int(text: str) -> int:
    """Like :func:`positive_int`, but zero means "tolerate nothing"."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return value


def positive_float(text: str) -> float:
    """A duration that must actually elapse. Zero would make everything stale."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not math.isfinite(value) or value <= 0.0:
        raise argparse.ArgumentTypeError(
            f"must be a finite number of seconds greater than 0, got {value}")
    return value


def finite_float(text: str) -> float:
    """Any real number, and nothing that is not one. R-13.

    ``type=float`` accepts ``nan`` and ``inf``, and argparse reports no error
    because ``float("nan")`` succeeds. ``--evidence-as-of nan`` therefore
    *silently disabled the freshness bound entirely*: every comparison against a
    NaN is false, ``Freshness.enabled`` went false, the "freshness bound:" line
    never printed, and the run exited zero having checked nothing an operator
    had explicitly asked it to check. Turning a control off is not a thing an
    argument value may do quietly, which is the same argument C4-05 made for
    ``positive_int``.
    """
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not math.isfinite(value):
        raise argparse.ArgumentTypeError(
            f"must be a finite number, got {text!r}. A non-finite value here "
            "would disable the bound rather than set it.")
    return value


def non_negative_float(text: str) -> float:
    """A tolerance that may be zero, but may not be negative or non-finite."""
    value = finite_float(text)
    if value < 0.0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return value


def unit_ratio(text: str) -> float:
    """A fraction in 0.0..1.0. ``--max-reject-ratio 2.0`` can never trip."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError(
            f"must be a fraction within 0.0..1.0, got {value}")
    return value


def _limits_from(args: argparse.Namespace) -> Limits:
    return DEFAULT_LIMITS.with_overrides(
        max_line_bytes=args.max_line_bytes,
        max_nesting_depth=args.max_nesting_depth,
        max_events_total=args.max_events,
        max_sessions=args.max_sessions,
        max_evidence_items=args.max_evidence_items,
        max_rejects=args.max_rejects,
        max_reject_ratio=args.max_reject_ratio,
        max_future_skew_s=getattr(args, "max_future_skew", None),
    )


def _load_manifest(path: str | None,
                   limits: Limits = DEFAULT_LIMITS) -> CapabilityManifest:
    """One read. The manifest carries the digest of the bytes it was parsed
    from, so nothing downstream has to resolve the path again -- see R-07 and
    ``CapabilityManifest.from_bytes``."""
    if not path:
        return EMPTY_MANIFEST
    manifest = CapabilityManifest.from_file(path, limits=limits)
    _err(f"[cohaera] capability manifest {sanitise_display(path, 160)}: "
         f"{len(manifest.tools)} tool(s), file digest {manifest.file_digest}, "
         f"semantic digest {manifest.semantic_digest}, "
         f"producer {sanitise_display(manifest.producer or '?', 80)}")
    return manifest


def _load_keys(path: str | None,
               limits: Limits = DEFAULT_LIMITS) -> TrustStore:
    if not path:
        return EMPTY_STORE
    store = TrustStore.from_file(path, limits=limits)
    _err(f"[cohaera] trust store {sanitise_display(path, 160)}: "
         f"{len(store.keys)} key(s) "
         f"({len(store.for_role('collector'))} collector, "
         f"{len(store.for_role('policy'))} policy), file digest "
         f"{store.file_digest}, semantic digest {store.semantic_digest}")
    for warning in store.warnings:
        # Not fatal. These are problems with the operator's own bookkeeping, and
        # refusing to run over one would be a denial of service against the
        # person trying to tighten their configuration. Said out loud instead,
        # because a rotation that exists in the file and not in the verifier is
        # invisible otherwise.
        _err(f"[cohaera] WARNING: trust store {warning}")
    return store


def _attest_policy(digest: str | None, sig_path: str | None, artifact: str,
                   store: TrustStore,
                   limits: Limits = DEFAULT_LIMITS) -> PolicyAttestation:
    """Verify a detached signature over one operator-supplied file.

    R-07. This used to take a PATH and open it, having been called with a file
    the caller had already read -- two reads of a name where there should be one
    read of a file. A rename in the window between them left Cohaera scoring one
    manifest while attesting the digest of another, and the signature still
    held, because it was checked against whichever bytes the second read found.
    It now takes the digest of the exact bytes the caller parsed or is about to
    parse, and has no way to look at the filesystem at all.

    Returns an attestation in every case, including the case where nothing was
    supplied, because ``POLICY_SIGNATURE_ABSENT`` in the verdict is the point:
    an unsigned manifest that says so is a different artifact from one that
    passes silently, and the second is what this codebase keeps arguing against.

    Raises rather than degrading when a signature WAS supplied and did not hold.
    An operator who passed --tool-manifest-sig asked for the file to be checked,
    and scoring on it anyway would answer a question they did not ask.
    """
    if not digest or not sig_path:
        return PolicyAttestation(artifact=artifact, status=P_ABSENT)
    signature = PolicySignature.from_file(sig_path, limits=limits)
    return verify_policy_signature(signature, digest, artifact, store)


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
    """R-07. The stack owns every descriptor opened for an artefact that is both
    hashed and read.

    An artefact whose signature Cohaera checks has to be hashed and parsed from
    the same bytes, and a path is not bytes -- resolving it twice is a race an
    atomic rename wins every time. The fix is to resolve it once and keep the
    descriptor, which means something has to own that descriptor across the run.
    This wrapper does, so that every early return below closes it without each
    of them having to remember to.
    """
    with contextlib.ExitStack() as stack:
        return _score(args, stack)


def _score(args: argparse.Namespace, stack: contextlib.ExitStack) -> int:
    try:
        limits = _limits_from(args)
    except LimitsError as exc:
        _err(f"[cohaera] invalid bound: {sanitise_display(str(exc), 300)}")
        return EXIT_ERROR
    try:
        manifest = _load_manifest(args.tool_manifest, limits)
    except (ManifestError, OSError) as exc:
        _err(f"[cohaera] capability manifest rejected: {sanitise_display(str(exc), 300)}")
        return EXIT_ERROR
    if args.trust_store and args.collector_keys:
        # Two paths naming the same thing, and no way to know which the operator
        # meant. Silently preferring one would mean a run verified against a key
        # set the operator did not think they had supplied, which is the worst
        # possible outcome for a flag whose entire job is to say which keys are
        # trusted.
        _err("[cohaera] --trust-store and --collector-keys both given, and they "
             "are the same option under two names. Pass one.")
        return EXIT_ERROR
    try:
        keys = _load_keys(args.trust_store or args.collector_keys, limits)
    except (TrustStoreError, OSError) as exc:
        # Refused, not degraded. An operator who passed --trust-store asked
        # for signatures to be verified; carrying on without them would report
        # an unverified stream as merely unsigned, which is the wrong answer to
        # the question they asked.
        _err(f"[cohaera] trust store rejected: "
             f"{sanitise_display(str(exc), 300)}")
        return EXIT_ERROR

    # The two operator-supplied files that decide how every record is READ. The
    # manifest says which tools are consequential; the baseline teaches CH01 what
    # normal looks like. Editing either changes every verdict without touching a
    # single telemetry record, which is why they are attested before they are
    # used rather than after.
    # R-07. The baseline is opened ONCE, here, and the same descriptor is what
    # `load` reads further down. It is hashed only when a signature was supplied,
    # which keeps the max_input_bytes error confined to the attestation path it
    # has always belonged to: without a signature there is nothing to disagree
    # with, and the reader's own budget stops an oversize file by truncating it
    # rather than by refusing.
    #
    # The manifest needs no descriptor. It was already read whole and bounded by
    # _load_manifest, and it carries the digest of exactly those bytes.
    baseline_fh: BinaryIO | None = None
    try:
        if args.baseline:
            baseline_fh = stack.enter_context(Path(args.baseline).open("rb"))
        baseline_digest = (
            stream_sha256(baseline_fh, limits.max_input_bytes, str(args.baseline))
            if baseline_fh is not None and args.baseline_sig else None)
        attestations = [
            _attest_policy(manifest.file_sha256 or None, args.tool_manifest_sig,
                           POLICY_ARTIFACT_MANIFEST, keys, limits),
            _attest_policy(baseline_digest, args.baseline_sig,
                           POLICY_ARTIFACT_BASELINE, keys, limits),
        ]
    except (PolicySignatureError, OSError) as exc:
        _err(f"[cohaera] policy signature rejected: "
             f"{sanitise_display(str(exc), 300)}")
        return EXIT_ERROR
    for att in attestations:
        if att.status == P_ABSENT:
            continue
        if not att.verified:
            _err(f"[cohaera] REFUSING to score: the {att.artifact} signature did "
                 f"not hold ({att.status}: {sanitise_display(att.detail, 200)}). "
                 "A signature that is checked and fails is the one case where "
                 "carrying on would be worse than not having asked.")
            return EXIT_ERROR
        _err(f"[cohaera] {att.artifact} signature VERIFIED under "
             f"{sanitise_display(att.key_id, 80)} "
             f"(file sha256 {att.file_sha256[:16]}...)")

    if args.require_signed_policy:
        supplied = {POLICY_ARTIFACT_MANIFEST: args.tool_manifest,
                    POLICY_ARTIFACT_BASELINE: args.baseline}
        unsigned = [a.artifact for a in attestations
                    if supplied.get(a.artifact) and not a.verified]
        if unsigned:
            _err(f"[cohaera] --require-signed-policy: {', '.join(unsigned)} "
                 "was supplied without a verified signature. Sign it with "
                 "tools/policy_sign.py and pass the detached signature, or drop "
                 "the flag and accept that the file is trusted because it is on "
                 "disk.")
            return EXIT_ERROR

    freshness = Freshness(max_age_s=args.evidence_max_age,
                          as_of=(args.evidence_as_of if args.evidence_as_of
                                 is not None else time.time()),
                          max_future_skew_s=limits.max_future_skew_s)
    if freshness.enabled:
        _err(f"[cohaera] freshness bound: signed records older than "
             f"{args.evidence_max_age:g}s as of {freshness.as_of:.0f} are stale, "
             f"and records dated more than {limits.max_future_skew_s:g}s after "
             f"it are INTEGRITY_EVIDENCE_FROM_FUTURE")

    if args.reject_log:
        try:
            _probe_writable(args.reject_log)
        except OSError as exc:
            _err(f"[cohaera] --reject-log {sanitise_display(args.reject_log, 160)} "
                 f"is not writable: {sanitise_display(str(exc), 200)}")
            return EXIT_ERROR

    ledger: StreamLedger | None = None
    if args.seen_streams:
        try:
            # R-04. Under an exclusive lock held until this run finishes, so
            # that two runs sharing a ledger cannot each read the position
            # before the other writes it. The stack releases it on every exit
            # path, including the error returns below.
            ledger = stack.enter_context(
                StreamLedger.locked(args.seen_streams, limits))
        except (LedgerError, OSError) as exc:
            # Refused, not started fresh. An unreadable ledger scores every
            # stream as new, which is precisely the state an attacker who
            # deleted it wants, and doing that quietly would hide the deletion.
            _err(f"[cohaera] seen-stream ledger rejected: "
                 f"{sanitise_display(str(exc), 400)}")
            return EXIT_ERROR
        _err(f"[cohaera] seen-stream ledger {sanitise_display(args.seen_streams, 160)}: "
             f"{len(ledger.streams)} stream(s) previously scored, "
             f"generation {ledger.generation}"
             + ("" if ledger.locked_exclusively else
                " (WARNING: no file locking on this host, so concurrent runs "
                "sharing this ledger cannot exclude each other)"))

    report = IngestReport(source=str(args.telemetry))
    correlator = _correlator(args, limits)

    grammar = None
    baseline_hash = ""
    baseline_ingest: dict | None = None
    if args.baseline:
        baseline_report = IngestReport(source=str(args.baseline))
        benign = load(args.baseline, limits=limits,
                      correlator=Correlator(None, limits=limits),
                      manifest=manifest, report=baseline_report,
                      fh=baseline_fh)
        # C5-07. A partial baseline used to produce a warning and then be fitted
        # anyway. That is the worst of both: CH01 is the one detector here that
        # LEARNS, its whole output is "unlike what I was shown", and quietly
        # showing it less than the operator supplied changes every verdict
        # afterwards -- in both directions, since a missing transition becomes a
        # false positive and a missing session becomes a blind spot.
        #
        # An abort can also happen with zero rejected records, so the warning
        # never fired for the case where the reader stopped early on a budget.
        # This checks the same budget function the target telemetry is checked
        # against, and refuses by default.
        baseline_problem = _budget_exceeded(baseline_report, limits)
        if baseline_report.rejected and not baseline_problem:
            baseline_problem = (f"{baseline_report.rejected} baseline record(s) "
                                "were quarantined")
        if baseline_problem and not args.allow_partial_baseline:
            _err(f"[cohaera] REFUSING to fit on a partial baseline: "
                 f"{sanitise_display(baseline_problem, 300)}. A baseline "
                 "assembled from incomplete data teaches a partial normal, and "
                 "every CH01 verdict after it is measured against the wrong "
                 "reference. Re-run with --allow-partial-baseline if that is "
                 "genuinely what you want; the choice is recorded in provenance.")
            return EXIT_BUDGET
        grammar = SequenceGrammar().fit(benign)
        baseline_hash = grammar.fingerprint()
        baseline_ingest = baseline_report.summary()
        _err(f"[cohaera] fitted grammar on {grammar.sessions_fitted} benign sessions, "
             f"{len(grammar.bigrams)} distinct transitions, baseline_hash "
             f"{baseline_hash or 'none'}")
        if baseline_problem:
            _err(f"[cohaera] WARNING: fitted on a PARTIAL baseline "
                 f"({sanitise_display(baseline_problem, 200)}) because "
                 "--allow-partial-baseline was given.")

    sessions = load(args.telemetry, limits=limits, correlator=correlator,
                    manifest=manifest, report=report, keys=keys,
                    freshness=freshness, ledger=ledger)
    _err(f"[cohaera] {sanitise_display(str(args.telemetry), 160)}: "
         f"{sum(len(s.events) for s in sessions)} events in {len(sessions)} sessions, "
         f"{report.rejected} record(s) quarantined\n")

    # R-06. Assembled BEFORE the ledger is written to and before the provenance
    # block below, because it must describe the configuration this run was
    # scored under rather than the state it left behind.
    ledger_identity = ({"enabled": True, "generation": ledger.generation,
                        "state": ledger.state_digest()} if ledger is not None
                       else {"enabled": False})
    trust_config = trust_config_digest(
        trust_store=keys.as_dict(limits.max_evidence_items),
        policy_attestations=[a.as_dict() for a in attestations],
        freshness=freshness.as_dict(),
        # See trust_config_digest: a pinned instant is part of the identity and
        # a defaulted wall clock cannot be, but which of the two happened is.
        freshness_as_of_pinned=args.evidence_as_of is not None,
        ledger=ledger_identity,
        correlation_key_version=correlator.key_version,
        correlation_keyed=correlator.keyed,
        baseline_partial_allowed=bool(args.allow_partial_baseline),
        schema=SESSION_SCHEMA,
    )
    run = run_id(
        detector_version=__version__,
        config_hash=limits.digest(),
        source=str(args.telemetry),
        # C4-01: the CONTENT of what was read, not the summary counts.
        input_digest=report.content_digest,
        baseline_hash=baseline_hash,
        manifest_hash=manifest.file_digest,
        trust_config=trust_config,
    )
    if ledger is not None:
        # Stamped here because analysis_run_id is a digest of everything read
        # and does not exist until reading finishes. WRITTEN LATER -- see the
        # save below the emission loop.
        ledger.stamp(run)

    provenance = {
        "analysis_run_id": run,
        "detector_version": __version__,
        "config_hash": limits.digest(),
        # R-06. Emitted as well as folded into analysis_run_id, so that two runs
        # whose IDs differ can be told WHY they differ without re-deriving it.
        "trust_config_digest": trust_config,
        "baseline_hash": baseline_hash,
        # C5-07. What the baseline was actually built from, so a verdict can be
        # audited against the reference it was measured against rather than
        # against the file somebody believes was used.
        "baseline_ingest": baseline_ingest,
        "baseline_partial_allowed": bool(args.allow_partial_baseline),
        "capability_manifest": manifest.as_dict(),
        "trust_store": keys.as_dict(limits.max_evidence_items),
        # What Cohaera established about the two files that decide how every
        # record is read. POLICY_SIGNATURE_ABSENT is the value nearly every
        # deployment will carry, and recording it is the point: an unsigned
        # manifest that says so is a different artifact from one that passes
        # silently.
        "policy_attestations": [a.as_dict() for a in attestations],
        "evidence_freshness": freshness.as_dict(),
        "stream_ledger": (
            {"enabled": True, "path": str(args.seen_streams),
             "streams_known": len(ledger.streams),
             # The generation and state READ, which is what the replay and fork
             # verdicts in this run were judged against (R-06).
             "generation_read": ledger_identity["generation"],
             "state_digest_read": ledger_identity["state"]} if ledger
            else {"enabled": False}),
        # Stream identity and extent, so that two runs which scored the same
        # collector stream twice are distinguishable after the fact. Cohaera
        # keeps no state between runs, so this is the only form replay detection
        # can take here. See evidence.Freshness.
        "collector_streams": report.integrity.get("stream_summary", []),
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

    if ledger is not None:
        # R-03, and a deliberate reversal. This used to run BEFORE the verdicts
        # were printed, reasoning that a run which dies mid-emission has still
        # SCORED those streams and forgetting that would let the same input
        # through again. The other side of that trade is worse: a run that dies
        # while printing has advanced the ledger past findings nobody ever saw,
        # and re-running now reports a replay, so the findings are lost and
        # unrecoverable. A duplicate alert is noise an analyst dismisses in
        # seconds; a missed one is the thing this project exists to prevent.
        #
        # Which is exactly why the concept is an OBSERVATION ledger and the
        # exactly-once-scoring language is gone. Saving after emission admits
        # the duplicate; saving before it hid a loss. Neither is exactly-once,
        # and only one of them fails in the direction an analyst can recover
        # from. A transactional version needs durable sink acknowledgement
        # across stdout, files and future SIEM sinks -- a design, not a patch.
        try:
            ledger.save()
        except (LedgerError, OSError) as exc:
            # Same reasoning as the quarantine ledger (C4-04). Losing the record
            # of what has been scored while reporting success means the next
            # replay of this stream is undetectable and nothing said so.
            _err(f"[cohaera] could not write the seen-stream ledger to "
                 f"{sanitise_display(str(args.seen_streams), 160)}: "
                 f"{sanitise_display(str(exc), 300)}")
            return EXIT_ERROR

    if args.reject_log:
        try:
            _write_reject_log_atomic(args.reject_log, report)
        except OSError as exc:
            _err(f"[cohaera] could not write the quarantine ledger to "
                 f"{sanitise_display(args.reject_log, 160)}: "
                 f"{sanitise_display(str(exc), 200)}")
            return EXIT_ERROR

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


def _write_reject_log_atomic(path: str, report: IngestReport) -> None:
    """Write the quarantine ledger without ever leaving a partial one.

    C5-06. This used to open the final path directly, so a run that died
    part-way through writing left a truncated ledger where a complete one had
    been -- and ``_probe_writable`` had already destroyed the previous contents
    before scoring even started. The record of what Cohaera REFUSED to score is
    audit evidence, and audit evidence that a failed run can erase is not
    evidence.

    Written to a sibling temporary file, flushed, fsynced, then moved into place
    with ``os.replace``, which is atomic on POSIX and on Windows. Either the old
    ledger is there or the new one is; there is no state in between.
    """
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent) or ".",
                               prefix=f".{target.name}.", suffix=".partial")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            _write_reject_log(fh, report)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _write_reject_log(fh: Any, report: IngestReport) -> None:
    """Machine-readable quarantine ledger, one JSON object per rejected record.

    C4-04. This used to catch OSError, print a line to stderr and return, so a
    run whose ``--reject-log`` path was unwritable -- a bad mount, a read-only
    volume, a typo, a directory an attacker removed -- still exited 0. The
    quarantine ledger is the record of what Cohaera REFUSED to score. Losing it
    while reporting success means an operator who asked "what did we drop"
    gets no answer and no indication that there was one, which is precisely the
    silent-data-loss failure the exit codes were introduced to remove.

    So it raises. The caller turns that into a non-zero exit.
    """
    for r in report.rejects:
        fh.write(json.dumps(r.as_dict(), sort_keys=True) + "\n")
    fh.write(json.dumps({"_summary": report.summary()}, sort_keys=True) + "\n")


def _probe_writable(path: str) -> None:
    """Fail before scoring rather than after, if the audit path is unusable.

    Scoring a 10 GB file and only then discovering the ledger cannot be written
    is a bad trade for the operator, and the failure is knowable up front.

    C5-06. It used to probe by opening the FINAL path in write mode, which
    truncated an existing ledger before a single record had been read -- so a
    run that then failed to load its input had already destroyed the previous
    run's audit evidence and never wrote a replacement. The probe now tests the
    destination DIRECTORY with a temporary file and leaves the target alone.
    """
    target = Path(path)
    parent = target.parent if str(target.parent) else Path()
    if target.exists() and not os.access(target, os.W_OK):
        raise OSError(f"{path}: exists and is not writable")
    fd, tmp = tempfile.mkstemp(dir=str(parent) or ".", prefix=".cohaera-probe-")
    os.close(fd)
    os.unlink(tmp)


def _add_common(p: argparse._ActionsContainer) -> None:
    p.add_argument("--tool-manifest", metavar="PATH",
                   help="JSON capability manifest keyed on exact tool ID. Declared "
                        "capabilities outrank the name heuristic and the producer's "
                        "reversible flag.")
    p.add_argument("--trust-store", metavar="PATH",
                   help="JSON trust store (cohaera.trust_store:1): public keys, what "
                        "each is authorised to attest, its validity window, and "
                        "whether it has been revoked. Used to verify "
                        "cohaera.integrity:1 signatures on telemetry and "
                        "cohaera.policy_signature:1 signatures on the manifest and "
                        "baseline. Without it, signed records are parsed and NOT "
                        "verified, and the verdict says so with NO_COLLECTOR_KEYS.")
    p.add_argument("--collector-keys", metavar="PATH",
                   help="Superseded name for --trust-store, kept because deployments "
                        "wrote cohaera.collector_keys:1 files. Either flag accepts "
                        "either schema; a legacy file's keys are collector-role only "
                        "and cannot attest policy.")
    p.add_argument("--tool-manifest-sig", metavar="PATH",
                   help="Detached cohaera.policy_signature:1 over the capability "
                        "manifest, verified against a policy-role key. Supplying it "
                        "and having it fail is a refusal to score, not a warning.")
    p.add_argument("--require-signed-policy", action="store_true",
                   help="Refuse to run unless every supplied policy file (manifest, "
                        "baseline) carries a signature that verified. Off by default "
                        "because it would break every existing deployment; on, it is "
                        "what turns the signature from an option into a control.")
    p.add_argument("--seen-approvals", metavar="PATH",
                   help="Ledger of spent approval nonces, so one approval "
                        "cannot authorise a second call in a later run "
                        "(EVASION.md E26). Inherits E22 whole: the file is "
                        "unsigned by necessity and is per-host.")
    p.add_argument("--require-signed-approvals", action="store_true",
                   help="An approval that no issuer signed does not cover a "
                        "call. OFF by default: turning it on in a deployment "
                        "that has issued no approval keys makes every "
                        "authorised action look like a bypass.")
    p.add_argument("--seen-streams", metavar="PATH",
                   help="JSON OBSERVATION ledger of collector streams already "
                        "seen, kept BETWEEN runs. It is what detects a stream "
                        "re-fed inside the freshness window, which every other "
                        "check passes because the replayed stream is genuine. "
                        "It records what Cohaera observed and scored, NOT what "
                        "any sink durably received, and it does not provide "
                        "exactly-once scoring: it is written after verdicts are "
                        "emitted, so a run that dies mid-emission is re-scored "
                        "and may duplicate. Created on first use; a file that "
                        "exists and does not parse is a hard error, because "
                        "scoring everything as new is what deleting it would "
                        "achieve. Only streams whose evidence held are written "
                        "to it. Unsigned local state and a single-host file "
                        "lock: an attacker who can delete it removes the "
                        "detection (EVASION.md E22).")
    p.add_argument("--evidence-max-age", type=positive_float, metavar="SECONDS",
                   help="Report signed records older than this as stale "
                        "(INTEGRITY_EVIDENCE_STALE). This is the bound that makes "
                        "re-feeding a captured stream detectable: every other check "
                        "passes on a replayed stream, because it really was written "
                        "by that collector. Off by default, and coverage says "
                        "NO_FRESHNESS_BOUND when it is off.")
    p.add_argument("--evidence-as-of", type=finite_float, metavar="EPOCH",
                   help="The instant --evidence-max-age is measured from, in seconds "
                        "since the epoch. Defaults to the wall clock at run start; "
                        "set it to make a run reproducible, or to score an archive "
                        "as of the day it was captured. Must be finite: a NaN here "
                        "used to disable the freshness bound rather than set it.")
    p.add_argument("--max-future-skew", type=non_negative_float, metavar="SECONDS",
                   help=f"How far after --evidence-as-of a signature-verified "
                        f"record may be dated before it is reported as "
                        f"INTEGRITY_EVIDENCE_FROM_FUTURE and the evidence becomes "
                        f"inadmissible (default "
                        f"{DEFAULT_LIMITS.max_future_skew_s:g}). A freshness window "
                        f"bounds only how OLD a record may be; without this a "
                        f"collector with a wrong clock buys unlimited freshness by "
                        f"adding to a number.")
    p.add_argument("--correlation-secret-env", metavar="NAME", default=SECRET_ENV,
                   help=f"Environment variable holding the HMAC key for anonymous "
                        f"correlation keys (default {SECRET_ENV}).")
    p.add_argument("--allow-partial-baseline", action="store_true",
                   help="Fit the sequence grammar even when the baseline file was "
                        "partially read or partially quarantined. Off by default: "
                        "a partial baseline teaches a partial normal and silently "
                        "changes every CH01 verdict. Recorded in provenance.")
    p.add_argument("--strict", action="store_true",
                   help="Exit non-zero if any record is quarantined.")
    p.add_argument("--max-rejects", type=non_negative_int, metavar="N",
                   help="Abort with exit 5 if more than N records are quarantined.")
    p.add_argument("--max-reject-ratio", type=unit_ratio, metavar="F",
                   help="Abort with exit 5 if the quarantined fraction exceeds F.")
    p.add_argument("--reject-log", metavar="PATH",
                   help="Write the quarantine ledger as JSONL to PATH.")
    p.add_argument("--max-line-bytes", type=positive_int, metavar="N",
                   help=f"Maximum bytes per JSONL record "
                        f"(default {DEFAULT_LIMITS.max_line_bytes}).")
    p.add_argument("--max-nesting-depth", type=positive_int, metavar="N",
                   help=f"Maximum JSON container depth "
                        f"(default {DEFAULT_LIMITS.max_nesting_depth}).")
    p.add_argument("--max-events", type=positive_int, metavar="N",
                   # R-20. It said "records read", and it is not that. It caps
                   # ACCEPTED events; the bound on records read is
                   # max_records_total, which is a different number and is not
                   # exposed here. An operator who set this believing it capped
                   # reading got a weaker bound than they asked for.
                   help=f"Maximum ACCEPTED events per run (default "
                        f"{DEFAULT_LIMITS.max_events_total}). This is not the "
                        f"number of records READ -- that is max_records_total, "
                        f"currently {DEFAULT_LIMITS.max_records_total}, and a "
                        f"file of pure garbage is bounded by it rather than by "
                        f"this.")
    p.add_argument("--max-sessions", type=positive_int, metavar="N",
                   help=f"Maximum sessions assembled per run "
                        f"(default {DEFAULT_LIMITS.max_sessions}).")
    p.add_argument("--max-evidence-items", type=positive_int, metavar="N",
                   help=f"Maximum rows carried in any one evidence field "
                        f"(default {DEFAULT_LIMITS.max_evidence_items}).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cohaera")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("score", help="score observra telemetry")
    sc.add_argument("telemetry", help="observra JSONL file")
    sc.add_argument("--baseline", help="benign JSONL to fit the sequence grammar")
    sc.add_argument("--baseline-sig", metavar="PATH",
                    help="Detached cohaera.policy_signature:1 over the baseline. "
                         "CH01 is the only detector here that LEARNS, so an "
                         "attacker who can add sessions to the baseline teaches it "
                         "that the attack is normal -- EVASION.md E03. This is what "
                         "makes editing the file detectable.")
    _add_common(sc)
    sc.set_defaults(func=cmd_score)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:                       # pragma: no cover
        _err("[cohaera] interrupted")
        return EXIT_ERROR
    except LimitsError as exc:
        _err(f"[cohaera] invalid bound: {sanitise_display(str(exc), 300)}")
        return EXIT_ERROR
    except OSError as exc:
        _err(f"[cohaera] {sanitise_display(str(exc), 300)}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
