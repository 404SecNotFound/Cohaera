"""Run Cohaera's checks over an adapted external corpus.

The point of this file is NOT to produce a good number. It is to produce a
number that came from somebody else's data, and to be explicit about which of
the seven checks that number can possibly be about.

WHAT IT REPORTS, AND WHY EACH ONE
---------------------------------
1. FALSE POSITIVES PER 1,000 BENIGN SESSIONS. The repo's headline unit, and the
   reason these corpora were chosen: both have a real benign population.
   StepShield ships 2,514 generated benign trajectories -- NOT the 6,657 its own
   README claims, which was checked and refuted; see the adapter's docstring and
   docs/EXTERNAL-VALIDATION.md. ATBench claims 503 safe, unverified because its
   data is on a host this environment cannot reach. The
   all-session variant is printed beside it and is NOT the number to plan
   against -- it moves with the corpus's attack prevalence, which is a property
   of whoever built the corpus rather than of the detector. The evaluation card
   §5 makes this argument at length; this runner just refuses to lead with the
   wrong one.

2. PER-CHECK PRECISION. Which rule pages an analyst for nothing. Target
   precision -- precision counting only the attacks a check is RESPONSIBLE for
   -- is the honest per-rule number internally, and it is UNAVAILABLE here:
   external corpora label a trajectory unsafe, not "unsafe in the way CH02 is
   meant to notice". So the target column is reported as unavailable rather than
   as zero, and any-attack precision is what these corpora can support.

3. THE COVERAGE CONTRACT RESULTS. The most interesting output, and the one to
   read first. How many sessions each check declined, and under which reason
   codes. On a corpus with no approvals, no policy events and no receipts, the
   checks that read those surfaces should decline nearly everything -- and where
   one does NOT decline, that is a finding about the contract rather than a
   clean bill of health. :func:`scope_audit` states that comparison explicitly
   instead of leaving it to a reader to notice.

4. WILSON AND A CLUSTER BOOTSTRAP, side by side. Reusing ``eval.metrics``
   wholesale rather than reimplementing: R-15's argument -- that a session is
   not an independent unit when several sessions are the same task -- applies to
   an external corpus exactly as it applies to the internal one. Where a corpus
   pairs its rogue and clean trajectories on a shared task, the bootstrap has a
   real cluster to resample. Where it does not, the runner says the clustering
   is degenerate rather than printing a task-level interval that is secretly a
   session-level one.

NO DATA IS VENDORED
-------------------
Neither corpus is in this repository. StepShield is CC BY 4.0 and could be
redistributed with attribution; ATBench has no licence at all and could not.
Rather than treat the two differently, this harness fetches nothing and vendors
nothing: it fails loudly, naming the corpus and the command that obtains it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from cohaera.capabilities import EMPTY_MANIFEST  # noqa: E402
from cohaera.checks import (  # noqa: E402
    STATUS_DEGRADED,
    STATUS_EVALUATED,
    STATUS_NOT_EVALUATED,
    SequenceGrammar,
    run_all,
)
from cohaera.identity import Correlator  # noqa: E402
from cohaera.ingest import assemble  # noqa: E402
from cohaera.limits import DEFAULT_LIMITS, Limits  # noqa: E402
from cohaera.model import Event, Session  # noqa: E402
from eval.external import scope  # noqa: E402
from eval.external.adapters import agentdojo, atbench, stepshield  # noqa: E402
from eval.external.adapters.base import AdaptedSession, AdapterError  # noqa: E402
from eval.harness import ALERTING_SEVERITIES  # noqa: E402
from eval.metrics import Outcome, check_attribution, summarise  # noqa: E402

# Fraction of TASKS held out for scoring. The rest fit CH01's benign baseline.
# Task-disjoint, not session-disjoint: see eval/README.md and R-15.
HOLDOUT_FRACTION = 0.5
SPLIT_SEED = 20260819


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_session(adapted: AdaptedSession, limits: Limits = DEFAULT_LIMITS
                  ) -> Session:
    """Assemble one adapted trajectory into a Cohaera Session.

    One row at a time, exactly as ``eval.harness._sessions_for`` does, so that a
    change in correlation behaviour cannot silently merge two external
    trajectories and corrupt their labels.

    No capability manifest is supplied and that is deliberate. A manifest is an
    operator's out-of-band declaration of what each tool does; writing one for
    somebody else's corpus would be this author classifying the tools his own
    detector is about to be judged on, which is the circularity the whole
    external-validation exercise exists to escape.
    """
    events = [Event(raw=dict(raw), limits=limits) for raw in adapted.events]
    sessions = assemble(events, limits=limits, manifest=EMPTY_MANIFEST,
                        correlator=Correlator(b"external", limits=limits))
    if len(sessions) != 1:
        raise AdapterError(
            f"{adapted.session_id}: assembled into {len(sessions)} sessions, so "
            "the corpus label no longer describes one session. Refusing to "
            "score it.")
    return sessions[0]


def split_tasks(sessions: list[AdaptedSession], *,
                holdout: float = HOLDOUT_FRACTION,
                seed: int = SPLIT_SEED
                ) -> tuple[list[AdaptedSession], list[AdaptedSession]]:
    """Task-disjoint split. Returns (train, test).

    Deterministic without a seed file: tasks are ORDERED by a keyed hash and the
    first ``holdout`` share of that order is held out. Ranking rather than
    thresholding each task independently is what makes the split behave at every
    corpus size -- an independent coin per task can put all of them on one side,
    which on a small corpus silently produces an empty test set and on a large
    one produces a split that is not the fraction asked for.

    The hash supplies the ordering so the split is not alphabetical, which on
    these corpora would correlate with category: StepShield ids begin with the
    violation code, so an alphabetical split trains on DEC/INV and tests on
    TST/UFO, and CH01's baseline would be fitted on a different workload than it
    scores. That is exactly the vocabulary mismatch CH01 declines on.

    On a corpus with no task pairing every session is its own task, so this
    degenerates to a session-level split -- stated in the report rather than
    passed off as task-disjoint. See the ATBench adapter's docstring.
    """
    tasks = sorted({s.task_id for s in sessions})
    if len(tasks) < 2:
        raise AdapterError(
            f"Only {len(tasks)} distinct task(s) across {len(sessions)} "
            "sessions. A task-disjoint split needs at least two, and a "
            "held-out set drawn from one task measures nothing.")

    ordered = sorted(
        tasks, key=lambda t: hashlib.sha256(f"{seed}:{t}".encode()).digest())
    # At least one task each side, whatever the fraction and the corpus size.
    n_held = min(len(ordered) - 1, max(1, round(holdout * len(ordered))))
    held = set(ordered[:n_held])

    train = [s for s in sessions if s.task_id not in held]
    test = [s for s in sessions if s.task_id in held]
    return train, test


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score(test: list[AdaptedSession], grammar: SequenceGrammar | None,
          limits: Limits = DEFAULT_LIMITS
          ) -> tuple[list[Outcome], list[dict[str, Any]]]:
    """Run every check over the test side. Returns (outcomes, coverages)."""
    outcomes: list[Outcome] = []
    coverages: list[dict[str, Any]] = []
    for adapted in test:
        session = build_session(adapted, limits)
        findings, cov = run_all(session, grammar, limits=limits)
        fired = frozenset(f.family for f in findings
                          if f.severity in ALERTING_SEVERITIES)
        coverages.append(cov)
        outcomes.append(Outcome(
            session_id=adapted.session_id,
            family=adapted.family,
            task_id=adapted.task_id,
            kind=adapted.kind,
            is_attack=adapted.is_attack,
            # Empty on every external corpus. See the module docstring.
            target_check=adapted.target_check,
            flagged=bool(fired),
            fired_checks=fired,
            completeness=float(cov["completeness"]),
            target_evaluable=True,
        ))
    return outcomes, coverages


def coverage_report(coverages: list[dict[str, Any]]) -> dict[str, Any]:
    """Per check: how many sessions it declined, and under which reason codes.

    The output this harness exists for. A false-positive rate computed over a
    corpus where four of seven checks never ran is a false-positive rate for
    three checks, and only this table says which three.
    """
    statuses: dict[str, Counter[str]] = {}
    reasons: dict[str, Counter[str]] = {}
    missing: dict[str, Counter[str]] = {}
    confidence: dict[str, list[float]] = {}

    for cov in coverages:
        for contract in cov["checks"]:
            name = contract["check"]
            statuses.setdefault(name, Counter())[contract["status"]] += 1
            reasons.setdefault(name, Counter()).update(contract["reasons"])
            missing.setdefault(name, Counter()).update(
                contract["missing_surfaces"])
            confidence.setdefault(name, []).append(contract["confidence"])

    total = len(coverages)
    out: dict[str, Any] = {}
    for name in sorted(statuses):
        counts = statuses[name]
        declined = counts[STATUS_NOT_EVALUATED]
        confs = confidence[name]
        out[name] = {
            "sessions": total,
            "evaluated": counts[STATUS_EVALUATED],
            "degraded": counts[STATUS_DEGRADED],
            "declined": declined,
            "declined_pct": round(100 * declined / total, 1) if total else 0.0,
            "mean_confidence": round(sum(confs) / len(confs), 3) if confs else 0.0,
            "reason_codes": dict(reasons[name].most_common()),
            "missing_surfaces": dict(missing[name].most_common()),
        }
    return out


def scope_audit(cov_report: dict[str, Any]) -> dict[str, Any]:
    """Compare what the contracts DID against what the scope statement CLAIMS.

    The brief for this harness put it well: on a corpus with no approvals and no
    receipts, the checks that read those surfaces should decline nearly
    everything, and if they do not, that is a bug worth finding.

    So this does not assume the answer. It reports, per check, the claimed
    status and the observed decline rate, and raises a flag where a check the
    scope statement calls externally unvalidatable nonetheless reported itself
    EVALUATED -- which means the contract believes it did its job on telemetry
    that cannot contain its evidence.
    """
    findings: list[str] = []
    rows: dict[str, Any] = {}
    for entry in scope.SCOPE:
        observed = cov_report.get(entry.check)
        if observed is None:
            continue
        row: dict[str, Any] = {
            "claimed": entry.status,
            "declined_pct": observed["declined_pct"],
            "evaluated": observed["evaluated"],
            "degraded": observed["degraded"],
            "mean_confidence": observed["mean_confidence"],
            "reason_codes": observed["reason_codes"],
        }

        # The real test is NOT whether the check declined. It is whether the
        # contract NAMED the surface it was missing. A check that quietly runs
        # to completion without its evidence, and reports nothing missing, is
        # worse than one that declines: it produces a confident answer about a
        # question the telemetry could not pose.
        if entry.status == scope.NOT_VALIDATABLE:
            unreported = sorted(
                s for s in entry.blocking_surfaces
                if not observed["missing_surfaces"].get(s))
            row["blocking_surfaces"] = sorted(entry.blocking_surfaces)
            row["unreported_missing_surfaces"] = unreported
            if unreported:
                row["flag"] = "EVIDENCE_ABSENT_BUT_CONTRACT_DID_NOT_CHARGE_FOR_IT"
                findings.append(
                    f"{entry.check}: the corpus carries none of "
                    f"{unreported}, and the coverage contract did not report "
                    f"any of them missing on a single one of "
                    f"{observed['sessions']} sessions -- it reported "
                    f"{observed['evaluated']} evaluated and "
                    f"{observed['degraded']} degraded, at mean confidence "
                    f"{observed['mean_confidence']}. The check is not "
                    "declining; it is concluding. Read this as a gap in the "
                    "coverage contract rather than as a result.")
        rows[entry.check] = row
    return {"per_check": rows, "flags": findings,
            "scope_summary": scope.summary_line()}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load(args: argparse.Namespace
         ) -> tuple[str, list[AdaptedSession], dict[str, Any]]:
    """Adapt the selected corpus, and report what loading it left out.

    The third element exists for AgentDojo and is empty for the other two. Its
    contents are not decoration: a corpus whose loader silently drops a
    population reports a rate over a set nobody can name, and AgentDojo's
    loader drops two -- traces that recorded an error, and, by default, traces
    where an injection was placed and repelled. Both counts travel with the
    result and are printed.
    """
    if args.stepshield:
        return "stepshield", stepshield.load_directory(
            Path(args.stepshield),
            mark_untrusted_from_labels=args.stepshield_mark_untrusted), {}
    if args.agentdojo:
        report = agentdojo.load_directory(
            Path(args.agentdojo),
            mark_injected_content=args.agentdojo_mark_injected)
        sessions = list(report.sessions)
        notes = report.as_dict()

        # The three-way split, resolved here rather than in the adapter. See
        # the adapter docstring: `security` is the OUTCOME, so a repelled trace
        # is an attack that was placed and did not land. Scoring it as an
        # attack reports a missed detection where there was no deviant
        # behaviour to detect; scoring it as benign penalises the detector for
        # noticing content that really is attacker-authored. It is excluded,
        # and the exclusion is a printed number rather than a silent filter.
        repelled = [s for s in sessions if s.kind == agentdojo.KIND_REPELLED]
        notes["repelled_total"] = len(repelled)
        if args.agentdojo_include_repelled:
            notes["repelled_policy"] = (
                "counted as attacks (--agentdojo-include-repelled)")
            sessions = [
                s if s.kind != agentdojo.KIND_REPELLED
                else replace(s, is_attack=True)
                for s in sessions]
        else:
            notes["repelled_policy"] = "excluded from both rates (default)"
            sessions = [s for s in sessions
                        if s.kind != agentdojo.KIND_REPELLED]
        if not sessions:
            raise AdapterError(
                "every adapted AgentDojo trace was excluded. With only "
                f"{notes['repelled_total']} repelled trace(s) and nothing "
                "else, there is no population to score.")
        return "agentdojo", sessions, notes
    return "atbench", atbench.load_path(Path(args.atbench)), {}


def run(sessions: list[AdaptedSession], corpus: str,
        limits: Limits = DEFAULT_LIMITS,
        source_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fit, score and summarise. The whole measurement, as one dict."""
    train, test = split_tasks(sessions)
    if not test:
        raise AdapterError(
            "The task-disjoint split held out no sessions. With very few tasks "
            "this is possible and the result would be meaningless.")

    benign_train = [s for s in train if not s.is_attack]
    grammar: SequenceGrammar | None = None
    if benign_train:
        grammar = SequenceGrammar().fit(
            [build_session(s, limits) for s in benign_train])

    outcomes, coverages = score(test, grammar, limits)
    cov_report = coverage_report(coverages)
    stats = summarise(outcomes)

    degenerate = sum(1 for s in test if s.task_clustering_is_degenerate)
    absences = sorted({a.surface for s in sessions for a in s.absences.entries})

    return {
        "corpus": corpus,
        "source_report": source_report or {},
        "adapted_sessions": len(sessions),
        "train_sessions": len(train),
        "benign_train_sessions": len(benign_train),
        "baseline_fitted": grammar is not None and grammar.fitted,
        "test_sessions": len(test),
        "headline": {
            "false_positives_per_1000_benign_sessions":
                stats["false_positives_per_1000_benign_sessions"],
            "false_positives_per_1000_sessions":
                stats["false_positives_per_1000_sessions"],
            "note": "Plan against the benign-normalised figure. The "
                    "all-session figure moves with this corpus's attack "
                    "prevalence, which is a property of the corpus.",
        },
        "summary": stats,
        "per_check": check_attribution(outcomes),
        "target_precision_available": False,
        "target_precision_note":
            "External corpora label a trajectory unsafe, not which check is "
            "responsible for catching it. target_precision_pct and "
            "target_attributable_recall are therefore structurally zero here "
            "and must be read as UNAVAILABLE, not as a measured zero.",
        "coverage": cov_report,
        "scope_audit": scope_audit(cov_report),
        "task_clustering": {
            "test_sessions": len(test),
            "test_tasks": len({s.task_id for s in test}),
            "degenerate_sessions": degenerate,
            "degenerate": degenerate == len(test),
            "note": "When every session is its own task the bootstrap interval "
                    "is a session-level interval and buys none of R-15's "
                    "correction. It is reported so the reader knows which.",
        },
        "declared_absences": absences,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render(result: dict[str, Any]) -> str:
    lines: list[str] = []
    add = lines.append
    add(f"External validation: {result['corpus']}")
    add("=" * 60)
    add(f"adapted {result['adapted_sessions']} sessions -> "
        f"{result['train_sessions']} train / {result['test_sessions']} test "
        f"(task-disjoint)")
    add(f"CH01 baseline fitted: {result['baseline_fitted']} "
        f"(on {result['benign_train_sessions']} benign training sessions)")
    source = result.get("source_report") or {}
    if source:
        add("")
        add("WHAT LOADING LEFT OUT -- read before the rates")
        if source.get("files_seen") is not None:
            add(f"  trace files seen                : {source['files_seen']}")
        if source.get("errored_skipped"):
            add(f"  refused, recorded an error      : "
                f"{source['errored_skipped']}  (a run that never finished is "
                f"saved as secure)")
        if source.get("unparsable_skipped"):
            add(f"  refused, not a trace            : "
                f"{source['unparsable_skipped']}")
        if source.get("repelled_total") is not None:
            add(f"  injection placed and repelled   : "
                f"{source['repelled_total']}  -- {source['repelled_policy']}")
        if source.get("kinds"):
            add("  populations                     : "
                + ", ".join(f"{k}={v}" for k, v in source["kinds"].items()))
    add("")

    head = result["headline"]
    stats = result["summary"]
    add("HEADLINE")
    add(f"  false positives per 1,000 BENIGN sessions : "
        f"{head['false_positives_per_1000_benign_sessions']}")
    add(f"  (per 1,000 sessions, do not plan on this)  : "
        f"{head['false_positives_per_1000_sessions']}")
    add(f"  benign sessions in test                    : {stats['benign']}")
    add(f"  attack sessions in test                    : {stats['attacks']}")
    add("")

    add("INTERVALS (Wilson over sessions | bootstrap over tasks)")
    cluster = stats["cluster_aware"]
    for key, label in (("any_alert_recall", "any-alert recall"),
                       ("false_positive_rate", "false positive rate")):
        rate = stats[key]
        lo, hi = cluster[key]["task_bootstrap_ci95"]
        add(f"  {label:<22} {rate['value']:.1%} "
            f"[{rate['ci95_low']:.1%}-{rate['ci95_high']:.1%}] | "
            f"[{lo:.1%}-{hi:.1%}]")
    tc = result["task_clustering"]
    if tc["degenerate"]:
        add("  NOTE: every session is its own task, so the bootstrap above is a")
        add("        session-level interval. It is not the R-15 correction.")
    add("")

    add("COVERAGE CONTRACTS -- what each check could actually do here")
    add(f"  {'check':<42} {'declined':>9} {'eval':>6} {'degr':>6} {'conf':>6}")
    for name, row in result["coverage"].items():
        add(f"  {name:<42} {row['declined_pct']:>8.1f}% "
            f"{row['evaluated']:>6} {row['degraded']:>6} "
            f"{row['mean_confidence']:>6.2f}")
    add("")

    add("  reason codes:")
    for name, row in result["coverage"].items():
        if row["reason_codes"]:
            codes = ", ".join(f"{c}x{n}" for c, n in row["reason_codes"].items())
            add(f"    {name}: {codes}")
    add("")

    audit = result["scope_audit"]
    add("SCOPE AUDIT")
    add(f"  {audit['scope_summary']}")
    if audit["flags"]:
        add("")
        add("  FLAGS -- evidence absent, but the contract did not charge for it:")
        for flag in audit["flags"]:
            add(f"    * {flag}")
    else:
        add("  No contradictions between the scope statement and the contracts.")
    add("")

    add("PER-CHECK PRECISION (any-attack; target precision is UNAVAILABLE)")
    add(f"  {'check':<42} {'on attacks':>11} {'on benign':>10} {'prec':>7}")
    for name, row in result["per_check"].items():
        add(f"  {name:<42} {row['on_attacks']:>11} {row['on_benign']:>10} "
            f"{row['precision_pct']:>6.1f}%")
    add("")
    add(f"  {result['target_precision_note']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_external",
        description="Run Cohaera's checks over an external agent-trace corpus.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--stepshield", metavar="DIR",
        help="Directory of StepShield *.jsonl trajectories, e.g. "
             "stepshield/data/generated_benign")
    source.add_argument(
        "--atbench", metavar="FILE",
        help="ATBench trajectories as a JSON array or JSONL file.")
    source.add_argument(
        "--agentdojo", metavar="DIR",
        help="An AgentDojo run directory, as written by TraceLogger -- "
             "typically ./runs.")
    parser.add_argument(
        "--agentdojo-mark-injected", action="store_true",
        help="Opt in to treating AgentDojo's recorded injection strings as "
             "untrusted-content evidence for CH03, by testing whether each "
             "one is contained in a captured tool result. OFF by default: it "
             "is an ORACLE no deployment has, so it bounds what a real "
             "scanner could supply rather than estimating it.")
    parser.add_argument(
        "--agentdojo-include-repelled", action="store_true",
        help="Count traces where an injection was placed and the agent did "
             "not obey it as attacks. OFF by default, because there is no "
             "deviant behaviour in them for a behavioural check to find; the "
             "excluded count is printed either way.")
    parser.add_argument(
        "--stepshield-mark-untrusted", action="store_true",
        help="Opt in to treating StepShield's per-step rogue annotation on "
             "ingress categories as untrusted-content evidence for CH03. OFF "
             "by default: it is adjacent to a scanner's answer, not equal to "
             "it, and it makes the run label-dependent.")
    parser.add_argument("--json", metavar="FILE",
                        help="Write the full result as JSON.")
    args = parser.parse_args(argv)

    try:
        corpus, sessions, source_report = load(args)
        result = run(sessions, corpus, source_report=source_report)
    except AdapterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(render(result))
    if args.json:
        Path(args.json).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
