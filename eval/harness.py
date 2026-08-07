"""Split, fit, score. The split is the part that decides whether any of it means
anything.

WHY THE SPLIT IS ENFORCED IN CODE
---------------------------------
The README already cites MCPShield's finding that random splits inflate AUROC by
up to 26 points on agent-trace data. Until now that was a sentence in a docstring
and nothing in the repository could have produced a random split by accident,
because nothing in the repository split anything at all.

A split is a load-bearing part of a measurement, and load-bearing parts get
assertions. :func:`split` refuses to return a split whose train and test sides
share a task, and the test suite checks that it refuses.

THREE REGIMES, AND WHY EACH ONE IS HERE
---------------------------------------

``task_disjoint`` (the honest default)
    Tasks are disjoint; families are shared. Every attempt of a task lands on
    the same side. This is the realistic deployment: you fit the baseline on
    this agent's own benign history, then score its new sessions.

``family_holdout``
    Whole families are held out, so the baseline has never seen the TEST
    workload's tools at all. This is the harder and less flattering question:
    does the detector transfer to an agent it was not fitted on? For a
    sequence-grammar check the answer is knowable in advance and the number is
    still worth having, because deployments do this by mistake.

``random`` (the leakage control -- NEVER a result)
    Sessions are split at random, so attempts of the same task appear on both
    sides. This exists solely to MEASURE the inflation on this corpus rather
    than cite someone else's figure for it. Any number produced under this
    regime is reported as contamination, and the card says so.
"""

from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera.capabilities import EMPTY_MANIFEST, CapabilityManifest
from cohaera.checks import SequenceGrammar, run_all
from cohaera.identity import Correlator
from cohaera.ingest import assemble
from cohaera.limits import DEFAULT_LIMITS, Limits
from cohaera.model import Event, Session
from eval.metrics import Outcome

# Where a tool's capability comes from. This is the axis the fourth review asked
# for, and it needs THREE settings rather than the obvious two.
#
# "With and without a manifest" turned out to measure nothing on the first run:
# both conditions scored identically, because observra auto-injects a
# ``reversible`` flag on every tool event and that flag alone classifies a call
# as consequential. The name heuristic was never consulted in either condition.
#
# So the interesting condition is the third one, where BOTH out-of-band sources
# are removed and the classifier has only the tool's name to go on. That is what
# "how well does the name heuristic generalise to tools it has never seen"
# actually asks, and it is the case a deployment lands in when it points Cohaera
# at an agent that neither ships a manifest nor emits reversibility.
CAP_MANIFEST = "manifest"            # out-of-band ground truth, operator-supplied
CAP_PRODUCER_FLAG = "producer_flag"  # no manifest; producer emits `reversible`
CAP_NAME_ONLY = "name_only"          # neither: the name heuristic, alone
CAPABILITY_SOURCES = (CAP_MANIFEST, CAP_PRODUCER_FLAG, CAP_NAME_ONLY)

REGIME_TASK_DISJOINT = "task_disjoint"
REGIME_FAMILY_HOLDOUT = "family_holdout"
REGIME_RANDOM = "random_LEAKY"
REGIMES = (REGIME_TASK_DISJOINT, REGIME_FAMILY_HOLDOUT, REGIME_RANDOM)

# Severities that count as "this session was flagged". info-level findings are
# not alerts and counting them as detections would inflate recall for free.
ALERTING_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


class LeakageError(AssertionError):
    """A split that would let the same task appear on both sides."""


@dataclass(frozen=True)
class Labelled:
    """One corpus session: its telemetry, and the truth about it."""

    session_id: str
    family: str
    task_id: str
    kind: str
    is_attack: bool
    target_check: str
    events: tuple[dict, ...]


def load_corpus(data_dir: Path, condition: str) -> list[Labelled]:
    """Read one condition's telemetry and labels back into memory."""
    labels = {}
    for line in (data_dir / f"{condition}.labels.jsonl").read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            labels[row["session_id"]] = row

    by_session: dict[str, list[dict]] = defaultdict(list)
    for line in (data_dir / f"{condition}.jsonl").read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            by_session[rec["session_id"]].append(rec)

    out = []
    for sid, events in by_session.items():
        row = labels[sid]
        out.append(Labelled(
            session_id=sid, family=row["family"], task_id=row["task_id"],
            kind=row["kind"], is_attack=row["is_attack"],
            target_check=row["target_check"], events=tuple(events)))
    out.sort(key=lambda s: s.session_id)
    return out


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def split(corpus: list[Labelled], regime: str, seed: int,
          test_fraction: float = 0.5) -> tuple[list[Labelled], list[Labelled]]:
    """Partition into (train, test) under one regime.

    Train is used only to fit the benign sequence grammar; nothing else in
    Cohaera learns. Only benign train sessions are used for that, because
    fitting a "normal" on attack traffic teaches the attack as normal -- which
    is EVASION.md E03, and is a corpus poisoning problem this harness cannot
    solve, only avoid committing itself.
    """
    rng = random.Random(f"{seed}:{regime}")

    if regime == REGIME_RANDOM:
        shuffled = list(corpus)
        rng.shuffle(shuffled)
        cut = int(len(shuffled) * (1 - test_fraction))
        return shuffled[:cut], shuffled[cut:]

    if regime == REGIME_TASK_DISJOINT:
        units = sorted({s.task_id for s in corpus})
    elif regime == REGIME_FAMILY_HOLDOUT:
        units = sorted({s.family for s in corpus})
    else:
        raise ValueError(f"unknown split regime {regime!r}")

    rng.shuffle(units)
    cut = max(1, int(len(units) * (1 - test_fraction)))
    train_units = set(units[:cut])
    key = ((lambda s: s.task_id) if regime == REGIME_TASK_DISJOINT
           else (lambda s: s.family))
    train = [s for s in corpus if key(s) in train_units]
    test = [s for s in corpus if key(s) not in train_units]
    assert_disjoint(train, test, regime)
    return train, test


def assert_disjoint(train: list[Labelled], test: list[Labelled],
                    regime: str) -> None:
    """Refuse a contaminated split. The one guarantee this harness makes.

    Deliberately NOT applied to ``random_LEAKY``: that regime exists to be
    contaminated, and asserting it clean would defeat the measurement it is for.
    """
    if regime == REGIME_RANDOM:
        return
    shared_tasks = {s.task_id for s in train} & {s.task_id for s in test}
    if shared_tasks:
        raise LeakageError(
            f"{regime}: {len(shared_tasks)} task(s) appear on both sides of the "
            f"split, so the test set contains near-duplicates of training "
            f"sessions: {sorted(shared_tasks)[:5]}")
    if regime == REGIME_FAMILY_HOLDOUT:
        shared = {s.family for s in train} & {s.family for s in test}
        if shared:
            raise LeakageError(
                f"{regime}: families on both sides: {sorted(shared)}")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _strip_reversible(event: dict) -> dict:
    """Remove the producer's in-band reversibility claim from one event.

    Used only by the ``name_only`` capability condition. It is a removal, not a
    falsification: the event still carries everything else it carried, so what
    is being measured is the absence of a signal rather than a corrupted one.
    """
    out = dict(event)
    data = out.get("data")
    if isinstance(data, dict) and "reversible" in data:
        data = dict(data)
        data.pop("reversible", None)
        out["data"] = data
    return out


def _sessions_for(rows: list[Labelled], manifest: CapabilityManifest,
                  limits: Limits, strip_reversible: bool = False
                  ) -> dict[str, Session]:
    """Assemble each labelled row into a Cohaera Session, keyed by session_id.

    Assembled one row at a time on purpose. The corpus supplies a session_id per
    row, so a single ``assemble`` over everything would produce the same
    grouping -- but doing it per row means a change to correlation behaviour
    cannot silently merge two corpus sessions and corrupt the labels.
    """
    out = {}
    for row in rows:
        raws = [_strip_reversible(e) if strip_reversible else dict(e)
                for e in row.events]
        events = [Event(raw=r, limits=limits) for r in raws]
        sessions = assemble(events, limits=limits, manifest=manifest,
                            correlator=Correlator(b"eval", limits=limits))
        if len(sessions) != 1:
            raise AssertionError(
                f"{row.session_id}: assembled into {len(sessions)} sessions, so "
                "the label no longer describes one session")
        out[row.session_id] = sessions[0]
    return out


def fit_grammar(train: list[Labelled], manifest: CapabilityManifest,
                limits: Limits, strip_reversible: bool = False) -> SequenceGrammar:
    """Fit the benign sequence grammar on the training side's BENIGN sessions."""
    benign = [r for r in train if not r.is_attack]
    sessions = list(_sessions_for(benign, manifest, limits,
                                  strip_reversible).values())
    return SequenceGrammar().fit(sessions)


def score(test: list[Labelled], grammar: SequenceGrammar | None,
          manifest: CapabilityManifest,
          limits: Limits = DEFAULT_LIMITS,
          strip_reversible: bool = False) -> list[Outcome]:
    """Run every check over the test side and record what happened."""
    sessions = _sessions_for(test, manifest, limits, strip_reversible)
    outcomes = []
    for row in test:
        session = sessions[row.session_id]
        findings, cov = run_all(session, grammar, limits=limits)
        fired = frozenset(f.family for f in findings
                          if f.severity in ALERTING_SEVERITIES)
        status = {c["check"]: c["status"] for c in cov["checks"]}
        outcomes.append(Outcome(
            session_id=row.session_id, family=row.family, task_id=row.task_id,
            kind=row.kind, is_attack=row.is_attack,
            target_check=row.target_check,
            flagged=bool(fired), fired_checks=fired,
            completeness=float(cov["completeness"]),
            target_evaluable=(
                status.get(row.target_check, "not_evaluated") != "not_evaluated"
                if row.target_check else True),
        ))
    return outcomes


def run_condition(corpus: list[Labelled], regime: str, seed: int,
                  manifest: CapabilityManifest,
                  limits: Limits = DEFAULT_LIMITS,
                  capability_source: str = CAP_MANIFEST
                  ) -> tuple[list[Outcome], dict]:
    """Split, fit on train-benign, score test. Returns (outcomes, provenance)."""
    strip = capability_source == CAP_NAME_ONLY
    if capability_source != CAP_MANIFEST:
        manifest = EMPTY_MANIFEST
    train, test = split(corpus, regime, seed)
    grammar = fit_grammar(train, manifest, limits, strip)
    outcomes = score(test, grammar, manifest, limits, strip)
    return outcomes, {
        "regime": regime,
        "capability_source": capability_source,
        "train_sessions": len(train),
        "test_sessions": len(test),
        "train_tasks": len({s.task_id for s in train}),
        "test_tasks": len({s.task_id for s in test}),
        "train_families": sorted({s.family for s in train}),
        "test_families": sorted({s.family for s in test}),
        "grammar_sessions_fitted": grammar.sessions_fitted,
        "grammar_transitions": len(grammar.bigrams),
        "baseline_hash": grammar.fingerprint(),
        "manifest_loaded": manifest.loaded,
        "manifest_file_digest": manifest.file_digest,
        "manifest_semantic_digest": manifest.semantic_digest,
        "manifest_tools": len(manifest.tools),
    }


def load_manifest(data_dir: Path, condition: str,
                  limits: Limits = DEFAULT_LIMITS) -> CapabilityManifest:
    return CapabilityManifest.from_file(
        data_dir / "manifests" / condition / "_all.json", limits=limits)


NO_MANIFEST = EMPTY_MANIFEST
