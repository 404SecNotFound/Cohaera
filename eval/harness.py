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
from cohaera.evidence import INTEGRITY_FIELD, body_digest, chain_step
from cohaera.identity import Correlator
from cohaera.ingest import assemble
from cohaera.limits import DEFAULT_LIMITS, Limits
from cohaera.model import Event, Session
from eval.corpus import generate as gen
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
        # STRATIFIED by (family, kind), not a free shuffle over all tasks.
        #
        # Tasks stay disjoint -- that is the guarantee, and it is still asserted
        # below -- but WHICH tasks land in train is no longer a coin flip per
        # kind. A free shuffle gave each family a ~25% chance of putting both of
        # its looping benign tasks in test, and with eight families the odds of
        # that happening somewhere were about 90%. A baseline fitted on the
        # remainder has then never seen an agent repeat its own spine, so every
        # loop boundary in a long session scores as a novel transition and the
        # dilution sessions stop measuring dilution.
        #
        # That is not a hypothetical: it is what this corpus revision hit, and
        # `test_the_long_kinds_stay_below_ch01s_rate_threshold` is what caught
        # it. The old numbers were not wrong so much as lucky, and a measurement
        # that depends on the seed landing well is not a measurement.
        #
        # Stratifying does not weaken the split. Leakage is attempts of ONE task
        # appearing on both sides; that is untouched. What it fixes is the train
        # side being unrepresentative of the benign behaviour it is supposed to
        # be a baseline OF -- which is what "fit on this agent's own history"
        # means in a deployment, where the history contains the loops because
        # the agent loops.
        #
        # Three groups, because two different things have to be true of train
        # and a single rule cannot make both true.
        #
        # 1. PLAIN BENIGN is stratified per (family, kind), so every family
        #    contributes ordinary work -- including a looping session -- to the
        #    baseline. This is the fix for the failure above.
        #
        # 2. benign_hard_long_rare_action is assigned per FAMILY, and half the
        #    families deliberately contribute NONE of it to train. This one is
        #    not a shuffle at all, and the reason is that it was one and should
        #    never have been. The card's "CH01 fires on 16 of 32" was a fact
        #    about where the seed happened to land: stratifying this kind sent
        #    the figure to 0 of 32, a free shuffle had previously sent it to
        #    16, and a later draw could send it anywhere. A confounder whose
        #    strength is a property of the seed cannot grade a detector, and
        #    reporting the flattering draw of it is how a corpus starts lying.
        #    Fixing the assignment makes the split of families -- some whose
        #    fitted window contains the rare action, some whose does not -- a
        #    stated property of the corpus, which is what it was always
        #    claiming to be.
        #
        # 3. EVERYTHING ELSE stays on the free shuffle. Those confounders do not
        #    depend on what the baseline learned, so nothing needs pinning.
        plain = set(gen.PLAIN_BENIGN_KINDS)
        kinds = {s.task_id: (s.family, s.kind) for s in corpus}
        families = sorted({f for f, _ in kinds.values()})
        # Families whose rare secondary action must stay OUT of the baseline.
        confounding = {f for i, f in enumerate(families) if i % 2 == 0}

        by_stratum: dict[tuple[str, str], list[str]] = defaultdict(list)
        long_rare: dict[str, list[str]] = defaultdict(list)
        loose: list[str] = []
        train_units = set()
        for task_id, (family, kind) in sorted(kinds.items()):
            if kind in plain:
                by_stratum[(family, kind)].append(task_id)
            elif kind == gen.BENIGN_HARD_LONG_RARE:
                long_rare[family].append(task_id)
            else:
                loose.append(task_id)
        # A confounding family sends all of its long-rare tasks to test, so the
        # baseline never learns its secondary action. A non-confounding family
        # keeps ONE back for test as well -- it must, or the test split would
        # contain nothing but sessions built to trip CH01 and the kind's row in
        # the card would read 32 of 32 by construction. The control case, where
        # the baseline HAS seen the rare action and the check correctly stays
        # quiet, is half of what this kind is for.
        for family, tasks in sorted(long_rare.items()):
            if family not in confounding:
                train_units.update(tasks[:-1])
        for stratum in sorted(by_stratum):
            group = by_stratum[stratum]
            rng.shuffle(group)
            train_units.update(group[:max(1, int(len(group) * (1 - test_fraction)))])
        rng.shuffle(loose)
        train_units.update(loose[:max(1, int(len(loose) * (1 - test_fraction)))])
        train = [s for s in corpus if s.task_id in train_units]
        test = [s for s in corpus if s.task_id not in train_units]
        assert_disjoint(train, test, regime)
        return train, test

    if regime == REGIME_FAMILY_HOLDOUT:
        units = sorted({s.family for s in corpus})
    else:
        raise ValueError(f"unknown split regime {regime!r}")

    rng.shuffle(units)
    cut = max(1, int(len(units) * (1 - test_fraction)))
    train_units = set(units[:cut])
    def key(s):
        return s.family
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


def _rechain(records: list[dict]) -> list[dict]:
    """Rebuild the integrity chain over records the harness has just edited.

    NOT a convenience. Without it, ``name_only`` measured something absurd:
    stripping ``reversible`` changes the record, the collector's hash chain
    correctly reports that the record changed, and CH06 fired on 596 of 596
    benign sessions -- a 100% false positive rate that was entirely the
    harness editing evidence and then being surprised that the tamper-evidence
    noticed.

    The counterfactual this condition constructs is *an agent that never
    emitted reversibility*. Its collector would have chained the records that
    agent actually wrote, so the honest edit is to strip the field AND rebuild
    the chain over the result. Stripping without rebuilding measures the
    integrity check instead of the classifier.

    Sequence numbers and stream identity are untouched, so a session whose
    records were DELETED at generation time still shows its gap. Only the chain
    is recomputed, and only for a condition that has already modified the
    stream on purpose.
    """
    out = []
    prev = None
    for record in records:
        sidecar = record.get(INTEGRITY_FIELD)
        if not isinstance(sidecar, dict):
            out.append(record)
            continue
        sidecar = dict(sidecar)
        if prev is not None:
            sidecar["prev"] = prev
        body = {k: v for k, v in record.items() if k != INTEGRITY_FIELD}
        prev = sidecar["chain"] = chain_step(sidecar.get("prev") or "",
                                             body_digest(body))
        out.append({**body, INTEGRITY_FIELD: sidecar})
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
        if strip_reversible:
            raws = _rechain(raws)
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
