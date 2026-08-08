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

import base64
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
from cohaera.evidence import (
    EMPTY_STORE,
    INTEGRITY_FIELD,
    TrustStore,
    body_digest,
    chain_step,
    signing_input,
)
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
    # Which attempt of its task this is. Needed by the leakage experiment, which
    # has to split a task's attempts across train and test on purpose.
    attempt: int = 0


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
            target_check=row["target_check"], events=tuple(events),
            attempt=int(row.get("attempt", 0))))
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

    THE SIGNATURE IS REBUILT TOO, and for exactly the same reason one layer up.
    A signature covers the chain head, so recomputing the chain and leaving the
    old signature in place would have made every signed session in this
    condition report INTEGRITY_SIGNATURE_INVALID -- the same false-positive
    cascade the chain rebuild exists to prevent, arriving one layer later and
    looking like a cryptographic finding instead of a harness artifact.

    Re-signing is only defensible because these are the corpus's own published
    keys, signing the corpus's own synthetic stream, and because the
    counterfactual collector would have signed the records that agent actually
    wrote. The key used is the one the record was ALREADY signed by, so the
    rotation and the revocation this condition is measuring are preserved
    exactly -- the harness does not get to decide which key attested anything.
    """
    secrets = {key_id: seed for seed, _public, key_id in gen.EVAL_KEYS.values()}
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
        secret = secrets.get(sidecar.get("key_id"))
        if secret is not None and sidecar.get("sig") is not None:
            # Through the corpus's signature cache, for the reason
            # eval/corpus/signatures.py gives: this is the producer side, the
            # message is derived from the chain the harness just rebuilt, and
            # rebuilding it is deterministic -- so every pass over the corpus was
            # re-deriving the same signatures the previous pass derived.
            sidecar["sig"] = base64.b64encode(gen.SIGNATURES.sign(
                secret, sidecar["key_id"],
                signing_input(sidecar["stream_id"], sidecar["seq"],
                              prev))).decode("ascii")
        out.append({**body, INTEGRITY_FIELD: sidecar})
    return out


def _assembly_fingerprint(manifest: CapabilityManifest, limits: Limits,
                          strip_reversible: bool,
                          store: TrustStore) -> tuple:
    """Everything other than the rows that decides what a Session comes out as.

    The regime is deliberately absent, and that absence is the whole point of
    :class:`SessionCache`: a regime decides which side of the split a session
    lands on, not what the session IS.
    """
    return (manifest.semantic_digest, manifest.loaded, len(manifest.tools),
            bool(strip_reversible), store.semantic_digest, limits.digest())


class SessionCache:
    """Assembled sessions, reused across regimes.

    THE COST THIS REMOVES IS NOT A MEASUREMENT. Assembly is the evaluation's
    dominant expense -- parsing every record, canonicalising it, walking the
    hash chain and verifying signatures in pure-Python Ed25519 -- and the grid
    runs three regimes over the same corpus under each capability condition. The
    regime changes which sessions are trained on and which are scored. It does
    not change what any session assembles into, so the corpus was being
    assembled about four times more often than there were distinct sessions, and
    every one of those repeats produced an object identical to the one before it.

    SAFE BECAUSE THE SESSIONS ARE SEALED. ``assemble`` returns sessions whose
    ``events`` is a tuple; see the C4-08 note on :class:`cohaera.model.Session`.
    Nothing downstream can mutate one, its derived values are cached over an
    immutable sequence, and ``run_all`` takes the grammar as an argument rather
    than storing it. Scoring the same session under three regimes therefore
    reads the same object three times and asks it three different questions.

    IT REFUSES TO ANSWER A QUESTION IT WAS NOT ASKED. A cache holds the
    assembly parameters it was first used with and raises on a lookup made under
    different ones, rather than serving a session assembled with a different
    manifest, trust store or capability condition. An evaluation that silently
    reports numbers from a configuration it never ran is the failure this is
    guarding against, and it is a quiet one.
    """

    def __init__(self) -> None:
        self.fingerprint: tuple | None = None
        self.sessions: dict[str, Session] = {}
        self.hits = 0
        self.misses = 0

    def bind(self, fingerprint: tuple) -> None:
        if self.fingerprint is None:
            self.fingerprint = fingerprint
            return
        if self.fingerprint != fingerprint:
            raise AssertionError(
                "this session cache was built under assembly parameters "
                f"{self.fingerprint} and is being used under {fingerprint}. "
                "Use one cache per (vocabulary, capability condition); sharing "
                "one across them would score sessions that were never "
                "assembled the way the cell claims.")

    def summary(self) -> str:
        total = self.hits + self.misses
        if not total:
            return "session cache: unused"
        return (f"session cache: {self.hits}/{total} reused "
                f"({self.misses} assembled)")


def _sessions_for(rows: list[Labelled], manifest: CapabilityManifest,
                  limits: Limits, strip_reversible: bool = False,
                  store: TrustStore = EMPTY_STORE,
                  cache: SessionCache | None = None) -> dict[str, Session]:
    """Assemble each labelled row into a Cohaera Session, keyed by session_id.

    Assembled one row at a time on purpose. The corpus supplies a session_id per
    row, so a single ``assemble`` over everything would produce the same
    grouping -- but doing it per row means a change to correlation behaviour
    cannot silently merge two corpus sessions and corrupt the labels.
    """
    if cache is not None:
        cache.bind(_assembly_fingerprint(manifest, limits, strip_reversible,
                                         store))
    out = {}
    for row in rows:
        if cache is not None:
            reused = cache.sessions.get(row.session_id)
            if reused is not None:
                cache.hits += 1
                out[row.session_id] = reused
                continue
        raws = [_strip_reversible(e) if strip_reversible else dict(e)
                for e in row.events]
        if strip_reversible:
            raws = _rechain(raws)
        events = [Event(raw=r, limits=limits) for r in raws]
        sessions = assemble(events, limits=limits, manifest=manifest,
                            correlator=Correlator(b"eval", limits=limits),
                            keys=store)
        if len(sessions) != 1:
            raise AssertionError(
                f"{row.session_id}: assembled into {len(sessions)} sessions, so "
                "the label no longer describes one session")
        out[row.session_id] = sessions[0]
        if cache is not None:
            cache.misses += 1
            cache.sessions[row.session_id] = sessions[0]
    return out


def fit_grammar(train: list[Labelled], manifest: CapabilityManifest,
                limits: Limits, strip_reversible: bool = False,
                store: TrustStore = EMPTY_STORE,
                cache: SessionCache | None = None) -> SequenceGrammar:
    """Fit the benign sequence grammar on the training side's BENIGN sessions."""
    benign = [r for r in train if not r.is_attack]
    sessions = list(_sessions_for(benign, manifest, limits,
                                  strip_reversible, store, cache).values())
    return SequenceGrammar().fit(sessions)


def score(test: list[Labelled], grammar: SequenceGrammar | None,
          manifest: CapabilityManifest,
          limits: Limits = DEFAULT_LIMITS,
          strip_reversible: bool = False,
          store: TrustStore = EMPTY_STORE,
          cache: SessionCache | None = None) -> list[Outcome]:
    """Run every check over the test side and record what happened."""
    sessions = _sessions_for(test, manifest, limits, strip_reversible, store,
                             cache)
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
                  capability_source: str = CAP_MANIFEST,
                  store: TrustStore = EMPTY_STORE,
                  cache: SessionCache | None = None
                  ) -> tuple[list[Outcome], dict]:
    """Split, fit on train-benign, score test. Returns (outcomes, provenance)."""
    strip = capability_source == CAP_NAME_ONLY
    if capability_source != CAP_MANIFEST:
        manifest = EMPTY_MANIFEST
    train, test = split(corpus, regime, seed)
    grammar = fit_grammar(train, manifest, limits, strip, store, cache)
    outcomes = score(test, grammar, manifest, limits, strip, store, cache)
    return outcomes, {
        "regime": regime,
        "capability_source": capability_source,
        "train_sessions": len(train),
        "trust_store_semantic_digest": store.semantic_digest,
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


def leakage_experiment(corpus: list[Labelled], seed: int,
                       manifest: CapabilityManifest,
                       limits: Limits = DEFAULT_LIMITS,
                       store: TrustStore = EMPTY_STORE,
                       ) -> tuple[list[Outcome], list[Outcome], dict]:
    """Measure leakage with ONE test set, varying only the contamination.

    C5-04. The card used to compare the ``task_disjoint`` cell against the
    ``random_LEAKY`` cell and call the difference the measured cost of leakage.
    It is not. Each regime seeds its own shuffle, so the two cells score
    DIFFERENT test sessions at different attack prevalences, and the random
    cell's precision is helped by having more attacks in it. Two things changed
    at once and the difference was attributed to one of them.

    The controlled version holds the test set fixed and changes exactly one
    thing -- whether sibling attempts of the test tasks are allowed into the
    training set:

        test set     attempts 0 and 1 of every held-out task, both runs
        clean train  the training tasks only
        leaky train  the training tasks PLUS attempts 2 and 3 of the test tasks

    Attempts of one task are near-duplicates by construction, so the leaky run
    fits its "normal" on near-copies of the very sessions it is about to score.
    That is the mistake MCPShield measured at up to 26 AUROC points on
    agent-trace data, and this is what it is worth on this corpus, paired.
    """
    train, test = split(corpus, REGIME_TASK_DISJOINT, seed)
    held_out_tasks = {row.task_id for row in test}
    fixed_test = [r for r in test if r.attempt in (0, 1)]
    siblings = [r for r in test if r.attempt not in (0, 1)]
    if not fixed_test or not siblings:
        raise AssertionError(
            "the leakage experiment needs at least two attempts per task on "
            "each side; the corpus no longer supplies them")

    # One cache across all four passes. Every one of them assembles under the
    # same manifest, store and capability condition -- the experiment varies the
    # TRAINING SET and nothing else, which is the point of it -- and the fixed
    # test set is scored twice by construction.
    cache = SessionCache()
    clean_grammar = fit_grammar(train, manifest, limits, store=store, cache=cache)
    leaky_grammar = fit_grammar([*train, *siblings], manifest, limits,
                                store=store, cache=cache)
    clean = score(fixed_test, clean_grammar, manifest, limits, store=store,
                  cache=cache)
    leaky = score(fixed_test, leaky_grammar, manifest, limits, store=store,
                  cache=cache)
    return clean, leaky, {
        "test_sessions": len(fixed_test),
        "test_attacks": sum(1 for r in fixed_test if r.is_attack),
        "test_tasks": len(held_out_tasks),
        "clean_train_sessions": len(train),
        "leaky_train_sessions": len(train) + len(siblings),
        "sibling_sessions_leaked": len(siblings),
        "clean_baseline_hash": clean_grammar.fingerprint(),
        "leaky_baseline_hash": leaky_grammar.fingerprint(),
        # The two runs score the SAME sessions. If this ever stops being true
        # the experiment has silently gone back to comparing two populations.
        "test_set_identical": True,
    }


def load_manifest(data_dir: Path, condition: str,
                  limits: Limits = DEFAULT_LIMITS) -> CapabilityManifest:
    return CapabilityManifest.from_file(
        data_dir / "manifests" / condition / "_all.json", limits=limits)


def load_trust_store(data_dir: Path, condition: str,
                     limits: Limits = DEFAULT_LIMITS) -> TrustStore:
    """The keys the corpus's second collector stream was signed under.

    Loaded out of band, from beside the manifests, because it is the same kind
    of artifact: something the operator declares and the telemetry cannot talk
    them out of.

    Every path that scores the corpus has to pass this. Without it the signed
    stream is parsed and not verified, so ``attack_revoked_key_stream`` becomes
    an ordinary session nothing fires on and overall recall silently falls --
    a measurement error that would look like a detector result.
    ``tests/test_eval.py`` asserts the kind is caught, so forgetting it fails
    loudly rather than quietly.
    """
    return TrustStore.from_file(
        data_dir / "manifests" / condition / "trust-store.json", limits=limits)


NO_MANIFEST = EMPTY_MANIFEST
