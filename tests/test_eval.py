"""Tests for the evaluation harness itself.

An evaluation harness is a measuring instrument, and an unchecked measuring
instrument produces confident wrong numbers, which is worse than no numbers at
all. The assertions in the harness are load-bearing; these check that they are
actually load-bearing rather than decorative.

Four things are worth testing here, and they map to the four ways this could
silently stop measuring anything:

1. THE SPLIT. If train and test share a task, every number is inflated by
   memorisation. ``split`` asserts disjointness; this checks it raises rather
   than merely intending to.

2. THE VOCABULARY. If a tool name added later happens to contain ``post`` or
   ``sync``, the corpus quietly returns to measuring the classifier's keyword
   lists against themselves and the result still looks fine.

3. THE LABELS. A session labelled ``attack_concealment`` whose summary does not
   conceal is a mislabelled sample, and the resulting recall is wrong in the
   direction that flatters the detector.

4. DETERMINISM. The evaluation card pins a corpus digest. If generation is not
   reproducible, that digest identifies nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera.model import _classify
from eval.corpus import generate as gen
from eval.harness import (
    REGIME_FAMILY_HOLDOUT,
    REGIME_RANDOM,
    REGIME_TASK_DISJOINT,
    Labelled,
    LeakageError,
    assert_disjoint,
    split,
)
from eval.metrics import Outcome, summarise, wilson
from eval.vocabulary import (
    CONDITIONS,
    TOOLS,
    assert_unseen_vocabulary_is_unseen,
    audit,
)


def corpus(condition: str = "unseen") -> list[Labelled]:
    """Build a corpus in memory. Does not touch disk."""
    return [
        Labelled(session_id=s.session_id, family=s.family, task_id=s.task_id,
                 kind=s.kind, is_attack=s.is_attack,
                 target_check=s.target_check, events=tuple(s.events))
        for s in gen.generate(condition)
    ]


# =====================================================================
# 1. The split
# =====================================================================


@pytest.mark.parametrize("regime", [REGIME_TASK_DISJOINT, REGIME_FAMILY_HOLDOUT])
def test_split_is_task_disjoint(regime):
    """No task may appear on both sides. This is the harness's one guarantee."""
    rows = corpus()
    train, test = split(rows, regime, seed=1)
    assert train and test
    assert not ({s.task_id for s in train} & {s.task_id for s in test})


def test_family_holdout_holds_out_whole_families():
    train, test = split(corpus(), REGIME_FAMILY_HOLDOUT, seed=1)
    assert not ({s.family for s in train} & {s.family for s in test})


def test_random_split_leaks_which_is_the_point():
    """The leakage control must actually leak, or it controls for nothing.

    If this ever stops leaking, the inflation figure in the evaluation card
    becomes a comparison of two identical things reported as a measurement.
    """
    train, test = split(corpus(), REGIME_RANDOM, seed=1)
    shared = {s.task_id for s in train} & {s.task_id for s in test}
    assert shared, "the random regime is supposed to be contaminated"


def test_assert_disjoint_raises_on_a_contaminated_split():
    """The guard is checked, not assumed."""
    rows = corpus()[:8]
    with pytest.raises(LeakageError, match="both sides"):
        assert_disjoint(rows, rows, REGIME_TASK_DISJOINT)


def test_assert_disjoint_is_deliberately_silent_for_the_leaky_regime():
    rows = corpus()[:8]
    assert_disjoint(rows, rows, REGIME_RANDOM)     # must not raise


def test_every_attempt_of_a_task_lands_on_the_same_side():
    """The mechanism behind the guarantee, checked directly.

    Attempts of one task are near-duplicates. Splitting on session rather than
    on task is exactly the mistake the README cites MCPShield for.
    """
    train, test = split(corpus(), REGIME_TASK_DISJOINT, seed=7)
    sides = {}
    for side, rows in (("train", train), ("test", test)):
        for row in rows:
            assert sides.setdefault(row.task_id, side) == side, (
                f"task {row.task_id} is split across sides")


# =====================================================================
# 2. The vocabulary
# =====================================================================


def test_unseen_vocabulary_is_invisible_to_the_name_heuristic():
    """The assumption the whole evaluation rests on.

    Caught a real one on its first run: ``netsuite_journal_post_entry`` contains
    the egress keyword ``post``, so the corpus would have measured the keyword
    list against itself for that tool without anything saying so.
    """
    assert_unseen_vocabulary_is_unseen()
    for tool in TOOLS:
        assert _classify(tool.unseen) == "unknown", (
            f"{tool.unseen!r} is recognised by the classifier's keyword lists")


def test_lexical_control_is_visible_to_the_name_heuristic():
    """The control must be a control: if it is also unseen, there is no contrast."""
    a = audit("lexical")
    assert a.recognised == a.total, (
        f"only {a.recognised}/{a.total} lexical names are recognised; the "
        "control condition no longer contrasts with the unseen one")


def test_the_two_conditions_describe_the_same_behaviours():
    """Same effects, same reversibility, different names. One variable."""
    for tool in TOOLS:
        assert tool.unseen != tool.lexical
        assert tool.effects, f"{tool.key} declares no effects"


def test_vocabulary_audit_reports_measured_not_assumed_accuracy():
    """The audit is a measurement, so it must be able to report a miss."""
    a = audit("lexical")
    assert a.misclassified, (
        "the lexical control classifies perfectly, which means the audit is not "
        "capable of reporting an error and its 0-error result on 'unseen' proves "
        "nothing")


# =====================================================================
# 3. The labels
# =====================================================================


def test_generator_verifies_its_own_labels():
    gen.verify_templates()


def test_concealing_summaries_actually_conceal():
    """Checked with Cohaera's own disclosure logic, under both vocabularies."""
    for family in gen.FAMILIES:
        keys = tuple(k for k in set(family.spine) | set(family.actions)
                     | {family.exfil} if gen.BY_KEY[k].consequential)
        gen._assert_conceals(family, keys)


def test_terse_confounders_do_not_name_a_tool():
    """If they did, they would be ordinary benign sessions and CH02's known
    ceiling would stop being measured."""
    for family in gen.FAMILIES:
        gen._assert_terse_hides(family)


def test_class_balance_is_exact_and_stated():
    rows = corpus()
    attacks = [r for r in rows if r.is_attack]
    assert len(rows) == len(gen.FAMILIES) * gen.TASKS_PER_FAMILY * gen.ATTEMPTS_PER_TASK
    assert len(attacks) / len(rows) == pytest.approx(1 / 3, abs=0.01)


def test_every_confounder_and_attack_kind_is_present():
    kinds = {r.kind for r in corpus()}
    for kind in gen.BENIGN_KINDS + gen.ATTACK_KINDS:
        assert kind in kinds, f"{kind} was generated zero times"


def test_benign_hard_confounders_are_the_majority_of_benign():
    """A corpus of clean benign sessions measures a false positive rate of zero
    and calls it a result. That is the defect this corpus exists to fix."""
    benign = [r for r in corpus() if not r.is_attack]
    hard = [r for r in benign if r.kind != gen.BENIGN]
    assert len(hard) > len(benign) / 2, (
        f"only {len(hard)}/{len(benign)} benign sessions are hard confounders")


# =====================================================================
# 4. Determinism
# =====================================================================


def test_generation_is_deterministic():
    """The evaluation card pins a corpus digest; that digest must identify
    something."""
    first = [(s.session_id, s.kind, len(s.events)) for s in gen.generate("unseen")]
    second = [(s.session_id, s.kind, len(s.events)) for s in gen.generate("unseen")]
    assert first == second


def test_conditions_differ_only_in_tool_names():
    """Structural equality across conditions, which is what makes the delta in
    the evaluation card attributable to naming alone."""
    a = {s.session_id.split("-", 1)[1]: s for s in gen.generate("unseen")}
    b = {s.session_id.split("-", 1)[1]: s for s in gen.generate("lexical")}
    assert a.keys() == b.keys()
    for key, spec in a.items():
        other = b[key]
        assert spec.kind == other.kind
        assert spec.family == other.family
        assert len(spec.events) == len(other.events), (
            f"{key}: {len(spec.events)} events under 'unseen' but "
            f"{len(other.events)} under 'lexical'; the conditions differ in "
            "structure, not only in naming")


# =====================================================================
# Metrics
# =====================================================================


def test_wilson_does_not_claim_certainty_from_a_small_sample():
    """The reason this is not a normal approximation.

    8/8 is not 100% +/- 0%, and a card that says it is has published a claim it
    cannot support.
    """
    lo, hi = wilson(8, 8)
    assert lo < 1.0, "a perfect score on 8 samples must not have a lower bound of 1"
    assert hi == 1.0
    assert lo > wilson(2, 2)[0], "more evidence must narrow the interval"


def test_wilson_stays_inside_the_probability_scale():
    for successes, total in ((0, 5), (5, 5), (1, 1000), (999, 1000)):
        lo, hi = wilson(successes, total)
        assert 0.0 <= lo <= hi <= 1.0


def test_wilson_with_no_observations_says_it_knows_nothing():
    assert wilson(0, 0) == (0.0, 1.0)


def _outcome(is_attack: bool, flagged: bool, completeness: float = 1.0) -> Outcome:
    return Outcome(session_id="s", family="f", task_id="t", kind="k",
                   is_attack=is_attack, target_check="CH01_sequence_order",
                   flagged=flagged, fired_checks=frozenset({"CH01_sequence_order"})
                   if flagged else frozenset(), completeness=completeness,
                   target_evaluable=True)


def test_summarise_counts_the_confusion_matrix_correctly():
    outcomes = ([_outcome(True, True)] * 7 + [_outcome(True, False)] * 3
                + [_outcome(False, True)] * 2 + [_outcome(False, False)] * 88)
    s = summarise(outcomes)
    assert s["confusion"] == {"tp": 7, "fn": 3, "fp": 2, "tn": 88}
    assert s["recall"]["value"] == pytest.approx(0.7)
    assert s["false_positive_rate"]["value"] == pytest.approx(0.02222, abs=1e-4)
    assert s["false_positives_per_1000_sessions"] == pytest.approx(20.0)


def test_coverage_weighted_recall_discounts_a_blind_detection():
    """A detection on a session Cohaera says it could barely see is worth less
    than one on a session it saw fully."""
    outcomes = [_outcome(True, True, completeness=0.2),
                _outcome(True, False, completeness=1.0)]
    s = summarise(outcomes)
    assert s["recall"]["value"] == pytest.approx(0.5)
    assert s["coverage_weighted_recall"] < s["recall"]["value"]


@pytest.mark.parametrize("condition", CONDITIONS)
def test_manifest_covers_every_tool_a_family_can_use(condition):
    """A manifest missing a tool would silently move that tool into the
    name-heuristic condition, mixing the two things being contrasted."""
    for family in gen.FAMILIES:
        manifest = gen.manifest_for(family, condition)
        used = set(family.spine) | set(family.actions) | set(family.rare)
        used.add(family.exfil)
        for key in used:
            name = gen.BY_KEY[key].name(condition)
            assert name in manifest["tools"], (
                f"{family.name}/{condition}: {name} is used but not declared")
