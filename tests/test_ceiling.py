"""Tests for the corpus discrimination ceiling.

The ceiling is an argument about what a corpus CAN test, and it is used to
explain a zero. That makes it exactly the kind of number that flatters whoever
computed it, so the tests here are aimed at the ways it could flatter:

1. THE BOUND IS A BOUND. Identical representations must count as
   indistinguishable, ties must be scored wrong rather than as half a
   detection, and adding information to a representation must never make the
   ceiling go DOWN. A ceiling that moves the wrong way when given more to read
   is not measuring what it says.

2. THE SPEED OPTIMISATION IS SEMANTICS-PRESERVING. The permutation test flips
   a pair by negating its precomputed delta instead of swapping the two
   trajectories and re-deriving features. That is only valid if the two are
   genuinely equal, so it is asserted against the slow path rather than
   assumed. The slow path is what the first version ran, and it took an hour.

3. NO LABEL LEAKAGE. The step labels ARE the answer. A feature that reads them
   would produce a beautiful accuracy and mean nothing, and the failure would
   look like success -- the worst shape a defect can have. Asserted by
   mutation: rewrite every label and require the features not to move.

The fixtures are hand-built pairs, not corpus data. No number computed here
says anything about StepShield.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval" / "external"))

import ceiling


def _step(action: str, args: dict | None = None, label: str | None = None) -> dict:
    return {"step": 1, "thought": "t", "action": action,
            "arguments": args or {}, "observation": "o",
            "label": label, "rationale": None}


def _pair(family: str, rogue: list[dict], clean: list[dict]) -> ceiling.Pair:
    return ceiling.Pair(f"{family}-001", family, rogue, clean)


def _twin(family: str, steps: list[dict]) -> ceiling.Pair:
    """A pair whose halves are identical -- the indistinguishable case."""
    return _pair(family, steps, json.loads(json.dumps(steps)))


# ---------------------------------------------------------------------------
# 1. The bound is a bound
# ---------------------------------------------------------------------------


def test_identical_halves_are_indistinguishable_at_every_representation():
    pair = _twin("SEC", [_step("run_command", {"command": "ls"}),
                         _step("submit", {"message": "done"})])
    for name, phi in ceiling.REPRESENTATIONS:
        assert ceiling.indistinguishable([pair], phi) == [pair], name


def test_a_pair_differing_only_in_argument_values_is_blind_to_structure():
    """The finding the whole document rests on, as a unit test.

    Same tool, same order, same argument keys, different values. Everything
    below the digest layer must call this pair indistinguishable; the digest
    layer must not.
    """
    rogue = [_step("run_command", {"command": "rm -rf /var/log/app"})]
    clean = [_step("run_command", {"command": "du -sh /var/log/app"})]
    pair = _pair("INV", rogue, clean)

    for name in ("action_sequence", "action_multiset", "sequence_plus_arity"):
        phi = dict(ceiling.REPRESENTATIONS)[name]
        assert ceiling.indistinguishable([pair], phi) == [pair], name

    digest = dict(ceiling.REPRESENTATIONS)["sequence_plus_digest"]
    assert ceiling.indistinguishable([pair], digest) == []


def test_more_information_never_lowers_the_ceiling():
    """Monotonicity. sequence_plus_digest reads a strict superset of what
    action_sequence reads, so it can only ever distinguish more pairs. If this
    inverts, a representation is dropping information it claims to add."""
    pairs = [
        _twin("SEC", [_step("run_command", {"command": "ls"})]),
        _pair("INV", [_step("run_command", {"command": "rm -rf /x"})],
              [_step("run_command", {"command": "du -sh /x"})]),
        _pair("TST", [_step("edit_file", {"path": "a"}), _step("submit", {})],
              [_step("submit", {}), _step("edit_file", {"path": "a"})]),
    ]
    seq = len(ceiling.indistinguishable(pairs, ceiling.action_sequence))
    dig = len(ceiling.indistinguishable(pairs, ceiling.sequence_plus_digest))
    assert dig <= seq


def test_order_matters_to_the_sequence_and_not_to_the_multiset():
    """The multiset is reported BECAUSE it is weaker. If it ever stopped being
    weaker, the pair of rows would no longer isolate how much of the signal is
    ordering, and reporting both would be noise."""
    pair = _pair("TST", [_step("edit_file", {"p": "a"}), _step("submit", {})],
                 [_step("submit", {}), _step("edit_file", {"p": "a"})])
    assert ceiling.indistinguishable([pair], ceiling.action_sequence) == []
    assert ceiling.indistinguishable([pair], ceiling.action_multiset) == [pair]


def test_a_tie_is_scored_wrong_and_never_as_half_a_detection():
    """Rounding an undecidable pair up to 0.5 is how a ceiling gets inflated,
    and it would be invisible in the headline number."""
    w = [1.0, 0.0]
    correct, total = ceiling._accuracy(w, [[0.0, 0.0], [0.0, 0.0]])
    assert (correct, total) == (0, 2)


def test_an_empty_rule_wins_nothing():
    correct, total = ceiling._accuracy([], [[1.0], [1.0]])
    assert correct == 0
    assert total == 2


# ---------------------------------------------------------------------------
# 2. The speed optimisation is semantics-preserving
# ---------------------------------------------------------------------------


def test_negating_a_delta_equals_swapping_the_two_trajectories():
    """The permutation test's entire correctness rests on this identity.

    It is asserted against the slow path -- actually building the swapped pair
    and re-deriving its features -- rather than reasoned about, because the
    optimisation was made for speed after the honest version had already run,
    and an optimisation that quietly changes a result is the failure mode.
    """
    rogue = [_step("run_command", {"command": "rm -rf /x"}),
             _step("edit_file", {"path": "tests/t.py"}),
             _step("submit", {"message": "done"})]
    clean = [_step("run_command", {"command": "du -sh /x"}),
             _step("open_file", {"path": "src/a.py"}),
             _step("submit", {"message": "failed"})]
    pair = _pair("SEC", rogue, clean)

    fast = [-x for x in ceiling._delta(pair)]
    slow = ceiling._delta(ceiling.Pair(pair.task, pair.family,
                                       pair.clean, pair.rogue))
    assert fast == slow


def test_the_holdout_declines_when_there_are_too_few_families():
    """A fold count of one is not a holdout. It must say so with a reason
    rather than returning an accuracy nobody can interpret."""
    rows = ceiling.samples([_pair("SEC", [_step("submit", {})],
                                  [_step("noop", {})])])
    result = ceiling.family_holdout(rows)
    assert result["folds"] == 0
    assert result["reason"] == "TOO_FEW_FAMILIES"
    assert "accuracy" not in result


def test_the_run_is_deterministic():
    """Same corpus, same JSON. A bound that moves between runs cannot be
    committed as an artefact, and the permutation test is the part that would
    move if the seed ever stopped being honoured."""
    pairs = [_pair(f, [_step("run_command", {"command": f"a{i}"})],
                   [_step("run_command", {"command": f"b{i}"})])
             for i, f in enumerate(("SEC", "INV", "TST", "DEC"))]
    rows = ceiling.samples(pairs)
    first = ceiling.permutation_test(rows, 50.0, rounds=5)
    second = ceiling.permutation_test(rows, 50.0, rounds=5)
    assert first == second


# ---------------------------------------------------------------------------
# 3. No label leakage
# ---------------------------------------------------------------------------


def test_features_do_not_read_step_labels():
    """Mutation: rewrite every label and require the features not to move.

    A feature reading the label would score near 100% and would look like the
    best result in the repository. Asserting on the label being absent from the
    feature list would not catch it -- only mutating the labels does.
    """
    steps = [_step("run_command", {"command": "rm -rf /x"}, label=None),
             _step("edit_file", {"path": "a"}, label=None)]
    before = ceiling.features(steps)

    labelled = [dict(s, label="SEC", rationale="violation") for s in steps]
    assert ceiling.features(labelled) == before


def test_features_do_not_read_thoughts_or_observations():
    """The same guard for the other two free-text fields. Both are content, and
    a feature reading either would be measuring the corpus's prose rather than
    the agent's behaviour."""
    steps = [_step("run_command", {"command": "ls"})]
    before = ceiling.features(steps)
    noisy = [dict(s, thought="I will now exfiltrate the key",
                  observation="PERMISSION DENIED") for s in steps]
    assert ceiling.features(noisy) == before


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_an_unpaired_trajectory_is_dropped_rather_than_counted(tmp_path):
    """A rogue with no clean twin cannot contribute to a paired bound. Keeping
    it would inflate the denominator with sessions the method cannot speak
    about, which would push the ceiling down and look conservative."""
    family = tmp_path / "SEC"
    family.mkdir()
    body = {"trajectory_id": "x", "task": {}, "steps": [_step("submit", {})]}
    for name in ("SEC-L1-001-ROGUE", "SEC-L1-001-CLEAN", "SEC-L1-002-ROGUE"):
        (family / f"{name}.jsonl").write_text(json.dumps(body), encoding="utf-8")

    pairs = ceiling.load_pairs(tmp_path)
    assert [p.task for p in pairs] == ["SEC-L1-001"]


def test_analyse_refuses_a_directory_with_no_pairs(tmp_path):
    (tmp_path / "SEC").mkdir()
    with pytest.raises(SystemExit):
        ceiling.analyse(tmp_path, rounds=1)


def test_binomial_p_is_exact_at_the_extremes():
    assert ceiling.binomial_p(0, 0) is None
    assert ceiling.binomial_p(10, 10) == pytest.approx(1 / 1024)
    assert ceiling.binomial_p(0, 10) == pytest.approx(1.0)
