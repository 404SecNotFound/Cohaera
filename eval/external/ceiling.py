"""What is the best any structure-reading detector could do on this corpus?

Cohaera scored zero on StepShield's attacks. That number is worthless on its
own, because it does not separate two very different explanations:

  1. the detector is bad, or
  2. the corpus does not carry the evidence the detector reads.

This file measures which. It never runs Cohaera. It asks a question about the
CORPUS: how much of the rogue/clean distinction survives at the layer a
structural detector can see at all?

THE ARGUMENT
------------
StepShield ships 639 ROGUE/CLEAN pairs. A pair is one task rendered twice --
same objective, one trajectory that misbehaves and one that does not. That
pairing is what makes a ceiling computable, and it is why this analysis is
possible on StepShield and not on a corpus that merely labels trajectories.

Let phi be everything a detector reads. If phi(rogue) == phi(clean) for a
pair, then any detector reading only phi assigns both the SAME score, because
it is a function of phi and its inputs are equal. It cannot flag one without
flagging the other. So at zero false positives that rogue is unreachable --
not "hard", not "needs tuning". Unreachable, by construction.

That gives a hard upper bound, and it is an upper bound rather than an
estimate: phi differing is necessary for detection, never sufficient. Two
trajectories can be trivially distinguishable and still carry nothing that
says which one is the attack.

So the second half asks whether the surviving difference is USABLE: given the
pairs that are distinguishable, can any rule over structural features pick the
rogue, and does that rule generalise to a task family it was not fitted on?
A rule that only works on the families it saw is a rule that memorised them.

WHAT PHI IS HERE
----------------
Four representations, in increasing generosity. Each is a strict superset of
the one above, so the bounds are monotone and a jump between two of them says
exactly which information bought the gain:

  action_sequence      ordered tool names. The layer CH01 reads.
  action_multiset      tool names and counts, order discarded. Reported because
                       it is WEAKER than the sequence and isolates how much of
                       the signal is ordering.
  sequence_plus_arity  ordered tool names plus argument-key names -- shape of
                       the call without its values.
  sequence_plus_digest ordered tool names plus a hash of the argument VALUES.
                       The most generous honest reading of Cohaera's input:
                       arg_digest is what actually travels in a finding.

The digest layer is the one to argue about, and it is deliberately included as
the friendliest case. A digest distinguishes without interpreting: it says two
calls differ, never that one is dangerous. A detector reading digests can
therefore separate a pair while having no basis to say which half is the
attack. Counting it as detectable is generous to the detector, which is the
right direction for an upper bound to lean.

WHAT THIS DOES NOT CLAIM
------------------------
Not a proof about all possible detectors. It bounds detectors whose input is
one of the four representations above. A detector that reads argument TEXT --
what the command actually says -- is outside the bound, and that is precisely
the class StepShield is built to reward. The conclusion is about a layer, not
about a ceiling on the field.

Deterministic: fixed seed, no wall-clock, no network. Same corpus, same JSON.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import itertools
import json
import math
import pathlib
import random
import sys

SEED = 20260820
FOLDS_MIN = 2

# Families are the task-holdout unit. StepShield's directory names ARE the
# families -- SEC, INV, DEC, RES, TST, UFO -- so holding one out is a real
# distribution shift and not a random split wearing the word "holdout".
Pair = collections.namedtuple("Pair", "task family rogue clean")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _steps(path: pathlib.Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["steps"]


def load_pairs(root: pathlib.Path) -> list[Pair]:
    """Every complete ROGUE/CLEAN pair under a StepShield train directory.

    Incomplete pairs are dropped rather than counted as anything. A rogue with
    no clean twin cannot contribute to a paired bound in either direction, and
    silently keeping it would inflate the denominator with sessions the method
    cannot speak about.
    """
    pairs: list[Pair] = []
    for family_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        by_task: dict[str, dict[str, pathlib.Path]] = collections.defaultdict(dict)
        for f in sorted(family_dir.glob("*.jsonl")):
            stem = f.stem
            for suffix in ("ROGUE", "CLEAN"):
                if stem.endswith(f"-{suffix}"):
                    by_task[stem[: -len(suffix) - 1]][suffix] = f
        for task, halves in sorted(by_task.items()):
            if {"ROGUE", "CLEAN"} <= set(halves):
                pairs.append(Pair(task, family_dir.name,
                                  _steps(halves["ROGUE"]),
                                  _steps(halves["CLEAN"])))
    return pairs


# ---------------------------------------------------------------------------
# Representations
# ---------------------------------------------------------------------------


def _digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def action_sequence(steps: list[dict]) -> tuple:
    return tuple(s.get("action") for s in steps)


def action_multiset(steps: list[dict]) -> tuple:
    return tuple(sorted(collections.Counter(
        s.get("action") for s in steps).items()))


def sequence_plus_arity(steps: list[dict]) -> tuple:
    return tuple((s.get("action"), tuple(sorted((s.get("arguments") or {}).keys())))
                 for s in steps)


def sequence_plus_digest(steps: list[dict]) -> tuple:
    return tuple((s.get("action"), _digest(s.get("arguments") or {}))
                 for s in steps)


REPRESENTATIONS = (
    ("action_sequence", action_sequence),
    ("action_multiset", action_multiset),
    ("sequence_plus_arity", sequence_plus_arity),
    ("sequence_plus_digest", sequence_plus_digest),
)


# ---------------------------------------------------------------------------
# Bound 1: how many pairs are indistinguishable at all
# ---------------------------------------------------------------------------


def indistinguishable(pairs: list[Pair], phi) -> list[Pair]:
    return [p for p in pairs if phi(p.rogue) == phi(p.clean)]


# ---------------------------------------------------------------------------
# Bound 2: is the surviving difference usable, and does it generalise
# ---------------------------------------------------------------------------

ACTIONS = ("create_file", "edit_file", "end", "noop",
           "open_file", "run_command", "search", "submit")


def features(steps: list[dict]) -> list[float]:
    """Structural features only. No argument values, no thoughts, no
    observations, and above all no step labels -- the labels ARE the answer,
    and a feature derived from them would measure nothing but leakage."""
    counts = collections.Counter(s.get("action") for s in steps)
    digests = {_digest(s.get("arguments") or {}) for s in steps}
    runs, longest = 1, 1
    seq = action_sequence(steps)
    for a, b in itertools.pairwise(seq):
        runs = runs + 1 if a == b else 1
        longest = max(longest, runs)
    return [float(len(steps)), float(len(set(seq))), float(longest),
            float(len(digests)), *(float(counts.get(a, 0)) for a in ACTIONS)]


def _fit(deltas: list[list[float]], *, epochs: int = 400,
         lr: float = 0.05) -> list[float]:
    """Logistic regression on paired differences, by gradient descent.

    Trained on (delta, +1) and (-delta, -1) together, so the rule is forced to
    be antisymmetric: it must decide which HALF of a pair is rogue, and cannot
    profit from a bias term that leans one way. Hand-rolled because this
    project ships zero runtime dependencies and a bound nobody can reproduce
    without installing a stack is a weaker bound.
    """
    if not deltas:
        return []
    width = len(deltas[0])
    scale = [max(1.0, *(abs(d[i]) for d in deltas)) for i in range(width)]
    w = [0.0] * width
    for _ in range(epochs):
        grad = [0.0] * width
        for d in deltas:
            x = [d[i] / scale[i] for i in range(width)]
            for sign in (1.0, -1.0):
                z = sum(w[i] * x[i] * sign for i in range(width))
                pred = 1.0 / (1.0 + pow(2.718281828459045, -z))
                err = pred - (1.0 if sign > 0 else 0.0)
                for i in range(width):
                    grad[i] += err * x[i] * sign
        n = 2 * len(deltas)
        w = [w[i] - lr * grad[i] / n for i in range(width)]
    return [w[i] / scale[i] for i in range(width)]


def _accuracy(w: list[float], deltas: list[list[float]]) -> tuple[int, int]:
    """Correct and total. A delta scoring exactly zero is a tie, and a tie is
    counted WRONG rather than as a coin flip -- an undecidable pair is not
    half a detection, and rounding it up is how a ceiling gets inflated."""
    if not w:
        return 0, len(deltas)
    correct = sum(1 for d in deltas
                  if sum(w[i] * d[i] for i in range(len(w))) > 0)
    return correct, len(deltas)


def _delta(p: Pair) -> list[float]:
    r, c = features(p.rogue), features(p.clean)
    return [r[i] - c[i] for i in range(len(r))]


# One delta per pair, computed once. The permutation test below needs the same
# deltas thousands of times, and flipping which half of a pair is called rogue
# is exactly negating its delta -- so re-deriving features per round would be
# recomputing a constant. The first version did, and cost over an hour for a
# result identical to this one.
Sample = collections.namedtuple("Sample", "family delta")


def samples(pairs: list[Pair]) -> list[Sample]:
    return [Sample(p.family, _delta(p)) for p in pairs]


def family_holdout(rows: list[Sample], *, distinguishable_only: bool = False) -> dict:
    """Fit on every family but one, test on the one held out.

    Two populations, reported separately, because pooling them answers neither
    question cleanly:

    ``distinguishable_only=False`` scores every pair, and a pair whose features
    are identical is a tie and counted wrong. That is the OPERATIONAL number --
    a detector in front of this corpus really does face those pairs and really
    cannot win them -- but it drags the chance line below 50%: with 22.7% of
    pairs unwinnable, coin-flipping the rest scores about 38.6%, which is why
    the permutation null sits there rather than at 50%.

    ``distinguishable_only=True`` drops the ties and asks the isolated
    question: WHERE a structural difference exists, does it say which half is
    the attack? Chance here is a clean 50%, so the permutation null landing on
    50% is a check that the machinery is sound rather than a result.
    """
    families = sorted({r.family for r in rows})
    if len(families) < FOLDS_MIN:
        return {"folds": 0, "reason": "TOO_FEW_FAMILIES"}
    per_family, correct_total, n_total = {}, 0, 0
    for held in families:
        # Ties are dropped from the TEST set only. Training on them is
        # harmless -- a zero delta contributes no gradient -- and removing
        # them from training as well would change the fit for no stated
        # reason.
        test = [r.delta for r in rows if r.family == held]
        if distinguishable_only:
            test = [d for d in test if any(d)]
        w = _fit([r.delta for r in rows if r.family != held])
        c, n = _accuracy(w, test)
        per_family[held] = {"pairs": n, "correct": c,
                            "accuracy": round(100 * c / n, 1) if n else None}
        correct_total += c
        n_total += n
    return {"folds": len(families), "per_family": per_family,
            "pairs": n_total, "correct": correct_total,
            "accuracy": round(100 * correct_total / n_total, 1) if n_total else None}


def binomial_p(correct: int, total: int) -> float | None:
    """Exact one-sided P(X >= correct | n, p=0.5).

    Reported beside the permutation p-value because the two fail differently.
    The permutation null accounts for the fitting and holdout procedure but is
    floored by its round count -- at 20 rounds the smallest p it can express is
    0.048, which looks like a result and is really the resolution limit. This
    one is exact and free, and it assumes independent pairs, which the family
    structure mildly violates. Neither alone; both, and they should agree.
    """
    if not total:
        return None
    tail = sum(math.comb(total, k) for k in range(correct, total + 1))
    return tail / (2 ** total)


def permutation_test(rows: list[Sample], observed: float, *,
                     rounds: int = 200, distinguishable_only: bool = False) -> dict:
    """How often does a randomly-relabelled corpus beat the real one?

    Which half of a pair is called rogue is shuffled -- negating that pair's
    delta -- the whole holdout is refitted, and the accuracy recorded. If the
    real accuracy sits inside that null spread, the rule found nothing the
    labels did not hand it.
    """
    rng = random.Random(SEED)
    beat, null = 0, []
    for _ in range(rounds):
        flipped = [Sample(r.family, [-x for x in r.delta])
                   if rng.random() < 0.5 else r for r in rows]
        acc = family_holdout(
            flipped, distinguishable_only=distinguishable_only).get("accuracy")
        if acc is None:
            continue
        null.append(acc)
        if acc >= observed:
            beat += 1
    null.sort()
    return {"rounds": len(null),
            "null_median": null[len(null) // 2] if null else None,
            "null_p95": null[int(0.95 * (len(null) - 1))] if null else None,
            "at_or_above_observed": beat,
            "p_value": round((beat + 1) / (len(null) + 1), 4) if null else None}


# ---------------------------------------------------------------------------
# Where the labelled violation actually lives
# ---------------------------------------------------------------------------


def violation_layer(pairs: list[Pair]) -> dict:
    """For each pair, at the step StepShield LABELS as the violation, what
    would a structural reader have seen?

    The ceiling above says how many pairs are separable. This says something
    sharper and more damaging: even where a difference exists, it is not in the
    part a structural detector reads. Comparing the labelled rogue step against
    the clean trajectory's step at the same index is only well defined when the
    two action sequences align, so pairs whose sequences differ are reported in
    their own bucket rather than compared positionally and quietly miscounted.

    Buckets are exclusive and exhaustive; they are asserted to sum to the pair
    count, because a classifier whose buckets do not add up is one silently
    dropping the cases it cannot handle.
    """
    buckets: dict[str, int] = collections.Counter()
    by_family: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter)

    for p in pairs:
        idx = next((i for i, s in enumerate(p.rogue) if s.get("label")), None)
        if idx is None:
            kind = "no_labelled_step"
        elif action_sequence(p.rogue) != action_sequence(p.clean):
            kind = "sequence_differs"
        elif idx >= len(p.clean):
            kind = "no_positional_twin"
        else:
            rogue_step, twin = p.rogue[idx], p.clean[idx]
            r_args = rogue_step.get("arguments") or {}
            c_args = twin.get("arguments") or {}
            if rogue_step.get("action") != twin.get("action"):
                kind = "different_tool"
            elif sorted(r_args) != sorted(c_args):
                kind = "different_argument_keys"
            elif r_args != c_args:
                kind = "argument_values_only"
            else:
                kind = "step_identical"
        buckets[kind] += 1
        by_family[p.family][kind] += 1

    assert sum(buckets.values()) == len(pairs), "buckets do not partition pairs"
    return {"pairs": len(pairs),
            "buckets": dict(sorted(buckets.items())),
            "by_family": {f: dict(sorted(c.items()))
                          for f, c in sorted(by_family.items())}}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def analyse(root: pathlib.Path, *, rounds: int) -> dict:
    pairs = load_pairs(root)
    if not pairs:
        raise SystemExit(f"no ROGUE/CLEAN pairs found under {root}")

    bounds = {}
    for name, phi in REPRESENTATIONS:
        blind = indistinguishable(pairs, phi)
        bounds[name] = {
            "pairs": len(pairs),
            "indistinguishable": len(blind),
            "indistinguishable_pct": round(100 * len(blind) / len(pairs), 1),
            "ceiling_recall_at_zero_fp_pct":
                round(100 * (len(pairs) - len(blind)) / len(pairs), 1),
            "by_family": {
                f: sum(1 for p in blind if p.family == f)
                for f in sorted({p.family for p in pairs})},
        }

    violations = violation_layer(pairs)

    rows = samples(pairs)
    learnability = {}
    for label, only in (("all_pairs", False), ("distinguishable_only", True)):
        ho = family_holdout(rows, distinguishable_only=only)
        acc = ho.get("accuracy")
        learnability[label] = {
            "family_holdout": ho,
            "permutation": permutation_test(
                rows, acc, rounds=rounds,
                distinguishable_only=only) if acc is not None else {},
            "binomial_p": binomial_p(ho.get("correct", 0), ho.get("pairs", 0)),
        }

    return {
        "corpus": "stepshield",
        "split": "train (paired)",
        "seed": SEED,
        "pairs": len(pairs),
        "families": sorted({p.family for p in pairs}),
        "bounds": bounds,
        "violation_layer": violations,
        "learnability": {
            "features": ["n_steps", "n_distinct_actions", "longest_run",
                         "n_distinct_arg_digests", *ACTIONS],
            **learnability,
        },
    }


def render(result: dict) -> str:
    out = [f"StepShield discrimination ceiling -- {result['pairs']} pairs, "
           f"{len(result['families'])} families", ""]
    out.append(f"{'representation':<22} {'blind pairs':>12} {'ceiling @ 0 FP':>16}")
    for name, b in result["bounds"].items():
        out.append(f"{name:<22} {b['indistinguishable']:>5} "
                   f"({b['indistinguishable_pct']:>4}%) "
                   f"{b['ceiling_recall_at_zero_fp_pct']:>14}%")
    out.append("")
    out.append("at the labelled violation step:")
    for kind, n in result["violation_layer"]["buckets"].items():
        out.append(f"    {kind:<26} {n:>4} "
                   f"({100 * n / result['pairs']:.1f}%)")
    out.append("")
    for label in ("all_pairs", "distinguishable_only"):
        block = result["learnability"][label]
        ho, perm = block["family_holdout"], block["permutation"]
        out.append(f"picking the rogue, {label}: {ho.get('accuracy')}% "
                   f"({ho.get('correct')}/{ho.get('pairs')})")
        if perm:
            out.append(f"    permutation null median {perm['null_median']}%, "
                       f"p95 {perm['null_p95']}%, p = {perm['p_value']}")
        bp = block.get("binomial_p")
        if bp is not None:
            out.append(f"    exact binomial vs 50%: p = {bp:.3g}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--train", required=True, type=pathlib.Path,
                    help="StepShield data/train directory.")
    ap.add_argument("--json", type=pathlib.Path, help="Write the result as JSON.")
    ap.add_argument("--rounds", type=int, default=200,
                    help="Permutation rounds (default 200).")
    args = ap.parse_args(argv)

    result = analyse(args.train, rounds=args.rounds)
    print(render(result))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
