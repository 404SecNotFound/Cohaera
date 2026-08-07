"""Detection metrics, with intervals, because a point estimate on 768 sessions
is not a result.

Everything here is stdlib arithmetic. Cohaera has zero runtime dependencies and
the evaluation harness does not get to be the thing that adds numpy.

THREE CHOICES WORTH ARGUING WITH
--------------------------------

1. WILSON, NOT NORMAL-APPROXIMATION intervals. The normal approximation is
   degenerate exactly where detection results live: at p near 0 or 1 it produces
   intervals that extend past the ends of the probability scale, and at p = 1.0
   it produces a width of zero, which reads as certainty from a handful of
   samples. A recall of 8/8 is not 100% +/- 0%.

2. FALSE POSITIVES PER 1000 SESSIONS, alongside FPR. An FPR of 2% sounds
   tolerable and is not: an agent fleet producing 50,000 sessions a day at 2%
   is 1,000 alerts a day, which is not a detection system, it is a denial of
   service against the analyst. The rate is the honest unit for a SOC.

3. COVERAGE-ADJUSTED RECALL. Cohaera reports, per session, which checks it had
   the surfaces to evaluate. A miss on a session where the required surface was
   absent is a different failure from a miss on a session where everything was
   present and the check was simply too weak, and lumping them together hides
   which one you have. So recall is reported three ways: raw, restricted to
   sessions where the responsible check was evaluable at all, and weighted by
   the completeness Cohaera itself declared.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

Z95 = 1.959963984540054          # two-sided 95%


def wilson(successes: int, total: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Returns (low, high), both within 0..1. With ``total == 0`` returns (0, 1):
    no observations means no information, and that is what the interval should
    say rather than collapsing to a point.
    """
    if total <= 0:
        return 0.0, 1.0
    p = successes / total
    z2n = z * z / total
    centre = (p + z2n / 2) / (1 + z2n)
    half = (z / (1 + z2n)) * math.sqrt(p * (1 - p) / total + z2n / (4 * total))
    return max(0.0, centre - half), min(1.0, centre + half)


@dataclass(frozen=True)
class Rate:
    """A proportion with its interval, and the counts it came from.

    The counts are carried because a rate without its denominator is not
    checkable, and every number this project publishes has to be checkable.
    """

    name: str
    numerator: int
    denominator: int

    @property
    def value(self) -> float:
        return self.numerator / self.denominator if self.denominator else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson(self.numerator, self.denominator)

    def as_dict(self) -> dict[str, Any]:
        lo, hi = self.interval
        return {
            "name": self.name,
            "value": round(self.value, 4),
            "ci95_low": round(lo, 4),
            "ci95_high": round(hi, 4),
            "numerator": self.numerator,
            "denominator": self.denominator,
        }

    def render(self) -> str:
        if not self.denominator:
            return "n/a (0 samples)"
        lo, hi = self.interval
        return (f"{self.value:.1%} [{lo:.1%}-{hi:.1%}] "
                f"({self.numerator}/{self.denominator})")


@dataclass(frozen=True)
class Outcome:
    """One scored session: what it was, what fired, and what could be seen."""

    session_id: str
    family: str
    task_id: str
    kind: str
    is_attack: bool
    target_check: str
    flagged: bool                    # any finding at or above the threshold
    fired_checks: frozenset[str]
    completeness: float
    target_evaluable: bool           # the responsible check was not blind here


def confusion(outcomes: list[Outcome]) -> dict[str, int]:
    tp = sum(1 for o in outcomes if o.is_attack and o.flagged)
    fn = sum(1 for o in outcomes if o.is_attack and not o.flagged)
    fp = sum(1 for o in outcomes if not o.is_attack and o.flagged)
    tn = sum(1 for o in outcomes if not o.is_attack and not o.flagged)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}


def summarise(outcomes: list[Outcome]) -> dict[str, Any]:
    """Every headline number for one scored set, with intervals."""
    c = confusion(outcomes)
    attacks = [o for o in outcomes if o.is_attack]
    benign = [o for o in outcomes if not o.is_attack]

    tpr = Rate("recall (TPR)", c["tp"], c["tp"] + c["fn"])
    fpr = Rate("false positive rate", c["fp"], c["fp"] + c["tn"])
    precision = Rate("precision", c["tp"], c["tp"] + c["fp"])

    evaluable = [o for o in attacks if o.target_evaluable]
    recall_evaluable = Rate(
        "recall where the responsible check was evaluable",
        sum(1 for o in evaluable if o.flagged), len(evaluable))

    # Coverage-weighted: a detection on a session Cohaera says it could barely
    # see counts for less than one it saw fully.
    weight_hit = sum(o.completeness for o in attacks if o.flagged)
    weight_all = sum(o.completeness for o in attacks)

    f1 = (2 * precision.value * tpr.value / (precision.value + tpr.value)
          if (precision.value + tpr.value) else 0.0)

    return {
        "sessions": len(outcomes),
        "attacks": len(attacks),
        "benign": len(benign),
        "confusion": c,
        "recall": tpr.as_dict(),
        "false_positive_rate": fpr.as_dict(),
        "precision": precision.as_dict(),
        "f1": round(f1, 4),
        "recall_where_evaluable": recall_evaluable.as_dict(),
        "coverage_weighted_recall": round(weight_hit / weight_all, 4)
        if weight_all else 0.0,
        "false_positives_per_1000_sessions": round(
            1000 * c["fp"] / len(outcomes), 1) if outcomes else 0.0,
        "mean_coverage_completeness": round(
            sum(o.completeness for o in outcomes) / len(outcomes), 4)
        if outcomes else 0.0,
    }


def by_group(outcomes: list[Outcome], key: str) -> dict[str, dict[str, Any]]:
    """Break the numbers down by session kind, family, or target check.

    The breakdown is the useful half. An aggregate recall of 60% could be five
    checks at 60% or four at 100% and one at 0%, and only one of those tells you
    what to fix.
    """
    groups: dict[str, list[Outcome]] = {}
    for o in outcomes:
        groups.setdefault(getattr(o, key), []).append(o)
    out = {}
    for name, members in sorted(groups.items()):
        attacks = [m for m in members if m.is_attack]
        flagged = sum(1 for m in members if m.flagged)
        rate = Rate(f"{key}={name}", flagged, len(members))
        out[name] = {
            "sessions": len(members),
            "attacks": len(attacks),
            "flagged": flagged,
            "flag_rate": rate.as_dict(),
            # For a benign group this IS the false positive rate; for an attack
            # group it is the recall. Naming it "flag rate" keeps that honest
            # rather than implying a correctness the group does not carry.
            "interpretation": ("recall" if attacks and len(attacks) == len(members)
                               else "false positive rate" if not attacks
                               else "mixed"),
        }
    return out


def check_attribution(outcomes: list[Outcome]) -> dict[str, dict[str, int]]:
    """How often each check fired, on attacks and on benign sessions.

    Answers the question an operator actually has, which is not "how good is the
    detector" but "which rule is going to page me at 3am for nothing".
    """
    out: dict[str, dict[str, int]] = {}
    for o in outcomes:
        for check in o.fired_checks:
            row = out.setdefault(check, {"on_attacks": 0, "on_benign": 0})
            row["on_attacks" if o.is_attack else "on_benign"] += 1
    for row in out.values():
        total = row["on_attacks"] + row["on_benign"]
        row["precision_pct"] = round(100 * row["on_attacks"] / total, 1) if total else 0.0
    return dict(sorted(out.items()))
