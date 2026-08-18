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

FOUR CORRECTIONS AFTER THE FIFTH EXTERNAL REVIEW
------------------------------------------------
Every one of these was a defect in the MEASUREMENT rather than in the detector,
which is the more embarrassing kind and the harder kind to notice, because a
broken measurement reports success.

C5-01. ANY ALERT WAS COUNTED AS A DETECTION. ``flagged`` is true if any check
    fired, so an attack labelled as CH01's was scored as caught when CH02 and
    CH05 happened to fire on the same trace and CH01 missed it entirely.
    Reproduced on this corpus: family_holdout recall reads 88.2% any-alert and
    **76.5% attributable**, and the 32 sessions between the two are
    ``attack_novel_sequence`` cases that CH01 declined on vocabulary mismatch.
    Both numbers are now published, and ``target_attributable_recall`` is the
    one the card leads with, because "something fired" is not the claim a
    per-check result is making.

C5-02. FALSE POSITIVES PER 1000 USED ALL SESSIONS AS ITS DENOMINATOR, so the
    number moved with the corpus's artificial 33.3% attack prevalence while
    being presented as an operational planning figure. The prevalence-free unit
    is per 1000 BENIGN sessions, and ``base_rate_projection`` standardises it to
    realistic prevalences, where precision collapses and the corpus number
    stops flattering anything.

C5-03. COVERAGE-WEIGHTED RECALL COULD EXCEED RAW RECALL. Dividing weight on
    detected attacks by weight on all attacks means a miss with poor telemetry
    barely enters the denominator, so a detector scores BETTER for missing the
    attacks it could see least of. That is precisely the wrong incentive for an
    end-to-end measurement. It is renamed ``weighted_detected_mass``, is never
    called recall, and the honest pair -- end-to-end recall, and recall where
    the responsible check was evaluable -- sits beside it.

C5-04 is fixed in the harness rather than here; see ``leakage_experiment``.
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


def attributed(outcome: Outcome) -> bool:
    """Did the check RESPONSIBLE for this session's behaviour actually fire?

    The corpus labels every attack with the check whose job it is. Scoring on
    "any alert" credits a detection to whichever check happened to fire, which
    is how a check that declined every one of its own labelled examples came to
    be reported at full recall (C5-01).

    Benign sessions have no responsible check, so this is meaningless for them
    and the false-positive side of every metric stays on ``flagged`` -- an
    analyst is paged by any alert, whatever its ID.
    """
    return bool(outcome.target_check) and outcome.target_check in outcome.fired_checks


def confusion(outcomes: list[Outcome]) -> dict[str, int]:
    tp = sum(1 for o in outcomes if o.is_attack and o.flagged)
    fn = sum(1 for o in outcomes if o.is_attack and not o.flagged)
    fp = sum(1 for o in outcomes if not o.is_attack and o.flagged)
    tn = sum(1 for o in outcomes if not o.is_attack and not o.flagged)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}


def base_rate_projection(tpr: float, fpr: float,
                         prevalences: tuple[float, ...] = (0.001, 0.01, 0.05)
                         ) -> list[dict[str, Any]]:
    """What this detector does at a REALISTIC attack base rate.

    The corpus runs at 33.3% prevalence, which is absurd and is stated as
    absurd, but a precision figure computed at that prevalence still gets read
    as a precision figure. Standardising to 0.1%, 1% and 5% is the only way the
    corpus number stops flattering the detector, and the collapse is severe
    enough that no amount of prose substitutes for the table.
    """
    out = []
    for p in prevalences:
        tp = tpr * p
        fp = fpr * (1 - p)
        out.append({
            "attack_prevalence": p,
            "alerts_per_1000_sessions": round(1000 * (tp + fp), 1),
            "precision": round(tp / (tp + fp), 5) if (tp + fp) else 0.0,
        })
    return out


def summarise(outcomes: list[Outcome]) -> dict[str, Any]:
    """Every headline number for one scored set, with intervals."""
    c = confusion(outcomes)
    attacks = [o for o in outcomes if o.is_attack]
    benign = [o for o in outcomes if not o.is_attack]

    tpr = Rate("recall (TPR)", c["tp"], c["tp"] + c["fn"])
    fpr = Rate("false positive rate", c["fp"], c["fp"] + c["tn"])
    precision = Rate("precision", c["tp"], c["tp"] + c["fp"])

    # C5-01. The number the card leads with. "Something fired" is not the claim
    # a per-check result makes, and the gap between these two is where a check
    # that declined all of its own labelled examples was being reported at full
    # recall.
    attributable = Rate("target-attributable recall",
                        sum(1 for o in attacks if attributed(o)), len(attacks))
    incidental = c["tp"] - attributable.numerator

    evaluable = [o for o in attacks if o.target_evaluable]
    recall_evaluable = Rate(
        "recall where the responsible check was evaluable",
        sum(1 for o in evaluable if attributed(o)), len(evaluable))

    # C5-03. NOT recall, and no longer named as though it were. Dividing weight
    # on detected attacks by weight on all attacks means a miss with poor
    # telemetry barely enters the denominator, so the figure RISES when the
    # detector misses the attacks it could see least of.
    weight_hit = sum(o.completeness for o in attacks if o.flagged)
    weight_all = sum(o.completeness for o in attacks)

    f1 = (2 * precision.value * tpr.value / (precision.value + tpr.value)
          if (precision.value + tpr.value) else 0.0)

    return {
        "sessions": len(outcomes),
        "attacks": len(attacks),
        "benign": len(benign),
        "confusion": c,
        # Kept under its old key so existing readers do not silently change
        # meaning, and renamed everywhere it is DISPLAYED.
        "recall": tpr.as_dict(),
        "any_alert_recall": tpr.as_dict(),
        "target_attributable_recall": attributable.as_dict(),
        "incidental_detections": incidental,
        "false_positive_rate": fpr.as_dict(),
        "precision": precision.as_dict(),
        "f1": round(f1, 4),
        "recall_where_evaluable": recall_evaluable.as_dict(),
        "weighted_detected_mass": round(weight_hit / weight_all, 4)
        if weight_all else 0.0,
        # C5-02. Both, because only the second is prevalence-free, and the first
        # is what the previous card wrongly told operators to plan against.
        "false_positives_per_1000_sessions": round(
            1000 * c["fp"] / len(outcomes), 1) if outcomes else 0.0,
        "false_positives_per_1000_benign_sessions": round(
            1000 * c["fp"] / len(benign), 1) if benign else 0.0,
        "base_rate_projection": base_rate_projection(tpr.value, fpr.value),
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

    def row(check: str) -> dict[str, int]:
        return out.setdefault(check, {"on_attacks": 0, "on_benign": 0,
                                      "on_target_attacks": 0,
                                      "incidental_on_attacks": 0,
                                      "labelled": 0, "missed_own_labels": 0})

    for o in outcomes:
        # C5-01, the per-check half. A check firing on an attack that belongs to
        # a DIFFERENT check is a bonus, not a hit, and counting it as one made
        # CH01 look as though it had caught sixty attacks it had never been
        # asked about.
        if o.is_attack and o.target_check:
            r = row(o.target_check)
            r["labelled"] += 1
            if o.target_check not in o.fired_checks:
                r["missed_own_labels"] += 1
        for check in o.fired_checks:
            r = row(check)
            if not o.is_attack:
                r["on_benign"] += 1
                continue
            r["on_attacks"] += 1
            if o.target_check == check:
                r["on_target_attacks"] += 1
            else:
                r["incidental_on_attacks"] += 1
    for r in out.values():
        total = r["on_attacks"] + r["on_benign"]
        r["precision_pct"] = round(100 * r["on_attacks"] / total, 1) if total else 0.0
        # Precision counting only the attacks this check is RESPONSIBLE for. The
        # honest per-rule number, and always the lower of the two.
        r["target_precision_pct"] = (
            round(100 * r["on_target_attacks"] / total, 1) if total else 0.0)
        r["target_recall_pct"] = (
            round(100 * r["on_target_attacks"] / r["labelled"], 1)
            if r["labelled"] else 0.0)
    return dict(sorted(out.items()))
