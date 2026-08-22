"""Which of Cohaera's seven checks external validation can and cannot reach.

This module is the single source of truth for the claim, and it is deliberately
executable rather than prose. ``docs/EXTERNAL-VALIDATION.md`` states the same
thing in English and ``tests/test_external.py`` asserts that the two agree AND
that both agree with what the engine's own coverage contracts do to a real
adapted session.

WHY THIS EXISTS AS CODE
-----------------------
A scope statement in a document is a claim that was true when someone typed it.
The failure this guards against is specific and likely: somebody adds an
approval surface to a corpus adapter, or the engine changes which surfaces CH04
requires, and the document goes on saying "three checks cannot be validated
externally" long after that stopped being the reason. The test derives the
answer from ``cohaera.checks.coverage`` run over an adapted session and compares
it to the table below, so the document cannot rot without a red test.

THE CLAIM
---------
Three of the seven checks can be validated against today's public corpora, one
partially, and three not at all. The three that cannot are not a random three:
CH04 and CH06 are the two the project's positioning leans on hardest, because
they are the ones that read the control plane rather than the agent's own
chatter. Their evidence -- policy decisions, approval grants, provider receipts
-- is produced by systems that public trace corpora do not model at all.

The README currently folds this into a general "no external corpus" caveat.
That understates it. "We have not validated externally yet" implies a task
that is merely undone; the truth for CH04, CH06 and CH07 is that no public
corpus exists to do it with, and collecting one would mean instrumenting a real
control plane rather than downloading a benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass

from cohaera.checks import (
    CH03_FAMILY,
    CH04_FAMILY,
    CH06_INTEGRITY,
    CH07_FAMILY,
    SURFACE_APPROVAL,
    SURFACE_BENIGN_BASELINE,
    SURFACE_EFFECT_RECEIPT,
    SURFACE_EVENT_INTEGRITY,
    SURFACE_INJECTION_SCANNER,
    SURFACE_POLICY_SEMANTICS,
)

CH01 = "CH01_sequence_order"
CH02 = "CH02_concealment_gap"
CH05 = "CH05_unpaired_calls"

VALIDATABLE = "validatable"
PARTIAL = "partial"
NOT_VALIDATABLE = "not_validatable"


@dataclass(frozen=True)
class ScopeEntry:
    """One check's external-validation status, and the reason it holds."""

    check: str
    status: str
    reason: str
    # The surfaces that, being absent from every public corpus, are why a
    # not-validatable check is not validatable. Empty for validatable checks.
    blocking_surfaces: frozenset[str] = frozenset()


SCOPE: tuple[ScopeEntry, ...] = (
    ScopeEntry(
        CH01, VALIDATABLE,
        "Needs a benign baseline, tool lifecycle and a correlation key. A trace "
        "corpus supplies the lifecycle, its own benign split fits the baseline, "
        "and the trajectory id is a producer-supplied correlation key."),
    ScopeEntry(
        CH02, VALIDATABLE,
        "Needs a final response, tool class and a correlation key. Both target "
        "corpora carry a final agent response, and tool class falls to the name "
        "heuristic -- which degrades confidence honestly rather than blocking."),
    ScopeEntry(
        CH03_FAMILY, PARTIAL,
        "Needs injection-scanner evidence, which no public corpus produces. It "
        "is partially reachable only where a corpus records where content the "
        "agent did not author entered the trajectory. StepShield annotates the "
        "step, behind an explicit opt-in. AgentDojo is stronger and still not "
        "a scanner: it records the injected STRINGS, so the question is settled "
        "by containment against the captured result rather than by trusting an "
        "annotation -- which makes it an oracle, and an upper bound on what a "
        "real scanner would supply, not an estimate of it. ATBench carries "
        "neither.",
        frozenset({SURFACE_INJECTION_SCANNER})),
    ScopeEntry(
        CH04_FAMILY, NOT_VALIDATABLE,
        "Needs policy semantics and approval binding. No public agent-trajectory "
        "corpus records the decisions of a policy engine or approvals bound to "
        "call arguments, because these are control-plane artefacts and the "
        "corpora are traces with no control plane behind them.",
        frozenset({SURFACE_POLICY_SEMANTICS, SURFACE_APPROVAL})),
    ScopeEntry(
        CH05, VALIDATABLE,
        "Needs tool lifecycle and a correlation key, both of which any trace "
        "corpus with tool calls supplies."),
    ScopeEntry(
        CH06_INTEGRITY, NOT_VALIDATABLE,
        "Needs a signed or hash-chained event stream. Corpora are distributed "
        "as JSON files; there is no collector signature to verify and no "
        "sequence to break, so CH06 has nothing to be right or wrong about.",
        frozenset({SURFACE_EVENT_INTEGRITY})),
    ScopeEntry(
        CH07_FAMILY, NOT_VALIDATABLE,
        "Needs provider effect receipts. Nothing public attests that a tool "
        "call reached an authority, so there is no claimed effect for CH07 to "
        "contradict.",
        frozenset({SURFACE_EFFECT_RECEIPT})),
)

BY_CHECK: dict[str, ScopeEntry] = {e.check: e for e in SCOPE}

EXTERNALLY_VALIDATABLE = frozenset(
    e.check for e in SCOPE if e.status == VALIDATABLE)
PARTIALLY_VALIDATABLE = frozenset(
    e.check for e in SCOPE if e.status == PARTIAL)
NOT_EXTERNALLY_VALIDATABLE = frozenset(
    e.check for e in SCOPE if e.status == NOT_VALIDATABLE)

# Surfaces no public corpus carries. The union of every blocking surface, minus
# the one CH03 can partially reach. Used by the test that checks an adapted
# session really does lack them.
ABSENT_FROM_ALL_PUBLIC_CORPORA = frozenset({
    SURFACE_POLICY_SEMANTICS, SURFACE_APPROVAL,
    SURFACE_EVENT_INTEGRITY, SURFACE_EFFECT_RECEIPT,
})

# CH01 is the one validatable check with a surface that is not in the telemetry
# at all: the baseline is FITTED rather than carried. Named here so the test
# knows to expect it present-after-fitting rather than absent.
FITTED_SURFACES = frozenset({SURFACE_BENIGN_BASELINE})


def summary_line() -> str:
    """One sentence, used by the runner and quoted by the document."""
    return (
        f"{len(EXTERNALLY_VALIDATABLE)} of 7 checks are externally validatable "
        f"today ({', '.join(sorted(EXTERNALLY_VALIDATABLE))}); "
        f"{len(PARTIALLY_VALIDATABLE)} partially "
        f"({', '.join(sorted(PARTIALLY_VALIDATABLE))}); "
        f"{len(NOT_EXTERNALLY_VALIDATABLE)} not at all "
        f"({', '.join(sorted(NOT_EXTERNALLY_VALIDATABLE))}).")
