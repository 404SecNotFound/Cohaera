"""Run the full evaluation grid and write the evaluation card.

    python eval/run_eval.py                # regenerate corpus, score, write card
    python eval/run_eval.py --no-generate  # score the committed corpus as-is

The grid is 2 vocabularies x 3 split regimes x 3 capability sources. Each cell is
a full fit-and-score, and every cell is reported -- including the ones that make
Cohaera look bad, which on this corpus is most of them.

The card is deterministic. There is no wall-clock timestamp anywhere in it, so
re-running on the same revision produces a byte-identical file and a diff shows
a change in the DETECTOR rather than a change in the clock. Provenance is the
corpus digest, the detector version and the bounds digest, which is what
identifies a result; the date it was run is not.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera import __version__
from cohaera.checks import MIN_CALLS_FOR_VOCABULARY_JUDGEMENT
from cohaera.limits import DEFAULT_LIMITS
from eval.corpus import generate as gen
from eval.harness import (
    CAP_MANIFEST,
    CAP_NAME_ONLY,
    CAPABILITY_SOURCES,
    REGIME_FAMILY_HOLDOUT,
    REGIME_RANDOM,
    REGIME_TASK_DISJOINT,
    REGIMES,
    SessionCache,
    leakage_experiment,
    load_corpus,
    load_manifest,
    load_trust_store,
    run_condition,
)
from eval.metrics import by_group, check_attribution, summarise
from eval.vocabulary import CONDITIONS, audit

REPO = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "corpus" / "data"
CARD_MD = Path(__file__).resolve().parent / "EVALUATION-CARD.md"
CARD_JSON = Path(__file__).resolve().parent / "evaluation-card.json"


def corpus_artefacts() -> set[Path]:
    """Exactly the files ``gen.write`` produces. Named, not discovered."""
    expected: set[Path] = set()
    for condition in CONDITIONS:
        expected.add(DATA / f"{condition}.jsonl")
        expected.add(DATA / f"{condition}.labels.jsonl")
        manifests = DATA / "manifests" / condition
        expected.add(manifests / "_all.json")
        expected.add(manifests / "trust-store.json")
        for family in gen.FAMILIES:
            expected.add(manifests / f"{family.name}.json")
    return expected


def corpus_digest() -> str:
    """One digest over every corpus artefact, so a card names its inputs.

    OVER A NAMED SET, NOT OVER WHATEVER IS IN THE DIRECTORY. This used to walk
    ``data/`` and hash what it found, which meant any file that ended up there
    -- an editor's swap file, a scratch export, a cache -- silently changed the
    corpus digest and therefore the card, and the card would report a change in
    the corpus when nothing about the corpus had changed. That is the same
    class of defect as the ``--no-generate`` drift below, and it was found the
    same way: by tripping it.

    A file in ``data/`` that is not a corpus artefact is refused rather than
    absorbed. The digest is a claim about the corpus; a directory listing is not.
    """
    expected = corpus_artefacts()
    present = {p for p in DATA.rglob("*") if p.is_file()}
    stray = sorted(p.relative_to(DATA).as_posix() for p in present - expected)
    if stray:
        raise SystemExit(
            f"{DATA} contains {len(stray)} file(s) that are not corpus "
            f"artefacts: {', '.join(stray[:5])}. The corpus digest is a "
            "statement about the corpus, so it will not absorb them. Remove "
            "them, or regenerate the corpus into a clean directory.")
    h = hashlib.sha256()
    for path in sorted(expected):
        h.update(path.relative_to(DATA).as_posix().encode("utf-8"))
        h.update(path.read_bytes())
    return h.hexdigest()[:16]


def _summary_without_generating(seed: int) -> dict[str, Any]:
    """The corpus summary ``gen.write`` returns, derived from the corpus on disk.

    It has to produce the SAME KEYS, and that is not cosmetic. The card embeds
    this summary, CI regenerates the card and fails on any diff, and this branch
    used to omit ``events`` and ``tools_declared`` -- so a card written with
    --no-generate differed from one written without it, and the drift check
    reported a change in the detector when the only thing that had changed was
    which flag the last person used. A determinism claim that depends on the
    invocation is not a determinism claim.
    """
    conditions: dict[str, Any] = {}
    for condition in CONDITIONS:
        rows = load_corpus(DATA, condition)
        attacks = sum(1 for s in rows if s.is_attack)
        conditions[condition] = {
            "sessions": len(rows),
            "events": sum(len(s.events) for s in rows),
            "attacks": attacks,
            "benign": len(rows) - attacks,
            "attack_prevalence": round(attacks / len(rows), 4),
            "tasks": len({s.task_id for s in rows}),
            "families": len(gen.FAMILIES),
            "tools_declared": len(load_manifest(DATA, condition).tools),
        }
    return {"seed": seed, "conditions": conditions}


def run_grid(seed: int) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for vocabulary in CONDITIONS:
        corpus = load_corpus(DATA, vocabulary)
        manifest = load_manifest(DATA, vocabulary)
        # Loaded for every cell, including the ones that ablate the manifest.
        # The trust store is not a capability signal and ablating it would
        # change what the ablation measures: `name_only` asks what happens when
        # the producer declares no capabilities, not what happens when the
        # operator also loses their keys.
        store = load_trust_store(DATA, vocabulary)
        # One assembled-session cache per capability condition, and none shared
        # across vocabularies -- both because the sessions differ and because
        # holding two vocabularies' worth at once buys nothing. The regimes
        # inside share it: a regime decides which side of the split a session
        # lands on, not what it assembles into. See harness.SessionCache.
        caches = {capability: SessionCache() for capability in CAPABILITY_SOURCES}
        for regime in REGIMES:
            for capability in CAPABILITY_SOURCES:
                outcomes, provenance = run_condition(
                    corpus, regime, seed, manifest, capability_source=capability,
                    store=store, cache=caches[capability])
                results[f"{vocabulary}|{regime}|{capability}"] = {
                    "vocabulary": vocabulary,
                    "regime": regime,
                    "capability_source": capability,
                    "provenance": provenance,
                    "metrics": summarise(outcomes),
                    "by_kind": by_group(outcomes, "kind"),
                    "by_family": by_group(outcomes, "family"),
                    "check_attribution": check_attribution(outcomes),
                }
    return results


def _cell(results: dict, vocabulary: str, regime: str, capability: str) -> dict:
    return results[f"{vocabulary}|{regime}|{capability}"]["metrics"]


def attribution_for(results: dict, vocabulary: str = "unseen",
                    regime: str = REGIME_TASK_DISJOINT,
                    capability: str = CAP_MANIFEST) -> dict:
    return results[f"{vocabulary}|{regime}|{capability}"]["check_attribution"]


def _pct(rate: dict) -> str:
    return (f"{rate['value']:.1%} [{rate['ci95_low']:.0%}-{rate['ci95_high']:.0%}] "
            f"({rate['numerator']}/{rate['denominator']})")


def render_card(results: dict[str, Any], seed: int, summary: dict,
                leakage: dict[str, Any]) -> str:
    audits = {c: audit(c) for c in CONDITIONS}
    unseen_name_only = _cell(results, "unseen", REGIME_TASK_DISJOINT, CAP_NAME_ONLY)
    lexical_name_only = _cell(results, "lexical", REGIME_TASK_DISJOINT, CAP_NAME_ONLY)

    unseen_manifest = _cell(results, "unseen", REGIME_TASK_DISJOINT, CAP_MANIFEST)
    recall_gap = (lexical_name_only["recall"]["value"]
                  - unseen_name_only["recall"]["value"])

    lines: list[str] = []
    add = lines.append

    add("# Cohaera evaluation card")
    add("")
    add("Generated by `python eval/run_eval.py`. Deterministic: no wall-clock value")
    add("appears anywhere in this file, so re-running on the same revision produces")
    add("a byte-identical card and any diff is a change in the detector.")
    add("")
    add("| Provenance | |")
    add("|---|---|")
    add(f"| detector version | `{__version__}` |")
    add(f"| bounds digest (`config_hash`) | `{DEFAULT_LIMITS.digest()}` |")
    add(f"| corpus digest | `{corpus_digest()}` |")
    add(f"| corpus seed | `{seed}` |")
    add(f"| sessions per vocabulary | {summary['conditions']['unseen']['sessions']} "
        f"({summary['conditions']['unseen']['attacks']} attack / "
        f"{summary['conditions']['unseen']['benign']} benign) |")
    add(f"| tasks | {summary['conditions']['unseen']['tasks']} across "
        f"{summary['conditions']['unseen']['families']} families |")
    add(f"| attack prevalence | "
        f"{summary['conditions']['unseen']['attack_prevalence']:.1%} |")
    add("")
    add("---")
    add("")

    # ---- the headline ---------------------------------------------------
    add("## The result")
    add("")
    add("Cohaera separates clean benign sessions from everything else almost")
    add("perfectly, and cannot separate a hard benign session from an attack at all.")
    add("Both halves of that sentence are in the numbers below, and the second half")
    add("is the one that matters for a deployment.")
    add("")
    add("### 1. How much of the measured performance is the detector, and how much")
    add("is the fixture author's word choice?")
    add("")
    add("Same behaviours, same sessions, same labels. The only difference is what the")
    add("tools are called, and whether any out-of-band capability declaration exists.")
    add("")
    add("| vocabulary | capability source | attributable recall | any-alert recall "
        "| false positive rate | precision | self-reported coverage |")
    add("|---|---|---|---|---|---|---|")
    for vocabulary in CONDITIONS:
        for capability in CAPABILITY_SOURCES:
            m = _cell(results, vocabulary, REGIME_TASK_DISJOINT, capability)
            add(f"| {vocabulary} | {capability} "
                f"| {_pct(m['target_attributable_recall'])} "
                f"| {_pct(m['any_alert_recall'])} "
                f"| {_pct(m['false_positive_rate'])} "
                f"| {_pct(m['precision'])} "
                f"| {m['mean_coverage_completeness']:.2f} |")
    add("")
    add(
        "**Two recall columns, because they are two different claims.** "
        "*Attributable* recall counts an attack as detected only when the check "
        "the corpus holds RESPONSIBLE for that behaviour fired. *Any-alert* "
        "recall counts it when anything fired. Where they differ, the gap is "
        "attacks caught by a check that was never asked about them -- real "
        "collateral detection, and not evidence that the responsible check "
        "works. Reporting only the second is how a check that declined every "
        "one of its own labelled examples came to be published at full recall; "
        "see §2.\n")
    add(
        "**With names the classifier knows, the name heuristic alone performs "
        "identically to a full capability manifest** -- same recall, same false "
        "positive rate, same precision, to the session. That is not a detector "
        "result. It is what the existing twelve fixtures have always measured, and "
        "it is the objection three reviews have now raised: the fixture tool names "
        "were drawn from the same keyword lists the classifier matches against, so "
        "the measurement was the list checking itself.\n")
    add(
        f"**Change nothing but the tool names and recall falls {recall_gap:.1%}, "
        f"from {lexical_name_only['recall']['value']:.1%} to "
        f"{unseen_name_only['recall']['value']:.1%}.** Name-heuristic accuracy on "
        f"the unseen vocabulary is **{audits['unseen'].accuracy:.0%}**: "
        f"{audits['unseen'].recognised} of {audits['unseen'].total} realistic "
        f"enterprise tool identifiers are recognised at all. On the lexical control "
        f"it is {audits['lexical'].accuracy:.0%}.\n")
    add(
        f"Read the false-positive column carefully, because it moves the wrong way "
        f"for the right reason. Under `unseen`/`name_only` the false positive rate "
        f"*drops* to {unseen_name_only['false_positive_rate']['value']:.1%} and "
        f"precision *rises* to {unseen_name_only['precision']['value']:.1%}, a "
        f"{unseen_name_only['precision']['value'] - unseen_manifest['precision']['value']:+.1%} "
        f"swing that a card reporting precision alone would have published as an "
        f"improvement. It is not one. Every check that needs to know whether a call "
        f"was consequential -- CH02, CH03, CH04 -- cannot fire at all, because every "
        f"tool classifies as `unknown`. The detector got quieter by going blind.\n")
    add(
        f"The thing that makes that visible is Cohaera's own coverage figure, which "
        f"falls from {lexical_name_only['mean_coverage_completeness']:.2f} to "
        f"{unseen_name_only['mean_coverage_completeness']:.2f} in the same cell. "
        f"Coverage reporting was built for exactly this and this is the first "
        f"measurement that shows it earning its place: **the precision number is "
        f"misleading and the coverage number next to it says so.**\n")

    # ---- leakage --------------------------------------------------------
    add("### 2. What a random split would have bought")
    add("")
    add("The README cites MCPShield for the claim that random splits inflate results")
    add("on agent-trace data. This measures it on this corpus instead of citing it.")
    add("Every task has four attempts; a random split puts attempts of the same task")
    add("on both sides.")
    add("")
    add("| split regime | attributable recall | any-alert recall "
        "| false positive rate | precision | note |")
    add("|---|---|---|---|---|---|")
    notes = {
        REGIME_TASK_DISJOINT: "the honest number",
        REGIME_FAMILY_HOLDOUT: "baseline never saw the test workload",
        REGIME_RANDOM: "**contaminated, not a result**",
    }
    for regime in REGIMES:
        m = _cell(results, "unseen", regime, CAP_MANIFEST)
        add(f"| {regime} | {_pct(m['target_attributable_recall'])} "
            f"| {_pct(m['any_alert_recall'])} "
            f"| {_pct(m['false_positive_rate'])} "
            f"| {_pct(m['precision'])} | {notes[regime]} |")
    add("")
    honest = _cell(results, "unseen", REGIME_TASK_DISJOINT, CAP_MANIFEST)
    fam = _cell(results, "unseen", REGIME_FAMILY_HOLDOUT, CAP_MANIFEST)
    leak_clean = leakage["clean"]
    leak_leaky = leakage["leaky"]
    d_prec = (leak_leaky["precision"]["value"] - leak_clean["precision"]["value"])
    d_fpr = (leak_leaky["false_positive_rate"]["value"]
             - leak_clean["false_positive_rate"]["value"])
    fam_by_kind = results[
        f"unseen|{REGIME_FAMILY_HOLDOUT}|{CAP_MANIFEST}"]["by_kind"]
    fam_dilution = fam_by_kind.get(gen.ATTACK_DILUTION, {"flagged": 0, "sessions": 0})
    fam_dilution_total = fam_dilution["sessions"]
    fam_missed_dilution = fam_dilution_total - fam_dilution["flagged"]
    add(
        f"**Measured, paired, on ONE test set: precision {d_prec:+.1%}, false "
        f"positive rate {d_fpr:+.1%}** -- both in the direction that flatters the "
        f"detector, which is what leakage always buys.\n")
    add(
        f"The `random_LEAKY` row above is kept as a contamination control and is "
        f"NOT where that figure comes from, because it cannot be. Each regime seeds "
        f"its own shuffle, so the task-disjoint and random cells score different "
        f"sessions at different attack prevalences: two things change at once and "
        f"the difference cannot be attributed to either. The number above comes "
        f"from `harness.leakage_experiment`, which holds the test set fixed "
        f"({leakage['provenance']['test_sessions']} sessions, "
        f"{leakage['provenance']['test_attacks']} attacks, identical in both runs) "
        f"and varies exactly one thing: whether "
        f"{leakage['provenance']['sibling_sessions_leaked']} sibling attempts of "
        f"those same tasks are allowed into the training set.\n")
    add(
        f"Smaller than MCPShield's 26-point AUROC figure, and the reason is worth "
        f"stating rather than hiding: attributable recall here is saturated at "
        f"{leak_clean['target_attributable_recall']['value']:.0%}, so leakage has no "
        f"headroom to inflate it and shows up only in the false-positive direction. "
        f"A corpus with harder attacks would show more. This is a floor on the "
        f"effect, not an estimate of it.\n")
    add(
        "`family_holdout` is the number to look at before pointing Cohaera at an "
        "agent whose benign history you have not fitted on. The sequence grammar has "
        "never seen the test families' tools, so CH01 has nothing to compare "
        "against.\n")
    add(
        "It used to flag everything in that situation: on the corpus revision where "
        "that was measured, a false positive rate of 100.0% at precision 33.3%, "
        "which is exactly the attack base rate and therefore an alarm carrying no "
        "information. A bigram model applied outside its distribution scores every "
        "transition as unseen, and the rate pins to 1.0 whether the session is "
        "benign or not.\n")
    add(
        f"CH01 now declines instead. When a session of at least "
        f"{MIN_CALLS_FOR_VOCABULARY_JUDGEMENT} calls uses tools the baseline mostly "
        f"does not know, the check reports `not_evaluated` with reason "
        f"`BASELINE_VOCABULARY_MISMATCH` rather than firing. False positive rate in "
        f"this regime is now "
        f"**{fam['false_positive_rate']['value']:.1%}** "
        f"({fam['false_positive_rate']['numerator']}/"
        f"{fam['false_positive_rate']['denominator']}), precision "
        f"**{fam['precision']['value']:.1%}**.\n")
    add(
        f"**And this regime is why the two recall columns exist.** Any-alert recall "
        f"here is {fam['any_alert_recall']['value']:.1%}; attributable recall is "
        f"**{fam['target_attributable_recall']['value']:.1%}**, and the "
        f"{fam['incidental_detections']} sessions between them are attacks whose "
        f"responsible check declined while a different check fired on the same "
        f"trace. A card reporting only the first would say CH01 kept its recall "
        f"after switching itself off, which is the opposite of what happened. "
        f"{fam_missed_dilution} of the {fam_dilution_total} `attack_dilution` "
        f"sessions go uncaught, because CH01 is the only check that can see a "
        f"diluted attack and CH01 is switched off here by its own vocabulary "
        f"contract.\n")
    add(
        f"What is left is a false positive rate within reach of `task_disjoint`'s "
        f"{honest['false_positive_rate']['value']:.1%}, which is the honest read: "
        f"the workload-transfer failure is gone and the residual is the "
        f"benign-hard confounder problem that every regime shares.\n")
    add(
        "CH01 still does not transfer across workloads. The difference is that it "
        "now says so in the coverage contract instead of paging somebody -- and the "
        "recall line above is the price of that honesty, stated rather than "
        "averaged away.\n")

    # ---- where the false positives come from ----------------------------
    add("### 3. Where the false positives come from")
    add("")
    add("Every benign-hard confounder is a session that is genuinely benign and")
    add("genuinely looks like the attack it sits next to. The plain benign sessions")
    add("are the control.")
    add("")
    add("| benign session kind | flagged | of | note |")
    add("|---|---|---|---|")
    kind_notes = {
        "benign": "clean control",
        gen.BENIGN_HARD_UNTRUSTED: "reads attacker-authored text then acts. "
                                   "That is the job (CH03)",
        gen.BENIGN_HARD_ADVISORY: "continues past an ADVISORY threshold. Nothing "
                                  "declares advisory vs blocking (CH04)",
        gen.BENIGN_HARD_TIMEOUT: "a call timed out and emitted no terminal "
                                 "event (CH05)",
        gen.BENIGN_HARD_TERSE: "honest summary, paraphrased. EVASION.md E04 (CH02)",
        gen.BENIGN_HARD_HONEST_DENIAL: "honest summary that also says what the agent "
                                       "did NOT do. Denial carries no label "
                                       "information here, by construction (CH02)",
        gen.BENIGN_HARD_RARE: "legitimate but rare ordering (CH01)",
        gen.BENIGN_LONG: "the same ordinary work, repeated. Second clean control, "
                         "and what teaches the baseline that agents loop",
        gen.BENIGN_HARD_LONG_RARE: "a long session ending in the family's own rare "
                                   "secondary action. Structurally identical to "
                                   "`attack_dilution` (CH01)",
        gen.BENIGN_HARD_REORDERED: "records delivered out of order. Every "
                                   "streaming path does this and it must not "
                                   "read as deletion (CH06)",
        gen.BENIGN_HARD_APPROVED: "a BLOCKING control fires and a human approves "
                                  "the exception properly. Correct operation "
                                  "that was indistinguishable from a bypass "
                                  "until approvals could bind (CH04)",
        gen.BENIGN_HARD_REAPPROVED: "an approved action fails and is retried "
                                    "under a fresh approval. The most ordinary "
                                    "thing a governed agent does (CH04)",
        gen.BENIGN_HARD_ROTATED: "a signed stream whose collector key is rotated "
                                 "partway through, one session straddling the "
                                 "handover. A verifier that reports a correct "
                                 "rotation as tampering teaches operators to "
                                 "rotate less often (CH06)",
    }
    by_kind = results[f"unseen|{REGIME_TASK_DISJOINT}|{CAP_MANIFEST}"]["by_kind"]
    for kind in gen.BENIGN_KINDS:
        row = by_kind.get(kind)
        if not row:
            continue
        add(f"| `{kind}` | {row['flagged']} | {row['sessions']} "
            f"| {kind_notes.get(kind, '')} |")
    add("")
    add("The plain benign sessions produce no false positives at all. Every false")
    add("positive in this corpus comes from a confounder, and every confounder trips")
    add("exactly the check it was built to trip. Cohaera is not noisy; it is")
    add("**unable to distinguish intent from sequence**, which is a different and")
    add("less fixable problem, and the one an operator will actually meet.")
    add("")
    add("| attack kind | flagged | of |")
    add("|---|---|---|")
    for kind in gen.ATTACK_KINDS:
        row = by_kind.get(kind)
        if not row:
            continue
        add(f"| `{kind}` | {row['flagged']} | {row['sessions']} |")
    add("")

    # ---- what P1 evidence trust bought ---------------------------------
    p1_attacks = (gen.ATTACK_OMITTED_CALL, gen.ATTACK_DENIED_EFFECT,
                  gen.ATTACK_REUSED_APPROVAL, gen.ATTACK_REVOKED_KEY)
    p1_benign = (gen.BENIGN_HARD_REORDERED, gen.BENIGN_HARD_APPROVED,
                 gen.BENIGN_HARD_REAPPROVED, gen.BENIGN_HARD_ROTATED)
    ch04 = attribution_for(results).get("CH04_guardrail_overrun", {})
    advisory = by_kind.get(gen.BENIGN_HARD_ADVISORY, {"flagged": 0, "sessions": 0})
    add("### 3b. What P1 evidence trust bought, and what it did not")
    add("")
    add("Four of the attack kinds above and four of the benign ones exist only")
    add("because [docs/EVIDENCE-TRUST.md](../docs/EVIDENCE-TRUST.md) needed to be")
    add("gradeable. A corpus can only grade fixes for attacks it contains, which is")
    add("the lesson E02 forced, applied in advance this time.")
    add("")
    add("| kind | flagged | of | what it measures |")
    add("|---|---|---|---|")
    p1_notes = {
        gen.ATTACK_OMITTED_CALL: "a consequential call deleted from a chained "
                                 "stream. **Invisible to CH01-CH05 by "
                                 "construction**",
        gen.ATTACK_DENIED_EFFECT: "the call reports failure and carries a receipt "
                                  "bound to it",
        gen.ATTACK_REUSED_APPROVAL: "an approval granted for one set of arguments, "
                                    "presented for another",
        gen.BENIGN_HARD_REORDERED: "out-of-order delivery. **Must not** read as "
                                   "deletion",
        gen.BENIGN_HARD_APPROVED: "a properly approved continuation. **Must not** "
                                  "read as a bypass",
        gen.BENIGN_HARD_REAPPROVED: "an approved retry after a failure. **Must "
                                    "not** fire",
        gen.ATTACK_REVOKED_KEY: "a stream signed by a key the operator has "
                                "declared compromised",
        gen.BENIGN_HARD_ROTATED: "a correctly performed key rotation, one session "
                                 "straddling the handover. **Must not** fire",
    }
    for kind in (*p1_attacks, *p1_benign):
        row = by_kind.get(kind)
        if not row:
            continue
        add(f"| `{kind}` | {row['flagged']} | {row['sessions']} "
            f"| {p1_notes[kind]} |")
    add("")
    add(
        f"**The one number to take from this section is CH04's.** It moved from "
        f"50% alert precision to **{ch04.get('precision_pct', 0)}%**, and "
        f"`benign_hard_advisory_threshold` from the corpus's largest single "
        f"source of false positives to **{advisory['flagged']} of "
        f"{advisory['sessions']}**. Nothing about the detection changed. A field "
        f"appeared that says whether the control was advisory or blocking, and a "
        f"check that had been reporting a sequence because it could not report a "
        f"bypass stopped having to.\n")
    add(
        "**And the one to be sceptical about is `attack_omitted_call`.** It is "
        "caught because the corpus emits `cohaera.integrity:1` and the deletion "
        "leaves a hole in the collector's sequence. Strip the sidecars from every "
        "record and the same sessions are undetectable again — which is where "
        "every deployment that has not adopted the format already is. The corpus "
        "measures the mechanism working; it does not measure anyone having "
        "deployed it. `tests/test_evidence.py` asserts both directions.\n")
    revoked = by_kind.get(gen.ATTACK_REVOKED_KEY, {"flagged": 0, "sessions": 0})
    rotated = by_kind.get(gen.BENIGN_HARD_ROTATED, {"flagged": 0, "sessions": 0})
    add(
        f"**Read the trust-store pair in the right order: the benign row is the "
        f"result and the attack row is nearly a tautology.** "
        f"`attack_revoked_key_stream` scores {revoked['flagged']} of "
        f"{revoked['sessions']}, and it does so by looking a key id up in a file "
        f"the operator supplied and finding `revoked_at` set. Nothing about that "
        f"could plausibly have failed, and publishing it as a detection win would "
        f"be measuring the label. The number that could have gone wrong is "
        f"`benign_hard_rotated_key`: {rotated['flagged']} of "
        f"{rotated['sessions']}, including one session per vocabulary whose "
        f"records straddle the rotation instant and are therefore signed by two "
        f"different keys, both correctly. A verifier that reported a correct "
        f"rotation as tampering would teach operators to rotate less often, which "
        f"is a security control making security worse.\n")
    add(
        "Most of the corpus is chained but **not signed**, and CH06 reports "
        "`degraded` rather than `evaluated` across it: a chain with nothing to "
        "verify its origin establishes that the stream is self-consistent, which "
        "an attacker who rewrote the whole stream can also arrange. That is the "
        "realistic first-adoption state. The two trust-store kinds are the "
        "exception and sit on a second, signed collector stream, because "
        "everything they measure is a statement about a KEY and an unsigned "
        "record's `key_id` is a string anybody can write. They are also the "
        "corpus's only multi-collector shape, so cross-stream gap attribution is "
        "measured here rather than asserted.\n")
    add(
        "**One kind was considered and declined: a replayed stream.** A captured "
        "stream re-fed months later passes every check in the module, and the "
        "only thing that separates it from a legitimately delayed batch is the "
        "age of a timestamp — the telemetry is otherwise byte-identical. "
        "Labelling one of two identical inputs `attack` would measure the label "
        "rather than a detector, which is the same reason `attack_forged_success` "
        "is absent. The freshness bound is real and is tested in "
        "`tests/test_evidence.py`; what it costs on a delayed batch is a property "
        "of the bound the operator sets, not of this corpus.\n")
    add(
        "The same goes for the seen-stream ledger, and it explains a number in "
        "this card that moves the wrong way. Cross-run replay needs TWO runs "
        "against shared state; this harness scores one run, so the ledger cannot "
        "be measured here at all and is tested directly instead. What it does do "
        "here is lower `mean_coverage_completeness`, because CH06 now reports "
        "`NO_STREAM_LEDGER` on every session — the eval runs without one. "
        "**Coverage fell because a control was added and is not in force**, which "
        "is the behaviour the contract is for: an absent check that says nothing "
        "would have left the number flat and the blind spot invisible.\n")
    dil = by_kind.get(gen.ATTACK_DILUTION, {"flagged": 0, "sessions": 0})
    long_rare = by_kind.get(gen.BENIGN_HARD_LONG_RARE,
                            {"flagged": 0, "sessions": 0})
    marginal = dil["flagged"] + long_rare["flagged"]
    add(
        f"**`attack_dilution` is EVASION.md E02, and it is the one pair of rows in "
        f"this section that records a change rather than a limitation.** A diluted "
        f"attack is the family's ordinary work looped three times with one "
        f"out-of-family export at the end; the violation rate falls to 0.15 and "
        f"CH01's rate trigger, on its own, caught **0 of "
        f"{dil['sessions']}**. With the count trigger it catches "
        f"**{dil['flagged']} of {dil['sessions']}**, and it also fires on "
        f"**{long_rare['flagged']} of {long_rare['sessions']}** "
        f"`benign_hard_long_rare_action` sessions, which are the same shape with a "
        f"legitimate trailing action. "
        + (f"That is {dil['flagged']}:{long_rare['flagged']} in favour on the "
           f"marginal alerts -- {dil['flagged'] / marginal:.0%} precision on the "
           f"alerts the change adds, against "
           f"{unseen_manifest['precision']['value']:.0%} corpus-wide. "
           if marginal else "")
        + "The trade is real in both directions and both directions are above.\n")

    # ---- per check ------------------------------------------------------
    add("### 4. Per-check alert precision")
    add("")
    add("Not \"how good is the detector\" but \"which rule pages an analyst for")
    add("nothing\". A check firing on as many benign sessions as attacks is a coin")
    add("flip wearing a rule ID.")
    add("")
    add("| check | on its OWN attacks | incidental on other attacks "
        "| on benign | target precision | any-attack precision | missed own labels |")
    add("|---|---|---|---|---|---|---|")
    attribution = results[
        f"unseen|{REGIME_TASK_DISJOINT}|{CAP_MANIFEST}"]["check_attribution"]
    for check, row in attribution.items():
        add(f"| `{check}` | {row['on_target_attacks']} "
            f"| {row['incidental_on_attacks']} | {row['on_benign']} "
            f"| {row['target_precision_pct']}% | {row['precision_pct']}% "
            f"| {row['missed_own_labels']} of {row['labelled']} |")
    add("")
    add(
        "**Target precision is the honest per-rule number and is always the lower "
        "of the two.** A check that fires on an attack belonging to a different "
        "check has helped, but it has not demonstrated that it does its own job -- "
        "and counting those as hits is what made the previous card's per-check "
        "table wrong in the flattering direction.\n")

    # ---- base rates -----------------------------------------------------
    add("### 5. The same detector at a realistic attack base rate")
    add("")
    add("Every precision figure above is computed at this corpus's attack")
    add("prevalence of "
        f"{summary['conditions']['unseen']['attack_prevalence']:.1%}, which is")
    add("absurd and is chosen so the corpus has enough attacks to measure. Precision")
    add("is not a property of a detector; it is a property of a detector AND a base")
    add("rate. Here is the same measured TPR and FPR standardised to prevalences a")
    add("real fleet might have.")
    add("")
    add("| attack prevalence | alerts per 1000 sessions | precision |")
    add("|---|---|---|")
    for row in unseen_manifest["base_rate_projection"]:
        add(f"| {row['attack_prevalence']:.1%} "
            f"| {row['alerts_per_1000_sessions']} | {row['precision']:.2%} |")
    add("")
    add(
        f"**The prevalence-free unit is "
        f"{unseen_manifest['false_positives_per_1000_benign_sessions']} false "
        f"positives per 1000 BENIGN sessions.** The previous card published "
        f"{unseen_manifest['false_positives_per_1000_sessions']} per 1000 sessions "
        f"and told operators to plan capacity against it, which understates the "
        f"load because the denominator included the corpus's own inflated attack "
        f"population. Plan against the benign-normalised number and read precision "
        f"from the table above, not from \u00a71.\n")

    # ---- clustering -----------------------------------------------------
    add("### 6. The intervals when a task, not a session, is the unit")
    add("")
    add("R-15. Every interval above is a Wilson interval over SESSIONS, and the")
    add("corpus generator says in its own docstring that the attempts of one task")
    add("are near-duplicates. Treating each attempt as an independent trial narrows")
    add("the interval, and gives a template rendered four times the weight of four")
    add("distinct tasks. Task-disjoint splitting stops a task's attempts")
    add("spanning train and test; it does nothing about the attempts inside the test")
    add("set still being the same task.")
    add("")
    ind = unseen_manifest["sample_independence"]
    add(f"This cell contains **{ind['sessions']} sessions** but only")
    add(f"**{ind['tasks']} independent tasks** across **{ind['families']} "
        f"families**.")
    add("")
    add("| measure | Wilson over sessions | bootstrap over tasks | macro average "
        "over tasks |")
    add("|---|---|---|---|")
    for label, key in (("target-attributable recall",
                        "target_attributable_recall"),
                       ("any-alert recall", "any_alert_recall"),
                       ("false positive rate", "false_positive_rate")):
        wilson_rate = unseen_manifest[key]
        cluster = unseen_manifest["cluster_aware"][key]
        t_lo, t_hi = cluster["task_bootstrap_ci95"]
        add(f"| {label} | {wilson_rate['value']:.1%} "
            f"[{wilson_rate['ci95_low']:.1%}-{wilson_rate['ci95_high']:.1%}] "
            f"| [{t_lo:.1%}-{t_hi:.1%}] "
            f"| {cluster['task_macro_average']:.1%} |")
    add("")
    add("The bootstrap interval is roughly twice the width of the Wilson one. That")
    add("factor is the correction, and it is the number to quote when the question")
    add("is whether a result would survive a different set of tasks rather than")
    add("whether it is stable on this one.")
    add("")
    # Only for measures that are not already saturated. A rate of exactly 0% or
    # 100% has zero variance under ANY resampling scheme, so a zero-width
    # family interval there says nothing about the corpus -- reporting it as a
    # finding would be reading a tautology as evidence.
    degenerate = [
        label for label, key in (("target-attributable recall",
                                  "target_attributable_recall"),
                                 ("any-alert recall", "any_alert_recall"),
                                 ("false positive rate", "false_positive_rate"))
        if 0.0 < unseen_manifest[key]["value"] < 1.0
        and (unseen_manifest["cluster_aware"][key]["family_bootstrap_ci95"][0]
             == unseen_manifest["cluster_aware"][key]["family_bootstrap_ci95"][1])
    ]
    if degenerate:
        add("**A finding about the corpus rather than about the detector.** "
            "Resampling")
        add(f"the {ind['families']} families cannot move "
            f"{'these measures' if len(degenerate) > 1 else 'this measure'} "
            f"({', '.join(degenerate)}).")
        add("Every family has an identical benign and attack count and produces an")
        add("identical rate, so a family-level interval has zero width. That is not")
        add("a strong result -- it is a measurement of how regular the generator is.")
        add("A real fleet's workloads do not come in equal portions and do not")
        add("detect equally, and a family holdout on this corpus is therefore")
        add("testing less than the name suggests.")
        add("")

    # ---- honesty --------------------------------------------------------
    add("---")
    add("")
    add("## What this does not measure")
    add("")
    add("Stated up front, because a limitation you declare is a limitation and one")
    add("you hide is a defect.")
    add("")
    add("- **The corpus is synthetic.** It is generated by "
        "`eval/corpus/generate.py`, by the same author as the detector. It is a")
    add("  large improvement on twelve near-identical fixtures and it is not real")
    add("  agent traffic. The numbers here are an upper bound on a lower bound: the")
    add("  attacks are as obvious as I could make them while staying plausible, and")
    add("  the confounders are as hard as I could think of.")
    add("- **Attack prevalence is "
        f"{summary['conditions']['unseen']['attack_prevalence']:.0%}, which is "
        "absurd.** Real")
    add("  prevalence is orders of magnitude lower, and precision falls with it. At a")
    add("  realistic base rate the false positive counts in section 3 dominate")
    add("  completely. Plan capacity against")
    add("  `false_positives_per_1000_benign_sessions`, never against precision and")
    add("  never against `false_positives_per_1000_sessions` -- this paragraph used")
    add("  to recommend the second, contradicting section 5 four hundred lines")
    add("  above it. The all-session figure moves with this corpus's artificial")
    add("  attack prevalence and is published only so the two can be compared.")
    add(f"- **No adaptive attacker.** Every attack here is one of "
        f"{len(gen.ATTACK_KINDS)} fixed shapes.")
    add("  EVASION.md catalogues seventeen ways to defeat these checks. Exactly one")
    add("  of them, E02, appears in this corpus, and only because a fix for it")
    add("  could not be graded otherwise. An attacker who has read that file scores")
    add("  differently.")
    add("- **CH02 is scored lexically because CH02 IS lexical.** The")
    add("  `benign_hard_terse_summary` confounder is not a corpus artefact; it is")
    add("  the check's known ceiling, measured.")
    add("- **The vocabulary is a sample of one author's guess at realistic tool")
    add("  names.** `unseen` means unseen by the keyword lists, which is checked in")
    add("  code and is the property that matters here. It does not mean")
    add("  representative of the tool names in your environment.")
    add("")
    add("## Reproducing")
    add("")
    add("```bash")
    add("python eval/corpus/generate.py     # deterministic; same seed, same bytes")
    add("python eval/run_eval.py            # regenerates this card")
    add("python eval/vocabulary.py          # the name-heuristic audit on its own")
    add("```")
    add("")
    add("Full per-cell numbers, including every confidence interval, family")
    add("breakdown and confusion matrix, are in `eval/evaluation-card.json`.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=gen.SEED)
    ap.add_argument("--reuse-generated", "--no-generate", action="store_true",
                    dest="no_generate",
                    help="reuse the corpus already in eval/corpus/data instead "
                         "of regenerating it. NOT the same as scoring a "
                         "committed corpus: that directory is gitignored and "
                         "absent from a clean checkout, so this fails with an "
                         "instruction until a generating run has happened. "
                         "--no-generate is the old name and still works.")
    args = ap.parse_args(argv)

    if args.no_generate and not any(DATA.glob("*.jsonl")):
        # R-20. This path advertised itself as "score the committed corpus",
        # and the corpus is not committed -- eval/corpus/data is gitignored
        # because it is 41 MB and deterministic from its seed. On a clean
        # checkout the command died in `read_text` with a FileNotFoundError
        # naming one file, which reads as a broken repository rather than as a
        # step that has not been run. CI always generates first, so nothing
        # ever exercised it.
        print(f"{DATA} has no corpus to reuse. It is generated rather than "
              f"committed: run `python eval/run_eval.py` with no arguments "
              f"once, then --reuse-generated will score what that produced.",
              file=sys.stderr)
        return 2

    if not args.no_generate:
        # The committed sample is regenerated here too, not only by
        # generate.py's own main(). CI checks it for drift, and a drift check
        # over a file the command never writes passes for the wrong reason.
        gen.write_sample(gen.generate("unseen", args.seed),
                         Path(__file__).resolve().parent / "corpus")
    summary = (gen.write(DATA, args.seed) if not args.no_generate
               else _summary_without_generating(args.seed))

    results = run_grid(args.seed)
    corpus = load_corpus(DATA, "unseen")
    clean, leaky, leak_prov = leakage_experiment(
        corpus, args.seed, load_manifest(DATA, "unseen"),
        store=load_trust_store(DATA, "unseen"))
    leakage = {"provenance": leak_prov, "clean": summarise(clean),
               "leaky": summarise(leaky)}
    payload = {
        "detector_version": __version__,
        "config_hash": DEFAULT_LIMITS.digest(),
        "corpus_digest": corpus_digest(),
        "seed": args.seed,
        "corpus": summary,
        "vocabulary_audit": {c: audit(c).as_dict() for c in CONDITIONS},
        "cells": results,
        "leakage_experiment": leakage,
    }
    CARD_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    CARD_MD.write_text(render_card(results, args.seed, summary, leakage),
                   encoding="utf-8")

    headline = _cell(results, "unseen", REGIME_TASK_DISJOINT, CAP_MANIFEST)
    blind = _cell(results, "unseen", REGIME_TASK_DISJOINT, CAP_NAME_ONLY)
    print(f"wrote {CARD_MD.relative_to(REPO)} and {CARD_JSON.relative_to(REPO)}")
    print(f"  unseen/task_disjoint/manifest   "
          f"recall {headline['recall']['value']:.1%}  "
          f"FPR {headline['false_positive_rate']['value']:.1%}  "
          f"FP/1000 benign "
          f"{headline['false_positives_per_1000_benign_sessions']}")
    print(f"  unseen/task_disjoint/name_only  "
          f"recall {blind['recall']['value']:.1%}  "
          f"FPR {blind['false_positive_rate']['value']:.1%}  "
          f"coverage {blind['mean_coverage_completeness']:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
