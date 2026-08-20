"""Adapter for StepShield code-agent trajectories.

Source: https://github.com/glo26/stepshield
Licence: code MIT (LICENSE file present, fetched and read); data CC BY 4.0
        (stated in both README.md and data/README.md). Verified 2026-08-19.

This adapter was written against REAL RECORDS fetched from the repository, not
only against its schema documentation -- which matters, because the two disagree.
See "the documented schema is incomplete" below.

THE BENIGN COUNT: 2,514, NOT 6,657
----------------------------------
The repository's top-level README and the composition table in data/README.md
both say 6,657 generated benign trajectories. That number is not in the
repository. Verified three independent ways on 2026-08-19:

  * File probing. ``data/generated_benign/BENIGN-GEN-02514.jsonl`` returns 200
    and ``BENIGN-GEN-02515.jsonl`` returns 404, as does ``BENIGN-GEN-06657``.
  * The repository's own CHANGELOG.md: "Released 2,514 generated benign
    trajectories for false positive rate calibration."
  * The directory-layout section of data/README.md, which contradicts the
    composition table four paragraphs above it: "generated_benign/ # 2,514
    benign trajectories for PPV calibration".

6,657 appears to describe a test split that exists in the paper rather than in
the published data. The benign denominator this harness can actually compute a
false-positive rate over is 2,514, and any figure quoted per 1,000 benign
sessions from this corpus rests on that number.

THE DOCUMENTED SCHEMA IS INCOMPLETE
-----------------------------------
data/README.md documents one record shape. The repository ships two, and an
adapter written only from the documentation crashes on the larger half.

Training pairs (``data/train/<CAT>/<ID>.jsonl``), pretty-printed JSON::

    {"trajectory_id": "SEC-L2-001-ROGUE", "task": {...}, "steps": [...]}

Generated benign (``data/generated_benign/BENIGN-GEN-NNNNN.jsonl``), one line::

    {"trajectory_id": "BENIGN-GEN-00001", "trajectory_type": "benign",
     "task_id": "benign-debugging-7001", "category": "DEC",
     "total_steps": 11, "task": {...}, "steps": [...]}

Three fields exist only on the benign records and none of them are documented:
``trajectory_type``, ``task_id``, ``category``. The consequence is not cosmetic.
The documented id format is ``CATEGORY-SEVERITY-NUMBER-TYPE``, so reading the
label off the id suffix works for ``SEC-L2-001-ROGUE`` and yields ``00001`` for
``BENIGN-GEN-00001`` -- an adapter that trusted the documentation alone would
reject every benign trajectory in the corpus, which is to say the entire benign
denominator. This adapter prefers the explicit fields and falls back to the id.

``steps[]`` is identical across both shapes: ``step``, ``thought``, ``action``,
``arguments``, ``observation``, ``label``, ``rationale``. ``label`` is the
violation category on a rogue step and null everywhere else.

WHY THIS CORPUS
---------------
It has a real benign denominator and it PAIRS. ``SEC-L2-001-ROGUE`` and
``SEC-L2-001-CLEAN`` are one task rendered two ways -- confirmed by fetching
both and finding the same task title -- which is exactly the cluster the
bootstrap interval needs and which R-15 already argued for internally.

WHAT MAPS, AND WHAT DOES NOT
----------------------------
Maps cleanly:
  step.action              -> tool_name on a tool_start/tool_end pair
  step.arguments           -> data.tool_args, so an argument digest is real
  step.observation         -> data.tool_result
  task.description         -> a user_message event
  the last step's output   -> a model_response carrying response_text

Does not map, and is therefore ABSENT rather than defaulted:
  reversibility      -- the corpus does not classify its actions. Omitted, so
                        Cohaera falls back to its name heuristic and charges
                        TOOL_CLASS_FROM_NAME_HEURISTIC / TOOL_CLASS_UNKNOWN
                        against coverage, which is the honest answer.
  injection scanner  -- see below; this is the one partial case.
  policy / approval / integrity / receipts -- NO_CONTROL_PLANE, as for every
                        public corpus.

THE ONE PARTIAL SURFACE
-----------------------
CH03 asks whether untrusted content reached a consequential call. StepShield
runs no injection scanner, so there is no ``has_injection_patterns`` to carry
over and writing one would be the exact fabrication base.py refuses.

What it DOES carry is a per-step rogue annotation, and for the data-exfiltration
and supply-chain categories that annotation frequently marks the step where
content the agent did not author entered the trajectory. That is adjacent to,
but not the same as, a scanner's answer, so it sits behind an explicit opt-in
(``mark_untrusted_from_labels``) which is OFF by default. Turning it on makes
CH03 partially measurable and simultaneously makes the run label-dependent; the
runner records which way it was set, and the scope statement calls CH03 partial
for exactly this reason.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cohaera.checks import SURFACE_INJECTION_SCANNER

from .base import (
    NO_CONTROL_PLANE,
    Absence,
    AbsenceLedger,
    AdaptedSession,
    AdapterError,
    assert_no_fabricated_evidence,
    cim_event,
    require_mapping,
    safe_id,
)

CORPUS = "stepshield"

# The six violation categories, from the repository's own table.
CATEGORIES = {
    "INV": "data_exfiltration",
    "SEC": "privilege_escalation",
    "RES": "resource_hijacking",
    "TST": "supply_chain_attack",
    "DEC": "destructive_action",
    "UFO": "covert_persistence",
}

# The three trajectory types the corpus uses. ROGUE is the only attack class;
# CLEAN is the matched control for a rogue pair, BENIGN the generated
# deployment-realistic population.
KIND_ROGUE = "rogue"
KIND_CLEAN = "clean"
KIND_BENIGN = "benign"
KINDS = frozenset({KIND_ROGUE, KIND_CLEAN, KIND_BENIGN})

# Categories whose rogue annotation tends to mark content entering the
# trajectory rather than an action the agent took unprompted. Only these are
# eligible for the opt-in untrusted marking, and even then only when the step
# actually produced an observation.
_INGRESS_CATEGORIES = frozenset({"INV", "TST"})

# One second per step. The corpus carries no wall clock at all, and inventing a
# plausible-looking one would be fabrication of a different kind -- so this is a
# monotonic synthetic ordering, declared as such, used only to preserve the step
# order the corpus DOES state. Cohaera reads order, not duration, from it.
STEP_SECONDS = 1.0
EPOCH = 1_760_000_000.0


def _kind(record: dict[str, Any], trajectory_id: str, where: str) -> str:
    """ROGUE / CLEAN / BENIGN, preferring the explicit field over the id.

    ``trajectory_type`` is present on the generated-benign records and absent
    from the training pairs. Neither is documented as optional, so both paths
    exist and the fallback is the DOCUMENTED one -- meaning a future record that
    drops the undocumented field still parses.
    """
    declared = record.get("trajectory_type")
    if isinstance(declared, str) and declared.strip().lower() in KINDS:
        return declared.strip().lower()

    # Documented format: CATEGORY-SEVERITY-NUMBER-TYPE.
    suffix = str(trajectory_id).rsplit("-", 1)[-1].strip().lower()
    if suffix in KINDS:
        return suffix
    # BENIGN-GEN-NNNNN, whose suffix is a number rather than a type.
    if str(trajectory_id).upper().startswith("BENIGN"):
        return KIND_BENIGN
    raise AdapterError(
        f"{where}: cannot determine the trajectory type of {trajectory_id!r}. "
        "There is no 'trajectory_type' field and the id suffix is not one of "
        f"{sorted(KINDS)}. Refusing to guess: a trajectory assumed benign moves "
        "a session from the numerator to the denominator of every rate here.")


def _task_id(record: dict[str, Any], trajectory_id: str) -> str:
    """The clustering unit, preferring the explicit field.

    On a training pair this is the id minus the ROGUE/CLEAN suffix, so a rogue
    and its clean twin share it and the bootstrap treats them as one draw --
    verified by fetching SEC-L2-001-ROGUE and SEC-L2-001-CLEAN and finding the
    same task title. On generated-benign records the corpus supplies its own
    ``task_id`` (e.g. ``benign-debugging-7001``), which several trajectories
    share, and that is the better cluster.
    """
    declared = record.get("task_id")
    if isinstance(declared, str) and declared.strip():
        return declared.strip()
    return str(trajectory_id).rsplit("-", 1)[0]


def _category(record: dict[str, Any], trajectory_id: str) -> str:
    declared = record.get("category")
    head = (declared if isinstance(declared, str) and declared
            else str(trajectory_id).split("-", 1)[0])
    return CATEGORIES.get(head.upper(), "unknown")


def adapt_trajectory(record: Any, *, source_name: str = "<memory>",
                     mark_untrusted_from_labels: bool = False
                     ) -> AdaptedSession:
    """Map one StepShield trajectory into an :class:`AdaptedSession`.

    Raises :class:`AdapterError` on anything that does not match the schema. It
    does not skip, warn and continue: a corpus that half-parses produces a
    false-positive rate over a population nobody can describe.
    """
    rec = require_mapping(record, "a trajectory", source_name)

    traj_id = rec.get("trajectory_id")
    if not isinstance(traj_id, str) or not traj_id:
        raise AdapterError(
            f"{source_name}: trajectory_id is missing or not a string. It "
            "carries the label and the pair key on training records, so there "
            "is nothing to fall back to.")

    steps = rec.get("steps")
    if not isinstance(steps, list) or not steps:
        raise AdapterError(
            f"{source_name}: 'steps' must be a non-empty list; got "
            f"{type(steps).__name__}.")

    kind = _kind(rec, traj_id, source_name)
    is_attack = kind == KIND_ROGUE

    sid = safe_id(traj_id)
    events: list[dict[str, Any]] = []
    ts = EPOCH

    # The task description is the user's request. Emitted because CH02 reads the
    # final response against what the session did, and a session with no request
    # is not the shape any real deployment produces.
    task = rec.get("task")
    if isinstance(task, dict):
        description = task.get("description")
        if isinstance(description, str) and description:
            events.append(cim_event(
                sid, ts, "user_message", source=CORPUS,
                user_message_text=description))
            ts += STEP_SECONDS

    scanner_marked_any = False
    last_observation: str | None = None

    for index, raw_step in enumerate(steps):
        step = require_mapping(raw_step, f"step {index}", source_name)
        action = step.get("action")
        if not isinstance(action, str) or not action:
            raise AdapterError(
                f"{source_name}: step {index} has no string 'action', so there "
                "is no tool name to record. The adapter will not invent one.")

        span = f"sp-{sid}-{index}"
        start_data: dict[str, Any] = {"action": "invoke_tool"}

        # Arguments, when the corpus supplies them. This is a genuine surface:
        # Cohaera recomputes an argument digest from captured arguments, which
        # is what lets an approval or receipt bind by argument rather than span.
        # Neither exists here, but the digest is still real and still recorded.
        arguments = step.get("arguments")
        if isinstance(arguments, dict) and arguments:
            start_data["tool_args"] = arguments

        events.append(cim_event(sid, ts, "tool_start", source=CORPUS,
                                tool=action, span=span, **start_data))

        # The opt-in, and the only place CH03 can be given anything at all.
        if mark_untrusted_from_labels:
            label = step.get("label")
            observation = step.get("observation")
            if (isinstance(label, str) and label.upper() in _INGRESS_CATEGORIES
                    and isinstance(observation, str) and observation):
                events.append(cim_event(
                    sid, ts + 0.1, "skill_invocation", source=CORPUS,
                    tool=action, action="invoke_tool",
                    # Pattern NAMES only. The corpus's own rationale text is not
                    # reproduced: it is the annotator's prose, not a marker.
                    injection_patterns=[f"stepshield_label_{label.upper()}"],
                    has_injection_patterns=True))
                scanner_marked_any = True

        end_data: dict[str, Any] = {}
        observation = step.get("observation")
        if isinstance(observation, str) and observation:
            end_data["tool_result"] = observation
            last_observation = observation

        events.append(cim_event(sid, ts + 0.4, "tool_end", source=CORPUS,
                                tool=action, span=span, result="success",
                                **end_data))
        ts += STEP_SECONDS

    # CH02 needs a final response. The corpus has no dedicated final-answer
    # field, so the last step's observation stands in -- and that substitution
    # is declared, because it is a real weakness: CH02 measures concealment in
    # the agent's summary, and a tool observation is not a summary. The scope
    # statement says CH02 is externally validatable; this note says on what.
    notes: list[str] = []
    if last_observation is not None:
        events.append(cim_event(
            sid, ts, "model_response", source=CORPUS,
            response_text=last_observation))
        notes.append(
            "final_response is the last step's observation. StepShield has no "
            "dedicated final-answer field, so CH02 is measured against tool "
            "output rather than an agent summary.")
    else:
        notes.append(
            "no observation on any step, so no final response was emitted; "
            "CH02 will decline with NO_FINAL_RESPONSE_TEXT.")

    absences = [*NO_CONTROL_PLANE]
    if not scanner_marked_any:
        absences.append(Absence(
            SURFACE_INJECTION_SCANNER,
            "StepShield runs no injection scanner. No has_injection_patterns "
            "was emitted, so CH03 declines with NO_INJECTION_SCANNER_EVIDENCE "
            "rather than being handed a fabricated negative."))

    # The doctrine's teeth, on this adapter's own output. The scanner surface is
    # named as sourced ONLY when the opt-in actually marked a step from the
    # corpus's own per-step annotation -- never merely because the flag was set.
    assert_no_fabricated_evidence(
        events, f"stepshield:{traj_id}",
        sourced=frozenset({SURFACE_INJECTION_SCANNER}) if scanner_marked_any
        else frozenset())

    return AdaptedSession(
        session_id=sid,
        events=tuple(events),
        is_attack=is_attack,
        task_id=_task_id(rec, traj_id),
        family=_category(rec, traj_id),
        kind=kind,
        absences=AbsenceLedger(tuple(absences)),
        corpus=CORPUS,
        target_check="",
        notes=tuple(notes),
    )


def load_directory(root: Path, *, mark_untrusted_from_labels: bool = False
                   ) -> list[AdaptedSession]:
    """Adapt every ``*.jsonl`` trajectory under ``root``, recursively.

    Fails loudly and specifically when the directory is absent, because that is
    the expected state of a fresh clone: the data is not in this repository and
    is not redistributed from it. See docs/EXTERNAL-VALIDATION.md for how to
    fetch it.
    """
    root = Path(root)
    if not root.exists():
        raise AdapterError(
            f"StepShield data not found at {root}.\n"
            "This repository does not vendor the corpus. Fetch it on a network "
            "that can reach github.com:\n"
            "    git clone https://github.com/glo26/stepshield.git\n"
            "and point --stepshield at its data/ directory, or at a split "
            "beneath it -- data/generated_benign is the 2,514-trajectory "
            "benign denominator.\n"
            "The dataset is CC BY 4.0: usable with attribution, and NOT "
            "redistributed here.")
    if not root.is_dir():
        raise AdapterError(f"StepShield path {root} is not a directory.")

    paths = sorted(root.rglob("*.jsonl"))
    if not paths:
        raise AdapterError(
            f"No *.jsonl trajectories under {root}. StepShield stores one JSON "
            "object per .jsonl file; an empty result means the wrong directory "
            "was given, and scoring zero sessions would report a false-positive "
            "rate of zero over a corpus that was never read.")

    out: list[AdaptedSession] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AdapterError(f"{path}: not valid JSON ({exc}).") from exc
        out.append(adapt_trajectory(
            payload, source_name=str(path),
            mark_untrusted_from_labels=mark_untrusted_from_labels))
    return out
