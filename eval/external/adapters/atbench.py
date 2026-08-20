"""Adapter for ATBench agent-trajectory safety records.

Source: https://github.com/LiYu0524/ATbench
Data:   Hugging Face, ``AI45Research/ATBench``.

READ THIS BEFORE TRUSTING ANY NUMBER THIS ADAPTER PRODUCES
----------------------------------------------------------
NO ATBENCH RECORD HAS EVER BEEN INSPECTED BY THIS CODE OR ITS AUTHOR.

1. THE GITHUB REPOSITORY CONTAINS NO DATA. It is a pointer repository. Verified
   on 2026-08-19 by direct fetch: ``assets/teaser.png`` returns 200, proving raw
   fetching works against this repo, while ``data/ATBench.json``,
   ``ATBench.jsonl`` and ``data/README.md`` all return 404. A placeholder file
   literally named ``ATBench Engine Coming Soon`` returns 200. The data is
   distributed only through Hugging Face (``AI45Research/ATBench``), which this
   sandbox's proxy blocks with a 403 CONNECT tunnel failure.

2. EVERY DATASET FIGURE IS A PROJECT CLAIM, NOT A VERIFIED FACT. 1,000
   trajectories, 503 safe / 497 unsafe, 9.01 average turns, "full human audit" --
   all of it is what the repository's README asserts about data nobody here
   could open. Cohaera's whole argument is that an unverified number is already
   wrong, so these are carried as claims and labelled as claims.

3. THERE IS NO LICENCE. Checked on the ``main`` ref: ``LICENSE``, ``LICENSE.md``,
   ``LICENSE.txt``, ``COPYING`` and ``license`` all return 404 while
   ``README.md`` on the same ref returns 200, so the absence is real rather than
   a fetch failure. The README grants no licence in prose either. Nothing here
   redistributes ATBench data and nothing should until the authors state terms:
   "publicly downloadable" is not a licence.

4. THE FIELD NAMES BELOW ARE THEREFORE UNVERIFIED. The README documents the
   trace SHAPE -- "user requests, agent responses, tool calls, and environment
   feedback", trajectory-level ``safe``/``unsafe`` labels, and a three-axis
   taxonomy of Risk Source, Failure Mode and Real-World Harm -- but not the JSON
   key names carrying it.

   So this adapter declares its key mapping in one table, :data:`FIELD_MAP`,
   marked UNVERIFIED, and fails loudly with the keys it actually observed when a
   record does not match. Correcting it against the real download is a one-place
   edit and the error message says what to put there. What it deliberately does
   NOT do is guess across several spellings and quietly succeed on whichever one
   hits, because an adapter that half-recognises a schema produces a
   false-positive rate over a population nobody can describe.

   StepShield is a warning here rather than a reassurance: its published schema
   documentation omitted three fields that its actual records carry, and an
   adapter written from the documentation alone would have rejected its entire
   benign population. Expect the same of ATBench and verify before trusting.

TASK POOLS, AND WHY THE BOOTSTRAP DEGENERATES HERE
--------------------------------------------------
StepShield pairs: ``SEC-L2-001-ROGUE`` and ``SEC-L2-001-CLEAN`` are one task
rendered twice, so a task is a real cluster and the bootstrap has something to
resample. ATBench documents no such pairing. Its generation pipeline runs
"sampled risks and candidate tool pools -> blueprint -> query generation, risk
injection, tool call simulation, tool response simulation, agent response
generation", which produces a trajectory per sampled risk rather than a safe and
unsafe rendering of a shared task, and the README never claims a shared pool.

The consequence is worth stating plainly because it is easy to miss: on ATBench
a task-disjoint split is ALSO a label-disjoint split, by construction. There is
no task that appears on both sides of the label boundary, so "we split by task"
buys none of the leakage protection it buys on a paired corpus, and any measured
difference between splits confounds task identity with label. Task clustering
therefore degenerates to session clustering here, the bootstrap interval
collapses to a session-level one, and the runner reports that rather than
presenting a task-level interval that is secretly nothing of the kind.

This is a documentation-derived conclusion, not a data-derived one -- the data
could not be downloaded to check. It is recorded as such.

WHAT MAPS, AND WHAT DOES NOT
----------------------------
Maps:      user request -> user_message; tool calls -> tool_start/tool_end
           pairs with arguments and environment feedback; final agent response
           -> model_response with response_text.
Absent:    policy events, approvals, integrity, receipts -- NO_CONTROL_PLANE.
           Tool reversibility is not declared, so it is omitted and Cohaera's
           name heuristic answers, degrading coverage honestly.
           No injection scanner, and unlike StepShield there is no per-step
           annotation to opt into, so CH03 declines outright on this corpus.
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

CORPUS = "atbench"

# UNVERIFIED. See the module docstring. Each logical field maps to the key names
# this adapter will accept, most-likely first. Edit here, in one place, once the
# real download is in front of you.
FIELD_MAP: dict[str, tuple[str, ...]] = {
    "id": ("id", "trajectory_id", "case_id", "sample_id"),
    "label": ("label", "safety_label", "is_safe", "safety"),
    "user_request": ("user_request", "query", "instruction", "user_query"),
    "trajectory": ("trajectory", "steps", "turns", "messages"),
    "final_response": ("final_response", "agent_response", "response", "answer"),
    "risk_source": ("risk_source", "risk", "risk_type"),
    "failure_mode": ("failure_mode", "failure"),
    "harm": ("real_world_harm", "harm", "harm_type"),
    # Within one trajectory turn.
    "tool_name": ("tool_name", "name", "tool", "action", "function"),
    "tool_args": ("arguments", "tool_args", "args", "parameters", "input"),
    "tool_result": ("observation", "tool_result", "environment_feedback",
                    "result", "output", "response"),
    "assistant_text": ("agent_response", "content", "text", "thought"),
}

# Values that mean "this trajectory is unsafe". Anything outside the safe and
# unsafe sets is refused rather than bucketed.
_UNSAFE = frozenset({"unsafe", "false", "0", "risky", "harmful"})
_SAFE = frozenset({"safe", "true", "1", "benign"})

STEP_SECONDS = 1.0
EPOCH = 1_760_000_000.0


def _pick(record: dict[str, Any], logical: str) -> Any:
    """First present key for a logical field, or None."""
    for key in FIELD_MAP[logical]:
        if key in record:
            return record[key]
    return None


def _missing(record: dict[str, Any], logical: str, where: str) -> AdapterError:
    """An error that tells the reader how to fix the mapping."""
    return AdapterError(
        f"{where}: could not find the {logical!r} field. Tried "
        f"{list(FIELD_MAP[logical])}; the record actually carries "
        f"{sorted(record)[:25]}.\n"
        "ATBench's key names could not be verified when this adapter was "
        "written (the data is on Hugging Face, which was unreachable), so "
        "FIELD_MAP in eval/external/adapters/atbench.py is the one place to "
        "correct. Do NOT work around this by defaulting the field.")


def _is_attack(value: Any, where: str) -> bool:
    """Read the trajectory-level safety label, refusing anything ambiguous."""
    if isinstance(value, bool):
        # A bare bool is 'is_safe', per the FIELD_MAP candidate of that name.
        return not value
    token = str(value).strip().lower()
    if token in _UNSAFE:
        return True
    if token in _SAFE:
        return False
    raise AdapterError(
        f"{where}: safety label {value!r} is neither safe nor unsafe. "
        "Refusing to bucket it -- a mislabelled trajectory silently moves a "
        "session between the numerator and the denominator of every rate this "
        "harness reports.")


def _turn_events(turn: Any, sid: str, index: int, ts: float,
                 where: str) -> tuple[list[dict[str, Any]], str | None]:
    """Map one trajectory turn. Returns (events, last_assistant_text)."""
    step = require_mapping(turn, f"trajectory turn {index}", where)
    events: list[dict[str, Any]] = []

    assistant_text = _pick(step, "assistant_text")
    text = assistant_text if isinstance(assistant_text, str) else None

    tool_name = _pick(step, "tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        # A turn with no tool call is a pure assistant message. That is a real
        # shape in a 9-turn trajectory and is not an error.
        return events, text

    span = f"sp-{sid}-{index}"
    start_data: dict[str, Any] = {"action": "invoke_tool"}
    args = _pick(step, "tool_args")
    if isinstance(args, dict) and args:
        start_data["tool_args"] = args

    events.append(cim_event(sid, ts, "tool_start", source=CORPUS,
                            tool=tool_name, span=span, **start_data))

    end_data: dict[str, Any] = {}
    feedback = _pick(step, "tool_result")
    if isinstance(feedback, str) and feedback:
        end_data["tool_result"] = feedback
    elif isinstance(feedback, dict | list) and feedback:
        end_data["tool_result"] = json.dumps(feedback, sort_keys=True)[:4000]

    events.append(cim_event(sid, ts + 0.4, "tool_end", source=CORPUS,
                            tool=tool_name, span=span, result="success",
                            **end_data))
    return events, text


def adapt_trajectory(record: Any, *, source_name: str = "<memory>"
                     ) -> AdaptedSession:
    """Map one ATBench trajectory into an :class:`AdaptedSession`."""
    rec = require_mapping(record, "a trajectory", source_name)

    raw_id = _pick(rec, "id")
    if raw_id is None:
        raise _missing(rec, "id", source_name)
    sid = safe_id(str(raw_id))

    label = _pick(rec, "label")
    if label is None:
        raise _missing(rec, "label", source_name)
    is_attack = _is_attack(label, f"{source_name}:{raw_id}")

    turns = _pick(rec, "trajectory")
    if not isinstance(turns, list) or not turns:
        raise _missing(rec, "trajectory", source_name)

    events: list[dict[str, Any]] = []
    ts = EPOCH

    request = _pick(rec, "user_request")
    if isinstance(request, str) and request:
        events.append(cim_event(sid, ts, "user_message", source=CORPUS,
                                user_message_text=request))
        ts += STEP_SECONDS

    last_text: str | None = None
    for index, turn in enumerate(turns):
        turn_events, text = _turn_events(turn, sid, index, ts,
                                         f"{source_name}:{raw_id}")
        events.extend(turn_events)
        if text:
            last_text = text
        ts += STEP_SECONDS

    notes: list[str] = []
    final = _pick(rec, "final_response")
    if not isinstance(final, str) or not final:
        final = last_text
        if final:
            notes.append(
                "final_response taken from the last assistant turn; no "
                "dedicated final-response field was present.")
    if isinstance(final, str) and final:
        events.append(cim_event(sid, ts, "model_response", source=CORPUS,
                                response_text=final))
    else:
        notes.append(
            "no final response text; CH02 will decline with "
            "NO_FINAL_RESPONSE_TEXT.")

    # ATBench carries no per-step provenance annotation, so unlike StepShield
    # there is not even an opt-in path to giving CH03 anything.
    absences = [*NO_CONTROL_PLANE, Absence(
        SURFACE_INJECTION_SCANNER,
        "ATBench runs no injection scanner and carries no per-step annotation "
        "marking content the agent did not author, so CH03 declines outright "
        "on this corpus.")]

    taxonomy = {k: _pick(rec, k) for k in ("risk_source", "failure_mode", "harm")}
    family = str(taxonomy.get("risk_source") or "unspecified")

    assert_no_fabricated_evidence(events, f"atbench:{raw_id}")

    return AdaptedSession(
        session_id=sid,
        events=tuple(events),
        is_attack=is_attack,
        # No documented pairing, so the task IS the session. The runner detects
        # this and reports the bootstrap as session-level. See the module
        # docstring for why that is a property of the corpus, not a shortcut.
        task_id=sid,
        family=safe_id(family),
        kind="unsafe" if is_attack else "safe",
        absences=AbsenceLedger(tuple(absences)),
        corpus=CORPUS,
        target_check="",
        notes=tuple(notes),
    )


def load_path(path: Path) -> list[AdaptedSession]:
    """Adapt ATBench from a JSON array or a JSONL file.

    Fails loudly when absent. The data is not vendored here and, given there is
    no licence, must not be.
    """
    path = Path(path)
    if not path.exists():
        raise AdapterError(
            f"ATBench data not found at {path}.\n"
            "This repository does not vendor the corpus, and ATBench publishes "
            "NO LICENCE -- there is no redistribution right to rely on. Fetch "
            "it yourself on a network that can reach huggingface.co:\n"
            "    from datasets import load_dataset\n"
            "    ds = load_dataset('AI45Research/ATBench', 'ATBench', "
            "split='test')\n"
            "    ds.to_json('atbench.jsonl')\n"
            "then point --atbench at that file. Confirm FIELD_MAP in this "
            "module matches the real key names before trusting any number.")

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise AdapterError(f"{path} is empty.")

    records: list[Any]
    if text.startswith("["):
        loaded = json.loads(text)
        if not isinstance(loaded, list):
            raise AdapterError(f"{path}: top-level JSON is not an array.")
        records = loaded
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]

    if not records:
        raise AdapterError(
            f"{path} contained no records. Scoring zero sessions would report a "
            "false-positive rate of zero over a corpus that was never read.")

    return [adapt_trajectory(r, source_name=f"{path}[{i}]")
            for i, r in enumerate(records)]
