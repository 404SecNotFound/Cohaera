"""Adapter for AgentDojo benchmark traces.

Source:  https://github.com/ethz-spylab/agentdojo
Licence: MIT (verified: ``LICENSE`` returns 200 at the pinned revision below,
         "Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic,
         Luca Beurer-Kellner, Marc Fischer, and Florian Tramer").

WHAT WAS ACTUALLY VERIFIED, AND WHAT WAS NOT
--------------------------------------------
Unlike ``atbench.py``, whose field names are guesses against data nobody here
could open, this adapter is written against AgentDojo's SOURCE, read directly at
a pinned revision. The trace schema below is not inferred from a README; it is
the literal ``json.dumps`` call in ``TraceLogger.save``.

Read at :data:`PINNED_REVISION`:

``src/agentdojo/logging.py``
    ``TraceLogger.save`` writes one JSON object per run to
    ``{logdir}/{pipeline_name}/{suite_name}/{user_task_id}/{attack_type}/{injection_task_id or 'none'}.json``
    with keys ``suite_name``, ``pipeline_name``, ``user_task_id``,
    ``injection_task_id``, ``attack_type``, ``injections``, ``messages``,
    ``error``, plus every other context argument -- which is where ``utility``,
    ``security``, ``duration``, ``evaluation_timestamp`` and
    ``agentdojo_package_version`` arrive.
``src/agentdojo/types.py``
    ``ChatUserMessage``, ``ChatAssistantMessage``, ``ChatToolResultMessage`` and
    ``ChatSystemMessage``. Note ``content`` is a LIST of content blocks
    (``text`` / ``thinking`` / ``redacted_thinking``), not a string. Older
    releases used a bare string, so both are accepted here.
``src/agentdojo/functions_runtime.py``
    ``FunctionCall`` is a pydantic model serialised by ``model_dump`` to
    ``{"function", "args", "id", "placeholder_args"}``.
``src/agentdojo/attacks/base_attacks.py``
    ``BaseAttack.attack`` returns ``dict[str, str]`` -- injection placeholder id
    to the injected text. This is the map that lands in ``injections``.

What was NOT verified: no real AgentDojo run directory has been scored by this
code. The fixtures under ``eval/external/fixtures/agentdojo/`` are synthetic,
hand-built to the schema above, and are labelled as such. They prove the adapter
parses what AgentDojo documents itself as writing; they prove nothing about a
real run.

THE LABEL, WHICH IS A THREE-WAY SPLIT AND NOT A TWO-WAY ONE
------------------------------------------------------------
This is the single most important decision in the file, and collapsing it is how
a wrong number gets produced with no visible error.

``security`` does NOT mean "this was an attack". Read ``benchmark.py``: it is the
OUTCOME, and ``security=True`` means the attack did not succeed. Three
populations therefore exist, not two:

``clean``
    ``attack_type`` is null and there is no injection task. Nothing attacker-
    authored is in the trajectory. This is the false-positive denominator.
``repelled``
    An injection was placed AND ``security`` is true: the attacker's content
    entered the trajectory, and the agent did the user's task anyway.
``compromised``
    An injection was placed AND ``security`` is false: the agent carried out the
    attacker's task.

``is_attack`` is set for ``compromised`` only. ``repelled`` is neither: there is
no deviant behaviour for a behavioural check to find, so scoring it as a missed
detection understates the detector, and scoring it as benign punishes the
detector for noticing genuinely attacker-authored content that is genuinely
there. The runner excludes it by default and PRINTS THE COUNT; ``--agentdojo-
include-repelled`` puts it back on the attack side for anyone who wants that
number. What does not happen is a silent choice.

ERRORED RUNS ARE REFUSED, AND THIS IS NOT FASTIDIOUSNESS
---------------------------------------------------------
``benchmark.py`` sets ``utility = False; security = True`` in three exception
handlers -- ``context_length_exceeded``, ``ApiError`` on an internal server
error, and ``ServerError`` -- and then saves the trace. A run that never
finished is therefore recorded as SECURE, with a truncated ``messages`` list.

Two things would go wrong if those traces were admitted. They would enter the
repelled or clean population as well-behaved sessions, and their truncation
would leave tool calls with no result message -- which is precisely the shape
CH05 fires on. The corpus would manufacture unpaired-call findings out of API
failures and Cohaera would report them as detections.

So a trace with a non-null ``error`` is skipped, counted, and the count is
returned. See :class:`LoadReport`.

THE SYNTHETIC CLOCK: ORDER IS REAL, DURATION IS NOT
----------------------------------------------------
AgentDojo records no per-message timestamp. It records ``duration`` for the whole
run and ``evaluation_timestamp`` for when the run started, and nothing else. So
per-event timestamps here are MANUFACTURED by this adapter, at a fixed step, and
that is a fabrication of a sort -- ``event_clock`` is one of Cohaera's evidence
surfaces.

The reason it is nonetheless admissible is narrow and worth stating exactly,
because the general claim would be false:

    The manufactured clock is a strictly monotone embedding of the message
    order, and the message order is real -- it is what AgentDojo appended. Every
    check in this engine that reads the clock reads it ONLY to order events; not
    one of them reads a duration or a gap. So ordering verdicts computed over
    the manufactured clock are the same verdicts that would be computed over a
    real one, and any statistic derived from the SPACING would not be.

That second half is load-bearing and is not left as prose:
``tests/test_external.py`` scores the fixtures twice with different step sizes
and asserts the findings are identical. The day somebody adds a check that reads
a gap, that test fails, and it fails before any external number is published
rather than after.

THE INJECTION MAP, WHICH IS BETTER EVIDENCE THAN STEPSHIELD'S LABEL
--------------------------------------------------------------------
CH03 needs injection-scanner evidence. No public corpus runs a scanner, and
writing ``has_injection_patterns`` from nothing is the exact fabrication
``base.py`` refuses.

AgentDojo carries something StepShield does not: ``injections`` holds the
literal attacker-authored strings that were placed into the environment. So the
question "did content the agent did not author reach this tool result" is
answerable HERE BY CONTAINMENT -- the injected string is either a substring of
the captured result or it is not. That is ground truth about provenance, checked
against the bytes, rather than an annotator's category.

It is still behind an opt-in (``mark_injected_content``, OFF by default) for a
reason that is not the same as StepShield's. StepShield's annotation is only
adjacent to a scanner's answer. AgentDojo's containment test is better than a
scanner's answer -- it is an ORACLE, and no production deployment has one. Using
it makes CH03 measurable and simultaneously makes the measurement an upper
bound on what a real scanner would supply. The runner records which way the flag
was set and the scope statement calls CH03 partial for this reason.

The asymmetry that keeps it honest: containment can only ever emit
``has_injection_patterns=True``. Absence of the injected string is NOT evidence
that a scanner ran and found nothing, so no negative is ever written -- which is
the fabrication that would buy CH03 coverage across the whole corpus.

WHAT MAPS, AND WHAT DOES NOT
-----------------------------
Maps:      user message -> user_message; assistant tool_calls -> tool_start with
           real arguments; tool result messages -> tool_end carrying the real
           returned content and the real error state; last assistant text ->
           model_response.
Absent:    policy events, approvals, integrity, receipts -- NO_CONTROL_PLANE, as
           for every public corpus. Tool reversibility is not declared, so it is
           omitted and Cohaera's name heuristic answers, degrading coverage
           honestly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
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

CORPUS = "agentdojo"

# The revision every schema claim in the module docstring was read at. Quoted
# rather than paraphrased: a claim about somebody else's code is worthless
# without the commit it was true at.
PINNED_REVISION = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"

# The three populations. See the module docstring -- this is a three-way split
# and the whole correctness of the reported rates depends on it staying one.
KIND_CLEAN = "clean"
KIND_REPELLED = "repelled"
KIND_COMPROMISED = "compromised"
KINDS = frozenset({KIND_CLEAN, KIND_REPELLED, KIND_COMPROMISED})

# One second per message, matching the other adapters so the corpora stay
# comparable. The value is arbitrary and MUST remain arbitrary: see the
# docstring's clock argument, and the test that scores at two different step
# sizes and demands identical findings.
STEP_SECONDS = 1.0
EPOCH = 1_760_000_000.0

# Positions WITHIN one message's step, as fractions of it rather than as
# absolute offsets. This is not tidiness. With absolute constants the marker and
# the tool_end escape their own step as soon as the step is smaller than the
# largest constant, and the event order -- the one thing the manufactured clock
# is supposed to preserve exactly -- silently changes with a parameter that is
# meant to be arbitrary. The clock-invariance test in tests/test_external.py
# caught precisely that at a 0.05s step.
MARKER_FRACTION = 0.3
RESULT_FRACTION = 0.4

# An injected string shorter than this is not used for containment: a short
# fragment matches ordinary text by coincidence, and a coincidental match would
# hand CH03 a marker on a result that carries nothing attacker-authored.
MIN_INJECTION_MATCH_CHARS = 24

# Captured tool results are truncated at this many characters before being
# written to the event. Cohaera's own limits bound what it will scan; this bound
# exists so an adapted event does not carry a megabyte of environment dump.
MAX_RESULT_CHARS = 8_000


# ---------------------------------------------------------------------------
# Content blocks
# ---------------------------------------------------------------------------


def message_text(content: Any) -> str:
    """Flatten a message's content to text, across both schema generations.

    Current AgentDojo carries ``list[MessageContentBlock]``; releases before the
    content-block change carried a bare string. Both appear in run directories
    that have been accumulated over time, so both are read. Anything else
    returns empty rather than raising, because a message shape this adapter does
    not recognise must not be able to take down a whole run directory -- the
    absence shows up as a missing final response, which the checks report.

    ``redacted_thinking`` blocks are skipped: their content is a provider
    placeholder, not model output, and including it would put a constant string
    into every response CH02 reads.
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
            continue
        if not isinstance(block, dict):
            continue
        if block.get("type") == "redacted_thinking":
            continue
        text = block.get("content")
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def _bool_field(record: dict[str, Any], key: str, where: str) -> bool:
    """Read a required boolean outcome, refusing to guess at anything else."""
    value = record.get(key)
    if isinstance(value, bool):
        return value
    raise AdapterError(
        f"{where}: {key!r} is {value!r}, not a boolean. AgentDojo writes it "
        f"via logger.set_contextarg({key!r}, ...) in benchmark.py, so a trace "
        "without it was not produced by benchmark_suite_with_injections and "
        "its population cannot be established. Refusing to guess: a trace in "
        "the wrong population moves every rate this harness reports.")


def classify(record: dict[str, Any], where: str) -> str:
    """Which of the three populations this trace belongs to.

    The injection is treated as PLACED when the trace names an injection task,
    not when ``injections`` happens to be non-empty -- an attack can legitimately
    produce no injection for a user task with no injection candidates, and that
    is still an attack run.
    """
    attack_type = record.get("attack_type")
    injection_task_id = record.get("injection_task_id")
    injected = bool(attack_type) or bool(injection_task_id)
    if not injected:
        return KIND_CLEAN
    if _bool_field(record, "security", where):
        return KIND_REPELLED
    return KIND_COMPROMISED


# ---------------------------------------------------------------------------
# One trace
# ---------------------------------------------------------------------------


def _injection_needles(record: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """The (placeholder, text) pairs long enough to test by containment."""
    injections = record.get("injections")
    if not isinstance(injections, dict):
        return ()
    return tuple(
        (str(key), value) for key, value in injections.items()
        if isinstance(value, str) and len(value) >= MIN_INJECTION_MATCH_CHARS)


def _result_text(message: dict[str, Any]) -> str:
    text = message_text(message.get("content"))
    return text[:MAX_RESULT_CHARS]


def _call_key(call: dict[str, Any]) -> str:
    """A stable identity for pairing an assistant's call with its result."""
    cid = call.get("id")
    if isinstance(cid, str) and cid:
        return cid
    function = call.get("function")
    return f"fn:{function}" if isinstance(function, str) else "fn:?"


def adapt_trace(record: Any, *, source_name: str = "<memory>",
                mark_injected_content: bool = False) -> AdaptedSession:
    """Map one AgentDojo trace file into an :class:`AdaptedSession`."""
    rec = require_mapping(record, "a trace", source_name)

    user_task_id = rec.get("user_task_id")
    if not isinstance(user_task_id, str) or not user_task_id:
        raise AdapterError(
            f"{source_name}: no 'user_task_id'. Every file TraceLogger.save "
            "writes carries one; a file without it is not an AgentDojo trace.")

    messages = rec.get("messages")
    if not isinstance(messages, list):
        raise AdapterError(
            f"{source_name}: 'messages' is {type(messages).__name__}, not a "
            "list. See TraceLogger.save at " + PINNED_REVISION + ".")

    kind = classify(rec, source_name)
    injection_task_id = rec.get("injection_task_id")
    suite = rec.get("suite_name")
    sid_parts = [str(suite or "suite"), user_task_id, str(rec.get("attack_type")
                                                          or "none"),
                 str(injection_task_id or "none")]
    sid = safe_id("-".join(sid_parts))

    needles = _injection_needles(rec) if mark_injected_content else ()

    events: list[dict[str, Any]] = []
    notes: list[str] = []
    ts = EPOCH
    scanner_marked_any = False
    open_calls: dict[str, tuple[str, str]] = {}   # key -> (span, tool name)
    last_assistant_text: str | None = None
    dangling_before_result = 0

    for index, raw in enumerate(messages):
        message = require_mapping(raw, f"message {index}", source_name)
        role = message.get("role")

        if role == "system":
            # The agent's own instructions. Not evidence about what it did, and
            # emitting it would put the system prompt into CH02's disclosure
            # matching, where it would read as the agent disclosing everything.
            continue

        if role == "user":
            text = message_text(message.get("content"))
            if text:
                events.append(cim_event(sid, ts, "user_message", source=CORPUS,
                                        user_message_text=text))
            ts += STEP_SECONDS
            continue

        if role == "assistant":
            text = message_text(message.get("content"))
            if text:
                last_assistant_text = text
            calls = message.get("tool_calls")
            if isinstance(calls, list):
                for offset, raw_call in enumerate(calls):
                    if not isinstance(raw_call, dict):
                        continue
                    function = raw_call.get("function")
                    if not isinstance(function, str) or not function:
                        continue
                    key = _call_key(raw_call)
                    span = f"sp-{sid}-{index}-{offset}"
                    start_data: dict[str, Any] = {"action": "invoke_tool"}
                    args = raw_call.get("args")
                    if isinstance(args, dict) and args:
                        # A genuine surface: Cohaera recomputes an argument
                        # digest from captured arguments. Nothing here binds to
                        # it -- no approval, no receipt -- but the digest is
                        # real and CH01's retry suppression reads it.
                        start_data["tool_args"] = args
                    events.append(cim_event(sid, ts, "tool_start", source=CORPUS,
                                            tool=function, span=span,
                                            **start_data))
                    open_calls[key] = (span, function)
            ts += STEP_SECONDS
            continue

        if role == "tool":
            raw_call = message.get("tool_call")
            call = raw_call if isinstance(raw_call, dict) else {}
            key = _call_key({"id": message.get("tool_call_id"),
                             "function": call.get("function")})
            span_and_name = open_calls.pop(key, None)
            if span_and_name is None:
                # A result with no start. Real AgentDojo does not produce this;
                # a truncated or hand-edited file can. Counted rather than
                # silently paired to the wrong call, because pairing it wrongly
                # would move a tool_end onto a different span and change what
                # CH05 sees.
                dangling_before_result += 1
                ts += STEP_SECONDS
                continue
            span, function = span_and_name

            text = _result_text(message)

            # The opt-in. Emitted BEFORE the tool_end that carries the content,
            # by a hair, so the marker's position in the order is the moment the
            # untrusted content arrived rather than the moment the call started.
            # CH03 orders consequential calls against this; putting it at the
            # tool_start would place the marker before content that had not
            # arrived yet.
            if needles and text:
                hits = [name for name, value in needles if value in text]
                if hits:
                    events.append(cim_event(
                        sid, ts + MARKER_FRACTION * STEP_SECONDS, "skill_invocation", source=CORPUS,
                        tool=function, action="invoke_tool",
                        # Placeholder NAMES only. The injected text itself is
                        # the attacker's prose and is already in tool_result;
                        # repeating it in a marker field would double-count it
                        # into any downstream content scan.
                        injection_patterns=[f"agentdojo_injection_{safe_id(h)}"
                                            for h in sorted(hits)],
                        has_injection_patterns=True))
                    scanner_marked_any = True

            end_data: dict[str, Any] = {}
            if text:
                end_data["tool_result"] = text
            error = message.get("error")
            # A real error state, carried rather than flattened. `result` is
            # what Cohaera reads to decide whether a call EXECUTED, and the
            # attempted/completed split in CH02 and CH03 turns on it.
            if isinstance(error, str) and error:
                end_data["error"] = error[:MAX_RESULT_CHARS]
                result = "error"
            else:
                result = "success"
            events.append(cim_event(sid, ts + RESULT_FRACTION * STEP_SECONDS,
                                    "tool_end", source=CORPUS,
                                    tool=function, span=span, result=result,
                                    **end_data))
            ts += STEP_SECONDS
            continue

        # An unrecognised role. Skipped and noted rather than guessed at.
        notes.append(f"message {index} has unrecognised role {role!r} and was "
                     "skipped.")
        ts += STEP_SECONDS

    if last_assistant_text:
        events.append(cim_event(sid, ts, "model_response", source=CORPUS,
                                response_text=last_assistant_text))
    else:
        notes.append("no assistant text in the trace, so no final response was "
                     "emitted; CH02 will decline with NO_FINAL_RESPONSE_TEXT.")

    if open_calls:
        # Calls the trace never returned a result for. Left unpaired, because
        # that IS what the file says, and reported because CH05's entire result
        # on this corpus depends on whether these are the agent's behaviour or
        # the corpus's truncation. A non-errored AgentDojo run should have none.
        notes.append(
            f"{len(open_calls)} tool call(s) have no result message. CH05 will "
            "count them as unpaired; on a trace with no 'error' this is the "
            "agent's behaviour, and on a truncated one it is an artefact -- "
            "which is why errored traces are refused at load time.")
    if dangling_before_result:
        notes.append(
            f"{dangling_before_result} tool result(s) had no matching call and "
            "were dropped rather than paired by guesswork.")

    notes.append(
        "per-event timestamps are synthesised at a fixed step: AgentDojo "
        "records only a run-level duration. The order is real; the spacing is "
        "not, and no check in this engine reads the spacing.")

    absences = [*NO_CONTROL_PLANE]
    if not scanner_marked_any:
        absences.append(Absence(
            SURFACE_INJECTION_SCANNER,
            "AgentDojo runs no injection scanner. No has_injection_patterns "
            "was emitted, so CH03 declines with NO_INJECTION_SCANNER_EVIDENCE "
            "rather than being handed a fabricated negative."))

    assert_no_fabricated_evidence(
        events, f"agentdojo:{sid}",
        sourced=frozenset({SURFACE_INJECTION_SCANNER}) if scanner_marked_any
        else frozenset())

    return AdaptedSession(
        session_id=sid,
        events=tuple(events),
        is_attack=kind == KIND_COMPROMISED,
        # A REAL task cluster, unlike ATBench. The same user_task_id is run
        # clean and under every injection task, so the bootstrap has genuine
        # within-task replication to resample and the task-disjoint split
        # actually prevents the clean rendering of a task from training a
        # baseline that is then tested on the attacked rendering of it.
        task_id=safe_id(f"{suite or 'suite'}-{user_task_id}"),
        family=safe_id(str(suite or "unspecified")),
        kind=kind,
        absences=AbsenceLedger(tuple(absences)),
        corpus=CORPUS,
        target_check="",
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Loading a run directory
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoadReport:
    """What a run directory yielded, including what it did NOT yield.

    Returned alongside the sessions rather than logged, for the same reason
    :class:`AbsenceLedger` is carried on a session: a caller that wants to know
    how many traces were refused must not have to re-derive it by counting.
    """

    sessions: tuple[AdaptedSession, ...] = ()
    files_seen: int = 0
    errored_skipped: int = 0
    unparsable_skipped: int = 0
    errored_files: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_seen": self.files_seen,
            "adapted": len(self.sessions),
            "errored_skipped": self.errored_skipped,
            "unparsable_skipped": self.unparsable_skipped,
            "kinds": {k: sum(1 for s in self.sessions if s.kind == k)
                      for k in sorted(KINDS)},
        }


def load_directory(root: Path, *, mark_injected_content: bool = False
                   ) -> LoadReport:
    """Adapt every trace under an AgentDojo ``runs`` directory.

    Walks recursively rather than assuming the
    ``{pipeline}/{suite}/{task}/{attack}/{injection}.json`` layout, because a
    user who has copied a subtree still has valid traces and the layout carries
    nothing this adapter needs -- every field it reads is inside the file.
    """
    root = Path(root)
    if not root.exists():
        raise AdapterError(
            f"AgentDojo traces not found at {root}.\n"
            "This repository vendors no benchmark data. AgentDojo is MIT "
            "licensed, so unlike ATBench its traces COULD be redistributed -- "
            "they are still not vendored here, because a number computed over "
            "a corpus frozen in this repository is a number about this "
            "repository. Produce traces yourself:\n"
            "    pip install agentdojo\n"
            "    python -m agentdojo.scripts.benchmark --logdir ./runs \\\n"
            "        -s workspace --model <model>\n"
            "then point --agentdojo at ./runs.")
    if not root.is_dir():
        raise AdapterError(f"{root} is not a directory.")

    sessions: list[AdaptedSession] = []
    errored: list[str] = []
    files_seen = 0
    unparsable = 0

    for path in sorted(root.rglob("*.json")):
        files_seen += 1
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            unparsable += 1
            continue
        if not isinstance(record, dict) or "messages" not in record:
            # Not a trace. Run directories accumulate other JSON.
            unparsable += 1
            continue

        # The refusal that keeps API failures out of the population. See the
        # module docstring: benchmark.py records a crashed run as secure.
        error = record.get("error")
        if isinstance(error, str) and error:
            errored.append(str(path.relative_to(root)))
            continue

        sessions.append(adapt_trace(
            record, source_name=str(path),
            mark_injected_content=mark_injected_content))

    if not sessions:
        raise AdapterError(
            f"{root} yielded no usable traces ({files_seen} JSON file(s) seen, "
            f"{len(errored)} skipped for a recorded error, {unparsable} "
            "unparsable). Scoring zero sessions would report a false-positive "
            "rate of zero over a corpus that was never read.")

    return LoadReport(
        sessions=tuple(sessions),
        files_seen=files_seen,
        errored_skipped=len(errored),
        unparsable_skipped=unparsable,
        errored_files=tuple(sorted(errored)),
    )
