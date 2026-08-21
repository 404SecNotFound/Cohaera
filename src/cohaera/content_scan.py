"""A second opinion on captured tool output, and nothing more than that.

WHAT THIS IS FOR, WHICH IS NARROWER THAN IT LOOKS
    CH03 orders injection markers against consequential calls. Every one of
    those markers is written by somebody else's scanner, running somewhere
    Cohaera cannot see, and CH03's detection ceiling is therefore set by that
    scanner's pattern list. EVASION.md E09 is the whole of that sentence: stay
    below the upstream regexes and CH03 has nothing to order.

    E09's remedy line said "scan tool_result inside Cohaera". Finding F-16 had
    already refused exactly that, and for a good reason: a detector that
    generates its own taint evidence is grading its own work, and a regex pass
    of Cohaera's own would be a fresh source of the same false confidence E09
    describes. Both statements are correct. They are about different things.

    So this module scans, and the scan is *tiered* the way effect receipts were
    tiered after CH07 issued a critical finding on a producer-written string.
    An upstream scanner answer is evidence about content, produced where the
    content arrived. A local pass is evidence about the SCANNER -- specifically,
    about whether its answer covered what was in front of it.

THE RULE THIS MODULE MUST NEVER BREAK
    Local markers are not taint evidence and may not behave like it:

      * ``scanner_marked`` does not consult this module, so CH03 cannot build a
        finding on it and no local hit ever produces one;
      * a local hit never moves CH03 off ``not_evaluated``, because a second
        opinion about content nobody scanned is not a scanner;
      * a local hit never raises a confidence and never adds a present surface.

    It may do exactly one thing: lower confidence and say why. That is the
    asymmetry E20 states in prose -- an in-band signal is safe to believe in the
    direction that costs the attacker something and unsafe in the direction that
    helps them -- applied to Cohaera's own output rather than the producer's. A
    local hit only ever costs Cohaera's verdict some claimed coverage. There is
    no arrangement of content that buys a session a cleaner report.

WHY A FALSE POSITIVE HERE IS CHEAP, AND WHY THAT IS THE POINT
    These patterns are lexical and will match benign text: a support article
    about phishing quotes the phishing. Because the only consequences are a
    lower coverage number and a remedy naming a call, the cost of being wrong
    is an operator reading one tool result. Compare the cost of being wrong in
    the direction F-16 refused, which is a critical finding manufactured from
    Cohaera's own regex. The patterns below are allowed to be imprecise
    precisely because of where their output is permitted to go.

RELATIONSHIP TO THE UPSTREAM LIST
    These are NOT observra's five patterns re-typed. A copy would agree with
    upstream everywhere and so could never report a disagreement, which is the
    only fact this module exists to produce. They target instruction-override
    and directive shapes near-miss to the ones a short list catches. That is a
    design intent, not a measured claim: nothing here has been evaluated against
    an independent corpus, and until it has, the honest description of this
    module is "a different regex list, whose disagreements are worth a look".
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .limits import DEFAULT_LIMITS, Limits

__all__ = ["LOCAL_MARKER_NAMES", "local_markers", "scan_text"]


# Each entry is (marker name, compiled pattern). Every pattern is linear: the
# only repetition that spans text is a bounded, negated character class, so
# there is no nesting for a crafted string to make expensive. The bound on the
# input itself is `Limits.max_scanned_result_chars`; both matter, because a
# regex that is linear in the input is still linear in an input the producer
# chooses the length of.
_NEAR = r"[^.\n]{0,60}"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # "ignore the above and ...", and the several dozen ways to write it that a
    # five-entry list does not enumerate.
    ("LOCAL_INSTRUCTION_OVERRIDE", re.compile(
        r"\b(?:ignore|disregard|forget|override|discard|bypass)\b" + _NEAR +
        r"\b(?:previous|prior|above|earlier|initial|original|foregoing|all)\b"
        + _NEAR +
        r"\b(?:instruction|directive|rule|prompt|guideline|command|order)s?\b",
        re.IGNORECASE)),
    # Re-assigning the agent's role is the other standard opener, and it does
    # not contain the word "instruction" at all.
    ("LOCAL_ROLE_REASSIGNMENT", re.compile(
        r"\b(?:you\s+are\s+now|from\s+now\s+on(?:,)?\s+you|act\s+as|"
        r"pretend\s+to\s+be|your\s+new\s+(?:role|task|objective|goal))\b",
        re.IGNORECASE)),
    # Asking the agent to recite its own configuration. The imperative form
    # only: a bare mention of the words "system prompt" is not a probe, and
    # matching one made every document ABOUT prompting into a marker.
    ("LOCAL_SYSTEM_PROMPT_PROBE", re.compile(
        r"\b(?:reveal|repeat|print|output|disclose|show|display|dump)\b"
        + _NEAR +
        r"\b(?:system\s+prompt|your\s+instructions|initial\s+prompt|"
        r"developer\s+message)\b",
        re.IGNORECASE)),
    # An instruction to move data out. This is the shape that matters most,
    # because it is the one that pairs with a consequential call.
    ("LOCAL_EXFIL_DIRECTIVE", re.compile(
        r"\b(?:send|email|e-mail|forward|upload|post|transmit|exfiltrate|"
        r"leak|share)\b" + _NEAR +
        r"\b(?:database|credential|password|secret|api[\s_-]?key|token|"
        r"customer\s+(?:list|data|record)|contact\s+list|private\s+key|"
        r"ssh\s+key)s?\b",
        re.IGNORECASE)),
    # A LOCAL_TOOL_DIRECTIVE pattern was written here and then removed. It
    # matched "call|invoke|run ... tool|function|api ... with|using", which is
    # a real injection shape and also the shape of every runbook, README and
    # support article ever written: "Step 3: run the diagnostic tool with the
    # --verbose flag" matched it. Tool output from a knowledge base is
    # PREDOMINANTLY technical documentation, so the pattern would have fired
    # more or less continuously on the exact corpus this module reads.
    #
    # It was dropped rather than tightened because its marginal value is near
    # zero: an injected tool directive that matters almost always carries an
    # override or an exfiltration shape as well, and those are matched above.
    # A pattern that fires on everything reports nothing, and a coverage
    # penalty an operator learns to ignore is worse than no penalty.
    # Content that is trying not to be read by a human: HTML comments, zero
    # width characters, and CSS that hides the element. The marker is the
    # concealment, independent of what is concealed.
    ("LOCAL_HIDDEN_TEXT", re.compile(
        r"<!--" + _NEAR + r"(?:ignore|instruction|system|prompt)|"
        r"[\u200b\u200c\u200d\u2060\ufeff]|"
        r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0",
        re.IGNORECASE)),
)

#: Every name this module can produce. Prefixed ``LOCAL_`` without exception,
#: so that a marker in a verdict is attributable to its origin by reading it --
#: an upstream ``INSTRUCTION_OVERRIDE`` and a local ``LOCAL_INSTRUCTION_OVERRIDE``
#: are different claims with different standing and must never be confusable in
#: an evidence blob, a Sigma rule or an analyst's eye.
LOCAL_MARKER_NAMES: tuple[str, ...] = tuple(name for name, _ in _PATTERNS)


def scan_text(value: Any, limits: Limits = DEFAULT_LIMITS) -> tuple[str, ...]:
    """Names of the local patterns matching ``value``, in declaration order.

    Anything that is not a non-empty string scans as no markers at all. This is
    the ``validate`` doctrine and not a shortcut: a ``tool_result`` that arrived
    as a dict is a defect already recorded on the record, and inventing a string
    for it here would be coercion of exactly the kind rule 3 forbids.

    Over-long content is scanned to ``max_scanned_result_chars`` and no further.
    A truncated scan can miss a marker past the bound, which is a false negative
    in a module whose output can only lower a confidence -- so the failure mode
    of the bound is that Cohaera says nothing, never that it says something
    wrong.
    """
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        return ()
    text = value[:limits.max_scanned_result_chars]
    return tuple(name for name, pattern in _PATTERNS if pattern.search(text))


def local_markers(data: Any, limits: Limits = DEFAULT_LIMITS) -> tuple[str, ...]:
    """Scan the ``tool_result`` of one event's ``data`` mapping.

    Only ``tool_result``. Not ``response_text``, which is the agent's own words
    and CH02's surface; not ``tool_args``, which the agent wrote. This module
    reads the one channel that carries content from outside the agent, because
    that is the channel E09 is about.
    """
    if not isinstance(data, Mapping):
        return ()
    return scan_text(data.get("tool_result"), limits)
