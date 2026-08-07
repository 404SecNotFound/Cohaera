"""Correlation keys and stable record identity.

Two problems live here, and they are the same problem seen from two ends.

CORRELATION KEY MANIPULATION (SEC-04, BUG-06, BUG-07)
    Cohaera groups events into sessions using a key the observed system
    supplies. When that key is absent the old code invented one, and the
    invented one had two faults. It embedded ``repr()`` of the host, user, agent
    and framework directly into ``session_id``, which is then emitted to a SIEM,
    so a field explicitly described as anonymous leaked the identity it was
    standing in for. And when EVERY identity field was absent it still bucketed
    by time, so two entirely unrelated records merged into one session on the
    strength of having happened within five minutes of each other. A correlation
    the data cannot support manufactures findings.

RECORD IDENTITY (SEC-06)
    Verdicts carried no stable identifier, so a SIEM retry, a re-analysis, a
    duplicated input file and a hostile replay were indistinguishable. Every
    identifier minted here is a CONTENT digest rather than a counter or a clock,
    which gives the property that actually matters downstream: scoring the same
    input under the same configuration twice produces byte-identical IDs, so a
    duplicate is recognisable as a duplicate, while any change to the input,
    the bounds, the baseline or the detector version produces a different ID.

Nothing here is a substitute for the collector-side signing described in the
review's F6. A digest computed by Cohaera proves that Cohaera saw this input; it
proves nothing about whether the input was truthful. That gap is E13 and it is
not closable at this layer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .limits import DEFAULT_LIMITS, Limits
from .validate import RecordView, json_safe

ANON_WINDOW_S = 300.0

KEY_VERSION_HMAC = "hmac-sha256-v1"
KEY_VERSION_DIGEST = "sha256-unkeyed-v1"

# What kind of evidence the session grouping rests on, and how much a verdict
# built on it should be believed. These are not measured probabilities. They are
# an ordering, so that a check cannot report full confidence on a session that
# was assembled out of guesswork.
KIND_SESSION_ID = "session_id"
KIND_TRACE_ID = "trace_id"
KIND_SCOPED_ANON = "scoped_anonymous"
KIND_ISOLATED_ANON = "isolated_anonymous"

CORRELATION_CONFIDENCE = {
    KIND_SESSION_ID: 1.0,
    KIND_TRACE_ID: 0.9,
    KIND_SCOPED_ANON: 0.3,
    KIND_ISOLATED_ANON: 0.0,
}


def canonical(obj: Any) -> str:
    """Deterministic JSON for hashing. Sorted keys, no whitespace, no NaN.

    Coerced through ``json_safe`` first. Everything hashed here is or contains
    producer-controlled structure, so a raw ``json.dumps(allow_nan=False)`` on
    it raises ValueError the moment a record carries ``duration_ms: Infinity``
    -- which is the very fault this hardening pass exists to remove, reappearing
    one layer down in the code that computes the record's own identity.
    """
    return json.dumps(json_safe(obj), sort_keys=True, separators=(",", ":"),
                      default=repr, allow_nan=False)


def digest(obj: Any, length: int = 32) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()[:length]


@dataclass(frozen=True)
class CorrelationKey:
    """The session key, and an honest label for where it came from."""

    value: str
    kind: str
    key_version: str
    keyed: bool

    @property
    def confidence(self) -> float:
        return CORRELATION_CONFIDENCE.get(self.kind, 0.0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "key_version": self.key_version,
            "keyed": self.keyed,
        }


class Correlator:
    """Assigns a session key to each record.

    ``secret`` should come from the deployment, not from the telemetry. With a
    secret the anonymous keys are HMACs and the identity behind them cannot be
    recovered or brute-forced from the SIEM copy. Without one they are plain
    digests: still unlinkable to a casual reader, but a short identity space
    (a few thousand hostnames) is trivially enumerable, so the key version says
    ``unkeyed`` and ``keyed`` is False. An operator who cares can then see from
    the record itself which of the two they are looking at, instead of assuming.
    """

    def __init__(self, secret: bytes | None = None,
                 window_s: float = ANON_WINDOW_S,
                 limits: Limits = DEFAULT_LIMITS) -> None:
        self._secret = secret or None
        self._window = window_s
        self._limits = limits
        self._window_start: dict[str, float] = {}
        self._ordinal = 0

    @property
    def keyed(self) -> bool:
        return self._secret is not None

    @property
    def key_version(self) -> str:
        return KEY_VERSION_HMAC if self._secret else KEY_VERSION_DIGEST

    def _mac(self, *parts: str) -> str:
        # \x1f between fields so host "a|b" + user "c" cannot collide with
        # host "a" + user "b|c". The separator cannot appear in a JSON-decoded
        # identity that survived validation without being visible as a defect.
        blob = "\x1f".join(parts).encode("utf-8")
        if self._secret:
            return hmac.new(self._secret, blob, hashlib.sha256).hexdigest()[:32]
        return hashlib.sha256(blob).hexdigest()[:32]

    def _isolate(self, raw_digest: Callable[[], str] | str) -> CorrelationKey:
        """A key that cannot collide with any other record's, by construction.

        Used wherever the data does not support a merge. The ordinal makes it
        unique even for two byte-identical records, because two identical
        records with nothing to correlate on are still two records.
        """
        self._ordinal += 1
        content = raw_digest() if callable(raw_digest) else raw_digest
        token = self._mac("isolated", content, str(self._ordinal))
        return CorrelationKey(f"anon-iso-{token}", KIND_ISOLATED_ANON,
                              self.key_version, self.keyed)

    def key_for(self, rv: RecordView,
                raw_digest: Callable[[], str] | str = "") -> CorrelationKey:
        """Return the session key for one validated record.

        Precedence: a producer-supplied session_id, then trace_id, then a
        scoped anonymous bucket, then isolation.

        ``raw_digest`` may be a callable. Only the isolation branch needs a
        content hash of the record, and hashing every record to build a key that
        is thrown away for the 99% case that carries a session_id costs a full
        JSON serialisation per event. Deferring it kept assembly of 64,000
        events at 0.26s instead of 0.65s.
        """
        if rv.session_key:
            return CorrelationKey(rv.session_key, KIND_SESSION_ID,
                                  "producer-supplied", False)
        if rv.trace_key:
            return CorrelationKey(rv.trace_key, KIND_TRACE_ID,
                                  "producer-supplied", False)

        ident = (rv.host, rv.user, rv.agent_name, rv.framework)
        if not any(ident):
            # BUG-06. No session, no trace, no host, no user, no agent, no
            # framework: there is no identity here for a merge to rest on, and
            # bucketing by clock alone joins records that have nothing in common
            # except arrival time. Isolate the record instead. A single-event
            # session produces no cross-event finding, which is the correct
            # outcome: the data does not support one.
            return self._isolate(raw_digest)

        if rv.ts != rv.ts:                       # NaN: no usable clock
            # C4-03, and the same fault as BUG-06 seen from the other side. A
            # scoped anonymous key is identity PLUS a time window; the window is
            # what stops every record a host ever emitted from collapsing into
            # one session. With an unparseable clock there is no window, and the
            # old key ``anon-<scope>-noclock`` was a single bucket that every
            # clockless record for that scope fell into, for the whole run. Two
            # unrelated events an hour apart merged, and the merged session then
            # supported cross-event findings that the data never justified.
            #
            # An invalid timestamp is producer-controlled, so this was reachable
            # on purpose: send two records with the same host and a junk clock
            # and they correlate. Isolation is the honest key -- identity alone
            # is not a session.
            return self._isolate(raw_digest)

        scope = self._mac(*(f"{k}={v or ''}" for k, v in
                            zip(("host", "user", "agent", "fw"), ident,
                                strict=True)))
        start = self._window_start.get(scope)
        if start is None or rv.ts - start > self._window:
            self._window_start[scope] = rv.ts
            start = rv.ts
        bucket = int(start // self._window) if self._window else 0
        return CorrelationKey(f"anon-{scope}-w{bucket}", KIND_SCOPED_ANON,
                              self.key_version, self.keyed)


# ---------------------------------------------------------------------------
# Stable analysis identity
# ---------------------------------------------------------------------------


def run_id(*, detector_version: str, config_hash: str, source: str,
           input_digest: str, baseline_hash: str = "",
           manifest_hash: str = "") -> str:
    """Identify one scoring run by everything that could change its output.

    Deterministic on purpose. Re-scoring the same file with the same detector,
    the same bounds, the same baseline and the same capability manifest is the
    same run and should be recognisable as a duplicate rather than counted
    twice. Change any input and the ID changes, so a re-analysis after a
    baseline update is visibly a different run.

    ``manifest_hash`` is the manifest's FILE digest, not its semantic one, and
    that is not an oversight. A run ID is the strict identity of a
    configuration: the semantic digest cannot move without the file digest
    moving too, so folding it in would add no distinguishing power, while
    dropping the file digest in its favour would make a reformat -- or an edit
    to a field this version does not parse -- invisible in the run's identity.
    Both digests still travel in the verdict's provenance block, where the gap
    between them is readable (C4-10).
    """
    return digest({
        "detector_version": detector_version, "config_hash": config_hash,
        "source": source, "input_digest": input_digest,
        "baseline_hash": baseline_hash, "manifest_hash": manifest_hash,
    }, 24)


def verdict_id(*, run: str, session_id: str, findings_digest: str,
               session_digest: str = "", coverage_digest: str = "",
               schema: str = "") -> str:
    """Identify one session verdict within one run.

    Commits to the EVIDENCE as well as the conclusion. Hashing only
    (run, session, findings) meant two sessions with different events but
    matching findings collided, and a SIEM deduplicating on verdict_id would
    discard the second as a retry (C4-01).
    """
    return digest({"run": run, "session": session_id,
                   "findings": findings_digest, "events": session_digest,
                   "coverage": coverage_digest, "schema": schema}, 32)
