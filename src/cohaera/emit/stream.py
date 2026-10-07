"""``StreamSigner``: the ``cohaera.integrity:1`` producer, one record at a time.

``tools/collector_sign.sign_stream`` is the reference for the bytes and it
takes a list, which is the right shape for a reference and the wrong shape for
a collector. A collector sees one record at a time, runs for weeks, and gets
restarted. This is the same arithmetic held as state:

    chain[0] = H(scheme || stream_id || key_id)
    chain[n] = H(chain[n-1] || H(canonical(record without "integrity")))
    sig      = Ed25519 over scheme || stream_id || seq || chain[n]

(``docs/EVIDENCE-TRUST.md`` section 2), imported from ``cohaera.evidence``
rather than restated, so the signer and the verifier cannot disagree about a
byte.

WHAT THE STATE IS, AND WHY A RESTART IS NOT A NEW STREAM. The verifier anchors
a stream at ``seq == 0`` by recomputing ``chain[0]``, and a stream that starts
anywhere else is ``INTEGRITY_STREAM_JOINED_MIDSTREAM``: covered from here,
attested before here by nobody. A collector that restarts and begins again at
zero does worse -- the ledger sees the same positions with a different head
and reports ``INTEGRITY_STREAM_FORKED``, which is the finding for a rewritten
history. So a restarted collector must continue: same stream id, next
sequence, the chain head it left off at. ``state()`` is those three numbers
and ``resume`` picks them up. Persist it after every record you have durably
written, or after every batch; where it goes is the caller's decision.

WHERE THIS RUNS. In the collector, after normalisation and before the record
leaves the host, and not in the agent process. The threat the chain closes is
a lying emitter, so a signer the emitter can reach closes nothing: the agent
signs whatever it chose to say, and CH06's coverage contract says so on every
session it evaluates. ``cohaera.ed25519.sign`` is also not constant-time; on a
shared host sign with libsodium and treat this module as the format.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import ed25519
from ..evidence import (
    CHAIN_HEX_CHARS,
    INTEGRITY_FIELD,
    INTEGRITY_SCHEMA,
    body_digest,
    chain_seed,
    chain_step,
    signing_input,
)
from ..validate import strict_json_loads
from ._fields import identity, require_strict_json

SIGNER_STATE_SCHEMA = "cohaera.signer_state:1"
MAX_STATE_BYTES = 65_536


class SignerStateError(ValueError):
    """The persisted state cannot continue a chain. Refuse; never restart at 0."""


class StreamClosedError(ValueError):
    """``sign`` was called on a signer that has signed a ``final`` record."""



def _rate(sign_every: Any) -> int:
    # R-05, verbatim from the reference signer. `seq % sign_every` accepted
    # anything an int could be: 0 emitted a stream nobody had attested and
    # reported success, -1 signed everything. A sampling rate must not be a
    # switch an operator flips by typing a number.
    if not isinstance(sign_every, int) or isinstance(sign_every, bool) \
            or sign_every < 1:
        raise ValueError(
            f"sign_every must be an integer >= 1, got {sign_every!r}. It is a "
            f"sampling rate, not a switch: 0 would emit a stream with no "
            f"signature on any record and report success.")
    return sign_every


def _hex_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != CHAIN_HEX_CHARS:
        raise SignerStateError(f"{name} must be {CHAIN_HEX_CHARS} hex characters")
    try:
        int(value, 16)
    except ValueError:
        raise SignerStateError(f"{name} is not hex") from None
    return value.lower()


class StreamSigner:
    """Attach a chained, signed sidecar to each record of one stream.

    One signer per stream, one key per signer. The chain seed binds the stream
    id to the key id, so a stream cannot change key without becoming a new
    stream; rotate keys by starting a new stream id under the new key.

    Thread-safe. Sequence allocation, the chain step and the signature are one
    critical section, because record n+1 cannot be chained until the head at n
    is known and two threads racing for a sequence number would produce two
    records at one position -- which the verifier reports as a replay.
    """

    def __init__(self, stream_id: str, private_key: bytes, key_id: str,
                 sign_every: int = 1, *, _next_seq: int = 0,
                 _head: str | None = None, _closed: bool = False) -> None:
        self._stream_id = identity(stream_id, "stream_id")
        self._key_id = identity(key_id, "key_id")
        if not isinstance(private_key, bytes) or len(private_key) != ed25519.KEY_BYTES:
            raise ValueError(f"private_key must be {ed25519.KEY_BYTES} bytes")
        self._secret = private_key
        self._sign_every = _rate(sign_every)
        self._next_seq = _next_seq
        self._head = _head if _head is not None else chain_seed(stream_id, key_id)
        self._closed = _closed
        self._lock = threading.Lock()

    # -- introspection ----------------------------------------------------

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def sign_every(self) -> int:
        return self._sign_every

    @property
    def next_seq(self) -> int:
        """The sequence number the next record will carry."""
        return self._next_seq

    @property
    def head(self) -> str:
        """The chain head after the last record signed; ``chain[0]`` before any."""
        return self._head

    @property
    def closed(self) -> bool:
        """Has a ``final`` record been signed? A closed signer signs nothing more."""
        return self._closed

    def __repr__(self) -> str:
        return (f"StreamSigner(stream_id={self._stream_id!r}, "
                f"key_id={self._key_id!r}, next_seq={self._next_seq})")

    # -- signing ----------------------------------------------------------

    def sign(self, record: Mapping[str, Any], *, attest: bool = False,
             final: bool = False) -> dict[str, Any]:
        """Return a copy of ``record`` with its ``integrity`` sidecar attached.

        The caller's mapping is never written to. The copy is shallow: nested
        values are shared, and the chain was computed over them as they are
        NOW, so a caller that mutates a nested value after signing and before
        writing has broken its own chain. Write what ``sign`` returns, and write
        it promptly.

        ``attest`` signs this record whatever the sampling rate says. A
        signature covers the chain head at its own sequence and nothing after
        it (R-05), so with ``sign_every > 1`` a stream whose last record fell
        between signing positions reports ``verified_prefix``, never
        ``verified_complete``. The reference signer always signs the last
        record of its list; an incremental signer cannot know which record is
        last, so the caller says -- at the end of each batch. With
        ``sign_every == 1`` the flag changes nothing.

        ``final`` CLOSES the stream (E30). The record is signed with the
        ``final`` marker in its signing input, so the verifier can tell a
        stream that ended from one that was cut off, and this signer refuses
        to sign anything further: the statement "nothing follows" is only
        worth signing if it is kept. Use it on shutdown, not at the end of
        each batch; a batch boundary is ``attest``.
        """
        if not isinstance(record, Mapping):
            raise TypeError(f"a record is a JSON object (dict), got "
                            f"{type(record).__name__}")
        if INTEGRITY_FIELD in record:
            raise ValueError(
                f"record already carries an {INTEGRITY_FIELD!r} field; it was "
                f"either signed twice or signed by somebody else, and signing "
                f"over it would discard that evidence rather than add to it")
        body = dict(record)
        require_strict_json(body)
        with self._lock:
            if self._closed:
                raise StreamClosedError(
                    f"stream {self._stream_id!r} was closed at seq "
                    f"{self._next_seq - 1}; a closed stream does not reopen. "
                    f"Start a new stream id for what follows")
            seq = self._next_seq
            prev = self._head
            head = chain_step(prev, body_digest(body))
            sidecar: dict[str, Any] = {
                "scheme": INTEGRITY_SCHEMA,
                "stream_id": self._stream_id,
                "seq": seq,
                "prev": prev,
                "chain": head,
            }
            if final:
                sidecar["final"] = True
            if final or attest or seq % self._sign_every == 0:
                sidecar["key_id"] = self._key_id
                sidecar["sig"] = base64.b64encode(
                    ed25519.sign(self._secret,
                                 signing_input(self._stream_id, seq, head, final=final))
                ).decode("ascii")
            self._head = head
            self._next_seq = seq + 1
            if final:
                self._closed = True
        return {**body, INTEGRITY_FIELD: sidecar}

    # -- persistence ------------------------------------------------------

    def state(self) -> dict[str, Any]:
        """What a restarted collector needs to continue this chain.

        Three facts and a schema tag. The private key is deliberately not in
        it, so the state can sit beside the output without extending the set
        of files that must be kept secret.
        """
        with self._lock:
            return {"scheme": SIGNER_STATE_SCHEMA, "stream_id": self._stream_id,
                    "key_id": self._key_id, "next_seq": self._next_seq,
                    "head": self._head, "closed": self._closed}

    @classmethod
    def resume(cls, state: Mapping[str, Any], private_key: bytes,
               key_id: str | None = None, sign_every: int = 1) -> StreamSigner:
        """Continue a chain from a ``state()`` object.

        Every field is checked, and a state that does not describe a chain is
        refused rather than repaired: the alternative to continuing correctly
        is starting at zero, which the ledger reports as a fork of the stream's
        own history. ``key_id``, when given, must be the one the state names --
        the chain seed binds the key id, so continuing under another key would
        produce records whose seed no verifier can recompute.
        """
        if not isinstance(state, Mapping):
            raise SignerStateError("state must be a JSON object")
        if state.get("scheme") != SIGNER_STATE_SCHEMA:
            raise SignerStateError(f"state is not a {SIGNER_STATE_SCHEMA} object")
        try:
            stream_id = identity(state.get("stream_id"), "state.stream_id")
            stored_key = identity(state.get("key_id"), "state.key_id")
        except ValueError as exc:
            raise SignerStateError(str(exc)) from None
        if key_id is not None and key_id != stored_key:
            raise SignerStateError(
                f"state was written under key {stored_key!r}, not {key_id!r}; "
                f"a stream cannot change key mid-chain. Rotate by starting a "
                f"new stream id under the new key")
        next_seq = state.get("next_seq")
        if isinstance(next_seq, bool) or not isinstance(next_seq, int) or next_seq < 0:
            raise SignerStateError("state.next_seq must be a non-negative integer")
        head = _hex_digest(state.get("head"), "state.head")
        if next_seq == 0 and head != chain_seed(stream_id, stored_key):
            raise SignerStateError(
                "state claims no record has been signed but its head is not "
                "chain[0] for this stream and key; the file is not this "
                "stream's state")
        closed = state.get("closed", False)
        if closed is not True and closed is not False:
            raise SignerStateError("state.closed must be true or false")
        return cls(stream_id, private_key, stored_key, sign_every,
                   _next_seq=next_seq, _head=head, _closed=closed)


def write_state(path: str | Path, state: Mapping[str, Any]) -> Path:
    """Persist a state object atomically: temp file, then ``os.replace``.

    Atomic because the state is read at the next startup, and a half-written
    file there means the collector either refuses to start or starts at zero.
    The first is a ticket; the second is a forked stream.
    """
    target = Path(path)
    parent = target.parent if str(target.parent) else Path()
    fd, tmp = tempfile.mkstemp(dir=str(parent) or ".", prefix=".signer-state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(state), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def read_state(path: str | Path) -> dict[str, Any]:
    """Load a state object. Parsed strictly; checked by ``StreamSigner.resume``."""
    target = Path(path)
    with target.open("rb") as handle:
        blob = handle.read(MAX_STATE_BYTES + 1)
    if len(blob) > MAX_STATE_BYTES:
        raise SignerStateError(f"{target}: larger than any signer state should be")
    try:
        state = strict_json_loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SignerStateError(f"{target}: not readable as UTF-8 JSON: {exc}") from exc
    if not isinstance(state, dict):
        raise SignerStateError(f"{target}: state must be a JSON object")
    return state
