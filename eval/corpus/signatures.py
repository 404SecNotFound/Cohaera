"""A content-addressed cache for the evaluation corpus's Ed25519 signatures.

WHY THIS EXISTS. ``src/cohaera/ed25519.py`` is pure Python by design -- Cohaera
has zero runtime dependencies, and a detector that needs a C extension to verify
its own evidence cannot run where this one is meant to run. The cost is about
5 ms per scalar multiplication, and the corpus's second collector stream signs
2160 records per condition at two multiplications each. That is roughly nine
seconds of signing inside every call to :func:`eval.corpus.generate.generate`,
and ``tests/test_eval.py`` calls it once per test. Before this cache the suite
spent well over half its wall clock re-deriving signatures it had already
derived, byte for byte, moments earlier.

WHAT IT DOES NOT SPEED UP, ON PURPOSE. Verification. Every signature Cohaera
checks while scoring the corpus is checked the slow way, through the same code
path a deployment uses, because the point of the evaluation is to measure that
path. This cache sits on the *producer* side -- the synthetic collector -- which
in a real deployment is not Cohaera's code at all.

WHY IT CANNOT LIE. The key is ``sha256(key_id || 0x00 || message)`` and the
value is the signature over exactly that message under exactly that key. There
is no version, no timestamp and no notion of staleness, because there is nothing
for the cache to be stale *about*: change the corpus and the chain head changes,
which changes the message, which changes the key, which misses. A cache that can
only be addressed by its own content cannot hand back an answer to a different
question.

That leaves one failure mode -- a corrupted or hand-edited file serving a wrong
signature for a right key. Two things bound it. The file carries a digest over
its own entries and is discarded whole on mismatch, which catches truncation and
accidental damage. And a wrong signature does not produce a quiet pass: the
corpus fails its own verification, ``attack_revoked_key_stream`` and
``benign_hard_rotated_key`` stop behaving as labelled, and the CI job that
regenerates the corpus and diffs the evaluation card fails. The cache is
gitignored local state; anyone able to poison it can edit the generator instead.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

from cohaera import ed25519

CACHE_SCHEMA = "cohaera.eval.sigcache:1"

#: Beside the generated corpus and deliberately NOT inside it. ``data/`` holds
#: corpus artefacts and ``eval/run_eval.py`` digests that directory to name the
#: card's inputs; a cache file in there changed the corpus digest, which made the
#: card depend on whether the cache had been enabled. The cache is derived state
#: about the generator, not part of what the generator produced.
DEFAULT_PATH = Path(__file__).resolve().parent / ".signature-cache.json"

#: Point at another file, or set it to ``0``/``off`` to sign everything the slow
#: way. The uncached path has to stay reachable or "the cache agrees with real
#: signing" becomes an assertion nothing can test.
ENV_PATH = "COHAERA_EVAL_SIGCACHE"


def _entries_digest(entries: dict[str, str]) -> str:
    h = hashlib.sha256()
    for key in sorted(entries):
        h.update(key.encode("ascii"))
        h.update(b" ")
        h.update(entries[key].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def resolve_path() -> Path | None:
    """The cache file to use, or ``None`` when caching to disk is off."""
    raw = os.environ.get(ENV_PATH)
    if raw is None:
        return DEFAULT_PATH
    if raw.strip().lower() in {"", "0", "off", "no", "none"}:
        return None
    return Path(raw).expanduser()


class SignatureCache:
    """Memoised :func:`cohaera.ed25519.sign`, addressed by what it signed.

    In-process first: a dict, which is where nearly all of the saving comes
    from, because one pytest process generates the same corpus dozens of times.
    Then on disk, which buys the first generation of each new process.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.hits = 0
        self.misses = 0
        self._entries: dict[str, str] = {}
        self._loaded = path is None
        self._dirty = False

    # -- addressing ------------------------------------------------------

    @staticmethod
    def key(key_id: str, message: bytes) -> str:
        """``sha256(key_id || 0x00 || message)``.

        The separator matters: without it a key id ending in the first byte of
        one message would collide with a shorter id and a longer message. Key
        ids are hex and messages are unit-separated text, so the collision is
        not reachable in this corpus -- and relying on that is how a cache
        acquires a bug that only appears when somebody renames a key.
        """
        digest = hashlib.sha256()
        digest.update(key_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(message)
        return digest.hexdigest()

    # -- the one operation -----------------------------------------------

    def sign(self, secret: bytes, key_id: str, message: bytes) -> bytes:
        """The signature over ``message`` under the key named ``key_id``.

        ``secret`` is used only on a miss and is never stored or hashed into the
        address. The public key id names the key; the seed stays in the caller.
        """
        if not self._loaded:
            self.load()
        address = self.key(key_id, message)
        cached = self._entries.get(address)
        if cached is not None:
            self.hits += 1
            return base64.b64decode(cached)
        self.misses += 1
        signature = ed25519.sign(secret, message)
        self._entries[address] = base64.b64encode(signature).decode("ascii")
        self._dirty = True
        return signature

    # -- persistence -----------------------------------------------------

    def load(self) -> None:
        """Read the cache file, or start empty.

        Every way of failing to read it is the same outcome -- an empty cache
        and a slow run -- because a cache is an optimisation and an optimisation
        that can abort a test run is a liability. The one thing not tolerated is
        a file whose recorded digest does not match its entries: that is
        discarded rather than partially trusted.
        """
        self._loaded = True
        if self.path is None:
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            return
        if not isinstance(doc, dict) or doc.get("scheme") != CACHE_SCHEMA:
            return
        entries = doc.get("signatures")
        if not isinstance(entries, dict):
            return
        entries = {k: v for k, v in entries.items()
                   if isinstance(k, str) and isinstance(v, str)}
        if doc.get("digest") != _entries_digest(entries):
            return
        self._entries.update(entries)

    def save(self) -> None:
        """Write the cache back, merging whatever another process added.

        Merge rather than overwrite because two pytest runs in two terminals is
        an ordinary thing to do, and a last-writer-wins cache would throw away
        the other one's work silently. Entries are content-addressed, so a merge
        cannot produce a conflict -- the same address always means the same
        signature.
        """
        if self.path is None or not self._dirty:
            return
        merged = dict(self._entries)
        disk = SignatureCache(self.path)
        disk._entries = {}
        disk.load()
        for address, signature in disk._entries.items():
            merged.setdefault(address, signature)
        doc = {
            "scheme": CACHE_SCHEMA,
            "digest": _entries_digest(merged),
            "signatures": dict(sorted(merged.items())),
            "_note": ("Derived, gitignored, and safe to delete: regenerated by "
                      "eval/corpus/generate.py. See eval/corpus/signatures.py "
                      "for why a stale entry is not a thing that exists."),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle, temp = tempfile.mkstemp(dir=str(self.path.parent),
                                            prefix=".sigcache-")
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as out:
                    json.dump(doc, out, separators=(",", ":"))
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temp, self.path)
            except BaseException:
                try:
                    os.unlink(temp)
                except OSError:                         # pragma: no cover
                    pass
                raise
        except OSError:
            # A read-only checkout, a full disk, a sandbox. All of them mean
            # "no cache next time", none of them mean "fail the corpus".
            return
        self._entries = merged
        self._dirty = False

    # -- reporting -------------------------------------------------------

    def summary(self) -> str:
        total = self.hits + self.misses
        if not total:
            return "signature cache: unused"
        where = "memory only" if self.path is None else str(self.path)
        return (f"signature cache: {self.hits}/{total} hit "
                f"({self.misses} signed, {where})")
