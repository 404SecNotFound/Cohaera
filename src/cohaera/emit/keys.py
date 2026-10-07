"""Keys for the producer side: generate, store, and publish the public half.

A key is three things here and they travel separately:

    the seed        32 bytes from ``secrets``. Lives on the signing host, in a
                    file nobody else can read, and nowhere else.
    the key id      ``ed25519:`` plus the first 16 hex characters of the public
                    key. The same rule ``tools/collector_sign.key_id_for`` uses,
                    restated here because ``tools/`` is outside the package;
                    ``tests/test_emit.py`` asserts the two agree.
    the entry       the public key with its ``roles``, window and succession,
                    in the ``cohaera.trust_store:1`` shape the verifier loads.

ROLES ARE NOT A CONVENIENCE. ``docs/EVIDENCE-TRUST.md`` section 2 puts the
argument in one sentence: a key that signs telemetry AND the policy that
decides how telemetry is read has handed the watched thing authority over the
rules it is watched by. So an entry has no default role, and ``keygen`` makes
the operator say which.

THE SEED FILE IS MODE 0600 AND THE READER CHECKS. A private key readable by
the group or the world is a key somebody else may hold, and a signature made
with it proves nothing about who made it. ``read_private_key`` refuses such a
file rather than signing with it, because a refusal at startup is a ticket and
a quietly worthless signature is an incident.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import ed25519
from ..evidence import (
    COLLECTOR_KEYS_SCHEMA,
    TRUST_STORE_SCHEMA,
    VALID_ROLES,
    TrustStore,
    TrustStoreError,
)
from ..validate import strict_json_loads
from ._fields import identity, optional_finite, optional_identity

PRIVATE_KEY_SCHEMA = "cohaera.private_key:1"
PRIVATE_KEY_MODE = 0o600
# Generous for a document that is four short fields, and a bound rather than
# none because the file is read with the same care the verifier gives a store.
MAX_PRIVATE_KEY_BYTES = 65_536


class PrivateKeyError(ValueError):
    """The seed file cannot be used. Refuse it; never sign with a guess."""


def key_id_for(public: bytes) -> str:
    """``ed25519:`` plus the first 16 hex characters of the public key."""
    if len(public) != ed25519.KEY_BYTES:
        raise ValueError(f"public key must be {ed25519.KEY_BYTES} bytes, "
                         f"got {len(public)}")
    return "ed25519:" + public.hex()[:16]


@dataclass(frozen=True)
class KeyPair:
    """A seed, its public key, and the id the trust store will know it by.

    ``seed`` is excluded from ``repr`` so a key pair that reaches a log line or
    a traceback shows its id and not its secret.
    """

    seed: bytes = field(repr=False)
    public: bytes
    key_id: str

    @classmethod
    def generate(cls) -> KeyPair:
        return cls.from_seed(secrets.token_bytes(ed25519.KEY_BYTES))

    @classmethod
    def from_seed(cls, seed: bytes) -> KeyPair:
        if not isinstance(seed, bytes) or len(seed) != ed25519.KEY_BYTES:
            raise ValueError(f"seed must be {ed25519.KEY_BYTES} bytes")
        public = ed25519.public_key(seed)
        return cls(seed=seed, public=public, key_id=key_id_for(public))

    def trust_store_entry(self, *, roles: Iterable[str],
                          not_before: float | None = None,
                          not_after: float | None = None,
                          revoked_at: float | None = None,
                          replaces: str | None = None) -> dict[str, Any]:
        return trust_store_entry(self.public, roles=roles, not_before=not_before,
                                 not_after=not_after, revoked_at=revoked_at,
                                 replaces=replaces)


# ---------------------------------------------------------------------------
# The seed file
# ---------------------------------------------------------------------------


def write_private_key(path: str | Path, pair: KeyPair, *,
                      overwrite: bool = False) -> Path:
    """Write the seed as a small JSON document, mode 0600, created exclusively.

    Exclusive by default: overwriting a key file in place is a rotation nobody
    recorded, and the old key's signatures become unverifiable the moment the
    seed is gone. ``overwrite=True`` is for the operator who means it.

    The mode is applied by ``os.open`` at creation and again by ``fchmod`` on
    the descriptor, so an overwritten file does not keep a permissive mode it
    had before. On platforms without POSIX modes the bits are ignored, and the
    reader's check is skipped there for the same reason.
    """
    target = Path(path)
    document = {"scheme": PRIVATE_KEY_SCHEMA, "algorithm": "ed25519",
                "key_id": pair.key_id, "seed_hex": pair.seed.hex()}
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(target, flags, PRIVATE_KEY_MODE)
    except FileExistsError:
        raise PrivateKeyError(
            f"{target}: already exists; a key file is not overwritten "
            f"silently, pass overwrite=True to replace it") from None
    try:
        if os.name == "posix":
            os.fchmod(fd, PRIVATE_KEY_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
    except BaseException:
        # fdopen owns the descriptor once it returns; before that we do.
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return target


def read_private_key(path: str | Path, *, check_mode: bool = True) -> KeyPair:
    """Load a seed file, refusing one that is shared, malformed or inconsistent.

    The ``key_id`` written beside the seed is recomputed and compared. A
    mismatch means the file was edited or a seed was pasted in from somewhere
    else, and either way the trust store that names the old id will refuse
    every signature this seed makes.
    """
    target = Path(path)
    if check_mode and os.name == "posix":
        mode = stat.S_IMODE(target.stat().st_mode)
        if mode & 0o077:
            raise PrivateKeyError(
                f"{target}: mode {mode:04o} is readable by others; a private "
                f"key somebody else can read is a key somebody else may hold. "
                f"chmod 600 it, or pass check_mode=False if you have decided "
                f"that is acceptable")
    with target.open("rb") as handle:
        blob = handle.read(MAX_PRIVATE_KEY_BYTES + 1)
    if len(blob) > MAX_PRIVATE_KEY_BYTES:
        raise PrivateKeyError(f"{target}: larger than any key file should be")
    try:
        document = strict_json_loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PrivateKeyError(f"{target}: not readable as UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("scheme") != PRIVATE_KEY_SCHEMA:
        raise PrivateKeyError(f"{target}: not a {PRIVATE_KEY_SCHEMA} document")
    seed_hex = document.get("seed_hex")
    if not isinstance(seed_hex, str) or len(seed_hex) != ed25519.KEY_BYTES * 2:
        raise PrivateKeyError(f"{target}: 'seed_hex' must be {ed25519.KEY_BYTES * 2} "
                              f"hex characters")
    try:
        pair = KeyPair.from_seed(bytes.fromhex(seed_hex))
    except ValueError as exc:
        raise PrivateKeyError(f"{target}: 'seed_hex' is not hex: {exc}") from exc
    declared = document.get("key_id")
    if declared is not None and declared != pair.key_id:
        raise PrivateKeyError(
            f"{target}: declares key_id {declared!r} but its seed derives "
            f"{pair.key_id!r}; the file was edited or the seed is not the one "
            f"the trust store names")
    return pair


# ---------------------------------------------------------------------------
# The public half, in the shape the verifier loads
# ---------------------------------------------------------------------------


def trust_store_entry(public: bytes, *, roles: Iterable[str],
                      not_before: float | None = None,
                      not_after: float | None = None,
                      revoked_at: float | None = None,
                      replaces: str | None = None) -> dict[str, Any]:
    """One key's entry for a ``cohaera.trust_store:1`` document.

    Same shape as ``tools/policy_sign.store_document`` builds, with the same
    rule that ``roles`` has no default. The window fields are optional and a
    key with none of them never expires, which ``TrustedKey.open_ended`` reports
    and the verifier warns about once a successor appears.
    """
    if len(public) != ed25519.KEY_BYTES:
        raise ValueError(f"public key must be {ed25519.KEY_BYTES} bytes")
    if isinstance(roles, str):
        # "collector" iterates as nine one-character roles, every one of them
        # unknown, and the error that would produce is not the one the caller
        # made.
        roles = [roles]
    chosen = sorted(set(roles))
    if not chosen:
        raise ValueError("a key needs at least one role; a key with none is an "
                         "operator who has not decided what it is for")
    unknown = [r for r in chosen if r not in VALID_ROLES]
    if unknown:
        raise ValueError(f"unknown role(s) {unknown!r}; valid roles are "
                         f"{sorted(VALID_ROLES)}")
    entry: dict[str, Any] = {
        "key": base64.b64encode(public).decode("ascii"),
        "roles": chosen,
    }
    before = optional_finite(not_before, "not_before")
    after = optional_finite(not_after, "not_after")
    if before is not None and after is not None and before > after:
        raise ValueError(f"not_before={before} is after not_after={after}: no "
                         f"record could ever be inside that window")
    for name, value in (("not_before", before), ("not_after", after),
                        ("revoked_at", optional_finite(revoked_at, "revoked_at")),
                        ("replaces", optional_identity(replaces, "replaces"))):
        if value is not None:
            entry[name] = value
    return entry


def trust_store_document(keys: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """A ``cohaera.trust_store:1`` document, checked with the verifier's parser.

    ``TrustStore.from_obj`` is the oracle, not a reimplementation of its rules:
    if the verifier would refuse the file, this raises ``TrustStoreError`` with
    the verifier's own message, before anything is written.
    """
    document: dict[str, Any] = {
        "scheme": TRUST_STORE_SCHEMA,
        "keys": {identity(key_id, "key_id"): dict(entry)
                 for key_id, entry in keys.items()},
    }
    TrustStore.from_obj(document)
    return document


def add_key(document: Mapping[str, Any], key_id: str,
            entry: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of ``document`` with one more key, refusing to replace one.

    Two entries under one id is not a rotation, it is an overwrite of whatever
    the old entry said -- including a ``revoked_at`` -- so a duplicate is
    refused. Rotation is a NEW id with ``replaces`` naming the old one.

    A ``cohaera.collector_keys:1`` file cannot carry roles or windows and is
    refused rather than silently upgraded; the operator converts it once, on
    purpose, by rewriting it as a trust store.
    """
    scheme = document.get("scheme") if isinstance(document, Mapping) else None
    if scheme == COLLECTOR_KEYS_SCHEMA:
        raise TrustStoreError(
            f"{COLLECTOR_KEYS_SCHEMA} cannot carry roles or windows; rewrite it "
            f"as {TRUST_STORE_SCHEMA} before adding keys to it")
    if scheme != TRUST_STORE_SCHEMA:
        raise TrustStoreError(f"document is not a {TRUST_STORE_SCHEMA}")
    existing = document.get("keys")
    if not isinstance(existing, Mapping):
        raise TrustStoreError("document carries no 'keys' object")
    identity(key_id, "key_id")
    if key_id in existing:
        raise TrustStoreError(
            f"key {key_id!r} is already in the store; a key is rotated by "
            f"adding a new id with 'replaces', not by rewriting its entry")
    merged = {str(k): dict(v) for k, v in existing.items()}
    merged[key_id] = dict(entry)
    return trust_store_document(merged)
