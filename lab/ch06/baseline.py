#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Small independent verifier for the CH06 conformance matrix.

This module deliberately imports no Cohaera code.  It implements only the wire
contract needed by the lab: canonical JSON, sequence continuity, SHA-256 chain
recomputation, Ed25519 verification and a tiny in-memory replay ledger.  It is a
comparison, not a second implementation of Cohaera's coverage model.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

SCHEME = "cohaera.integrity:1"
SEPARATOR = b"\x1f"

# RFC 8032 / edwards25519 constants.  Affine arithmetic is intentionally small
# and slow: this verifier handles six-record fixtures, not hostile production
# input.  Keeping it here avoids sharing Cohaera's verifier with its baseline.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_BY = (4 * pow(5, _Q - 2, _Q)) % _Q


def _xrecover(y: int, sign: int = 0) -> int:
    xx = ((y * y - 1) * pow((_D * y * y + 1) % _Q, _Q - 2, _Q)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q:
        raise ValueError("point is not on edwards25519")
    if x & 1 != sign:
        x = _Q - x
    return x


_B = (_xrecover(_BY), _BY)
_IDENTITY = (0, 1)


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = (_D * x1 * x2 * y1 * y2) % _Q
    x3 = ((x1 * y2 + x2 * y1) * pow((1 + product) % _Q, _Q - 2, _Q)) % _Q
    y3 = ((y1 * y2 + x1 * x2) * pow((1 - product) % _Q, _Q - 2, _Q)) % _Q
    return x3, y3


def _multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("wrong point length")
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical point")
    point = (_xrecover(y, sign), y)
    if _encode_point(point) != encoded:
        raise ValueError("non-canonical point")
    return point


def _verify_ed25519(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    encoded_r, encoded_s = signature[:32], signature[32:]
    scalar_s = int.from_bytes(encoded_s, "little")
    if scalar_s >= _L:
        return False
    try:
        point_a = _decode_point(public)
        point_r = _decode_point(encoded_r)
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little",
    ) % _L
    return _multiply(_B, scalar_s) == _add(
        point_r, _multiply(point_a, challenge),
    )


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )


def _body_digest(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "integrity"}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


def _chain_seed(stream_id: str, key_id: str) -> str:
    digest = hashlib.sha256()
    for part in (SCHEME, stream_id, key_id):
        digest.update(part.encode())
        digest.update(SEPARATOR)
    return digest.hexdigest()


def _chain_step(previous: str, body_digest: str) -> str:
    digest = hashlib.sha256()
    digest.update(previous.encode())
    digest.update(SEPARATOR)
    digest.update(body_digest.encode())
    return digest.hexdigest()


def _signing_input(stream_id: str, seq: int, chain: str) -> bytes:
    return SEPARATOR.join((
        SCHEME.encode(), stream_id.encode(), str(seq).encode(), chain.encode(),
    ))


@dataclass(frozen=True)
class BaselineResult:
    status: str
    issues: tuple[str, ...]
    affected_sessions: tuple[str, ...]
    first_seq: int | None
    last_seq: int | None
    verified_to: int | None
    signatures_verified: int
    records_reordered: int

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["issues"] = list(self.issues)
        value["affected_sessions"] = list(self.affected_sessions)
        return value


def verify(records: list[dict[str, Any]], *, public_key: bytes | None,
           seen: dict[str, tuple[int, int, str]] | None = None) -> BaselineResult:
    """Verify one stream and return a deliberately small result contract."""
    sessions = tuple(sorted({
        str(record.get("session_id")) for record in records
        if isinstance(record.get("session_id"), str)
    }))
    rows: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    for record in records:
        sidecar = record.get("integrity")
        if (not isinstance(sidecar, dict)
                or sidecar.get("scheme") != SCHEME
                or not isinstance(sidecar.get("stream_id"), str)
                or not isinstance(sidecar.get("seq"), int)
                or isinstance(sidecar.get("seq"), bool)):
            return BaselineResult(
                "not_evaluated", ("unsupported_integrity",), (), None, None,
                None, 0, 0,
            )
        rows.append((sidecar["seq"], record, sidecar))

    if not rows:
        return BaselineResult(
            "not_evaluated", ("no_integrity",), (), None, None, None, 0, 0,
        )
    stream_ids = {sidecar["stream_id"] for _, _, sidecar in rows}
    if len(stream_ids) != 1:
        return BaselineResult(
            "not_evaluated", ("multiple_streams",), (), None, None, None, 0, 0,
        )
    stream_id = next(iter(stream_ids))

    reordered = 0
    furthest = -1
    for seq, _, _ in rows:
        if seq < furthest:
            reordered += 1
        furthest = max(furthest, seq)

    ordered = sorted(rows, key=lambda row: row[0])
    seqs = [row[0] for row in ordered]
    first_seq, last_seq = seqs[0], seqs[-1]
    issues: set[str] = set()
    affected: set[str] = set()

    if len(seqs) != len(set(seqs)):
        issues.add("sequence_replay")
        affected.update(sessions)

    key_id = next((
        sidecar.get("key_id") for _, _, sidecar in ordered
        if isinstance(sidecar.get("key_id"), str)
    ), "")
    head = (_chain_seed(stream_id, key_id) if first_seq == 0
            else str(ordered[0][2].get("prev") or ""))
    expected_seq = first_seq
    previous_session = ""
    verified_to: int | None = None
    signatures_verified = 0
    signature_present = False

    for seq, record, sidecar in ordered:
        session_id = (record.get("session_id")
                      if isinstance(record.get("session_id"), str) else "")
        if seq > expected_seq:
            issues.add("sequence_gap")
            affected.update(key for key in (previous_session, session_id) if key)
            # The missing records make the intervening head unknowable. Resume
            # from the survivor's declared predecessor, as the product does.
            head = str(sidecar.get("prev") or head)
        expected_seq = seq + 1

        prev = sidecar.get("prev")
        declared_chain = sidecar.get("chain")
        expected_chain = _chain_step(head, _body_digest(record)) if head else ""
        if not isinstance(prev, str) or not isinstance(declared_chain, str):
            issues.add("chain_metadata_missing")
            if session_id:
                affected.add(session_id)
        else:
            if prev != head or declared_chain != expected_chain:
                issues.add("chain_broken")
                affected.update(
                    key for key in (previous_session, session_id) if key
                )
        head = declared_chain if isinstance(declared_chain, str) else expected_chain
        previous_session = session_id

        signature_text = sidecar.get("sig")
        signature_key = sidecar.get("key_id")
        if isinstance(signature_text, str) and isinstance(signature_key, str):
            signature_present = True
            if public_key is not None and isinstance(declared_chain, str):
                try:
                    signature = base64.b64decode(signature_text, validate=True)
                except (binascii.Error, ValueError):
                    signature = b""
                if _verify_ed25519(
                        public_key,
                        _signing_input(stream_id, seq, declared_chain), signature):
                    signatures_verified += 1
                    verified_to = seq if verified_to is None else max(verified_to, seq)
                else:
                    issues.add("signature_invalid")
                    if session_id:
                        affected.add(session_id)

    fingerprint = (first_seq, last_seq, head)
    if seen is not None:
        previous = seen.get(stream_id)
        if previous == fingerprint:
            issues.add("stream_replayed")
            affected.update(sessions)
        elif previous is not None:
            issues.add("stream_forked")
            affected.update(sessions)
        else:
            seen[stream_id] = fingerprint

    inadmissible = {
        "sequence_replay", "sequence_gap", "chain_broken",
        "chain_metadata_missing", "signature_invalid", "stream_replayed",
        "stream_forked",
    }
    if issues & inadmissible:
        status = "replayed" if "stream_replayed" in issues else "inadmissible"
    elif public_key is None or not signature_present or signatures_verified == 0:
        status = "chained_unsigned"
    elif verified_to is not None and verified_to >= last_seq:
        status = "verified_complete"
    else:
        status = "verified_prefix"

    return BaselineResult(
        status=status,
        issues=tuple(sorted(issues)),
        affected_sessions=tuple(sorted(affected)),
        first_seq=first_seq,
        last_seq=last_seq,
        verified_to=verified_to,
        signatures_verified=signatures_verified,
        records_reordered=reordered,
    )
