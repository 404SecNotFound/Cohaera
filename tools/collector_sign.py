#!/usr/bin/env python3
"""Reference collector-side signer for ``cohaera.integrity:1``.

    python tools/collector_sign.py --in raw.jsonl --out signed.jsonl \
        --secret-hex <64 hex chars> --keys-out keys.json
    python tools/collector_sign.py --gen-key

WHY THIS IS A TOOL AND NOT A LIBRARY
-------------------------------------
Cohaera VERIFIES integrity evidence; it never produces any. That separation is
deliberate and it is the point of the whole mechanism: a verifier that could
also sign would be a verifier whose attestations prove nothing, since the thing
checking the evidence could have written it. Everything in ``src/cohaera`` is
therefore verify-only, and the signing half lives here, outside the package.

It exists because somebody has to emit this. A wire format with no reference
producer is a specification nobody can implement against, and the first
question an observra maintainer will ask is "show me the bytes". This is the
bytes -- about eighty lines, all of it the format and none of it clever.

WHERE THIS BELONGS IN A REAL DEPLOYMENT
---------------------------------------
Inside the collector, after normalisation, before the record leaves the host,
and NOT inside the agent process. The threat this closes is a lying emitter, so
a signer the emitter can reach closes nothing: it moves the forgery from "write
whatever you like" to "write whatever you like and sign it". If your adapter
runs in-process with the agent, adopting this format buys you tamper-evidence
in transit and nothing at all against the agent itself, and Cohaera's coverage
contract will say so rather than let you believe otherwise.

THE SECRET
----------
``--secret-hex`` takes a 32-byte seed as hex, and ``--gen-key`` mints one from
``secrets.token_bytes``. The signing implementation in ``cohaera.ed25519`` is
NOT constant-time. For a real collector on a shared host, use libsodium and
treat this file as the format reference rather than the implementation.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera import ed25519
from cohaera.evidence import (
    INTEGRITY_FIELD,
    INTEGRITY_SCHEMA,
    ROLE_COLLECTOR,
    TRUST_STORE_SCHEMA,
    body_digest,
    chain_seed,
    chain_step,
    signing_input,
)


def sign_stream(records: list[dict], stream_id: str, secret: bytes,
                key_id: str, sign_every: int = 1) -> list[dict]:
    """Add an ``integrity`` sidecar to each record, chained and signed.

    ``sign_every`` exists because the signature covers the CHAIN HEAD rather
    than the record, so one verified signature covers every record before it.
    A collector under load can sign every hundredth record and a verifier
    cannot tell the difference in what it establishes -- only in how much
    scalar multiplication it does. Signing every record is the default because
    it is the easiest thing to reason about, not because it is required.
    """
    head = chain_seed(stream_id, key_id)
    out = []
    for seq, record in enumerate(records):
        body = {k: v for k, v in record.items() if k != INTEGRITY_FIELD}
        prev = head
        head = chain_step(prev, body_digest(body))
        sidecar = {
            "scheme": INTEGRITY_SCHEMA,
            "stream_id": stream_id,
            "seq": seq,
            "prev": prev,
            "chain": head,
        }
        if sign_every and seq % sign_every == 0:
            sidecar["key_id"] = key_id
            sidecar["sig"] = base64.b64encode(
                ed25519.sign(secret, signing_input(stream_id, seq, head))
            ).decode("ascii")
        out.append({**body, INTEGRITY_FIELD: sidecar})
    return out


def key_id_for(public: bytes) -> str:
    return "ed25519:" + public.hex()[:16]


def keys_document(public: bytes, key_id: str, not_before: float | None = None,
                  not_after: float | None = None,
                  replaces: str | None = None) -> dict:
    """A ``cohaera.trust_store:1`` document naming this key as a COLLECTOR key.

    Deliberately not the ``policy`` role. This key lives on the collector host,
    and a collector that could also sign the capability manifest could rewrite
    the document that says which of its own tools are consequential. Use
    ``tools/policy_sign.py``, with a different key, for that.

    The window fields are optional and unset by default, which produces a key
    that never expires -- honest for a first deployment, and the thing to fix
    second. Set ``--not-after`` on the outgoing key and ``--not-before`` on its
    replacement and the rotation exists in the verifier rather than only in
    somebody's runbook.
    """
    entry: dict[str, object] = {
        "key": base64.b64encode(public).decode("ascii"),
        "roles": [ROLE_COLLECTOR],
    }
    for name, value in (("not_before", not_before), ("not_after", not_after),
                        ("replaces", replaces)):
        if value is not None:
            entry[name] = value
    return {"scheme": TRUST_STORE_SCHEMA, "keys": {key_id: entry}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--gen-key", action="store_true",
                    help="print a fresh 32-byte secret seed as hex and exit")
    ap.add_argument("--in", dest="src", help="input JSONL")
    ap.add_argument("--out", dest="dst", help="output JSONL, with sidecars")
    ap.add_argument("--secret-hex", help="32-byte signing seed, hex encoded")
    ap.add_argument("--keys-out", help="write the public key document here")
    ap.add_argument("--stream-id", default="reference-stream-0")
    ap.add_argument("--sign-every", type=int, default=1,
                    help="sign every Nth record (default 1). The chain makes "
                         "one signature cover everything before it.")
    ap.add_argument("--not-before", type=float,
                    help="epoch seconds this key becomes valid, written into "
                         "--keys-out")
    ap.add_argument("--not-after", type=float,
                    help="epoch seconds this key stops being valid. Set it on "
                         "the outgoing key when you rotate, or the retired key "
                         "signs valid records forever.")
    ap.add_argument("--replaces", metavar="KEY_ID",
                    help="the key id this one supersedes, recorded so an auditor "
                         "can reconstruct the rotation")
    args = ap.parse_args(argv)

    if args.gen_key:
        print(secrets.token_bytes(32).hex())
        return 0
    if not (args.src and args.dst and args.secret_hex):
        ap.error("--in, --out and --secret-hex are required unless --gen-key")

    secret = bytes.fromhex(args.secret_hex)
    public = ed25519.public_key(secret)
    key_id = key_id_for(public)

    records = [json.loads(line) for line in
               Path(args.src).read_text(encoding="utf-8").splitlines() if line.strip()]
    signed = sign_stream(records, args.stream_id, secret, key_id, args.sign_every)
    Path(args.dst).write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in signed),
        encoding="utf-8")
    if args.keys_out:
        Path(args.keys_out).write_text(
            json.dumps(keys_document(public, key_id, args.not_before,
                                     args.not_after, args.replaces),
                       indent=2) + "\n",
            encoding="utf-8")
    print(f"signed {len(signed)} record(s) as stream {args.stream_id!r} "
          f"under {key_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
