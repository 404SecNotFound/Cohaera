#!/usr/bin/env python3
"""Reference signer for ``cohaera.policy_signature:1``.

    python tools/policy_sign.py --gen-key
    python tools/policy_sign.py sign --artifact capability_manifest \
        --file manifest.json --out manifest.json.sig \
        --secret-hex <64 hex chars> --signed-at 1785700000
    python tools/policy_sign.py store --secret-hex <64 hex> --roles policy \
        --out trust-store.json

WHAT THIS SIGNS, AND WHY IT IS NOT THE COLLECTOR'S JOB
-----------------------------------------------------
Two files decide how Cohaera reads every record, and neither is telemetry:

    the capability manifest   says which tools are consequential. Edit it and an
                              egress tool becomes read_only, and CH02, CH03 and
                              CH04 all go quiet on it without one telemetry
                              record changing.
    the baseline              teaches CH01 what normal looks like. CH01 is the
                              only detector in this project that LEARNS, so
                              adding sessions to the baseline teaches it that
                              the attack is normal. That is EVASION.md E03, and
                              until now it was mitigated by keeping the file
                              somewhere safe, which is a hope rather than a
                              control.

These are the OPERATOR's files, so they are signed with an operator's key, and
the trust store gives that key the ``policy`` role rather than ``collector``.
The separation is the whole reason the roles exist: a collector that could also
sign the manifest could rewrite the document saying which of its own tools are
dangerous, which is a privilege escalation wearing the costume of a convenience.
Keep the two keys apart, and keep this one off the collector host.

DETACHED, OVER THE EXACT BYTES
------------------------------
The signature is a separate file covering ``sha256`` of the artifact's bytes,
not a canonicalisation of its parsed contents. A signature over parsed semantics
would verify happily after an edit that adds a field the current parser ignores,
and "did this file change at all" is exactly the question a tamper signal has to
answer strictly. Detached also leaves the artifact untouched, so a signed
manifest is still a plain JSON document every other tool can read.

THE SECRET
----------
``--secret-hex`` takes a 32-byte seed as hex and ``--gen-key`` mints one. The
implementation in ``cohaera.ed25519`` is NOT constant-time; for a key that
matters, sign with libsodium and treat this file as the format reference.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera import ed25519
from cohaera.evidence import (
    POLICY_SIGNATURE_SCHEMA,
    ROLE_COLLECTOR,
    ROLE_POLICY,
    TRUST_STORE_SCHEMA,
    VALID_POLICY_ARTIFACTS,
    VALID_ROLES,
    policy_signing_input,
)

CHUNK = 1 << 20


def key_id_for(public: bytes) -> str:
    return "ed25519:" + public.hex()[:16]


def digest_of(path: Path) -> str:
    """Chunked, because the baseline is telemetry and may be very large."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def signature_document(artifact: str, file_sha256: str, signed_at: int,
                       secret: bytes, key_id: str) -> dict:
    sig = ed25519.sign(secret,
                       policy_signing_input(artifact, file_sha256, signed_at))
    return {
        "scheme": POLICY_SIGNATURE_SCHEMA,
        "artifact": artifact,
        "file_sha256": file_sha256,
        "signed_at": signed_at,
        "key_id": key_id,
        "sig": base64.b64encode(sig).decode("ascii"),
    }


def store_document(public: bytes, key_id: str, roles: list[str],
                   not_before: float | None = None,
                   not_after: float | None = None,
                   revoked_at: float | None = None,
                   replaces: str | None = None) -> dict:
    """One key's entry in a ``cohaera.trust_store:1`` document.

    ``roles`` has no default here for the same reason it has none in the parser:
    a key with no declared role is an operator who has not decided what the key
    is for, and deciding for them is how a collector key ends up able to sign
    the manifest.
    """
    entry: dict[str, object] = {
        "key": base64.b64encode(public).decode("ascii"),
        "roles": sorted(set(roles)),
    }
    for name, value in (("not_before", not_before), ("not_after", not_after),
                        ("revoked_at", revoked_at), ("replaces", replaces)):
        if value is not None:
            entry[name] = value
    return {"scheme": TRUST_STORE_SCHEMA, "keys": {key_id: entry}}


def _epoch(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--gen-key", action="store_true",
                    help="print a fresh 32-byte secret seed as hex and exit")
    sub = ap.add_subparsers(dest="cmd")

    sg = sub.add_parser("sign", help="sign one policy artifact")
    sg.add_argument("--artifact", required=True, choices=sorted(VALID_POLICY_ARTIFACTS))
    sg.add_argument("--file", required=True, help="the artifact to sign")
    sg.add_argument("--out", required=True, help="where to write the .sig JSON")
    sg.add_argument("--secret-hex", required=True, help="32-byte seed, hex encoded")
    sg.add_argument("--signed-at", type=_epoch, required=True,
                    help="integer epoch seconds, covered by the signature so that "
                         "the key's validity window has something attested to be "
                         "judged against")
    sg.add_argument("--store-out",
                    help="also write a trust store containing this public key "
                         "with the 'policy' role")

    st = sub.add_parser("store", help="write a trust store entry for a key")
    st.add_argument("--secret-hex", required=True)
    st.add_argument("--roles", nargs="+", default=[ROLE_POLICY],
                    choices=sorted(VALID_ROLES))
    st.add_argument("--out", required=True)
    st.add_argument("--not-before", type=float)
    st.add_argument("--not-after", type=float)
    st.add_argument("--revoked-at", type=float)
    st.add_argument("--replaces")

    args = ap.parse_args(argv)

    if args.gen_key:
        print(secrets.token_bytes(32).hex())
        return 0
    if not args.cmd:
        ap.error("give a subcommand (sign, store) or --gen-key")

    secret = bytes.fromhex(args.secret_hex)
    public = ed25519.public_key(secret)
    key_id = key_id_for(public)

    if args.cmd == "store":
        doc = store_document(public, key_id, args.roles,
                             not_before=args.not_before,
                             not_after=args.not_after,
                             revoked_at=args.revoked_at,
                             replaces=args.replaces)
        Path(args.out).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"wrote trust store for {key_id} with roles "
              f"{sorted(set(args.roles))}")
        return 0

    digest = digest_of(Path(args.file))
    doc = signature_document(args.artifact, digest, args.signed_at, secret, key_id)
    Path(args.out).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    if args.store_out:
        Path(args.store_out).write_text(
            json.dumps(store_document(public, key_id, [ROLE_POLICY]), indent=2)
            + "\n", encoding="utf-8")
    print(f"signed {args.artifact} {args.file} (sha256 {digest[:16]}...) "
          f"under {key_id}")
    print(f"verify with: --{'tool-manifest' if args.artifact == 'capability_manifest' else 'baseline'}-sig "
          f"{args.out} --trust-store <store with {key_id} as {ROLE_POLICY}>")
    if ROLE_COLLECTOR in getattr(args, "roles", []):
        print("WARNING: this key is also a collector key. Keep policy signing "
              "off the collector host; see the module docstring.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
