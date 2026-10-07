"""``python -m cohaera.emit``: keygen, sign, issue-approval.

    python -m cohaera.emit keygen --out collector.key --roles collector \\
        --trust-store trust-store.json
    python -m cohaera.emit sign --key collector.key --stream-id collector-01 \\
        --in raw.jsonl --out signed.jsonl --state collector-01.state
    python -m cohaera.emit issue-approval --key approver.key --decision allow \\
        --span-id sp-42 --tool-id send_email --tool-args '{"to": "a@b"}' \\
        --expires-in 300

Deliberately not registered in ``cohaera.cli``. The scoring CLI is the
verifier and must stay importable without any signing code (see the package
docstring); the integrator wires this entry point in where it belongs.
``argparse`` only, like everything else in the package.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from ..evidence import VALID_DECISIONS, VALID_ENFORCEMENT, VALID_ROLES, TrustStoreError
from ..validate import sanitise_display, strict_json_loads
from .approvals import ApprovalIssuer
from .keys import (
    KeyPair,
    PrivateKeyError,
    add_key,
    read_private_key,
    trust_store_document,
    write_private_key,
)
from .stream import SignerStateError, StreamSigner, read_state, write_state
from .writer import JsonlWriter

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


def _err(message: str) -> None:
    print(f"[cohaera.emit] {message}", file=sys.stderr)


def _epoch(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if value != value or value in (float("inf"), float("-inf")):
        # A NaN here would be accepted by float() and compared false to
        # everything downstream, which is how C4-05 turned a bound off.
        raise argparse.ArgumentTypeError("must be finite")
    return value


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return value


def _load_key(path: str) -> KeyPair:
    try:
        return read_private_key(path)
    except (PrivateKeyError, OSError) as exc:
        _err(f"private key refused: {sanitise_display(str(exc), 300)}")
        raise SystemExit(EXIT_REFUSED) from None


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    pair = KeyPair.generate()
    try:
        entry = pair.trust_store_entry(roles=args.roles, not_before=args.not_before,
                                       not_after=args.not_after, replaces=args.replaces)
        document: dict[str, Any] | None = None
        if args.trust_store:
            store_path = Path(args.trust_store)
            if store_path.exists():
                # Merging into an existing store is what a rotation looks like
                # from the operator's chair: the new key goes in beside the old
                # one, with `replaces` naming it. Nothing here edits the old
                # entry; setting its `not_after` is a separate, deliberate act.
                existing = strict_json_loads(store_path.read_text(encoding="utf-8"))
                if not isinstance(existing, dict):
                    raise TrustStoreError(f"{store_path}: not a JSON object")
                document = add_key(existing, pair.key_id, entry)
            else:
                document = trust_store_document({pair.key_id: entry})
        write_private_key(args.out, pair, overwrite=args.overwrite)
    except (ValueError, TrustStoreError, OSError) as exc:
        _err(f"refused: {sanitise_display(str(exc), 300)}")
        return EXIT_REFUSED
    if document is not None:
        Path(args.trust_store).write_text(json.dumps(document, indent=2, sort_keys=True)
                                          + "\n", encoding="utf-8")
    print(pair.key_id)
    _err(f"wrote private key to {sanitise_display(args.out, 160)} (mode 0600) "
         f"with roles {sorted(set(args.roles))}"
         + (f"; public half in {sanitise_display(args.trust_store, 160)}"
            if args.trust_store else "; no trust store written, pass --trust-store"))
    return EXIT_OK


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


def _records(handle: IO[str], name: str) -> Iterator[dict[str, Any]]:
    """Parse one JSON object per line, refusing the batch on the first bad line.

    Refusing rather than skipping: a line this signer cannot sign is a record
    the collector would otherwise drop, and the stream it then emits is
    contiguous and attested with the drop invisible in it. The verifier can
    only report a deletion it can see.
    """
    for number, line in enumerate(handle, 1):
        if not line.strip():
            continue
        try:
            record = strict_json_loads(line)
        except ValueError as exc:
            raise ValueError(f"{name} line {number}: {exc}") from None
        if not isinstance(record, dict):
            raise ValueError(f"{name} line {number}: not a JSON object")
        yield record


def cmd_sign(args: argparse.Namespace) -> int:
    pair = _load_key(args.key)
    state_path = Path(args.state) if args.state else None
    try:
        if state_path is not None and state_path.exists():
            signer = StreamSigner.resume(read_state(state_path), pair.seed,
                                         key_id=pair.key_id, sign_every=args.sign_every)
            if signer.stream_id != args.stream_id:
                raise SignerStateError(
                    f"state file is for stream {signer.stream_id!r}, not "
                    f"{args.stream_id!r}")
            _err(f"resuming stream {args.stream_id!r} at seq {signer.next_seq}")
        else:
            signer = StreamSigner(args.stream_id, pair.seed, pair.key_id,
                                  sign_every=args.sign_every)
    except (SignerStateError, ValueError, OSError) as exc:
        _err(f"refused: {sanitise_display(str(exc), 300)}")
        return EXIT_REFUSED

    source = sys.stdin if args.src == "-" else open(args.src, encoding="utf-8")
    signed = 0
    try:
        if args.dst == "-":
            sink: Any = sys.stdout
        else:
            sink = JsonlWriter(args.dst, append=args.append)
        try:
            pending: dict[str, Any] | None = None
            # One record of lookahead, so the last one can be signed whatever
            # the sampling rate says (R-05: `verified_complete` is unreachable
            # otherwise). Streaming, not a list, because a collector's batch
            # is whatever size the collector chose.
            for record in _records(source, args.src):
                if pending is not None:
                    _emit(sink, signer.sign(pending))
                    signed += 1
                pending = record
            if pending is not None:
                _emit(sink, signer.sign(pending, attest=True, final=args.close))
                signed += 1
        finally:
            if sink is not sys.stdout:
                sink.close()
            else:
                sys.stdout.flush()
    except (ValueError, OSError) as exc:
        # StreamClosedError is a ValueError: signing into a closed stream is
        # refused here with the reason, and the state file is left as it was.
        _err(f"refused after {signed} record(s): {sanitise_display(str(exc), 300)}")
        return EXIT_REFUSED
    finally:
        if source is not sys.stdin:
            source.close()
    if state_path is not None:
        write_state(state_path, signer.state())
    _err(f"signed {signed} record(s) as stream {args.stream_id!r} under "
         f"{pair.key_id}; next seq {signer.next_seq}"
         + (f", state in {sanitise_display(str(state_path), 160)}" if state_path else ""))
    return EXIT_OK


def _emit(sink: Any, record: dict[str, Any]) -> None:
    if isinstance(sink, JsonlWriter):
        sink.write(record)
    else:
        sink.write(json.dumps(record, ensure_ascii=False, allow_nan=False,
                              sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# issue-approval
# ---------------------------------------------------------------------------


def cmd_issue_approval(args: argparse.Namespace) -> int:
    pair = _load_key(args.key)
    issuer = ApprovalIssuer(pair.seed, pair.key_id)
    granted_at = time.time() if args.granted_at is None else args.granted_at
    if args.expires_at is not None:
        expires_at = args.expires_at
    elif args.expires_in is not None:
        expires_at = granted_at + args.expires_in
    else:
        _err("refused: give --expires-at or --expires-in; an approval with no "
             "expiry cannot be signed")
        return EXIT_REFUSED
    kwargs: dict[str, Any] = {}
    if args.tool_args is not None:
        try:
            kwargs["tool_args"] = strict_json_loads(args.tool_args)
        except ValueError as exc:
            _err(f"refused: --tool-args is not JSON: {sanitise_display(str(exc), 200)}")
            return EXIT_REFUSED
    try:
        approval = issuer.issue(
            args.decision, args.span_id, args.tool_id, expires_at=expires_at,
            arg_digest=args.arg_digest, granted_at=granted_at,
            granted_by=args.granted_by, policy_id=args.policy_id,
            policy_digest=args.policy_digest, enforcement=args.enforcement,
            **kwargs)
    except ValueError as exc:
        _err(f"refused: {sanitise_display(str(exc), 300)}")
        return EXIT_REFUSED
    text = json.dumps(approval, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        Path(args.out).write_text(text, encoding="utf-8")
    return EXIT_OK


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cohaera.emit",
                                 description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate a key pair and publish the public half")
    kg.add_argument("--out", required=True, metavar="PATH",
                    help="where to write the private key (created 0600, never "
                         "overwritten without --overwrite)")
    kg.add_argument("--roles", nargs="+", required=True, choices=sorted(VALID_ROLES),
                    help="what this key may attest. 'collector' signs telemetry, "
                         "'approval' issues approvals, 'policy' signs the manifest "
                         "and baseline. One key doing two of these is a weakened "
                         "deployment; see docs/EVIDENCE-TRUST.md section 2.")
    kg.add_argument("--trust-store", metavar="PATH",
                    help="write the public half here as cohaera.trust_store:1, or "
                         "add it to the store already at this path (a rotation)")
    kg.add_argument("--not-before", type=_epoch, metavar="EPOCH")
    kg.add_argument("--not-after", type=_epoch, metavar="EPOCH",
                    help="set it on the OUTGOING key when you rotate, or the "
                         "retired key signs valid records forever")
    kg.add_argument("--replaces", metavar="KEY_ID",
                    help="the key id this one supersedes, so an auditor can "
                         "reconstruct the rotation")
    kg.add_argument("--overwrite", action="store_true")
    kg.set_defaults(func=cmd_keygen)

    sg = sub.add_parser("sign", help="attach cohaera.integrity:1 sidecars to JSONL")
    sg.add_argument("--key", required=True, metavar="PATH", help="private key file")
    sg.add_argument("--stream-id", required=True,
                    help="one id per collector instance; the chain is per stream")
    sg.add_argument("--in", dest="src", default="-", metavar="PATH",
                    help="raw JSONL, one object per line (default stdin)")
    sg.add_argument("--out", dest="dst", default="-", metavar="PATH",
                    help="signed JSONL (default stdout)")
    sg.add_argument("--append", action="store_true",
                    help="append to --out rather than truncating it; what you "
                         "want when resuming into the same file")
    sg.add_argument("--state", metavar="PATH",
                    help="signer state: read to resume if it exists, written "
                         "after the batch. Without it every run starts at seq 0, "
                         "which a ledger reports as a forked stream.")
    sg.add_argument("--sign-every", type=_positive_int, default=1, metavar="N",
                    help="sign every Nth record; the last record of a batch is "
                         "always signed (default 1)")
    sg.set_defaults(func=cmd_sign)

    sg.add_argument("--close", action="store_true",
                    help="mark the last record of this input as the end of the "
                         "stream and sign that (E30). The state file then records "
                         "the stream as closed and a later `sign` on it is "
                         "refused. Without it the last record is signed as a "
                         "batch boundary and the stream stays open.")
    ia = sub.add_parser("issue-approval", help="sign one cohaera.approval:1")
    ia.add_argument("--key", required=True, metavar="PATH",
                    help="private key file for a key with the 'approval' role")
    ia.add_argument("--decision", required=True, choices=sorted(VALID_DECISIONS))
    ia.add_argument("--span-id", required=True)
    ia.add_argument("--tool-id", required=True)
    ia.add_argument("--arg-digest", metavar="SHA256",
                    help="'sha256:' plus 64 hex, as cohaera.evidence.arg_digest "
                         "computes it")
    ia.add_argument("--tool-args", metavar="JSON",
                    help="the call's arguments; the digest is computed from them")
    ia.add_argument("--expires-at", type=_epoch, metavar="EPOCH")
    ia.add_argument("--expires-in", type=_epoch, metavar="SECONDS",
                    help="seconds after --granted-at (or now)")
    ia.add_argument("--granted-at", type=_epoch, metavar="EPOCH",
                    help="default: now. Must not be after the call starts.")
    ia.add_argument("--granted-by")
    ia.add_argument("--policy-id")
    ia.add_argument("--policy-digest", metavar="SHA256")
    ia.add_argument("--enforcement", choices=sorted(VALID_ENFORCEMENT))
    ia.add_argument("--out", default="-", metavar="PATH", help="default stdout")
    ia.set_defaults(func=cmd_issue_approval)

    args = ap.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:                       # pragma: no cover
        _err("interrupted")
        return EXIT_REFUSED
    except OSError as exc:
        _err(sanitise_display(str(exc), 300))
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
