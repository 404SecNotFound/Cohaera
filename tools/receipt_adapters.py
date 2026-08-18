#!/usr/bin/env python3
"""Reference adapters: real provider responses to ``cohaera.receipt:1``.

    from tools.receipt_adapters import adapt, binding_for

    receipt = adapt("aws.s3.put_object", response, binding_for(
        span_id=span, tool_id="s3_object_put", args=call_args))
    end_event["data"]["effect_receipt"] = receipt

WHY THIS EXISTS, AND WHY IT IS THE SLOW HALF
--------------------------------------------
``docs/EVIDENCE-TRUST.md`` §3 says a receipt is an identifier **minted by the
system the action happened to**, drawn from a namespace the agent does not
control, and that the mechanism is worth nothing unless the receipt is BOUND to
the exact call and the exact arguments. All of that was built on the verifier
side: the schema parses, the binding is checked, and CH07 fires when a call
reports failure while carrying a receipt bound to it.

None of it helps anybody until an adapter emits one. That is the slow half, and
it is slow because it is per-integration: the identifier lives in a different
field of a different response shape for every provider, and there is no generic
way to find it. What this file can do is remove the part that is genuinely the
same every time -- the binding, the schema, the argument digest -- so that adding
a provider is a one-line entry naming a field rather than a fresh reading of the
specification.

WHERE THIS BELONGS
------------------
In the tool adapter, on the producer side, next to the code that already holds
the provider's response and today throws it away. NOT in ``src/cohaera``:
Cohaera verifies receipts and must never be able to mint one, for the same reason
it verifies integrity signatures and never signs. A verifier that can produce the
evidence it checks is attesting to its own output.

WHAT AN ADAPTER CAN AND CANNOT ESTABLISH
----------------------------------------
It can establish that the provider returned an identifier for this call. It
cannot establish that the identifier is real, and neither can Cohaera -- both are
offline with respect to the authority. What the receipt buys is stated precisely
in §3 and is worth repeating here, because it is the opposite of the intuition:

    Receipts do NOT make a reported success more believable. A success with no
    receipt is exactly as unfalsifiable as it always was. What they make
    falsifiable is FAILURE and SILENCE -- a call whose telemetry says it failed
    while carrying a receipt bound to it is an effect that happened and a record
    that denies it.

So an adapter that cannot find an identifier should emit NOTHING. Inventing one
-- a UUID the adapter generated, a hash of the request, a timestamp -- produces a
receipt drawn from a namespace the agent DOES control, which is the one property
that made the mechanism worth anything. ``NO_EFFECT_RECEIPT`` in coverage is the
correct output for a tool with no identifier to surface, and it is why every
adapter here returns ``None`` rather than guessing.

ON PROVIDER RESPONSE SHAPES
---------------------------
The field paths below are written from each provider's documented response and
are the part most likely to drift. They are deliberately declarative -- a tuple
of candidate paths per authority -- so that correcting one is an edit to data
rather than to logic, and so that a reader can check them against the provider's
documentation without reading any Python.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.evidence import RECEIPT_SCHEMA, arg_digest

# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
#
# Each entry: the authority string that travels in the receipt, the `kind` of
# identifier, and the candidate paths to look in, most specific first. Dotted
# paths descend through dicts; a path matches only if it resolves to a non-empty
# scalar.
#
# The order within `paths` matters and is not arbitrary. Where a provider returns
# more than one identifier, the one listed first is the one that identifies THIS
# operation rather than the object it acted on. An S3 PUT returns both a version
# id (this write) and an ETag (this content), and two writes of identical bytes
# share an ETag -- so an ETag would let a receipt for one write be presented for
# another, which is exactly the substitution the binding exists to stop.

_ADAPTERS: dict[str, dict[str, Any]] = {
    # --- object storage: the easiest first adoption, per EVIDENCE-TRUST §3 ---
    "aws.s3.put_object": {
        "authority": "aws:s3",
        "kind": "object_version",
        "paths": ("VersionId", "ResponseMetadata.HTTPHeaders.x-amz-version-id"),
    },
    "aws.s3.delete_object": {
        "authority": "aws:s3",
        "kind": "delete_marker_version",
        "paths": ("VersionId", "ResponseMetadata.HTTPHeaders.x-amz-version-id"),
    },
    "gcp.storage.upload": {
        "authority": "gcp:storage",
        "kind": "object_generation",
        "paths": ("generation",),
    },
    "azure.blob.upload": {
        "authority": "azure:blob",
        "kind": "blob_version",
        "paths": ("version_id", "x-ms-version-id"),
    },

    # --- email: the Message-ID is minted by the submitting MTA -------------
    #
    # Note the failure mode this one has and object storage does not. A client
    # library may GENERATE the Message-ID locally and pass it to the server, in
    # which case it is not drawn from a namespace the agent lacks control over
    # and the receipt is worth much less. Take it from the server's reply
    # (smtplib's send response, an SES MessageId, a Sendgrid X-Message-Id
    # header) rather than from the message you composed.
    "smtp.send": {
        "authority": "smtp",
        "kind": "message_id",
        "paths": ("server_message_id", "Message-ID", "message_id"),
    },
    "aws.ses.send_email": {
        "authority": "aws:ses",
        "kind": "message_id",
        "paths": ("MessageId",),
    },
    "sendgrid.send": {
        "authority": "sendgrid",
        "kind": "message_id",
        "paths": ("headers.X-Message-Id", "x-message-id"),
    },

    # --- payments and ticketing -------------------------------------------
    "stripe.charge": {
        "authority": "stripe",
        "kind": "charge_id",
        "paths": ("id",),
    },
    "stripe.refund": {
        "authority": "stripe",
        "kind": "refund_id",
        "paths": ("id",),
    },
    "jira.create_issue": {
        "authority": "jira",
        "kind": "issue_key",
        "paths": ("key", "id"),
    },
    "servicenow.create_record": {
        "authority": "servicenow",
        "kind": "sys_id",
        "paths": ("result.sys_id", "sys_id"),
    },

    # --- infrastructure ----------------------------------------------------
    #
    # Kubernetes gives two useful identifiers and they answer different
    # questions. `uid` identifies the object across its whole life; `
    # resourceVersion` identifies THIS mutation of it. The mutation is what a
    # receipt for a write should carry, so it leads.
    "kubernetes.apply": {
        "authority": "kubernetes",
        "kind": "resource_version",
        "paths": ("metadata.resourceVersion", "metadata.uid"),
    },
    "aws.cloudtrail.event": {
        "authority": "aws:cloudtrail",
        "kind": "event_id",
        "paths": ("eventID",),
    },
    "github.create_pull_request": {
        "authority": "github",
        "kind": "node_id",
        "paths": ("node_id", "number"),
    },

    # --- databases ---------------------------------------------------------
    #
    # A transaction id is only a receipt if it survives the transaction. A
    # per-connection counter that resets, or an id reused after wraparound, is
    # an identifier the agent's own process can collide with by accident, which
    # is weaker than it looks. PostgreSQL's commit LSN is the durable one.
    "postgres.commit": {
        "authority": "postgresql",
        "kind": "commit_lsn",
        "paths": ("pg_current_wal_lsn", "commit_lsn"),
    },
}


class ReceiptAdapterError(ValueError):
    """The caller asked for an authority nothing here knows how to read."""


def _dig(obj: Any, path: str) -> Any:
    """Follow a dotted path through nested mappings. Never raises.

    Case-insensitive at the leaf for HTTP header names, because header casing is
    not stable across clients and ``X-Message-Id`` versus ``x-message-id`` is a
    difference no adapter should have an opinion about.
    """
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        if part in cur:
            cur = cur[part]
            continue
        lowered = {k.lower(): v for k, v in cur.items() if isinstance(k, str)}
        if part.lower() in lowered:
            cur = lowered[part.lower()]
            continue
        return None
    return cur


def _scalar(value: Any) -> str | None:
    """A non-empty identifier as text, or None. Booleans are not identifiers."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def binding_for(span_id: str, tool_id: str, args: Any) -> dict[str, str]:
    """The three fields that make a receipt more than decoration.

    ``arg_digest`` is the one that does the work. Without it a receipt binds to a
    span and a tool name, which stops nothing an attacker cares about: an
    approval-style substitution keeps both and changes the recipient. Compute it
    over the SAME argument object the call was made with, canonically, which is
    what ``cohaera.evidence.arg_digest`` does.
    """
    return {"span_id": span_id, "tool_id": tool_id,
            "arg_digest": arg_digest(args)}


def identifier_from(authority: str, response: Any) -> tuple[str, str] | None:
    """``(kind, identifier)`` for one provider response, or None.

    None is a legitimate and common answer: the call succeeded and the provider
    returned nothing that identifies it. Returning None is what makes coverage
    say ``NO_EFFECT_RECEIPT`` instead of the adapter inventing an identifier from
    a namespace the agent controls.
    """
    spec = _ADAPTERS.get(authority)
    if spec is None:
        raise ReceiptAdapterError(
            f"no adapter for {authority!r}; known authorities are "
            f"{sorted(_ADAPTERS)}")
    for path in spec["paths"]:
        found = _scalar(_dig(response, path))
        if found is not None:
            return spec["kind"], found
    return None


def adapt(authority: str, response: Any, binding: dict[str, str],
          observed_at: float | None = None) -> dict[str, Any] | None:
    """One provider response as a ``cohaera.receipt:1`` object, or None.

    ``observed_at`` is when the RECEIPT was seen, not when the call started. It
    is advisory -- Cohaera parses it and no check turns on it -- and it exists so
    that a human reconciling a receipt against the authority's own logs has a
    time to search around.
    """
    spec = _ADAPTERS[authority] if authority in _ADAPTERS else None
    found = identifier_from(authority, response)
    if found is None or spec is None:
        return None
    kind, identifier = found
    receipt: dict[str, Any] = {
        "scheme": RECEIPT_SCHEMA,
        "authority": spec["authority"],
        "kind": kind,
        "identifier": identifier,
        "binding": dict(binding),
    }
    if observed_at is not None:
        receipt["observed_at"] = observed_at
    return receipt


def known_authorities() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def main(argv: list[str] | None = None) -> int:
    """Print the registry, so the field paths can be checked against the docs."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="emit the registry as JSON")
    args = ap.parse_args(argv)
    if args.json:
        print(json.dumps(_ADAPTERS, indent=2, sort_keys=True))
        return 0
    for name in known_authorities():
        spec = _ADAPTERS[name]
        print(f"{name:32s} {spec['authority']:16s} {spec['kind']:22s} "
              f"{', '.join(spec['paths'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
