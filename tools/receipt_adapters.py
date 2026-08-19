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
import math
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cohaera.evidence import RECEIPT_SCHEMA, arg_digest

# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
#
# Each entry: the authority string that travels in the receipt, and the candidate
# paths to look in, most specific first. Dotted paths descend through dicts; a
# path matches only if it resolves to a non-empty finite scalar.
#
# Each PATH declares its own kind and its own assurance. R-17: they used to
# share one kind per authority, so `metadata.resourceVersion` and
# `metadata.uid` both emitted `resource_version`, `node_id` and `number` both
# emitted `node_id`, and a Jira `id` was reported as an `issue_key`. Those pairs
# answer different questions -- one identifies THIS operation, the other
# identifies the object it acted on for the rest of its life -- and a receipt
# carrying the second under the first's name is a receipt that can be presented
# for a later mutation of the same object. A fallback whose security meaning is
# weaker has to say so in the output, or it is not a fallback, it is a
# substitution the consumer cannot see.
#
# The order within `paths` still matters and is still not arbitrary: the
# strongest identifier leads. An S3 PUT returns both a version id (this write)
# and an ETag (this content), and two writes of identical bytes share an ETag --
# so an ETag would let a receipt for one write be presented for another, which
# is exactly the substitution the binding exists to stop.

# How much the identifier is worth, independent of which provider minted it.
# Ordered strongest first, and none of them means "the effect is confirmed":
# nothing here contacts the provider to ask.
ASSURANCE_OPERATION = "provider_returned_operation"   # names THIS operation
ASSURANCE_OBJECT = "provider_returned_object"         # names the object, not the write
ASSURANCE_CLIENT = "client_claimed"                   # the caller may have minted it

ASSURANCE_LEVELS = (ASSURANCE_OPERATION, ASSURANCE_OBJECT, ASSURANCE_CLIENT)

_ADAPTERS: dict[str, dict[str, Any]] = {
    # --- object storage: the easiest first adoption, per EVIDENCE-TRUST §3 ---
    "aws.s3.put_object": {
        "authority": "aws:s3",
        "paths": (
            ("VersionId", "object_version", ASSURANCE_OPERATION),
            ("ResponseMetadata.HTTPHeaders.x-amz-version-id", "object_version",
             ASSURANCE_OPERATION),
        ),
    },
    "aws.s3.delete_object": {
        "authority": "aws:s3",
        "paths": (
            ("VersionId", "delete_marker_version", ASSURANCE_OPERATION),
            ("ResponseMetadata.HTTPHeaders.x-amz-version-id",
             "delete_marker_version", ASSURANCE_OPERATION),
        ),
    },
    "gcp.storage.upload": {
        "authority": "gcp:storage",
        "paths": (("generation", "object_generation", ASSURANCE_OPERATION),),
    },
    "azure.blob.upload": {
        "authority": "azure:blob",
        "paths": (
            ("version_id", "blob_version", ASSURANCE_OPERATION),
            ("x-ms-version-id", "blob_version", ASSURANCE_OPERATION),
        ),
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
        "paths": (
            ("server_message_id", "message_id", ASSURANCE_OPERATION),
            # R-17. A Message-ID the client composed is not evidence the client
            # cannot fabricate, and these two paths used to be indistinguishable
            # in the output. They are now different facts.
            ("Message-ID", "client_message_id", ASSURANCE_CLIENT),
            ("message_id", "client_message_id", ASSURANCE_CLIENT),
        ),
    },
    "aws.ses.send_email": {
        "authority": "aws:ses",
        "paths": (("MessageId", "message_id", ASSURANCE_OPERATION),),
    },
    "sendgrid.send": {
        "authority": "sendgrid",
        "paths": (
            ("headers.X-Message-Id", "message_id", ASSURANCE_OPERATION),
            ("x-message-id", "message_id", ASSURANCE_OPERATION),
        ),
    },

    # --- payments and ticketing -------------------------------------------
    "stripe.charge": {
        "authority": "stripe",
        "paths": (("id", "charge_id", ASSURANCE_OPERATION),),
    },
    "stripe.refund": {
        "authority": "stripe",
        "paths": (("id", "refund_id", ASSURANCE_OPERATION),),
    },
    "jira.create_issue": {
        "authority": "jira",
        "paths": (
            ("key", "issue_key", ASSURANCE_OPERATION),
            # R-17. A numeric id is not an issue key, and reporting it as one
            # meant a consumer looking the value up in Jira found nothing and
            # had no way to tell that from a forged receipt.
            ("id", "issue_id", ASSURANCE_OBJECT),
        ),
    },
    "servicenow.create_record": {
        "authority": "servicenow",
        "paths": (
            ("result.sys_id", "sys_id", ASSURANCE_OPERATION),
            ("sys_id", "sys_id", ASSURANCE_OPERATION),
        ),
    },

    # --- infrastructure ----------------------------------------------------
    #
    # Kubernetes gives two useful identifiers and they answer different
    # questions. `uid` identifies the object across its whole life; `
    # resourceVersion` identifies THIS mutation of it. The mutation is what a
    # receipt for a write should carry, so it leads.
    "kubernetes.apply": {
        "authority": "kubernetes",
        "paths": (
            ("metadata.resourceVersion", "resource_version",
             ASSURANCE_OPERATION),
            # `uid` is stable for the object's whole life, so a receipt carrying
            # it can be presented for ANY later mutation of the same object. It
            # is still worth recording and it is not the same claim.
            ("metadata.uid", "resource_uid", ASSURANCE_OBJECT),
        ),
    },
    "aws.cloudtrail.event": {
        "authority": "aws:cloudtrail",
        "paths": (("eventID", "event_id", ASSURANCE_OPERATION),),
    },
    "github.create_pull_request": {
        "authority": "github",
        "paths": (
            ("node_id", "node_id", ASSURANCE_OPERATION),
            # A PR number is scoped to the repository and reused across forks;
            # a node id is global. Calling the first the second let a receipt
            # from one repository read as a receipt from another.
            ("number", "pull_request_number", ASSURANCE_OBJECT),
        ),
    },

    # --- databases ---------------------------------------------------------
    #
    # A transaction id is only a receipt if it survives the transaction. A
    # per-connection counter that resets, or an id reused after wraparound, is
    # an identifier the agent's own process can collide with by accident, which
    # is weaker than it looks. PostgreSQL's commit LSN is the durable one.
    "postgres.commit": {
        "authority": "postgresql",
        "paths": (
            ("commit_lsn", "commit_lsn", ASSURANCE_OPERATION),
            # R-17. pg_current_wal_lsn is the CLUSTER's current write position,
            # not this transaction's commit position. It moves because anyone
            # wrote, so it is evidence that the database was alive, not that
            # this transaction committed.
            ("pg_current_wal_lsn", "cluster_wal_position", ASSURANCE_OBJECT),
        ),
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
    """A non-empty identifier as text, or None. Booleans are not identifiers.

    R-17. ``float`` used to go through ``str`` unconditionally, so a response
    carrying ``nan`` or ``inf`` -- which a JSON decoder will happily produce
    from a non-strict parser upstream -- became the identifier text "nan". That
    is not an identifier; it is a parse failure wearing one, and the receipt it
    produced would have been accepted, stored, and looked up by a human who
    found nothing.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, float) and not math.isfinite(value):
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


def identifier_from(authority: str,
                    response: Any) -> tuple[str, str, str] | None:
    """``(kind, identifier, assurance)`` for one response, or None.

    None is a legitimate and common answer: the call succeeded and the provider
    returned nothing that identifies it. Returning None is what makes coverage
    say ``NO_EFFECT_RECEIPT`` instead of the adapter inventing an identifier from
    a namespace the agent controls.

    R-17. The third element is new and it is the point. A weaker fallback path
    now says it is weaker in the output rather than borrowing the strong path's
    name.
    """
    spec = _ADAPTERS.get(authority)
    if spec is None:
        raise ReceiptAdapterError(
            f"no adapter for {authority!r}; known authorities are "
            f"{sorted(_ADAPTERS)}")
    for path, kind, assurance in spec["paths"]:
        found = _scalar(_dig(response, path))
        if found is not None:
            return kind, found, assurance
    return None


def adapt(authority: str, response: Any, binding: dict[str, str],
          observed_at: float | None = None,
          scope: dict[str, str] | None = None) -> dict[str, Any] | None:
    """One provider response as a ``cohaera.receipt:1`` object, or None.

    ``observed_at`` is when the RECEIPT was seen, not when the call started. It
    is advisory -- Cohaera parses it and no check turns on it -- and it exists so
    that a human reconciling a receipt against the authority's own logs has a
    time to search around.

    ``scope`` narrows the authority to the account, region, tenant, project,
    repository or bucket the identifier lives in. R-17: "stripe" is not an
    authority, it is a company. A charge id is unique within one Stripe account
    and a receipt that does not say which account cannot be reconciled by
    anyone who has more than one -- and everybody has more than one, because
    test mode is one. Optional, because a producer that cannot supply it should
    emit a receipt without it rather than invent a scope.
    """
    spec = _ADAPTERS[authority] if authority in _ADAPTERS else None
    found = identifier_from(authority, response)
    if found is None or spec is None:
        return None
    kind, identifier, assurance = found
    receipt: dict[str, Any] = {
        "scheme": RECEIPT_SCHEMA,
        "authority": spec["authority"],
        "kind": kind,
        "identifier": identifier,
        # What this identifier is worth. NONE of these levels means the effect
        # is confirmed: nothing in this file contacts the provider to ask, and
        # naming the strongest level `provider_returned_operation` rather than
        # `verified` is deliberate.
        "assurance": assurance,
        "binding": dict(binding),
    }
    if scope:
        receipt["scope"] = {k: v for k, v in sorted(scope.items())
                            if _scalar(v) is not None}
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
        for i, (path, kind, assurance) in enumerate(spec["paths"]):
            label = name if i == 0 else ""
            authority = spec["authority"] if i == 0 else ""
            print(f"{label:32s} {authority:16s} {kind:24s} "
                  f"{assurance:28s} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
