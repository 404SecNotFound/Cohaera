"""Build ``cohaera.receipt:1`` objects with an explicit assurance and scope.

A receipt is an identifier MINTED BY THE SYSTEM THE ACTION HAPPENED TO
(``docs/EVIDENCE-TRUST.md`` section 3). The provider-specific half -- which
field of which response carries it, for S3, SES, Stripe, Kubernetes and the
rest -- is a registry of data about providers and lives in
``tools/receipt_adapters.py``, outside the package on purpose: it drifts with
provider documentation and is corrected as data. What is the same for every
provider is here: the binding, the schema, the assurance vocabulary and the
argument digest. ``adapt`` in that file produces exactly what ``receipt`` here
produces, and ``tests/test_emit.py`` holds the two to it.

ASSURANCE IS NOT OPTIONAL AND NONE OF ITS VALUES MEANS "CONFIRMED". R-17: a
Kubernetes ``uid`` names the object for its whole life and a
``resourceVersion`` names this mutation; an SMTP ``Message-ID`` the client
composed is not evidence the client cannot fabricate. A fallback whose
security meaning is weaker has to say so in the output, or it is a
substitution the consumer cannot see. Nothing in this project contacts a
provider to ask, so the strongest level is ``provider_returned_operation`` and
not ``verified``.

DO NOT INVENT AN IDENTIFIER. A UUID the adapter generated, a hash of the
request, a timestamp -- each is drawn from a namespace the agent controls,
which removes the one property that made the receipt worth anything. A tool
with no identifier to surface emits no receipt, and coverage says
``NO_EFFECT_RECEIPT``, which is the correct output.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..evidence import RECEIPT_SCHEMA, EffectReceipt
from ._fields import identity, optional_finite
from .approvals import _UNSET, subject_digest

# Ordered strongest first. The strings are the wire values and must not change:
# a SIEM rule written against `provider_returned_operation` has to keep
# matching the receipts that carry it.
ASSURANCE_OPERATION = "provider_returned_operation"   # names THIS operation
ASSURANCE_OBJECT = "provider_returned_object"         # names the object, not the write
ASSURANCE_CLIENT = "client_claimed"                   # the caller may have minted it
ASSURANCE_LEVELS = (ASSURANCE_OPERATION, ASSURANCE_OBJECT, ASSURANCE_CLIENT)


def binding(span_id: str, tool_id: str, *, arg_digest: str | None = None,
            tool_args: Any = _UNSET) -> dict[str, str]:
    """The three fields that make a receipt more than decoration.

    All three, always. R-01: a receipt naming two of them carried the authority
    of one bound to the exact call, and an empty binding carried the authority
    of a full one. The verifier now separates ``bound`` from
    ``bound_span_only`` and only the first can carry CH07's contradiction, so
    an incomplete binding here would be a receipt that can never do its job.
    """
    return {"span_id": identity(span_id, "span_id"),
            "tool_id": identity(tool_id, "tool_id"),
            "arg_digest": subject_digest(arg_digest_text=arg_digest,
                                         tool_args=tool_args)}


def receipt(authority: str, kind: str, identifier: str, *,
            binding: Mapping[str, str], assurance: str,
            scope: Mapping[str, str] | None = None,
            observed_at: float | None = None) -> dict[str, Any]:
    """One ``cohaera.receipt:1`` object, checked with the verifier's parser.

    ``scope`` narrows the authority to the account, region, tenant, project or
    bucket the identifier is unique within -- "stripe" is a company, and a
    charge id is unique within one Stripe account. ``observed_at`` is when the
    receipt was seen, advisory, so a human reconciling it against the
    provider's own logs has a time to search around. Both are parsed by the
    verifier and no check turns on either; they are for the person who follows
    the receipt back to the authority.
    """
    if assurance not in ASSURANCE_LEVELS:
        raise ValueError(f"assurance must be one of {list(ASSURANCE_LEVELS)}, got "
                         f"{assurance!r}; a receipt has to say what its identifier "
                         f"is worth, and 'verified' is not an option because "
                         f"nothing here asks the provider")
    bound = {"span_id": identity(binding.get("span_id"), "binding.span_id"),
             "tool_id": identity(binding.get("tool_id"), "binding.tool_id"),
             "arg_digest": subject_digest(arg_digest_text=binding.get("arg_digest"))}
    out: dict[str, Any] = {
        "scheme": RECEIPT_SCHEMA,
        "authority": identity(authority, "authority"),
        "kind": identity(kind, "kind"),
        "identifier": identity(identifier, "identifier"),
        "assurance": assurance,
        "binding": bound,
    }
    if scope:
        out["scope"] = {identity(k, "scope key"): identity(v, f"scope[{k}]")
                        for k, v in sorted(scope.items())}
    seen = optional_finite(observed_at, "observed_at")
    if seen is not None:
        out["observed_at"] = seen
    parsed, codes = EffectReceipt.parse(out)
    if parsed is None or codes or not parsed.binding.complete:
        raise RuntimeError(f"built receipt does not parse as {RECEIPT_SCHEMA}: "
                           f"{codes or 'incomplete binding'}")
    return out
