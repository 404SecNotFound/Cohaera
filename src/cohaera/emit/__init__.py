"""The producer side: emit telemetry Cohaera can verify.

Everything else in this package VERIFIES. ``cohaera.evidence`` checks chains,
signatures, receipts and approvals, and it was kept unable to produce any of
them, for the reason ``tools/collector_sign.py`` gives: a verifier that could
also sign is a verifier whose attestations prove nothing, since the thing
checking the evidence could have written it. The reference producers were
therefore scripts in ``tools/``, outside the package.

That left the format with no library. Three external reviews reached the same
conclusion: the signed, chained telemetry with effect receipts and approvals
bound to the exact call is the differentiated part of this project, and
nothing in the wild emits it. A wire format with a verifier and no producer is
a specification, and the first question a collector or gateway maintainer
asks is "show me the five lines". This subpackage is those lines:

    from cohaera.emit import KeyPair, StreamSigner, JsonlWriter

    pair = KeyPair.generate()
    signer = StreamSigner("collector-01", pair.seed, pair.key_id)
    with JsonlWriter("signed.jsonl") as out:
        for record in records:
            out.write(signer.sign(record))

THE BOUNDARY IS KEPT, ONE DIRECTORY DOWN. Nothing in ``evidence``, ``checks``,
``model`` or ``cli`` imports this package, and ``tests/test_emit.py`` asserts
it by importing the verifier in a fresh interpreter and checking what loaded.
A host that only scores never loads signing code. The producers here reuse the
verifier's primitives -- ``chain_seed``, ``chain_step``, ``body_digest``,
``signing_input``, ``approval_signing_input``, ``arg_digest`` -- by import and
never by copy, so the two halves cannot disagree about a byte, and each
producer runs its output back through the verifier's own parser before
returning it.

WHAT A SIGNATURE FROM HERE PROVES. That the records were not altered, deleted
or reordered after the signer saw them, by anyone who does not hold the key.
Not that the agent behaved; not that the collector was honest; not, where the
signer runs inside the agent process, anything at all -- the agent then signs
whatever it chose to say. ``docs/EMITTING.md`` is the guide and
``docs/EVIDENCE-TRUST.md`` section 7 is the honest accounting.

``cohaera.ed25519.sign`` is not constant-time. For a key that matters on a
shared host, sign with libsodium and treat this package as the format.
"""

from .approvals import ApprovalIssuer
from .keys import (
    PRIVATE_KEY_SCHEMA,
    KeyPair,
    PrivateKeyError,
    add_key,
    key_id_for,
    read_private_key,
    trust_store_document,
    trust_store_entry,
    write_private_key,
)
from .receipts import (
    ASSURANCE_CLIENT,
    ASSURANCE_LEVELS,
    ASSURANCE_OBJECT,
    ASSURANCE_OPERATION,
    binding,
    receipt,
)
from .stream import (
    SIGNER_STATE_SCHEMA,
    SignerStateError,
    StreamSigner,
    read_state,
    write_state,
)
from .writer import JsonlWriter

__all__ = [
    "ASSURANCE_CLIENT",
    "ASSURANCE_LEVELS",
    "ASSURANCE_OBJECT",
    "ASSURANCE_OPERATION",
    "PRIVATE_KEY_SCHEMA",
    "SIGNER_STATE_SCHEMA",
    "ApprovalIssuer",
    "JsonlWriter",
    "KeyPair",
    "PrivateKeyError",
    "SignerStateError",
    "StreamSigner",
    "add_key",
    "binding",
    "key_id_for",
    "read_private_key",
    "read_state",
    "receipt",
    "trust_store_document",
    "trust_store_entry",
    "write_private_key",
    "write_state",
]
