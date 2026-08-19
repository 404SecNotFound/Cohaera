"""P1 evidence trust: schemas, chain verification, binding, and the two new checks.

Everything here tests a mechanism whose job is to be HARD TO FAKE, so most of
these tests are attacks rather than happy paths. The happy paths are the short
ones.

The layout follows docs/EVIDENCE-TRUST.md:

    section 1   the crypto, against RFC 8032, including the malleability case
                that a hand-written Ed25519 verifier gets wrong
    section 2   parsing, where every malformed sidecar must read as ABSENT and
                never as a weaker version of itself
    section 3   the stream verifier: deletion, modification, replay, reorder,
                and the bounds that stop a producer choosing how much work it
                costs to check
    section 4   approval binding and the CH04 enforcement split
    section 5   CH07, and the asymmetry that makes receipts worth collecting
    section 6   the suppression this whole design creates, and its EVASION entry
    section 7   the trust store: roles, windows, revocation, rotation, and the
                ORDER the verifier decides them in, which is the argument for
                why judging a producer-supplied clock is admissible at all
    section 8   cohaera.policy_signature:1 over the manifest and the baseline,
                including the substitutions that make a signature decorative if
                they are not checked
    section 9   freshness, which is the only thing here that sees a replayed
                stream at all, because a replayed stream is a genuine one

Run: PYTHONPATH=src python3 -m pytest tests/test_evidence.py -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import signal
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera import ed25519
from cohaera.capabilities import CapabilityManifest
from cohaera.checks import (
    APPROVAL_SPAN_ONLY,
    CH04_BYPASSED,
    CH04_COMPLETED,
    CH06_INTEGRITY,
    CH07_CONTRADICTED,
    CH07_PARTIAL,
    CH07_UNBOUND,
    EVIDENCE_INADMISSIBLE,
    EVIDENCE_NOT_APPLICABLE,
    EVIDENCE_STATES,
    EVIDENCE_UNATTESTED,
    EVIDENCE_VERIFIED_COMPLETE,
    EVIDENCE_VERIFIED_PREFIX,
    R_RECEIPT_NOT_ARGUMENT_BOUND,
    ch04_guardrail_overrun,
    ch06_evidence_integrity,
    ch07_effect_contradiction,
    coverage,
    evidence_status,
    run_all,
)
from cohaera.cli import EXIT_ERROR, EXIT_OK
from cohaera.cli import main as cli_main
from cohaera.evidence import (
    APPROVAL_ORIGIN_IN_BAND,
    APPROVAL_SCHEMA,
    BINDING_CONTEXT,
    BINDING_TRUSTED,
    BOUND_EXACT,
    BOUND_SPAN_ONLY,
    INADMISSIBLE,
    INTEGRITY_SCHEMA,
    LEDGER_SCHEMA,
    NO_FRESHNESS,
    P_ARTIFACT_MISMATCH,
    P_DIGEST_MISMATCH,
    P_INVALID,
    P_KEY_REVOKED,
    P_KEY_UNKNOWN,
    P_KEY_WRONG_ROLE,
    P_NO_KEYS,
    P_VERIFIED,
    POLICY_ARTIFACT_BASELINE,
    POLICY_ARTIFACT_MANIFEST,
    POLICY_SIGNATURE_SCHEMA,
    R_CHAIN_BROKEN,
    R_FRESHNESS_UNVERIFIABLE,
    R_FROM_FUTURE,
    R_KEY_EXPIRED,
    R_KEY_NOT_YET_VALID,
    R_KEY_REVOKED,
    R_KEY_UNKNOWN,
    R_KEY_WINDOW_UNCHECKED,
    R_KEY_WRONG_ROLE,
    R_LEDGER_NOT_ADVANCED,
    R_NO_COLLECTOR_KEYS,
    R_NO_STREAM_LEDGER,
    R_PARTIAL_INTEGRITY,
    R_REORDER_BUDGET,
    R_REORDERED,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REPLAY,
    R_SIGNATURE_INVALID,
    R_SIGNATURE_PREFIX_ONLY,
    R_STALE,
    R_STREAM_BOUNDARY_UNVERIFIED,
    R_STREAM_FORKED,
    R_STREAM_REPLAYED,
    R_STREAM_SKIPPED_RECORDS,
    R_UNSIGNED,
    RECEIPT_SCHEMA,
    ROLE_COLLECTOR,
    ROLE_POLICY,
    SEEN_ADVANCED,
    SEEN_NEW,
    TRUST_STORE_SCHEMA,
    W_ALL_KEYS_REVOKED,
    W_LEGACY_SCHEMA,
    W_ROTATION_CYCLE,
    W_SUPERSEDED_OPEN,
    Approval,
    Binding,
    EffectReceipt,
    Freshness,
    Integrity,
    LedgerError,
    PolicySignature,
    PolicySignatureError,
    SeenStream,
    SeenVerdict,
    StreamLedger,
    StreamVerifier,
    TrustStore,
    TrustStoreError,
    arg_digest,
    body_digest,
    chain_seed,
    chain_step,
    file_sha256,
    policy_signing_input,
    signing_input,
    stream_sha256,
    verify_policy_signature,
)
from cohaera.identity import NO_TRUST_CONFIG, trust_config_digest
from cohaera.ingest import assemble, load, read_events
from cohaera.limits import (
    DEFAULT_LIMITS,
    DEFECT_APPROVAL_TYPE,
    DEFECT_INTEGRITY_TYPE,
    DEFECT_RECEIPT_TYPE,
    Limits,
    LimitsError,
)
from cohaera.model import SESSION_SCHEMA, Event, Session
from cohaera.validate import IngestReport
from tools.collector_sign import key_id_for, keys_document, sign_stream
from tools.receipt_adapters import (
    _ADAPTERS,
    ASSURANCE_CLIENT,
    ASSURANCE_LEVELS,
    ASSURANCE_OBJECT,
    ASSURANCE_OPERATION,
    ReceiptAdapterError,
    adapt,
    binding_for,
)

# ---------------------------------------------------------------------------
# 1. The crypto
# ---------------------------------------------------------------------------

# RFC 8032 section 7.1, all four published vectors. These are the only reason to
# believe the pure-Python implementation at all: it was written from the spec,
# and a scheme written from a spec and never checked against its vectors is a
# scheme that works on the author's examples.
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
     "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
     "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_rfc8032_vectors(sk, pk, msg, sig):
    sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
    assert ed25519.public_key(sk) == pk
    assert ed25519.sign(sk, msg) == sig
    assert ed25519.verify(pk, msg, sig)


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_a_flipped_bit_does_not_verify(sk, pk, msg, sig):
    pk, msg, sig = bytes.fromhex(pk), bytes.fromhex(msg), bytearray.fromhex(sig)
    for index in (0, 31, 32, 63):
        bad = bytearray(sig)
        bad[index] ^= 0x01
        assert not ed25519.verify(pk, msg, bytes(bad))


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_signature_malleability_is_rejected(sk, pk, msg, sig):
    """S >= L must not verify.

    The classic Ed25519 verifier bug, and it matters here specifically. Without
    this check, anyone can turn one valid signature into a second, different,
    also-valid signature over the same message -- so a signature would stop
    uniquely identifying the bytes that produced it, and an attacker could
    rewrite the ``sig`` field of a record whose chain they wanted intact.
    """
    pk, msg, sig = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
    s = int.from_bytes(sig[32:], "little")
    if s + ed25519.L >= 2**256:
        pytest.skip("this vector's S + L does not fit in 32 bytes")
    mutated = sig[:32] + (s + ed25519.L).to_bytes(32, "little")
    assert ed25519.verify(pk, msg, sig)
    assert not ed25519.verify(pk, msg, mutated)


def test_verify_never_raises_on_rubbish():
    """Malformed and invalid must produce the same verdict, not an exception.

    A scoring run must not die because one record carried a 3-byte signature.
    """
    pk = bytes.fromhex(RFC8032[1][1])
    for bad_key in (b"", b"\x00" * 31, b"\xff" * 32, None, "notbytes"):
        assert not ed25519.verify(bad_key, b"x", b"\x00" * 64)
    for bad_sig in (b"", b"\x00" * 63, None, 12345):
        assert not ed25519.verify(pk, b"x", bad_sig)


# ---------------------------------------------------------------------------
# 1a. Small-order keys: the forgery
# ---------------------------------------------------------------------------
#
# Verification checks [s]G == R + [k]A. Hand it the identity point as A, the
# identity point as R and S = 0, and both sides are the identity FOR EVERY
# MESSAGE -- one 64-byte string that verifies anything, under a key that has
# never signed anything. RFC 8032 does not require rejecting these and every
# serious implementation does it anyway.
#
# The eight canonical small-order encodings: the identity, the order-2 point,
# two of order 4 and four of order 8.

SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]
IDENTITY_POINT = (1).to_bytes(32, "little")


@pytest.mark.parametrize("message", [b"hello", b"completely different", b"",
                                     b"\xff" * 100])
def test_the_identity_key_does_not_verify_every_message(message):
    """The reported reproduction, verbatim. This returned True for all four."""
    signature = IDENTITY_POINT + (0).to_bytes(32, "little")
    assert not ed25519.verify(IDENTITY_POINT, message, signature)


@pytest.mark.parametrize("encoded", SMALL_ORDER)
def test_no_small_order_key_verifies_anything(encoded):
    key = bytes.fromhex(encoded)
    for sig_r in (key, IDENTITY_POINT):
        for scalar in (0, 1, 8):
            signature = sig_r + scalar.to_bytes(32, "little")
            assert not ed25519.verify(key, b"arbitrary message", signature)


@pytest.mark.parametrize("encoded", SMALL_ORDER)
def test_no_small_order_point_is_an_admissible_key(encoded):
    """`[L]A == identity` holds for the IDENTITY too, because the identity times
    anything is the identity. A subgroup check that forgets to exclude the
    torsion subgroup readmits the exact key the forgery used."""
    assert not ed25519.admissible_public_key(bytes.fromhex(encoded))


def test_a_small_order_key_forges_even_with_a_well_formed_r():
    """The A guard, isolated.

    The first version of these tests used R = identity as well as A = identity,
    so the R guard and the A guard each caught the case and a mutation removing
    EITHER still passed. That is a test suite agreeing with itself. Here R is
    ``[s]G`` for a chosen s -- an ordinary point of full order -- and A is the
    identity, so the ``[k]A`` term vanishes and ``[s]G == R`` holds for every
    message. Only the check on A stops it.
    """
    scalar = 12345
    r_bytes = ed25519._compress(ed25519._mul(ed25519._G, scalar))
    signature = r_bytes + scalar.to_bytes(32, "little")
    assert not ed25519._is_small_order(ed25519._decompress(r_bytes)), (
        "R must NOT be small order here, or this stops isolating the A guard")
    for message in (b"hello", b"completely different", b"third"):
        assert not ed25519.verify(IDENTITY_POINT, message, signature)


def test_a_small_order_r_does_not_verify_under_a_real_key():
    """The other half, and DEFENCE IN DEPTH rather than a demonstrated forgery.

    Under the cofactorless equation this file uses, a small-order R does not by
    itself produce a signature that verifies -- so unlike the check on A, a
    mutation removing this one does not fail a test, and saying otherwise would
    be claiming a proof there is not. It is here because libsodium rejects it,
    because a legitimate R lands in the torsion subgroup with probability about
    2^-252 so refusing it costs no honest signature, and because it removes the
    family of tricks that adds a small-order component to a valid point.
    """
    secret = bytes(range(32))
    public = ed25519.public_key(secret)
    for encoded in SMALL_ORDER:
        signature = bytes.fromhex(encoded) + (0).to_bytes(32, "little")
        assert not ed25519.verify(public, b"m", signature)


def test_a_real_key_and_signature_are_untouched_by_the_guard():
    """A rejection that also rejects honest input is an outage, not a fix."""
    secret = bytes(range(1, 33))
    public = ed25519.public_key(secret)
    assert ed25519.admissible_public_key(public)
    assert ed25519.verify(public, b"legitimate", ed25519.sign(secret, b"legitimate"))


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_the_rfc_keys_are_all_admissible(sk, pk, msg, sig):
    assert ed25519.admissible_public_key(bytes.fromhex(pk))


def test_the_trust_store_refuses_a_key_nobody_could_have_generated():
    """End to end: the forgery needs such a key in the store, and the store is
    where it is refused by name rather than carried and hoped about."""
    doc = {"scheme": TRUST_STORE_SCHEMA,
           "keys": {"ed25519:forged": {
               "key": base64.b64encode(IDENTITY_POINT).decode("ascii"),
               "roles": [ROLE_POLICY]}}}
    with pytest.raises(TrustStoreError, match="usable Ed25519 public key"):
        TrustStore.from_obj(doc)


# ---------------------------------------------------------------------------
# 1b. The fixed-base comb
# ---------------------------------------------------------------------------
#
# `s * G` is half of every verification and G never changes, so the multiples
# are precomputed. The vectors above already prove `verify` still verifies; what
# is left to check is that the table is the same function as double-and-add
# everywhere, not just on the four scalars RFC 8032 happens to publish -- and
# that the SECRET path did not quietly acquire a table lookup along with it.

_COMB_SCALARS = [
    0,                                   # every digit zero: the identity
    1, 2, 15, 16, 17,                    # inside, at, and over one window
    ed25519.L - 1,                       # the largest scalar verify can see
    (1 << 252),                          # a single set bit high up
    0xF << 252,                          # a full digit in the top row
    (1 << 255) - 1,                      # every digit at maximum
]


@pytest.mark.parametrize("scalar", _COMB_SCALARS)
def test_the_comb_agrees_with_double_and_add(scalar):
    assert ed25519._equal(ed25519._mul_base(scalar),
                          ed25519._mul(ed25519._G, scalar))


def test_the_comb_agrees_with_double_and_add_on_random_scalars():
    """Seeded, so a failure is reproducible rather than a story about a run."""
    rng = random.Random(20260808)
    for _ in range(24):
        scalar = rng.randrange(ed25519.L)
        assert ed25519._equal(ed25519._mul_base(scalar),
                              ed25519._mul(ed25519._G, scalar)), scalar


def test_a_scalar_wider_than_the_comb_is_still_multiplied_correctly():
    """The table covers 256 bits and nothing verify sees is wider. The fallback
    exists so that "nothing sees it" being wrong someday is a slow answer rather
    than a wrong one."""
    wide = (1 << 260) + 12345
    assert ed25519._equal(ed25519._mul_base(wide),
                          ed25519._mul(ed25519._G, wide))


_WINDOW_SCALARS = [
    0, 1, 2, 3,                          # below and at the first window
    31, 32, 33,                          # the largest odd table entry, and past it
    (1 << 40) - 1,                       # a long run of ones: every window full
    1 << 253,                            # a single set bit: one window, many zeros
    0b101010101010101010101,             # alternating, so no window ever extends
    ed25519.L - 1,
]


@pytest.mark.parametrize("scalar", _WINDOW_SCALARS)
def test_the_sliding_window_agrees_with_double_and_add(scalar):
    """Windows are chosen from the bits ahead and trimmed to end on a set bit, so
    the cases that break an implementation are the boundaries of that trimming:
    runs of ones, isolated bits, and alternating bits that never let a window
    grow."""
    point = ed25519._mul(ed25519._G, 0x1234_5678_9abc_def0)
    assert ed25519._equal(ed25519._mul_var(point, scalar),
                          ed25519._mul(point, scalar))


def test_the_sliding_window_agrees_on_random_points_and_scalars():
    rng = random.Random(20260809)
    for _ in range(8):
        point = ed25519._mul(ed25519._G, rng.randrange(1, ed25519.L))
        scalar = rng.randrange(ed25519.L)
        assert ed25519._equal(ed25519._mul_var(point, scalar),
                              ed25519._mul(point, scalar)), (point, scalar)


def test_the_sliding_window_handles_the_identity_as_a_base_point():
    """Not reachable through ``verify`` -- a public key that decodes to the
    identity is a broken key, not a valid one -- but the multiplication is a
    multiplication and must not depend on that being true elsewhere."""
    assert ed25519._equal(ed25519._mul_var(ed25519._IDENTITY, 12345),
                          ed25519._IDENTITY)


@pytest.mark.parametrize("sk,pk,msg,sig", RFC8032)
def test_the_secret_path_uses_no_fast_multiplication(sk, pk, msg, sig,
                                                     monkeypatch):
    """The security decision behind every table here, as an assertion.

    The comb routines index a table with the scalar's digits and ``_mul_var``
    branches on runs of its bits. Either is fine for a scalar out of a
    signature, which is public. Neither belongs on a path handling a secret,
    and the module docstring says so -- so make ``sign`` and ``public_key``
    prove they still produce the RFC vectors with all of them booby-trapped.
    """
    def refuse(*_args, **_kwargs):
        raise AssertionError("a secret scalar reached a table-driven multiply")

    for name in ("_mul_base", "_mul_var", "_comb_mul", "_key_comb"):
        monkeypatch.setattr(ed25519, name, refuse)
    sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
    assert ed25519.public_key(sk) == pk
    assert ed25519.sign(sk, msg) == sig


# -- combs for signers' keys -------------------------------------------------
#
# These are the only tests in the file that care about module state surviving
# between calls, so they are the only ones that have to clean up after
# themselves. Without the fixture they would pass or fail depending on what ran
# before them, which under `pytest-randomly` means depending on the day.


@pytest.fixture
def fresh_key_combs():
    combs, uses = dict(ed25519._KEY_COMBS), dict(ed25519._KEY_USES)
    ed25519._KEY_COMBS.clear()
    ed25519._KEY_USES.clear()
    yield
    ed25519._KEY_COMBS.clear()
    ed25519._KEY_COMBS.update(combs)
    ed25519._KEY_USES.clear()
    ed25519._KEY_USES.update(uses)


def _signed(index: int) -> tuple[bytes, bytes, bytes]:
    secret = bytes([index + 1]) + bytes(31)
    return ed25519.public_key(secret), b"payload", ed25519.sign(secret, b"payload")


def test_a_key_earns_a_comb_by_repeating_and_a_one_off_key_does_not(
        fresh_key_combs):
    """A table costs 7 ms and pays back after about four uses, so a key that
    turns up once must not get one -- a stream of single-record sessions from
    many collectors would otherwise be slower than doing nothing."""
    hot, msg, sig = _signed(0)
    cold, cold_msg, cold_sig = _signed(1)

    for _ in range(ed25519._KEY_COMB_USES - 1):
        assert ed25519.verify(hot, msg, sig)
    assert hot not in ed25519._KEY_COMBS, "a table was built before it paid off"

    assert ed25519.verify(hot, msg, sig)
    assert hot in ed25519._KEY_COMBS

    assert ed25519.verify(cold, cold_msg, cold_sig)
    assert cold not in ed25519._KEY_COMBS


def test_the_verdict_is_the_same_either_side_of_the_table(fresh_key_combs):
    """The table changes how ``k * A`` is computed and nothing else. A good
    signature must verify and a bad one must not, both before the key has earned
    a table and after."""
    pub, msg, sig = _signed(2)
    forged = sig[:32] + bytes(a ^ 1 for a in sig[32:])

    assert ed25519.verify(pub, msg, sig)
    assert not ed25519.verify(pub, msg, forged)
    assert pub not in ed25519._KEY_COMBS

    for _ in range(ed25519._KEY_COMB_USES):
        ed25519.verify(pub, msg, sig)
    assert pub in ed25519._KEY_COMBS

    assert ed25519.verify(pub, msg, sig)
    assert not ed25519.verify(pub, msg, forged)
    assert not ed25519.verify(pub, b"different", sig)


def test_the_tables_never_outgrow_their_cap(fresh_key_combs):
    """302 KB each, and how many keys a run sees is decided outside this file.

    There is no eviction on purpose: a cache that evicted would let a stream
    alternating between more hot keys than it holds rebuild a table per
    verification, which is far slower than never having cached at all. Keys
    past the cap keep the sliding window, which is what they would have used
    anyway -- so the cap costs correctness nothing and bounds the memory
    absolutely.
    """
    keys = [_signed(i) for i in range(ed25519._MAX_KEY_COMBS + 4)]
    for _ in range(ed25519._KEY_COMB_USES + 1):
        for pub, msg, sig in keys:
            assert ed25519.verify(pub, msg, sig)
            assert not ed25519.verify(pub, b"tampered", sig)

    assert len(ed25519._KEY_COMBS) == ed25519._MAX_KEY_COMBS
    assert len(ed25519._KEY_USES) <= ed25519._MAX_TRACKED_KEYS


def test_the_use_counter_is_bounded_too(fresh_key_combs):
    """The smaller half of the same argument. Keys reaching ``verify`` have
    already been found in the operator's trust store, so the population is
    bounded by ``max_collector_keys`` -- this is what makes that a belt rather
    than the only thing holding the trousers up."""
    ed25519._KEY_USES.update({bytes([i]) * 32: 1
                              for i in range(ed25519._MAX_TRACKED_KEYS)})
    pub, msg, sig = _signed(3)
    for _ in range(ed25519._KEY_COMB_USES + 2):
        assert ed25519.verify(pub, msg, sig)
    assert len(ed25519._KEY_USES) == ed25519._MAX_TRACKED_KEYS
    assert pub not in ed25519._KEY_COMBS, (
        "a key got a table without ever being counted")


def test_the_comb_is_not_built_until_something_verifies():
    """Two claims in one subprocess, because both are about module state that
    the rest of the suite will have already dirtied.

    Built lazily: a `cohaera score` over telemetry carrying no signatures --
    still the common case -- must not pay 7 ms and 960 points for a table it
    never reads.

    And NOT built by signing. `sign` and `public_key` multiply by a secret, and
    the module docstring says they keep double-and-add so that a secret's digits
    never index a table. That is a claim about the code, so it is a test.
    """
    script = (
        "import sys; sys.path.insert(0, 'src')\n"
        "from cohaera import ed25519 as e\n"
        "built = lambda: e._comb.cache_info().currsize\n"
        "assert not built(), 'built at import'\n"
        "seed = bytes(range(32))\n"
        "pub = e.public_key(seed)\n"
        "sig = e.sign(seed, b'x')\n"
        "assert not built(), 'signing built the comb'\n"
        "assert e.verify(pub, b'x', sig)\n"
        "assert built(), 'verifying did not build the comb'\n"
        "print('ok')\n"
    )
    root = Path(__file__).resolve().parent.parent
    done = subprocess.run([sys.executable, "-c", script], cwd=root,
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "ok"


# ---------------------------------------------------------------------------
# 2. Parsing: malformed must read as ABSENT
# ---------------------------------------------------------------------------

GOOD_INTEGRITY = {"scheme": INTEGRITY_SCHEMA, "stream_id": "s1", "seq": 0,
                  "prev": "ab" * 32, "chain": "cd" * 32}
GOOD_RECEIPT = {"scheme": RECEIPT_SCHEMA, "authority": "aws:s3:eu-west-2",
                "kind": "object_version", "identifier": "3sL4kqtJ",
                "binding": {"span_id": "sp-1", "tool_id": "object_put",
                            "arg_digest": arg_digest({"key": "x"})}}
GOOD_APPROVAL = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
                 "subject": {"span_id": "sp-1", "tool_id": "object_put",
                             "arg_digest": arg_digest({"key": "x"})},
                 "granted_by": "user:alice", "granted_at": 10.0,
                 "expires_at": 100.0, "enforcement": "blocking"}


@pytest.mark.parametrize("mutation", [
    {"scheme": "cohaera.integrity:2"},      # a scheme this version cannot read
    {"scheme": None},
    {"stream_id": 17},                      # not a string
    {"stream_id": True},                    # bool is not a stream, even though
                                            # Python would happily index on it
    {"seq": -1},
    {"seq": True},                          # True == 1 aliasing, again
    {"seq": "0"},
    {"sig": "not base64!!"},
    {"sig": base64.b64encode(b"short").decode()},
])
def test_a_malformed_integrity_object_is_absent_not_weaker(mutation):
    obj = {**GOOD_INTEGRITY, **mutation}
    parsed, codes = Integrity.parse(obj, DEFAULT_LIMITS)
    assert parsed is None, f"{mutation} was accepted"
    assert DEFECT_INTEGRITY_TYPE in codes


@pytest.mark.parametrize("mutation", [
    {"scheme": "other"},
    {"authority": None},
    {"identifier": ""},
    {"binding": "sp-1"},                    # a string is not a binding
    {"binding": None},
])
def test_a_malformed_receipt_is_absent(mutation):
    parsed, codes = EffectReceipt.parse({**GOOD_RECEIPT, **mutation},
                                        DEFAULT_LIMITS)
    assert parsed is None
    assert DEFECT_RECEIPT_TYPE in codes


@pytest.mark.parametrize("mutation", [
    {"decision": "maybe"},
    {"decision": True},
    {"subject": {}},                        # names no span: binds to nothing
    {"subject": {"tool_id": "object_put"}},
    {"scheme": "cohaera.approval:0"},
])
def test_a_malformed_approval_is_absent(mutation):
    parsed, codes = Approval.parse({**GOOD_APPROVAL, **mutation}, DEFAULT_LIMITS)
    assert parsed is None
    assert DEFECT_APPROVAL_TYPE in codes


def test_an_unreadable_enforcement_degrades_to_undeclared_not_to_blocking():
    """The one place fail-closed would be wrong.

    Every other malformed field here fails towards MORE suspicion. This one
    fails towards less, on purpose: treating a bad value as ``blocking`` would
    let a producer's serialiser bug manufacture a critical finding, and a
    detector that a typo can make cry wolf is worse than one that stays quiet
    and records that it stayed quiet.
    """
    parsed, codes = Approval.parse({**GOOD_APPROVAL, "enforcement": "BLOCKING!"},
                                   DEFAULT_LIMITS)
    assert parsed is not None
    assert parsed.enforcement == "undeclared"
    assert codes


def test_an_unprefixed_digest_is_not_a_digest():
    """A bare hex string must not bind.

    Accepting one would compare unequal to everything Cohaera computes, which
    reads downstream as an attacker reusing an approval -- a producer's
    formatting choice turned into a security finding.
    """
    subject = {"span_id": "sp-1", "arg_digest": "a" * 64}
    parsed, _ = Approval.parse({**GOOD_APPROVAL, "subject": subject},
                               DEFAULT_LIMITS)
    assert parsed is not None and parsed.subject.arg_digest is None


def test_collector_key_file_is_refused_rather_than_half_loaded():
    for bad in (
        {"keys": {"k": "AAAA"}},                                # no scheme
        {"scheme": "cohaera.collector_keys:1", "keys": {}},     # empty
        {"scheme": "cohaera.collector_keys:1", "keys": {"k": "!!!"}},
        {"scheme": "cohaera.collector_keys:1",
         "keys": {"k": base64.b64encode(b"tooshort").decode()}},
    ):
        with pytest.raises(TrustStoreError):
            TrustStore.from_obj(bad)


# ---------------------------------------------------------------------------
# 3. The stream verifier
# ---------------------------------------------------------------------------

SECRET = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUBLIC = ed25519.public_key(SECRET)
KEY_ID = key_id_for(PUBLIC)
KEYS = TrustStore.from_obj(keys_document(PUBLIC, KEY_ID))


def _records(n: int = 6, sid: str = "sess-1") -> list[dict]:
    return [{"event_type": "tool_start", "session_id": sid,
             "timestamp": 1000.0 + i, "span_id": f"sp-{i}",
             "tool_name": "alert_read", "data": {"action": "invoke_tool"}}
            for i in range(n)]


def _run(records: list[dict], keys=KEYS, limits=DEFAULT_LIMITS,
         order: list[int] | None = None,
         freshness=NO_FRESHNESS) -> StreamVerifier:
    v = StreamVerifier(keys=keys, limits=limits, freshness=freshness)
    seq = order if order is not None else range(len(records))
    for i in seq:
        raw = records[i]
        e = Event(raw=raw, limits=limits)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    return v


def test_a_clean_signed_stream_verifies():
    signed = sign_stream(_records(), "stream-a", SECRET, KEY_ID)
    state = _run(signed).for_session("sess-1")
    assert not state.inadmissible
    assert state.signatures_verified == 6
    assert state.attested


def test_deleting_a_record_is_detected_as_a_gap():
    """E13's naive case, which before this was catchable only by accident.

    A deleted event was previously visible only when the missing call happened
    to break a learned bigram. A sequence with a hole in it is not luck.
    """
    signed = sign_stream(_records(), "stream-a", SECRET, KEY_ID)
    del signed[3]
    state = _run(signed).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert state.gaps == [{"missing_from": 3, "missing_to": 3, "missing_count": 1}]


def test_records_after_a_deletion_are_not_reported_as_reordered():
    """Found by running the CLI over a tampered stream, not by reading the code.

    Every record after a gap has to be held while the verifier waits for the one
    that never arrives, and counting them on release made a DELETION report
    ``INTEGRITY_RECORDS_REORDERED`` alongside its gap. To an analyst that reads
    as a delivery problem sitting next to a tamper signal, which is the one
    reading this check exists to prevent.
    """
    signed = sign_stream(_records(8), "stream-a", SECRET, KEY_ID)
    del signed[3]
    state = _run(signed).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert R_REORDERED not in state.codes
    assert state.reordered == 0


def test_one_deletion_does_not_read_as_a_wholly_forged_stream():
    """After a gap the verifier resyncs on the survivor's declared predecessor.

    Without that, every record after a deletion also fails to chain, one edit
    reads as total forgery, and -- worse -- the LOCATION of the edit is lost in
    the noise. Localising is half the value of a chain.
    """
    signed = sign_stream(_records(10), "stream-a", SECRET, KEY_ID)
    del signed[4]
    state = _run(signed).for_session("sess-1")
    assert R_SEQUENCE_GAP in state.codes
    assert not state.chain_breaks, "the surviving records should still chain"
    assert state.signatures_verified == 9


def test_modifying_a_record_breaks_the_chain_and_localises():
    signed = sign_stream(_records(), "stream-a", SECRET, KEY_ID)
    signed[2] = {**signed[2], "tool_name": "object_put"}
    state = _run(signed).for_session("sess-1")
    assert R_CHAIN_BROKEN in state.codes
    assert state.chain_breaks == [2], "the break must name the record that moved"


def test_reordering_is_reported_as_reordering_and_not_as_deletion():
    """The difference between a page at 3am and a healthy streaming path."""
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    state = _run(signed, order=[0, 2, 1, 3, 5, 4]).for_session("sess-1")
    assert R_SEQUENCE_GAP not in state.codes
    assert R_REORDERED in state.codes
    assert state.reordered == 2
    assert not state.inadmissible


def test_replaying_a_record_is_detected():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run([*signed, signed[1]]).for_session("sess-1")
    assert R_SEQUENCE_REPLAY in state.codes


def test_a_forged_signature_does_not_verify():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    sidecar = dict(signed[2]["integrity"])
    raw = bytearray(base64.b64decode(sidecar["sig"]))
    raw[10] ^= 0x01
    sidecar["sig"] = base64.b64encode(bytes(raw)).decode()
    signed[2] = {**signed[2], "integrity": sidecar}
    state = _run(signed).for_session("sess-1")
    assert R_SIGNATURE_INVALID in state.codes
    assert state.bad_signatures == [2]


def test_a_key_the_operator_did_not_supply_is_not_trusted():
    other = ed25519.public_key(bytes.fromhex("11" * 32))
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=TrustStore.from_obj(
        keys_document(other, "ed25519:someone-else"))).for_session("sess-1")
    assert R_KEY_UNKNOWN in state.codes
    assert state.signatures_verified == 0


def test_without_keys_signatures_are_parsed_and_not_verified():
    """And that state is NAMED, rather than looking like a pass."""
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=TrustStore()).for_session("sess-1")
    assert R_NO_COLLECTOR_KEYS in state.codes
    assert state.signatures_verified == 0
    assert not state.inadmissible, "unverified is not the same as failed"


def test_stripping_the_sidecar_from_the_edited_record_is_itself_detected():
    """The obvious way round a chain, closed.

    A record with no integrity object cannot fail a chain check, so an attacker
    who edits one record would simply delete its sidecar. A session where some
    records are attested and others are not is that shape, and it is reported.
    """
    signed = sign_stream(_records(5), "stream-a", SECRET, KEY_ID)
    signed[2] = {k: v for k, v in signed[2].items() if k != "integrity"}
    state = _run(signed).for_session("sess-1")
    assert R_PARTIAL_INTEGRITY in state.codes
    assert state.inadmissible


def test_the_reorder_buffer_is_bounded_and_says_when_the_bound_decided():
    """A producer chooses how far out of order it delivers. That is a budget.

    When the bound forces the call rather than the evidence, the verdict has to
    say which of the two it was, or a bound becomes an undeclared heuristic.
    """
    limits = DEFAULT_LIMITS.with_overrides(max_reorder_window=2)
    signed = sign_stream(_records(8), "stream-a", SECRET, KEY_ID)
    state = _run(signed, limits=limits,
                 order=[0, 5, 6, 7, 1, 2, 3, 4]).for_session("sess-1")
    assert R_REORDER_BUDGET in state.codes
    assert R_SEQUENCE_GAP in state.codes


def test_the_signature_budget_is_bounded():
    """Verification is a couple of milliseconds of scalar multiplication per
    record and the producer decides how many records there are. The fixed-base
    comb made that constant smaller; it did not make it a constant."""
    limits = DEFAULT_LIMITS.with_overrides(max_signature_verifications=2)
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    v = _run(signed, limits=limits)
    assert v.signatures_verified == 2
    assert v.signature_budget_exhausted


def test_joining_a_stream_midway_is_declared_rather_than_assumed():
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    state = _run(signed[3:]).for_session("sess-1")
    assert "INTEGRITY_STREAM_JOINED_MIDSTREAM" in state.codes
    assert not state.inadmissible, "records before the join are absent, not bad"


def test_integrity_is_verified_in_arrival_order_not_clock_order():
    """Sessions are assembled clock-sorted; streams are written in arrival order.

    Verifying over the sorted list would reorder the stream before checking
    whether it had been reordered, so any clock skew in the input would read as
    a delivery fault. This record set is signed in arrival order and carries a
    deliberately out-of-order clock.
    """
    records = _records(5)
    records[1]["timestamp"] = 9999.0            # a skewed clock, not a reorder
    signed = sign_stream(records, "stream-a", SECRET, KEY_ID)
    events = [Event(raw=r) for r in signed]
    sessions = assemble(events, keys=KEYS)
    assert len(sessions) == 1
    assert not sessions[0].integrity.inadmissible
    assert sessions[0].integrity.signatures_verified == 5


# ---------------------------------------------------------------------------
# 4. Approval binding and the CH04 split
# ---------------------------------------------------------------------------

ARGS = {"recipient": "alice@example.com"}
OTHER_ARGS = {"recipient": "attacker@example.net"}


def _session(*, enforcement: str | None, approval: dict | None = None,
             call_args: dict | None = None,
             manifest: CapabilityManifest | None = None) -> Session:
    """A policy event, then one consequential call that completed."""
    policy: dict = {"event_type": "cost_threshold_exceeded", "session_id": "s",
                    "timestamp": 100.0,
                    "data": {"action": "policy_event", "threshold_usd": 0.5,
                             "policy_id": "cost-guard"}}
    if enforcement is not None:
        policy["data"]["enforcement"] = enforcement
    if approval is not None:
        policy["data"]["approval"] = approval
    start = {"event_type": "tool_start", "session_id": "s", "timestamp": 110.0,
             "span_id": "sp-send", "tool_name": "send_email",
             "data": {"action": "invoke_tool", "reversible": False,
                      "tool_args": call_args if call_args is not None else ARGS}}
    end = {"event_type": "tool_end", "session_id": "s", "timestamp": 111.0,
           "span_id": "sp-send", "tool_name": "send_email",
           "data": {"action": "invoke_tool", "result": "success"}}
    s = Session(session_id="s", events=[Event(raw=r) for r in (policy, start, end)],
                manifest=manifest or CapabilityManifest())
    s.seal()
    return s


def _approval(**kw) -> dict:
    base = {"scheme": APPROVAL_SCHEMA, "decision": "allow",
            "subject": {"span_id": "sp-send", "tool_id": "send_email",
                        "arg_digest": arg_digest(ARGS)},
            "granted_by": "user:alice", "granted_at": 100.0, "expires_at": 200.0}
    base.update(kw)
    return base


def test_an_advisory_control_no_longer_fires_at_all():
    """The corpus's largest single source of false positives, closed by a field.

    An advisory threshold is a notification and continuing past it is the
    intended behaviour. Firing on it was never a detection -- it was Cohaera
    not having been told what the control was for.
    """
    assert ch04_guardrail_overrun(_session(enforcement="advisory")) == []


def test_a_blocking_control_with_no_approval_is_a_bypass_and_may_say_so():
    findings = ch04_guardrail_overrun(_session(enforcement="blocking"))
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert "bypassed" in findings[0].title.lower()
    assert findings[0].evidence["approval_states"] == ["no_approval"]


def test_a_blocking_control_with_a_bound_approval_does_not_fire():
    findings = ch04_guardrail_overrun(
        _session(enforcement="blocking", approval=_approval()))
    assert findings == []


def test_an_approval_for_different_arguments_does_not_cover_the_call():
    """The whole mechanism, in one test.

    An approval for send_email to alice must not cover send_email to an
    attacker. Before argument binding, nothing stopped it -- and the two calls
    are indistinguishable at the span and tool level, which is exactly why
    span-only binding is reported as the weaker thing it is.
    """
    s = _session(enforcement="blocking", approval=_approval(),
                 call_args=OTHER_ARGS)
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == ["approval_for_other_arguments"]


def test_an_expired_approval_is_not_an_approval():
    s = _session(enforcement="blocking",
                 approval=_approval(granted_at=1.0, expires_at=50.0))
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == ["approval_expired"]


# R-10. The approval half of the same fault. ``Approval.parse`` already refuses
# a subject with no span, so the reachable incomplete subsets are the three that
# name one.
_INCOMPLETE_SUBJECTS = [
    {"span_id": "sp-send"},
    {"span_id": "sp-send", "tool_id": "send_email"},
    {"span_id": "sp-send", "arg_digest": arg_digest(ARGS)},
]


@pytest.mark.parametrize("subject", _INCOMPLETE_SUBJECTS,
                         ids=lambda s: "+".join(sorted(s)))
def test_an_incompletely_bound_approval_does_not_suppress_a_bypass(subject):
    """An approval for ``send_email`` covers ``send_email`` to anyone.

    That is the failure argument binding exists to prevent, and until R-10 a
    span-only approval silenced CH04 outright -- the check reported nothing at
    all, rather than reporting a bypass approved on weaker evidence than the
    schema was designed to carry.
    """
    s = _session(enforcement="blocking", approval=_approval(subject=subject))
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == [APPROVAL_SPAN_ONLY]


def test_an_incompletely_bound_approval_is_not_a_covering_approval():
    s = _session(enforcement="blocking",
                 approval=_approval(subject={"span_id": "sp-send",
                                             "tool_id": "send_email"}))
    call = s.tool_calls[0]
    assert s.approvals_for(call)          # it was presented
    assert s.covering_approval(call) is None   # it does not cover


def test_an_approval_is_recorded_as_a_claim_with_its_origin():
    """An in-band approval is an approval CLAIM.

    It arrives on the same event stream the agent produces, so "approved" in a
    verdict is the producer's assertion that a decision was made, not an
    authorization fact Cohaera established. The origin is emitted so an analyst
    can tell the two apart without reading this docstring.
    """
    s = _session(enforcement="blocking", approval=_approval())
    call = s.tool_calls[0]
    covering = s.covering_approval(call)
    assert covering is not None
    assert covering.approval.origin == APPROVAL_ORIGIN_IN_BAND
    assert covering.approval.as_dict()["approval_origin"] == APPROVAL_ORIGIN_IN_BAND
    findings = ch04_guardrail_overrun(_session(enforcement="blocking"))
    assert findings[0].evidence["approval_origins"] == []


def test_a_span_only_denial_still_annotates_rather_than_silencing():
    """Precedence is unchanged for refusals, but the binding is not.

    A DENY that does not name the arguments is still a refusal presented for
    this span, and a completed call after one is still worth reporting -- but it
    is reported as a weaker claim than a DENY bound to the exact arguments.
    """
    s = _session(enforcement="blocking",
                 approval=_approval(decision="deny",
                                    subject={"span_id": "sp-send",
                                             "tool_id": "send_email"}))
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == [APPROVAL_SPAN_ONLY]


def test_an_explicit_denial_is_a_bypass_even_on_an_advisory_control():
    """A refusal naming the exact call outranks the control's own semantics.

    An advisory notice is a suggestion. A DENY bound to this span and these
    arguments is not, and a completed call after one is the policy engine being
    overruled whatever the threshold was for.
    """
    s = _session(enforcement="advisory", approval=_approval(decision="deny"))
    findings = ch04_guardrail_overrun(s)
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["approval_states"] == ["denied"]


def test_undeclared_semantics_keep_the_old_check_and_the_old_wording():
    """Backwards compatibility is a security property here.

    Every deployment that emits nothing new must behave exactly as it did, or
    upgrading Cohaera silently changes what an existing Sigma rule matches.
    """
    findings = ch04_guardrail_overrun(_session(enforcement=None))
    assert [f.check for f in findings] == [CH04_COMPLETED]
    assert "carries no declaration of policy semantics" in findings[0].detail


def test_the_manifest_outranks_an_in_band_advisory_claim():
    """EVASION.md E20, and the answer to it.

    ``enforcement`` arrives in band, and a value of ``advisory`` SUPPRESSES a
    finding, so an agent that wanted CH04 quiet would send it. An operator's
    manifest declaration wins, for the same reason and with the same precedence
    as a tool capability.
    """
    manifest = CapabilityManifest.from_obj({
        "tools": {"send_email": {"effects": ["egress"], "reversible": False}},
        "policies": {"cost-guard": {"enforcement": "blocking"}},
    })
    findings = ch04_guardrail_overrun(
        _session(enforcement="advisory", manifest=manifest))
    assert [f.check for f in findings] == [CH04_BYPASSED]
    assert findings[0].evidence["policy_enforcement_source"] == "manifest"


def test_believing_an_in_band_declaration_costs_confidence_and_says_why():
    s = _session(enforcement="blocking")
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH04_guardrail_overrun")
    assert "POLICY_ENFORCEMENT_DECLARED_IN_BAND" in contract["reasons"]
    assert contract["confidence"] < 1.0


def test_a_dangling_approval_is_reported():
    s = _session(enforcement="blocking", approval=_approval(
        subject={"span_id": "sp-nonexistent", "tool_id": "send_email"}))
    assert len(s.dangling_approvals) == 1
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH04_guardrail_overrun")
    assert "APPROVAL_MATCHES_NO_CALL" in contract["reasons"]


# ---------------------------------------------------------------------------
# 5. CH07: the asymmetry
# ---------------------------------------------------------------------------


def _call_session(result: str, receipt: dict | None,
                  call_args: dict | None = None) -> Session:
    start = {"event_type": "tool_start", "session_id": "s", "timestamp": 10.0,
             "span_id": "sp-1", "tool_name": "send_email",
             "data": {"action": "invoke_tool", "reversible": False,
                      "tool_args": call_args if call_args is not None else ARGS}}
    end_data: dict = {"action": "invoke_tool", "result": result}
    if receipt is not None:
        end_data["effect_receipt"] = receipt
    end = {"event_type": "tool_end" if result == "success" else "tool_error",
           "session_id": "s", "timestamp": 11.0, "span_id": "sp-1",
           "tool_name": "send_email", "data": end_data}
    s = Session(session_id="s", events=[Event(raw=r) for r in (start, end)])
    s.seal()
    return s


def _receipt(**kw) -> dict:
    base = {"scheme": RECEIPT_SCHEMA, "authority": "smtp:mail.example.com",
            "kind": "message_id", "identifier": "<abc@example.com>",
            "binding": {"span_id": "sp-1", "tool_id": "send_email",
                        "arg_digest": arg_digest(ARGS)}}
    base.update(kw)
    return base


def test_a_reported_failure_with_a_bound_receipt_is_a_detection():
    """The only check here that catches a lying emitter rather than routing
    around one: two fields of the same record disagree, and one of them is not
    the agent's to choose."""
    findings = ch07_effect_contradiction(_call_session("failure", _receipt()))
    assert [f.check for f in findings] == [CH07_CONTRADICTED]
    assert findings[0].severity == "critical"


def test_a_reported_success_with_a_receipt_is_not_a_finding():
    assert ch07_effect_contradiction(_call_session("success", _receipt())) == []


def test_a_reported_success_with_no_receipt_is_coverage_and_not_a_finding():
    """Receipts do not make ``success`` more believable. A finding per
    receiptless call would be a pager storm on day one of any real deployment,
    and it would be a finding about the deployment rather than the agent."""
    s = _call_session("success", None)
    assert ch07_effect_contradiction(s) == []
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH07_effect_contradiction")
    assert contract["status"] == "not_evaluated"
    assert contract["reasons"] == ["NO_EFFECT_RECEIPT"]


def test_a_receipt_copied_onto_another_call_does_not_bind():
    """Without this the mechanism is decorative: a receipt from a call that
    really happened, pasted onto one that did not."""
    stolen = _receipt(binding={"span_id": "sp-99", "tool_id": "send_email",
                               "arg_digest": arg_digest(ARGS)})
    findings = ch07_effect_contradiction(_call_session("failure", stolen))
    assert [f.check for f in findings] == [CH07_UNBOUND]


def test_a_receipt_for_different_arguments_does_not_bind():
    findings = ch07_effect_contradiction(
        _call_session("failure", _receipt(), call_args=OTHER_ARGS))
    assert [f.check for f in findings] == [CH07_UNBOUND]


# R-01. Every PROPER subset of {span_id, tool_id, arg_digest}. A binding that
# omits any of the three constrains less than the checks reading it assume, and
# the seven of them are enumerated rather than sampled because the fault was
# that one unenumerated combination -- all three absent -- reached a critical
# finding.
_INCOMPLETE_BINDINGS = [
    {},
    {"span_id": "sp-1"},
    {"tool_id": "send_email"},
    {"arg_digest": arg_digest(ARGS)},
    {"span_id": "sp-1", "tool_id": "send_email"},
    {"span_id": "sp-1", "arg_digest": arg_digest(ARGS)},
    {"tool_id": "send_email", "arg_digest": arg_digest(ARGS)},
]


@pytest.mark.parametrize("binding", _INCOMPLETE_BINDINGS,
                         ids=lambda b: "+".join(sorted(b)) or "empty")
def test_an_incompletely_bound_receipt_is_never_a_contradiction(binding):
    """The R-01 matrix.

    ``BINDING_TRUSTED`` used to contain ``bound_span_only``, so a receipt that
    named nothing at all -- or named two of the three fields -- carried the
    same authority as one bound to the exact call and the exact arguments. A
    contradiction is a claim that the record disagrees with itself, and it can
    only be made about a receipt that provably refers to THIS call.
    """
    findings = ch07_effect_contradiction(
        _call_session("failure", _receipt(binding=binding)))
    assert CH07_CONTRADICTED not in [f.check for f in findings]


def test_a_receipt_with_an_empty_binding_is_not_a_receipt():
    """R-01 as the review reproduced it, at the parse boundary.

    A failed egress call carrying a valid authority, kind and identifier and
    ``binding: {}`` produced a trusted receipt and a critical CH07
    contradiction. An empty object is not a binding; the receipt is rejected
    and the defect is recorded, per the rejection-vs-defect rule.
    """
    s = _call_session("failure", _receipt(binding={}))
    assert s.tool_calls[0].receipt is None
    assert ch07_effect_contradiction(s) == []
    assert Binding.parse({}, DEFAULT_LIMITS) is None
    parsed, codes = EffectReceipt.parse(_receipt(binding={}), DEFAULT_LIMITS)
    assert parsed is None and DEFECT_RECEIPT_TYPE in codes


def test_a_partially_bound_receipt_on_a_failed_call_is_reported_as_itself():
    """Not a contradiction, and not silence either.

    A receipt that names the span and the tool but not the arguments, arriving
    on a call the telemetry reports as failed, is the shape CH07 exists to look
    at with a field missing. Downgrading it to nothing would lose the only
    signal there is; calling it a contradiction claims a binding that was never
    established.
    """
    findings = ch07_effect_contradiction(_call_session(
        "failure", _receipt(binding={"span_id": "sp-1",
                                     "tool_id": "send_email"})))
    assert [f.check for f in findings] == [CH07_PARTIAL]
    assert findings[0].severity == "low"
    assert findings[0].evidence["partial_total"] == 1


def test_a_partially_bound_receipt_on_a_successful_call_is_not_a_finding():
    """The pager-storm guard.

    Requiring exact binding must not turn every adapter that omits an argument
    digest into a finding per call. A partial receipt on a call that reported
    success is a producer-shape gap, and it belongs in coverage.
    """
    s = _call_session("success", _receipt(binding={"span_id": "sp-1",
                                                   "tool_id": "send_email"}))
    assert ch07_effect_contradiction(s) == []
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == "CH07_effect_contradiction")
    assert R_RECEIPT_NOT_ARGUMENT_BOUND in contract["reasons"]
    assert contract["confidence"] < 1.0


def test_span_only_is_context_and_never_trust():
    """The constant the fault lived in.

    Stated as a test because the two sets are read from different modules and
    an editor adding a state to the trusted set is exactly how this returns.
    """
    assert BINDING_TRUSTED == frozenset({BOUND_EXACT})
    assert BOUND_SPAN_ONLY in BINDING_CONTEXT
    assert not (BINDING_TRUSTED & BINDING_CONTEXT)


# ---------------------------------------------------------------------------
# 6. Evidence status, CH06, and what the whole design still cannot do
# ---------------------------------------------------------------------------


def test_a_session_with_no_integrity_evidence_is_unattested_not_verified():
    """The default state of every deployment, and the sentence that matters.

    ``unattested`` does not mean tampering was ruled out. It means nothing was
    ever in a position to rule it in.
    """
    s = _call_session("success", None)
    assert evidence_status(s) == EVIDENCE_UNATTESTED
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == CH06_INTEGRITY)
    assert contract["status"] == "not_evaluated"
    assert contract["confidence"] == 0.0


def test_every_finding_carries_how_far_the_evidence_was_established():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    del signed[2]
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    findings, _ = run_all(sessions[0])
    checks = {f.check for f in findings}
    assert CH06_INTEGRITY in checks
    for f in findings:
        # CH06 is exempt: it IS the statement that the evidence failed, and
        # marking it as resting on failed evidence would be circular.
        # R-05: not_applicable, not "verified". CH06's subject IS the
        # integrity evidence, so asking how far that evidence was established
        # is a category error -- and the old value said something false rather
        # than merely incomplete.
        expected = (EVIDENCE_NOT_APPLICABLE if f.check == CH06_INTEGRITY
                    else EVIDENCE_INADMISSIBLE)
        assert f.evidence_status == expected


# R-05. How far the attestation REACHED, which is a different question from
# whether anything was signed -- and the second one is what evidence_status used
# to answer.


def _unsign_tail(signed: list[dict], keep_signed_to: int) -> list[dict]:
    """Strip signatures after ``keep_signed_to``, leaving the chain intact.

    The shape a third-party collector produces when it samples signatures and
    the batch does not end on a signing position. Cohaera's own signer no longer
    emits it -- it always signs the final record -- but the verifier has to
    detect it whoever wrote the stream, which is the whole point.
    """
    out = []
    for record in signed:
        sidecar = dict(record["integrity"])
        if sidecar["seq"] > keep_signed_to:
            sidecar.pop("sig", None)
            sidecar.pop("key_id", None)
        out.append({**record, "integrity": sidecar})
    return out


def _session_of(signed: list[dict], **kw):
    v = StreamVerifier(keys=KEYS, **kw)
    events = []
    for raw in signed:
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, "sess-1")
        events.append(e)
    v.finalise()
    s = Session(session_id="sess-1", events=events)
    s.integrity = v.for_session("sess-1")
    s.seal()
    return s


def test_a_stream_signed_to_its_middle_is_a_prefix_and_not_verified():
    """R-05, the review's fixture, reproduced.

    150 records, signatures at sequence 0 and 100. ``evidence_status`` returned
    ``verified`` because ``signatures_verified > 0`` -- a fact about whether
    signing happened at all, not about what it covered. A signature covers the
    chain head at its own sequence, so it attests every record up to that point
    and nothing after it: 49 records sat past the last attestation, chained and
    vouched for by nobody, under a word an analyst reads as settled.
    """
    signed = _unsign_tail(
        sign_stream(_records(150), "stream-a", SECRET, KEY_ID, sign_every=100),
        keep_signed_to=100)
    s = _session_of(signed)

    assert s.integrity.signatures_verified == 2
    assert evidence_status(s) == EVIDENCE_VERIFIED_PREFIX
    assert not s.integrity.signature_covers_final


def test_the_verified_range_is_carried_rather_than_summarised():
    """"Signed to 100 of 149" is the finding. An analyst asked to trust a
    session needs to see where the attestation stopped, not be told that it
    did."""
    signed = _unsign_tail(
        sign_stream(_records(150), "stream-a", SECRET, KEY_ID, sign_every=100),
        keep_signed_to=100)
    ranges = _session_of(signed).integrity.signature_ranges

    assert ranges == [{"stream_id": "stream-a", "first_seq": 0,
                       "last_seq": 149, "verified_to": 100}]


def test_confidence_is_not_one_when_a_tail_is_unattested():
    """The number that made the old status survivable, and did not.

    With freshness and a ledger in force the other CH06 penalties fall away and
    the contract scored the review's fixture at exactly 1.0 -- fully evaluated,
    no reservation, 49 records attested by nobody.
    """
    signed = _unsign_tail(
        sign_stream(_records(150), "stream-a", SECRET, KEY_ID, sign_every=100),
        keep_signed_to=100)
    s = _session_of(
        signed,
        freshness=Freshness(max_age_s=86400.0, as_of=1200.0,
                            max_future_skew_s=300.0),
        ledger=StreamLedger(streams={}, path=Path("unused")))
    contract = next(c for c in coverage(s, None)["checks"]
                    if c["check"] == CH06_INTEGRITY)

    assert contract["confidence"] < 1.0
    assert R_SIGNATURE_PREFIX_ONLY in contract["reasons"]
    # 101 of 150 records reached, so the share is the multiplier and nothing
    # else is penalising this run.
    assert contract["confidence"] == round(101 / 150, 3)


def test_a_stream_signed_to_its_end_is_complete():
    signed = sign_stream(_records(150), "stream-a", SECRET, KEY_ID,
                         sign_every=100)
    s = _session_of(signed)
    assert evidence_status(s) == EVIDENCE_VERIFIED_COMPLETE
    assert s.integrity.signature_covers_final
    assert s.integrity.signature_coverage == 1.0


def test_the_signer_always_signs_the_final_record():
    """What makes verified_complete reachable for a sampled stream at all.

    Sampling leaves everything after the last signing position attested by
    nobody, and a batch rarely ends on a multiple of the rate. One extra scalar
    multiplication per stream closes it.
    """
    signed = sign_stream(_records(150), "stream-a", SECRET, KEY_ID,
                         sign_every=100)
    positions = [r["integrity"]["seq"] for r in signed
                 if "sig" in r["integrity"]]
    assert positions == [0, 100, 149]


@pytest.mark.parametrize("rate", [0, -1, 1.5, True, "4"])
def test_a_sampling_rate_that_signs_nothing_is_refused(rate):
    """``sign_every=0`` emitted a stream with no signature on any record and
    reported success: `if sign_every and seq % sign_every == 0` short-circuits,
    so the ZeroDivisionError never arrived to give it away. ``-1`` signs
    everything, since seq % -1 == 0 always. An operator tuning a sampling rate
    must not be able to switch signing off by typing a number."""
    with pytest.raises(ValueError, match="sign_every"):
        sign_stream(_records(4), "stream-a", SECRET, KEY_ID, sign_every=rate)


def test_verified_is_no_longer_a_value_this_schema_can_emit():
    """The rename, asserted rather than assumed.

    Stated as a test because `verified` reads as settled and `verified_prefix`
    does not, and a downstream rule written against the old value must fail
    loudly rather than silently match nothing.
    """
    assert "verified" not in EVIDENCE_STATES
    assert EVIDENCE_STATES == {
        "verified_complete", "verified_prefix", "chained_unsigned",
        "unattested", "inadmissible", "not_applicable"}


def test_a_session_is_only_as_attested_as_its_weakest_stream():
    """Two streams, one signed to its end and one not. Averaging would report
    the better half; every stream feeding a session has to be covered."""
    a = sign_stream(_records(4, sid="sess-1"), "stream-a", SECRET, KEY_ID)
    b = _unsign_tail(
        sign_stream(_records(4, sid="sess-1"), "stream-b", SECRET, KEY_ID,
                    sign_every=1),
        keep_signed_to=1)
    s = _session_of(a + b)
    assert evidence_status(s) == EVIDENCE_VERIFIED_PREFIX
    assert 0.0 < s.integrity.signature_coverage < 1.0


def test_ch06_stays_quiet_on_a_stream_that_verifies():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    assert ch06_evidence_integrity(sessions[0]) == []
    assert evidence_status(sessions[0]) == EVIDENCE_VERIFIED_COMPLETE


def test_a_collector_inside_the_agent_gains_nothing_and_the_contract_says_so():
    """The honest limit, asserted so it cannot be quietly dropped later.

    If the signer is reachable from the agent, a perfectly verified stream is a
    perfectly verified stream of whatever the agent chose to say. The coverage
    assumption is the only place a reader is told that.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    contract = next(c for c in coverage(sessions[0], None)["checks"]
                    if c["check"] == CH06_INTEGRITY)
    assert any("blast radius" in a for a in contract["assumptions"])
    assert any("does not say the collector was truthful" in a
               for a in contract["assumptions"])


def test_the_reference_signer_round_trips_through_the_cli(tmp_path):
    """The wire format has a producer, and it is checked against the verifier.

    A format with no reference producer is a specification nobody can implement
    against.
    """
    raw = tmp_path / "raw.jsonl"
    raw.write_text("".join(json.dumps(r) + "\n" for r in _records(4)),
                   encoding="utf-8")
    signed = sign_stream(
        [json.loads(x) for x in raw.read_text(encoding="utf-8").splitlines()],
        "stream-cli", SECRET, KEY_ID)
    out = tmp_path / "signed.jsonl"
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in signed),
                   encoding="utf-8")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(json.dumps(keys_document(PUBLIC, KEY_ID)),
                         encoding="utf-8")

    loaded = TrustStore.from_file(keys_path)
    events = [Event(raw=json.loads(line))
              for line in out.read_text(encoding="utf-8").splitlines()]
    sessions = assemble(events, keys=loaded)
    assert sessions[0].integrity.signatures_verified == 4
    assert not sessions[0].integrity.inadmissible


# ---------------------------------------------------------------------------
# 7. The trust store
# ---------------------------------------------------------------------------

OTHER_SECRET = bytes.fromhex(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
OTHER_PUBLIC = ed25519.public_key(OTHER_SECRET)
OTHER_KEY_ID = key_id_for(OTHER_PUBLIC)

B64 = base64.b64encode(PUBLIC).decode("ascii")
B64_OTHER = base64.b64encode(OTHER_PUBLIC).decode("ascii")


def _store(**entry) -> TrustStore:
    """A one-key trust store for KEY_ID, with whatever the test wants said."""
    spec = {"key": B64, "roles": [ROLE_COLLECTOR]}
    spec.update(entry)
    return TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA,
                                "keys": {KEY_ID: spec}})


def test_a_legacy_key_file_still_loads_and_is_collector_only():
    """Deployments that adopted P1.1 wrote one of these; do not break them.

    The role is not a guess. That schema's NAME is the declaration, so reading
    it as collector-only is faithful rather than lenient -- and it deliberately
    cannot authorise policy signing, because there is nowhere in that format to
    say so.
    """
    store = TrustStore.from_obj({"scheme": "cohaera.collector_keys:1",
                                 "keys": {KEY_ID: B64}})
    assert store.get(KEY_ID).roles == frozenset({ROLE_COLLECTOR})
    assert not store.has_role(ROLE_POLICY)
    assert W_LEGACY_SCHEMA in store.warnings


def test_a_key_with_no_declared_role_is_refused():
    """No default. See _trusted_key.

    Picking a role for an operator who did not state one is how a collector key
    ends up able to sign the manifest that says which of the collector's own
    tools are consequential.
    """
    for roles in (None, [], "collector", ["collector", "root"]):
        spec = {"key": B64}
        if roles is not None:
            spec["roles"] = roles
        with pytest.raises(TrustStoreError):
            TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA,
                                 "keys": {KEY_ID: spec}})


def test_trust_store_refuses_the_legacy_bare_string_form():
    """Mixing the two schemas silently would make `roles` optional in practice."""
    with pytest.raises(TrustStoreError):
        TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA,
                             "keys": {KEY_ID: B64}})


def test_a_window_that_closes_before_it_opens_is_refused():
    """Nothing can be inside it, so every record would read as tampering.

    Refusing the file is the only outcome that does not manufacture a critical
    finding out of a typo.
    """
    with pytest.raises(TrustStoreError):
        _store(not_before=200.0, not_after=100.0)


def test_clock_fields_must_be_finite_numbers():
    for field in ("not_before", "not_after", "revoked_at"):
        for bad in ("2026-01-01", True, float("nan"), float("inf"), {}):
            with pytest.raises(TrustStoreError):
                _store(**{field: bad})


def test_a_key_cannot_replace_itself():
    with pytest.raises(TrustStoreError):
        _store(replaces=KEY_ID)


def test_a_rotation_announced_but_never_enforced_is_reported():
    """The failure that actually happens: the new key is added, the old one is
    left open, and the rotation exists in the file rather than in the verifier.

    A stolen copy of the retired key keeps producing perfectly valid records
    forever, and nothing says so unless something looks.
    """
    store = TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": {
        KEY_ID: {"key": B64, "roles": [ROLE_COLLECTOR]},
        OTHER_KEY_ID: {"key": B64_OTHER, "roles": [ROLE_COLLECTOR],
                       "replaces": KEY_ID},
    }})
    assert W_SUPERSEDED_OPEN in store.warnings

    closed = TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": {
        KEY_ID: {"key": B64, "roles": [ROLE_COLLECTOR], "not_after": 5000.0},
        OTHER_KEY_ID: {"key": B64_OTHER, "roles": [ROLE_COLLECTOR],
                       "not_before": 5000.0, "replaces": KEY_ID},
    }})
    assert W_SUPERSEDED_OPEN not in closed.warnings


def test_a_rotation_cycle_is_reported_rather_than_followed():
    store = TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": {
        KEY_ID: {"key": B64, "roles": [ROLE_COLLECTOR], "replaces": OTHER_KEY_ID},
        OTHER_KEY_ID: {"key": B64_OTHER, "roles": [ROLE_COLLECTOR],
                       "replaces": KEY_ID},
    }})
    assert W_ROTATION_CYCLE in store.warnings


def test_a_store_where_everything_is_revoked_says_so():
    assert W_ALL_KEYS_REVOKED in _store(revoked_at=1.0).warnings


def test_the_semantic_digest_moves_when_the_meaning_moves():
    """A byte digest alone would not distinguish a reformat from a revocation."""
    base = _store()
    assert _store().semantic_digest == base.semantic_digest
    assert _store(revoked_at=1.0).semantic_digest != base.semantic_digest
    assert _store(not_after=1.0).semantic_digest != base.semantic_digest
    assert _store(roles=[ROLE_COLLECTOR, ROLE_POLICY]).semantic_digest \
        != base.semantic_digest


def test_a_revoked_key_makes_the_evidence_inadmissible():
    """And spends no scalar multiplication doing it.

    Revocation is the operator saying somebody else holds this key. A signature
    made by that somebody is a correctly-made signature that means nothing, so
    there is nothing to learn from checking it.
    """
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=_store(revoked_at=999.0)).for_session("sess-1")
    assert R_KEY_REVOKED in state.codes
    assert R_KEY_REVOKED in state.inadmissible
    assert state.signatures_verified == 0


def test_revocation_ignores_the_records_own_clock():
    """The whole reason revocation is absolute. See TrustedKey.

    Every record here is dated long BEFORE the revocation, which is exactly what
    an attacker holding the compromised key would arrange. Believing that date
    means believing a timestamp signed by the person you just declared
    compromised.
    """
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    assert all(r["timestamp"] < 5000.0 for r in signed)
    state = _run(signed, keys=_store(revoked_at=5000.0)).for_session("sess-1")
    assert R_KEY_REVOKED in state.codes


def test_a_policy_key_cannot_attest_telemetry():
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=_store(roles=[ROLE_POLICY])).for_session("sess-1")
    assert R_KEY_WRONG_ROLE in state.codes
    assert R_KEY_WRONG_ROLE in state.inadmissible
    assert state.signatures_verified == 0


def test_a_retired_key_still_signing_is_detected():
    """Rotation, expressed as a window and enforced against the record."""
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=_store(not_after=1002.0)).for_session("sess-1")
    assert R_KEY_EXPIRED in state.codes
    assert R_KEY_EXPIRED in state.inadmissible
    # The records inside the window are fine; only the ones after it are not.
    assert state.codes[R_KEY_EXPIRED] == 1
    assert state.signatures_verified == 4


def test_a_key_used_before_its_window_opens_is_a_different_code():
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=_store(not_before=5000.0)).for_session("sess-1")
    assert R_KEY_NOT_YET_VALID in state.codes
    assert R_KEY_EXPIRED not in state.codes


def test_a_key_with_no_window_produces_no_window_code_at_all():
    """"This key has no window" is not a coverage gap.

    Reporting it as one would put INTEGRITY_KEY_WINDOW_UNCHECKED on every
    well-formed store in existence, which is noise that teaches operators to
    ignore the code for the case that matters.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=_store()).for_session("sess-1")
    assert R_KEY_WINDOW_UNCHECKED not in state.codes


def test_a_windowed_key_with_an_unusable_record_clock_says_it_could_not_check():
    records = _records(3)
    for r in records:
        r["timestamp"] = "yesterday"
    signed = sign_stream(records, "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=_store(not_after=1002.0)).for_session("sess-1")
    assert R_KEY_WINDOW_UNCHECKED in state.codes
    assert R_KEY_WINDOW_UNCHECKED not in state.inadmissible, \
        "could not check is not the same as failed"


def test_the_window_is_judged_only_after_the_signature_holds():
    """The ordering IS the argument, so it is asserted rather than assumed.

    A window check reads the timestamp on the record, and that timestamp is
    worth reading only once the signature has established the collector wrote
    it. Here the signature is broken AND the record is outside the window: the
    verifier must report the signature, because the clock underneath a bad
    signature is a number the producer chose.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    bad = bytearray(base64.b64decode(signed[2]["integrity"]["sig"]))
    bad[0] ^= 0x01
    signed[2]["integrity"]["sig"] = base64.b64encode(bytes(bad)).decode("ascii")
    state = _run(signed, keys=_store(not_after=1000.0)).for_session("sess-1")
    assert R_SIGNATURE_INVALID in state.codes
    assert state.codes[R_SIGNATURE_INVALID] == 1
    # Records 0 and 1 verified and ARE outside the window, so the code is
    # present -- but not for record 2, which never got that far.
    assert state.codes.get(R_KEY_EXPIRED) == 1


def test_the_verdict_records_which_key_vouched_for_a_session():
    """The first question asked when a key turns out to be compromised."""
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed).for_session("sess-1")
    assert state.as_dict()["signing_key_ids"] == [KEY_ID]


# ---------------------------------------------------------------------------
# 8. cohaera.policy_signature:1
# ---------------------------------------------------------------------------

POLICY_SECRET = bytes.fromhex(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
POLICY_PUBLIC = ed25519.public_key(POLICY_SECRET)
POLICY_KEY_ID = key_id_for(POLICY_PUBLIC)
SIGNED_AT = 1785700000


def _policy_store(**entry) -> TrustStore:
    spec = {"key": base64.b64encode(POLICY_PUBLIC).decode("ascii"),
            "roles": [ROLE_POLICY]}
    spec.update(entry)
    return TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA,
                               "keys": {POLICY_KEY_ID: spec}})


def _sign_policy(artifact: str, digest: str, signed_at: int = SIGNED_AT,
                 secret: bytes = POLICY_SECRET,
                 key_id: str = POLICY_KEY_ID) -> PolicySignature:
    sig = ed25519.sign(secret, policy_signing_input(artifact, digest, signed_at))
    return PolicySignature.from_obj({
        "scheme": POLICY_SIGNATURE_SCHEMA, "artifact": artifact,
        "file_sha256": digest, "signed_at": signed_at, "key_id": key_id,
        "sig": base64.b64encode(sig).decode("ascii")})


def _artifact(tmp_path, name: str, body: str) -> tuple[Path, str]:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p, file_sha256(p, 1 << 20)


def test_a_signed_manifest_verifies(tmp_path):
    _p, digest = _artifact(tmp_path, "manifest.json", '{"tools":{}}')
    att = verify_policy_signature(
        _sign_policy(POLICY_ARTIFACT_MANIFEST, digest), digest,
        POLICY_ARTIFACT_MANIFEST, _policy_store())
    assert att.status == P_VERIFIED
    assert att.verified and att.key_id == POLICY_KEY_ID


def test_editing_the_manifest_after_signing_is_detected(tmp_path):
    """The whole point. A manifest that says an egress tool is read_only turns
    CH02, CH03 and CH04 off for that tool without one telemetry record changing.
    """
    p, digest = _artifact(tmp_path, "manifest.json",
                          '{"tools":{"send":{"effects":["egress"]}}}')
    signature = _sign_policy(POLICY_ARTIFACT_MANIFEST, digest)
    p.write_text('{"tools":{"send":{"effects":["read"]}}}', encoding="utf-8")
    att = verify_policy_signature(signature, file_sha256(p, 1 << 20),
                                  POLICY_ARTIFACT_MANIFEST, _policy_store())
    assert att.status == P_DIGEST_MISMATCH
    assert not att.verified


def test_a_baseline_signature_cannot_be_presented_as_a_manifest_signature(tmp_path):
    """Domain separation, checked rather than assumed.

    Both files are signed by the same operator with the same key, so without the
    artifact tag in the signing input AND this comparison, a real signature over
    a baseline would verify perfectly as cover for a swapped manifest.
    """
    _p, digest = _artifact(tmp_path, "shared.bin", "same bytes either way")
    signature = _sign_policy(POLICY_ARTIFACT_BASELINE, digest)
    att = verify_policy_signature(signature, digest, POLICY_ARTIFACT_MANIFEST,
                                  _policy_store())
    assert att.status == P_ARTIFACT_MISMATCH


def test_the_artifact_tag_is_inside_the_signature_not_only_beside_it(tmp_path):
    """Rewriting the tag in the .sig file must break the signature itself.

    If the tag lived only in the JSON, an attacker would edit it and the
    comparison above would pass.
    """
    _p, digest = _artifact(tmp_path, "shared.bin", "same bytes either way")
    baseline_sig = _sign_policy(POLICY_ARTIFACT_BASELINE, digest)
    relabelled = PolicySignature.from_obj({
        "scheme": POLICY_SIGNATURE_SCHEMA,
        "artifact": POLICY_ARTIFACT_MANIFEST, "file_sha256": digest,
        "signed_at": SIGNED_AT, "key_id": POLICY_KEY_ID,
        "sig": base64.b64encode(baseline_sig.sig).decode("ascii")})
    att = verify_policy_signature(relabelled, digest, POLICY_ARTIFACT_MANIFEST,
                                  _policy_store())
    assert att.status == P_INVALID


def test_a_policy_signature_is_not_an_integrity_signature(tmp_path):
    """Cross-protocol separation. The two signing inputs share a key type and
    must never share a message space."""
    _p, digest = _artifact(tmp_path, "manifest.json", "{}")
    assert not policy_signing_input(
        POLICY_ARTIFACT_MANIFEST, digest, SIGNED_AT).startswith(
        INTEGRITY_SCHEMA.encode("utf-8"))


def test_a_collector_key_cannot_sign_policy(tmp_path):
    """The role separation, exercised.

    A collector that could sign the manifest could rewrite the document saying
    which of its own tools are consequential.

    The store here HAS a policy key, so this is the security case rather than
    the configuration one: a real signature by a key the operator trusted for
    something else. A store with no policy key at all is a different mistake and
    gets a different code -- see the test below.
    """
    _p, digest = _artifact(tmp_path, "manifest.json", "{}")
    store = TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": {
        POLICY_KEY_ID: {"key": base64.b64encode(POLICY_PUBLIC).decode("ascii"),
                        "roles": [ROLE_COLLECTOR]},
        OTHER_KEY_ID: {"key": B64_OTHER, "roles": [ROLE_POLICY]},
    }})
    att = verify_policy_signature(_sign_policy(POLICY_ARTIFACT_MANIFEST, digest),
                                  digest, POLICY_ARTIFACT_MANIFEST, store)
    assert att.status == P_KEY_WRONG_ROLE


def test_a_revoked_policy_key_does_not_attest(tmp_path):
    _p, digest = _artifact(tmp_path, "manifest.json", "{}")
    att = verify_policy_signature(_sign_policy(POLICY_ARTIFACT_MANIFEST, digest),
                                  digest, POLICY_ARTIFACT_MANIFEST,
                                  _policy_store(revoked_at=1.0))
    assert att.status == P_KEY_REVOKED


def test_an_unknown_policy_key_and_an_empty_store_read_differently(tmp_path):
    """"I do not know that key" and "I was given no policy keys at all" are
    different operator mistakes and lead to different fixes."""
    _p, digest = _artifact(tmp_path, "manifest.json", "{}")
    signature = _sign_policy(POLICY_ARTIFACT_MANIFEST, digest)
    other = TrustStore.from_obj({"scheme": TRUST_STORE_SCHEMA, "keys": {
        "ed25519:someone-else": {"key": B64_OTHER, "roles": [ROLE_POLICY]}}})
    assert verify_policy_signature(signature, digest, POLICY_ARTIFACT_MANIFEST,
                                   other).status == P_KEY_UNKNOWN
    assert verify_policy_signature(signature, digest, POLICY_ARTIFACT_MANIFEST,
                                   _store()).status == P_NO_KEYS


def test_the_signature_file_is_refused_rather_than_half_loaded():
    good = {"scheme": POLICY_SIGNATURE_SCHEMA,
            "artifact": POLICY_ARTIFACT_MANIFEST, "file_sha256": "ab" * 32,
            "signed_at": SIGNED_AT, "key_id": "k",
            "sig": base64.b64encode(b"\x00" * 64).decode("ascii")}
    PolicySignature.from_obj(good)
    for bad in (
        {**good, "scheme": "something.else:1"},
        {**good, "artifact": "the_universe"},
        {**good, "file_sha256": "ab" * 16},          # too short
        {**good, "file_sha256": "zz" * 32},          # not hex
        {**good, "signed_at": "1785700000"},         # a string is not a clock
        {**good, "signed_at": True},                 # nor is a boolean
        {**good, "key_id": ""},
        {**good, "sig": base64.b64encode(b"\x00" * 32).decode("ascii")},
        {**good, "sig": "!!!not base64!!!"},
    ):
        with pytest.raises(PolicySignatureError):
            PolicySignature.from_obj(bad)


def test_hashing_an_oversized_artifact_is_refused_rather_than_read(tmp_path):
    """C4-02's lesson, applied to the attestation path: the work has to be
    bounded by a number here, not by the size of somebody else's file."""
    p = tmp_path / "huge.jsonl"
    p.write_text("x" * 4096, encoding="utf-8")
    with pytest.raises(PolicySignatureError):
        file_sha256(p, 1024)


# ---------------------------------------------------------------------------
# 9. Freshness, and the replay every other check is blind to
# ---------------------------------------------------------------------------


def test_a_replayed_archive_is_stale_and_otherwise_perfect():
    """The stream is genuine. That is what makes replay a different attack.

    Sequence contiguous, chain intact, every signature valid -- and the records
    are three months old, which is the only thing that gives it away.
    """
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run(signed, freshness=Freshness(max_age_s=3600.0, as_of=9_000_000.0)
                 ).for_session("sess-1")
    assert R_CHAIN_BROKEN not in state.codes
    assert R_SEQUENCE_GAP not in state.codes
    assert state.signatures_verified == 4
    assert R_STALE in state.codes
    assert R_STALE in state.inadmissible


def test_a_stream_inside_the_bound_is_not_stale():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run(signed, freshness=Freshness(max_age_s=3600.0, as_of=1100.0)
                 ).for_session("sess-1")
    assert R_STALE not in state.codes
    assert state.freshness_checked == 4


def test_a_future_dated_record_is_not_reported_as_stale():
    """Clock skew is somebody else's finding. Calling it replay would be wrong
    in the one direction that costs an analyst their trust in the code.

    It is somebody else's finding, and R-13 is where somebody else finally makes
    it: see the two tests below. This one holds the line that STALE stays
    STALE -- an archive replay and a wrong clock are separate remedies and a
    shared code makes both unguessable.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, freshness=Freshness(max_age_s=60.0, as_of=0.0)
                 ).for_session("sess-1")
    assert R_STALE not in state.codes


def test_a_record_dated_a_year_ahead_is_inadmissible_rather_than_fresh():
    """R-13, reproduced.

    ``_records`` is stamped at t=1000; ``as_of`` is a year earlier, so every
    record is dated a year in the future. Before this, ``stale()`` returned
    False and nothing else was computed, so the session read exactly like one
    whose records were written a second ago -- a collector with a wrong clock,
    or one an attacker holds, bought unlimited freshness by adding to a number.

    Inadmissible, not a warning, because the whole argument for trusting the
    timestamp is that it is signed and a replayer cannot re-date it. A record
    dated after the instant it was scored breaks that argument at the root.
    """
    year = 365 * 24 * 3600
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, freshness=Freshness(max_age_s=3600.0,
                                             as_of=1000.0 - year,
                                             max_future_skew_s=300.0)
                 ).for_session("sess-1")
    assert R_FROM_FUTURE in state.codes
    assert R_FROM_FUTURE in state.inadmissible
    assert R_STALE not in state.codes, "a year ahead is not three months old"
    assert state.furthest_future_s is not None
    assert state.furthest_future_s >= year


def test_ordinary_clock_disagreement_is_inside_the_skew_and_says_nothing():
    """The reason the tolerance is not zero.

    Two hosts running NTP disagree by milliseconds and occasionally by seconds.
    A bound with no tolerance would make every collector whose clock runs a
    little fast inadmissible, which is a finding about the estate's time
    synchronisation delivered as a tampering alert.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, freshness=Freshness(max_age_s=3600.0, as_of=990.0,
                                             max_future_skew_s=300.0)
                 ).for_session("sess-1")
    assert R_FROM_FUTURE not in state.codes
    assert R_STALE not in state.codes
    assert state.furthest_future_s is None


def test_future_skew_is_not_answered_when_freshness_is_off():
    """``None``, never ``False``. Not checked is not checked and fine."""
    assert Freshness().from_future(1e12) is None
    assert Freshness(max_age_s=60.0).from_future(1e12) is None
    off = Freshness(max_age_s=60.0, as_of=0.0, max_future_skew_s=300.0)
    assert off.from_future(None) is None
    assert off.from_future(float("nan")) is None


def test_the_skew_tolerance_is_read_as_a_magnitude():
    """A negative tolerance would invert the bound and report every record as
    from the future, which is the C4-05 shape: a number tightening a control
    that instead removes it."""
    f = Freshness(max_age_s=60.0, as_of=0.0, max_future_skew_s=-300.0)
    assert f.from_future(100.0) is False
    assert f.from_future(400.0) is True


def test_freshness_over_an_unsigned_chain_is_reported_as_unverifiable():
    """A chained-but-unsigned record's timestamp is a number the producer chose,
    so aging it would be aging the attacker's own claim.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, keys=TrustStore(),
                 freshness=Freshness(max_age_s=1.0, as_of=9_000_000.0)
                 ).for_session("sess-1")
    assert R_STALE not in state.codes
    assert R_FRESHNESS_UNVERIFIABLE in state.codes
    assert R_FRESHNESS_UNVERIFIABLE not in state.inadmissible


def test_freshness_says_nothing_when_no_bound_was_set():
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed).for_session("sess-1")
    assert R_STALE not in state.codes
    assert R_FRESHNESS_UNVERIFIABLE not in state.codes


def test_coverage_states_that_replay_was_not_considered():
    """The absence has to be SAID. An operator reading a clean CH06 contract
    should not have to know that replay was never in scope for that run.
    """
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    contract = next(c for c in coverage(sessions[0], None)["checks"]
                    if c["check"] == CH06_INTEGRITY)
    assert "NO_FRESHNESS_BOUND" in contract["reasons"]
    assert any("not checked for stream replay" in a
               for a in contract["assumptions"])


def test_the_verdict_records_each_streams_extent_for_cross_run_comparison():
    """Cohaera keeps no state between runs, so this is the only shape replay
    detection can take: write down what was scored and let two verdicts differ.
    """
    signed = sign_stream(_records(5), "stream-a", SECRET, KEY_ID)
    summary = _run(signed).summary()["stream_summary"]
    assert summary[0]["stream_id"] == "stream-a"
    assert (summary[0]["first_seq"], summary[0]["last_seq"]) == (0, 4)
    assert summary[0]["head"]


# ---------------------------------------------------------------------------
# 10. The control surface: what the CLI refuses to do
# ---------------------------------------------------------------------------
#
# A signature nobody acts on is decoration. These assert the three decisions the
# CLI makes on the operator's behalf: refuse when a supplied signature fails,
# refuse when signatures were required and are missing, and record the absence
# honestly when neither applies.


def _policy_fixture(tmp_path, manifest_body='{"tools":{}}'):
    telemetry = tmp_path / "t.jsonl"
    telemetry.write_text(json.dumps(
        {"event_type": "tool_start", "timestamp": 1000.0, "session_id": "a",
         "tool_name": "read_x", "span_id": "S1"}) + "\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(manifest_body, encoding="utf-8")
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"scheme": TRUST_STORE_SCHEMA, "keys": {
        POLICY_KEY_ID: {"key": base64.b64encode(POLICY_PUBLIC).decode("ascii"),
                        "roles": [ROLE_POLICY]}}}), encoding="utf-8")
    sig = tmp_path / "manifest.json.sig"
    signature = _sign_policy(POLICY_ARTIFACT_MANIFEST,
                             file_sha256(manifest, 1 << 20))
    sig.write_text(json.dumps({
        "scheme": POLICY_SIGNATURE_SCHEMA, "artifact": POLICY_ARTIFACT_MANIFEST,
        "file_sha256": signature.file_sha256, "signed_at": signature.signed_at,
        "key_id": signature.key_id,
        "sig": base64.b64encode(signature.sig).decode("ascii")}),
        encoding="utf-8")
    return telemetry, manifest, store, sig


def test_cli_scores_a_signed_manifest_and_records_the_attestation(tmp_path, capsys):
    telemetry, manifest, store, sig = _policy_fixture(tmp_path)
    assert cli_main(["score", str(telemetry), "--tool-manifest", str(manifest),
                     "--tool-manifest-sig", str(sig),
                     "--trust-store", str(store)]) == EXIT_OK
    prov = json.loads(capsys.readouterr().out.strip())["data"]["provenance"]
    att = next(a for a in prov["policy_attestations"]
               if a["artifact"] == POLICY_ARTIFACT_MANIFEST)
    assert att["verified"] and att["key_id"] == POLICY_KEY_ID
    assert prov["trust_store"]["policy_key_count"] == 1


def test_cli_refuses_to_score_when_a_supplied_signature_does_not_hold(tmp_path):
    """The one case where carrying on is worse than never having asked."""
    telemetry, manifest, store, sig = _policy_fixture(tmp_path)
    manifest.write_text('{"tools":{"send":{"effects":["read"]}}}',
                        encoding="utf-8")
    assert cli_main(["score", str(telemetry), "--tool-manifest", str(manifest),
                     "--tool-manifest-sig", str(sig),
                     "--trust-store", str(store)]) == EXIT_ERROR


def _swap_on_second_open(monkeypatch, target: Path, replacement: Path):
    """Atomically replace ``target`` with ``replacement`` after its first open.

    ``rename`` rather than a rewrite, because that is both the realistic attack
    and the only version that proves anything: a descriptor already handed out
    keeps the ORIGINAL inode, so the first reader still sees the honest bytes
    and only a *second resolution of the path* sees the swap. A test that
    truncated the file in place would fail against correct code too, for a
    reason that has nothing to do with the race.

    Returns a one-element list holding the number of times the path was opened.
    """
    real_open = Path.open
    opens = [0]

    def counting_open(self, *a, **kw):
        if self == target:
            opens[0] += 1
            fh = real_open(self, *a, **kw)
            if opens[0] == 1:
                os.rename(replacement, self)
            return fh
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", counting_open)
    return opens


def test_the_manifest_is_parsed_and_hashed_from_the_same_bytes(tmp_path,
                                                               monkeypatch):
    """R-07, reproduced.

    ``CapabilityManifest.from_file`` resolved the path and parsed it; the CLI
    then resolved the SAME PATH again to hash it for the signature. A path is
    not a file. An atomic rename in the window between the two left Cohaera
    scoring one manifest and attesting the digest of another -- and the
    signature held, because it was checked against whichever bytes the second
    read happened to find. The operator's verdict then carried a VERIFIED
    attestation for a file that had not been used.
    """
    _telemetry, manifest, _store, _sig = _policy_fixture(
        tmp_path, manifest_body='{"tools":{"send":{"effects":["egress"]}}}')
    hostile = tmp_path / "hostile.json"
    hostile.write_text('{"tools":{"send":{"effects":["read"]}}}',
                       encoding="utf-8")
    honest_sha = file_sha256(manifest, 1 << 20)

    opens = _swap_on_second_open(monkeypatch, manifest, hostile)
    parsed = CapabilityManifest.from_file(manifest, limits=DEFAULT_LIMITS)

    assert opens[0] == 1, (
        "the manifest must be resolved exactly once; a second resolution is "
        "the race")
    assert parsed.file_sha256 == honest_sha, (
        "the digest carried forward must describe the bytes that were parsed")
    assert parsed.tools["send"].consequential, "the honest bytes were parsed"
    # And the swap really did happen, so the fixture is testing something.
    assert file_sha256(manifest, 1 << 20) != honest_sha


def test_a_swapped_manifest_cannot_borrow_the_honest_files_attestation(
        tmp_path, monkeypatch, capsys):
    """The same race at the CLI boundary, which is where it mattered.

    Before R-07 this run exited OK with a VERIFIED manifest attestation while
    scoring a manifest the signature had never covered. Now the digest comes
    from the bytes that were parsed, so the swap either goes unnoticed -- the
    honest file was read and the honest file was attested -- or is refused. What
    must never happen is a verified attestation over bytes that were not used.
    """
    telemetry, manifest, store, sig = _policy_fixture(
        tmp_path, manifest_body='{"tools":{"send":{"effects":["egress"]}}}')
    hostile = tmp_path / "hostile.json"
    hostile.write_text('{"tools":{"send":{"effects":["read"]}}}',
                       encoding="utf-8")
    honest_sha = file_sha256(manifest, 1 << 20)
    sig.write_text(json.dumps({
        "scheme": POLICY_SIGNATURE_SCHEMA, "artifact": POLICY_ARTIFACT_MANIFEST,
        "file_sha256": honest_sha, "signed_at": SIGNED_AT,
        "key_id": POLICY_KEY_ID,
        "sig": base64.b64encode(ed25519.sign(
            POLICY_SECRET,
            policy_signing_input(POLICY_ARTIFACT_MANIFEST, honest_sha,
                                 SIGNED_AT))).decode("ascii")}),
        encoding="utf-8")

    _swap_on_second_open(monkeypatch, manifest, hostile)
    code = cli_main(["score", str(telemetry), "--tool-manifest", str(manifest),
                     "--tool-manifest-sig", str(sig),
                     "--trust-store", str(store)])
    assert code == EXIT_OK
    prov = json.loads(capsys.readouterr().out.strip())["data"]["provenance"]
    att = next(a for a in prov["policy_attestations"]
               if a["artifact"] == POLICY_ARTIFACT_MANIFEST)
    assert att["verified"]
    assert att["file_sha256"] == honest_sha
    assert prov["capability_manifest"]["file_sha256"] == honest_sha, (
        "the manifest recorded in provenance must be the one that was attested")


def test_the_baseline_is_hashed_and_read_through_one_descriptor(tmp_path,
                                                                monkeypatch):
    """The baseline half of R-07.

    ``file_sha256`` hashed the path and ``load`` reopened it, so the same rename
    put a different baseline into CH01's grammar than the one the signature
    covered -- and the baseline is the file that decides what "unlike normal"
    means for every session afterwards. Unlike the manifest it is telemetry and
    may be large, so it is not read into memory: the descriptor is opened once,
    hashed by streaming, rewound, and handed to the reader. An open descriptor
    keeps its inode whatever happens to the path.
    """
    baseline = tmp_path / "benign.jsonl"
    baseline.write_text(json.dumps(
        {"event_type": "tool_start", "timestamp": 1000.0, "session_id": "b",
         "tool_name": "read_x", "span_id": "S1"}) + "\n", encoding="utf-8")
    hostile = tmp_path / "hostile.jsonl"
    hostile.write_text(json.dumps(
        {"event_type": "tool_start", "timestamp": 1000.0, "session_id": "b",
         "tool_name": "send_email", "span_id": "S1"}) + "\n", encoding="utf-8")

    opens = _swap_on_second_open(monkeypatch, baseline, hostile)
    with baseline.open("rb") as fh:
        digest = stream_sha256(fh, 1 << 20, "benign.jsonl")
        events = list(read_events(baseline, report=IngestReport(), quiet=True,
                                  fh=fh))

    assert opens[0] == 1, "one open, so there is no window to rename into"
    assert digest == hashlib.sha256(
        json.dumps({"event_type": "tool_start", "timestamp": 1000.0,
                    "session_id": "b", "tool_name": "read_x",
                    "span_id": "S1"}).encode() + b"\n").hexdigest()
    assert [e.tool_name for e in events] == ["read_x"], (
        "the descriptor that was hashed is the one that was read")


def test_cli_records_an_unsigned_manifest_as_unsigned(tmp_path, capsys):
    """POLICY_SIGNATURE_ABSENT is the value nearly every deployment carries, and
    it has to be in the verdict rather than implied by silence."""
    telemetry, manifest, _store, _sig = _policy_fixture(tmp_path)
    assert cli_main(["score", str(telemetry),
                     "--tool-manifest", str(manifest)]) == EXIT_OK
    prov = json.loads(capsys.readouterr().out.strip())["data"]["provenance"]
    assert all(not a["verified"] for a in prov["policy_attestations"])
    assert {a["status"] for a in prov["policy_attestations"]} == {
        "POLICY_SIGNATURE_ABSENT"}


def test_cli_require_signed_policy_refuses_an_unsigned_manifest(tmp_path):
    telemetry, manifest, store, _sig = _policy_fixture(tmp_path)
    assert cli_main(["score", str(telemetry), "--tool-manifest", str(manifest),
                     "--trust-store", str(store),
                     "--require-signed-policy"]) == EXIT_ERROR


def test_cli_require_signed_policy_passes_when_everything_is_signed(tmp_path):
    telemetry, manifest, store, sig = _policy_fixture(tmp_path)
    assert cli_main(["score", str(telemetry), "--tool-manifest", str(manifest),
                     "--tool-manifest-sig", str(sig),
                     "--trust-store", str(store),
                     "--require-signed-policy"]) == EXIT_OK


def test_cli_still_accepts_the_superseded_collector_keys_flag(tmp_path):
    """Deployments that adopted P1.1 pass --collector-keys at a
    cohaera.collector_keys:1 file. Both halves keep working."""
    telemetry, _m, _s, _sig = _policy_fixture(tmp_path)
    legacy = tmp_path / "keys.json"
    legacy.write_text(json.dumps({"scheme": "cohaera.collector_keys:1",
                                  "keys": {KEY_ID: B64}}), encoding="utf-8")
    assert cli_main(["score", str(telemetry),
                     "--collector-keys", str(legacy)]) == EXIT_OK


def test_cli_refuses_both_names_for_the_same_option(tmp_path):
    """Silently preferring one would verify against a key set the operator did
    not think they had supplied, which is the worst outcome for a flag whose
    whole job is to say which keys are trusted."""
    telemetry, _m, store, _sig = _policy_fixture(tmp_path)
    assert cli_main(["score", str(telemetry), "--trust-store", str(store),
                     "--collector-keys", str(store)]) == EXIT_ERROR


def test_cli_freshness_flags_reach_the_verdict(tmp_path, capsys):
    telemetry, _m, _s, _sig = _policy_fixture(tmp_path)
    assert cli_main(["score", str(telemetry), "--evidence-max-age", "3600",
                     "--evidence-as-of", "1785700000"]) == EXIT_OK
    prov = json.loads(capsys.readouterr().out.strip())["data"]["provenance"]
    assert prov["evidence_freshness"] == {
        "max_age_s": 3600.0, "as_of": 1785700000.0, "enabled": True,
        "max_future_skew_s": 300.0}


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "-inf", "Infinity"])
def test_a_nonfinite_evidence_as_of_is_refused_at_the_boundary(tmp_path, value):
    """R-13's second half.

    ``--evidence-as-of`` was ``type=float``, and ``float("nan")`` succeeds, so
    argparse reported nothing. Every comparison against a NaN is false:
    ``Freshness.enabled`` went false, the "freshness bound" line never printed,
    and the run exited ZERO having silently skipped the one check the operator
    had gone out of their way to ask for. Exit 2, as a usage error, because an
    argument value must never be able to turn a control off quietly.
    """
    telemetry, _m, _s, _sig = _policy_fixture(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli_main(["score", str(telemetry), "--evidence-max-age", "3600",
                  "--evidence-as-of", value])
    assert exc.value.code == 2


def test_a_nonfinite_future_skew_is_refused_too(tmp_path):
    """The same argument for the bound R-13 added. An infinite tolerance is not
    a wide tolerance, it is no tolerance being enforced."""
    telemetry, _m, _s, _sig = _policy_fixture(tmp_path)
    for value in ("inf", "nan", "-1"):
        with pytest.raises(SystemExit) as exc:
            cli_main(["score", str(telemetry), "--evidence-max-age", "3600",
                      "--max-future-skew", value])
        assert exc.value.code == 2


def test_a_nonfinite_skew_cannot_reach_limits_by_any_other_route():
    """The CLI is one door. Limits refuses it directly as well, because a
    --limits-file or an embedding caller is another."""
    for value in (float("nan"), float("inf"), -1.0):
        with pytest.raises(LimitsError):
            Limits(max_future_skew_s=value)
    assert Limits(max_future_skew_s=0.0).max_future_skew_s == 0.0


# ---------------------------------------------------------------------------
# 11. The receipt adapters
# ---------------------------------------------------------------------------
#
# CH07's schema and binding were built with nothing to feed them. These assert
# the producer-side half against the response shapes real providers return, and
# assert the property that makes the whole mechanism worth anything: an adapter
# that cannot find an identifier emits NOTHING rather than inventing one.

BIND = {"span_id": "S1", "tool_id": "s3_object_put",
        "arg_digest": arg_digest({"bucket": "b", "key": "k"})}


@pytest.mark.parametrize("authority,response,expected", [
    ("aws.s3.put_object", {"VersionId": "3sL4kqtJlcpXroDTDmJ"},
     "3sL4kqtJlcpXroDTDmJ"),
    ("aws.s3.put_object",
     {"ResponseMetadata": {"HTTPHeaders": {"x-amz-version-id": "abc123"}}},
     "abc123"),
    ("gcp.storage.upload", {"generation": 1785700000123456}, "1785700000123456"),
    ("azure.blob.upload", {"version_id": "2026-08-08T00:00:00.0000000Z"},
     "2026-08-08T00:00:00.0000000Z"),
    ("aws.ses.send_email", {"MessageId": "0100018f-1234"}, "0100018f-1234"),
    ("sendgrid.send", {"headers": {"X-Message-Id": "xyz.filterdrecv"}},
     "xyz.filterdrecv"),
    ("stripe.charge", {"id": "ch_3Ov", "object": "charge"}, "ch_3Ov"),
    ("jira.create_issue", {"key": "OPS-4412", "id": "10042"}, "OPS-4412"),
    ("servicenow.create_record", {"result": {"sys_id": "9f2c4e6a8b0d"}},
     "9f2c4e6a8b0d"),
    ("kubernetes.apply",
     {"metadata": {"uid": "u-1", "resourceVersion": "88213"}}, "88213"),
    ("aws.cloudtrail.event", {"eventID": "e-9f2c"}, "e-9f2c"),
    ("github.create_pull_request", {"node_id": "PR_kwDO", "number": 6},
     "PR_kwDO"),
    ("postgres.commit", {"commit_lsn": "0/16B3748"}, "0/16B3748"),
])
def test_each_adapter_finds_the_identifier_the_provider_returned(
        authority, response, expected):
    receipt = adapt(authority, response, BIND)
    assert receipt["identifier"] == expected
    parsed, codes = EffectReceipt.parse(receipt)
    assert parsed is not None and codes == (), \
        "an adapter must emit something the verifier accepts"
    assert parsed.binding.arg_digest == BIND["arg_digest"]


def test_an_adapter_with_nothing_to_report_emits_nothing():
    """The property the whole mechanism rests on.

    Inventing an identifier -- a generated UUID, a hash of the request -- would
    produce a receipt from a namespace the AGENT controls, which is the one
    property that made a receipt worth more than the boolean it replaces.
    NO_EFFECT_RECEIPT is the correct output for a tool with nothing to surface.
    """
    for response in ({}, {"VersionId": ""}, {"VersionId": None},
                     {"VersionId": True}, {"ResponseMetadata": {}}, "not a dict"):
        assert adapt("aws.s3.put_object", response, BIND) is None


def test_the_mutation_identifier_wins_over_the_object_identifier():
    """Kubernetes returns both, and only one of them identifies THIS write.

    `uid` is stable for the object's whole life, so a receipt carrying it could
    be presented for any later mutation of the same object.
    """
    receipt = adapt("kubernetes.apply",
                    {"metadata": {"uid": "u-1", "resourceVersion": "88213"}},
                    BIND)
    assert receipt["kind"] == "resource_version"
    assert receipt["identifier"] == "88213"


def test_header_casing_is_not_something_an_adapter_has_an_opinion_about():
    assert adapt("sendgrid.send", {"headers": {"x-message-id": "lower"}},
                 BIND)["identifier"] == "lower"


def test_an_unknown_authority_is_an_error_not_a_silent_none():
    """A typo in an authority name must not read as "this call had no receipt"."""
    with pytest.raises(ReceiptAdapterError):
        adapt("aws.s3.put_objekt", {"VersionId": "v"}, BIND)


def test_an_adapted_receipt_binds_and_contradicts_end_to_end():
    """The producer half meeting the verifier half, through CH07.

    A call whose telemetry reports failure while carrying an adapter-produced
    receipt bound to it is the one detection in this repository that catches a
    lying emitter rather than routing around it.
    """
    args = {"bucket": "audit-logs", "key": "2026/08/report.csv"}
    receipt = adapt("aws.s3.put_object", {"VersionId": "v-9f2c"},
                    binding_for("S1", "s3_object_put", args))
    events = [
        Event(raw={"event_type": "tool_start", "timestamp": 1000.0,
                   "session_id": "a", "span_id": "S1",
                   "tool_name": "s3_object_put",
                   "data": {"action": "invoke_tool", "tool_args": args}}),
        # tool_error, not tool_end: the telemetry says this call did NOT take
        # effect, and it carries a receipt from the authority saying it did.
        Event(raw={"event_type": "tool_error", "timestamp": 1001.0,
                   "session_id": "a", "span_id": "S1",
                   "tool_name": "s3_object_put",
                   "data": {"action": "invoke_tool", "tool_args": args,
                            "effect_receipt": receipt}}),
    ]
    manifest = CapabilityManifest.from_obj(
        {"tools": {"s3_object_put": {"effects": ["write"], "reversible": False}}})
    session = assemble(events, manifest=manifest)[0]
    assert [f.check for f in ch07_effect_contradiction(session)] == [
        CH07_CONTRADICTED]


def test_a_receipt_bound_to_different_arguments_does_not_contradict_quietly():
    """The guard on the detection above. A receipt copied from a real call onto
    a different one must be reported as unbound rather than counted."""
    real = binding_for("S1", "s3_object_put", {"bucket": "b", "key": "real"})
    receipt = adapt("aws.s3.put_object", {"VersionId": "v-9f2c"}, real)
    args = {"bucket": "b", "key": "substituted"}
    events = [
        Event(raw={"event_type": "tool_start", "timestamp": 1000.0,
                   "session_id": "a", "span_id": "S1",
                   "tool_name": "s3_object_put",
                   "data": {"action": "invoke_tool", "tool_args": args}}),
        # tool_error, not tool_end: the telemetry says this call did NOT take
        # effect, and it carries a receipt from the authority saying it did.
        Event(raw={"event_type": "tool_error", "timestamp": 1001.0,
                   "session_id": "a", "span_id": "S1",
                   "tool_name": "s3_object_put",
                   "data": {"action": "invoke_tool", "tool_args": args,
                            "effect_receipt": receipt}}),
    ]
    session = assemble(events)[0]
    assert [f.check for f in ch07_effect_contradiction(session)] == [CH07_UNBOUND]


# ---------------------------------------------------------------------------
# 7. The seen-stream ledger: replay INSIDE the freshness window
# ---------------------------------------------------------------------------
#
# Every check above passes on a replayed archive, and each for a good reason:
# the sequence really is contiguous, the chain really does hold, the signatures
# really do verify. Freshness catches the replay that is OLD. This is the
# residue -- re-feeding yesterday's stream, still inside any sane window.


def _scored(records: list[dict], ledger_path, run_id: str = "run-1"):
    """One full run against a persistent ledger, as the CLI does it."""
    ledger = StreamLedger.load(ledger_path)
    v = StreamVerifier(keys=KEYS, ledger=ledger, run_id=run_id)
    for raw in records:
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    ledger.stamp(run_id)
    ledger.save()
    return v.for_session("sess-1"), ledger


def test_a_stream_scored_twice_is_detected_the_second_time(tmp_path):
    """The whole point. Nothing else in this module can see this."""
    path = tmp_path / "seen.json"
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)

    first, _ = _scored(signed, path)
    assert not first.inadmissible, "a stream's first scoring must be clean"

    second, _ = _scored(signed, path, run_id="run-2")
    assert R_STREAM_REPLAYED in second.codes
    assert second.inadmissible
    assert second.replayed_streams[0]["head_comparison"] == "match"


def test_a_rewritten_history_is_a_fork_and_not_a_replay(tmp_path):
    """Same sequence positions, DIFFERENT records, both validly signed.

    A replay re-sends the same records and rebuilds the same chain, so the head
    matches at a shared sequence. A fork fills the same positions with different
    records, so it does not. That distinction is the reason the ledger stores a
    chain head and not just a sequence number -- without it, a collector restart
    and a rewritten history are the same event, and one of them is an attack.
    """
    path = tmp_path / "seen.json"
    _scored(sign_stream(_records(6), "stream-a", SECRET, KEY_ID), path)

    other = [{**r, "tool_name": "object_put"} for r in _records(6)]
    forked = sign_stream(other, "stream-a", SECRET, KEY_ID)
    state, _ = _scored(forked, path, run_id="run-2")

    assert R_STREAM_FORKED in state.codes
    assert R_STREAM_REPLAYED not in state.codes
    assert state.replayed_streams[0]["head_comparison"] == "differs"


def test_a_genuine_continuation_is_not_a_replay(tmp_path):
    """The confounder that decides whether this is usable.

    A collector tailed in batches sends seq 0-5 then 6-11. If that read as a
    replay, the ledger would fire on every scheduled run and be turned off
    within a day.
    """
    path = tmp_path / "seen.json"
    full = sign_stream(_records(12), "stream-b", SECRET, KEY_ID)
    first, _ = _scored(full[:6], path)
    second, ledger = _scored(full[6:], path, run_id="run-2")

    assert not first.inadmissible
    assert R_STREAM_REPLAYED not in second.codes
    assert R_STREAM_FORKED not in second.codes
    assert ledger.streams["stream-b"].last_seq == 11
    assert ledger.streams["stream-b"].runs == 2


def test_a_replay_does_not_advance_the_ledger(tmp_path):
    """Or the SECOND replay would pass.

    Recording a replay's extent would move the reference forward to exactly
    where the attacker's copy ends, so re-feeding it again would read as a
    continuation. Nothing legitimate was scored, so nothing is recorded except
    that it happened.
    """
    path = tmp_path / "seen.json"
    signed = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    _scored(signed, path)
    _, after_first = _scored(signed, path, run_id="run-2")
    third, after_second = _scored(signed, path, run_id="run-3")

    assert R_STREAM_REPLAYED in third.codes, "the second replay must also fire"
    assert after_first.streams["stream-a"].last_seq == 5
    assert after_second.streams["stream-a"].runs == 3, (
        "the ledger must still count the attempts even though it records no new "
        "extent")


def test_a_fork_does_not_become_the_reference(tmp_path):
    """Adopting the fork's head would make the attacker's version the history
    every future run is measured against."""
    path = tmp_path / "seen.json"
    original = sign_stream(_records(6), "stream-a", SECRET, KEY_ID)
    _scored(original, path)
    honest_head = StreamLedger.load(path).streams["stream-a"].head

    other = [{**r, "tool_name": "object_put"} for r in _records(6)]
    _scored(sign_stream(other, "stream-a", SECRET, KEY_ID), path, run_id="run-2")
    assert StreamLedger.load(path).streams["stream-a"].head == honest_head


def test_records_never_scored_are_reported_but_not_called_tampering(tmp_path):
    """Scoring a subset on purpose and having records deleted look identical
    from inside one run, so this is a reason code and not a finding."""
    path = tmp_path / "seen.json"
    full = sign_stream(_records(12), "stream-b", SECRET, KEY_ID)
    _scored(full[:4], path)
    state, _ = _scored(full[8:], path, run_id="run-2")
    assert R_STREAM_SKIPPED_RECORDS in state.codes
    assert not state.inadmissible


def _sign_from(records: list[dict], stream_id: str, start_seq: int,
               head: str) -> list[dict]:
    """A validly signed run that starts at ``start_seq`` from ANY head.

    ``sign_stream`` always starts a stream at seq 0 from its canonical seed, so
    it cannot express the thing R-02 is about: a continuation minted by somebody
    holding a collector key, glued onto the sequence numbers of a stream the
    ledger already knows. Every signature this produces is genuine -- that is
    the point. Nothing inside a single run can tell it from the real thing.
    """
    out = []
    for i, record in enumerate(records):
        seq = start_seq + i
        body = {k: v for k, v in record.items() if k != "integrity"}
        prev = head
        head = chain_step(prev, body_digest(body))
        out.append({**body, "integrity": {
            "scheme": INTEGRITY_SCHEMA, "stream_id": stream_id, "seq": seq,
            "prev": prev, "chain": head, "key_id": KEY_ID,
            "sig": base64.b64encode(ed25519.sign(
                SECRET, signing_input(stream_id, seq, head))).decode("ascii")}})
    return out


def test_a_continuation_from_a_boundary_nobody_scored_is_a_fork(tmp_path):
    """R-02, reproduced. The serious half.

    ``compare`` asked one question of a continuation -- is its first sequence
    past the last one scored -- which establishes that the new records came
    AFTER the old ones and never that they came FROM them. A second, mutually
    exclusive history minted under a valid collector key, starting at exactly
    ``last_seq + 1`` and declaring a predecessor the ledger had never recorded,
    read as ordinary advancement. Every signature verifies, the chain within the
    run is perfect, and nothing inside one run can see it: this is precisely the
    class of attack the ledger exists for.

    Worse than the missed detection was what happened next. ``record`` advanced
    on ``advanced``, so the fabricated head became the reference every later run
    was measured against -- the attacker's history, adopted as the truth.
    """
    path = tmp_path / "seen.json"
    _scored(sign_stream(_records(3), "stream-a", SECRET, KEY_ID), path)
    honest_head = StreamLedger.load(path).streams["stream-a"].head

    false_head = chain_step(chain_seed("stream-a", KEY_ID), "0" * 64)
    assert false_head != honest_head
    fabricated = _sign_from(_records(3, sid="sess-1"), "stream-a", 3, false_head)
    state, ledger = _scored(fabricated, path, run_id="run-2")

    assert R_STREAM_FORKED in state.codes
    assert state.inadmissible
    verdict = state.replayed_streams[0]
    assert verdict["status"] == "forked"
    assert verdict["boundary"] == "differs"
    assert verdict["declared_prev"] == false_head
    assert verdict["previous_head"] == honest_head
    assert StreamLedger.load(path).streams["stream-a"].head == honest_head, (
        "a fabricated continuation must not become the reference")
    assert ledger.streams["stream-a"].last_seq == 2


def test_a_gap_in_a_continuation_is_not_ordinary_advancement(tmp_path):
    """R-02, the other half.

    Records 3 and 4 were never scored by anything, and the verdict said
    ``advanced`` -- the same word a healthy batched collector gets. The reason
    code was there, derived separately by arithmetic, but the status a SIEM rule
    or a human reads first said normal progress.

    It stays non-inadmissible, and that is unchanged and deliberate: an operator
    scoring a subset on purpose and an attacker deleting a range are the same
    input from here, and the ledger holds no head for the missing stretch to
    tell them apart. What changed is that it no longer calls itself ordinary.
    """
    path = tmp_path / "seen.json"
    full = sign_stream(_records(12), "stream-b", SECRET, KEY_ID)
    _scored(full[:3], path)
    state, ledger = _scored(full[5:], path, run_id="run-2")

    assert state.replayed_streams[0]["status"] == "discontinuous"
    assert state.replayed_streams[0]["boundary"] == "gap"
    assert R_STREAM_SKIPPED_RECORDS in state.codes
    assert not state.inadmissible, (
        "a subset scored on purpose looks the same; this is a report, not an "
        "accusation")
    assert ledger.streams["stream-b"].last_seq == 11, (
        "the records after the gap were genuinely scored and must be recorded, "
        "or the next run reads them as a replay")


def test_a_contiguous_continuation_onto_the_stored_head_is_still_advancement():
    """The confounder R-02's fix must not break.

    A collector tailed in batches is the ordinary case and the whole reason the
    ledger is usable. If tightening the boundary check made this fire, the
    ledger would be turned off within a day and the replay detection with it.
    """
    ledger = StreamLedger(streams={"s": SeenStream(
        stream_id="s", first_seq=0, last_seq=5, head="abc")}, path=Path("x"))
    verdict = ledger.compare("s", 6, 11, "def", None, first_prev="abc")
    assert verdict.status == SEEN_ADVANCED
    assert verdict.boundary == "match"


def test_an_undeclared_boundary_advances_but_never_reads_as_checked(tmp_path):
    """``prev`` is optional in the sidecar, so the join can be unverifiable.

    Refusing to advance would break every collector that omits the field, and
    calling it a fork would accuse them. Reported as its own code instead, and
    not inadmissible -- a question that could not be answered is not an answer,
    which is the same rule INTEGRITY_KEY_WINDOW_UNCHECKED follows. What it must
    never do is read as a boundary that was checked and matched.
    """
    ledger = StreamLedger(streams={"s": SeenStream(
        stream_id="s", first_seq=0, last_seq=5, head="abc")}, path=Path("x"))
    verdict = ledger.compare("s", 6, 11, "def", None, first_prev=None)
    assert verdict.status == SEEN_ADVANCED
    assert verdict.boundary == "unstated"
    assert verdict.boundary != "match"
    assert R_STREAM_BOUNDARY_UNVERIFIED not in INADMISSIBLE


# R-03. Admission. `record` used to be called for every stream that had a first
# and a last sequence, with no requirement that any of it verified -- so the file
# that exists to say "these streams were scored" recorded streams that were not.


def _chain_only(records: list[dict], stream_id: str) -> list[dict]:
    """Chained and NOT signed. No key needed; anyone who can append can write it."""
    head = chain_seed(stream_id, "")
    out = []
    for seq, record in enumerate(records):
        body = {k: v for k, v in record.items() if k != "integrity"}
        prev = head
        head = chain_step(prev, body_digest(body))
        out.append({**body, "integrity": {
            "scheme": INTEGRITY_SCHEMA, "stream_id": stream_id, "seq": seq,
            "prev": prev, "chain": head}})
    return out


def test_an_unsigned_stream_does_not_claim_a_position_in_the_ledger(tmp_path):
    """R-03, path 1, and the acceptance case from the review.

    Under a LOADED trust store, a chained-but-unsigned stream was written to the
    ledger with its head. Nothing signs it and nothing needs to: chaining is
    arithmetic, so anyone who can append to the input can produce it. The
    genuine signed stream then arrived at the same positions with a different
    head and read as ``forked`` -- so squatting a stream id turned into a
    critical finding against the real collector, and the real collector was the
    one that looked like the rewrite.
    """
    path = tmp_path / "seen.json"
    unsigned = _chain_only(_records(4), "stream-a")
    state, ledger = _scored(unsigned, path, run_id="run-1")

    assert KEYS.loaded, "the rule is conditional on the operator having said who may attest"
    assert "stream-a" not in ledger.streams, (
        "an unsigned stream must not be remembered as scored")
    assert R_LEDGER_NOT_ADVANCED in state.codes
    assert R_UNSIGNED in state.codes

    genuine, _ = _scored(sign_stream(_records(4), "stream-a", SECRET, KEY_ID),
                         path, run_id="run-2")
    assert R_STREAM_FORKED not in genuine.codes, (
        "the real collector must not be accused because a squatter got there "
        "first")
    assert R_STREAM_REPLAYED not in genuine.codes


def test_with_no_trust_store_the_ledger_still_records_what_it_can(tmp_path):
    """The switch, and why it is where it is.

    An operator who has loaded no keys has told Cohaera nothing about who may
    attest, so requiring a verified signature would turn the ledger off for
    every unsigned deployment -- which is most of them today, and the replay it
    catches is worth having even on evidence nobody signed. Once keys ARE
    loaded, an unsigned record is not evidence and the ledger must not treat it
    as any.
    """
    path = tmp_path / "seen.json"
    unsigned = _chain_only(_records(4), "stream-a")
    ledger = StreamLedger.load(path)
    v = StreamVerifier(keys=TrustStore(), ledger=ledger, run_id="run-1")
    for raw in unsigned:
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()
    assert "stream-a" in ledger.streams
    assert R_LEDGER_NOT_ADVANCED not in v.for_session("sess-1").codes


def test_a_stream_whose_evidence_failed_is_not_written_to_the_ledger(tmp_path):
    """R-03, path 3. A broken chain did not stop the position being committed
    as a scored fact, so the next run reads the tampered range as a replay and
    never looks at it again."""
    path = tmp_path / "seen.json"
    signed = sign_stream(_records(5), "stream-a", SECRET, KEY_ID)
    signed[2]["tool_name"] = "object_put"          # edited after signing
    state, ledger = _scored(signed, path, run_id="run-1")

    assert R_CHAIN_BROKEN in state.codes
    assert "stream-a" not in ledger.streams
    assert R_LEDGER_NOT_ADVANCED in state.codes


def test_records_dropped_by_a_budget_do_not_advance_the_ledger(tmp_path):
    """R-03, path 2, reproduced through the real assembly path.

    Assembly drops events past ``max_sessions`` and the verifier had already
    recorded their stream positions -- correctly, because a dropped record still
    occupies a position and omitting it would manufacture a gap out of Cohaera's
    own budget. What was wrong was committing that extent to the ledger: the
    records of the session nobody scored were marked as already seen, so
    re-feeding them reads as a replay and they can never be scored at all.
    """
    path = tmp_path / "seen.json"
    interleaved = []
    for i in range(3):
        for sid in ("sess-A", "sess-B"):
            interleaved.append(
                {"event_type": "tool_start", "session_id": sid,
                 "timestamp": 1000.0 + i, "span_id": f"sp-{sid}-{i}",
                 "tool_name": "alert_read", "data": {"action": "invoke_tool"}})
    signed = sign_stream(interleaved, "stream-a", SECRET, KEY_ID)
    source = tmp_path / "t.jsonl"
    source.write_text("\n".join(json.dumps(r) for r in signed) + "\n",
                      encoding="utf-8")

    ledger = StreamLedger.load(path)
    sessions = load(source, limits=Limits(max_sessions=1), keys=KEYS,
                    ledger=ledger, quiet=True)
    assert len(sessions) == 1, "the fixture must actually hit the budget"
    assert "stream-a" not in ledger.streams, (
        "three records were verified and never scored; committing their extent "
        "would make them unscoreable forever")
    assert R_LEDGER_NOT_ADVANCED in sessions[0].integrity.codes


def test_a_refused_stream_does_not_consume_the_ledgers_budget(tmp_path):
    """A producer minting an unsigned stream id per record could otherwise
    exhaust max_ledger_streams with streams it never signed -- and the budget
    being exhausted is what makes an earlier stream's replay undetectable."""
    path = tmp_path / "seen.json"
    limits = Limits(max_ledger_streams=1)
    ledger = StreamLedger(streams={}, path=path, limits=limits)
    v = StreamVerifier(keys=KEYS, limits=limits, ledger=ledger, run_id="run-1")
    for name in ("junk-1", "junk-2", "junk-3"):
        for raw in _chain_only(_records(2), name):
            e = Event(raw=raw, limits=limits)
            v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()

    assert ledger.streams == {}, "nothing unsigned may take a slot"
    assert not ledger.budget_exhausted, (
        "a refused stream must not spend the budget a real one needs")


def test_the_refusals_are_named_in_the_run_summary(tmp_path):
    """A stream absent from the ledger looks exactly like one never seen, so
    the omission has to be stated rather than inferred."""
    path = tmp_path / "seen.json"
    ledger = StreamLedger.load(path)
    v = StreamVerifier(keys=KEYS, ledger=ledger, run_id="run-1")
    for raw in _chain_only(_records(3), "stream-a"):
        e = Event(raw=raw)
        v.observe(e.raw, e.integrity, raw.get("session_id", ""))
    v.finalise()

    refusals = v.summary()["stream_ledger_refusals"]
    assert [r["stream_id"] for r in refusals] == ["stream-a"]
    assert "signature" in refusals[0]["reason"]


def test_the_ledger_is_written_after_the_verdicts_are_emitted(tmp_path):
    """R-03, path 3, and a deliberate reversal of the old ordering.

    Saving first reasoned that a run dying mid-emission has still SCORED those
    streams. The other side of that trade is worse: the ledger has advanced past
    findings nobody ever saw, re-running reports a replay, and the findings are
    gone. A duplicate alert is noise an analyst dismisses; a missed one is the
    thing this project exists to prevent.

    Asserted by making emission fail. The ledger must be untouched.
    """
    telemetry = tmp_path / "t.jsonl"
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    telemetry.write_text("\n".join(json.dumps(r) for r in signed) + "\n",
                         encoding="utf-8")
    store = tmp_path / "keys.json"
    store.write_text(json.dumps({"scheme": TRUST_STORE_SCHEMA, "keys": {
        KEY_ID: {"key": base64.b64encode(PUBLIC).decode("ascii"),
                 "roles": [ROLE_COLLECTOR]}}}), encoding="utf-8")
    path = tmp_path / "seen.json"

    class _Broken:
        def write(self, _text):
            raise OSError("the sink went away mid-emission")

        def flush(self):
            pass

    real_stdout = sys.stdout
    sys.stdout = _Broken()
    try:
        code = cli_main(["score", str(telemetry), "--trust-store", str(store),
                         "--seen-streams", str(path)])
    finally:
        sys.stdout = real_stdout

    assert code == EXIT_ERROR, "a failed emission is a failed run"
    assert not path.exists() or "stream-a" not in StreamLedger.load(path).streams, (
        "a run that died while emitting must leave the input re-scoreable")


# R-04. Concurrency. The write was atomic and the read-modify-write around it
# was not, so two runs on one host each loaded, each scored, and each replaced --
# and the file left behind had no record of whichever one finished first.

_CONCURRENT_WORKER = """
import sys, base64
sys.path.insert(0, {root!r})
sys.path.insert(0, {src_root!r})
from cohaera import ed25519
from cohaera.evidence import (StreamLedger, StreamVerifier, TrustStore,
                              TRUST_STORE_SCHEMA, ROLE_COLLECTOR, LedgerError)
from cohaera.model import Event
from tools.collector_sign import key_id_for, sign_stream

secret = bytes.fromhex("ab" * 32)
public = ed25519.public_key(secret)
kid = key_id_for(public)
keys = TrustStore.from_obj({{"scheme": TRUST_STORE_SCHEMA, "keys": {{
    kid: {{"key": base64.b64encode(public).decode(), "roles": [ROLE_COLLECTOR]}}}}}})
records = [{{"event_type": "tool_start", "session_id": "s", "timestamp": 1000.0 + i,
            "span_id": "sp-%d" % i, "tool_name": "alert_read",
            "data": {{"action": "invoke_tool"}}}} for i in range(3)]

stream_id = sys.argv[1]
try:
    with StreamLedger.locked({path!r}, wait_s=25.0) as ledger:
        v = StreamVerifier(keys=keys, ledger=ledger, run_id=stream_id)
        for raw in sign_stream(records, stream_id, secret, kid):
            e = Event(raw=raw)
            v.observe(e.raw, e.integrity, "s")
        v.finalise()
        ledger.stamp(stream_id)
        ledger.save()
    print("saved")
except LedgerError as exc:
    print("refused")
"""


def test_two_concurrent_runs_both_reach_the_ledger(tmp_path):
    """R-04, reproduced and closed.

    Two processes, two different streams, one ledger, started together. Before
    the lock this lost an update on most runs: both loaded the same state, both
    scored, and the second ``os.replace`` wrote a file with no trace of the
    first. A stream missing from the ledger is a stream whose next replay is
    undetectable, and nothing anywhere said so -- both runs exited zero.

    The acceptance is that both are present, or that one visibly refuses.
    Serialising is the intended outcome and not a compromise: two runs scoring
    the same stream at once would each read the position before the other wrote
    it, so neither would see the replay, and a replay detector that misses a
    replay because it was busy is not worth keeping.
    """
    path = tmp_path / "seen.json"
    root = str(Path(__file__).resolve().parent.parent)
    script = _CONCURRENT_WORKER.format(root=root, src_root=str(Path(root) / "src"),
                                       path=str(path))
    running = [subprocess.Popen([sys.executable, "-c", script, sid],
                                stdout=subprocess.PIPE, text=True)
               for sid in ("stream-A", "stream-B")]
    outs = [proc.communicate(timeout=90)[0].strip() for proc in running]

    assert all(proc.returncode == 0 for proc in running)
    assert set(outs) <= {"saved", "refused"}
    final = StreamLedger.load(path)
    saved = [sid for sid, out in zip(("stream-A", "stream-B"), outs, strict=True)
             if out == "saved"]
    for stream_id in saved:
        assert stream_id in final.streams, (
            f"{stream_id} reported success and is not in the ledger; its next "
            f"replay is undetectable and nothing said so")
    assert len(saved) == 2, (
        "both runs should serialise on the lock and both should land")


def test_a_stale_generation_never_overwrites_a_newer_ledger(tmp_path):
    """The backstop for when the lock was not taken or is not honoured.

    ``flock`` is advisory and local -- it does not travel over NFS, and a
    process that opens the file without asking for it is not stopped by it. The
    generation makes that case loud instead of silent: a save whose parent is
    not what is on disk is refused, so the run fails rather than reporting
    success having discarded another run's work.
    """
    path = tmp_path / "seen.json"
    _scored(sign_stream(_records(3), "stream-a", SECRET, KEY_ID), path)

    stale = StreamLedger.load(path)          # both read the same generation
    fresh = StreamLedger.load(path)
    assert stale.generation == fresh.generation == 1

    fresh.streams["other"] = SeenStream(stream_id="other", first_seq=0,
                                        last_seq=1, head="ab")
    fresh.save()
    assert StreamLedger.load(path).generation == 2

    stale.streams["mine"] = SeenStream(stream_id="mine", first_seq=0,
                                       last_seq=1, head="cd")
    with pytest.raises(LedgerError, match="generation"):
        stale.save()
    after = StreamLedger.load(path)
    assert "other" in after.streams, "the newer write must survive"
    assert "mine" not in after.streams


def test_the_generation_advances_once_per_save(tmp_path):
    path = tmp_path / "seen.json"
    ledger = StreamLedger(streams={}, path=path)
    assert ledger.generation == 0
    ledger.save()
    assert ledger.generation == 1
    assert StreamLedger.load(path).generation == 1
    ledger.save()
    assert StreamLedger.load(path).generation == 2


def test_a_ledger_written_before_generations_existed_still_loads(tmp_path):
    """Upgrading must not delete a deployment's replay memory.

    The generation is deliberately outside the digest for this reason: folding
    it in would make every pre-existing ledger fail to load, and a failed load
    is refused, so the operator's only way forward would be to delete the file --
    which is exactly the state an attacker who deleted it wants.
    """
    path = tmp_path / "seen.json"
    _scored(sign_stream(_records(3), "stream-a", SECRET, KEY_ID), path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    del doc["generation"]
    path.write_text(json.dumps(doc), encoding="utf-8")

    ledger = StreamLedger.load(path)
    assert ledger.generation == 0
    assert "stream-a" in ledger.streams
    ledger.save()                                  # and it can be written again


def test_the_lock_is_a_sidecar_rather_than_the_ledger_itself(tmp_path):
    """``save`` ends in ``os.replace``, which swaps the inode.

    A lock held on the ledger's own descriptor would be protecting a file that
    is no longer at that name the moment the first writer finishes, so the
    second writer would take a lock on a different object and both would
    proceed. The sidecar is never replaced.
    """
    path = tmp_path / "seen.json"
    assert StreamLedger.lock_path_for(path) == tmp_path / "seen.json.lock"
    with StreamLedger.locked(path) as ledger:
        ledger.save()
    assert (tmp_path / "seen.json.lock").exists()
    assert path.exists()


def test_waiting_for_a_held_lock_ends_in_a_refusal_rather_than_a_hang(tmp_path):
    """A scheduled run that never returns is worse than one that fails.

    The alarm is the test. Deleting the deadline from ``_acquire_ledger_lock``
    does not make this assertion false, it makes it never evaluate -- the run
    blocks forever and CI reports a job timeout hours later instead of a failing
    test. A guard that can only be caught by a hang is a guard nobody will
    notice regressing, so the hang is converted into a failure here.
    """
    path = tmp_path / "seen.json"

    def _too_slow(signum, frame):
        raise AssertionError(
            "acquiring a held lock did not give up; the wait has no deadline")

    with StreamLedger.locked(path):
        previous = signal.signal(signal.SIGALRM, _too_slow)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            with pytest.raises(LedgerError, match="another run has held"):
                with StreamLedger.locked(path, wait_s=0.1):
                    pass
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)


def test_without_a_ledger_the_absence_is_stated(tmp_path):
    """Not silence. A run with no ledger did not check for replay, and a
    verdict that does not say so invites the reader to assume it did."""
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    state = _run(signed).for_session("sess-1")
    assert R_NO_STREAM_LEDGER in state.codes
    assert not state.inadmissible


def test_a_missing_ledger_file_is_a_first_run_and_a_corrupt_one_is_not(tmp_path):
    """The asymmetry matters. Absent is the first run. Present-and-unreadable
    is refused, because scoring everything as new is exactly what deleting the
    ledger achieves, and doing it quietly would hide the deletion."""
    missing = tmp_path / "nope.json"
    assert StreamLedger.load(missing).streams == {}

    corrupt = tmp_path / "bad.json"
    corrupt.write_text("{", encoding="utf-8")
    with pytest.raises(LedgerError):
        StreamLedger.load(corrupt)

    path = tmp_path / "seen.json"
    _scored(sign_stream(_records(4), "stream-a", SECRET, KEY_ID), path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["streams"]["stream-a"]["last_seq"] = 99      # edited body, stale digest
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(LedgerError, match="digest does not match"):
        StreamLedger.load(path)


def test_the_ledger_is_replaced_atomically(tmp_path):
    """C5-06's lesson, applied to the one file that survives between runs."""
    path = tmp_path / "seen.json"
    _scored(sign_stream(_records(4), "stream-a", SECRET, KEY_ID), path)
    assert json.loads(path.read_text(encoding="utf-8"))["scheme"] == LEDGER_SCHEMA
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_the_ledger_refuses_to_grow_without_bound(tmp_path):
    """A stream id is producer-chosen, so a hostile producer minting one per
    record turns the ledger into an unbounded disk write that PERSISTS. Refused
    rather than evicted, because evicting makes an earlier stream's replay
    undetectable and the producer picks which one goes."""
    limits = DEFAULT_LIMITS.with_overrides(max_ledger_streams=2)
    ledger = StreamLedger(streams={}, path=tmp_path / "seen.json", limits=limits)
    for i in range(5):
        signed = sign_stream(_records(2), f"stream-{i}", SECRET, KEY_ID)
        v = StreamVerifier(keys=KEYS, ledger=ledger, limits=limits)
        for raw in signed:
            e = Event(raw=raw, limits=limits)
            v.observe(e.raw, e.integrity, raw.get("session_id", ""))
        v.finalise()
    assert len(ledger.streams) == 2
    assert ledger.budget_exhausted


def test_the_ledger_catches_what_freshness_cannot(tmp_path):
    """The two controls in one place, showing they cover different things.

    A stream replayed one minute after it was scored is INSIDE any sane
    freshness window, so the freshness bound passes it. That is not a defect in
    freshness -- an old-stream bound cannot see a recent replay -- and it is the
    entire reason this ledger exists.
    """
    path = tmp_path / "seen.json"
    records = _records(5)
    for i, r in enumerate(records):
        r["timestamp"] = 1_000_000.0 + i
    signed = sign_stream(records, "stream-a", SECRET, KEY_ID)
    fresh = Freshness(max_age_s=3600.0, as_of=1_000_100.0)

    def run(run_id: str):
        ledger = StreamLedger.load(path)
        v = StreamVerifier(keys=KEYS, ledger=ledger, freshness=fresh,
                           run_id=run_id)
        for raw in signed:
            e = Event(raw=raw)
            v.observe(e.raw, e.integrity, raw.get("session_id", ""))
        v.finalise()
        ledger.save()
        return v.for_session("sess-1")

    first = run("run-1")
    second = run("run-2")
    assert R_STALE not in first.codes and R_STALE not in second.codes, (
        "both runs are inside the freshness window, which is the premise")
    assert R_STREAM_REPLAYED in second.codes, (
        "and the ledger is what sees it anyway")


# =====================================================================
# R-06. Identity. `run_id` covered the detector, the bounds, the source, the
# input, the baseline and the manifest -- and nothing the evidence layer added
# after it. Every one of those later settings is emitted in provenance BECAUSE
# it changes how the output should be read, and every one of them sat outside
# the ID that the documentation tells a SIEM to deduplicate on. So the run that
# knew whether the telemetry was signed could be discarded as a retry of the
# run that did not.
# =====================================================================


def _identity_fixture(tmp_path):
    telemetry = tmp_path / "t.jsonl"
    telemetry.write_text(json.dumps(
        {"event_type": "tool_start", "timestamp": 1000.0, "session_id": "a",
         "tool_name": "read_x", "span_id": "S1"}) + "\n", encoding="utf-8")
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"scheme": TRUST_STORE_SCHEMA, "keys": {
        KEY_ID: {"key": base64.b64encode(PUBLIC).decode("ascii"),
                 "roles": [ROLE_COLLECTOR]}}}), encoding="utf-8")
    return telemetry, store


def _run_ids(capsys, argv):
    assert cli_main(argv) == EXIT_OK
    out = capsys.readouterr().out.strip().splitlines()
    records = [json.loads(line) for line in out if line.strip()]
    prov = records[0]["data"]["provenance"]
    return prov, [r["verdict_id"] for r in records]


def test_r06_a_trust_store_changes_the_run_id_it_governs(tmp_path, capsys):
    """R-06, reproduced exactly as the review reported it.

    Same telemetry, scored once with no trust store and once with one collector
    key loaded. Before this, both runs produced the same ``analysis_run_id`` and
    the same ``verdict_id`` while carrying different provenance and emitting
    different bytes. A SIEM following this project's own deduplication advice
    would have kept whichever arrived first and dropped the other.
    """
    telemetry, store = _identity_fixture(tmp_path)

    bare, bare_verdicts = _run_ids(capsys, ["score", str(telemetry)])
    trusted, trusted_verdicts = _run_ids(
        capsys, ["score", str(telemetry), "--trust-store", str(store)])

    assert bare["trust_store"]["key_count"] == 0
    assert trusted["trust_store"]["key_count"] == 1, "the fixture must differ"
    assert bare["analysis_run_id"] != trusted["analysis_run_id"], (
        "two runs whose trust configuration differs are two runs")
    assert bare_verdicts != trusted_verdicts, (
        "and the verdict IDs, which are what a SIEM actually deduplicates on, "
        "must differ with them")


def test_r06_the_same_configuration_is_still_the_same_run(tmp_path, capsys):
    """The property the fix must not cost.

    Determinism is the whole reason these IDs are content digests. A fix that
    made every run unique would 'close' R-06 by destroying deduplication.
    """
    telemetry, store = _identity_fixture(tmp_path)
    argv = ["score", str(telemetry), "--trust-store", str(store)]
    first, first_verdicts = _run_ids(capsys, argv)
    second, second_verdicts = _run_ids(capsys, argv)
    assert first["analysis_run_id"] == second["analysis_run_id"]
    assert first_verdicts == second_verdicts


def test_r06_the_trust_config_digest_is_readable_in_provenance(tmp_path, capsys):
    """Folded into the ID *and* emitted, so a reader can tell WHY two IDs
    differ without re-deriving the digest from the pieces."""
    telemetry, store = _identity_fixture(tmp_path)
    bare, _ = _run_ids(capsys, ["score", str(telemetry)])
    trusted, _ = _run_ids(capsys, ["score", str(telemetry),
                                   "--trust-store", str(store)])
    assert bare["trust_config_digest"] != trusted["trust_config_digest"]

    # And it is reproducible from the provenance beside it, which is what makes
    # it auditable rather than just another opaque field: a reader holding one
    # verdict can re-derive the digest and see it commits to what it claims to.
    for prov in (bare, trusted):
        assert prov["trust_config_digest"] == trust_config_digest(
            trust_store=prov["trust_store"],
            policy_attestations=prov["policy_attestations"],
            freshness=prov["evidence_freshness"],
            freshness_as_of_pinned=False,
            ledger={"enabled": prov["stream_ledger"]["enabled"],
                    "generation": prov["stream_ledger"].get("generation_read"),
                    "state": prov["stream_ledger"].get("state_digest_read", "")},
            correlation_key_version=prov["correlation_key_version"],
            correlation_keyed=prov["correlation_keyed"],
            baseline_partial_allowed=prov["baseline_partial_allowed"],
            schema=SESSION_SCHEMA)


@pytest.mark.parametrize("field,value", [
    ("trust_store", {"file_digest": "x", "semantic_digest": "y",
                     "key_count": 1}),
    ("policy_attestations", [{"artifact": "manifest", "status": "verified",
                              "key_id": "k", "file_sha256": "s"}]),
    ("freshness", {"enabled": True, "max_age_s": 60.0,
                   "max_future_skew_s": 300.0}),
    ("ledger", {"enabled": True, "generation": 3, "state": "abc"}),
    ("correlation_key_version", "hmac-sha256-v1"),
    ("correlation_keyed", True),
    ("baseline_partial_allowed", True),
    ("schema", "cohaera:0.9"),
])
def test_r06_every_trust_setting_moves_the_digest(field, value):
    """Each field is in there because it can change a verdict or how one should
    be read. A field that cannot move the digest is decorative, and this is what
    catches one being dropped from the canonical object later."""
    assert trust_config_digest(**{field: value}) != NO_TRUST_CONFIG


def test_r06_attestation_order_is_not_part_of_the_identity():
    """Two attestations are a set, not a sequence. Sorting them stops the order
    the CLI happened to build the list in from minting a second identity for
    one configuration."""
    a = {"artifact": "manifest", "status": "verified", "key_id": "k",
         "file_sha256": "1"}
    b = {"artifact": "baseline", "status": "absent", "key_id": "",
         "file_sha256": "2"}
    assert (trust_config_digest(policy_attestations=[a, b])
            == trust_config_digest(policy_attestations=[b, a]))


def test_r06_the_same_policy_bytes_verified_and_unverified_are_two_configs():
    """The outcome, not just the document. A manifest that verified and the
    same manifest whose signature did not hold govern the run differently even
    though the bytes are identical."""
    verified = {"artifact": "manifest", "status": "verified", "key_id": "k",
                "file_sha256": "same"}
    failed = dict(verified, status="invalid")
    assert (trust_config_digest(policy_attestations=[verified])
            != trust_config_digest(policy_attestations=[failed]))


def test_r06_a_pinned_as_of_is_in_the_identity_and_a_defaulted_one_is_not():
    """The deliberate deviation, and the reason is in trust_config_digest.

    An instant decides which records are stale, so by the rule this digest
    encodes it belongs in the identity. But an unpinned ``as_of`` is the wall
    clock at start-up, and folding a wall clock into a content digest would make
    every re-score of the same file a different run -- destroying the property
    the ID exists for. So the pinned instant counts and the defaulted one does
    not, while WHICH OF THE TWO happened counts either way.
    """
    pinned_a = trust_config_digest(
        freshness={"enabled": True, "max_age_s": 60.0, "as_of": 1000.0},
        freshness_as_of_pinned=True)
    pinned_b = trust_config_digest(
        freshness={"enabled": True, "max_age_s": 60.0, "as_of": 2000.0},
        freshness_as_of_pinned=True)
    assert pinned_a != pinned_b, "a pinned instant is part of the identity"

    drifting_a = trust_config_digest(
        freshness={"enabled": True, "max_age_s": 60.0, "as_of": 1000.0})
    drifting_b = trust_config_digest(
        freshness={"enabled": True, "max_age_s": 60.0, "as_of": 2000.0})
    assert drifting_a == drifting_b, (
        "an unpinned clock cannot enter, or re-scoring one file would never "
        "produce one run")
    assert drifting_a != pinned_a, (
        "but a run measured from an operator's chosen instant is a different "
        "kind of run from one measured off the wall clock, and the ID says so")


def test_r06_the_correlation_secret_never_enters_the_digest(tmp_path, capsys):
    """Only the key VERSION and whether a key was supplied. This digest is
    published in every verdict; hashing a secret into a published field is how
    a secret stops being one."""
    telemetry, _store = _identity_fixture(tmp_path)

    def with_secret(value):
        os.environ["COHAERA_CORRELATION_SECRET"] = value
        try:
            return _run_ids(capsys, ["score", str(telemetry)])[0]
        finally:
            os.environ.pop("COHAERA_CORRELATION_SECRET", None)

    one = with_secret("aa" * 32)
    two = with_secret("bb" * 32)
    assert one["correlation_keyed"] is True
    assert one["trust_config_digest"] == two["trust_config_digest"], (
        "two different secrets at the same key version are the same "
        "configuration as far as a published digest may say")

    unkeyed = _run_ids(capsys, ["score", str(telemetry)])[0]
    assert unkeyed["trust_config_digest"] != one["trust_config_digest"], (
        "but WHETHER a key was supplied changes every anonymous session id, "
        "so it is part of the configuration")


def test_r06_the_ledger_state_read_is_what_the_run_was_judged_against(tmp_path):
    """A ledger's state digest covers extent and head, and deliberately not the
    run counter or timestamps: those move when a stream is merely seen again,
    which changes no verdict and would break deduplication."""
    empty = StreamLedger()
    assert StreamLedger().state_digest() == empty.state_digest()

    seeded = StreamLedger()
    seeded.record(SeenVerdict("stream-a", SEEN_NEW), 0, 4, "head-1",
                  "run-1", None)
    assert seeded.state_digest() != empty.state_digest()

    again = StreamLedger()
    again.record(SeenVerdict("stream-a", SEEN_NEW), 0, 4, "head-1",
                 "run-2", 99.0)
    assert again.state_digest() == seeded.state_digest(), (
        "same streams at the same extent and head: the identity of the state "
        "that judgments are made against has not moved")


# =====================================================================
# R-17. A fallback whose meaning is weaker has to say so.
# =====================================================================


@pytest.mark.parametrize("authority,response,kind,assurance", [
    # The strong path and the weak path of the same adapter, side by side.
    ("kubernetes.apply", {"metadata": {"resourceVersion": "88213"}},
     "resource_version", ASSURANCE_OPERATION),
    ("kubernetes.apply", {"metadata": {"uid": "u-1"}},
     "resource_uid", ASSURANCE_OBJECT),
    ("github.create_pull_request", {"node_id": "PR_kwDO"},
     "node_id", ASSURANCE_OPERATION),
    ("github.create_pull_request", {"number": 6},
     "pull_request_number", ASSURANCE_OBJECT),
    ("jira.create_issue", {"key": "OPS-1"}, "issue_key", ASSURANCE_OPERATION),
    ("jira.create_issue", {"id": "10001"}, "issue_id", ASSURANCE_OBJECT),
    ("postgres.commit", {"commit_lsn": "0/16B3748"},
     "commit_lsn", ASSURANCE_OPERATION),
    ("postgres.commit", {"pg_current_wal_lsn": "0/16B3748"},
     "cluster_wal_position", ASSURANCE_OBJECT),
    ("smtp.send", {"server_message_id": "<a@h>"},
     "message_id", ASSURANCE_OPERATION),
    ("smtp.send", {"Message-ID": "<a@h>"},
     "client_message_id", ASSURANCE_CLIENT),
])
def test_a_weaker_path_gets_its_own_kind_and_says_it_is_weaker(
        authority, response, kind, assurance):
    """R-17, reproduced across every adapter that had the fault.

    These pairs used to emit the SAME kind. `metadata.uid` identifies the
    object for its whole life while `resourceVersion` identifies one mutation
    of it; a PR number is scoped to a repository while a node id is global; a
    Jira numeric id is not an issue key; and `pg_current_wal_lsn` is the
    cluster's write position, which moves because ANYBODY wrote. A consumer
    given the second under the first's name has no way to tell the difference
    between a weaker receipt and a forged one.
    """
    receipt = adapt(authority, response, BIND)
    assert receipt["kind"] == kind
    assert receipt["assurance"] == assurance
    parsed, codes = EffectReceipt.parse(receipt)
    assert parsed is not None and codes == ()


def test_no_adapter_claims_an_effect_is_confirmed():
    """None of the levels means the provider was asked. Nothing in this file
    contacts a provider, and a level called `verified` would be read as though
    something had."""
    assert ASSURANCE_OPERATION == "provider_returned_operation"
    for level in ASSURANCE_LEVELS:
        assert "verified" not in level and "confirmed" not in level


def test_a_nonfinite_number_is_not_an_identifier():
    """R-17. `float` went through `str` unconditionally, so a response carrying
    nan became the identifier text "nan" -- a parse failure wearing an
    identifier, which would have been stored and looked up by a human who found
    nothing."""
    for value in (float("nan"), float("inf"), float("-inf")):
        assert adapt("aws.s3.put_object", {"VersionId": value}, BIND) is None


def test_authority_scope_travels_when_the_producer_has_it():
    """R-17. "stripe" is a company, not an authority. A charge id is unique
    within one account and everybody has at least two, because test mode is
    one."""
    receipt = adapt("stripe.charge", {"id": "ch_1"}, BIND,
                    scope={"account": "acct_9", "livemode": "true"})
    assert receipt["scope"] == {"account": "acct_9", "livemode": "true"}
    parsed, codes = EffectReceipt.parse(receipt)
    assert parsed is not None and codes == (), (
        "an optional scope must not make the receipt unparseable")


def test_a_producer_without_a_scope_omits_it_rather_than_inventing_one():
    assert "scope" not in adapt("stripe.charge", {"id": "ch_1"}, BIND)
    assert "scope" not in adapt("stripe.charge", {"id": "ch_1"}, BIND, scope={})


def test_every_adapter_path_declares_a_known_assurance_level():
    """The registry is edited by hand and a typo in an assurance string would
    produce a receipt whose worth nothing can compare."""
    for name, spec in _ADAPTERS.items():
        for path, kind, assurance in spec["paths"]:
            assert assurance in ASSURANCE_LEVELS, (
                f"{name}:{path} declares unknown assurance {assurance!r}")
            assert kind and kind.replace("_", "").isalnum(), (
                f"{name}:{path} has a malformed kind {kind!r}")
