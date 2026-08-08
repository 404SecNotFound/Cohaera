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
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cohaera import ed25519
from cohaera.capabilities import CapabilityManifest
from cohaera.checks import (
    CH04_BYPASSED,
    CH04_COMPLETED,
    CH06_INTEGRITY,
    CH07_CONTRADICTED,
    CH07_UNBOUND,
    EVIDENCE_INADMISSIBLE,
    EVIDENCE_UNATTESTED,
    EVIDENCE_VERIFIED,
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
    APPROVAL_SCHEMA,
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
    R_KEY_EXPIRED,
    R_KEY_NOT_YET_VALID,
    R_KEY_REVOKED,
    R_KEY_UNKNOWN,
    R_KEY_WINDOW_UNCHECKED,
    R_KEY_WRONG_ROLE,
    R_NO_COLLECTOR_KEYS,
    R_NO_STREAM_LEDGER,
    R_PARTIAL_INTEGRITY,
    R_REORDER_BUDGET,
    R_REORDERED,
    R_SEQUENCE_GAP,
    R_SEQUENCE_REPLAY,
    R_SIGNATURE_INVALID,
    R_STALE,
    R_STREAM_FORKED,
    R_STREAM_REPLAYED,
    R_STREAM_SKIPPED_RECORDS,
    RECEIPT_SCHEMA,
    ROLE_COLLECTOR,
    ROLE_POLICY,
    TRUST_STORE_SCHEMA,
    W_ALL_KEYS_REVOKED,
    W_LEGACY_SCHEMA,
    W_ROTATION_CYCLE,
    W_SUPERSEDED_OPEN,
    Approval,
    EffectReceipt,
    Freshness,
    Integrity,
    LedgerError,
    PolicySignature,
    PolicySignatureError,
    StreamLedger,
    StreamVerifier,
    TrustStore,
    TrustStoreError,
    arg_digest,
    file_sha256,
    policy_signing_input,
    verify_policy_signature,
)
from cohaera.ingest import assemble
from cohaera.limits import (
    DEFAULT_LIMITS,
    DEFECT_APPROVAL_TYPE,
    DEFECT_INTEGRITY_TYPE,
    DEFECT_RECEIPT_TYPE,
)
from cohaera.model import Event, Session
from tools.collector_sign import key_id_for, keys_document, sign_stream
from tools.receipt_adapters import (
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
        expected = (EVIDENCE_VERIFIED if f.check == CH06_INTEGRITY
                    else EVIDENCE_INADMISSIBLE)
        assert f.evidence_status == expected


def test_ch06_stays_quiet_on_a_stream_that_verifies():
    signed = sign_stream(_records(4), "stream-a", SECRET, KEY_ID)
    sessions = assemble([Event(raw=r) for r in signed], keys=KEYS)
    assert ch06_evidence_integrity(sessions[0]) == []
    assert evidence_status(sessions[0]) == EVIDENCE_VERIFIED


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
    in the one direction that costs an analyst their trust in the code."""
    signed = sign_stream(_records(3), "stream-a", SECRET, KEY_ID)
    state = _run(signed, freshness=Freshness(max_age_s=60.0, as_of=0.0)
                 ).for_session("sess-1")
    assert R_STALE not in state.codes


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
        "max_age_s": 3600.0, "as_of": 1785700000.0, "enabled": True}


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
