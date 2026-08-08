"""Ed25519, in pure Python, because Cohaera has no dependencies.

WHY THIS FILE EXISTS AT ALL
---------------------------
P1.1 (see ``docs/EVIDENCE-TRUST.md``) moves the trust in a telemetry stream from
"the agent said so" to "the collector signed it". That needs a signature scheme
whose verification key is public, so that a verifier holding the key cannot
forge what it verifies. HMAC would not do: a shared secret means Cohaera could
mint the very records it is attesting to, and an operator reading a verdict
could not tell the difference.

The standard library has SHA-512 and nothing else that helps, and the whole
project is deliberately dependency-free -- CI asserts a zero-dependency install,
because a security tool that drags a transitive tree into a collector VM has
made the collector's attack surface its own problem. So the scheme is here, and
it is RFC 8032 Ed25519 with nothing invented.

WHAT IS AND IS NOT SAFE ABOUT THIS
----------------------------------
``verify`` is the function Cohaera uses, and it operates entirely on public
values: a public key, a message, and a signature, all of which an attacker
already has. There is no secret to leak through timing, so the fact that this
implementation is not constant-time does not matter for that path.

``sign`` and ``public_key`` handle a SECRET and are NOT constant-time. They are
here because ``tools/collector_sign.py`` needs them to produce reference
streams and the tests need them to construct a signed stream to attack, and
because splitting the field arithmetic across two files to hide four lines
would make both harder to check. **Cohaera itself never calls them.** Do not
sign production telemetry with this on a host where an adversary can measure
the process; use libsodium.

That asymmetry is why the two paths multiply differently. ``verify`` uses a
precomputed comb for ``s * G`` (see ``_mul_base``), which is about 6.7 times
faster and is safe precisely because ``s`` comes out of the signature and is
public. ``sign`` and ``public_key`` keep plain double-and-add: their scalars are
secret, and indexing a table with a secret's digits would trade a
secret-dependent branch for a secret-dependent memory access, which is a
side channel this file has no business introducing for a speed-up nothing in
Cohaera's path would use.

WHAT IS CHECKED
---------------
``tests/test_evidence.py`` runs the four RFC 8032 section 7.1 test vectors,
plus the negative cases that a hand-written verifier gets wrong: a flipped bit
in the signature, the wrong public key, a non-canonical point encoding, and a
scalar ``S >= L``. That last one is the malleability check, and omitting it is
the classic Ed25519 verifier bug -- without it, anyone can turn one valid
signature into a second, different, also-valid signature for the same message,
which would let an attacker rewrite the ``sig`` field of a record whose chain
they wanted to keep intact.
"""

from __future__ import annotations

import functools
import hashlib

# The prime field, the group order, and the twisted-Edwards curve constant.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

KEY_BYTES = 32
SIG_BYTES = 64

# Points are (X, Y, Z, T) in extended homogeneous coordinates, where the affine
# point is (X/Z, Y/Z) and T satisfies X*Y = Z*T. The identity is (0, 1, 1, 0).
_IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int | None:
    """The x coordinate matching this y, with the requested parity, or None.

    Returns None for a y that is not on the curve and for the one encoding that
    is on the curve but non-canonical: x == 0 with the sign bit set. Rejecting
    that case is what stops two distinct byte strings from decoding to the same
    point, which is a distinctness property signature verification relies on.
    """
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None                      # y is not the y of any curve point
    if (x & 1) != sign:
        x = P - x
    return x


_G_Y = 4 * pow(5, P - 2, P) % P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None                  # the base point is a constant, not input
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % P)


def _add(p: tuple[int, int, int, int],
         q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Unified addition (add-2008-hwcd-3). Correct when p is q, so it doubles."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * _D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(p: tuple[int, int, int, int], s: int) -> tuple[int, int, int, int]:
    """Scalar multiplication, double-and-add. Not constant-time; see the module
    docstring for why that is acceptable on the verification path and not on the
    signing one."""
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


# ---------------------------------------------------------------------------
# Fixed-base multiplication
# ---------------------------------------------------------------------------
#
# Half of every verification is ``s * G``, and G is a constant. Double-and-add
# does not know that: it spends about 380 point additions rediscovering the
# multiples of a point that never changes. A comb precomputes them once --
# (d+1) * 2^(4i) * G, for every 4-bit digit d at every digit position i -- after
# which the multiplication is a lookup and an add per nonzero digit, and there
# are at most 64 of those.
#
# WHAT THIS IS NOT. It is not a different algorithm and not a different result:
# the table is built by the same ``_add`` from the same ``_G``, and
# ``tests/test_evidence.py`` checks it against ``_mul(_G, s)`` directly, on the
# boundaries as well as at random. The RFC 8032 vectors still run through
# ``verify`` unchanged.
#
# WHY VERIFICATION ONLY. ``sign`` and ``public_key`` keep double-and-add. Both
# multiply by a SECRET scalar, and a table indexed by that scalar's digits
# replaces a secret-dependent branch with a secret-dependent memory access --
# the textbook cache-timing side channel. Neither path is constant-time and the
# module docstring says so, but there is no reason to add a new class of leak to
# the secret path for a saving nothing needs: signing here produces test
# fixtures, and ``eval/corpus/signatures.py`` already caches the ones that used
# to cost anything.
_COMB_WINDOW = 4
_COMB_MASK = (1 << _COMB_WINDOW) - 1
_COMB_BITS = 256                         # every scalar this is asked for is < L
_COMB_ROWS = _COMB_BITS // _COMB_WINDOW


@functools.lru_cache(maxsize=1)
def _comb() -> tuple[tuple[tuple[int, int, int, int], ...], ...]:
    """The table, built once on first use. ``_comb.cache_info().currsize`` says
    whether it exists yet, which is how the tests check it was not built at
    import and is not built by signing."""
    rows = []
    base = _G
    for _ in range(_COMB_ROWS):
        row = [base]
        for _ in range(_COMB_MASK - 1):
            row.append(_add(row[-1], base))
        rows.append(tuple(row))
        for _ in range(_COMB_WINDOW):     # base <<= window, i.e. * 2^4
            base = _add(base, base)
    return tuple(rows)


def _mul_base(s: int) -> tuple[int, int, int, int]:
    """``s * G``, by table lookup rather than double-and-add.

    BUILT ON FIRST USE, NOT AT IMPORT. The table costs about 7 ms and 960 points
    to build, which is roughly five verifications' worth of the saving -- so a
    process that verifies nothing (every ``cohaera score`` over telemetry with
    no ``cohaera.integrity:1`` sidecars, which is still the common case) must not
    pay for it, and one that verifies four signatures comes out slightly behind.
    The case worth optimising is the other one: ``max_signature_verifications``
    bounds a producer-controlled quantity at 100,000, and that worst case is
    where this earns its keep.
    """
    if s < 0 or s >= 1 << _COMB_BITS:     # pragma: no cover - unreachable for s < L
        return _mul(_G, s)                # wider than the table: be right, not fast
    q = _IDENTITY
    for row in _comb():
        if not s:
            break
        digit = s & _COMB_MASK
        if digit:
            q = _add(q, row[digit - 1])
        s >>= _COMB_WINDOW
    return q


def _equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    """Projective equality: cross-multiply rather than normalise both sides."""
    if (p[0] * q[2] - q[0] * p[2]) % P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % P == 0


def _decompress(blob: bytes) -> tuple[int, int, int, int] | None:
    if len(blob) != KEY_BYTES:
        return None
    y = int.from_bytes(blob, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _compress(p: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x = x * zi % P
    y = y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), KEY_BYTES, "little")


def _sha512_int(blob: bytes) -> int:
    return int.from_bytes(hashlib.sha512(blob).digest(), "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if ``signature`` is a valid Ed25519 signature over ``message``.

    Never raises. Every malformed input -- a key of the wrong length, a point
    that is not on the curve, a signature whose scalar is out of range -- is a
    verification failure, because from Cohaera's position "this is not a valid
    signature" and "this is not a signature at all" call for the same verdict
    and an exception in the middle of a scoring run does not.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != KEY_BYTES:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIG_BYTES:
        return False
    public_key = bytes(public_key)
    signature = bytes(signature)

    a_point = _decompress(public_key)
    if a_point is None:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    r_point = _decompress(r_bytes)
    if r_point is None:
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        # Malleability. Without this, s + L (mod 2^256) is a second valid
        # signature over the same message under the same key, so a signature
        # would not uniquely identify the bytes that produced it.
        return False
    k = _sha512_int(r_bytes + public_key + message) % L
    return _equal(_mul_base(s), _add(r_point, _mul(a_point, k)))


# ---------------------------------------------------------------------------
# Signing. Used by tools/collector_sign.py and by the tests. NOT by Cohaera.
# ---------------------------------------------------------------------------


def _clamp(blob: bytes) -> int:
    a = int.from_bytes(blob[:32], "little")
    a &= (1 << 254) - 8                  # clear the low 3 bits: cofactor
    a |= 1 << 254                        # set bit 254: fixed high bit
    return a


def public_key(secret: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret seed."""
    if len(secret) != KEY_BYTES:
        raise ValueError(f"secret must be {KEY_BYTES} bytes, got {len(secret)}")
    h = hashlib.sha512(secret).digest()
    return _compress(_mul(_G, _clamp(h)))


def sign(secret: bytes, message: bytes) -> bytes:
    """Sign with a 32-byte secret seed. Not constant-time; see the docstring."""
    if len(secret) != KEY_BYTES:
        raise ValueError(f"secret must be {KEY_BYTES} bytes, got {len(secret)}")
    h = hashlib.sha512(secret).digest()
    a = _clamp(h)
    prefix = h[32:]
    a_bytes = _compress(_mul(_G, a))
    r = _sha512_int(prefix + message) % L
    r_bytes = _compress(_mul(_G, r))
    k = _sha512_int(r_bytes + a_bytes + message) % L
    return r_bytes + int.to_bytes((r + k * a) % L, 32, "little")
