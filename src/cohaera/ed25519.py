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

That asymmetry is why the two paths multiply differently. ``verify`` splits into
``s * G`` and ``k * A``, and has a faster routine for each: ``_mul_base`` reads
a precomputed comb, because G is a constant, and ``_mul_var`` slides a window,
because A arrives with the input and only the additions can be saved. Both
scalars come out of the signature and the hash of it, so both are public and
neither leaks anything by being read unevenly.

``sign`` and ``public_key`` call neither. Their scalars are SECRET, and both
routines are secret-dependent in a way plain double-and-add is not: one indexes
a table with the scalar's digits, the other branches on runs of its bits. That
is a cache-timing side channel, and there is no reason to introduce one on the
secret path for a speed-up nothing in Cohaera's own path would use --
``tests/test_evidence.py`` booby-traps both routines and checks that signing
still reproduces the RFC vectors.

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
# Comb multiplication, for points that repeat
# ---------------------------------------------------------------------------
#
# Double-and-add spends about 380 point additions rediscovering the multiples of
# a point. When the point is the same one every time, that is waste: a comb
# precomputes them -- (d+1) * 2^(4i) * P, for every 4-bit digit d at every digit
# position i -- after which a multiplication is a lookup and an add per nonzero
# digit, at most 64 of them. About 6.7 times faster, for 960 points and 302 KB.
#
# TWO POINTS REPEAT, FOR DIFFERENT REASONS. G repeats because it is a constant.
# A signer's public key repeats because a collector signs a whole stream with one
# key, so a scoring run verifying thousands of records is verifying them under a
# handful of keys. Both get combs; the difference is only in what bounds them,
# below.
#
# WHAT THIS IS NOT. Not a different algorithm and not a different result: tables
# are built by the same ``_add`` from the same points, and
# ``tests/test_evidence.py`` checks them against ``_mul`` directly, on the digit
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

_Comb = tuple


def _build_comb(p: tuple[int, int, int, int]) -> tuple:
    rows = []
    base = p
    for _ in range(_COMB_ROWS):
        row = [base]
        for _ in range(_COMB_MASK - 1):
            row.append(_add(row[-1], base))
        rows.append(tuple(row))
        for _ in range(_COMB_WINDOW):     # base <<= window, i.e. * 2^4
            base = _add(base, base)
    return tuple(rows)


def _comb_mul(table: tuple, s: int) -> tuple[int, int, int, int]:
    q = _IDENTITY
    for row in table:
        if not s:
            break
        digit = s & _COMB_MASK
        if digit:
            q = _add(q, row[digit - 1])
        s >>= _COMB_WINDOW
    return q


@functools.lru_cache(maxsize=1)
def _comb() -> tuple:
    """G's table, built once on first use. ``_comb.cache_info().currsize`` says
    whether it exists yet, which is how the tests check it was not built at
    import and is not built by signing."""
    return _build_comb(_G)


def _mul_base(s: int) -> tuple[int, int, int, int]:
    """``s * G``, by table lookup rather than double-and-add.

    BUILT ON FIRST USE, NOT AT IMPORT. The table costs about 7 ms to build,
    roughly five verifications' worth of the saving -- so a process that verifies
    nothing (every ``cohaera score`` over telemetry with no
    ``cohaera.integrity:1`` sidecars, which is still the common case) must not
    pay for it, and one that verifies four signatures comes out slightly behind.
    The case worth optimising is the other one: ``max_signature_verifications``
    bounds a producer-controlled quantity at 100,000.
    """
    if s < 0 or s >= 1 << _COMB_BITS:     # pragma: no cover - unreachable for s < L
        return _mul(_G, s)                # wider than the table: be right, not fast
    return _comb_mul(_comb(), s)


# ---------------------------------------------------------------------------
# Combs for signers' keys
# ---------------------------------------------------------------------------
#
# G's table is one table for the life of the process. A key's table is not, and
# the difference is the whole design here: how many keys a run sees is decided
# outside this file, so an unbounded cache would be a memory bug and an evicting
# one would be a performance bug -- a stream alternating between more hot keys
# than the cache holds would rebuild a 7 ms table per verification and come out
# far slower than plain double-and-add. Neither is acceptable in code reachable
# from a producer-controlled record count.
#
# So: no eviction, ever. A fixed number of tables, given to the first keys that
# prove they are worth one, and every other key keeps using ``_mul_var``, which
# is what it would have used anyway. That makes the WORST case this can cost a
# fixed 8 x 7 ms once per process, and the best case a 6.7x on half of every
# verification for the streams that actually repeat a key -- which is all of the
# ones with a collector behind them.
#
# The counter is bounded for the same reason. Keys reaching here have already
# been found in the operator's trust store, so the population is bounded by
# ``limits.max_collector_keys`` rather than by anything an attacker writes; the
# cap is belt and braces against that stopping being true.
_MAX_KEY_COMBS = 8                       # 8 x 302 KB, hard ceiling
_MAX_TRACKED_KEYS = 64
_KEY_COMB_USES = 8                       # break-even is ~3.5; wait for a margin

_KEY_COMBS: dict[bytes, tuple] = {}
_KEY_USES: dict[bytes, int] = {}


def _key_comb(public_key: bytes, point: tuple[int, int, int, int]) -> tuple | None:
    """The table for a key that keeps coming back, or None to use ``_mul_var``.

    ``public_key`` is the compressed encoding and ``point`` its decompression;
    the encoding is the cache key because it is 32 bytes and already hashable,
    and because two encodings that decode to the same point cannot both reach
    here -- ``_recover_x`` rejects the non-canonical one.
    """
    table = _KEY_COMBS.get(public_key)
    if table is not None:
        return table
    if len(_KEY_COMBS) >= _MAX_KEY_COMBS:
        return None                      # full. Everyone else keeps the window.
    uses = _KEY_USES.get(public_key)
    if uses is None and len(_KEY_USES) >= _MAX_TRACKED_KEYS:
        return None
    uses = (uses or 0) + 1
    _KEY_USES[public_key] = uses
    if uses < _KEY_COMB_USES:
        return None
    table = _build_comb(point)
    _KEY_COMBS[public_key] = table
    return table


# ---------------------------------------------------------------------------
# Variable-base multiplication
# ---------------------------------------------------------------------------
#
# The other half of a verification is ``k * A``, where A is the signer's public
# key. No table can be precomputed for a point that arrives with the input, so
# the doublings stay: what a sliding window removes is additions. Double-and-add
# adds once per set bit -- about 127 times for a 254-bit scalar. Reading the
# scalar in runs of up to five bits instead, against a table of the odd
# multiples 1A, 3A .. 31A, brings that to about 50.
#
# THE RETURN IS SMALL AND THAT IS THE HONEST NUMBER: roughly 1.2x on this
# multiplication, because the ~254 doublings it cannot avoid are most of the
# work and are untouched. It is here because it is exact, self-contained and
# costs nothing when unused -- not because it changes the shape of anything.
#
# Same division as the comb: this is for VERIFICATION only. ``_mul`` stays the
# plain double-and-add that ``sign`` and ``public_key`` use on secret scalars,
# and that these are tested against.
_VAR_WINDOW = 5
_VAR_TABLE = 1 << (_VAR_WINDOW - 1)      # 1A, 3A, 5A ... (2^w - 1)A


def _odd_multiples(p: tuple[int, int, int, int]) -> list[tuple[int, int, int, int]]:
    twice = _add(p, p)
    table = [p]
    for _ in range(_VAR_TABLE - 1):
        table.append(_add(table[-1], twice))
    return table


def _mul_var(p: tuple[int, int, int, int], s: int) -> tuple[int, int, int, int]:
    """``s * p`` for a point that is not known in advance, by sliding window.

    Left to right, so the window is chosen from the bits still ahead rather than
    from a recoding of the whole scalar. Every window is odd by construction --
    it always starts on a set bit and is trimmed back to one -- which is why the
    table holds only the odd multiples and is half the size it looks.
    """
    if s <= 0:                            # pragma: no cover - k is a reduced hash
        return _mul(p, s)                 # identity, via the reference path
    table = _odd_multiples(p)
    q = _IDENTITY
    i = s.bit_length() - 1
    while i >= 0:
        if not (s >> i) & 1:
            q = _add(q, q)                # a zero bit is a doubling and nothing else
            i -= 1
            continue
        low = max(i - _VAR_WINDOW + 1, 0)
        while not (s >> low) & 1:         # trim: the window must end on a set bit
            low += 1
        width = i - low + 1
        digit = (s >> low) & ((1 << width) - 1)
        for _ in range(width):
            q = _add(q, q)
        q = _add(q, table[(digit - 1) // 2])
        i = low - 1
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
    table = _key_comb(public_key, a_point)
    ka = _comb_mul(table, k) if table is not None else _mul_var(a_point, k)
    return _equal(_mul_base(s), _add(r_point, ka))


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
