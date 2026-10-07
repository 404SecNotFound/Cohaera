"""Field checks shared by the producers in this package.

The verifier's schema firewall (``cohaera.validate``) treats a malformed field
as ABSENT and flags it. That is the right rule for a reader of hostile input
and the wrong rule for a writer: an emitter that lets a bad value through
produces a record the verifier will quietly weaken -- an approval whose
``span_id`` carries a newline is parsed, bound to nothing, and reported as
``claimed`` rather than refused. Everything here therefore raises. A producer
should find out at the point it minted the value, not in a verdict a month
later.

The bounds are the verifier's own (``DEFAULT_LIMITS``), imported rather than
restated, so that what this package refuses to emit is exactly what
``cohaera.evidence`` would refuse to read.
"""

from __future__ import annotations

import math
import re
from typing import Any

from ..limits import DEFAULT_LIMITS

# The same class ``cohaera.validate.sanitise_display`` escapes: every C0
# control, DEL, and the C1 range. An identity that CONTAINS one of these is
# itself a finding on the verifier side (SEC-08), so it is a refusal here.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# ``cohaera.validate.json_safe`` bounds its walk at this depth and substitutes
# a marker beyond it. A record nested deeper would therefore be HASHED as a
# different structure from the one written, and the chain would break on a
# record nobody edited.
MAX_JSON_DEPTH = 100

# ``cohaera.validate.MAX_JSON_INT_DIGITS``: the strict reader quarantines an
# integer wider than this, so a record carrying one is a record that will never
# be scored, and signing it attests a line the verifier refuses.
_MAX_INT = 10 ** 1024


def identity(value: Any, name: str,
             max_chars: int = DEFAULT_LIMITS.max_identity_chars) -> str:
    """A non-empty, bounded string with no control characters, or ValueError.

    ``bool`` is refused before ``str`` for the reason ``validate.identity_text``
    gives: ``True`` is not a name, and ``True == 1`` is how a span once got
    closed by a terminal event carrying a different type.
    """
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"{name} must be a string, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value) > max_chars:
        raise ValueError(
            f"{name} is {len(value)} characters; the verifier reads at most "
            f"{max_chars} and would treat a longer one as absent")
    hit = _CONTROL.search(value)
    if hit:
        raise ValueError(
            f"{name} contains a control character (\\x{ord(hit.group()):02x}); "
            f"an identity with one in it is a finding, not a name")
    return value


def optional_identity(value: Any, name: str) -> str | None:
    return None if value is None else identity(value, name)


def finite(value: Any, name: str) -> float:
    """A finite number as a float, or ValueError. Booleans are not numbers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number, got {type(value).__name__}")
    out = float(value)
    if not math.isfinite(out):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return out


def optional_finite(value: Any, name: str) -> float | None:
    return None if value is None else finite(value, name)


def require_strict_json(value: Any, path: str = "record", depth: int = 0) -> None:
    """Refuse anything ``cohaera.validate.strict_json_loads`` would not read back.

    The chain is computed over ``canonical(record)``, which coerces: a NaN
    becomes a marker, a set becomes a list, an unknown object becomes its
    ``repr``. The record a writer then serialises is a different thing -- or
    ``json.dumps`` raises on it, or the strict reader quarantines it -- and in
    every one of those cases the signature was made over bytes nobody ever
    stored. So the signer refuses the record before it is chained, with the
    path to the offending value, rather than producing a sidecar that fails to
    verify for a reason the operator cannot see.
    """
    if depth > MAX_JSON_DEPTH:
        raise ValueError(
            f"{path}: nested deeper than {MAX_JSON_DEPTH}; the verifier hashes "
            f"a truncated structure beyond that depth and the chain would break")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not -_MAX_INT < value < _MAX_INT:
            raise ValueError(f"{path}: integer is wider than the strict reader "
                             f"accepts (1024 digits)")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}: {value!r} is not a JSON number")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"{path}: key {key!r} is not a string; JSON keys are strings "
                    f"and a writer would spell this one differently from the hash")
            require_strict_json(item, f"{path}.{key}", depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            require_strict_json(item, f"{path}[{index}]", depth + 1)
        return
    raise ValueError(f"{path}: {type(value).__name__} is not a JSON value")
