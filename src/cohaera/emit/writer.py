"""``JsonlWriter``: one record per line, in the bytes the verifier reads back.

Small on purpose. The two decisions in it are the ones a collector author
would otherwise make differently from the verifier:

    ``allow_nan=False``   ``json.dumps`` writes ``NaN`` by default, and the
                          strict reader (``cohaera.validate.strict_json_loads``)
                          quarantines the line. A record that was signed and
                          then written as something the verifier refuses is a
                          sequence gap of the collector's own making. Refused
                          at write time, with the exception ``json`` raises.
    ``ensure_ascii=False`` Non-ASCII text is written as itself. The chain is
                          computed over the canonical form, which is
                          independent of this choice; what the choice buys is
                          a file an analyst can read without decoding escapes.

Flushed after every line so a collector killed between records loses at most
the record it was writing, and the signer state persisted after ``write``
returned describes records that reached the kernel.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import IO, Any


class JsonlWriter:
    """Append JSON objects to a file, one per line, ``\\n`` terminated."""

    def __init__(self, path: str | Path, *, append: bool = True,
                 sort_keys: bool = True) -> None:
        self._path = Path(path)
        self._sort_keys = sort_keys
        # newline="" so the "\n" written is the "\n" stored on every platform;
        # a translated line ending would still parse, but byte-identical output
        # is what makes two collectors' files comparable by digest.
        self._handle: IO[str] | None = open(
            self._path, "a" if append else "w", encoding="utf-8", newline="")
        self._count = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def count(self) -> int:
        """Records written by this writer since it was opened."""
        return self._count

    def write(self, record: Mapping[str, Any]) -> None:
        if self._handle is None:
            raise ValueError(f"{self._path}: writer is closed")
        if not isinstance(record, Mapping):
            raise TypeError(f"a record is a JSON object (dict), got "
                            f"{type(record).__name__}")
        line = json.dumps(dict(record), ensure_ascii=False, allow_nan=False,
                          sort_keys=self._sort_keys)
        self._handle.write(line + "\n")
        self._handle.flush()
        self._count += 1

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> JsonlWriter:
        return self

    def __exit__(self, exc_type: type[BaseException] | None,
                 exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()
