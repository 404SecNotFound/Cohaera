# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Measure what an external corpus can and cannot discriminate.

A detection result of zero has two very different explanations, and a number
alone does not separate them:

  1. the detector looked and missed, or
  2. the discriminative signal is not in the fields the detector reads.

This probe answers the second question about the *corpus*, independently of
Cohaera. It reads no verdict, imports nothing from ``cohaera``, and would give
the same answer if the detector were deleted. That independence is the point:
it is evidence about the measuring stick rather than about the thing measured.

What it measures on StepShield's paired split, where every task ships as one
``-ROGUE`` and one ``-CLEAN`` rendering:

``identical_sequence_pairs``
    Pairs whose tool-call sequences are equal, action for action. For these,
    the rogue and clean renderings are the *same trace* as far as any
    sequence-based check can see. No tuning reaches them; they are a hard
    ceiling on structural recall, not a tuning failure.

``same_length_pairs``
    Pairs of equal step count. Weaker than the above, and reported because a
    length difference is the crudest signal a structural check could use.

``rogue_arg_values_also_on_clean_steps``
    Argument values appearing both on annotator-labelled rogue steps and on
    unlabelled ones. A value on both sides carries no label information.

The counts print as a JSON object so a document can derive its sentences from
this file rather than restating them. Run it against a StepShield checkout::

    python eval/external/corpus_probe.py --stepshield-train PATH/data/train

Nothing here is Cohaera-specific and nothing here is a detection result.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
from typing import Any

ROGUE_SUFFIX = "-ROGUE"
CLEAN_SUFFIX = "-CLEAN"


def _load(path: pathlib.Path) -> dict[str, Any]:
    """Read one trajectory.

    StepShield names its files ``.jsonl`` but each holds a single
    pretty-printed JSON object spanning many lines, so a line-at-a-time reader
    fails on the first one. Read whole and parse whole.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def _sequence(record: dict[str, Any]) -> tuple[str | None, ...]:
    return tuple(step.get("action") for step in record.get("steps") or ())


def probe_stepshield_train(root: pathlib.Path) -> dict[str, Any]:
    """Measure the paired split's discriminability. Pure counting."""
    pairs: dict[str, dict[str, pathlib.Path]] = collections.defaultdict(dict)
    for path in sorted(root.rglob("*.jsonl")):
        stem = path.stem
        if stem.endswith(ROGUE_SUFFIX):
            pairs[stem[: -len(ROGUE_SUFFIX)]]["rogue"] = path
        elif stem.endswith(CLEAN_SUFFIX):
            pairs[stem[: -len(CLEAN_SUFFIX)]]["clean"] = path

    complete = {k: v for k, v in pairs.items() if len(v) == 2}
    if not complete:
        raise SystemExit(
            f"{root}: no complete ROGUE/CLEAN pairs found. Point --stepshield-train "
            "at the corpus's data/train directory.")

    actions: collections.Counter[str | None] = collections.Counter()
    rogue_args: collections.Counter[str] = collections.Counter()
    clean_args: collections.Counter[str] = collections.Counter()
    identical = same_length = 0
    labelled_rogue_steps = 0

    for entry in complete.values():
        rogue, clean = _load(entry["rogue"]), _load(entry["clean"])
        a, b = _sequence(rogue), _sequence(clean)
        identical += a == b
        same_length += len(a) == len(b)
        for record in (rogue, clean):
            for step in record.get("steps") or ():
                actions[step.get("action")] += 1
                values = [v for v in (step.get("arguments") or {}).values()
                          if isinstance(v, str)]
                if step.get("label"):
                    labelled_rogue_steps += 1
                    for v in values:
                        rogue_args[v] += 1
                else:
                    for v in values:
                        clean_args[v] += 1

    overlap = set(rogue_args) & set(clean_args)
    total = len(complete)
    return {
        "corpus": "stepshield",
        "split": "train (paired)",
        "pairs": total,
        "identical_sequence_pairs": identical,
        "identical_sequence_pct": round(100 * identical / total, 1),
        "same_length_pairs": same_length,
        "same_length_pct": round(100 * same_length / total, 1),
        "distinct_actions": len(actions),
        "actions": dict(actions.most_common()),
        "labelled_rogue_steps": labelled_rogue_steps,
        "distinct_rogue_arg_values": len(rogue_args),
        "rogue_arg_values_also_on_clean_steps": len(overlap),
        "rogue_arg_overlap_pct": round(100 * len(overlap) / max(len(rogue_args), 1), 1),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--stepshield-train", metavar="DIR", required=True,
                    type=pathlib.Path,
                    help="StepShield's data/train directory, holding the paired "
                         "-ROGUE / -CLEAN trajectories.")
    ap.add_argument("--json", metavar="FILE", type=pathlib.Path,
                    help="Write the result as JSON.")
    args = ap.parse_args(argv)

    result = probe_stepshield_train(args.stepshield_train)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(text, encoding="utf-8")
        print(f"wrote {args.json}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
