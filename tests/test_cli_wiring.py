# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""Every option the CLI parses must be read somewhere in the CLI.

``--seen-approvals`` was parsed, documented in ``--help``, cited by
``CHANGELOG.md`` and ``EVASION.md`` as the remedy for E26, and never read:
``args.seen_approvals`` appears nowhere in ``src/cohaera/cli.py``. An operator
who passed it got a ledger that was never opened and a nonce that was never
spent, and nothing -- not the exit code, not stderr, not the verdict's
provenance -- said so. ``--require-signed-approvals`` is the same.

That is a declared control that enforces nothing, which is the shape this
repository treats as worse than no control: ``tests/test_lab.py`` pins the same
defect in the PowerShell builder (``-TimeoutSec`` declared and never read), and
``tests/test_ci_config.py`` pins it in the ruleset (a required check no job
reports). This file pins it in the parser.

The check is STATIC, over the AST rather than by running the CLI, because the
failure mode is an option that is accepted and ignored, which no invocation can
distinguish from an option that is accepted and obeyed. The parser is read for
every ``add_argument`` and the destination argparse would assign; the rest of
the module is read for every ``args.<dest>`` and ``getattr(args, "<dest>")``;
and the first set must be a subset of the second.

Two deliberate limits. A destination is only counted as read when the attribute
is taken off a name that is bound to an ``argparse.Namespace`` -- a parameter
annotated as one, or the ``args`` the parser returns -- so a stray ``.strict``
on some other object does not count. And ``vars(args)`` is forbidden outright:
it reads every destination at once and would make this test pass for anything.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "src" / "cohaera" / "cli.py"

# Options that are parsed and known NOT to be read, each with the reason and
# the thing that will fix it. The pairing is enforced both ways: an entry here
# whose destination IS read fails the suite, so the day the wiring lands the
# entry has to go in the same change. An entry without a reason is not allowed
# to exist, and an entry is not a licence -- it is a defect with a name.
KNOWN_INERT: dict[str, str] = {
    "seen_approvals":
        "Parsed and never read: the approval-nonce ledger EVASION.md E26 "
        "names as its remedy is never opened. Wiring it is a change to "
        "src/cohaera/cli.py; delete this entry in that change.",
    "require_signed_approvals":
        "Parsed and never read: an unsigned approval still covers a call "
        "with the flag set. Same change as seen_approvals; delete this "
        "entry with it.",
}


def _tree() -> ast.Module:
    return ast.parse(CLI.read_text(encoding="utf-8"), filename=str(CLI))


def _string(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def declared_destinations(tree: ast.Module) -> dict[str, int]:
    """``{dest: line}`` for every ``add_argument`` call in the module.

    The destination is derived the way argparse derives it: an explicit
    ``dest=`` wins; otherwise the first long option with its leading dashes
    stripped and inner dashes turned to underscores; otherwise the short
    option; otherwise the positional's own name. ``action="help"`` and
    ``action="version"`` store nothing and are skipped.
    """
    out: dict[str, int] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            continue
        keywords = {k.arg: k.value for k in node.keywords if k.arg}
        if _string(keywords.get("action")) in ("help", "version"):
            continue
        dest = _string(keywords.get("dest"))
        if dest is None:
            flags = [s for s in (_string(a) for a in node.args) if s is not None]
            assert flags, f"{CLI.name}:{node.lineno}: add_argument with no name"
            long = [f for f in flags if f.startswith("--")]
            if long:
                dest = long[0][2:].replace("-", "_")
            elif flags[0].startswith("-"):
                dest = flags[0].lstrip("-").replace("-", "_")
            else:
                dest = flags[0].replace("-", "_")
        assert dest not in out, (
            f"{CLI.name}:{node.lineno}: destination {dest!r} is declared "
            f"twice (first at line {out[dest]})")
        out[dest] = node.lineno
    return out


def namespace_names(tree: ast.Module) -> set[str]:
    """Names bound to a parsed namespace: parameters annotated
    ``argparse.Namespace`` (or ``Namespace``), plus whatever ``parse_args``
    is assigned to."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for arg in [*node.args.args, *node.args.kwonlyargs,
                        *node.args.posonlyargs]:
                annotation = ast.unparse(arg.annotation) if arg.annotation else ""
                if annotation.endswith("Namespace"):
                    names.add(arg.arg)
        if (isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "parse_args"):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def read_destinations(tree: ast.Module, names: set[str]) -> set[str]:
    """Every attribute read off a namespace name, by either spelling."""
    read: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in names):
            read.add(node.attr)
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in names
                and len(node.args) >= 2):
            attr = _string(node.args[1])
            if attr is not None:
                read.add(attr)
    return read


def test_the_parser_is_readable_and_declares_options():
    """A control: if the AST walk stops finding anything, every assertion
    below passes vacuously and this file is decoration."""
    tree = _tree()
    declared = declared_destinations(tree)
    assert len(declared) >= 20, f"only found {len(declared)} options; walker broke"
    assert "telemetry" in declared, "the positional is not being derived"
    assert "tool_manifest" in declared, "long options are not being derived"
    assert "args" in namespace_names(tree)


def test_nothing_reads_the_whole_namespace_at_once():
    """``vars(args)`` or ``args.__dict__`` would count as reading every option
    and make the assertion below unfalsifiable."""
    tree = _tree()
    names = namespace_names(tree)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "vars" and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in names):
            pytest.fail(f"{CLI.name}:{node.lineno}: vars() over the namespace "
                        "reads every option at once; read them by name")
    assert "__dict__" not in read_destinations(tree, names)


def test_every_parsed_option_is_read_somewhere_in_the_cli():
    """THE ASSERTION THIS FILE EXISTS FOR.

    An option argparse stores and nothing reads is a documented control that
    enforces nothing. It fails here by destination name and line, so the
    reviewer sees ``--seen-approvals`` rather than a count.
    """
    tree = _tree()
    declared = declared_destinations(tree)
    read = read_destinations(tree, namespace_names(tree))

    inert = sorted(d for d in declared if d not in read and d not in KNOWN_INERT)
    assert not inert, (
        "these options are parsed and never read, so passing them changes "
        "nothing and nothing says so: "
        + ", ".join(f"{d} (cli.py:{declared[d]})" for d in inert)
        + ". Either read the option or, if it genuinely cannot be wired yet, "
        "add it to KNOWN_INERT in tests/test_cli_wiring.py with the reason.")


def test_the_known_inert_list_is_exactly_the_inert_set():
    """The matched pair. An entry for an option that is now read is stale
    and hides the next one; an entry for an option that does not exist is
    the same. Both fail, so the list cannot outlive the defects it names."""
    tree = _tree()
    declared = declared_destinations(tree)
    read = read_destinations(tree, namespace_names(tree))

    for dest, reason in KNOWN_INERT.items():
        assert len(reason) > 40, f"{dest}: the reason is too thin to be useful"
        assert dest in declared, (
            f"KNOWN_INERT names {dest!r}, which the parser no longer declares; "
            "remove the entry")
        assert dest not in read, (
            f"KNOWN_INERT names {dest!r}, which cli.py now reads; the entry is "
            "stale and must be removed so the next inert option is not hidden "
            "behind it")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
