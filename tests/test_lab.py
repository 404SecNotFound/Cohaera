# Copyright 2026 Imran Hafeez
# SPDX-License-Identifier: Apache-2.0
"""The lab builder's safety properties, checked against its source.

COH-R18. `lab/Build-CohaeraLab.ps1` is PowerShell for VMware Workstation and it
cannot run in CI -- there is no Windows, no VMware, and the script's own header
says it is untested by its author. That is exactly why these assertions exist
rather than why they do not: the parts of it that are *controls* can be checked
as text, and a control that quietly stops being one is the failure mode this
repository keeps finding.

Three things the sixth review raised, all of them the same shape -- something
that looks like a check and is not:

  * ``-TimeoutSec`` was a declared parameter the body never read, so the call
    sites that passed one got no timeout and the signature said otherwise;
  * an absent ISO checksum was a warning, so the build proceeded from an
    unverified image with a yellow line the operator scrolled past;
  * the verify stage printed the isolation checks for a human to run by hand,
    which means the lab's central claim was never tested by anything.

Same idea as ``tests/test_ci_config.py``: committed configuration that names a
property should be checked against the thing it names. Text assertions are
weaker than executing the script, and they are much stronger than nothing.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "lab"

sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests"))

import make_fixtures  # noqa: E402

from cohaera.checks import SequenceGrammar, run_all  # noqa: E402
from cohaera.ingest import load  # noqa: E402

SCRIPT = LAB / "Build-CohaeraLab.ps1"
CONFIG = LAB / "lab.config.psd1"


def script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def config() -> str:
    return CONFIG.read_text(encoding="utf-8")


def invoke_tool_body() -> str:
    """The text of Invoke-Tool, from its definition to the next top-level one."""
    src = script()
    start = src.index("function Invoke-Tool")
    rest = src[start:]
    end = rest.index("\n# =====")
    return rest[:end]


# ---------------------------------------------------------------------------
# The timeout that was not one
# ---------------------------------------------------------------------------


def test_the_timeout_parameter_is_actually_read():
    """It was declared and never used. A signature that promises a deadline and
    does not enforce one is worse than no parameter: the tools this drives --
    packer waiting on an SSH handshake, vmrun on a wedged service -- hang
    rather than fail, and a hang is indistinguishable from slow progress."""
    body = invoke_tool_body()
    assert "$TimeoutSec" in body, "Invoke-Tool no longer takes a timeout"
    uses = body.count("$TimeoutSec")
    assert uses > 1, (
        "$TimeoutSec appears only in the parameter list, so it is declared and "
        "never read -- which is the defect COH-R18 reported")
    assert "WaitForExit" in body, (
        "nothing waits with a deadline, so the timeout cannot be enforced")
    assert "Kill" in body, (
        "a timeout that does not kill the process leaves it running and the "
        "next run failing on a locked vmx")


def invoke_tool_calls() -> list[str]:
    """Every Invoke-Tool CALL, whole, including continuation lines.

    A line-based regex gets this wrong in both directions: it truncates the
    multi-line ssh probes, whose -TimeoutSec sits three lines down, and it
    matches the function's own definition. So this balances parentheses from
    each call site and stops at the first newline outside them.
    """
    src = script()
    out: list[str] = []
    for m in re.finditer(r"Invoke-Tool\s", src):
        if src[max(0, m.start() - 9):m.start()].endswith("function "):
            continue
        depth, i = 0, m.start()
        while i < len(src):
            ch = src[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "\n" and depth <= 0:
                # A trailing backtick continues the statement onto the next line.
                if not src[:i].rstrip().endswith("`"):
                    break
            i += 1
        out.append(src[m.start():i])
    return out


def test_the_operations_that_hang_all_carry_a_deadline():
    """packer build is the one that matters -- it is the 25-minute step that
    waits on a VM that may never come up -- but a wedged vmrun or a vnetlib
    holding a lock stalls the run just as completely."""
    calls = invoke_tool_calls()
    assert calls, "no Invoke-Tool call sites found; this test is stale"
    assert len(calls) >= 10, f"only found {len(calls)} call sites; extractor is stale"

    without = [" ".join(c.split()) for c in calls if "-TimeoutSec" not in c]
    assert not without, (
        "these external-tool calls can hang forever:\n  "
        + "\n  ".join(without))


def test_the_packer_build_deadline_is_derived_from_the_configured_budget():
    """A hardcoded build timeout drifts from BuildTimeoutMin the first time
    somebody raises it for a slow disk, and then the deadline fires during a
    legitimate build."""
    src = script()
    assert re.search(r"BuildTimeoutMin\s*\*\s*60", src), (
        "the packer build timeout must come from BuildTimeoutMin, not a "
        "literal")


# ---------------------------------------------------------------------------
# The ISO checksum that was a suggestion
# ---------------------------------------------------------------------------


def test_a_missing_iso_checksum_fails_the_build():
    """The ISO is the root of trust for every VM in the lab. Warning about it
    and continuing produces four machines nobody can vouch for, and makes every
    isolation property below unfalsifiable."""
    src = script()
    m = re.search(r"if \(-not \$cfg\.UbuntuIsoSha256\) \{(.{0,1500}?)\n    \}",
                  src, re.DOTALL)
    assert m, "the UbuntuIsoSha256 check is gone or was restructured"
    block = m.group(1)
    assert "Die" in block, (
        "an absent ISO checksum must fail the build, not warn and continue")
    assert "AllowUnverifiedIso" in block, (
        "failing closed needs a named escape, as COH-R04 has for a partial "
        "baseline; otherwise the next person deletes the check")


def test_the_escape_is_an_explicit_switch_the_operator_types():
    src = script()
    assert re.search(r"\[switch\]\s+\$AllowUnverifiedIso", src), (
        "the escape must be a real parameter, so using it is a decision on "
        "the record rather than an edit to the config")
    assert ".PARAMETER AllowUnverifiedIso" in src, (
        "an escape hatch nobody documents is a trap")


def test_a_checksum_that_is_set_is_verified_here_and_not_only_by_packer():
    """A checksum in the config that does not match the file reads as verified
    and is not. Packer would catch it forty minutes into a build; a hash costs
    seconds at preflight."""
    src = script()
    assert "Get-FileHash" in src, (
        "a configured checksum is never compared against the ISO on disk")
    assert re.search(r"\$\{?got\}? -ne \$\{?want\}?", src) or "MISMATCH" in src, (
        "nothing fails on a checksum mismatch")


# ---------------------------------------------------------------------------
# The isolation that was printed rather than tested
# ---------------------------------------------------------------------------

_PROBE = re.compile(r"@\{\s*From\s*=\s*'([^']+)';\s*Kind\s*=\s*'([^']+)';"
                    r"\s*Target\s*=\s*'([^']+)';\s*Expect\s*=\s*'([^']+)'",
                    re.DOTALL)


def probes() -> list[tuple[str, str, str, str]]:
    return _PROBE.findall(config())


def test_the_reachability_matrix_exists_and_is_not_empty():
    assert "Reachability" in config(), "the isolation matrix is gone"
    assert probes(), "the Reachability table declares no probes"


def test_the_negative_properties_are_the_ones_actually_declared():
    """The lab's reason for existing. `analysis-01 cannot reach agent-01` is
    what makes an egress finding mean anything; without it the scoring host and
    the thing it is scoring share a failure domain."""
    rows = probes()
    blocked = [r for r in rows if r[3] == "blocked"]
    assert blocked, "no negative reachability assertions at all"

    analysis_to_agent = [r for r in rows
                         if r[0] == "analysis-01" and "10.10.10.10" in r[2]]
    assert analysis_to_agent, "nothing asserts analysis-01 cannot reach agent-01"
    assert all(r[3] == "blocked" for r in analysis_to_agent)

    # ICMP alone is not the property: a filter can drop pings and pass TCP.
    kinds = {r[1] for r in analysis_to_agent}
    assert {"ping", "tcp"} <= kinds, (
        "the agent-unreachable claim is tested by only one protocol")


def test_analysis_is_asserted_to_have_no_way_out():
    rows = [r for r in probes() if r[0] == "analysis-01"]
    outward = [r for r in rows if r[1] in ("https", "dns")]
    assert outward, "nothing asserts analysis-01 is offline"
    assert all(r[3] == "blocked" for r in outward)


def test_every_probe_says_what_it_protects():
    """A failing probe an operator does not understand gets deleted."""
    body = config()
    for row in _PROBE.finditer(body):
        tail = body[row.end():row.end() + 400]
        assert "Why" in tail, (
            f"probe {row.group(1)} -> {row.group(3)} has no Why")


def test_the_verify_stage_runs_the_probes_and_can_fail_on_them():
    """The whole finding. These were printed for a human to run."""
    src = script()
    verify = src[src.index("# STAGE: verify"):]
    assert "$cfg.Reachability" in verify, (
        "the verify stage does not read the matrix")
    assert "ssh" in verify, "the probes are not executed on the guests"
    assert re.search(r"\$fail\+\+", verify), (
        "nothing increments the failure count, so verification cannot fail")
    assert "Die" in verify, "a failed probe does not fail the run"


def test_a_probe_that_cannot_run_is_not_treated_as_a_pass():
    """The quiet way this reverts to being decorative: ssh fails, no answer
    comes back, and an absent answer reads as the expected one."""
    src = script()
    verify = src[src.index("# STAGE: verify"):]
    assert "did not run" in verify, (
        "there is no branch for a probe that produced no answer")
    m = re.search(r"if \(-not \$answer\) \{(.{0,300}?)\}", verify, re.DOTALL)
    assert m, "the no-answer branch is gone"
    assert "$fail++" in m.group(1), (
        "a probe that did not run must count as a failure; a probe that did "
        "not run is not a probe that passed")


def test_the_collector_is_asserted_not_to_route_between_segments():
    """Without this the two negative rows are an accident of routing tables
    rather than a property of the topology."""
    assert "NoForwarding" in config()
    src = script()
    verify = src[src.index("# STAGE: verify"):]
    assert "ip_forward" in verify, (
        "nothing checks that the collector does not forward")


def test_the_manual_list_no_longer_claims_the_probes_are_manual():
    """The printed section is still right about the things nothing can check --
    a bridged vmnet passes every probe above -- but it must not still be
    telling the operator to run the checks the script now runs."""
    src = script()
    verify = src[src.index("# STAGE: verify"):]
    assert "ping -c1 -W2 10.10.10.10" not in verify, (
        "the manual instructions still list a probe the verify stage runs")
    assert "Virtual Network Editor" in verify, (
        "the genuinely-manual host-only check was dropped; the probes pass "
        "just as happily on a bridged segment")


# ---------------------------------------------------------------------------
# R-08. A required positive probe that no routing table could satisfy.
# ---------------------------------------------------------------------------

_NIC = re.compile(r"@\{\s*Net\s*=\s*'([^']+)';\s*Ip\s*=\s*'([\d.]+)/\d+'\s*\}")
_VM_NAME = re.compile(r"Name\s*=\s*'([^']+)'")


def interfaces() -> dict[str, set[str]]:
    """Every VM's static addresses, by name, read out of the Vms block."""
    body = config()
    start = body.index("Vms = @(")
    block = body[start:body.index("# Isolation, as assertions", start)]
    out: dict[str, set[str]] = {}
    current = ""
    for line in block.splitlines():
        name = _VM_NAME.search(line)
        if name:
            current = name.group(1)
            out[current] = set()
        for _net, ip in _NIC.findall(line):
            if current:
                out[current].add(ip)
    return out


def _subnet(address: str) -> str:
    return ".".join(address.split(".")[:3])


def test_every_required_positive_probe_is_on_a_segment_the_source_can_reach():
    """R-08, reproduced as a rule rather than as one corrected address.

    The matrix required ``agent-01`` to reach ``10.10.20.10:22`` -- the
    collector's COLLECTION-side address. ``agent-01`` has one static interface,
    on the generation segment, and its default route is NAT. ``NoForwarding``
    asserts the collector is a boundary rather than a router, so nothing carries
    that packet either. The build could only ever fail its own required check.

    The address was not the defect. Believing a host can reach a segment it has
    no interface on was, and one corrected address does not stop the next one.
    So this asserts the property: every ``reach`` row must name a target on a
    subnet the source host actually has an address on, or be an advisory row
    that leaves the lab entirely.
    """
    nics = interfaces()
    unreachable = []
    for source, kind, target, expect in probes():
        if expect != "reach" or kind in ("https", "dns"):
            continue
        host = target.split(":")[0]
        if not host[0].isdigit():
            continue
        if _subnet(host) not in {_subnet(ip) for ip in nics.get(source, set())}:
            unreachable.append(
                f"{source} -> {target}: {source} has "
                f"{sorted(nics.get(source, set())) or 'no static address'}, "
                f"none of them on {_subnet(host)}.0/24")
    assert not unreachable, (
        "these rows require a route that the declared interfaces cannot "
        "provide, and no forwarding is permitted:\n  " + "\n  ".join(unreachable))


def test_the_agent_is_asserted_off_the_collection_segment():
    """The property the impossible row was standing in front of.

    An agent that can reach the collection segment can reach the archive it is
    being judged from. That is the boundary the whole lab exists to create, and
    until R-08 nothing asserted it -- the row in that position was a positive
    one, pointed at the same segment, and could not pass.
    """
    rows = [r for r in probes() if r[0] == "agent-01"]
    collection = [r for r in rows if r[2].startswith("10.10.20.")]
    assert collection, "nothing constrains agent-01's access to collection"
    assert all(r[3] == "blocked" for r in collection), (
        "agent-01 must not be asserted to reach the collection segment")
    assert {r[2].split(":")[0] for r in collection} >= {"10.10.20.10",
                                                        "10.10.20.30"}, (
        "assert it against both hosts on that segment: the collector's foot "
        "there and the scoring host")


def test_the_agent_can_still_ship_telemetry_to_the_collector():
    """And the positive half, which the lab is useless without."""
    rows = [r for r in probes()
            if r[0] == "agent-01" and r[2].startswith("10.10.10.20")]
    assert rows, "nothing asserts the agent can reach the collector at all"
    assert all(r[3] == "reach" for r in rows)


def test_the_documentation_addresses_agree_with_the_built_lab():
    """R-08's other half. ``LAB.md`` described a third topology -- collector on
    10.10.20.10 alone, analysis on 10.10.30.10, SIEM on 10.10.40.10 -- and its
    commands followed it. An operator configuring endpoints the built lab does
    not have reads a silent scenario as a detector that declined to fire.
    """
    doc = (REPO / "LAB.md").read_text(encoding="utf-8")
    section = doc[doc.index("| VM | Role |"):doc.index("Base image:")]
    # Only the table's own rows. The prose beneath it quotes the addresses the
    # stale version named, and a check that cannot tell a correction from the
    # thing it corrects would forbid explaining the fix.
    table = "\n".join(line for line in section.splitlines()
                      if line.startswith("|"))
    declared = set(re.findall(r"10\.10\.\d+\.\d+", table))
    built = {ip for ips in interfaces().values() for ip in ips}
    assert declared <= built, (
        f"LAB.md's hardware table names addresses the lab does not build: "
        f"{sorted(declared - built)}")
    assert built <= declared, (
        f"LAB.md's hardware table omits addresses the lab does build: "
        f"{sorted(built - declared)}")


# ---------------------------------------------------------------------------
# The local lab, and the committed evidence it produces.
# ---------------------------------------------------------------------------

LOCAL_RUN = LAB / "local" / "runs" / "latest" / "RUN-MANIFEST.json"


def local_manifest() -> dict:
    return json.loads(LOCAL_RUN.read_text(encoding="utf-8"))


def test_the_local_lab_has_a_committed_run():
    """The point of the local lab is that its output is in the repository. A
    lab whose results live only on the author's machine is a claim."""
    assert LOCAL_RUN.is_file(), "no committed run manifest"
    assert (LAB / "local/runs/latest/RESULTS.md").is_file()
    assert (LAB / "local/runs/latest/verdicts.jsonl").is_file()


def test_the_committed_run_demonstrates_each_state_distinctly():
    """Six states of one workflow. If two of them produce the same output the
    demonstration is not demonstrating anything, and that is a failure worth
    catching before somebody is shown it."""
    doc = local_manifest()
    outcomes = {}
    for state in doc["states"]:
        for verdict in state["verdicts"]:
            outcomes[state["state"]] = (
                tuple(verdict["triggered_rules"]),
                verdict["evidence_status"],
            )
    assert len(outcomes) == 6, f"expected six states, found {sorted(outcomes)}"
    assert len(set(outcomes.values())) == len(outcomes), (
        f"two states produce identical output: {outcomes}")


def test_the_bound_receipt_contradicts_and_the_unbound_one_does_not():
    """R-01, as a product behaviour rather than as a unit test.

    The two states carry the same claim -- the agent says the refund failed --
    and the same provider identifier. One binds to the exact span, tool and
    argument digest; the other names no arguments. Before R-01 both produced
    the same critical contradiction.
    """
    doc = local_manifest()
    by_state = {s["state"]: s["verdicts"][0] for s in doc["states"]
                if s["verdicts"]}
    bound = by_state["04-contradiction"]
    unbound = by_state["04b-unbound-receipt"]
    assert "CH07_reported_failure_with_effect_receipt" in bound["triggered_rules"]
    assert "CH07_reported_failure_with_effect_receipt" not in unbound["triggered_rules"], (
        "an incomplete binding must never carry a contradiction")
    assert "CH07_effect_receipt_partially_bound" in unbound["triggered_rules"], (
        "and it must not vanish either: absent is a different fact, not a "
        "weaker one, and an analyst should still see the receipt")


def test_the_unsigned_tail_is_a_prefix_and_not_a_verified_session():
    """R-05, likewise. The state signed at every fourth record, read while the
    tail was still being written, must not claim its last records were
    attested."""
    doc = local_manifest()
    partial = next(s for s in doc["states"]
                   if s["state"].startswith("05"))
    assert partial["verdicts"][0]["evidence_status"] == "verified_prefix"

    normal = next(s for s in doc["states"] if s["state"].startswith("01"))
    assert normal["verdicts"][0]["evidence_status"] == "verified_complete", (
        "and a fully signed stream must still reach complete, or the fix has "
        "made every session look partial")


def test_the_ledger_tells_a_replay_from_a_fork():
    """The two cases that need memory between runs, and that every other check
    passes because the records really are genuine."""
    doc = local_manifest()
    codes = {entry["pass"]: entry["integrity_codes"] for entry in doc["ledger"]}
    assert codes["first"] == [], "the first pass of a fresh stream is clean"
    assert "INTEGRITY_STREAM_REPLAYED" in codes["replay"]
    assert "INTEGRITY_STREAM_FORKED" in codes["fork"]
    assert "INTEGRITY_STREAM_REPLAYED" not in codes["fork"], (
        "a rewritten history is not a re-feed, and collapsing the two would "
        "make the more serious one invisible")


def test_the_local_lab_does_not_claim_to_be_the_isolated_one():
    """Two labs, one of which has never been built. Saying so is the difference
    between a reproducible demonstration and an overstated one."""
    readme = (LAB / "local" / "README.md").read_text(encoding="utf-8")
    lowered = readme.lower()
    assert "network" in lowered and "not" in lowered
    assert "eval/EVALUATION-CARD.md" in readme, (
        "it must point at the efficacy numbers rather than let six sessions "
        "stand in for them")


def _walk(node: object) -> Iterator[tuple[str | None, object]]:
    """Every (key, value) in the document, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield None, value
            # Recursing here is the whole point: `states`, `ledger` and
            # `contract` are all lists of dicts, so a walk that stopped at the
            # list saw none of the document that was added after it was
            # written. Caught by mutation -- a hostname three levels down
            # passed a guard whose name says it forbids exactly that.
            yield from _walk(value)


# Names that describe the machine a run happened on rather than the run. Any of
# them appearing as a key means the document has stopped being a statement about
# the detector and started being a statement about a host.
_ENVIRONMENT_KEYS = frozenset({
    "python", "python_version", "interpreter", "implementation", "platform",
    "machine", "processor", "os", "hostname", "fqdn", "cwd", "pwd", "workdir",
    "username", "uid", "environ", "env", "wall_clock", "generated_at",
    "created_at", "started_at", "finished_at", "elapsed", "elapsed_s",
    "duration", "duration_s", "runtime_s", "seed", "random_seed", "pid",
})


def test_the_run_manifest_carries_no_environment_facts():
    """The manifest asserts that these inputs produce these verdicts. That has
    to hold on every interpreter the project supports, so CI running a
    different one from whoever regenerated the file is the POINT of the check.

    Caught the hard way: the manifest stamped the interpreter version, and the
    first CI run failed on 3.12 against a file written on 3.11 -- a real
    property turned into a host fact, and a green local check that meant
    nothing.

    Extended when the coverage-contract section was added. The original scanned
    the TOP-LEVEL keys for "python" and the raw text for four version strings.
    That catches the fault it was written for and would not have caught the
    same fault three levels down inside `contract`, nor a hostname, nor an
    absolute path, nor a wall-clock reading -- none of which contain the string
    "3.11". A guard that only knows the last defect is not a guard.
    """
    raw = LOCAL_RUN.read_text(encoding="utf-8")
    doc = local_manifest()

    for key, _value in _walk(doc):
        assert key is None or key.lower() not in _ENVIRONMENT_KEYS, (
            f"the compared document carries {key!r}, which describes the "
            f"machine rather than the run; a manifest that depends on the "
            f"environment cannot assert a property of the detector")

    for host_fact in ("3.10", "3.11", "3.12", "3.13", "elapsed", "duration"):
        assert f'"{host_fact}"' not in raw, (
            f"{host_fact!r} appears as a value in the compared manifest")

    # No path from this machine, and no absolute path from anyone else's.
    assert str(REPO) not in raw, "the manifest names this checkout's location"
    assert '"/' not in raw, (
        "a string value in the manifest is an absolute path, so the document "
        "depends on where the checkout lives")

    # No wall clock. Every instant in this document derives from the fixed
    # constant in scenarios.py, so anything at epoch scale must sit inside the
    # lab's own window. A `time.time()` reading is roughly a fortnight past it
    # and moves every second.
    base = _lab_base()
    for _key, value in _walk(doc):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            assert value < 1_000_000 or base <= value <= base + 100_000, (
                f"{value} is at epoch scale and outside the lab's pinned "
                f"window, which is what a wall-clock reading looks like")


def _lab_base() -> float:
    """``scenarios.BASE``, read from the file rather than copied.

    A duplicated constant in the test would go on passing after the lab moved
    its clock, which is the failure mode this whole module is about.
    """
    src = (LAB / "local" / "scenarios.py").read_text(encoding="utf-8")
    match = re.search(r"^BASE = ([\d_]+\.\d+)$", src, re.MULTILINE)
    assert match, "scenarios.BASE is gone or was reformatted"
    return float(match.group(1).replace("_", ""))


def test_the_lab_run_ignores_a_correlation_secret_in_the_environment():
    """$COHAERA_CORRELATION_SECRET is folded into trust_config_digest and so
    into every verdict_id in the manifest. Inheriting it made the committed
    document a function of whoever ran the lab: --check passed on a clean shell
    and failed on an operator's, with a diff full of changed verdict IDs and
    nothing to explain them. Same defect as stamping the interpreter version,
    arriving through an input instead of through a field.

    Asserted by RUNNING the lab with the variable set, not by reading run.py
    for the line that clears it. The source assertion was tried first and it
    passed with that line commented out, because a regex over the file cannot
    tell code from a comment -- which is the "test that passes for the wrong
    reason" this repository treats as worse than no test.
    """
    env = dict(os.environ)
    env["COHAERA_CORRELATION_SECRET"] = "an-operators-own-secret"
    proc = subprocess.run(
        [sys.executable, str(LAB / "local" / "run.py"), "--check"],
        cwd=str(REPO), env=env, capture_output=True, text=True, timeout=300,
        check=False)
    assert proc.returncode == 0, (
        "the committed lab run depends on the operator's environment:\n"
        + proc.stdout + proc.stderr)


def test_the_correlation_secret_the_lab_uses_is_a_committed_constant():
    """And it must not reach the compared document. Hashing a secret into a
    published field is how a secret stops being one -- this one is worthless by
    construction, and the habit is not."""
    src = (LAB / "local" / "run.py").read_text(encoding="utf-8")
    match = re.search(r'^LAB_CORRELATION_SECRET = "([^"]+)"$', src, re.MULTILINE)
    assert match, (
        "the keyed pass must use a committed lab constant, not the operator's "
        "own secret")
    assert match.group(1) not in LOCAL_RUN.read_text(encoding="utf-8"), (
        "the correlation secret reached the compared document")


# ---------------------------------------------------------------------------
# The coverage contract, as the thing a first-time reader actually meets.
#
# The six states above all run in the configuration the author chose: manifest
# supplied, collector key supplied, producer emitting a session_id. The
# SHIPPING DEFAULT is none of those, and in that configuration large parts of
# the detector decline to answer. `run.py` scores three more sessions twice
# each, with the prerequisite and without, and these assert that the pairs stay
# a demonstration rather than becoming two rows that say the same thing.
# ---------------------------------------------------------------------------

LOCAL_INPUTS = LAB / "local" / "runs" / "latest" / "inputs"
LOCAL_RESULTS = LAB / "local" / "runs" / "latest" / "RESULTS.md"
LOCAL_README = LAB / "local" / "README.md"


def contracts() -> dict[str, dict]:
    return {c["contract"]: c for c in local_manifest()["contract"]}


def pair(key: str) -> tuple[dict, dict]:
    """The (without, with) passes for one prerequisite."""
    without, supplied = contracts()[key]["passes"]
    return without, supplied


def checks_of(entry: dict) -> dict[str, dict]:
    return entry["verdicts"][0]["checks"]


def test_every_prerequisite_is_scored_both_ways():
    """A blind spot shown on its own reads as a quiet result. The pair is the
    demonstration: same telemetry, one thing different, two different answers."""
    found = contracts()
    assert set(found) == {"06-no-manifest", "07-chained-unsigned",
                          "08-anonymous"}, sorted(found)
    for key, entry in found.items():
        assert len(entry["passes"]) == 2, key
        assert entry["question"].endswith("?"), (
            f"{key} states a description where it should state the question "
            f"the pair answers")
        for p in entry["passes"]:
            assert p["exit_code"] == 0, (key, p["pass"])
            assert p["verdicts"], f"{key}/{p['pass']} produced no verdict"


def test_without_a_capability_manifest_the_behavioural_checks_decline():
    """The documented default state, and the one a new operator is actually in.

    ``issue_refund`` matches no keyword set in model.py and the stream carries
    no ``reversible`` hint, so with nothing declaring it Cohaera does not know
    the session contained a consequential action. What matters is that it says
    so: the checks report `degraded` at confidence 0.0, which is a stated
    absence, and NOT `evaluated` with an empty finding list, which would be a
    clean bill of health for a question nobody asked.
    """
    absent, supplied = pair("06-no-manifest")

    blinded = ["CH02_concealment_gap", "CH03_untrusted_to_consequential",
               "CH04_guardrail_overrun", "CH07_effect_contradiction"]
    for check in blinded:
        assert checks_of(absent)[check]["confidence"] == 0.0, (
            f"{check} claims confidence on a session containing a call it "
            f"could not classify")
        assert checks_of(supplied)[check]["status"] == "evaluated", (
            f"{check} does not recover when the manifest declares the tool, so "
            f"the pair no longer attributes anything to the manifest")

    assert absent["verdicts"][0]["triggered_rules"] == [], (
        "the unequipped pass fires something, so the demonstration is not "
        "about the manifest any more")
    assert "CH03_untrusted_to_completed_action" in \
        supplied["verdicts"][0]["triggered_rules"], (
        "the equipped pass must fire, or the pair shows two silences")
    assert (absent["verdicts"][0]["coverage_completeness"]
            < supplied["verdicts"][0]["coverage_completeness"])


def test_the_manifest_pair_differs_only_by_the_manifest():
    """Both passes read the same file. If they did not, the difference between
    them would be attributable to the telemetry as easily as to the flag."""
    assert contracts()["06-no-manifest"]["inputs"] == ["06-no-manifest.jsonl"]
    assert contracts()["08-anonymous"]["inputs"] == ["08-anonymous.jsonl"]


def test_a_chain_with_no_key_is_not_a_verified_session():
    """The realistic first-adoption state, which eval/EVALUATION-CARD.md says
    most of the evaluation corpus is in. A hash chain establishes that a stream
    is internally consistent, and so is a stream an attacker rewrote end to
    end, because with no key there is nothing to check the chain against."""
    chained, signed = pair("07-chained-unsigned")
    assert chained["verdicts"][0]["evidence_status"] == "chained_unsigned"
    assert signed["verdicts"][0]["evidence_status"] == "verified_complete"

    weak = checks_of(chained)["CH06_evidence_integrity"]
    strong = checks_of(signed)["CH06_evidence_integrity"]
    assert weak["status"] == "degraded"
    assert weak["confidence"] < strong["confidence"], (
        "an unsigned chain must cost CH06 confidence, or the signature is "
        "buying nothing the contract can see")


def test_the_signed_and_unsigned_streams_carry_identical_records():
    """The pair's attribution. Only the integrity sidecar may differ; the
    bodies the verdict is about have to be the same bytes, or the difference
    between the two passes is not the signature."""
    def bodies(name: str) -> list[dict]:
        lines = (LOCAL_INPUTS / name).read_text(encoding="utf-8").splitlines()
        return [{k: v for k, v in json.loads(x).items() if k != "integrity"}
                for x in lines if x.strip()]

    assert bodies("07-chained-unsigned.jsonl") == \
        bodies("07-chained-unsigned-signed.jsonl")


def test_a_correlation_secret_does_not_buy_back_correlation_confidence():
    """The honest half of the third pair, and the reason it is a pair.

    A stream with no producer session_id correlates at 0.3 whatever else is
    configured, because the session boundary was inferred. Setting
    $COHAERA_CORRELATION_SECRET changes the key from an unkeyed digest to an
    HMAC -- which is what stops a small identity space being enumerated out of
    the SIEM copy -- and changes NOTHING about how much the grouping deserves
    to be believed. Presenting the secret as a fix for the 0.3 would be exactly
    the kind of overstatement this repository keeps removing.
    """
    unkeyed, keyed = pair("08-anonymous")
    for entry in (unkeyed, keyed):
        correlation = entry["verdicts"][0]["correlation"]
        assert correlation["kind"] == "scoped_anonymous"
        assert correlation["confidence"] == 0.3, (
            "an inferred session boundary must not report full confidence")

    assert unkeyed["correlation_key_version"] == "sha256-unkeyed-v1"
    assert keyed["correlation_key_version"] == "hmac-sha256-v1"
    assert unkeyed["correlation_keyed"] is False
    assert keyed["correlation_keyed"] is True
    assert (unkeyed["verdicts"][0]["checks"]
            == keyed["verdicts"][0]["checks"]), (
        "the secret moved a check contract, which would mean the lab is "
        "teaching that a secret improves what the detector can establish")


def test_an_inferred_session_costs_the_checks_that_reason_across_events():
    """And the other half: what the missing session_id actually does cost.

    Compared against the same workflow WITH a session_id -- the `signed` pass
    of the 07 pair is the same records, fully attested -- so the comparison is
    the correlation key and not the scenario.
    """
    anonymous, _ = pair("08-anonymous")
    _, identified = pair("07-chained-unsigned")
    assert (anonymous["verdicts"][0]["coverage_completeness"]
            < identified["verdicts"][0]["coverage_completeness"])
    for check in ("CH02_concealment_gap", "CH04_guardrail_overrun",
                  "CH05_unpaired_calls", "CH07_effect_contradiction"):
        assert checks_of(anonymous)[check]["confidence"] <= 0.3, check


# ---------------------------------------------------------------------------
# The quickstart. A reader has to be able to tell whether their run matched.
# ---------------------------------------------------------------------------


def test_the_quickstart_quotes_the_output_the_run_actually_produces():
    """lab/local/README.md reproduces the generated tables inline so somebody
    can compare their run against the page rather than against a memory of it.

    Duplicated prose drifts, so it is checked rather than trusted: every table
    row RESULTS.md generates must appear verbatim in the README. This is the
    same treatment tools/readme_facts.py gives the counted claims.
    """
    generated = [line for line in
                 LOCAL_RESULTS.read_text(encoding="utf-8").splitlines()
                 if line.startswith("|")]
    readme = LOCAL_README.read_text(encoding="utf-8")
    missing = [line for line in generated if line not in readme]
    assert not missing, (
        "the quickstart quotes output the run no longer produces:\n  "
        + "\n  ".join(missing[:8]))


def test_the_quickstart_names_the_one_entry_point():
    readme = LOCAL_README.read_text(encoding="utf-8")
    assert "python lab/local/run.py --check" in readme
    assert "python lab/local/run.py\n" in readme


def test_the_local_lab_says_it_is_not_an_evaluation():
    """Its output is six hand-written stories and it must not be mistaken for a
    measurement. The evaluation card is the thing that measures the detector,
    and the page has to send the reader there in as many words."""
    readme = LOCAL_README.read_text(encoding="utf-8").lower()
    assert "smoke test" in readme
    assert "not an evaluation" in readme
    assert "eval/evaluation-card.md" in readme


# ---------------------------------------------------------------------------
# The unexecuted plan, marked as one.
# ---------------------------------------------------------------------------

LAB_MD = REPO / "LAB.md"
_PHASE = re.compile(r"^## Phase \d+ · .+$", re.MULTILINE)


def test_lab_md_opens_by_saying_it_has_not_been_executed():
    """Three reviews made the same point: an unexecuted five-phase build plan
    shipped beside working code makes a reader discount the working code. The
    objection was to the PRESENTATION, so the fix is presentation -- the status
    goes at the top, in the first screen, not in a caveat at the bottom."""
    doc = LAB_MD.read_text(encoding="utf-8")
    opening = doc[:doc.index("## Status of every phase")]
    lowered = opening.lower()
    assert "none of the vmware phases on this page have been executed" in lowered, (
        "the top of the page does not say plainly that the VMware phases were "
        "never run")
    assert "no vm has been created" in lowered
    assert "lab/local" in opening, (
        "and it does not point at the half that does run")
    # Before the first phase heading, not after it. The objection three reviews
    # made was to the presentation: a status a reader meets on screen two has
    # already let them read the plan as a record.
    assert doc.index("have been executed") < doc.index("## Phase 0")


def test_every_phase_declares_a_status():
    """Per phase, because a page-level disclaimer gets scrolled past and a
    reader who lands on Phase 3 from a link never sees it."""
    doc = LAB_MD.read_text(encoding="utf-8")
    headings = _PHASE.findall(doc)
    assert len(headings) == 6, headings
    for heading in headings:
        after = doc[doc.index(heading) + len(heading):][:600]
        assert "> **Status:" in after, (
            f"{heading!r} states no status; a reader arriving at this heading "
            f"cannot tell whether it happened")


def test_the_phase_status_table_covers_every_phase():
    doc = LAB_MD.read_text(encoding="utf-8")
    table = doc[doc.index("## Status of every phase"):
                doc.index("## Status of every artefact")]
    for phase in range(6):
        assert f"**{phase} ·" in table, f"phase {phase} missing from the table"
    assert "Not built" in table, (
        "a status table in which nothing is unbuilt is not describing this lab")


def test_the_powershell_builder_says_at_the_top_that_it_never_ran():
    """It is a real design and it is kept. What it must not do is present
    itself with the same authority as the half that has been executed."""
    doc = (LAB / "README.md").read_text(encoding="utf-8")
    opening = doc[:doc.index("## Read this before you run it")]
    assert "NEVER EXECUTED" in opening
    assert "local/README.md" in opening


def test_lab_md_does_not_present_the_evaluation_card_as_this_lab_output():
    """The measurement that exists is synthetic and is a different measurement
    from the one phase 4 designs. Letting the two blur would give the plan
    credit for a result it did not produce."""
    doc = LAB_MD.read_text(encoding="utf-8")
    phase4 = doc[doc.index("## Phase 4 · Measure"):doc.index("## Phase 5 ·")]
    assert "synthetic" in phase4.lower()
    assert "eval/EVALUATION-CARD.md" in phase4


# ---------------------------------------------------------------------------
# The one command on that page that anybody can run, and the number it prints.
# ---------------------------------------------------------------------------


def test_the_fixture_counts_lab_md_quotes_are_the_counts_it_produces(tmp_path):
    """LAB.md step 2.2 is the only step of the VMware plan that runs anywhere,
    and it told the reader to expect NINE findings against a tree that produces
    seven. That is the C4-11 defect -- a number in the documentation that
    nothing keeps true -- in the one place a new reader is most likely to check
    the tool against the page and conclude the tool is broken.
    """
    def written(name: str, records: list[dict]) -> Path:
        path = tmp_path / name
        path.write_text("".join(json.dumps(r) + "\n" for r in records),
                        encoding="utf-8")
        return path

    benign = load(written("benign.jsonl",
                          [e for i in range(12)
                           for e in make_fixtures.benign_session(i)]),
                  quiet=True)
    suspect = load(written("suspect.jsonl",
                           make_fixtures.s_concealment()
                           + make_fixtures.s_untrusted_flow()
                           + make_fixtures.s_guardrail_overrun()
                           + make_fixtures.s_novel_sequence()),
                   quiet=True)
    grammar = SequenceGrammar().fit(benign)

    findings = sum(len(run_all(s, grammar)[0]) for s in suspect)
    clean = sum(len(run_all(s, grammar)[0]) for s in benign)

    doc = LAB_MD.read_text(encoding="utf-8")
    claim = re.search(r"(\w+) findings across (\w+) suspect sessions, zero on "
                      r"the (\w+) benign ones", doc)
    assert claim, "the step 2.2 expectation is gone or was reworded"
    words = {"zero": 0, "four": 4, "seven": 7, "twelve": 12, "nine": 9}
    assert words[claim.group(1).lower()] == findings, (
        f"LAB.md promises {claim.group(1)} findings; the fixtures produce "
        f"{findings}")
    assert words[claim.group(2).lower()] == len(suspect)
    assert words[claim.group(3).lower()] == len(benign)
    assert clean == 0, (
        f"the benign fixtures now produce {clean} finding(s), so the page's "
        f"'zero' is wrong and the detector has a false positive")
