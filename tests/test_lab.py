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

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "lab"
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
