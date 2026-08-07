# Automated lab build, VMware Workstation Pro 17

Four unattended Ubuntu Server 24.04 VMs, three segmented host-only networks,
static addressing, SSH keys and audit rules. You supply the ISO.

```powershell
cd lab
notepad lab.config.psd1          # ISO path, password hash, SSH key
.\Build-CohaeraLab.ps1 -DryRun   # generate and READ everything first
.\Build-CohaeraLab.ps1           # build, 40 to 90 minutes
```

---

## Read this before you run it

**I have not run this script.** It was written against VMware Workstation Pro 17
and Ubuntu 24.04 documentation, not against a working deployment, and there is
no PowerShell interpreter in the environment it was authored in. What I *did*
verify:

- The generated cloud-init parses as valid YAML for all three VM roles.
- The base64 file payloads round-trip, with nftables quoting intact.
- Braces, parentheses and here-strings balance in the script.
- No duplicate static IPs, and every address sits on a declared subnet.
- No use of vmnet1 or vmnet8, which VMware reserves.

What I could **not** verify: that the script parses in PowerShell, that
`vnetlib64.exe` accepts those arguments on your build, that the Packer
`boot_command` timing suits your disk speed, or that any VM boots.

**Run `-DryRun` first, read `generated/cloud-init/agent-01/user-data`, then build
one VM with `-Only agent-01` before you build four.**

---

## Why Packer

Two problems make a hand-rolled `vmrun` script painful, and Packer solves both.

**Ubuntu 24.04 will not autoinstall from a seed alone.** Subiquity finds a
`cidata` volume, then stops and asks for confirmation unless `autoinstall` is on
the kernel command line. The alternatives are remastering the ISO (needs
`oscdimg` or `xorriso` on Windows) or typing at the GRUB prompt. Packer's
`boot_command` types it:

```
"<wait5s>c<wait2s>",
"linux /casper/vmlinuz --- autoinstall ds='nocloud'<enter><wait2s>",
"initrd /casper/initrd<enter><wait2s>",
"boot<enter>"
```

**The seed ISO has to be built.** Packer's `cd_files` plus `cd_label = "cidata"`
does it, so you need no ISO tooling on the host at all.

```powershell
winget install HashiCorp.Packer
```

---

## Topology

```
                    ┌─────────── NAT (vmnet8) ──────────► hosted LLM API
                    │
   ┌────────────────┴─────┐
   │ agent-01             │  4 vCPU  8 GB  40 GB
   │ 10.10.10.10          │  AgentDojo + observra. nftables + auditd.
   └──────────┬───────────┘
              │ vmnet2  10.10.10.0/24   GENERATION
   ┌──────────┴───────────┐
   │ collector-01         │  2 vCPU  4 GB  100 GB
   │ 10.10.10.20          │  Telemetry sink. Sits on both segments.
   │ 10.10.20.10          │  IP forwarding OFF: it is a boundary, not a router.
   └──────────┬───────────┘
              │ vmnet3  10.10.20.0/24   COLLECTION
   ┌──────────┴───────────┐
   │ analysis-01          │  4 vCPU  16 GB  100 GB
   │ 10.10.20.30          │  Cohaera + scoring. No internet. No route to agent-01.
   └──────────────────────┘

   siem-01  vmnet4  10.10.30.10   Phase 5 only, Enabled = $false by default.
```

**The segmentation is the instrument, not hardening around it.** CH02 and CH03
classify calls as `egress`. If `agent-01` can reach the whole internet, "egress"
has no boundary to cross and stops meaning anything. Likewise `analysis-01`
having no route back to `agent-01` is what stops a run contaminating the
labelled corpus.

---

## Usage

| Command | What it does |
|---|---|
| `.\Build-CohaeraLab.ps1 -DryRun` | Generates Packer and cloud-init, creates nothing. Start here. |
| `.\Build-CohaeraLab.ps1` | Full build, all stages, all enabled VMs. |
| `-Only agent-01` | One VM. Use this for your first real build. |
| `-Stage generate,build` | Skip network creation, useful when vmnets already exist. |
| `-Destroy` | Stop and delete the VMs. Leaves the vmnets alone. |
| `-Verbose` | Echoes every external command before it runs. |

Stages run in order and each is idempotent:
`preflight` → `networks` → `generate` → `build` → `configure` → `verify`

**`networks` needs an elevated PowerShell.** Nothing else does. If you would
rather not run elevated, create vmnet2, vmnet3 and vmnet4 by hand in the Virtual
Network Editor as **host-only with DHCP disabled**, then skip that stage.

---

## What preflight refuses to build on

Deliberately fatal, because each one wastes an hour before it surfaces:

- ISO missing, or the filename does not contain `live-server` (desktop and
  legacy images cannot autoinstall this way)
- `LabPasswordHash` still the placeholder
- `SshPublicKey` still the placeholder, or not an OpenSSH key
- Packer not on PATH
- `vmrun.exe` not where the config says
- `networks` requested without elevation

Warnings, not fatal: no ISO checksum, tight disk, VMs requesting more than 75%
of host RAM.

---

## Known rough edges

**`vnetlib64.exe` reports success when it does nothing.** It is undocumented and
version-sensitive. The script tolerates failures and tells you to check. **Open
the Virtual Network Editor and confirm host-only, correct subnet, DHCP
unticked.** Do not skip this; the lab's security property depends on it.

**`boot_command` timing is disk-dependent.** If the installer starts normally
instead of autoinstalling, GRUB was not ready when Packer typed. Raise the
`<wait5s>` in the generated `.pkr.hcl`, or set `HeadlessBuild = $false` and watch
it happen.

**Interface names assume `ens33`, `ens34`.** Standard for vmxnet3 on Workstation,
but check with `ip link` if networking does not come up.

**The nftables output chain ships as ACCEPT.** A deny-all at build time breaks
apt on first boot. Tightening it is phase 2 in [LAB.md](../LAB.md), and until you
do it the `egress` classification has no boundary behind it.

**Your password hash and SSH key end up in `generated/cloud-init/*/user-data`.**
That directory is gitignored. Check before you commit anyway.

---

## After the build

```powershell
.\Build-CohaeraLab.ps1 -Stage verify
```

Then the four things the script cannot check for you:

1. **Virtual Network Editor**: vmnet2/3/4 host-only, DHCP unticked.
2. **From agent-01**: LLM API reachable, collector reachable, everything else not.
3. **From analysis-01**: `ping 10.10.10.10` must fail.
4. **Set a hard spend cap at your API provider** before the first corpus run.
   Runaway agent loops are a real failure mode, and unbounded consumption is
   LLM10 in the OWASP Top 10.

Snapshots are taken automatically as `clean-baseline`. **Restore to it between
run sets.** Run-to-run comparability depends on it and a research audience will
ask whether you did.

Full phase-by-phase build, experiment protocol and cost calibration:
[LAB.md](../LAB.md).
