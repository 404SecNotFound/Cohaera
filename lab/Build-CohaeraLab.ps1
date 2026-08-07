#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the Cohaera lab on VMware Workstation Pro 17. You supply the ISO.

.DESCRIPTION
    Four unattended Ubuntu Server 24.04 VMs, three host-only segments with DHCP
    off, static addressing, SSH keys, packages, and nftables egress control on
    the agent host.

    Packer does the heavy lifting for two reasons that matter:
      1. It types the autoinstall kernel arguments at the GRUB prompt, which is
         the only reliable way to get a fully unattended subiquity install
         without remastering the ISO.
      2. Its cd_files option builds the cloud-init CIDATA seed ISO for you, so
         you do not need oscdimg, xorriso or the Windows ADK.

    Stages, each skippable and each idempotent:
        preflight -> networks -> generate -> build -> configure -> verify

.PARAMETER Stage
    Run only the named stages. Default is all of them.

.PARAMETER Only
    Build only these VMs by name. Default is every enabled VM in the config.

.PARAMETER DryRun
    Do everything except create networks, run Packer, or touch a VM. Writes the
    generated Packer and cloud-init files so you can read them first.
    RUN THIS FIRST.

.PARAMETER Destroy
    Stop and delete the lab VMs. Does not remove the vmnets.

.EXAMPLE
    .\Build-CohaeraLab.ps1 -DryRun
    Generate and inspect everything without building.

.EXAMPLE
    .\Build-CohaeraLab.ps1
    Full build. Expect 40 to 90 minutes depending on disk and network.

.EXAMPLE
    .\Build-CohaeraLab.ps1 -Only agent-01 -Stage build,configure,verify

.NOTES
    UNTESTED BY ITS AUTHOR. This was written against VMware Workstation Pro 17
    and Ubuntu 24.04 documentation, not against a running deployment. Run
    -DryRun, read the generated files, then build one VM before all four.

    Network creation needs an ELEVATED PowerShell. Everything else does not.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]   $Config = "$PSScriptRoot\lab.config.psd1",
    [ValidateSet('preflight','networks','generate','build','configure','verify')]
    [string[]] $Stage  = @('preflight','networks','generate','build','configure','verify'),
    [string[]] $Only,
    [switch]   $DryRun,
    [switch]   $Destroy
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# =====================================================================
# Output helpers
# =====================================================================
$script:Warnings = @()
function Say  ($m) { Write-Host "  $m" }
function Head ($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Ok   ($m) { Write-Host "  [ ok ] $m" -ForegroundColor Green }
function Warn ($m) { $script:Warnings += $m; Write-Host "  [warn] $m" -ForegroundColor Yellow }
function Die  ($m) { Write-Host "  [FAIL] $m" -ForegroundColor Red; throw $m }
function Step ($m) { Write-Host "  [ .. ] $m" -ForegroundColor DarkGray }

function Invoke-Tool {
    param([string]$Exe, [string[]]$Args, [switch]$IgnoreExit, [int]$TimeoutSec = 0)
    if ($DryRun) { Say "DRYRUN would run: $Exe $($Args -join ' ')"; return @{ ExitCode = 0; Output = '' } }
    Write-Verbose "$Exe $($Args -join ' ')"
    $out = & $Exe @Args 2>&1
    $code = $LASTEXITCODE
    if (-not $IgnoreExit -and $code -ne 0) {
        Say ($out | Out-String)
        Die "$Exe exited $code"
    }
    @{ ExitCode = $code; Output = ($out | Out-String) }
}

# =====================================================================
# Config
# =====================================================================
if (-not (Test-Path $Config)) { Die "Config not found: $Config" }
$cfg = Import-PowerShellDataFile -Path $Config

$VmxRoot   = $cfg.VmRoot
$GenRoot   = Join-Path $PSScriptRoot 'generated'
$Vmrun     = Join-Path $cfg.VmwarePath 'vmrun.exe'
$Vnetlib   = Join-Path $cfg.VmwarePath 'vnetlib64.exe'

$targets = $cfg.Vms | Where-Object {
    (-not $_.ContainsKey('Enabled') -or $_.Enabled) -and
    (-not $Only -or $_.Name -in $Only)
}
if (-not $targets) { Die "No VMs selected. Check -Only and the Enabled flags." }

Write-Host @"

  Cohaera lab builder
  VMs      : $($targets.Name -join ', ')
  Stages   : $($Stage -join ' -> ')
  Root     : $VmxRoot
  Mode     : $(if ($DryRun) { 'DRY RUN, nothing will be created' } else { 'BUILD' })
"@ -ForegroundColor White

# =====================================================================
# Destroy
# =====================================================================
if ($Destroy) {
    Head 'Destroy'
    foreach ($vm in $targets) {
        $vmx = Join-Path $VmxRoot "$($vm.Name)\$($vm.Name).vmx"
        if (-not (Test-Path $vmx)) { Say "$($vm.Name): not present"; continue }
        if ($PSCmdlet.ShouldProcess($vm.Name, 'stop and delete')) {
            Invoke-Tool $Vmrun @('stop', $vmx, 'hard') -IgnoreExit | Out-Null
            Invoke-Tool $Vmrun @('deleteVM', $vmx)     -IgnoreExit | Out-Null
            if (-not $DryRun) {
                Remove-Item (Split-Path $vmx) -Recurse -Force -ErrorAction SilentlyContinue
            }
            Ok "$($vm.Name) removed"
        }
    }
    Say 'vmnets were left in place. Remove them in the Virtual Network Editor if you want them gone.'
    return
}

# =====================================================================
# STAGE: preflight
# =====================================================================
if ('preflight' -in $Stage) {
    Head 'Preflight'

    if (-not (Test-Path $cfg.UbuntuIso)) { Die "Ubuntu ISO not found: $($cfg.UbuntuIso)" }
    $isoName = Split-Path $cfg.UbuntuIso -Leaf
    if ($isoName -notmatch 'live-server') {
        Die "'$isoName' does not look like a live-server ISO. Autoinstall needs the subiquity live-server image, not desktop and not the legacy installer."
    }
    $isoGB = [math]::Round((Get-Item $cfg.UbuntuIso).Length / 1GB, 2)
    Ok "ISO: $isoName ($isoGB GB)"
    if (-not $cfg.UbuntuIsoSha256) { Warn 'UbuntuIsoSha256 is null. Packer will not verify the ISO.' }

    if (-not (Test-Path $Vmrun)) { Die "vmrun.exe not found at $Vmrun. Fix VmwarePath in the config." }
    $ver = (Invoke-Tool $Vmrun @('-T','ws','list') -IgnoreExit).Output
    Ok "vmrun responds"

    $packer = Get-Command $cfg.PackerExe -ErrorAction SilentlyContinue
    if (-not $packer) {
        Die @"
Packer not found on PATH.

Packer is what makes this unattended. It types the autoinstall kernel args at
the GRUB prompt and builds the cloud-init seed ISO. Without it you are back to
clicking through four installers.

    winget install HashiCorp.Packer
    # or download the single .exe from https://developer.hashicorp.com/packer/install

Then set PackerExe in lab.config.psd1 if it is not on PATH.
"@
    }
    $pv = (Invoke-Tool $packer.Source @('version') -IgnoreExit).Output.Trim()
    Ok "Packer: $pv"

    if ($cfg.LabPasswordHash -eq 'REPLACE_ME_WITH_A_SHA512_CRYPT_HASH') {
        Die "LabPasswordHash is still the placeholder. Generate one with: mkpasswd -m sha-512"
    }
    if ($cfg.LabPasswordHash -notmatch '^\$(6|y)\$') {
        Warn "LabPasswordHash does not start with `$6`$ or `$y`$. That is usually a sign it is not a crypt hash."
    }
    if ($cfg.SshPublicKey -match 'REPLACE_ME') {
        Die "SshPublicKey is still the placeholder. Paste your real public key; password SSH is disabled in these images."
    }
    if ($cfg.SshPublicKey -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-)') {
        Die "SshPublicKey does not look like an OpenSSH public key."
    }
    Ok 'Credentials look sane'

    # Capacity. Thin-provisioned, so this is the ceiling not the immediate cost.
    $needGB = ($targets | Measure-Object -Property DiskGB -Sum).Sum
    $needMB = ($targets | Measure-Object -Property MemoryMB -Sum).Sum
    $drive  = (Split-Path $VmxRoot -Qualifier)
    $free   = [math]::Round((Get-PSDrive $drive.TrimEnd(':')).Free / 1GB, 1)
    Say "Disk: ${needGB} GB max across $($targets.Count) VMs, ${free} GB free on $drive"
    if ($free -lt ($needGB * 0.35)) {
        Warn "Free space is tight. Thin provisioning means you probably fit, but a full corpus run will not."
    }
    $hostMB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    Say "RAM: ${needMB} MB requested, ${hostMB} MB on the host"
    if ($needMB -gt ($hostMB * 0.75)) {
        Warn "The VMs want more than 75% of host RAM. Do not run them all at once, or trim MemoryMB."
    }

    $elevated = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ('networks' -in $Stage -and -not $elevated -and -not $DryRun) {
        Die "Creating vmnets needs an elevated PowerShell. Re-run as Administrator, or use -Stage generate,build,configure,verify and create vmnet2/3/4 by hand in the Virtual Network Editor."
    }
    Ok "Preflight complete"
}

# =====================================================================
# STAGE: networks
# =====================================================================
if ('networks' -in $Stage) {
    Head 'Virtual networks'
    if (-not (Test-Path $Vnetlib)) {
        Warn "vnetlib64.exe not found. Create these by hand in Edit > Virtual Network Editor, HOST-ONLY, DHCP DISABLED:"
        foreach ($k in $cfg.Networks.Keys) {
            $n = $cfg.Networks[$k]; Say "   $($n.VmNet)  $($n.Subnet)/$($n.Mask)   ($k)"
        }
    } else {
        foreach ($k in $cfg.Networks.Keys) {
            $n = $cfg.Networks[$k]
            Step "$($n.VmNet) -> $($n.Subnet) ($k)"
            if ($PSCmdlet.ShouldProcess($n.VmNet, 'create host-only network')) {
                # vnetlib64 is version-sensitive and largely undocumented.
                # Failures are tolerated and reported rather than fatal.
                Invoke-Tool $Vnetlib @('--','add','adapter',$n.VmNet)              -IgnoreExit | Out-Null
                Invoke-Tool $Vnetlib @('--','set','vnet',$n.VmNet,'addr',$n.Subnet) -IgnoreExit | Out-Null
                Invoke-Tool $Vnetlib @('--','set','vnet',$n.VmNet,'mask',$n.Mask)   -IgnoreExit | Out-Null
                # DHCP OFF is the point. Static-only means no stray addresses.
                Invoke-Tool $Vnetlib @('--','remove','dhcp',$n.VmNet)               -IgnoreExit | Out-Null
                Invoke-Tool $Vnetlib @('--','update','adapter',$n.VmNet)            -IgnoreExit | Out-Null
                Invoke-Tool $Vnetlib @('--','update','dhcp',$n.VmNet)               -IgnoreExit | Out-Null
            }
            Ok "$($n.VmNet) configured"
        }
        Warn 'vnetlib64 reports success even when it does nothing. VERIFY in the Virtual Network Editor: host-only, correct subnet, DHCP unticked.'
    }
}

# =====================================================================
# STAGE: generate
# =====================================================================
function New-CloudInit {
    param($Vm, $Cfg)

    # Per-NIC netplan. Names are predictable on VMware: ens33, ens34, ...
    $ethLines = @()
    $i = 33
    foreach ($nic in $Vm.Nics) {
        $dev = "ens$i"; $i++
        if ($nic.Net -eq 'nat' -or -not $nic.Ip) {
            $ethLines += "        ${dev}:"
            $ethLines += "          dhcp4: true"
        } else {
            $ethLines += "        ${dev}:"
            $ethLines += "          dhcp4: false"
            $ethLines += "          addresses: [$($nic.Ip)]"
            if ($Vm.Gateway) {
                $ethLines += "          routes:"
                $ethLines += "            - to: default"
                $ethLines += "              via: $($Vm.Gateway)"
            }
        }
    }
    $netplan = $ethLines -join "`n"

    # Role-specific files, delivered as base64 through cloud-init write_files.
    #
    # An earlier version heredoc'd this through curtin late-commands. That meant
    # PowerShell quoting, then YAML quoting, then shell quoting, all stacked on
    # one line. Base64 has exactly none of those layers, so it either decodes or
    # it does not.
    $writeFiles = @()

    if ($Vm.Role -eq 'agent') {
        # The nftables policy IS part of the instrument. Without a boundary,
        # "egress" is not a meaningful classification.
        #
        # NOTE the output chain is ACCEPT here on purpose. A deny-all at build
        # time breaks apt on first boot. LAB.md phase 2 replaces this with
        # deny-all plus a pinned LLM API allowlist, and until you do that the
        # egress classification has nothing to mean anything against.
        $nft = @'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    ip saddr 10.10.0.0/16 tcp dport 22 accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
    # PHASE 2: change policy to drop and add, with addresses you have resolved
    # and pinned yourself:
    #   ip daddr 10.10.20.10 tcp dport 8080 accept    # collector
    #   ip daddr @llm_api    tcp dport 443  accept    # hosted LLM API
    #   log prefix "COHAERA-LAB-BLOCKED: " level warn counter drop
  }
}
'@
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($nft -replace "`r`n","`n")))
        $writeFiles += @"
      - path: /etc/nftables.conf
        permissions: '0755'
        encoding: b64
        content: $b64
"@

        $audit = @'
-a always,exit -F arch=b64 -S execve -k cohaera_exec
-a always,exit -F arch=b64 -S connect -k cohaera_net
-w /tmp  -p wa -k cohaera_write
-w /home -p wa -k cohaera_write
'@
        $b64a = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($audit -replace "`r`n","`n")))
        $writeFiles += @"
      - path: /etc/audit/rules.d/cohaera.rules
        permissions: '0640'
        encoding: b64
        content: $b64a
"@
    }

    $roleBanner = "Cohaera lab: $($Vm.Name) [$($Vm.Role)]. $($Vm.Notes)"
    $b64m = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$roleBanner`n"))
    $writeFiles += @"
      - path: /etc/motd
        permissions: '0644'
        encoding: b64
        content: $b64m
"@

    $wfBlock = if ($writeFiles) { "    write_files:`n" + ($writeFiles -join "`n") } else { '' }
    $runcmd  = if ($Vm.Role -eq 'agent') {
        "    runcmd:`n      - [ systemctl, enable, --now, nftables ]`n      - [ augenrules, --load ]`n      - [ systemctl, restart, auditd ]"
    } else { '' }

    @"
#cloud-config
# GENERATED BY Build-CohaeraLab.ps1 FOR $($Vm.Name). DO NOT EDIT BY HAND.
autoinstall:
  version: 1
  locale: en_GB.UTF-8
  keyboard: { layout: gb }
  identity:
    hostname: $($Vm.Name)
    username: $($Cfg.LabUser)
    password: "$($Cfg.LabPasswordHash)"
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - "$($Cfg.SshPublicKey)"
  storage:
    layout: { name: direct }
  network:
    network:
      version: 2
      ethernets:
$netplan
  packages:
    - python3
    - python3-venv
    - python3-pip
    - git
    - jq
    - curl
    - tmux
    - auditd
    - nftables
    - open-vm-tools
  user-data:
    disable_root: true
$wfBlock
$runcmd
  shutdown: poweroff
"@
}

function New-PackerTemplate {
    param($Vm, $Cfg, $OutDir)

    $nicBlocks = @()
    $n = 0
    foreach ($nic in $Vm.Nics) {
        $n++
        $suffix = if ($n -eq 1) { '' } else { $n }
        if ($nic.Net -eq 'nat') {
            $nicBlocks += @"
    "ethernet${suffix}.present"           = "TRUE"
    "ethernet${suffix}.connectionType"    = "nat"
    "ethernet${suffix}.virtualDev"        = "vmxnet3"
    "ethernet${suffix}.addressType"       = "generated"
"@
        } else {
            $vmnet = $Cfg.Networks[$nic.Net].VmNet
            $nicBlocks += @"
    "ethernet${suffix}.present"           = "TRUE"
    "ethernet${suffix}.connectionType"    = "custom"
    "ethernet${suffix}.vnet"              = "$vmnet"
    "ethernet${suffix}.virtualDev"        = "vmxnet3"
    "ethernet${suffix}.addressType"       = "generated"
"@
        }
    }
    $nics = $nicBlocks -join "`n"

    $checksum = if ($Cfg.UbuntuIsoSha256) { "`n  iso_checksum         = `"$($Cfg.UbuntuIsoSha256)`"" } else { '' }
    $isoPath  = $Cfg.UbuntuIso -replace '\\','/'
    $outPath  = $Cfg.VmRoot   -replace '\\','/'

    @"
# GENERATED BY Build-CohaeraLab.ps1 FOR $($Vm.Name). DO NOT EDIT BY HAND.
packer {
  required_plugins {
    vmware = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/vmware"
    }
  }
}

source "vmware-iso" "$($Vm.Name)" {
  vm_name              = "$($Vm.Name)"
  iso_url              = "file:///$isoPath"$checksum
  output_directory     = "$outPath/$($Vm.Name)"

  guest_os_type        = "ubuntu-64"
  cpus                 = $($Vm.Cpus)
  memory               = $($Vm.MemoryMB)
  disk_size            = $($Vm.DiskGB * 1024)
  disk_type_id         = "0"          # single growable file, thin
  headless             = $(($Cfg.HeadlessBuild).ToString().ToLower())

  # cloud-init NoCloud seed. Packer builds the ISO and labels it cidata, so no
  # oscdimg or xorriso needed on the host.
  cd_files             = ["./cloud-init/$($Vm.Name)/user-data", "./cloud-init/$($Vm.Name)/meta-data"]
  cd_label             = "cidata"

  # THE LOAD-BEARING PART. Ubuntu 24.04 subiquity will not autoinstall without
  # 'autoinstall' on the kernel command line: with only the seed present it
  # stops and asks for confirmation. Typing it at the GRUB command line is the
  # standard way to avoid remastering the ISO.
  boot_wait            = "5s"
  boot_command         = [
    "<wait5s>c<wait2s>",
    "linux /casper/vmlinuz --- autoinstall ds='nocloud'<enter><wait2s>",
    "initrd /casper/initrd<enter><wait2s>",
    "boot<enter>"
  ]

  ssh_username         = "$($Cfg.LabUser)"
  ssh_private_key_file = "~/.ssh/id_ed25519"
  ssh_timeout          = "$($Cfg.BuildTimeoutMin)m"
  ssh_handshake_attempts = 100

  shutdown_command     = "sudo -S shutdown -P now"
  shutdown_timeout     = "5m"

  vmx_data = {
    "virtualHW.version" = "20"
$nics
    "tools.syncTime"    = "TRUE"
  }
}

build {
  sources = ["source.vmware-iso.$($Vm.Name)"]

  provisioner "shell" {
    inline = [
      "echo '--- $($Vm.Name) post-install ---'",
      "sudo apt-get update -qq",
      "python3 -m venv ~/venv",
      "~/venv/bin/pip install --quiet --upgrade pip",
      "echo 'source ~/venv/bin/activate' >> ~/.bashrc"
    ]
  }
}
"@
}

if ('generate' -in $Stage) {
    Head 'Generate Packer and cloud-init'
    New-Item -ItemType Directory -Force -Path $GenRoot | Out-Null
    foreach ($vm in $targets) {
        $ciDir = Join-Path $GenRoot "cloud-init\$($vm.Name)"
        New-Item -ItemType Directory -Force -Path $ciDir | Out-Null

        # cloud-init line endings MUST be LF. CRLF breaks the YAML parse.
        $ud = New-CloudInit -Vm $vm -Cfg $cfg
        [IO.File]::WriteAllText((Join-Path $ciDir 'user-data'), ($ud -replace "`r`n","`n"))
        [IO.File]::WriteAllText((Join-Path $ciDir 'meta-data'),
            "instance-id: $($vm.Name)-001`nlocal-hostname: $($vm.Name)`n")

        $tpl = New-PackerTemplate -Vm $vm -Cfg $cfg -OutDir $GenRoot
        [IO.File]::WriteAllText((Join-Path $GenRoot "$($vm.Name).pkr.hcl"), ($tpl -replace "`r`n","`n"))
        Ok "$($vm.Name): user-data, meta-data, $($vm.Name).pkr.hcl"
    }
    Say ""
    Say "Generated in: $GenRoot"
    Say "READ user-data BEFORE BUILDING. It contains your password hash and SSH key."
}

# =====================================================================
# STAGE: build
# =====================================================================
if ('build' -in $Stage) {
    Head 'Build'
    Push-Location $GenRoot
    try {
        Step 'packer init'
        Invoke-Tool $cfg.PackerExe @('init', '.') -IgnoreExit | Out-Null

        foreach ($vm in $targets) {
            $vmx = Join-Path $VmxRoot "$($vm.Name)\$($vm.Name).vmx"
            if (Test-Path $vmx) { Warn "$($vm.Name) already exists, skipping. Use -Destroy first to rebuild."; continue }

            Step "packer validate $($vm.Name)"
            Invoke-Tool $cfg.PackerExe @('validate', "$($vm.Name).pkr.hcl") | Out-Null

            if ($PSCmdlet.ShouldProcess($vm.Name, 'packer build')) {
                Step "packer build $($vm.Name), expect 10 to 25 minutes"
                $t0 = Get-Date
                Invoke-Tool $cfg.PackerExe @('build','-force',"$($vm.Name).pkr.hcl")
                Ok "$($vm.Name) built in $([int]((Get-Date) - $t0).TotalMinutes) min"
            }
        }
    } finally { Pop-Location }
}

# =====================================================================
# STAGE: configure
# =====================================================================
if ('configure' -in $Stage) {
    Head 'Post-build configuration'
    foreach ($vm in $targets) {
        $vmx = Join-Path $VmxRoot "$($vm.Name)\$($vm.Name).vmx"
        if (-not (Test-Path $vmx) -and -not $DryRun) { Warn "$($vm.Name): no vmx, skipping"; continue }
        if ($cfg.SnapshotAfterBuild -and $PSCmdlet.ShouldProcess($vm.Name, "snapshot '$($cfg.SnapshotName)'")) {
            Invoke-Tool $Vmrun @('snapshot', $vmx, $cfg.SnapshotName) -IgnoreExit | Out-Null
            Ok "$($vm.Name): snapshot '$($cfg.SnapshotName)'"
        }
    }
    Say ''
    Say 'Restore to this snapshot between run sets. Run-to-run comparability depends on it,'
    Say 'and a research audience will ask whether you did.'
}

# =====================================================================
# STAGE: verify
# =====================================================================
if ('verify' -in $Stage) {
    Head 'Verify'
    $fail = 0
    foreach ($vm in $targets) {
        $vmx = Join-Path $VmxRoot "$($vm.Name)\$($vm.Name).vmx"
        if (Test-Path $vmx) { Ok "$($vm.Name): vmx present" }
        else { if (-not $DryRun) { Warn "$($vm.Name): vmx MISSING"; $fail++ } }
    }

    Write-Host @"

  Manual checks the script cannot do for you
  ------------------------------------------
  1. Virtual Network Editor: vmnet2/3/4 are HOST-ONLY with DHCP UNTICKED.
     vnetlib64 reports success even when it changes nothing.

  2. From agent-01, the LLM API must be reachable and everything else must not:
       curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/v1/messages
       nc -zv 10.10.20.10 8080
       curl -m 5 https://example.com          # should FAIL once you tighten nftables

  3. From analysis-01, agent-01 must be unreachable:
       ping -c1 -W2 10.10.10.10               # must FAIL

  4. Tighten the agent egress policy. The generated nftables output chain is
     ACCEPT so that first-boot apt works. Phase 2 in LAB.md replaces it with
     deny-all plus a pinned LLM API allowlist. UNTIL YOU DO THAT, the 'egress'
     classification in Cohaera has no boundary to mean anything against.

  5. Set a HARD SPEND CAP at your API provider before the first corpus run.
"@ -ForegroundColor White

    if ($script:Warnings) {
        Write-Host "`n  Warnings raised during this run:" -ForegroundColor Yellow
        $script:Warnings | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    }
    if ($fail) { Die "$fail VM(s) missing" }
    Ok 'Done'
}
