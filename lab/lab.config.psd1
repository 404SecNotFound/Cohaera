<#
    Cohaera lab configuration.

    THIS IS THE ONLY FILE YOU SHOULD NEED TO EDIT.

    Everything else is generated. Set the ISO paths, pick a password hash,
    drop in your SSH public key, and run Build-CohaeraLab.ps1.
#>

@{

    # ---------------------------------------------------------------------
    # REQUIRED: where your ISOs live
    # ---------------------------------------------------------------------
    # Ubuntu Server 24.04.x LIVE SERVER iso. Not the desktop image, not the
    # "legacy" installer. The autoinstall path below only works with the
    # subiquity live-server installer.
    #   https://releases.ubuntu.com/24.04/
    UbuntuIso        = 'D:\ISO\ubuntu-24.04.2-live-server-amd64.iso'

    # Optional. Leave $null unless you actually verified it. If set, Packer
    # checks it and refuses to build on mismatch, which is worth doing.
    UbuntuIsoSha256  = $null      # e.g. 'sha256:d6dab0c3a657988501b4bd76f1297c053df710e06e0c3aece60dead24f270b4d'

    # ---------------------------------------------------------------------
    # REQUIRED: credentials
    # ---------------------------------------------------------------------
    # Generate on any Linux box or WSL:
    #     mkpasswd -m sha-512
    # Or:
    #     python3 -c "import crypt;print(crypt.crypt('yourpass', crypt.mksalt(crypt.METHOD_SHA512)))"
    #
    # DO NOT commit a real hash. This placeholder is 'cohaera-lab' and MUST be
    # replaced; the preflight refuses to build while it is unchanged.
    LabUser          = 'labadmin'
    LabPasswordHash  = 'REPLACE_ME_WITH_A_SHA512_CRYPT_HASH'

    # Contents of your id_ed25519.pub. Password SSH is disabled in the images.
    SshPublicKey     = 'ssh-ed25519 AAAA_REPLACE_ME your@host'

    # ---------------------------------------------------------------------
    # Paths
    # ---------------------------------------------------------------------
    VmRoot           = 'D:\VMs\CohaeraLab'    # where the VMs get built
    VmwarePath       = 'C:\Program Files (x86)\VMware\VMware Workstation'
    PackerExe        = 'packer'               # or a full path to packer.exe

    # ---------------------------------------------------------------------
    # Network segments
    # ---------------------------------------------------------------------
    # vmnet1 and vmnet8 are reserved by VMware for host-only and NAT. These
    # three are created as HOST-ONLY with DHCP DISABLED, so the only addresses
    # on them are the static ones below. That matters: the lab's security
    # property depends on there being no stray routes.
    Networks = @{
        Generation = @{ VmNet = 'vmnet2'; Subnet = '10.10.10.0'; Mask = '255.255.255.0' }
        Collection = @{ VmNet = 'vmnet3'; Subnet = '10.10.20.0'; Mask = '255.255.255.0' }
        Analysis   = @{ VmNet = 'vmnet4'; Subnet = '10.10.30.0'; Mask = '255.255.255.0' }
    }

    # ---------------------------------------------------------------------
    # The machines
    # ---------------------------------------------------------------------
    # Nics are applied in order: nic1, nic2. 'nat' gives internet via vmnet8.
    #
    # The topology deliberately gives collector-01 a foot in both the
    # collection and analysis segments, and gives analysis-01 NO route to
    # agent-01. IP forwarding is left OFF on the collector, so analysis pulls
    # from the collector rather than reaching through it.
    Vms = @(
        @{
            Name   = 'agent-01'
            Role   = 'agent'
            Cpus   = 4;  MemoryMB = 8192;  DiskGB = 40
            Nics   = @(
                @{ Net = 'nat';        Ip = $null }                      # LLM API egress
                @{ Net = 'Generation'; Ip = '10.10.10.10/24' }
            )
            Gateway = $null            # NAT DHCP supplies the default route
            Notes  = 'Runs the instrumented agent and AgentDojo. Egress locked by nftables.'
        }
        @{
            Name   = 'collector-01'
            Role   = 'collector'
            Cpus   = 2;  MemoryMB = 4096;  DiskGB = 100
            Nics   = @(
                @{ Net = 'Generation'; Ip = '10.10.10.20/24' }
                @{ Net = 'Collection'; Ip = '10.10.20.10/24' }
            )
            Gateway = $null
            Notes  = 'Telemetry sink. Boundary between generation and analysis.'
        }
        @{
            Name   = 'analysis-01'
            Role   = 'analysis'
            Cpus   = 4;  MemoryMB = 16384; DiskGB = 100
            Nics   = @(
                @{ Net = 'Collection'; Ip = '10.10.20.30/24' }
            )
            Gateway = $null            # deliberately no default route, no internet
            Notes  = 'Cohaera and scoring. No internet. No route to agent-01.'
        }
        @{
            Name   = 'siem-01'
            Role   = 'siem'
            Cpus   = 4;  MemoryMB = 16384; DiskGB = 200
            Nics   = @(
                @{ Net = 'Analysis';   Ip = '10.10.30.10/24' }
            )
            Gateway = $null
            Enabled = $false           # phase 5 only. Set $true when you need it.
            Notes  = 'Rule authoring and corpus replay.'
        }
    )

    # ---------------------------------------------------------------------
    # Isolation, as assertions rather than prose
    # ---------------------------------------------------------------------
    # COH-R18. The lab's whole reason for existing is that the segments are
    # separated, and that separation used to be checked by printing a list of
    # commands for the operator to run by hand. A property nobody runs is a
    # property nobody has, and the negative ones are the load-bearing half:
    # "analysis-01 cannot reach agent-01" is what makes an egress finding in
    # Cohaera mean something, and it is exactly the sort of thing a stray route
    # or a helpful DHCP server breaks silently months later.
    #
    # The verify stage runs every row over SSH and fails the build on any
    # disagreement. Expect is what the lab DESIGN says, so a row that fails is
    # either a broken lab or a design that changed without this table.
    #
    #   From     the VM the probe runs on, by name
    #   Kind     tcp | ping | dns | https
    #   Target   host, or host:port for tcp
    #   Expect   reach | blocked
    #   Why      shown when the probe disagrees; say what it protects
    #
    # Advisory rows do not fail the build. Exactly one thing here depends on
    # the outside world -- the LLM API -- and a lab that fails verification
    # because somebody's WAN is down is a lab that gets verified with -Stage
    # skipping this. It still prints, loudly.
    Reachability = @(
        @{ From = 'analysis-01'; Kind = 'ping';  Target = '10.10.10.10';      Expect = 'blocked'
           Why  = 'analysis must have NO route to the agent host. If it does, telemetry and the thing producing it share a failure domain and an egress finding proves nothing.' }
        @{ From = 'analysis-01'; Kind = 'tcp';   Target = '10.10.10.10:22';   Expect = 'blocked'
           Why  = 'as above, and ICMP alone can be filtered while TCP is open.' }
        @{ From = 'analysis-01'; Kind = 'https'; Target = 'https://example.com'; Expect = 'blocked'
           Why  = 'analysis-01 has no default route by design. Reaching the internet means one was added, and the scoring host is no longer offline.' }
        @{ From = 'analysis-01'; Kind = 'dns';   Target = 'example.com';      Expect = 'blocked'
           Why  = 'DNS is the resolution path that survives a missing default route and the first one to leak.' }
        @{ From = 'analysis-01'; Kind = 'tcp';   Target = '10.10.20.10:22';   Expect = 'reach'
           Why  = 'analysis PULLS from the collector. If this fails the lab is not merely isolated, it is broken.' }
        @{ From = 'collector-01'; Kind = 'tcp';  Target = '10.10.10.10:22';   Expect = 'reach'
           Why  = 'the collector has a foot in the generation segment on purpose.' }
        @{ From = 'agent-01';    Kind = 'tcp';   Target = '10.10.20.10:22';   Expect = 'reach'
           Why  = 'the agent must be able to ship telemetry to the collector.' }
        @{ From = 'agent-01';    Kind = 'https'; Target = 'https://api.anthropic.com/v1/messages'; Expect = 'reach'; Advisory = $true
           Why  = 'the agent needs the LLM API. Advisory: this is the one row that depends on the outside world.' }
        @{ From = 'agent-01';    Kind = 'https'; Target = 'https://example.com'; Expect = 'blocked'
           Why  = 'LAB.md phase 2 replaces the permissive first-boot nftables output chain with deny-all plus a pinned API allowlist. Until this row passes, the egress class in Cohaera has no boundary to mean anything against.' }
    )

    # collector-01 must not forward between its two segments: analysis pulls
    # from it rather than reaching through it. Checked directly on the guest,
    # because a router in the middle silently converts the two negative rows
    # above into an accident of routing tables.
    NoForwarding = @('collector-01')

    # ---------------------------------------------------------------------
    # Behaviour
    # ---------------------------------------------------------------------
    SnapshotAfterBuild = $true
    SnapshotName       = 'clean-baseline'
    HeadlessBuild      = $true      # $false to watch the installer, useful when debugging
    BuildTimeoutMin    = 45         # per VM
}
