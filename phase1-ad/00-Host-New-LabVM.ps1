<#
.SYNOPSIS
    Armstrong IAM lab - creates the lab network and any lab VM on the Hyper-V HOST.

.DESCRIPTION
    Run in an elevated PowerShell window on your laptop (not inside a VM).
    - Creates the internal switch 'IAMLab-Switch' and a NAT for 10.10.10.0/24 the first time it
      runs, and reuses them after that. The lab is isolated from your home network but still
      reaches the internet.
    - Creates a Generation 2 VM that boots from the ISO you pass.
    Re-run it for each VM: DC01, SRV01, CLIENT01, LNX01, LNX02, PAM01.

.EXAMPLE
    # Domain controller (time sync off - a DC must not take time from the host)
    .\00-Host-New-LabVM.ps1 -VmName DC01 -IsoPath C:\ISO\Server2025.iso -DisableTimeSync

.EXAMPLE
    # Windows 11 client: 4 GB at boot because Windows 11 setup checks for 4 GB, TPM for BitLocker later
    .\00-Host-New-LabVM.ps1 -VmName CLIENT01 -IsoPath C:\ISO\Win11Ent.iso -MemStartup 4GB -MemMax 4GB -EnableTpm

.EXAMPLE
    # Linux server (Rocky / RHEL / Ubuntu need the Microsoft UEFI CA template for Secure Boot)
    .\00-Host-New-LabVM.ps1 -VmName LNX01 -IsoPath C:\ISO\Rocky-9.iso -MemStartup 1GB -MemMax 2GB -DiskSize 30GB -Linux

.NOTES
    16 GB laptop: run only the VMs the current phase needs; Save-VM the rest.
    Enable Hyper-V once (Windows 11 Pro/Enterprise), then reboot:
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$VmName,
    [Parameter(Mandatory)][string]$IsoPath,
    [string]$VmRoot     = 'C:\HyperV\ArmstrongIAM',
    [string]$SwitchName = 'IAMLab-Switch',
    [string]$NatPrefix  = '10.10.10.0/24',
    [string]$GatewayIP  = '10.10.10.1',
    [int64] $DiskSize   = 60GB,
    [int64] $MemStartup = 2GB,
    [int64] $MemMax     = 3GB,
    [int]   $Cpu        = 2,
    [switch]$DisableTimeSync,
    [switch]$EnableTpm,
    [switch]$Linux
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }

# --- 1. Internal switch + NAT (created once, reused by every VM) ---
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($SwitchName, 'Create internal switch')) {
        New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
        $ifIndex = (Get-NetAdapter -Name "vEthernet ($SwitchName)").ifIndex
        New-NetIPAddress -IPAddress $GatewayIP -PrefixLength 24 -InterfaceIndex $ifIndex | Out-Null
    }
}
# Windows allows only one NAT network in most setups: reuse any NAT that already covers this prefix
if (-not (Get-NetNat -ErrorAction SilentlyContinue | Where-Object InternalIPInterfaceAddressPrefix -eq $NatPrefix)) {
    if ($PSCmdlet.ShouldProcess($NatPrefix, 'Create NAT')) {
        New-NetNat -Name $SwitchName -InternalIPInterfaceAddressPrefix $NatPrefix | Out-Null
    }
}

# --- 2. The VM ---
if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) { throw "$VmName already exists." }

$vmDir = Join-Path $VmRoot $VmName
$vhd   = Join-Path $vmDir "$VmName.vhdx"

if ($PSCmdlet.ShouldProcess($VmName, 'Create VM')) {
    New-Item -ItemType Directory -Path $vmDir -Force | Out-Null
    New-VM -Name $VmName -Generation 2 -Path $VmRoot `
           -NewVHDPath $vhd -NewVHDSizeBytes $DiskSize `
           -MemoryStartupBytes $MemStartup -SwitchName $SwitchName | Out-Null

    $memMin = [math]::Min([int64]1GB, $MemStartup)
    Set-VM -Name $VmName -ProcessorCount $Cpu -DynamicMemory `
           -MemoryMinimumBytes $memMin -MemoryMaximumBytes ([math]::Max($MemMax, $MemStartup)) `
           -AutomaticCheckpointsEnabled $false

    if ($DisableTimeSync) {
        Disable-VMIntegrationService -VMName $VmName -Name 'Time Synchronization'
    }
    if ($Linux) {
        Set-VMFirmware -VMName $VmName -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'
    }
    if ($EnableTpm) {
        Set-VMKeyProtector -VMName $VmName -NewLocalKeyProtector
        Enable-VMTPM -VMName $VmName
    }

    $dvd = Add-VMDvdDrive -VMName $VmName -Path $IsoPath -Passthru
    Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd
}

Write-Host "`n$VmName created. Next:" -ForegroundColor Green
Write-Host "  Start-VM $VmName; vmconnect localhost $VmName"
Write-Host "  Press a key at 'Press any key to boot from CD or DVD'"
Write-Host "  After install and first sign-in: Checkpoint-VM -Name $VmName -SnapshotName 'Clean OS'"

