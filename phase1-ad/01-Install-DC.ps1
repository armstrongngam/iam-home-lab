<#
.SYNOPSIS
    Armstrong IAM lab - Phase 1 (run INSIDE the DC01 VM, elevated).
    Three stages, run in order. The VM reboots after Stage 1 and Stage 2.

      .\01-Install-DC.ps1 -Stage Prep      # rename, static IP, reboot
      .\01-Install-DC.ps1 -Stage Promote   # install AD DS + DNS, new forest, reboot
      .\01-Install-DC.ps1 -Stage Verify    # DNS forwarders, NTP, health checks

    Log: C:\LabLogs\DC01-Build.log
#>

param(
    [Parameter(Mandatory)]
    [ValidateSet('Prep','Promote','Verify')]
    [string]$Stage,
    [string]$DomainName = 'corp.armstrongiam.com',
    [string]$NetBIOS    = 'ARMIAM',
    [string]$IP         = '10.10.10.10',
    [string]$Gateway    = '10.10.10.1',
    [string]$TimeZone   = 'Central Standard Time'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path C:\LabLogs -Force | Out-Null
Start-Transcript -Path C:\LabLogs\DC01-Build.log -Append | Out-Null

switch ($Stage) {

  'Prep' {
    $nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
    Write-Host "Setting static IP $IP on $($nic.Name)" -ForegroundColor Cyan
    Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
    Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IP -PrefixLength 24 -DefaultGateway $Gateway | Out-Null
    # Point DNS at itself; AD DS installs DNS during promotion.
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses '127.0.0.1'

    Set-TimeZone -Id $TimeZone
    Write-Host "Renaming to DC01 and rebooting..." -ForegroundColor Cyan
    Stop-Transcript | Out-Null
    Rename-Computer -NewName 'DC01' -Restart
  }

  'Promote' {
    if ($env:COMPUTERNAME -ne 'DC01') { throw 'Run -Stage Prep first (computer is not named DC01).' }

    Write-Host 'Installing AD DS role...' -ForegroundColor Cyan
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

    $dsrm = Read-Host 'Enter a DSRM (Directory Services Restore Mode) password' -AsSecureString

    Import-Module ADDSDeployment
    $params = @{
        DomainName                    = $DomainName
        DomainNetbiosName             = $NetBIOS
        InstallDns                    = $true
        SafeModeAdministratorPassword = $dsrm
        DatabasePath                  = 'C:\Windows\NTDS'
        LogPath                       = 'C:\Windows\NTDS'
        SysvolPath                    = 'C:\Windows\SYSVOL'
        NoRebootOnCompletion          = $false
        Force                         = $true
    }

    Write-Host 'Running prerequisite check...' -ForegroundColor Cyan
    Test-ADDSForestInstallation @params | Format-Table Status, Message -AutoSize

    Write-Host "Creating forest $DomainName (VM will reboot)..." -ForegroundColor Cyan
    Stop-Transcript | Out-Null
    Install-ADDSForest @params
  }

  'Verify' {
    Import-Module ActiveDirectory

    # Internet name resolution for later phases (Entra, Okta agent downloads)
    Write-Host 'Adding DNS forwarders...' -ForegroundColor Cyan
    Set-DnsServerForwarder -IPAddress 1.1.1.1, 8.8.8.8

    # PDC emulator is the forest time source; point it at an external NTP server.
    Write-Host 'Configuring NTP on the PDC emulator...' -ForegroundColor Cyan
    w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /reliable:yes /update | Out-Null
    Restart-Service w32time
    w32tm /resync /force | Out-Null

    Write-Host "`n--- Domain ---" -ForegroundColor Green
    Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator | Format-List
    Get-ADForest | Select-Object Name, ForestMode, SchemaMaster | Format-List

    Write-Host '--- DNS ---' -ForegroundColor Green
    Resolve-DnsName $DomainName | Select-Object Name, IPAddress | Format-Table -AutoSize
    Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV | Select-Object NameTarget, Port | Format-Table -AutoSize
    Resolve-DnsName 'login.microsoftonline.com' | Select-Object -First 1 Name | Format-Table -AutoSize

    Write-Host '--- Time ---' -ForegroundColor Green
    w32tm /query /source

    Write-Host '--- dcdiag (errors only) ---' -ForegroundColor Green
    dcdiag /q
    if ($LASTEXITCODE -eq 0) { Write-Host 'dcdiag: no errors reported.' -ForegroundColor Green }

    Write-Host "`nTake a checkpoint from the host now:  Checkpoint-VM -Name DC01 -SnapshotName 'Forest created'" -ForegroundColor Yellow
  }
}

try { Stop-Transcript | Out-Null } catch {}
