<#
.SYNOPSIS
    Armstrong IAM lab - Phase 1 deep dive: LDAP, Kerberos vs NTLM, AD Recycle Bin, backup and restore.

.DESCRIPTION
    Guided exercises for the topics AD engineer interviews probe hardest. Run on DC01
    (elevated) one exercise at a time, read the output, and write what you saw in the
    Phase 1 README. Interview prep notes are in the comments of each exercise.

      -Exercise Ldap        Raw LDAP filters (bitwise and in-chain matching rules), LDAPS check
      -Exercise Kerberos    Tickets, SPNs, time skew, DC events 4768/4769
      -Exercise Ntlm        Turn on NTLM auditing and find who still uses NTLM
      -Exercise RecycleBin  Enable AD Recycle Bin, delete and restore a test user
      -Exercise Backup      System state backup to a second disk; authoritative restore steps

.EXAMPLE
    .\05-Invoke-ADDeepDive.ps1 -Exercise Ldap
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Ldap', 'Kerberos', 'Ntlm', 'RecycleBin', 'Backup')]
    [string]$Exercise,
    [string]$BackupTarget = 'E:'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dc     = (Get-ADDomainController).HostName

function Show([string]$Title) { Write-Host "`n=== $Title ===" -ForegroundColor Cyan }

function Invoke-Ldap([string]$Filter, [string[]]$Props = @('samaccountname')) {
    $s = [adsisearcher]$Filter
    $s.PageSize = 500
    $Props | ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
    $s.FindAll() | ForEach-Object { $_.Properties.samaccountname }
}

switch ($Exercise) {

  'Ldap' {
    # Interview: LDAP is the protocol (389, 636 for LDAPS); AD is the directory that speaks it.
    # Filters use prefix notation; bit flags need matching-rule OIDs.
    Show 'Finance users  (&(objectCategory=person)(objectClass=user)(department=Finance))'
    Invoke-Ldap '(&(objectCategory=person)(objectClass=user)(department=Finance))'

    Show 'Disabled accounts  userAccountControl bit 2 (rule 1.2.840.113556.1.4.803 = bitwise AND)'
    Invoke-Ldap '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))'

    Show 'Password never expires  bit 65536'
    Invoke-Ldap '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))'

    Show 'Accounts with an SPN (Kerberoastable if a user account with a weak password)'
    Invoke-Ldap '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'

    $da = (Get-ADGroup 'Domain Admins').DistinguishedName
    Show 'Everyone in Domain Admins, including nested  (rule 1.2.840.113556.1.4.1941 = in chain)'
    Invoke-Ldap "(memberOf:1.2.840.113556.1.4.1941:=$da)"

    Show 'LDAPS (636) - works after a DC certificate exists (AD Certificate Services, Phase 10)'
    Test-NetConnection $dc -Port 636 | Select-Object ComputerName, RemotePort, TcpTestSucceeded | Format-Table -AutoSize
    Write-Host 'Also try ldp.exe: Connection > Connect (389, then 636 with SSL) > Bind > Browse > Search.'
  }

  'Kerberos' {
    # Interview: Kerberos = tickets from the KDC on the DC (AS-REQ -> TGT, TGS-REQ -> service ticket),
    # needs DNS names, SPNs, and clocks within 5 minutes. NTLM = challenge/response, fallback
    # when you use an IP address, a missing/duplicate SPN, or a non-domain machine.
    Show 'Your tickets now (klist)'
    klist
    Show "Request a service ticket for cifs/$dc"
    klist get "cifs/$dc"
    Show 'Duplicate SPNs break Kerberos (setspn -X)'
    setspn -X
    Show 'Time skew against the PDC emulator (must be < 5 minutes)'
    w32tm /stripchart /computer:$($domain.PDCEmulator) /samples:3 /dataonly
    Show 'DC events: 4768 = TGT issued, 4769 = service ticket, 4771 = pre-auth failed'
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768, 4769, 4771 } -MaxEvents 15 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{ n = 'Account'; e = { $_.Properties[0].Value } } | Format-Table -AutoSize
    Write-Host "`nBreak it on purpose: on CLIENT01 run 'dir \\10.10.10.10\SYSVOL' (IP = NTLM) vs 'dir \\$dc\SYSVOL' (name = Kerberos), then compare klist."
  }

  'Ntlm' {
    # Interview: you can't switch NTLM off blind - audit first, find who uses it, fix them, then restrict.
    Show 'Enable NTLM auditing on this DC (production: set the same through a GPO)'
    $msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $net = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Set-ItemProperty -Path $msv -Name AuditReceivingNTLMTraffic -Value 2 -Type DWord   # audit all incoming NTLM
    Set-ItemProperty -Path $net -Name AuditNTLMInDomain        -Value 7 -Type DWord   # audit all NTLM in the domain
    Write-Host 'Auditing on. Generate some NTLM (dir \\10.10.10.10\SYSVOL from CLIENT01), then re-run this exercise.'
    Show 'NTLM events (Microsoft-Windows-NTLM/Operational 8004) and 4776 credential validation'
    Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 15 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message | Format-Table -Wrap
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4776 } -MaxEvents 10 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, @{ n = 'Account'; e = { $_.Properties[1].Value } }, @{ n = 'Workstation'; e = { $_.Properties[2].Value } } |
        Format-Table -AutoSize
  }

  'RecycleBin' {
    # Interview: Recycle Bin keeps all attributes (group memberships too) for the deleted-object lifetime
    # (180 days by default). Enabling it is irreversible. Without it you need an authoritative restore.
    $feature = Get-ADOptionalFeature 'Recycle Bin Feature'
    if (-not $feature.EnabledScopes) {
        Show 'Enabling AD Recycle Bin (irreversible - fine in a lab)'
        Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $domain.Forest -Confirm:$false
    }
    $ou = "OU=Sales,OU=Users,OU=Corp,$($domain.DistinguishedName)"
    Show 'Create, group, delete, and restore a test user'
    New-ADUser -Name 'Test Restore' -SamAccountName 'test.restore' -Path $ou -Enabled $false
    Add-ADGroupMember 'GRP-Sales-Users' -Members 'test.restore'
    Remove-ADUser 'test.restore' -Confirm:$false
    Get-ADObject -Filter "samAccountName -eq 'test.restore'" -IncludeDeletedObjects | Restore-ADObject
    Get-ADUser 'test.restore' -Properties memberOf | Select-Object SamAccountName, DistinguishedName, memberOf | Format-List
    Write-Host 'Group membership came back with the object. Clean up: Remove-ADUser test.restore -Confirm:$false'
  }

  'Backup' {
    # Prerequisite (on the HOST): give DC01 a second disk, then bring it online as E: in Disk Management.
    #   New-VHD -Path C:\HyperV\ArmstrongIAM\DC01\DC01-backup.vhdx -SizeBytes 40GB -Dynamic
    #   Add-VMHardDiskDrive -VMName DC01 -Path C:\HyperV\ArmstrongIAM\DC01\DC01-backup.vhdx
    if (-not (Get-WindowsFeature Windows-Server-Backup).Installed) {
        Show 'Installing Windows Server Backup'
        Install-WindowsFeature Windows-Server-Backup | Out-Null
    }
    if (-not (Test-Path $BackupTarget)) { throw "Backup target $BackupTarget not found - add the second disk first (see comments)." }
    Show "System state backup to $BackupTarget"
    wbadmin start systemstatebackup -backupTarget:$BackupTarget -quiet
    wbadmin get versions
    Write-Host @"

Authoritative restore (practise once, then write it up as a runbook):
  1. bcdedit /set safeboot dsrepair ; shutdown /r /t 0       (boot into DSRM; sign in .\Administrator with the DSRM password)
  2. wbadmin get versions ; wbadmin start systemstaterecovery -version:<version> -quiet
  3. Do NOT reboot. ntdsutil "activate instance ntds" "authoritative restore" "restore object <DN of deleted user>" q q
  4. bcdedit /deletevalue safeboot ; shutdown /r /t 0
Non-authoritative = DC catches up from partners. Authoritative = this copy wins and replicates out.
With one DC, a normal restore is enough; the authoritative step matters once you have two.
"@
  }
}
