<#
.SYNOPSIS
    Armstrong IAM lab - Phase 1: admin tiering, help desk delegation, and service accounts.

.DESCRIPTION
    Run on DC01 (elevated) AFTER the 50 users exist (..\phase5-lifecycle\Invoke-LifecycleSync.ps1).

    Admin tiering
      - Separate adm- accounts for privileged work; daily accounts stay unprivileged.
      - Tier 0 (domain control): Domain Admins + Protected Users.
      - Tier 1 (servers, directory ops): GRP-IT-Admins and GRP-Workstation-Admins.
      - All adm- accounts: "sensitive and cannot be delegated", stricter FGPP (03 script),
        owner's EmployeeId stored in employeeNumber so the leaver process disables them too.

    Help desk delegation (least privilege)
      - GRP-Helpdesk can reset passwords and unlock users in OU=Users only - no admin rights.

    Service accounts (non-human identities, used again in Phase 10)
      - gMSA gmsa-app01: password managed and rotated by AD; nobody knows it.
      - svc-backup: traditional account WITH an owner and description.
      - svc-sqlreport: DELIBERATELY BAD - SPN, password never expires, no owner.
        Phase 10's NHI inventory should find it and flag it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Tier0Owners    = @('priya.raman'),
    [string[]]$Tier1Owners    = @('marcus.bell', 'sofia.alvarez', 'ryan.kowalski', 'mei.chen'),
    [string[]]$HelpdeskUsers  = @('tomas.novak', 'aisha.bello', 'owen.fischer'),
    [string]  $UpnSuffix      = 'armstrongiam.com',
    [string]  $PasswordFile   = 'C:\LabSecrets\initial-passwords.csv',
    [string]  $LogPath        = 'C:\LabLogs\Phase1-Admins.log'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
New-Item -ItemType Directory -Path (Split-Path $LogPath), (Split-Path $PasswordFile) -Force -WhatIf:$false | Out-Null
function Write-Log([string]$m) { $l = '{0:u} [{1}] {2}' -f (Get-Date), $env:USERNAME, $m; Add-Content $LogPath $l -WhatIf:$false; Write-Host $l }

$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName
$netbios  = $domain.NetBIOSName
$tier0OU  = "OU=Tier0,OU=Admins,OU=Corp,$domainDN"
$tier1OU  = "OU=Tier1,OU=Admins,OU=Corp,$domainDN"
$svcOU    = "OU=Service Accounts,OU=Corp,$domainDN"
$userOU   = "OU=Users,OU=Corp,$domainDN"

function New-RandomPassword([int]$Length = 24) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%*-_=+?'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    do {
        $bytes = New-Object byte[] $Length; $rng.GetBytes($bytes)
        $pw = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    } until ($pw -cmatch '[A-Z]' -and $pw -cmatch '[a-z]' -and $pw -match '\d' -and $pw -match '[^A-Za-z0-9]')
    $pw
}

function New-AdminAccount([string]$OwnerSam, [string]$Tier, [string]$Path, [string[]]$Groups) {
    $owner = Get-ADUser $OwnerSam -Properties employeeID, GivenName, Surname
    $sam   = ('adm-' + $OwnerSam); if ($sam.Length -gt 20) { $sam = $sam.Substring(0, 20) }
    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Write-Verbose "$sam exists"; return
    }
    if ($PSCmdlet.ShouldProcess($sam, "Create $Tier admin account")) {
        $pw = New-RandomPassword
        New-ADUser -Name "$($owner.GivenName) $($owner.Surname) (Admin $Tier)" -SamAccountName $sam `
            -UserPrincipalName "$sam@$UpnSuffix" -GivenName $owner.GivenName -Surname $owner.Surname `
            -Description "$Tier admin account for $OwnerSam" -EmployeeNumber $owner.employeeID `
            -Path $Path -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) `
            -Enabled $true -AccountNotDelegated $true -ChangePasswordAtLogon $true
        foreach ($g in $Groups) { Add-ADGroupMember -Identity $g -Members $sam }
        [pscustomobject]@{ SamAccountName = $sam; EmployeeId = "owner:$($owner.employeeID)"; InitialPassword = $pw; Created = (Get-Date).ToString('s') } |
            Export-Csv -Path $PasswordFile -Append -NoTypeInformation
        Write-Log "Created $sam ($Tier) owned by $OwnerSam; groups: $($Groups -join ', ')"
    }
}

# ---------- Tiered admin accounts ----------
foreach ($o in $Tier0Owners) { New-AdminAccount $o 'Tier0' $tier0OU @('Domain Admins', 'Protected Users') }
foreach ($o in $Tier1Owners) { New-AdminAccount $o 'Tier1' $tier1OU @('GRP-IT-Admins', 'GRP-Workstation-Admins') }

# ---------- Help desk: reset password + unlock on user objects under OU=Users ----------
foreach ($h in $HelpdeskUsers) {
    if ($PSCmdlet.ShouldProcess($h, 'Add to GRP-Helpdesk')) { Add-ADGroupMember -Identity 'GRP-Helpdesk' -Members $h }
}
if ($PSCmdlet.ShouldProcess($userOU, 'Delegate reset/unlock to GRP-Helpdesk')) {
    $who = "$netbios\GRP-Helpdesk"
    dsacls $userOU /I:S /G "${who}:CA;Reset Password;user" | Out-Null
    dsacls $userOU /I:S /G "${who}:RPWP;pwdLastSet;user"   | Out-Null
    dsacls $userOU /I:S /G "${who}:RPWP;lockoutTime;user"  | Out-Null
    Write-Log "Delegated reset password / unlock on $userOU to GRP-Helpdesk"
}

# ---------- gMSA ----------
if (-not (Get-KdsRootKey)) {
    if ($PSCmdlet.ShouldProcess('KDS', 'Create KDS root key (lab: back-dated so it works immediately)')) {
        # Production: Add-KdsRootKey -EffectiveImmediately and wait 10 hours for replication.
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
        Write-Log 'Created KDS root key'
    }
}
$hostGroup = 'GRP-gMSA-App01-Hosts'
if (-not (Get-ADGroup -Filter "Name -eq '$hostGroup'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($hostGroup, 'Create gMSA host group')) {
        New-ADGroup -Name $hostGroup -GroupScope Global -GroupCategory Security -Path $svcOU `
            -Description 'Computers allowed to retrieve the gmsa-app01 password (add SRV01$ when it exists)'
    }
}
if (-not (Get-ADServiceAccount -Filter "Name -eq 'gmsa-app01'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess('gmsa-app01', 'Create gMSA')) {
        New-ADServiceAccount -Name 'gmsa-app01' -DNSHostName "gmsa-app01.$($domain.DNSRoot)" `
            -PrincipalsAllowedToRetrieveManagedPassword $hostGroup -Path $svcOU `
            -Description 'Owner: sofia.alvarez | Purpose: App01 service on SRV01'
        Write-Log 'Created gMSA gmsa-app01'
    }
}

# ---------- Traditional service accounts ----------
$svc = @(
    @{ Sam = 'svc-backup';    Desc = 'Owner: marcus.bell | Purpose: nightly file server backup | Review: quarterly'; Spn = $null;                                      NeverExpires = $false },
    @{ Sam = 'svc-sqlreport'; Desc = '';                                                                             Spn = "MSSQLSvc/srv01.$($domain.DNSRoot):1433"; NeverExpires = $true }   # deliberately bad
)
foreach ($s in $svc) {
    if (Get-ADUser -Filter "SamAccountName -eq '$($s.Sam)'" -ErrorAction SilentlyContinue) { continue }
    if ($PSCmdlet.ShouldProcess($s.Sam, 'Create service account')) {
        $params = @{
            Name = $s.Sam; SamAccountName = $s.Sam; Path = $svcOU; Enabled = $true
            AccountPassword = (ConvertTo-SecureString (New-RandomPassword 32) -AsPlainText -Force)
            PasswordNeverExpires = $s.NeverExpires; CannotChangePassword = $true
        }
        if ($s.Desc) { $params.Description = $s.Desc }
        if ($s.Spn)  { $params.ServicePrincipalNames = @($s.Spn) }
        New-ADUser @params
        Write-Log "Created service account $($s.Sam)$(if (-not $s.Desc) { ' (no owner - Phase 10 finding)' })"
    }
}

Write-Host "`nVerify:" -ForegroundColor Green
Write-Host "  Get-ADGroupMember 'Domain Admins'"
Write-Host "  Get-ADUser -Filter 'employeeNumber -like ""*""' -Properties employeeNumber | ft SamAccountName, employeeNumber"
Write-Host "  dsacls '$userOU' | Select-String Helpdesk"
Write-Host "  Get-ADServiceAccount gmsa-app01 -Properties PrincipalsAllowedToRetrieveManagedPassword"
