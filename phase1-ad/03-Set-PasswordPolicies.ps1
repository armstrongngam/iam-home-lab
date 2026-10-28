<#
.SYNOPSIS
    Armstrong IAM lab - Phase 1: domain password/lockout policy and a stricter
    fine-grained password policy (FGPP) for admin accounts.

.DESCRIPTION
    Run on DC01 (elevated) after 02-New-LabStructure.ps1.

    Design choices (be ready to defend these in an interview):
    - Long minimum length (14) and no forced periodic expiry for users, following
      NIST SP 800-63B: length beats rotation; change on suspected compromise.
      (Many audits still expect expiry - set -MaxPasswordAgeDays if yours does.)
    - Lockout threshold 10: slows password spraying without making lockouts a
      denial-of-service tool.
    - Admins get a separate FGPP: 20 characters, lockout at 5, 180-day max age.
      FGPPs apply to users or GLOBAL groups, never to OUs.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$MinLength          = 14,
    [int]$History            = 24,
    [int]$MaxPasswordAgeDays = 0,      # 0 = never expires
    [int]$LockoutThreshold   = 10,
    [int]$LockoutMinutes     = 15,
    [string]$AdminGroup      = 'GRP-IT-Admins',
    [string]$LogPath         = 'C:\LabLogs\Phase1-Policies.log'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force -WhatIf:$false | Out-Null
function Write-Log([string]$m) { $l = '{0:u} [{1}] {2}' -f (Get-Date), $env:USERNAME, $m; Add-Content $LogPath $l -WhatIf:$false; Write-Host $l }

$domain = Get-ADDomain

# ---------- Default domain policy (applies to everyone) ----------
$maxAge = if ($MaxPasswordAgeDays -gt 0) { New-TimeSpan -Days $MaxPasswordAgeDays } else { New-TimeSpan -Days 0 }
if ($PSCmdlet.ShouldProcess($domain.DNSRoot, 'Set default domain password policy')) {
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
        -MinPasswordLength $MinLength `
        -PasswordHistoryCount $History `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -MaxPasswordAge $maxAge `
        -LockoutThreshold $LockoutThreshold `
        -LockoutDuration (New-TimeSpan -Minutes $LockoutMinutes) `
        -LockoutObservationWindow (New-TimeSpan -Minutes $LockoutMinutes)
    Write-Log "Default policy: min $MinLength, history $History, lockout $LockoutThreshold/$LockoutMinutes min, max age $MaxPasswordAgeDays days"
}

# ---------- Fine-grained password policy for admins ----------
$fgppName = 'FGPP-Admins'
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$fgppName'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($fgppName, 'Create fine-grained password policy')) {
        New-ADFineGrainedPasswordPolicy -Name $fgppName -Precedence 10 `
            -MinPasswordLength 20 -PasswordHistoryCount 24 -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false `
            -MinPasswordAge (New-TimeSpan -Days 1) -MaxPasswordAge (New-TimeSpan -Days 180) `
            -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) `
            -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
            -ProtectedFromAccidentalDeletion $true
        Write-Log "Created $fgppName (min 20, lockout 5/30 min, max age 180 days)"
    }
}
foreach ($subject in @($AdminGroup, 'Domain Admins')) {
    if ($PSCmdlet.ShouldProcess($subject, "Apply $fgppName")) {
        $applied = (Get-ADFineGrainedPasswordPolicy $fgppName).AppliesTo
        $dn = (Get-ADGroup $subject).DistinguishedName
        if ($applied -notcontains $dn) {
            Add-ADFineGrainedPasswordPolicySubject -Identity $fgppName -Subjects $subject
            Write-Log "Applied $fgppName to $subject"
        }
    }
}

Write-Host "`nVerify:" -ForegroundColor Green
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, LockoutThreshold
Get-ADFineGrainedPasswordPolicy $fgppName | Format-List Name, MinPasswordLength, LockoutThreshold, AppliesTo
Write-Host "Check the policy an account actually gets: Get-ADUserResultantPasswordPolicy <user>"
