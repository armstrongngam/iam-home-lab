<#
.SYNOPSIS
    Armstrong IAM lab - joiner / mover / leaver sync from the HR file to Active Directory.

.DESCRIPTION
    HR (data\hr.csv) is the source of truth. Each run compares HR with AD and:
      JOINER  new EmployeeId          -> create account in the department OU, birthright groups,
                                         random first password (must change at sign-in).
                                         Future start date -> created DISABLED (pre-provisioned),
                                         enabled automatically on a run on/after the start date.
      MOVER   department changed      -> move OU, swap department group, update attributes.
                                         Other (requested) groups are NOT removed automatically;
                                         they are flagged in the audit log for an access review.
      UPDATE  title / cost center / manager changed -> update attributes.
      LEAVER  Status=Terminated or EndDate reached -> disable, scramble password, remove all
                                         groups, move to Disabled Users. (Phase 5 adds Entra
                                         session revocation and Okta deactivation.)
      ORPHAN  in AD with an employeeID but not in HR -> reported only, never deleted.

    Matching is on employeeID, never on name: names change and repeat, IDs don't.
    Every action is written to an audit CSV (who, what, when, result).

    Phase 1 uses this script to load the 50 starting users. Phase 5 extends it.

.EXAMPLE
    .\Invoke-LifecycleSync.ps1 -WhatIf      # preview every change, touch nothing
    .\Invoke-LifecycleSync.ps1              # apply

.NOTES
    Initial passwords are written to C:\LabSecrets (Administrators-only ACL) for the lab.
    In production you would use a Temporary Access Pass or self-service onboarding instead.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$HrFile         = (Join-Path $PSScriptRoot '..\data\hr.csv'),
    [string]$UpnSuffix      = 'armstrongiam.com',
    [string]$Company        = 'Armstrong IAM',
    [string]$CloudSyncGroup = 'GRP-Cloud-Sync',
    [string]$AuditLog       = 'C:\LabLogs\lifecycle-audit.csv',
    [string]$PasswordFile   = 'C:\LabSecrets\initial-passwords.csv'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domainDN    = (Get-ADDomain).DistinguishedName
$usersOU     = "OU=Users,OU=Corp,$domainDN"
$disabledOU  = "OU=Disabled Users,OU=Corp,$domainDN"
$corpOU      = "OU=Corp,$domainDN"
$today       = (Get-Date).Date
$operator    = "$env:USERDOMAIN\$env:USERNAME"
$stats       = @{ Joiner = 0; Mover = 0; Update = 0; Leaver = 0; Enabled = 0; Orphan = 0; Error = 0 }

foreach ($p in @($AuditLog, $PasswordFile)) { New-Item -ItemType Directory -Path (Split-Path $p) -Force -WhatIf:$false | Out-Null }

# Lock the secrets folder to Administrators + SYSTEM
if (-not $WhatIfPreference) {
    $secretsDir = Split-Path $PasswordFile
    icacls $secretsDir /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
}

# ---------------- helpers ----------------
function Write-Audit([string]$Action, [string]$EmployeeId, [string]$Sam, [string]$Detail, [string]$Result) {
    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s'); Operator = $operator; Action = $Action
        EmployeeId = $EmployeeId; SamAccountName = $Sam; Detail = $Detail; Result = $Result
    } | Export-Csv -Path $AuditLog -Append -NoTypeInformation -WhatIf:$false
    $color = switch ($Result) { 'Error' { 'Red' } 'WhatIf' { 'DarkGray' } default { 'Gray' } }
    Write-Host ("{0,-8} {1,-6} {2,-22} {3}" -f $Action, $EmployeeId, $Sam, $Detail) -ForegroundColor $color
}

function New-RandomPassword([int]$Length = 20) {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%*-_=+?')
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $pick = {
        param($chars)
        $b = New-Object byte[] 4; $rng.GetBytes($b)
        $chars[[BitConverter]::ToUInt32($b, 0) % $chars.Length]
    }
    $all = -join $sets
    $chars = @(); foreach ($s in $sets) { $chars += & $pick $s }          # one from each set
    while ($chars.Count -lt $Length) { $chars += & $pick $all }
    -join ($chars | Sort-Object { Get-Random })
}

function Get-UniqueSam([string]$First, [string]$Last) {
    $base = (($First + '.' + $Last).ToLower() -replace '[^a-z0-9.]', '')
    if ($base.Length -gt 20) { $base = $base.Substring(0, 20) }
    $sam = $base; $n = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        $n++; $suffix = "$n"
        $sam = $base.Substring(0, [math]::Min($base.Length, 20 - $suffix.Length)) + $suffix
    }
    $sam
}

function Test-IsLeaver($row) {
    if ($row.Status -eq 'Terminated') { return $true }
    if ($row.EndDate -and ([datetime]$row.EndDate).Date -le $today) { return $true }
    $false
}

function Invoke-CloudLeaverHooks($user, $row) {
    # Phase 5 adds:
    #   Microsoft Graph: Revoke-MgUserSignInSession -UserId <upn>
    #   Okta API:        POST /api/v1/users/{id}/lifecycle/deactivate
    Write-Verbose "Cloud leaver hooks not configured yet for $($user.SamAccountName) (Phase 5)."
}

# ---------------- load and validate HR ----------------
if (-not (Test-Path $HrFile)) { throw "HR file not found: $HrFile" }
$hr = @(Import-Csv $HrFile)
$required = 'EmployeeId','FirstName','LastName','Department','Title','ManagerId','CostCenter','StartDate','EndDate','Status'
$missing = $required | Where-Object { $hr[0].PSObject.Properties.Name -notcontains $_ }
if ($missing) { throw "HR file is missing columns: $($missing -join ', ')" }
$dupes = $hr | Group-Object EmployeeId | Where-Object Count -gt 1
if ($dupes) { throw "Duplicate EmployeeId in HR file: $($dupes.Name -join ', ')" }

$props = 'employeeID','department','title','division','manager','company','memberOf','Enabled','GivenName','Surname'
$adUsers = @{}
Get-ADUser -Filter "employeeID -like '*'" -SearchBase $corpOU -Properties $props |
    ForEach-Object { $adUsers[$_.employeeID] = $_ }

Write-Host "HR rows: $($hr.Count)   AD users with employeeID: $($adUsers.Count)`n" -ForegroundColor Cyan

# ---------------- pass 1: joiners, movers, updates, leavers ----------------
foreach ($row in $hr) {
    $id = $row.EmployeeId
    try {
        $user     = $adUsers[$id]
        $isLeaver = Test-IsLeaver $row
        $deptOU   = "OU=$($row.Department),$usersOU"
        $deptGrp  = "GRP-$($row.Department)-Users"
        $started  = ([datetime]$row.StartDate).Date -le $today

        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$deptOU'" -ErrorAction SilentlyContinue)) {
            throw "No OU for department '$($row.Department)'. Run 02-New-LabStructure.ps1 or fix the HR row."
        }

        # ---- JOINER ----
        if (-not $user) {
            if ($isLeaver) { continue }   # terminated before ever being created
            $sam  = Get-UniqueSam $row.FirstName $row.LastName
            $name = "$($row.FirstName) $($row.LastName)"
            if (Get-ADUser -Filter "Name -eq '$name'" -SearchBase $deptOU -ErrorAction SilentlyContinue) { $name = "$name ($id)" }
            $detail = "$($row.Department) / $($row.Title)" + $(if (-not $started) { ' / pre-provisioned, disabled until ' + $row.StartDate } else { '' })

            if ($PSCmdlet.ShouldProcess($sam, 'Create user (joiner)')) {
                $pw = New-RandomPassword
                New-ADUser -Name $name -SamAccountName $sam -UserPrincipalName "$sam@$UpnSuffix" `
                    -GivenName $row.FirstName -Surname $row.LastName -DisplayName "$($row.FirstName) $($row.LastName)" `
                    -EmployeeID $id -Department $row.Department -Title $row.Title -Division $row.CostCenter `
                    -Company $Company -Office $row.Office -Path $deptOU `
                    -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) `
                    -ChangePasswordAtLogon $true -Enabled $started
                Add-ADGroupMember -Identity $deptGrp -Members $sam
                Add-ADGroupMember -Identity $CloudSyncGroup -Members $sam
                [pscustomobject]@{ SamAccountName = $sam; EmployeeId = $id; InitialPassword = $pw; Created = (Get-Date).ToString('s') } |
                    Export-Csv -Path $PasswordFile -Append -NoTypeInformation
                Write-Audit 'JOINER' $id $sam $detail 'Success'
            } else { Write-Audit 'JOINER' $id $sam $detail 'WhatIf' }
            $stats.Joiner++
            continue
        }

        $sam = $user.SamAccountName

        # ---- LEAVER ----
        if ($isLeaver) {
            if (-not $user.Enabled -and $user.DistinguishedName -like "*$disabledOU") { continue }  # already processed
            $groups = @($user.memberOf | ForEach-Object { (Get-ADGroup $_).Name })
            $detail = "Disabled; removed groups: $(if ($groups) { $groups -join ';' } else { 'none' })"
            if ($PSCmdlet.ShouldProcess($sam, 'Disable and deprovision (leaver)')) {
                Disable-ADAccount -Identity $user
                Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString (New-RandomPassword 32) -AsPlainText -Force)
                foreach ($g in $user.memberOf) { Remove-ADGroupMember -Identity $g -Members $user -Confirm:$false }
                Set-ADUser -Identity $user -Description ("Leaver {0:yyyy-MM-dd} - {1}" -f $today, $id)
                Move-ADObject -Identity $user.DistinguishedName -TargetPath $disabledOU
                # Linked privileged (adm-) accounts carry the owner's ID in employeeNumber - disable them too
                Get-ADUser -Filter "employeeNumber -eq '$id'" | ForEach-Object {
                    Disable-ADAccount -Identity $_
                    Write-Audit 'LEAVER' $id $_.SamAccountName 'Linked admin account disabled' 'Success'
                }
                Invoke-CloudLeaverHooks $user $row
                Write-Audit 'LEAVER' $id $sam $detail 'Success'
            } else { Write-Audit 'LEAVER' $id $sam $detail 'WhatIf' }
            $stats.Leaver++
            continue
        }

        # ---- ENABLE pre-provisioned joiner on start date ----
        if (-not $user.Enabled -and $started -and $user.DistinguishedName -notlike "*$disabledOU") {
            if ($PSCmdlet.ShouldProcess($sam, 'Enable (start date reached)')) {
                Enable-ADAccount -Identity $user
                Write-Audit 'ENABLE' $id $sam "Start date $($row.StartDate) reached" 'Success'
            } else { Write-Audit 'ENABLE' $id $sam "Start date $($row.StartDate) reached" 'WhatIf' }
            $stats.Enabled++
        }

        # ---- MOVER ----
        if ($user.department -ne $row.Department) {
            $oldGrp = "GRP-$($user.department)-Users"
            $other  = @($user.memberOf | ForEach-Object { (Get-ADGroup $_).Name } |
                        Where-Object { $_ -ne $oldGrp -and $_ -ne $CloudSyncGroup })
            $detail = "$($user.department) -> $($row.Department)" +
                      $(if ($other) { "; REVIEW other access: $($other -join ';')" } else { '' })
            if ($PSCmdlet.ShouldProcess($sam, 'Move department (mover)')) {
                if (Get-ADGroup -Filter "Name -eq '$oldGrp'") { Remove-ADGroupMember -Identity $oldGrp -Members $user -Confirm:$false }
                Add-ADGroupMember -Identity $deptGrp -Members $user
                Set-ADUser -Identity $user -Department $row.Department
                Move-ADObject -Identity $user.DistinguishedName -TargetPath $deptOU
                Write-Audit 'MOVER' $id $sam $detail 'Success'
            } else { Write-Audit 'MOVER' $id $sam $detail 'WhatIf' }
            $stats.Mover++
        }

        # ---- ATTRIBUTE UPDATES ----
        $changes = @{}
        if ($user.title    -ne $row.Title)      { $changes.Title    = $row.Title }
        if ($user.division -ne $row.CostCenter) { $changes.Division = $row.CostCenter }
        if ($changes.Count) {
            $detail = ($changes.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
            if ($PSCmdlet.ShouldProcess($sam, 'Update attributes')) {
                Set-ADUser -Identity $sam @changes
                Write-Audit 'UPDATE' $id $sam $detail 'Success'
            } else { Write-Audit 'UPDATE' $id $sam $detail 'WhatIf' }
            $stats.Update++
        }
    }
    catch {
        $stats.Error++
        Write-Audit 'ERROR' $id '' $_.Exception.Message 'Error'
    }
}

# ---------------- pass 2: managers (after everyone exists) ----------------
if (-not $WhatIfPreference) {
    $byId = @{}
    Get-ADUser -Filter "employeeID -like '*'" -SearchBase $corpOU -Properties employeeID, manager |
        ForEach-Object { $byId[$_.employeeID] = $_ }
    foreach ($row in $hr) {
        $u = $byId[$row.EmployeeId]
        if (-not $u -or (Test-IsLeaver $row)) { continue }
        $mgr = if ($row.ManagerId) { $byId[$row.ManagerId] } else { $null }
        $want = if ($mgr) { $mgr.DistinguishedName } else { $null }
        if ($u.manager -ne $want) {
            try {
                if ($want) { Set-ADUser $u -Manager $want } else { Set-ADUser $u -Clear manager }
                Write-Audit 'UPDATE' $row.EmployeeId $u.SamAccountName "Manager=$(if ($mgr) { $mgr.SamAccountName } else { 'none' })" 'Success'
                $stats.Update++
            } catch { $stats.Error++; Write-Audit 'ERROR' $row.EmployeeId $u.SamAccountName $_.Exception.Message 'Error' }
        }
    }
}

# ---------------- orphans: in AD, not in HR ----------------
$hrIds = @{}; $hr | ForEach-Object { $hrIds[$_.EmployeeId] = $true }
foreach ($u in $adUsers.Values) {
    if (-not $hrIds.ContainsKey($u.employeeID) -and $u.Enabled) {
        Write-Audit 'ORPHAN' $u.employeeID $u.SamAccountName 'Enabled in AD but not in HR - investigate' 'Flagged'
        $stats.Orphan++
    }
}

Write-Host "`nSummary: $(($stats.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '  ')" -ForegroundColor Green
Write-Host "Audit log: $AuditLog"
if ($stats.Joiner -and -not $WhatIfPreference) { Write-Host "Initial passwords: $PasswordFile (Administrators only - never commit this file)" -ForegroundColor Yellow }
