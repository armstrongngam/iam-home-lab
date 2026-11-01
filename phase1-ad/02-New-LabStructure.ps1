<#
.SYNOPSIS
    Armstrong IAM lab - Phase 1: OU structure and AGDLP group model.

.DESCRIPTION
    Run on DC01 (elevated) after 01-Install-DC.ps1 -Stage Verify passes.
    Safe to re-run: existing OUs and groups are skipped, not duplicated.

    OU design
      Corp
        Users          Executive, IT, HR, Finance, Sales   (people, one OU per department)
        Disabled Users                                     (leavers land here)
        Groups         Role, Resource                      (AGDLP: role = Global, resource = Domain Local)
        Computers      Workstations, Servers
        Service Accounts                                   (kept out of cloud sync)
        Admins         Tier0, Tier1                        (adm- accounts, never daily-use)

    AGDLP
      Accounts -> Global role groups (GRP-*) -> Domain Local resource groups (DL-*) -> Permissions
      Access is granted to a role, not a person, so onboarding and audits stay predictable.

.EXAMPLE
    .\02-New-LabStructure.ps1 -WhatIf     # preview
    .\02-New-LabStructure.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Departments = @('Executive', 'IT', 'HR', 'Finance', 'Sales'),
    [string]  $UpnSuffix   = 'armstrongiam.com',   # public domain you own; users sign in as first.last@armstrongiam.com
    [string]  $LogPath     = 'C:\LabLogs\Phase1-Structure.log'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force -WhatIf:$false | Out-Null

$domainDN = (Get-ADDomain).DistinguishedName

function Write-Log([string]$Message) {
    $line = '{0:u} [{1}] {2}' -f (Get-Date), $env:USERNAME, $Message
    Add-Content -Path $LogPath -Value $line -WhatIf:$false
    Write-Host $line
}

function New-LabOU([string]$Name, [string]$Path) {
    $dn = "OU=$Name,$Path"
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue) {
        Write-Verbose "OU exists: $dn"
    } elseif ($PSCmdlet.ShouldProcess($dn, 'Create OU')) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
        Write-Log "Created OU $dn"
    }
    return $dn
}

function New-LabGroup([string]$Name, [string]$Scope, [string]$Path, [string]$Description) {
    if (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Verbose "Group exists: $Name"
    } elseif ($PSCmdlet.ShouldProcess($Name, "Create $Scope security group")) {
        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope $Scope -GroupCategory Security `
                    -Path $Path -Description $Description
        Write-Log "Created $Scope group $Name"
    }
}

function Add-LabNesting([string]$Member, [string]$Parent) {
    if ($WhatIfPreference) { Write-Host "What if: nest $Member in $Parent"; return }
    $already = Get-ADGroupMember -Identity $Parent | Where-Object Name -eq $Member
    if (-not $already) {
        Add-ADGroupMember -Identity $Parent -Members $Member
        Write-Log "Nested $Member -> $Parent"
    }
}

# ---------- OUs ----------
$corp      = New-LabOU 'Corp'             $domainDN
$users     = New-LabOU 'Users'            $corp
foreach ($d in $Departments) { New-LabOU $d $users | Out-Null }
New-LabOU 'Disabled Users'   $corp | Out-Null
$groups    = New-LabOU 'Groups'           $corp
$roleOU    = New-LabOU 'Role'             $groups
$resOU     = New-LabOU 'Resource'         $groups
$computers = New-LabOU 'Computers'        $corp
$wksOU     = New-LabOU 'Workstations'     $computers
New-LabOU 'Servers'          $computers | Out-Null
New-LabOU 'Service Accounts' $corp | Out-Null
$admins    = New-LabOU 'Admins'           $corp
New-LabOU 'Tier0'            $admins | Out-Null
New-LabOU 'Tier1'            $admins | Out-Null

# ---------- Role groups (Global) ----------
foreach ($d in $Departments) {
    New-LabGroup "GRP-$d-Users" Global $roleOU "Everyone in the $d department (maintained by lifecycle sync)"
}
$roleGroups = @{
    'GRP-IT-Admins'                 = 'Tier 1 server and directory admins (adm- accounts only)'
    'GRP-Helpdesk'                  = 'Help desk staff - password resets and unlocks on user OUs'
    'GRP-Workstation-Admins'        = 'Accounts allowed local admin on workstations (adm- accounts only)'
    'GRP-Cloud-Sync'                = 'Scope for Entra Cloud Sync - only members are synced to the cloud'
    'GRP-Linux-Users'               = 'Allowed to sign in to Linux servers (Phase 9)'
    'GRP-Linux-Admins'              = 'Sudo on Linux servers (Phase 9)'
    'GRP-Finance-VendorCreators'    = 'Can create vendors - separation of duties with PaymentApprovers (Phase 8)'
    'GRP-Finance-PaymentApprovers'  = 'Can approve payments - separation of duties with VendorCreators (Phase 8)'
}
foreach ($g in $roleGroups.GetEnumerator()) { New-LabGroup $g.Key Global $roleOU $g.Value }

# ---------- Resource groups (Domain Local) ----------
$resGroups = @{
    'DL-FinanceShare-Read'      = 'Read on \\SRV01\Finance'
    'DL-FinanceShare-Modify'    = 'Modify on \\SRV01\Finance'
    'DL-HRShare-Modify'         = 'Modify on \\SRV01\HR'
    'DL-ITShare-Modify'         = 'Modify on \\SRV01\IT'
    'DL-Workstations-LocalAdmin'= 'Local Administrators on workstations (applied by GPO or Intune)'
}
foreach ($g in $resGroups.GetEnumerator()) { New-LabGroup $g.Key DomainLocal $resOU $g.Value }

# ---------- AGDLP nesting: role -> resource ----------
Add-LabNesting 'GRP-Finance-Users'      'DL-FinanceShare-Modify'
Add-LabNesting 'GRP-Executive-Users'    'DL-FinanceShare-Read'
Add-LabNesting 'GRP-HR-Users'           'DL-HRShare-Modify'
Add-LabNesting 'GRP-IT-Users'           'DL-ITShare-Modify'
Add-LabNesting 'GRP-Workstation-Admins' 'DL-Workstations-LocalAdmin'

# ---------- UPN suffix: sign-in names match the public domain (needed for Entra ID and Okta in Phase 2-3) ----------
if ((Get-ADForest).UPNSuffixes -notcontains $UpnSuffix) {
    if ($PSCmdlet.ShouldProcess($UpnSuffix, 'Add forest UPN suffix')) {
        Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{ Add = $UpnSuffix }
        Write-Log "Added UPN suffix $UpnSuffix"
    }
}

# ---------- New computers land in Workstations, not the default Computers container ----------
if ($PSCmdlet.ShouldProcess($wksOU, 'Redirect default computer container')) {
    redircmp $wksOU | Out-Null
    Write-Log "Default computer container redirected to $wksOU"
}

   if (-not $WhatIfPreference) { Write-Log 'Structure complete. Next: 03-Set-PasswordPolicies.ps1' }
