# Phase 1: On-prem Active Directory

> Status: Not started

## Problem
Armstrong IAM needs a directory that every later phase syncs from: Entra ID, Okta, Linux,
and the lifecycle automation. Access has to be assigned by role, not by person, and
privileged work has to be separated from daily accounts.

## Design
- **Forest:** `corp.armstrongiam.com`, one DC (DC01, 10.10.10.10) on an isolated Hyper-V NAT network.
- **OUs:** `Corp > Users (Executive, IT, HR, Finance, Sales)`, `Disabled Users`,
  `Groups (Role, Resource)`, `Computers (Workstations, Servers)`, `Service Accounts`, `Admins (Tier0, Tier1)`.
- **AGDLP:** accounts → Global role groups (`GRP-*`) → Domain Local resource groups (`DL-*`) → permissions.
- **Tiering:** separate `adm-` accounts; Tier 0 in Domain Admins + Protected Users; Tier 1 in `GRP-IT-Admins`.
  The owner's EmployeeId is stored on each admin account, so the leaver process disables it too.
- **Least privilege:** help desk can reset passwords and unlock accounts in `OU=Users` only.
- **Passwords:** 14-character minimum, lockout at 10 (NIST SP 800-63B: length over rotation);
  admins get a fine-grained policy: 20 characters, lockout at 5.
- **Source of truth:** HR (`../data/hr.csv`). Users are created by the lifecycle script, matched on employeeID.

## Build (run order)

| Step | Where | Command |
|---|---|---|
| 1 | Laptop (admin PowerShell) | `.\00-Host-New-LabVM.ps1 -VmName DC01 -IsoPath <Server 2025 ISO> -DisableTimeSync` |
| 2 | DC01 | Install Windows Server 2025 Standard (Desktop Experience), then checkpoint "Clean OS" |
| 3 | DC01 | `.\01-Install-DC.ps1 -Stage Prep` → reboots |
| 4 | DC01 | `.\01-Install-DC.ps1 -Stage Promote` → asks for DSRM password, reboots |
| 5 | DC01 | `.\01-Install-DC.ps1 -Stage Verify`, then checkpoint "Forest created" |
| 6 | DC01 | `.\02-New-LabStructure.ps1 -WhatIf`, then without `-WhatIf` |
| 7 | DC01 | `.\03-Set-PasswordPolicies.ps1` |
| 8 | DC01 | `..\phase5-lifecycle\Invoke-LifecycleSync.ps1 -WhatIf`, then without → 50 users |
| 9 | DC01 | `.\04-New-AdminAndServiceAccounts.ps1` |
| 10 | Laptop + CLIENT01 | `.\00-Host-New-LabVM.ps1 -VmName CLIENT01 -IsoPath <Win11 ISO> -MemStartup 4GB -MemMax 4GB -EnableTpm`, install, set DNS to 10.10.10.10, join the domain |
| 11 | DC01 | GPO: restricted local admins (`DL-Workstations-LocalAdmin` → Administrators) linked to `Workstations` |

Copy the whole repo into the VM (for example `C:\Labs\iam-home-lab`) so the relative paths work.
Initial passwords go to `C:\LabSecrets\` (Administrators only). Never commit that folder.

## What broke and how I fixed it
- Symptom:
- Root cause:
- Fix:

## Verification
- `Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName`
- `(Get-ADUser -Filter "employeeID -like '*'").Count` → 50
- `Get-ADUserResultantPasswordPolicy adm-marcus.bell` → FGPP-Admins
- Sign in on CLIENT01 as a help desk user and reset a Sales user's password (works); try a Tier 1 admin (denied)

## Exam and interview mapping
- SC-300: foundation for hybrid identity (Phase 2).
- Story: "I designed the OU and group model so access is assigned by role, not by person, which makes onboarding and audits predictable."
