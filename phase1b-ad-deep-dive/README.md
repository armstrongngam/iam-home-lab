# Phase 1B: Active Directory engineering deep dive

> Status: In progress — Step 1 done (DC02, two-way replication, FSMO transfer, site subnet, DNS). Next: DNS deep dive, Group Policy.

Exercises: `..\phase1-ad\05-Invoke-ADDeepDive.ps1 -Exercise Ldap | Kerberos | Ntlm | RecycleBin | Backup`

## Topics
- Second DC (DC02), replication (`repadmin`, `dcdiag`), FSMO roles, sites and subnets
- DNS: AD-integrated zones, reverse zone, conditional forwarder, scavenging, SRV records
- Group Policy: central store, security baseline, filtering, WMI filter, loopback, `gpresult`, GPO backup/restore
- LDAP and LDAPS, LDAP signing (event 2889)
- Kerberos vs NTLM: tickets, SPNs, clock skew, NTLM auditing and restriction
- Backup and restore: AD Recycle Bin, system state backup, authoritative restore runbook
- Auditing: advanced audit policy, Windows Event Forwarding to SRV01
- Security assessment: PingCastle or Purple Knight before and after
- AD build standard (deployment standard document)

## Findings and fixes
| Area | What I found | What I changed | Evidence |
|---|---|---|---|
| | | | |

## Runbooks
- [ ] Authoritative restore
- [ ] GPO restore
- [ ] Replication troubleshooting

## Interview story
"Adding a second domain controller, replication failed with RPC 1722 even though DNS and the network looked fine. Working layer by layer, I found the new DC's clock had drifted, then that the PDC emulator itself was days off and pushing bad time. After fixing time, the new DC still resolved its partner to a public IP: its empty DNS server forwarded internal names to the internet, where the domain's wildcard record answered. Pointing it at the existing DC, clearing the DNS cache, and re-registering its records gave clean two-way replication. Lesson: check time, then DNS, then connectivity."

(Planned for later in this phase: audit NTLM usage and restrict it.)


## What broke and how I fixed it

### 2026-11-14 — Adding DC02: six problems in one day
| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | Server Manager asked to configure "Certificate Services" | Installed **AD CS** instead of **AD DS** (similar names) | Removed AD CS before configuring it; installed AD DS. Lesson: never run a CA on a DC. |
| 2 | Wizard: "user name or password is incorrect" | Credential format | Used UPN format `administrator@corp.armstrongiam.com` |
| 3 | After promotion: SSPI errors, repadmin 8341 | DC02 clock 42 h behind (Hyper-V time sync off for DCs, VM had been saved) | Set the clock manually, set w32time to `domhier`, purged Kerberos tickets |
| 4 | DC02 then jumped back to Nov 8 | **DC01 (PDC emulator) was 6 days behind** and pushed its time to DC02; w32time won't auto-correct >48 h on a DC | Set DC01's clock manually, resynced with time.windows.com |
| 5 | RPC 1722 to DC01 and to itself; 8440 on ForestDnsZones | **DNS island + public wildcard:** DC02 used its own empty DNS, which forwarded `corp.armstrongiam.com` queries to the internet; the registrar's wildcard `*.armstrongiam.com` returned parking IPs | Pointed DC02 DNS at DC01 only, cleared DNS server cache; plan: remove the public wildcard |
| 6 | DC01 couldn't pull from DC02 (8452) | DC02's records/partitions not yet known to DC01 | `ipconfig /registerdns` + Netlogon restart on DC02, `repadmin /kcc`, restarted DC01 |


### 2026-11-19 — Step 1 completed
- **FSMO:** transferred the RID Master DC01 → DC02 in ADUC (GUI), verified with `netdom query fsmo`, transferred back with `Move-ADDirectoryServerOperationMasterRole`.
- **Sites:** subnet 10.10.10.0/24 → Default-First-Site-Name (`nltest /dsgetsite` confirms).
- **DNS:** DC02 now hosts the AD-integrated zones (`corp` and `_msdcs`); each DC points to its partner first, then itself.
- **Lesson:** VMs left running froze when the laptop slept → fixed both clocks (PDC first), purged Kerberos tickets. `repadmin /replsummary` showed 0 fails but a "largest delta" of 1d10h — replication was stale, not broken. Always read both columns.

**Result:** `repadmin /replsummary` → 0 / 5 fails in both directions; `dcdiag /test:Advertising` passed; SYSVOL and NETLOGON shared on DC02; test user created on DC02 appeared on DC01.

**Prevention:** shut down DC VMs cleanly (never save or pause them); start DC01 first; a new DC points DNS at an existing DC until its zones replicate; don't leave public wildcard records on a domain used internally.

### 2026-11-22 — DNS deep dive + ADMX central store
- Reverse zone 10.10.10.x: AD-integrated, secure dynamic updates; PTRs for DC01/DC02.
- Conditional forwarder aws.armstrongiam.com → 10.10.20.10 (placeholder for Phase 5B), AD-stored, replicated to DC02.
- Scavenging: zone aging 7/7 + server ScavengingInterval was 00:00:00 (never ran) → set to 7 days.
- Central store: copied PolicyDefinitions to SYSVOL (222 ADMX), verified on DC02.

### 2026-11-24 — Microsoft security baseline (Windows 11 24H2)
- Imported 8 MSFT baseline GPOs with Baseline-ADImport.ps1 (unlinked by default).
- Linked only "MSFT Windows 11 24H2 - Computer" to empty pilot OU Corp\Computers\Baseline-Test.
- Reviewed User Rights: network logon limited to Administrators/RDU; local accounts denied network + RDP logon (anti pass-the-hash); audit-log management limited to Administrators.
- Lesson: "Domain Security" GPO only applies at the domain root; group-specific password rules need FGPP.
- Next: move CLIENT01 into Baseline-Test, gpresult, confirm nothing breaks.

### 2026-11-25 — Baseline pilot on CLIENT01
- Moved CLIENT01 into Baseline-Test; gpresult confirms "MSFT Windows 11 24H2 - Computer" applied.
- Verified enforcement with secedit: SeDenyNetworkLogonRight and SeDenyRemoteInteractiveLogonRight = *S-1-5-113 (Local account) → blocks pass-the-hash with local admin accounts.

**What broke**
| Symptom | Root cause | Fix |
|---|---|---|
| gpupdate: "could not resolve computer name" + "LDAP Bind failed" | VMs idle overnight → clock skew → Kerberos failures | PDC (DC01) synced to external NTP, Hyper-V time provider disabled on DC01, DC02 follows domain hierarchy, `klist purge` on client |
| After the OU move, the WKS Local Administrators GPO no longer applied, but its group stayed in local Administrators | GPP Local Users and Groups (Update) tattoos the setting; "Remove this item when no longer applied" was off | Linked WKS Local Administrators to Baseline-Test so the pilot mirrors production |

**Lessons:** a pilot OU must have the production GPOs **plus** the change. Moving an object between OUs is a change with blast radius. Verify controls with evidence (secedit), not just gpresult.

### 2026-11-26 — GPO security filtering + MS16-072
- Created TEST - Logon Banner (computer-side logon banner), linked to Baseline-Test.
- Security filtering: removed Authenticated Users, added GRP-Baseline-Pilot (contains CLIENT01$).
- Purged computer Kerberos tickets (`klist -li 0x3e7 purge`) so CLIENT01's token picked up the new group.

| Test | Result |
|---|---|
| CLIENT01 in group, Authenticated Users removed | Applied (computer GPO reads as itself) |
| CLIENT01 removed, no Authenticated Users Read | Not Applied (Unknown Reason): computer can't read the GPO |
| Authenticated Users = Read, CLIENT01 not in group (old ticket) | Denied (Security) |
| Ticket purged, CLIENT01 back in group | Applied |

**What changed with the baseline:** UAC now prompts admins for credentials on the secure desktop (ConsentPromptBehaviorAdmin = 2).
**Lessons:** keep Authenticated Users with Read when filtering (MS16-072). Group changes need a new Kerberos ticket (reboot or klist purge). GPO permission changes must replicate to the DC the client uses (CLIENT01 used DC02).