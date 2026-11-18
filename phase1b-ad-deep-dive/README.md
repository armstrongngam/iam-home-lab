# Phase 1B: Active Directory engineering deep dive

> Status: In progress — DC02 promoted (GUI wizard), two-way replication healthy. Next: FSMO, sites, DNS.

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

**Result:** `repadmin /replsummary` → 0 / 5 fails in both directions; `dcdiag /test:Advertising` passed; SYSVOL and NETLOGON shared on DC02; test user created on DC02 appeared on DC01.

**Prevention:** shut down DC VMs cleanly (never save or pause them); start DC01 first; a new DC points DNS at an existing DC until its zones replicate; don't leave public wildcard records on a domain used internally.
