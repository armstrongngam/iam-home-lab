# Phase 1B: Active Directory engineering deep dive

> Status: Not started

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
"A share worked by name but failed by IP, which told me it was falling back from Kerberos to NTLM. I audited NTLM across the domain, fixed what still used it, and only then restricted it."
