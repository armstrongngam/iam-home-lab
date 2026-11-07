# IAM Home Lab — Armstrong IAM

A hands-on identity and access management lab covering the full identity lifecycle across
**Active Directory, Microsoft Entra ID, Okta, Intune, AWS, and Linux**, plus **non-human
identities, PAM, and identity threat detection**.

**Armstrong IAM** (`corp.armstrongiam.com`, users sign in as `first.last@armstrongiam.com`) is a fictional
50-person IT consultancy built for this lab. Every phase builds on it. All people in it are fictional.

```
HR file (data/hr.csv)
      │  joiner / mover / leaver (phase5-lifecycle)
      ▼
Active Directory (DC01, DC02) ── Cloud Sync ──► Microsoft Entra ID ──► Intune (device trust)
      │        │                                    │      ▲
      │        └─ forest trust ── AWS Managed AD    │      │ federation
      │ Okta AD Agent                               ▼      │
      ▼                                                    │
    Okta ─────────────── SSO (SAML / OIDC) + SCIM ──────► Apps
      │
      ├── Linux servers (SSSD, sudo by AD group)
      └── Jump host (Guacamole + Vault) ──► isolated OT segment

Sign-in and DC security logs ──► Microsoft Sentinel (detections, incident response)
```

## Phases

| Phase | Folder | Topic | Status |
|---|---|---|---|
| 1 | [phase1-ad](phase1-ad/) | On-prem Active Directory, tiering, AGDLP | Complete |
| 1B | [phase1b-ad-deep-dive](phase1b-ad-deep-dive/) | Replication, DNS, GPO, LDAP, Kerberos/NTLM, backup and restore | Not started |
| 2 | [phase2-hybrid-entra](phase2-hybrid-entra/) | Entra Cloud Sync, hybrid join, dynamic groups | Not started |
| 2B | [phase2b-aws-ad](phase2b-aws-ad/) | AWS Managed Microsoft AD, AD on EC2, forest trust | Not started |
| 3 | [phase3-okta](phase3-okta/) | Okta + AD agent, delegated auth, group rules | Not started |
| 4 | [phase4-sso](phase4-sso/) | SAML, OIDC, Entra–Okta federation, break and fix | Not started |
| 5 | [phase5-lifecycle](phase5-lifecycle/) | Joiner-mover-leaver, Graph, Okta API, SCIM | Not started |
| 6 | [phase6-access](phase6-access/) | MFA, Conditional Access, passwordless | Not started |
| 7 | [phase7-intune](phase7-intune/) | Compliance, app protection, Autopilot, LAPS | Not started |
| 8 | [phase8-governance](phase8-governance/) | PIM, access reviews, access requests, separation of duties | Not started |
| 9 | [phase9-linux](phase9-linux/) | Linux AD join, sudo by AD group, SSH | Not started |
| 10 | [phase10-nhi-pam](phase10-nhi-pam/) | Service accounts, secrets, certificates, Vault, PAM | Not started |
| 11 | [phase11-itdr](phase11-itdr/) | Sentinel detections and identity incident response | Not started |
| 12 | [phase12-ot-pam](phase12-ot-pam/) | Privileged remote access into an isolated OT network | Not started |
| 13 | [phase13-iac](phase13-iac/) | Identity as code with Terraform (bonus) | Not started |

## Lab machines (16 GB laptop — only the VMs a phase needs run at once)

| VM | OS | Role | RAM | Phases |
|---|---|---|---|---|
| DC01 | Windows Server 2025 (eval) | Domain controller, DNS | 2–3 GB | All |
| DC02 | Windows Server 2025 (eval) | Second DC | 2 GB | 1B |
| SRV01 | Windows Server 2025 (eval) | Cloud Sync agent, Okta AD Agent, event collector | 2–3 GB | 2–8 |
| CLIENT01 | Windows 11 Enterprise (eval) | Domain + hybrid joined client | 4 GB | 1–8 |
| LNX01 / LNX02 | Rocky Linux 9 / Ubuntu 24.04 | AD-joined Linux servers | 1–1.5 GB each | 9, 13 |
| PAM01 | Linux + Docker | Vault, Guacamole jump host | 2–3 GB | 10, 12 |

Network: Hyper-V internal switch `IAMLab-Switch` + NAT (`10.10.10.0/24`, gateway `10.10.10.1`), dedicated to this lab; DC01 = `10.10.10.10`; every lab VM uses DC01 for DNS.

## Data handling
All people and data are fictional. No real passwords, tenant IDs, client secrets, API tokens,
or Terraform state are stored in this repo (see `.gitignore`).
