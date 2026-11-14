# AD/DNS deployment

Use the [shared preflight](README.md#shared-preflight). This guide assumes an
existing domain controller and DNS service, not a new domain installation.
The role script targets Server 2019; test it on a disposable matching DC
before using it on Server 2022. Audit runs create reports and restrict the
report directory ACL.

## Before changes

Record hostname, domain, DNS zones/forwarders, replication partners, DNS
clients, management paths and scoring checks. Confirm an approved restorable
system-state backup and recovery process; CSV exports and AD Recycle Bin are
not substitutes. Keep console access and the current admin session.

## Inspect

From an elevated x64 PowerShell at the repository root:

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,DomainRole
Get-Service DNS,Netlogon
.\windows\addns\harden-addns.ps1
.\windows\Set-PacketFirewall.ps1 -Role AD -AuditOnly
```

Read both reports before selecting changes. A domain role of 4 or 5 is a DC;
do not select `AD` on another machine. The firewall audit requires elevation.
Its additive policy preserves existing allows and explicit blocks; it is not
a strict allowlist. It must not be stacked with unrelated firewall scripts.

## Apply only after approval

Run `harden-addns.ps1` with a reviewed category and `-WhatIf` first. The
`-SecureDnsZones` category can change dynamic updates and zone transfers;
identify secondary servers and clients before using it. Authentication and
spooler changes have separate dependency risks. Do not apply every category
at once. Even with `-WhatIf`, reporting may write to the report directory.
For a firewall change, follow the timed rollback and commit sequence in
[Windows defense playbook](../../windows/DEFENSE-PLAYBOOK.md); retain console.

## Verify and recover

- Query an approved known DNS name over UDP and TCP; compare the returned
  address with the live source of truth. Also verify reverse zones if used.
- From a permitted client, exercise domain login, DNS registration, LDAP,
  Kerberos, replication and the actual management/scoring operation.
- Generate a new event and confirm ingestion if forwarding is configured.
- On failure, stop further changes. Use the tested role-specific recovery or
  firewall rollback; a DNS zone export alone is not an AD restore. Check all
  dependent clients again before closing the original admin session.
