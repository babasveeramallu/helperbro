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

## Review identity dependencies

The audit reports several privileged groups, but group names in an inventory
are not evidence of malicious membership and the list is not a complete
privilege audit. Review direct and nested membership, delegated object rights,
replication rights, service accounts and owners against an approved baseline.
Do not remove accounts, groups or replication permissions solely because
they look unfamiliar. Review DnsAdmins and certificate-related permissions
where applicable, without assuming the presence of a group means its
associated role is installed.

Before requiring LDAP signing or channel binding, identify actual client and
scoring dependencies and inspect Directory Service events on each relevant
DC. Event 2887 summarizes unsigned binds when they occur; detailed 2889
events require the appropriate diagnostic logging. An absent event alone does
not prove all clients are compatible. See Microsoft's
[LDAP signing guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server).
Review effective Group Policy and record the original values and recovery
procedure. The role script's `-HardenDcAuth` changes several settings together;
it does not configure LDAP channel binding. Test all affected clients before
and after any approved change.

Review lockout and password policy with service and scoring owners; an
aggressive lockout can be used to deny service. MFA, managed service
accounts and privileged-access controls need a compatible deployment plan,
not an automatic conversion during scoring. Protect administrative
credentials and review sensitive event logs before forwarding or sharing them.

## If certificate services or federation exist

AD CS and AD FS are separate roles and are not implied by AD/DNS. Identify
their actual hosts, owners and dependencies before applying their guidance.
On the relevant Server host, `Get-WindowsFeature ADCS-Cert-Authority,ADFS-Federation`
can help identify locally installed roles when Server Manager is available;
it does not discover roles on other hosts.

For AD CS, review CA administration and enrollment permissions, published
templates, who can request or manage certificates, issued certificates and
the recovery plan. Do not revoke certificates or modify templates without
identifying affected services and testing recovery. See Microsoft's
[CA security and audit guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority)
and [template management guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates).

For AD FS, inventory federation servers, trusted applications, service
accounts, signing and decryption certificate protection, and logging. A
compromised federation server can put authentication and signing keys at
risk; investigate suspected compromise through the approved incident
process. Do not export keys, rotate certificates or remove files without a
recovery plan. Microsoft's [FoggyWeb analysis](https://www.microsoft.com/en-us/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor/)
describes one historical AD FS threat; lack of its indicators does not rule
out compromise. See also [AD FS security guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs).

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
