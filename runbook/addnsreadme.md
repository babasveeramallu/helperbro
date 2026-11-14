# Windows AD/DNS runbook

[All machines](README.md) | [AD service guide](../docs/services/ad-dns.md)

## 1. Role, defaults and stop conditions

The documented packet default is **Windows Server 2022 / `172.20.240.100`**.
Verify that this is the live domain controller, not a member server. Record its
actual hostname/FQDN, domain/forest, DNS zones/forwarders, replication partners,
time source, service accounts and scoring credentials through approved channels.
The source AD/DNS role script targets **Server 2019**; test compatibility on a
matching noncompetition 2022 DC before applying it.

The supplied scoreboard confirms **`ad-dns`, `ad-ping`, `ad-winrm`**.
Verify the DNS answer and WinRM transaction in the portal, not just listeners.
Usual endpoints are DNS TCP/UDP 53, ICMP echo and packet WinRM TCP 5985
(5986 only if configured); the screenshot itself does not show ports/accounts.

Keep domain login, DNS, Kerberos, LDAP, SYSVOL/SMB, replication, required time
service, scored authenticated WinRM and ping working. Do not equate opening
5985 with a working WinRM login. Do not rename accounts or reset `krbtgt` as an
ordinary first-hour step. A member host is not an acceptable substitute DC.

Use an approved restorable AD/system-state recovery procedure. A CSV export,
DNS export, registry baseline or AD Recycle Bin is not a full DC backup.
The packet does not promise event-time snapshots or scrubbing.

## 2. First audit on the DC

Use elevated **x64** PowerShell at the repository root:

```powershell
[Environment]::Is64BitProcess
$PSVersionTable.PSVersion
hostname
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name,Domain,DomainRole
Get-NetIPConfiguration
Get-Service DNS,Netlogon,NTDS,WinRM
Get-Date
.\windows\first-hour.ps1
.\windows\addns\harden-addns.ps1
.\windows\Set-PacketFirewall.ps1 -Role AD -AuditOnly
```

`DomainRole` 4 or 5 indicates a DC. A returned error or missing module is a gap,
not proof that the service is absent or healthy. The first two toolkit audits
write protected reports/baselines; the packet-firewall audit creates no run/task.

With the required RSAT modules and rights, inspect the real domain/DNS state:

```powershell
Get-ADDomain
Get-ADDefaultDomainPasswordPolicy
Get-DnsServerZone
Get-DnsServerForwarder
repadmin.exe /replsummary
```

Review errors and replication age before touching authentication. Do not delete
an unfamiliar privileged account, service principal, DNS record or GPO without
establishing ownership and preserving evidence.

## 3. Script behavior and selection

| Tool | What it does on this machine |
|---|---|
| [first-hour.ps1](../windows/first-hour.ps1) | Common host/account/service/task/startup/WMI baseline; optional selected policy, firewall, protocol, USB, signing, Spooler and Sysmon work |
| [harden-addns.ps1](../windows/addns/harden-addns.ps1) | Audit domain/forest, privileged groups, risky account attributes, GPO metadata, SYSVOL scripts, DNS zones, LDAP/Netlogon settings and Spooler |
| [Set-WindowsForwarder.ps1](../splunk/Set-WindowsForwarder.ps1) | AD event forwarding to the verified receiver; no AD/WinRM/firewall policy change |
| [Set-PacketFirewall.ps1](../windows/Set-PacketFirewall.ps1) | Additive dependency rules and profile defaults with independent rollback |
| [harden-ad.ps1](../windows/lib/harden-ad.ps1) | Separate standalone LDAP/Kerberos hardener, **not an alias** of the role script |
| [auto-harden.ps1](../windows/auto-harden.ps1) | Broad multi-category wrapper; not the normal DC procedure here |

Most library files define helpers; do not execute them directly. The five
[standalone exceptions](README.md#5-shared-script-map) apply by default unless
`-AuditOnly` is supplied. The separate local-password helper refuses DCs; local
rotation is not a domain-account recovery plan.

## 4. Establish forwarding before hardening

The Debian operator must first verify the existing receiver and required indexes.
The following are **packet defaults only**; replace them after live verification:

```powershell
$Indexer = '172.20.240.20'
$Port = 9997
.\splunk\Set-WindowsForwarder.ps1 -Role AD -Indexer $Indexer -Port $Port -AuditOnly
```

Audit does not install UF. If missing, stage an approved, vendor-signed x64 MSI
and follow the [interactive installation procedure](../splunk/PLAYBOOK.md#5-windows-forwarder-procedure).
Use a unique UF-local administrator credential, not domain/scoring credentials;
verify its service identity can read Security and Directory Service.

**APPLY after transport and installation approval:**

```powershell
.\splunk\Set-WindowsForwarder.ps1 -Role AD -Indexer $Indexer -Port $Port -AllowPlaintext
```

This configures `ccdc_windows_forwarder/local/{inputs,outputs,props}.conf`, enables
selected existing disabled source channels, sets UF startup to Automatic, and
starts/restarts **only SplunkForwarder** as needed. Backups and `run.json` default
to `%ProgramData%\CCDC\Splunk\forwarder-...`.

All roles select Security/System/Application plus available PowerShell, task,
WMI, Defender, RDP and installed Sysmon channels. AD adds Directory Service and
available DNS Server/DFS Replication. Missing required channels fail the run;
optional channels warn. It does not install Sysmon or enable comprehensive source
audit policy. Collection is live-event-only while UF runs, not old history.
Plaintext requires explicit approval; TLS is not configured by this switch.

Generate one harmless new verification event, an intentional test write:

```powershell
$Marker = "CCDC-AD-$env:COMPUTERNAME-$([guid]::NewGuid().ToString('N'))"
eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /SO CCDC-Forwarder-Test /D $Marker
if ($LASTEXITCODE -ne 0) { throw 'Verification event creation failed.' }
$Marker
```

Find that exact marker in `index=wineventlog sourcetype=XmlWinEventLog*`
with `earliest=-10m latest=now`, tied to this actual hostname. Use the
[central verification queries](splunkreadme.md#7-verification-three-independent-levels).

## 5. Optional AD/DNS hardening: one category per change

The role script needs **`-Apply` plus the category** to write policy. Without
`-Apply`, selected categories describe a plan but still write reports.
Record original settings and compatible clients before approval.

| Category | Actual changes | What can break |
|---|---|---|
| `-SecureDnsZones` | Secure updates for eligible AD-integrated primary zones; replaces transfer-to-any behavior with approved secondaries or disables transfers if none supplied | Non-domain DNS registration, legitimate secondaries and applications depending on those records |
| `-AllowedZoneTransferServer` | Array of approved secondary IPs used with secure-zone work | Wrong/omitted values can prevent legitimate transfers |
| `-HardenDcAuth` | LDAP signing required, Netlogon secure-channel enforcement, anonymous restriction and NTLM compatibility level 5 | Unsigned LDAP, legacy authentication and older clients/scoring |
| `-DisableSpooler` | Stop Spooler and set startup Disabled | Printing or an unexpected workflow depending on Spooler |
| `-EnableAuditPolicy` | Back up advanced audit policy; enable selected success/failure categories including directory/Kerberos; include process command lines | Log volume and sensitive command-line collection |
| `-ReportDirectory` | Protected report/baseline destination | Must be trusted, writable and kept private |

Example: preview audit-policy work without changing it:

```powershell
.\windows\addns\harden-addns.ps1 -EnableAuditPolicy
```

**APPLY only after reviewing volume, backup and downstream permissions:**

```powershell
.\windows\addns\harden-addns.ps1 -Apply -EnableAuditPolicy
```

That selection does not also secure zones or enforce LDAP. Do not append every
category because it is available. `-WhatIf` can preview supported writes but
still performs discovery/reporting and can create audit-policy backup artifacts.

### Domain password policy is a domain-wide decision

```powershell
.\windows\first-hour.ps1 -PlanOnly -SetAccountPolicy -SkipRestorePoint
```

Without `-PlanOnly`, selecting `-SetAccountPolicy` applies the default **domain**
policy on domain-joined hosts with RSAT: minimum length 8, complexity and history
5. It preserves current maximum age and lockout unless separately selected.
`-MaxPasswordAgeDays` can expire older credentials; `-EnableAccountLockout` can
let deliberate failures deny service to scored/service accounts. These require
explicit review, not routine first-hour enablement. Record existing domain
policy yourself; this is not a full domain-policy backup/automatic transaction.

The standalone `harden-ad.ps1` also changes LDAP channel binding and the Kerberos
encryption mask. Its optional double `krbtgt` reset invalidates tickets and needs
deliberate incident-response timing/replication planning. It is not a general
quick fix and is not included in this run sequence.

## 6. Packet firewall: audit, apply, externally verify, commit

Do not combine this with the first-hour firewall or standalone legacy firewall.
Use console access and coordinate edits to profile fields during the pending run.

```powershell
$Plan = .\windows\Set-PacketFirewall.ps1 -Role AD -Indexer $Indexer -IndexerPort $Port -AuditOnly
$Plan.Plan | Format-Table Direction,Protocol,Port,Remote -AutoSize
$Plan.ExistingExplicitBlocks | Format-List
$Plan.UnplannedListeners | Format-Table -AutoSize
```

The AD plan intentionally includes standard DNS/Kerberos/LDAP/SMB/replication,
WinRM and dynamic RPC TCP 49152-65535 dependencies, not just scoring port 5985.
It preserves existing rules, permits required ICMP and DHCP, enables all profiles
with inbound Block/outbound Allow, and adds Splunk egress to the selected IP.
It refuses active explicit blocks or policy disabling required local rule
merging. Do not delete legitimate blocks just to pass that guard.

**APPLY after approval**; `-Indexer` here requires a literal IP:

```powershell
.\windows\Set-PacketFirewall.ps1 -Role AD -Indexer $Indexer -IndexerPort $Port -RollbackMinutes 10
```

Record the printed run path/deadline. Before that deadline, a teammate must
verify DNS, domain login, replication, authenticated scored WinRM, existing admin
access, ping and a fresh Splunk event from the required network.

Only when those checks pass, use the actual printed run path:

```powershell
$Run = 'C:\ProgramData\CCDC\Firewall\run-REPLACE_ACTUAL_RUN_ID'
& "$Run\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $Run -Action Commit -ScoringVerified
```

On failure instead:

```powershell
& "$Run\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $Run -Action Revert
```

The SYSTEM watchdog attempts recovery at the deadline if not committed.
Run-specific rollback removes only its own rules and restores supported changed
local profile fields. Concurrent conflicts and original `NotConfigured` fields
can leave recovery incomplete and Pending; keep console access and investigate.
Older saved runs can still perform whole-policy imports.
Read [recovery limits](../windows/DEFENSE-PLAYBOOK.md#6-firewall-apply-verify-then-commit).
Existing broad/GPO rules remain; this is not a strict allowlist.

## 7. Functional validation and recovery

From an authorized domain client, use actual names and known expected records:

```powershell
$DcName = 'REPLACE_ACTUAL_DC_FQDN'
$DomainName = 'REPLACE_ACTUAL_DOMAIN_FQDN'
Resolve-DnsName -Name $DomainName -Server $DcName
Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -Server $DcName
Resolve-DnsName -Name $DomainName -Server $DcName -TcpOnly
Test-WSMan -ComputerName $DcName -Authentication Kerberos -Credential (Get-Credential)
```

Use an approved test identity interactively. Confirm DNS answers and actual
required WinRM command execution, not just the WSMan response. Do not weaken
TrustedHosts, certificate checks or domain authentication to hide a failure.
Recheck representative domain logins and replication after auth/DNS changes.

Role-script changes are not covered by the packet firewall timer. Audit policy
has an `auditpol-before-...csv` backup; restoring it does not restore separately
changed registry values such as process command-line inclusion. Capture original
registry existence/type/value and DNS update/transfer settings before edits.
Restore only the approved changed settings; do not guess permissive defaults.

UF recovery restores only its managed app/channel/service state, not the domain.
A failed domain operation needs the AD owner and tested component/system-state
recovery, not an arbitrary firewall snapshot import.

## 8. Handoff

- [ ] DC identity, DNS/replication baseline and backup/recovery owner recorded.
- [ ] Real domain login, DNS, WinRM and scoring still work.
- [ ] New AD marker searchable; Directory Service/Security coverage checked.
- [ ] Any DNS/auth/audit change and original value documented.
- [ ] Firewall run deliberately committed or verified reverted; unresolved Pending states escalated.
- [ ] No credential or sensitive directory export committed to the repository.
