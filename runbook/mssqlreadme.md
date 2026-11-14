# Windows MSSQL, SMB/SOP and RDP runbook

[All machines](README.md) | [SQL service guide](../docs/services/mssql.md)

## 1. Mission and live inventory

The documented packet default is **Windows Server 2019 / `172.20.240.120`**.
Confirm the live hostname/address, SQL edition/version, instance, database,
authentication mode, engine account, SQL port, required SMB share/file and RDP
identity before changing anything.

The supplied scoreboard confirms **`mssql-mssql`, `mssql-ping`, `mssql-rdp`,
`mssql-smb`**. The first is the SQL check, not a second machine. Its exact query,
credentials, instance/port, required SMB content and RDP transaction must still
come from the live scoring definition. Ping uses ICMP, not a TCP/UDP port.

This machine is not only a SQL port. Preserve all three packet functions:

| Function | Packet starting point | Actual acceptance |
|---|---|---|
| SQL | TCP 1433 | Correct instance/database login and approved read-only query |
| SMB/SOP | TCP 445 | Intended account reads the correct share and required file/content |
| RDP | TCP 3389 | A new authenticated session works while the original stays open |
| General dependencies | Required ICMP, DNS, domain/time, backup and logging paths | Verify from the actual client/scoring network |

Named SQL instances may use a different/dynamic TCP port and SQL Browser UDP
1434. Do not assume the default packet profile covers an actual custom port.
Helperbro does not install SQL, create databases, fix logins, change share
permissions or deploy the required SOP files.

## 2. Inspect before using toolkit apply

On this machine, use elevated x64 PowerShell from the repository root:

```powershell
[Environment]::Is64BitProcess
hostname
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name,Domain,PartOfDomain,DomainRole
Get-NetIPConfiguration
Get-Service 'MSSQLSERVER','MSSQL$*'
Get-CimInstance Win32_Service |
    Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' } |
    Select-Object Name,State,StartName,PathName
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess
Get-SmbShare
Get-SmbServerConfiguration |
    Select-Object EnableSMB1Protocol,RequireSecuritySignature
.\windows\first-hour.ps1
.\windows\Set-PacketFirewall.ps1 -Role MSSQL -AuditOnly
```

`Get-Service` can report a missing default instance while a named one exists;
inspect the actual matching services and errors. A service's presence does not
prove the database is online or listening. Never rotate its account password
without updating every dependency through the supported SQL/service workflow.
The host must not be a DC for the MSSQL forwarding/firewall role.

Record product-supported database backups, recovery model/log chain as needed,
share/file backup with ACLs, application configuration and approved recovery
contacts. A filesystem copy of a running database is not a validated SQL backup.

## 3. Which scripts apply

| Script | Actual behavior and limits |
|---|---|
| [first-hour.ps1](../windows/first-hour.ps1) | Common audit and selected host controls; not a SQL hardening/backup script |
| [Set-WindowsForwarder.ps1](../splunk/Set-WindowsForwarder.ps1), role `MSSQL` | Windows channels and selected SQL text ERRORLOG monitoring |
| [Set-PacketFirewall.ps1](../windows/Set-PacketFirewall.ps1), role `MSSQL` | Additive SQL/SMB/RDP dependencies with timed rollback |
| [Invoke-ServiceProbe.ps1](../windows/Invoke-ServiceProbe.ps1) | One TCP/HTTP(S)/DNS/banner check; no SQL authentication or SMB content test |
| [HostFirewall.ps1](../windows/lib/HostFirewall.ps1) | Helper invoked by first-hour; different discovered-service firewall, no independent commit timer |
| [auto-harden.ps1](../windows/auto-harden.ps1) | Broad common/role baseline; has no dedicated SQL role hardener |

A server without DC/IIS roles can receive the wrapper's workstation-baseline
fallback. That does not make it an approved SQL configuration procedure.
Do not run the wrapper to obtain forwarding.

## 4. Forward Windows and actual SQL text logs

Verify the Debian receiver first. These are **unverified packet defaults**:

```powershell
$Indexer = '172.20.240.20'
$Port = 9997
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -Indexer $Indexer -Port $Port -AuditOnly
```

Audit writes no script backup/report and does not install missing UF. Apply may
launch a staged vendor-signed x64 MSI interactively; follow
[installation and service-identity requirements](../splunk/PLAYBOOK.md#5-windows-forwarder-procedure).
The chosen service account must read Security and the SQL log files. The script
does not grant SQL file ACLs or change the service identity.

### SQL path discovery

Without `-SqlLogPath`, the script reads instance names and `SQLArg*` startup
parameters in the SQL registry and selects each `-e` ERRORLOG path.
It does not recursively scan the installation or auto-monitor binary `.xel`/
`.trc` files. No discovered file produces a warning; Windows Application events
can still be forwarded, which is not proof SQL text-log coverage is complete.

For actual nonstandard paths, use one array, not repeated parameter names:

```powershell
$SqlLogs = @(
    'C:\REPLACE_ACTUAL_SQL_LOG_DIRECTORY\ERRORLOG'
)
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -Indexer $Indexer -Port $Port -SqlLogPath $SqlLogs -AuditOnly
```

Explicit paths **replace** discovery. Each must be an existing literal rooted
file. Confirm every intended instance is included. Do not point text monitoring
at a binary audit/trace file.

**APPLY after approval**, choosing the reviewed discovered-path case:

```powershell
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -Indexer $Indexer -Port $Port -AllowPlaintext
```

If you audited explicit paths, add the same `-SqlLogPath $SqlLogs` on apply.
`-AllowPlaintext` acknowledges unencrypted internal TCP, not TLS.

### Files, services and data

- Writes only its `ccdc_windows_forwarder/local/inputs.conf`, `outputs.conf`,
  `props.conf` under the actual UF home.
- Creates protected backups and `run.json` under
  `%ProgramData%\CCDC\Splunk\forwarder-...` by default.
- Enables selected existing disabled channels, sets UF Automatic, and starts/
  restarts only **SplunkForwarder**, not SQL, SMB or RDP.
- Sends ordinary selected Windows channels to `wineventlog`, installed Sysmon
  to `sysmon`, and ERRORLOG text to `mssql` with
  `sourcetype=ccdc:mssql:errorlog`.
- Windows event inputs collect only events arriving while UF runs. SQL file
  monitoring can read existing text initially; verify rotation separately.
- Does not enable SQL Server Audit, log every query, install Sysmon or enable
  complete source audit policies. ERRORLOG is not a full SQL audit trail.

## 5. Prove both Windows and SQL receipt

Create one harmless Application event, an explicit test write:

```powershell
$Marker = "CCDC-SQLHOST-$env:COMPUTERNAME-$([guid]::NewGuid().ToString('N'))"
eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /SO CCDC-Forwarder-Test /D $Marker
if ($LASTEXITCODE -ne 0) { throw 'Verification event creation failed.' }
$Marker
```

Find the exact marker centrally under `index=wineventlog`,
`sourcetype=XmlWinEventLog*`, `earliest=-10m latest=now`. Separately search:

```spl
index=mssql sourcetype=ccdc:mssql:errorlog earliest=-15m latest=now
| stats count latest(_time) as newest by host source
| eval newest=strftime(newest,"%F %T")
```

Compare source activity, path, encoding, timestamps and multiline records.
A quiet log can have no new messages; do not restart SQL or write errors into
its live log just to make a chart green.

Useful local checks:

```powershell
$Uf = 'C:\Program Files\SplunkUniversalForwarder'
Get-Service SplunkForwarder
Test-NetConnection $Indexer -Port $Port
& "$Uf\bin\splunk.exe" btool inputs list --debug
& "$Uf\bin\splunk.exe" btool outputs list --debug
Get-Content "$Uf\var\log\splunk\splunkd.log" -Tail 100 |
    Select-String 'TcpOutputProc|WinEventLog|ERROR|WARN'
```

Adjust `$Uf` to the actual home. Keep diagnostic output private; a connected
socket or running service alone is not delivery verification.

## 6. Firewall change, only if authorized

Audit the proposed rules, active explicit blocks and unplanned listeners:

```powershell
$Plan = .\windows\Set-PacketFirewall.ps1 -Role MSSQL -Indexer $Indexer -IndexerPort $Port -AuditOnly
$Plan.Plan | Format-Table Direction,Protocol,Port,Remote -AutoSize
$Plan.ExistingExplicitBlocks | Format-List
$Plan.UnplannedListeners | Format-Table -AutoSize
```

The default plan includes TCP 139/445/1433/3389, UDP 137/138/1434 plus DHCP,
required ICMP and selected Splunk egress. It preserves existing rules; inbound
default becomes Block and outbound default Allow on all profiles.
Existing explicit blocks/GPO can still defeat local allows, and broad allows
remain broad. The script does not start SQL or enable Browser.

If a legitimate custom SQL port is required, supply verified
`-AdditionalTcpPorts` on **both audit and apply**. It accepts arrays of ports/
ranges, not service discovery or a replacement for inventory. Use a literal
receiver IP for `-Indexer` here.

**APPLY from console after approval:**

```powershell
.\windows\Set-PacketFirewall.ps1 -Role MSSQL -Indexer $Indexer -IndexerPort $Port -RollbackMinutes 10
```

Before the printed deadline, verify actual SQL, SOP share/file access, second
RDP login, ping and fresh log receipt externally. Then use the exact printed
run path:

```powershell
$Run = 'C:\ProgramData\CCDC\Firewall\run-REPLACE_ACTUAL_RUN_ID'
& "$Run\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $Run -Action Commit -ScoringVerified
```

On any failed check, use `-Action Revert` instead. Do not claim verification
merely because rule creation succeeded. The independent SYSTEM watchdog attempts
scoped recovery if uncommitted. Same-field conflicts and original local
`NotConfigured` values can prevent full profile restoration and leave Pending.
Keep the run files/task and console while investigating.
See [complete limits](../windows/DEFENSE-PLAYBOOK.md#6-firewall-apply-verify-then-commit).

Do not combine this with `-EnforceHostFirewall` or the standalone legacy firewall.
Do not use management/system scoping to narrow scored SQL/SMB/RDP to team-only
addresses. Do not disable SMB to reduce exposure on a host scored through SMB.

## 7. Authenticated business checks and risky categories

On an authorized client, if `sqlcmd` is already available and integrated
authentication is the expected path:

```powershell
$SqlHost = 'REPLACE_ACTUAL_SQL_HOST'
$SqlPort = 1433
sqlcmd.exe -S "$SqlHost,$SqlPort" -E -b -Q "SELECT @@SERVERNAME AS ServerName, DB_NAME() AS DatabaseName;"
if ($LASTEXITCODE -ne 0) { throw 'SQL login/query verification failed.' }
```

Use the required database and approved read-only query for real acceptance.
If SQL authentication is required, use an approved interactive client;
do not place `-P PASSWORD` or connection-string secrets in the command line.
Investigate certificate failures rather than disabling encryption/trust checks.

Using the intended account, open the real SMB share and verify the required
SOP file/content or trusted expected hash without modifying it. A list of shares
or TCP 445 connection does not establish read permissions/content. Open a second
authenticated RDP session and retain the original one.

| Optional first-hour selection | Why it needs service-owner review |
|---|---|
| `-SetAccountPolicy` | On a domain member, changes **domain** password policy with RSAT, not SQL login policy |
| `-EnableAccountLockout`, `-MaxPasswordAgeDays` | Can lock/expire scoring or service identities; not on by default |
| `-DisableLegacyProtocols`, `-RequireSmbSigning` | Legacy clients/SMB workflows may fail; signing needs client compatibility |
| `-RotatePasswords` | Local-account selection is not SQL/service credential migration; dependencies are not exhaustive |
| `-KillPersistence` | Disable only verified malicious exact task paths, not unfamiliar backup/SQL jobs |
| `-InstallSysmon` | Requires approved signed binary/XML, volume review and telemetry verification |

Preview first-hour categories with `-PlanOnly`. Selecting a category without
that switch applies it; the role scripts' different apply model does not apply.

## 8. Troubleshooting, rollback and handoff

| Failure | First checks |
|---|---|
| SQL TCP connects but login/query fails | Instance/database state, identity, auth mode, certificate and source ERRORLOG |
| SQL works, SOP fails | SMB service, real share path/file/ACL and intended account; do not grant Everyone access |
| RDP fails after policy work | Listener, NLA/authentication, domain/DNS/time and actual effective rules |
| SQL log absent centrally | Correct literal path, UF identity read rights, source activity and effective monitor |
| Firewall recovery incomplete | Saved state, local profile values, conflicts and watchdog errors from console |

Firewall rollback does not restore a database, share content/ACL, password,
audit policy or SQL service configuration. UF rollback does not uninstall a
previously launched MSI or undo SQL changes. Use component-specific approved
backups and preserve evidence before recovery.

- [ ] Actual instance, ports, database/share/SOP, identities and backups recorded.
- [ ] Authenticated SQL query, required file read and second RDP login succeeded.
- [ ] New Windows marker and actual SQL text-log coverage verified.
- [ ] Timer committed/reverted deliberately; saved run and recovery limits understood.
- [ ] Scoring, domain dependencies and original admin session remain healthy.
