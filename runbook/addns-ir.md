# AD/DNS: assumed-compromise triage and auditing

[AD/DNS machine runbook](addnsreadme.md) | [All machines](README.md)

Use this Windows-only procedure on the existing **Windows Server 2022 AD/DNS
domain controller**. Run from a trusted copy of the complete repository in
**elevated, 64-bit Windows PowerShell 5.1**. See the machine runbook for Git,
curl/ZIP and approved offline staging.

The order is **preserve evidence -> inspect persistence and possible C2 ->
enable selected auditing -> verify new events -> verify off-host receipt**.
Keep the same PowerShell window open: later blocks use `$Out`, `$channels` and
`$configs` from earlier blocks. Each numbered section states its write boundary.

## Safety and interpretation

- Keep console access and an operator watching scoring. Preserve DNS, domain
  authentication, replication, SYSVOL, ping and scored authenticated WinRM.
- Do not begin by disabling WinRM, deleting unfamiliar tasks/services, killing
  processes, clearing logs, resetting `krbtgt`, rebooting or running the
  auto-hardener. Establish ownership and preserve evidence before containment.
- A suspicious path, repeated connection or unusual event is a lead, not proof.
  Legitimate DNS, Splunk, replication and management traffic can look periodic.
- A privileged attacker can alter local logs, tools and command output. These
  checks cannot certify a DC as clean or replace a coordinated AD recovery plan.
  Correlate with independently collected network and off-host evidence.
- Reports, process command lines, script blocks and EVTX files can contain
  secrets. Keep them private; never commit them or paste unredacted logs into
  chats. Use approved evidence transfer, not an external upload/scanning service.
- These are operator commands, not a transaction or an unattended script.
  **Stop on errors.** Some settings may already have changed if an APPLY block
  fails. Record the failure and inspect before continuing.

## 1. Confirm the role and preserve the pre-change state

**Writes: protected evidence files only.** No account, authentication, firewall,
service-startup or audit-policy changes. Local reads can themselves generate
events; this is live triage, not a forensic disk acquisition.

```powershell
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal](
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) { throw 'Open PowerShell as Administrator.' }
if (-not [Environment]::Is64BitProcess -or
    $PSVersionTable.PSEdition -ne 'Desktop' -or
    $PSVersionTable.PSVersion -lt [version]'5.1') {
    throw 'Use elevated 64-bit Windows PowerShell 5.1.'
}

$computer = Get-CimInstance Win32_ComputerSystem
$computer | Select-Object Name,Domain,DomainRole
if ($computer.DomainRole -notin 4,5) {
    throw 'This is not a domain controller. Stop here.'
}
Get-Item .\windows\addns\harden-addns.ps1,
         .\windows\lib\audit-windows-persistence.ps1 | Out-Null

$Out = Join-Path $env:ProgramData (
    'CCDC\AD-Triage-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $Out | Out-Null
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls.exe $Out /inheritance:r /grant:r `
    "*${me}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Evidence-directory ACL failed.' }

Get-Date -Format o | Set-Content "$Out\collection-time.txt"
Get-TimeZone | Format-List * | Out-File "$Out\timezone.txt"
Get-Service DNS,NTDS,Netlogon,WinRM |
    Export-Csv "$Out\critical-services.csv" -NoTypeInformation

foreach ($log in 'Security','System','Application') {
    wevtutil.exe epl $log "$Out\$log-before.evtx"
    if ($LASTEXITCODE -ne 0) { throw "Could not export $log." }
}
auditpol.exe /backup "/file:$Out\audit-policy-before.csv"
if ($LASTEXITCODE -ne 0) { throw 'Audit-policy backup failed.' }

"Evidence directory: $Out"
```

Capture **registry value existence, type and original value before audit apply**.
The role script changes command-line inclusion, so this backup must precede
section 4, not follow it.

```powershell
$targets = @(
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Name = 'EnableScriptBlockLogging'
    }
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        Name = 'ProcessCreationIncludeCmdLine_Enabled'
    }
)
$registryBefore = foreach ($target in $targets) {
    $keyExists = Test-Path -LiteralPath $target.Path
    $key = if ($keyExists) { Get-Item -LiteralPath $target.Path } else { $null }
    $valueExists = $keyExists -and ($key.GetValueNames() -contains $target.Name)
    [pscustomobject]@{
        Path = $target.Path
        Name = $target.Name
        KeyExisted = $keyExists
        ValueExisted = $valueExists
        Kind = if ($valueExists) { [string]$key.GetValueKind($target.Name) } else { $null }
        Value = if ($valueExists) { $key.GetValue($target.Name) } else { $null }
    }
}
$registryBefore | Export-Clixml "$Out\logging-registry-before.xml"

$channels = @(
    'Security'
    'Microsoft-Windows-PowerShell/Operational'
    'Microsoft-Windows-TaskScheduler/Operational'
    'Microsoft-Windows-WMI-Activity/Operational'
    'Microsoft-Windows-WinRM/Operational'
    'Microsoft-Windows-DNSServer/Audit'
)
$configs = @(
    foreach ($name in $channels) {
        Get-WinEvent -ListLog $name -ErrorAction Stop
    }
)
$configs |
    Select-Object LogName,IsEnabled,MaximumSizeInBytes,LogMode,LogFilePath |
    Export-Clixml "$Out\event-channel-settings-before.xml"

foreach ($config in $configs | Where-Object LogName -ne 'Security') {
    if ($config.RecordCount -gt 0) {
        $file = ($config.LogName -replace '[\\/:*?"<>|]', '_') + '-before.evtx'
        wevtutil.exe epl $config.LogName (Join-Path $Out $file)
        if ($LASTEXITCODE -ne 0) { throw "Could not export $($config.LogName)." }
    } else {
        Write-Warning "$($config.LogName): zero/unknown reported records; no pre-change export. This is not a clean-host finding."
    }
}
```

Missing/denied channels are a coverage gap, not an instruction to install roles
or suppress errors. Record the channel and resolve the discrepancy first.

## 2. Inspect persistence and AD/DNS state

**Writes: audit reports only.** The following repository commands do not request
hardening. The standalone persistence script needs its explicit `-AuditOnly`:
without it the script also changes PowerShell logging and transcription.

```powershell
.\windows\lib\audit-windows-persistence.ps1 `
    -AuditOnly -OutputDirectory $Out

.\windows\addns\harden-addns.ps1 -ReportDirectory $Out
if ($LASTEXITCODE -ne 0) { throw 'AD/DNS audit failed; inspect its report.' }
```

The [persistence auditor](../windows/lib/audit-windows-persistence.ps1) inspects
Run/RunOnce entries, loaded user hives, startup folders, Winlogon, IFEO,
WMI subscriptions and selected services/tasks. It excludes Microsoft task paths
and uses heuristic service-path filtering; some enumeration errors are
suppressed in its implementation. Inspect all error/failure messages and treat
its output as leads, not exhaustive coverage or a clean bill of health.

Capture all normally enumerated tasks and services, including Microsoft-looking
task paths. Hidden/tampered tasks may still evade normal enumeration.

```powershell
Get-ScheduledTask |
    Select-Object TaskPath,TaskName,State,Principal,Actions,Triggers |
    ConvertTo-Json -Depth 8 |
    Set-Content "$Out\all-scheduled-tasks.json"

Get-CimInstance Win32_Service |
    Select-Object Name,State,StartMode,StartName,PathName |
    Export-Csv "$Out\all-services.csv" -NoTypeInformation

Import-Module ActiveDirectory
Import-Module DnsServer

Get-ADGroupMember -Identity (
    (Get-ADDomain).DomainSID.Value + '-512'
) | Select-Object Name,SamAccountName,ObjectClass

Get-DnsServerForwarder
Get-DnsServerZone |
    Select-Object ZoneName,ZoneType,IsDsIntegrated,DynamicUpdate

Get-ItemProperty `
    'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' |
    Select-Object ServerLevelPluginDll

$sysvol = (Get-SmbShare -Name SYSVOL).Path
Get-ChildItem -LiteralPath $sysvol -Recurse -File |
    Where-Object LastWriteTime -ge (Get-Date).AddHours(-8) |
    Select-Object FullName,LastWriteTime,Length |
    Export-Csv "$Out\recent-sysvol-files.csv" -NoTypeInformation
```

Review unexpected task actions/principals, writable executable locations, encoded
commands, DNS plugin DLLs, forwarders and changed GPO/logon scripts. Check binary
hashes/signatures against trusted off-host sources; do not execute a suspicious
file to identify it. A signed executable or a familiar filename is not enough.

The group query shows **direct Domain Admins membership only**. Review nested
groups, other privileged groups, delegation and AD ACLs separately. The SYSVOL
query is only an eight-hour timestamp filter: timestamps can be forged, old
persistence is missed, and recent legitimate GPO updates are expected.

## 3. Capture processes and possible C2 connections

**Writes: evidence CSVs only.** No process termination or network blocking.

```powershell
Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,CreationDate,
                  Name,ExecutablePath,CommandLine |
    Export-Csv "$Out\processes.csv" -NoTypeInformation

$Connections = for ($sample = 0; $sample -lt 30; $sample++) {
    $processes = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $processes[[int]$_.ProcessId] = $_
    }
    Get-NetTCPConnection |
        Where-Object State -eq Established |
        ForEach-Object {
            $process = $processes[[int]$_.OwningProcess]
            [pscustomobject]@{
                Time = Get-Date -Format o
                PID = $_.OwningProcess
                Process = $process.Name
                Path = $process.ExecutablePath
                ProcessStart = $process.CreationDate
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                ProcessSeen = ($null -ne $process)
            }
        }
    Start-Sleep -Seconds 2
}

if (@($Connections).Count) {
    $Connections |
        Export-Csv "$Out\tcp-samples.csv" -NoTypeInformation
    $Connections |
        Group-Object Process,RemoteAddress,RemotePort |
        Sort-Object Count -Descending |
        Select-Object -First 25 Count,Name |
        Format-Table -AutoSize
} else {
    Write-Warning 'No established TCP rows observed; no TCP CSV created. This does not exclude C2.'
}
```

This takes roughly a minute plus collection time. **Counts are observations,
not connection attempts or measured beacon intervals**: one long-lived connection
can appear in every sample. The grouping also combines different instances of
the same process name; examine the CSV's PID, start time, path and timestamps.
Process/connection snapshots race with exits and PID reuse; a missing process
association or apparently matched PID is not definitive attribution.

Short-lived connections, UDP/DNS C2, long sleep intervals, injection and
in-memory malware can evade these snapshots. Correlate suspicious destinations
with packet/firewall telemetry and process events from a trusted collector.
Do not upload an internal IP, secret-bearing command line or private binary to
an external reputation/scanning service.

## 4. Enable selected auditing

**APPLY: changes local audit subcategories, process command-line inclusion,
PowerShell script-block logging and event-channel settings.** No account,
authentication, firewall, DNS-zone, service-startup or WinRM access changes.

Confirm section 1's backups exist first. Check log storage before applying:
this procedure assumes event logs use the system volume and requires at least
3 GiB free there. If logs are redirected, stop and review the actual volume.

```powershell
Get-Item "$Out\audit-policy-before.csv",
         "$Out\logging-registry-before.xml",
         "$Out\event-channel-settings-before.xml" | Out-Null

$systemVolume = $env:SystemDrive.TrimEnd(':')
if ((Get-PSDrive -Name $systemVolume).Free -lt 3GB) {
    throw 'Less than 3 GiB free on the system volume; review log storage.'
}
foreach ($config in $configs) {
    $path = [Environment]::ExpandEnvironmentVariables($config.LogFilePath)
    if ($path -notlike "$env:SystemDrive\*") {
        throw "Custom event-log location: $path. Review capacity before apply."
    }
}

.\windows\addns\harden-addns.ps1 `
    -EnableAuditPolicy -ReportDirectory $Out
if ($LASTEXITCODE -ne 0) { throw 'Audit-policy preview failed.' }
```

Review the preview, then deliberately run the APPLY block:

```powershell
.\windows\addns\harden-addns.ps1 `
    -Apply -EnableAuditPolicy -ReportDirectory $Out
if ($LASTEXITCODE -ne 0) {
    throw 'Audit setup failed; inspect output for partial changes.'
}

$psLogging = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $psLogging -Force | Out-Null
New-ItemProperty -Path $psLogging -Name EnableScriptBlockLogging `
    -PropertyType DWord -Value 1 -Force | Out-Null

foreach ($name in $channels) {
    $config = Get-WinEvent -ListLog $name -ErrorAction Stop
    $minimum = if ($name -eq 'Security') { 512MB } else { 64MB }
    if ($config.MaximumSizeInBytes -lt $minimum) {
        $config.MaximumSizeInBytes = $minimum
    }
    if (-not $config.IsEnabled) { $config.IsEnabled = $true }
    $config.SaveChanges()
}

auditpol.exe /get /category:*
if ($LASTEXITCODE -ne 0) { throw 'Audit-policy readback failed.' }
Get-ItemProperty -LiteralPath $psLogging -Name EnableScriptBlockLogging
foreach ($name in $channels) {
    Get-WinEvent -ListLog $name |
        Select-Object LogName,IsEnabled,MaximumSizeInBytes,LogMode
}
```

The role script backs up policy and enables selected success/failure auditing
for logons, account/group management, scheduled tasks, process creation,
audit-policy changes, credential validation, Kerberos and directory changes.
Do not append authentication hardening, firewall or DNS-zone switches.

Limits and operational checks:

- New logging cannot recover activity that was never recorded. Logging is not
  malware prevention. Command lines and script blocks can expose secrets.
- Local policy can be superseded by domain GPO. Coordinate durable settings
  with the AD owner and recheck effective policy after normal policy refresh.
  The existing role helper's verification expects English `auditpol` output;
  on a non-English host it can fail after partially applying settings.
- Event caps are raised only when smaller than 512 MiB for Security or 64 MiB
  for the listed operational channels. Retention/overwrite mode is preserved.
  Monitor capacity, record growth and forwarding; a retain-mode full log can
  stop accepting new events. Do not clear it as a shortcut.
- Directory-change events such as 5136 require the appropriate **object SACL**.
  The audit subcategory alone does not audit every AD object. This procedure
  does not add broad directory-access SACLs or claim comprehensive DCSync
  detection.
- DNS **Audit** tracks changes, not all DNS queries. Verbose DNS debug and
  Analytical logging are not enabled here; review load and a separate bounded
  capture plan before enabling them.
- The block enables PowerShell **4104**, not comprehensive module logging
  (4103) or transcription. New PowerShell processes may be needed to pick up
  script-block logging policy.

## 5. Read bounded event-log windows

**Read-only.** Queries show at most the latest 100 matching events per call.
Busy authentication logs can exceed that cap; narrow the IDs/time window and
use preserved EVTX/off-host data for a complete timeline.

```powershell
function Show-RecentEvents {
    param(
        [Parameter(Mandatory)][string]$Log,
        [int[]]$Ids = @(),
        [ValidateRange(1,1440)][int]$Minutes = 30
    )
    $filter = @{
        LogName = $Log
        StartTime = (Get-Date).AddMinutes(-$Minutes)
    }
    if ($Ids.Count) { $filter.Id = $Ids }
    try {
        Get-WinEvent -FilterHashtable $filter `
            -MaxEvents 100 -ErrorAction Stop |
            Format-List TimeCreated,Id,ProviderName,Message
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-Warning "No matching events in $Log for this window; this is not evidence that the host is clean."
        } else {
            throw
        }
    }
}
```

Persistence, privilege changes and log tampering:

```powershell
Show-RecentEvents -Log Security -Ids @(
    1102,4719,4697,
    4698,4699,4700,4701,4702,
    4720,4722,4724,4726,4728,4732,4738,4756,
    5136,5137,5139,5141
)
Show-RecentEvents -Log System -Ids 7045,7040
```

Authentication and possible lateral movement:

```powershell
Show-RecentEvents -Log Security -Ids @(
    4624,4625,4648,4672,4740,4768,4769,4771,4776
) -Minutes 10
```

Correlate account, source address, workstation, logon type and time. Logon type
3, privileged logons and service-ticket requests are routine on DCs; they are
not automatically lateral movement or ticket forgery.

PowerShell, scheduled tasks, WMI, WinRM and DNS:

```powershell
Show-RecentEvents -Log 'Microsoft-Windows-PowerShell/Operational' -Ids 4103,4104
Show-RecentEvents -Log 'Microsoft-Windows-TaskScheduler/Operational'
Show-RecentEvents -Log 'Microsoft-Windows-WMI-Activity/Operational'
Show-RecentEvents -Log 'Microsoft-Windows-WinRM/Operational'
Show-RecentEvents -Log 'Microsoft-Windows-DNSServer/Audit'
```

If Sysmon is already installed with an approved configuration, inspect its
enabled collection too. This optional query **does not install or configure
Sysmon**; a missing log is a known coverage gap.

```powershell
Show-RecentEvents -Log 'Microsoft-Windows-Sysmon/Operational' `
    -Ids 1,3,11,12,13,14,19,20,21,22
```

Sysmon network-connection event 3 is not enabled by default; DNS event 22 and
other event coverage also depend on configuration/filtering. Missing events do
not establish that no network or persistence activity occurred.

| Log / event | What to investigate |
|---|---|
| Security 1102 / 4719 | Security log cleared / audit policy changed |
| Security 4688 | New process, parent process and command line |
| Security 4698-4702 | Scheduled-task changes |
| System 7045 / 7040 | Service installed / startup type changed |
| Security 4720 / 4724 | Account created / password-reset attempt |
| Security 4728 / 4732 / 4756 | Member added to security group |
| Security 5136 | AD object modified, where audit policy/SACL permits |
| PowerShell 4104 | Script-block content |
| Sysmon 1 / 3 / 22 | Configured process / network / DNS-query telemetry |

Use Event Viewer (`eventvwr.msc`) for an interactive view. Keep the same bounded
time filters and preserve the underlying events, not just screenshots.

## 6. Verify new events and off-host receipt

**Intentional test write:** launches a harmless new PowerShell process and
generates normal process/script-block events. It does not create persistence.

```powershell
$Marker = 'CCDC-AUDIT-CHECK-' + [guid]::NewGuid().ToString('N')
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -NoProfile -NonInteractive -Command "Write-Output '$Marker'"
if ($LASTEXITCODE -ne 0) { throw 'Test process failed.' }
Start-Sleep -Seconds 3
Show-RecentEvents -Log Security -Ids 4688 -Minutes 5
Show-RecentEvents -Log 'Microsoft-Windows-PowerShell/Operational' `
    -Ids 4104 -Minutes 5
$Marker
```

Find that exact marker in the new process command line and script-block content,
with the actual DC identity and current timestamp. Unrelated old events or
registry readback alone do not prove collection. A failed verification is a gap
to investigate, not permission to weaken authentication or clear logs.

Use the [AD forwarding procedure](addnsreadme.md#4-establish-forwarding-before-hardening)
and [central verification guidance](splunkreadme.md#7-verification-three-independent-levels).
**Enabling a channel does not add a forwarder input.** Explicitly verify inputs,
read permissions and fresh receipt for Security, Directory Service, PowerShell,
Task Scheduler, WMI, WinRM and DNS Audit. Do not assume the existing AD profile
includes every channel enabled here. Preserve existing Splunk app/routing and
transport settings; never overwrite them with a generic example.

Copy approved evidence off-host and record the time/source/destination. A local
administrator-level attacker can tamper with local collection even when a test
event appears.

## 7. Recovery boundaries and handoff

The audit-policy CSV restores audit policy only, not registry values or channel
configuration. The XML snapshots record the registry value preimages and event
channel settings. They are evidence/reference files, **not an automatic restore
script**.

Coordinate recovery with other operators. Compare current state with the intended
changes, then restore only approved fields to their actual saved values/types.
If a value was originally absent, do not invent a default; if it changed
independently, investigate rather than overwriting a teammate's work. Do not
blindly import an entire audit-policy backup during concurrent administration.
Do not delete newly created logs or the collected evidence as "rollback".

- [ ] DC identity, timezone, evidence path and trusted off-host copy recorded.
- [ ] Existing DNS, domain login, replication, ping and scored WinRM rechecked.
- [ ] Persistence/C2 leads assigned owners; benign activity not auto-deleted.
- [ ] Audit, registry and channel preimages saved before logging changes.
- [ ] Logging errors, absent channels, SACL gaps and collection limits recorded.
- [ ] New process/script-block marker verified locally and off-host.
- [ ] Forwarder coverage, log volume, disk capacity and retention checked.
- [ ] Any containment/recovery approved separately; no clean-host claim.

## References

- [Existing AD audit-policy implementation](../windows/lib/RoleCommon.ps1)
- [Existing persistence auditor](../windows/lib/audit-windows-persistence.ps1)
- [Microsoft: advanced audit policy and event mappings](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft: DNS logging, Audit versus Analytical](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics)
