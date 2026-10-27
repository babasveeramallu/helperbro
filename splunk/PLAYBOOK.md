# Playbook: AD, MSSQL and Windows workstation to Debian Splunk

This is the operator procedure for this repository's Windows forwarding and
Debian receiver scripts. It documents what the code does, not what a generic
Splunk installation might do. Start from the [main operator guide](../README.md)
for unrelated host-hardening tools.

After telemetry receipt is verified, use the separate
[packet-aware firewall and detection-decoy playbook](../windows/DEFENSE-PLAYBOOK.md)
if applying those defenses. The forwarding scripts themselves still do not
change host firewall policy. Decoy Application events use the existing
`wineventlog` input; alert examples and source limits are in that playbook.

## Contents

1. [Mission, topology and scoring boundaries](#1-mission-topology-and-scoring-boundaries)
2. [Files, data flow and trust boundaries](#2-files-data-flow-and-trust-boundaries)
3. [Preflight and stop conditions](#3-preflight-and-stop-conditions)
4. [Debian receiver procedure](#4-debian-receiver-procedure)
5. [Windows forwarder procedure](#5-windows-forwarder-procedure)
6. [What gets collected and how it is configured](#6-what-gets-collected-and-how-it-is-configured)
7. [Prove end-to-end delivery](#7-prove-end-to-end-delivery)
8. [Troubleshooting by symptom](#8-troubleshooting-by-symptom)
9. [Rollback, reruns and recovery limits](#9-rollback-reruns-and-recovery-limits)
10. [Acceptance checklist and handoff](#10-acceptance-checklist-and-handoff)
11. [Offline tests and what remains unverified](#11-offline-tests-and-what-remains-unverified)

## 1. Mission, topology and scoring boundaries

### Mission

Collect Windows security/operational telemetry and available SQL Server text
error logs on the existing Debian Splunk server. Preserve the existing
business/scoring services. Do not combine this deployment with broad hardening,
password rotation, domain policy changes, or a firewall replacement.

### Packet inventory

Source: the supplied *2026 Midwest Invitational Team Packet*, page 13 VM table;
pages 14-15 functional services; page 17 systems rules. The PDF contains initial
credentials and is intentionally not copied into this repository.

| System | Packet OS/software | Packet internal IP | Selected role |
|---|---|---|---|
| AD | Windows Server 2022 Standard | `172.20.240.100` | `AD` |
| MSSQL | Windows Server 2019 Standard | `172.20.240.120` | `MSSQL` |
| Windows workstation | Windows 11 | DHCP | `Wkst` |
| Debian Splunk | Debian 12, Splunk 10.0.2 | `172.20.240.20` | Existing receiver |

The scripts do not enforce these source IPs or Windows versions. `-Role` is
explicit; selecting `Wkst` is not a full workstation-OS validation. The Windows
script does check domain-controller status, and selecting `MSSQL` requires a
database-engine service. Hostnames are not replaced with the role labels.

Live NETLAB/portal details override the packet. Record the real hostnames and
addresses before running commands. Use the internal receiver address for this
LAN path, rather than calculating a team-specific public/NAT address.

### Protect these services

| System | Preserve | Why forwarding setup avoids touching it |
|---|---|---|
| AD | Domain operations, DNS and scored WinRM authentication/commands | No AD policy, account, WinRM or firewall modifications |
| MSSQL | SMB/SOP files, RDP/3389, SQL/1433, accounts and queries | No SQL/SMB/RDP restart, password rotation or content edits |
| Workstation | Normal user access and administration | No hostname, IP, user or workstation-role change |
| Debian | Scored Splunk query and management authentication on 8089 | No credential/endpoint changes; a necessary Splunk restart still briefly interrupts access |
| All | Ping and requested organizer access | No firewall replacement or ICMP changes |

The packet prohibits knife-edge filtering that makes public services available
only to scoring IPs. Do not scope scored MSSQL RDP or AD WinRM to team-only
management ranges just because another generic hardening script offers it.
Do not assume event-time snapshots or VM scrubbing are available: the packet
explicitly says they are not.

## 2. Files, data flow and trust boundaries

### Copy the entire Splunk directory

| File | Purpose | Run directly? |
|---|---|---|
| [Set-WindowsForwarder.ps1](Set-WindowsForwarder.ps1) | Windows discovery, optional MSI launch, UF configuration, service handling and rollback | Yes, on each Windows host |
| [WindowsForwarder.Common.ps1](WindowsForwarder.Common.ps1) | Channel lists, config rendering, SQL path discovery, TCP check, config parsing and ACL helpers | No; loaded by the Windows entry point |
| [setup-debian-receiver.sh](setup-debian-receiver.sh) | Existing Enterprise receiver/index app setup | Yes, on Debian |
| [mssql-props.conf](mssql-props.conf) | Custom SQL ERRORLOG encoding, event-boundary and timestamp settings | No; copied by both setup scripts |
| [Test-WindowsForwarder.ps1](Test-WindowsForwarder.ps1) | Offline Windows fixture/mock tests | Yes, for toolkit checks |
| [test-debian-receiver.sh](test-debian-receiver.sh) | Offline Bash rendering/argument tests | Yes, for toolkit checks |
| [generate-configs.py](generate-configs.py) | Older parent-workspace config generator | Not part of this deployment procedure |

The new setup scripts do not require the older generator's parent `config/` and
`generated/` directories. Do not mix the older generated inputs/outputs with
these dedicated apps unless you deliberately reconcile configuration precedence.

### Data path

```text
AD / MSSQL / Wkst Windows
    |
    +-- Windows Event Log channels
    +-- MSSQL only: discovered/explicit text ERRORLOG files
    |
Splunk Universal Forwarder (Windows service: SplunkForwarder)
    |
    +-- TCP 9997, default destination 172.20.240.20
    |
Existing Splunk Enterprise on Debian
    +-- wineventlog: Windows event channels other than Sysmon
    +-- sysmon: Sysmon Operational events, if available
    +-- mssql: SQL text ERRORLOG input
    |
Splunk Search: prove a NEW event arrived from each actual hostname
```

### Transport and credential limits

- The supplied baseline is **unencrypted Splunk TCP**, not TLS. Both apply
  paths require explicit acknowledgment: `-AllowPlaintext` on Windows and
  `--allow-plaintext` on Debian.
- These switches do not enable encryption; they acknowledge its absence.
  Logs can contain account names, commands, paths and other sensitive evidence.
- `useACK = true` requests indexer acknowledgments. It is not encryption,
  authentication, a complete disk-persistent queue policy, or a guarantee of
  exactly-once delivery through every failure scenario.
- No shared secret or certificate is configured to authenticate incoming senders.
  Restrict the added ingestion path according to approved network policy without
  breaking the packet's public-service requirements.
- TLS deployment needs a separate certificate/receiver/forwarder plan. Do not
  point this plaintext output at a TLS-only receiver.
- No passwords are hardcoded, passed by these scripts to `msiexec`, or exported
  to a password file. Splunk's installer and runtime may have their own files;
  protect those and review their behavior separately.
- A UF-local administrator is distinct from a Windows administrator, a domain
  administrator, a SQL login and the central Splunk scoring account.
  Do not reuse those passwords or put `-auth user:password` in commands.

## 3. Preflight and stop conditions

### Operator checklist

- [ ] Confirm authorization to install the approved Universal Forwarder package
  and use the proposed transport on the competition network.
- [ ] Record actual IPs/hostnames and check the current portal service checks.
- [ ] Coordinate with the Debian operator; plan the receiver restart first.
- [ ] Retain NETLAB console access. Do not rely solely on RDP/WinRM/SSH.
- [ ] Stage the complete scripts directory and an approved x64 UF MSI compatible
  with the supplied Splunk version. Prefer a pinned, verified 10.0.x package for
  this packet unless organizers approve something different.
- [ ] Obtain the package's expected SHA256 through a trusted channel if using
  hash verification. Computing a hash locally alone does not establish provenance.
- [ ] Verify free space on Debian and Windows. Plan index retention separately.
- [ ] Identify existing UF outputs, deployment-server apps, indexes and channel
  subscriptions before changing any of them.
- [ ] Record how to restore the previous app and who can approve downtime.

### Read-only discovery

On Windows, from an elevated **x64** PowerShell session:

```powershell
[Environment]::Is64BitProcess             # Must be True
$PSVersionTable.PSVersion                # Windows PowerShell 5.1 or PowerShell 7+
hostname
Get-NetIPConfiguration
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, Domain, DomainRole
Get-Service SplunkForwarder -ErrorAction SilentlyContinue
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
    Select-Object Name, State, StartName, StartMode
```

On Debian:

```bash
hostname
ip -brief address
systemctl list-unit-files --type=service | grep -i splunk
df -h /opt/splunk
sudo ss -ltnp
```

If installed somewhere other than `/opt/splunk`, check that actual mount's free
space as well. A unit might be called `splunk`, `Splunkd`, or something else;
use its actual name consistently.

### Stop rather than guessing

Stop if the receiver address is wrong, scored services are already failing,
Splunk is not installed/running on Debian, the chosen unit points to another
program, or existing forwarding goes somewhere else and no migration is approved.
Also stop for invalid signatures/hashes, insufficient channel/file read access,
or unresolved higher-precedence configuration.

The Windows script's missing-UF audit stops early: it does not yet verify every
role/channel/SQL prerequisite. Similarly, an audit that exits without exception
does not mean all sources or the full end-to-end path are healthy.

## 4. Debian receiver procedure

### Commands

On Debian, change into the copied `splunk` directory:

```bash
cd splunk
sudo bash setup-debian-receiver.sh --audit-only --service Splunkd
```

Read the output: chosen TCP port, current receiver disabled value, and each
index's effective `homePath`. A blank value usually means that setting/index is
not yet configured. This mode reports current state; it is not an ingestion test.

When approved:

```bash
sudo bash setup-debian-receiver.sh --allow-plaintext --service Splunkd
```

Type `APPLY` when prompted. Use `--force` only after review if the prompt must be
skipped; it does not bypass root checks, service validation or plaintext approval.

### What the script does, in execution order

| Stage | What happens | Why it matters |
|---|---|---|
| Arguments | Validates the port, absolute home/output paths and unit-name format | Refuses invalid input rather than inventing defaults |
| Installation | Requires the existing executable and apps directory | Does not install or replace Enterprise |
| File safety | Refuses symlinks at the managed app/local/config targets it checks | Avoids overwriting those redirected targets |
| Service check | Requires a loaded, active systemd unit and checks its main process executable against this installation's `splunkd` | Prevents restarting an unrelated unit |
| Discovery | Runs `btool inputs list` and `btool indexes list` | Reads merged configuration instead of trusting one file |
| Audit exit | Prints current settings and exits if audit was requested | No app/backup/report is written by the script in audit mode |
| Apply gates | Requires root, plaintext approval and typed `APPLY` unless forced | Makes the change explicit |
| Backup | Creates a restrictive output directory and unique `receiver-XXXXXXXX` directory; copies an existing managed app | Preserves the previous app before overwriting its files |
| Desired config | Builds receiver, index and SQL parsing files in `desired/` | Separates intended settings from effective settings |
| Index preservation | Adds definitions for missing indexes; retains definitions it already manages; leaves existing externally defined index paths alone | Avoids relocating existing indexed data |
| Repeat-run check | Compares the three managed file contents, validates effective input/index settings and checks listening-process ownership | Matching files do not alone prove a usable receiver |
| App installation | Writes the managed files with ownership based on the running `splunkd` process | Allows the existing service identity to read them |
| Validation | Rechecks merged receiver/index configuration | A higher-precedence disabled receiver/index causes failure |
| Activation | Restarts the selected Splunk unit when managed file contents changed | Loads the new receiver/parsing settings |
| Readiness | Polls for up to 60 one-second attempts for an active unit and a socket owned by its main PID | Avoids mistaking another process's port for Splunk |
| Completion | Prints readiness and next-step instructions | This is receiver readiness, not proof of Windows event receipt |

Even a matching configuration apply run creates a backup/log before deciding
that a restart is unnecessary. The comparison is of managed app **file contents**;
do not describe it as a complete semantic diff of all Splunk settings.

### Files written

```text
/opt/splunk/etc/apps/ccdc_windows_receiver/local/
    inputs.conf
    indexes.conf
    props.conf

/var/log/ccdc-splunk/receiver-XXXXXXXX/
    apply.log
    desired/
        inputs.conf
        indexes.conf
        props.conf
    app/                  # Only when the app existed before this run
```

Home/output overrides change those locations. The output directory is installed
with mode `0700`; `umask 077` restricts newly created backup/log files.
The installed app directories use `0750` and config files use `0640`.
Treat backups as sensitive operational data.

### Receiver options

| Option | Default | Exact purpose |
|---|---|---|
| `--audit-only`, `--plan-only` | Off | Inspect without applying or creating script reports/backups |
| `--force` | Off | Skip typed `APPLY`; other checks still run |
| `--allow-plaintext` | Off | Required acknowledgment for non-TLS apply |
| `--splunk-home PATH` | `/opt/splunk` | Select the existing installation; absolute path required |
| `--service NAME` | `Splunkd` | Select the active unit whose main process matches that installation |
| `--port NUMBER` | `9997` | Add the Splunk TCP receiver at that port |
| `--output-directory PATH` | `/var/log/ccdc-splunk` | Absolute backup/log destination |
| `--render-only PATH` | Off | Write sample configs to a new absolute destination without checking/installing Splunk |
| `--help` | N/A | Show usage |

`--render-only` deliberately writes files: it is not audit mode, cannot be combined
with it, and does not check live index preservation or ingestion.

### What Debian setup does not change

No Enterprise reinstall, account reset, license change, service enable-at-boot
change, firewall edit, scoring credential edit, Web/8089 configuration change,
or retention sizing. A Splunk restart still interrupts all functionality provided
by that process briefly, including existing ingestion and scored queries.
Check those again immediately afterward.

## 5. Windows forwarder procedure

### Pick the role explicitly

Run from the repository root containing the `splunk` directory, **not** from
inside that directory. If you copied only that directory, omit the leading
`.\splunk\` from the commands.

```powershell
# AD host
.\splunk\Set-WindowsForwarder.ps1 -Role AD -AuditOnly

# MSSQL host
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -AuditOnly

# Windows 11 workstation
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -AuditOnly
```

Run only the matching line on each machine. The `AD` role is refused on a non-DC;
the other roles are refused on a DC. `MSSQL` additionally requires a service named
`MSSQLSERVER` or matching `MSSQL$*`. That check does not prove SQL is healthy or
listening on 1433.

### If Universal Forwarder is missing

Audit warns and returns without installing or creating an output directory.
During apply, provide the real staged MSI path:

```powershell
$msi = 'C:\Staging\splunkforwarder-approved-x64.msi'
Get-AuthenticodeSignature -LiteralPath $msi
Get-FileHash -LiteralPath $msi -Algorithm SHA256

.\splunk\Set-WindowsForwarder.ps1 -Role AD -InstallerPath $msi -AllowPlaintext
```

Change `AD` to `MSSQL` or `Wkst` on the other machines. Optionally add
`-InstallerSha256` with the actual expected 64-character hash obtained separately.
Do not paste placeholder hashes and expect installation to succeed.

The script requires a `.msi` with valid Authenticode status and a signer subject
matching Splunk. It checks the optional hash, asks for confirmation, then launches
`msiexec /i ... /norestart` interactively and waits.

In the wizard:

1. Install to `C:\Program Files\SplunkUniversalForwarder`, or match your explicit
   `-SplunkHome` override.
2. Review and accept the vendor license yourself.
3. Choose a service identity with the needed event/file read permissions.
   Local System is operationally simple in this lab but has substantial local
   privileges. A least-privilege identity must be tested on every source.
4. Set a unique UF-local administrator password. Store it using your team's
   approved secret-handling method, not Git or the incident report.
5. Do not add a separate forwarding destination/deployment server that would
   conflict with this script's managed app.
6. Complete installation. Exit `0` or `3010` is accepted; `3010` produces a reboot
   warning, not an automatic reboot.

**Installation precedes later role/network checks.** A wrong role, unreachable
receiver or configuration conflict discovered afterward can leave the MSI
installed. Rollback does not uninstall it. `-Force` does not make the installer
silent or skip its credential/license pages.

### Apply one host at a time

Once audit output and prerequisites are understood:

```powershell
# Use the appropriate command on its corresponding host:
.\splunk\Set-WindowsForwarder.ps1 -Role AD -AllowPlaintext
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -AllowPlaintext
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -AllowPlaintext
```

Confirm the PowerShell change prompt. Complete verification for that host before
moving to the next. Use `-Force` only when reviewed automation should skip the
script's confirmation.

### Windows execution stages

| Stage | Actual behavior |
|---|---|
| Shell | Refuses x86 PowerShell; apply requires elevation |
| UF check | Requires both the executable and service, or takes the optional interactive installer path |
| Role check | Checks DC status and the MSSQL engine-service requirement |
| Identity discovery | Reports the UF service account and startup mode; does not change its identity |
| Channel discovery | Runs `wevtutil gl ... /f:xml` for the role's channels and reads their enabled state |
| Required/optional handling | Failure to read Security, System, Application, or the selected AD Directory Service channel stops the run; unavailable optional channels warn and are omitted |
| SQL discovery | For MSSQL, reads registry startup parameters or explicit paths and verifies literal file existence |
| Desired rendering | Builds inputs/outputs and reads the bundled SQL props file |
| Existing-output guard | Refuses a nonempty effective `defaultGroup` other than `ccdc_windows_indexer` |
| Target safety | Refuses reparse points at its managed app/local/config targets |
| Comparison | Compares the three desired file contents against its managed app |
| TCP test | Attempts a connection to the receiver, with a five-second wait limit; does not authenticate or send a test event |
| Audit return | Emits the inspection object and exits before script writes/service changes |
| Apply gates | Requires confirmation, plaintext approval and a reachable receiver |
| Backup/report | Creates a protected unique run directory, copies an existing app and writes `run.json` |
| File update | When content differs, writes its app's inputs/outputs/props as UTF-8 without BOM |
| Channel enablement | Enables selected existing disabled channels with `wevtutil sl ... /e:true` |
| Merged validation | Uses `btool` to check effective destination, channel enabled/index/XML/sourcetype settings and SQL monitor index/enabled settings |
| Service startup | Changes `SplunkForwarder` to Automatic when needed |
| Service activation | Starts a stopped UF or restarts it when app content/channel state changed; waits up to 60 seconds for Running |
| Completion report | Sets `Status` to `ConfiguredDeliveryNotYetVerified` |

The script checks channel existence using the current operator's privileges;
it does not prove that the UF service identity can read each channel. Likewise,
file existence for the operator is not proof of UF read access.

### Audit output interpretation

| Property | Meaning | Not a guarantee of |
|---|---|---|
| `Role` | Requested profile after role checks | Full application health |
| `Receiver` | Proposed destination | Correct live topology |
| `TcpReachable` | TCP connection attempt succeeded | Splunk protocol acceptance or indexing |
| `Channels` | Existing readable channels selected by this run | Relevant events being generated |
| `DisabledChannels` | Selected source channels that apply would enable | Full source audit-policy coverage |
| `SqlLogs` | Discovered/explicit files, if any | SQL statement auditing or UF read permissions |
| `ConfigChangeNeeded` | Managed app file contents differ/missing | Complete effective-config compliance |
| `ServiceStatus` | Current Windows service state | Active forward-server or data receipt |
| `StartupChangeNeeded` | Startup is not currently Automatic | Service will survive every failure |

For an installed UF, audit can still report an unreachable destination without
throwing. Effective-input validation happens on apply; an audit result alone
does not certify every higher-precedence input setting.

### Windows parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-Role AD\|MSSQL\|Wkst` | Required | Select source channels and SQL discovery |
| `-Indexer` | `172.20.240.20` | Hostname or IPv4 destination; this validator does not accept IPv6 literals |
| `-Port` | `9997` | Destination TCP port, 1-65535 |
| `-SplunkHome` | `C:\Program Files\SplunkUniversalForwarder` | Existing or chosen installation directory |
| `-InstallerPath` | None | Signed staged MSI; used only when installation is missing |
| `-InstallerSha256` | None | Optional trusted expected SHA256 for that installation |
| `-SqlLogPath` | Auto-discover | MSSQL-only array of existing literal absolute paths; replaces discovery, not appends |
| `-OutputDirectory` | `%ProgramData%\CCDC\Splunk` | Backup/run-report parent |
| `-AuditOnly`, `-PlanOnly` | Off | Inspection only; does not write its own files |
| `-WhatIf` | Off | Standard PowerShell preview; does not install/apply, but may perform discovery |
| `-AllowPlaintext` | Off | Required acknowledgment for plaintext apply |
| `-Force` | Off | Suppress the script's PowerShell confirmation; does not bypass validation |

Multiple SQL instances/nonstandard error log example:

```powershell
$logs = @(
    'C:\SQLLogs\InstanceA\ERRORLOG',
    'D:\SQLLogs\InstanceB\ERRORLOG'
)
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -SqlLogPath $logs -AuditOnly
# After reviewing the result:
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -SqlLogPath $logs -AllowPlaintext
```

Those are example paths, not directories the script creates. Use actual paths.
Do not repeat a named PowerShell array parameter; use an array as shown.

### Windows files and ACLs

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\
    ccdc_windows_forwarder\local\
        inputs.conf
        outputs.conf
        props.conf

C:\ProgramData\CCDC\Splunk\
    forwarder-<timestamp>-<guid>\
        run.json
        app\                  # Only if the app existed before this run
```

The unique backup directory disables inherited permissions and gives SYSTEM and
built-in Administrators full access. The managed app uses those permissions
plus **Authenticated Users ReadAndExecute** so a non-System UF identity can read
configuration. The live app is therefore not a secret store.
The script does not add that read access to SQL logs or change their ACLs.

`run.json` records computer, role, receiver, channels, SQL paths, previous startup
mode, status and an error field. It is **not a full console transcript**, complete
machine backup, or persistent channel-state rollback ledger.

## 6. What gets collected and how it is configured

### Event channels

All roles attempt these sources:

| Channel | Operational value |
|---|---|
| `Security` | Authentication, account changes and other enabled security audits |
| `System` | Service/driver/system events |
| `Application` | Application errors and SQL events emitted there |
| `Windows PowerShell` | Classic PowerShell engine events |
| `Microsoft-Windows-PowerShell/Operational` | Operational/script events when the source policy generates them |
| `Microsoft-Windows-TaskScheduler/Operational` | Scheduled task execution and activity |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI operational activity |
| `Microsoft-Windows-Windows Defender/Operational` | Defender detections and status events when available |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | RDP/local session transitions |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | Remote desktop connection activity |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon telemetry if Sysmon is already installed |

Role additions:

| Profile | Extra channels |
|---|---|
| `AD` | `Directory Service`, `DNS Server`, `DFS Replication` |
| `MSSQL` | No extra Windows channels; adds text ERRORLOG monitors |
| `Wkst` | `Microsoft-Windows-DeviceSetupManager/Admin`, `Microsoft-Windows-DriverFrameworks-UserMode/Operational` |

DNS Server, DFS Replication, Sysmon and the other optional providers may not exist
on every host. The script warns rather than installing them.

### Windows event input, line by line

Example generated Security stanza:

```ini
[WinEventLog://Security]
disabled = 0
renderXml = true
index = wineventlog
sourcetype = XmlWinEventLog:Security
start_from = newest
current_only = 0
checkpointInterval = 5
```

| Setting | Meaning and caution |
|---|---|
| `WinEventLog://Security` | Subscribe through the Windows event-log input, not a raw `.evtx` file monitor |
| `disabled = 0` | Enable the Splunk input; source-channel enabled state is a separate check/change |
| `renderXml = true` | Send XML event structure; field extraction still needs appropriate Splunk knowledge objects/add-on |
| `index` | `sysmon` for the selected Sysmon channel; `wineventlog` for the others |
| `sourcetype` | Explicit `XmlWinEventLog:<channel>`; preserve this when writing searches |
| `start_from = newest` | Select the newest starting position for a fresh subscription; do not rely on this workflow for complete historical backfill |
| `current_only = 0` | Do not configure current-only collection; input checkpoints/recovery behavior still matters |
| `checkpointInterval = 5` | Configure frequent event-input checkpoint updates |

Existing checkpoints, installed UF behavior and event-log retention affect what
is reread. Verify first-run/backlog behavior on the installed version and monitor
event volume. Do not clear checkpoints to troubleshoot casually; that can
change coverage or cause re-ingestion. No event-code whitelist is generated.

### Forwarding output, line by line

```ini
[tcpout]
defaultGroup = ccdc_windows_indexer

[tcpout:ccdc_windows_indexer]
server = 172.20.240.20:9997
useACK = true
```

`defaultGroup` routes default forwarded data to the named group, not just the
new Windows channels. Existing unmanaged inputs can be affected by a routing
change, which is why the script refuses a different existing default group.
There is one configured destination, not a load-balanced HA receiver set.

`btool ... list --debug` shows which file contributes a setting. App files do
not automatically outrank `system/local` or every deployment app. Do not
delete conflicting settings before confirming what existing/scored data needs.

### MSSQL ERRORLOG discovery and parsing

For the MSSQL profile:

1. With explicit `-SqlLogPath`, use only those paths.
2. Otherwise read instance IDs from
   `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`.
3. Read each instance's `MSSQLServer\Parameters` values named `SQLArg*`.
4. Select `-e...` startup arguments as error-log file paths.
5. Remove duplicate paths, require rooted literal existing files, and refuse
   wildcard/INI-delimiter/newline characters that this implementation disallows.
6. Generate one `monitor://<path>` stanza per accepted path:

```ini
[monitor://C:\SQLLogs\ERRORLOG]
disabled = 0
index = mssql
sourcetype = ccdc:mssql:errorlog
```

If no paths are discovered, the script warns and still collects Application
events. If a selected path is invalid/inaccessible/nonexistent, it throws.
No binary `.xel`/`.trc` audit or trace file is discovered automatically.
Do not explicitly point this text monitor at binary audit/trace files.
The current ERRORLOG may include historical content when first monitored.
Archived ERRORLOGs are not explicitly added, and rotation behavior needs
verification on the actual SQL host.

The bundled props file is installed on both tiers:

| Property | Purpose |
|---|---|
| `CHARSET = AUTO` | Ask Splunk to detect encoding, including BOM-bearing text; verify the real SQL file |
| `SHOULD_LINEMERGE = false` | Use explicit event boundaries rather than heuristic merging |
| `LINE_BREAKER` | Start a new record before a line beginning with the expected date/time pattern; retain continuation lines |
| `TIME_PREFIX = ^` | Look for the timestamp at the start |
| `TIME_FORMAT = %Y-%m-%d %H:%M:%S.%3N` | Parse the expected millisecond SQL timestamp |
| `MAX_TIMESTAMP_LOOKAHEAD = 23` | Limit timestamp scanning to that prefix |

It does not set a timezone or extract every SQL-specific field. Compare source
and indexed timestamps, line boundaries and encoding on actual logs. A quiet
ERRORLOG can have no events inside a short search window even when monitoring
works.

### Source activation is not comprehensive auditing

| Desired telemetry | Separate prerequisite not enabled by these scripts |
|---|---|
| Security logon events | Appropriate Windows/AD audit policy |
| Security process creation 4688 | Process Creation auditing; command-line inclusion is another policy |
| PowerShell script block 4104 | Script Block Logging policy |
| Sysmon process/network events | Installed Sysmon with a suitable configuration |
| Every SQL statement or SQL audit action | Deliberate SQL Server Audit/Extended Events design and a compatible ingestion method |
| Linux authentication/web/flow telemetry | Separate inputs; these scripts cover your Windows assignment |

Do not equate collecting an Operational channel with enabling its generating
policy. Do not enable all high-volume sources blindly during active scoring.

## 7. Prove end-to-end delivery

Use three levels of checks: receiver readiness, forwarder health, then a newly
generated event searchable centrally. Only the third proves that source's path.

### A. Debian readiness and scoring

```bash
sudo systemctl is-active Splunkd
sudo ss -ltnp 'sport = :9997'
sudo /opt/splunk/bin/splunk btool inputs list --debug
sudo /opt/splunk/bin/splunk btool indexes list --debug
sudo tail -n 100 /opt/splunk/var/log/splunk/splunkd.log
```

Adjust the service/home to the values used during setup. Confirm the listener is
`splunkd`, not merely that the port exists. Check Splunk query/login and management
scoring status in the portal after its restart; an active unit alone is insufficient.

### B. Windows service, routing and source checks

```powershell
$uf = 'C:\Program Files\SplunkUniversalForwarder'
Get-Service SplunkForwarder
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
    Select-Object State, StartName, StartMode
Test-NetConnection 172.20.240.20 -Port 9997
& "$uf\bin\splunk.exe" btool outputs list --debug
& "$uf\bin\splunk.exe" btool inputs list --debug
& "$uf\bin\splunk.exe" list forward-server
Get-Content "$uf\var\log\splunk\splunkd.log" -Tail 100 |
    Select-String 'TcpOutputProc|WinEventLog|ERROR|WARN'
```

The active forwarding server should be the intended receiver. The last CLI
operation can prompt for the UF-local Splunk administrator; enter it interactively.
Do not paste its password in chat, reports or a command line.

### C. Generate a unique harmless event on each Windows host

This is an intentional **test write**, not part of audit mode. Run once on each
host and record its marker/time:

```powershell
$marker = "CCDC-FWD-$env:COMPUTERNAME-$([guid]::NewGuid().ToString('N'))"
eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /SO CCDC-Forwarder-Test /D $marker
if ($LASTEXITCODE -ne 0) { throw 'Verification event was not created.' }
$marker
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'CCDC-Forwarder-Test'
    Id = 100
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 | Select-Object TimeCreated, Id, Message
```

The test creates a benign Application event and may register the named event
source. It is not an attack simulation. Keep the marker as deployment evidence.
Do not repeatedly generate events to mask a broken pipeline.

### D. Search centrally for the exact marker

Replace `PASTE_THE_EXACT_MARKER` with the printed value:

```spl
index=wineventlog sourcetype=XmlWinEventLog* earliest=-10m latest=now "PASTE_THE_EXACT_MARKER"
| stats count latest(_time) as newest by host sourcetype
| eval newest=strftime(newest,"%F %T")
```

Expected: at least one result tied to the correct actual host. Investigate an
unexpected host value or duplicate counts; do not rename a scored machine to
make the search look correct. Repeat for all three markers/hosts.

### E. Coverage and parsing checks

```spl
(index=wineventlog OR index=sysmon) sourcetype=XmlWinEventLog* earliest=-15m latest=now
| stats count latest(_time) as newest by host index sourcetype
| eval newest=strftime(newest,"%F %T")
```

```spl
index=mssql sourcetype=ccdc:mssql:errorlog earliest=-15m latest=now
| stats count latest(_time) as newest by host source
| eval newest=strftime(newest,"%F %T")
```

Once XML extraction is verified, authentication coverage can be checked with:

```spl
index=wineventlog sourcetype=XmlWinEventLog:Security earliest=-15m latest=now (EventCode=4624 OR EventCode=4625)
| stats count latest(_time) as newest by host EventCode
| eval newest=strftime(newest,"%F %T")
```

An unparsed XML event can be searchable by raw text while `EventCode` is absent.
Install/verify the compatible Splunk Add-on for Microsoft Windows on the proper
tiers before relying on parsed fields. Do not call ingestion broken solely
because a field-based detection returns nothing.

All searches above scope indexes, sourcetypes and time before the first pipe.
Use actual source activity to judge quiet channels; no Sysmon events may mean
Sysmon is not installed, not that Security/Application forwarding failed.

## 8. Troubleshooting by symptom

Work from source to destination. Preserve relevant errors/config provenance
before changing anything.

| Symptom | Likely layer | First action / safe interpretation |
|---|---|---|
| x86 shell refused | Operator shell | Launch x64 Windows PowerShell/PowerShell 7; verify `Is64BitProcess` |
| UF missing in audit | Installation | Stage/install the approved MSI; audit does not install it |
| Invalid signature/hash | Package trust | Stop; obtain the expected package/hash through the approved channel |
| MSI exit other than 0/3010 | Installation | Inspect vendor installer results; do not rerun endlessly |
| Role/DC mismatch | Wrong host/profile | Verify `DomainRole`; do not force the AD profile onto a workstation |
| No MSSQL engine service | Wrong host/SQL prerequisite | Verify the actual database host and engine service |
| Required event channel unreadable | Permissions/OS | Verify channel locally and elevate; do not silently drop Security |
| Optional Sysmon/DNS/DFS warning | Source not installed | Confirm whether that provider is expected; other channels can still work |
| TCP receiver unreachable | Listener/network | Check Debian first, then route/Windows egress/PA ingress; do not flush firewalls |
| Different existing `defaultGroup` | Existing telemetry routing | Inspect `btool outputs list --debug`; coordinate migration instead of deleting the old output |
| Effective input overridden | Splunk config precedence | Find the winning file with `btool ... --debug`; review the conflicting setting before editing |
| Running UF but no active receiver | Forwarding/protocol | Check `TcpOutputProc` logs, correct address/port and plaintext versus TLS mismatch |
| TCP works but no indexed data | Splunk/source pipeline | Check index existence/enabled state, input selection, service permissions, logs, license and disk health |
| Marker found but `EventCode` missing | Search-time extraction | Validate the Windows add-on/XML knowledge objects |
| SQL path error | Discovery/path/access | Inspect registry `-e` argument; provide actual literal `-SqlLogPath` if needed |
| SQL events absent in 15 minutes | Quiet source/time/access | Check source modification/activity and timestamp; do not restart SQL to manufacture logs |
| SQL events garbled/merged/wrong time | Parsing | Compare raw ERRORLOG encoding, timestamp pattern, multiline behavior and timezone |
| Debian unit inactive/wrong process | Existing Splunk service | Diagnose the correct existing unit/install; receiver script refuses to manage the wrong process |
| Matching app but receiver not listening | Runtime or another override | Inspect current effective settings and `splunkd.log`; matching files are not success |
| Receiver restart/readiness failure | Enterprise runtime | Read apply log, automatic rollback output and systemd journal immediately |
| Scoring degrades after setup | Service availability | Check query/8089 and original scoring paths; stop further changes and use recovery procedure |

Useful focused diagnostics:

```powershell
wevtutil.exe gl Security /f:xml
wevtutil.exe gl "Microsoft-Windows-PowerShell/Operational" /f:xml
auditpol.exe /get /category:*
```

```bash
sudo systemctl status Splunkd --no-pager
sudo journalctl -u Splunkd -n 100 --no-pager
sudo /opt/splunk/bin/splunk btool props list ccdc:mssql:errorlog --debug
```

Read errors rather than treating every warning as malicious. Do not reset a
scoring/central administrator password to fix a UF-local CLI authentication issue.

## 9. Rollback, reruns and recovery limits

### Automatic recovery during a failed Windows apply

For errors inside its apply `try/catch`, the script attempts to:

1. Restore the previous managed app, or remove only its newly created app.
2. Disable only source channels that this run successfully enabled.
3. Restart the old UF configuration if it was previously running, or stop UF if
   this run started a previously stopped service.
4. Restore the previous startup mode when this run changed it.
5. Mark the report `FailedSeeRollbackOutput`, record the original error and rethrow.

These are attempts, not a transaction. A rollback step can fail; inspect any
`ROLLBACK FAILED` output and verify the actual state. The code maps the prior
startup category back to Automatic/Manual/Disabled; do not assume it preserves
every Windows service nuance such as delayed-auto-start metadata.

Installer operations happen before this rollback region and are not undone.
Pre-apply/backup-creation failures may have no `run.json`. Channel prior states
are kept in memory, not completely serialized in that report, so retain audit
output when planning manual restoration.

### Automatic recovery during a failed Debian apply

After its rollback trap is armed for app installation, the script attempts to
restore the saved app's contents. If there was no previous app, it removes its
three new config files. If it attempted a restart, it also attempts to restart
the restored configuration. It exits with failure and prints the backup path.

Early validation/backup/render errors occur before the trap is armed. Once the
script reports success, later service failures or a failed delivery test do not
automatically invoke rollback.

It does not remove index buckets already created/received, undo externally
changed settings, restore a full Splunk installation, or repair licenses/disk.
Removing an index stanza is not permission to delete its stored data.

### Manual recovery after a successful deployment

There is no `-Rollback` or `--rollback` flag. Do not invent one. Use the exact
printed run directory and coordinate with the system owner before restoring.

1. Record the failure time, service/scoring impact and relevant errors.
2. Preserve the current app/config and relevant logs in a protected evidence
   location before replacing anything.
3. Identify the **correct pre-change backup**:
   - Windows: the saved `app/` in the relevant `forwarder-...` run.
   - Debian: the saved `app/` in the relevant `receiver-...` run.
4. If that run had a previous app, restore its exact contents to the same managed
   app path. Avoid copying a backup *inside* the live app as a nested subfolder.
   Recheck ownership/ACLs and merged `btool` settings.
5. If that run created the app from scratch, remove only the deployment's
   identified app/config after preserving it and confirming no later legitimate
   changes must be retained. Do not delete the whole `etc/apps` tree.
6. Restore Windows source-channel and service states from the recorded preflight
   state where appropriate. Do not disable logs that another operator now needs.
7. Restart only the affected Splunk service in an approved window.
8. Verify original scoring behavior, then decide whether to redeploy.

No broad recursive delete/reset/OS reinstallation is part of this playbook.
When uncertain about a backup or later changes, stop and have the system owner
review the recovery scope.

### Rerun behavior

- Windows can create a new backup/report on every approved apply even when no
  service restart is needed.
- A Windows restart is triggered by differing app files, newly enabled channels,
  or UF not already running. A startup-mode-only correction need not restart it.
- Debian can create a new backup/log before determining files match. Matching
  files plus valid effective settings and its owned listener avoid a restart.
- A restart is not a repair for an unresolved higher-precedence configuration.
- Changes to the supplied SQL props file can trigger app changes/restarts even
  on Windows hosts without SQL inputs.
- After editing or redeploying, verify fresh events again. Do not equate
  idempotence with delivery continuity.

## 10. Acceptance checklist and handoff

Mark deployment complete only when all required items are verified:

- [ ] Live topology, actual hostnames and selected profiles recorded.
- [ ] Debian receiver belongs to the expected Splunk process.
- [ ] Required indexes are present/enabled; storage capacity/retention reviewed.
- [ ] AD, MSSQL and Wkst each have a running, Automatic UF service.
- [ ] Intended active forward-server confirmed on each host.
- [ ] A distinct newly generated marker from each host is searchable centrally.
- [ ] Expected Security/Application/operational coverage checked.
- [ ] Sysmon availability explicitly recorded, not assumed.
- [ ] MSSQL text-log path, service read access, source activity and parser checked.
- [ ] Parsed Windows fields validated before field-based detections are trusted.
- [ ] MSSQL SMB/SOP, RDP and SQL; AD WinRM; Splunk query/8089; and ping rechecked.
- [ ] Backups, errors/warnings, transport choice and remaining gaps recorded.
- [ ] No credential or private key added to Git, chat evidence or reports.

Handoff record template:

| System | Actual hostname/IP | Profile / destination | Apply time | Backup/run directory | Marker / receipt time | Scoring result | Open gaps / owner |
|---|---|---|---|---|---|---|---|
| Debian | Fill in | Receiver | Fill in | Fill in | Listener ready time | Fill in | Fill in |
| AD | Fill in | AD / receiver | Fill in | Fill in | Fill in | Fill in | Fill in |
| MSSQL | Fill in | MSSQL / receiver | Fill in | Fill in | Fill in | Fill in | Fill in |
| Wkst | Fill in | Wkst / receiver | Fill in | Fill in | Fill in | Fill in | Fill in |

Deployment evidence belongs in a protected operational record. For an actual
incident, use the team's incident-report template and distinguish observed facts
from assumptions. Do not create an incident merely because an optional event
provider is absent.

## 11. Offline tests and what remains unverified

From the repository root:

```powershell
.\splunk\Test-WindowsForwarder.ps1
```

```bash
bash splunk/test-debian-receiver.sh
```

The Windows tests parse/render config, use a temporary fixture, and mock discovery,
event-log commands, network, ACL and service operations for audit/apply/rollback
checks. They do **not** restart real Windows services. Use x64 for those
entry-point tests; an x86 test run covers parser/rendering only and warns.

The Bash tests validate syntax, sample config generation and argument rejection
without changing a real Splunk installation.

Offline checks do not prove MSI behavior, actual UF service read rights, live
Enterprise restart/rollback, installed-version event subscription semantics,
SQL rotation/encoding, add-on field extraction, firewall reachability or receipt
from the three competition VMs. The live acceptance checklist above is mandatory.
