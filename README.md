# CCDC Windows Defense and Splunk Operator Guide

This repository contains host audit/hardening tools and a packet-specific Splunk
deployment workflow. For your assignment, prioritize **AD Windows, MSSQL Windows,
and the Windows workstation forwarding to Debian Splunk**. Collect and verify
telemetry before making unrelated authentication or firewall changes.

**Start here:** [Detailed Windows-to-Debian Splunk playbook](splunk/PLAYBOOK.md).
It explains every deployment stage, the files and services changed, every
parameter, expected results, troubleshooting, rollback boundaries, and handoff.

## Guide map

| Need | Read |
|---|---|
| Deploy telemetry on your three assigned Windows hosts | [Your deployment order](#your-deployment-order) |
| Understand exactly what the forwarding scripts do | [Detailed Splunk playbook](splunk/PLAYBOOK.md) |
| Review scoring and recovery precautions | [Safety rules](#safety-rules) |
| Use general Windows audits and role tools | [Windows](#windows) |
| Use Linux host-hardening tools | [Linux](#linux) |
| Use Splunk deployment commands or the older generator | [Splunk forwarding and configuration](#splunk-forwarding-and-configuration) |
| Check the toolkit without changing scored services | [Tests and validation](#tests-and-validation) |
| Review the five standalone hardening modules | [Standalone hardening modules](#standalone-hardening-modules-windowslib) |

## Your deployment order

The packet's page 13 inventory is the starting point, not a substitute for checking
the live NETLAB/portal values:

| Order | Host | Internal address | Action |
|---|---|---|---|
| 1 | Debian 12 / Splunk 10.0.2 | `172.20.240.20` | Audit and configure the existing receiver |
| 2 | AD / Windows Server 2022 | `172.20.240.100` | Configure profile `AD`, prove receipt |
| 3 | MSSQL / Windows Server 2019 | `172.20.240.120` | Configure profile `MSSQL`, prove event and SQL log receipt |
| 4 | Windows 11 workstation | DHCP | Configure profile `Wkst`, prove receipt |

1. Record current hostnames, addresses, service health, and scoring results.
2. Coordinate one possible Splunk restart with the Debian operator.
3. Audit/configure the receiver before changing any forwarder.
4. Audit/configure one Windows host at a time using **x64 elevated PowerShell**.
5. Generate a harmless verification event on each host and find it in Splunk.
6. Recheck scored services and record the backup location and verification time.

The scripts do not install Sysmon or enable all source audit policies. A running
forwarder is not proof of collection; an open TCP port is not proof of delivery.
See the [acceptance checklist](splunk/PLAYBOOK.md#10-acceptance-checklist-and-handoff).

**Do not run auto-hardening as a prerequisite for forwarding.** Your packet scores
MSSQL SMB/SOP access, RDP and SQL, AD WinRM, Splunk queries/8089, and ping.
Keep those functional. The packet also prohibits restricting public services
to scoring-only source addresses.

## Safety Rules

- Entry points have different apply models; do not assume one switch applies to all scripts. The Windows first-hour script applies selected categories by default; use `-PlanOnly` to preview them. Windows role scripts require `-Apply`, and Linux hardening scripts require `--apply`. Splunk setup instead applies after confirmation unless audit mode is selected, and requires explicit plaintext-transport approval.
- A plan-only run is not a substitute for checking the target service and scoring requirements. Review the plan and report before applying.
- Use a permitted backup/recovery method before apply. The Invitational packet says snapshot/scrub recovery is not available during the event; do not plan around reverting a competition VM. Practice on disposable snapshots outside competition. Windows System Restore points are client-only and are not available on Server; Linux firewall apply has an automatic timed rollback only on systemd hosts.
- Keep console access or a tested out-of-band recovery path. Firewall, authentication, TLS, account policy, and service changes can interrupt scoring or administration.
- Do not put real passwords, private keys, or other secrets in command lines, reports, or version control. Password rotation writes generated passwords to a restricted report file; protect and remove that file after securely recording the credentials.
- The Windows scripts target Windows PowerShell 5.1-compatible syntax. Linux scripts require Bash and the listed system tools. Run scripts from a trusted, administrator-controlled copy.

## Windows

Run from an elevated Windows PowerShell 5.1 session. The role scripts load shared files from `windows\lib`; copy the entire `windows` directory and preserve its layout.

### One-command auto-hardening

**Not the starting point for this team packet.** This tool can scope scored
management services to local/admin ranges. Review the packet's public-service
requirements and every planned category before considering apply.

Entry point: `windows\auto-harden.ps1` (elevated PowerShell). It detects the host (domain controller, IIS web, IIS FTP, workstation) and applies every applicable category without prompting: account policy, legacy protocols, USB storage, and a host firewall scoped to the local subnet(s), plus the matching role script switches. Each step runs separately, so one failure does not stop the rest.

```powershell
.\windows\auto-harden.ps1              # apply everything applicable
.\windows\auto-harden.ps1 -PlanOnly    # preview only
.\windows\auto-harden.ps1 -SkipFirewall -SkipUsb
```

Not automatic: password rotation, scheduled-task disabling, and `-RequireFtpTls` (needs a certificate). Take a snapshot first; a reboot may be required.

### General first-hour audit and hardening

Entry point: `windows\first-hour.ps1`

Audit only:

```powershell
.\windows\first-hour.ps1
```

Plan selected changes without applying:

```powershell
.\windows\first-hour.ps1 -PlanOnly -SetAccountPolicy -DisableLegacyProtocols -DisableUsbStorage
```

Example apply (replace every example value with the actual environment values first). The selected categories apply even without `-Apply`; it remains accepted for backward compatibility:

```powershell
.\windows\first-hour.ps1 -Apply -SetAccountPolicy -EnforceHostFirewall -ManagementRange '10.20.30.0/24' -DisableUsbStorage
```

Options:

- Supplying any change-category switch applies the selected categories by default. With no category switches, the script remains audit-only.
- `-PlanOnly`: report the selected changes without applying them. Cannot be combined with `-Apply`.
- `-Apply`: explicit apply mode retained for backward compatibility. High-impact operations use PowerShell `ShouldProcess` confirmation; `-WhatIf` can be used to preview ShouldProcess actions.
- `-SetAccountPolicy`: configure local policy on standalone hosts or the AD default domain policy on a domain controller/domain-joined host. Domain mode requires RSAT ActiveDirectory tools. Review domain-wide impact first.
- `-EnforceHostFirewall -ManagementRange CIDR`: set Windows Firewall inbound defaults to Block and allow discovered listeners; RDP/WinRM access is scoped to supplied management ranges. Provide the actual admin range or remote management may be lost.
- `-DisableLegacyProtocols`: disable SMBv1, LLMNR, and NetBIOS over TCP/IP. Some changes may need a reboot.
- `-DisableUsbStorage`: disable the USB mass-storage driver; it does not block every USB device class.
- `-KillPersistence -DisableTask '\TaskPath\TaskName'`: disable only exact named scheduled tasks. Repeat `-DisableTask` for multiple tasks; built-in Microsoft tasks are refused.
- `-RotatePasswords -IncludeAccount NAME -ExcludeAccount scoring,breakglass`: rotate only explicitly selected local accounts. Use at least two distinct exclusions for scoring/service/break-glass accounts. Supply a comma-separated array, not repeated `-ExcludeAccount` parameters. Each selected account is rechecked for service/task use and requires typed confirmation.
- `-RotateBuiltInAdministrator`: also permits rotating the built-in Administrator, only when explicitly included; it is processed last.
- `-AllowPasswordRerotation`: manually override the one-shot rotation ledger; requires a second typed confirmation.
- `-InstallSysmon -SysinternalsPath PATH -SysmonConfig FILE`: install or update Sysmon using a valid XML config. The script checks that the binary has a valid Microsoft signature and verifies the service after apply. Sysmon is not installed unless this switch is given.
- `-SysinternalsPath PATH`: optionally run available signed `autorunsc`, `tcpvcon`, `logonsessions`, `psloggedon`, `pipelist`, and `sigcheck` tools during the baseline snapshot. Stage and verify the Sysinternals Suite in advance; missing tools are skipped.
- `-SkipRestorePoint`: skip before/after restore point attempts on supported client Windows. On Windows Server, take a VM snapshot and use this switch if running this general script with apply options.
- `-ReportDirectory PATH`: change the default report location (`%LOCALAPPDATA%\CCDC\Reports`).

Password rotation example for plan-only mode (replace names; do not assume these are safe targets):

```powershell
.\windows\first-hour.ps1 -PlanOnly -RotatePasswords -IncludeAccount 'localadmin' -ExcludeAccount 'scoring','breakglass'
```

### Role scripts

Each role script is audit-only without `-Apply` and a category switch. Run from the repository root as shown, or from any location using the script's full path. Server roles require a VM snapshot before apply; restore points do not work on Windows Server.

| Script | Intended host | Available apply categories |
| --- | --- | --- |
| `windows\addns\harden-addns.ps1` | AD/DNS, Windows Server 2019 | `-SecureDnsZones`, `-HardenDcAuth`, `-DisableSpooler`, `-EnableAuditPolicy` |
| `windows\webserver\harden-webserver.ps1` | IIS web server, Windows Server 2019 | `-DisableDirectoryBrowsing`, `-HideServerHeader`, `-HardenTls`, `-EnableAuditPolicy` |
| `windows\ftpserver\harden-ftpserver.ps1` | IIS FTP, Windows Server 2022 | `-DisableAnonymousFtp`, `-RequireFtpTls`, `-EnableFtpLogging`, `-HardenTls`, `-EnableAuditPolicy` |
| `windows\workstation\harden-workstation.ps1` | Windows 11 workstation | `-HardenCredentials`, `-EnablePowerShellLogging`, `-DisableAutorun`, `-EnableDefender`, `-EnableAuditPolicy` |

Audit and plan examples:

```powershell
.\windows\addns\harden-addns.ps1
.\windows\webserver\harden-webserver.ps1 -DisableDirectoryBrowsing
.\windows\ftpserver\harden-ftpserver.ps1 -DisableAnonymousFtp
.\windows\workstation\harden-workstation.ps1 -HardenCredentials -EnableDefender
```

Apply examples (only after reviewing the plan and taking a VM snapshot):

```powershell
.\windows\addns\harden-addns.ps1 -Apply -SecureDnsZones -AllowedZoneTransferServer '10.20.30.10'
.\windows\webserver\harden-webserver.ps1 -Apply -DisableDirectoryBrowsing
.\windows\ftpserver\harden-ftpserver.ps1 -Apply -DisableAnonymousFtp
.\windows\workstation\harden-workstation.ps1 -Apply -EnablePowerShellLogging
```

Role-specific cautions:

- **AD/DNS:** apply refuses on a non-domain-controller. `-SecureDnsZones` may change dynamic update and zone transfer behavior. `-HardenDcAuth` changes LDAP signing, secure channel enforcement, anonymous restrictions, and NTLM compatibility; test domain logons, LDAP clients, and scoring immediately.
- **Web:** IIS/WebAdministration is required for IIS settings. `-ExtraWebRoot` can add a non-IIS web root for content and ACL inspection. `-HardenTls` disables legacy TLS/SSL protocols and needs a reboot; ensure the scoring clients support TLS 1.2.
- **FTP:** IIS FTP/WebAdministration is required for IIS FTP settings. `-ExtraFtpRoot` adds another FTP root for content and ACL inspection. `-RequireFtpTls` requires a bound certificate and FTPS-capable scoring clients; it can break plain FTP logins.
- **Workstation:** restore points are attempted before and after apply unless `-SkipRestorePoint` is given. Credential protection, PowerShell logging, AutoRun, Defender, and audit policy are independent switches.
- All role scripts accept `-ReportDirectory PATH`. They write role logs and a before baseline; apply runs also write an after baseline. They use the same `ShouldProcess`/confirmation model as the general script.

### Windows shared library

Most files in `windows\lib` define shared functions used by the entry points;
do not run those helpers directly. The five explicitly named
[standalone modules](#standalone-hardening-modules-windowslib) are exceptions.
Keep the whole directory with its scripts when copying or staging the toolkit.

## Linux

### Linux first-hour audit and hardening

Entry point: `linux/first-hour.sh`. Requires Bash. Run from the repository root or invoke by absolute path.

Audit only:

```bash
bash scripts/linux/first-hour.sh
```

Plan-only examples:

```bash
bash scripts/linux/first-hour.sh --set-account-policy
bash scripts/linux/first-hour.sh --apply-host-firewall --management-cidr 10.20.30.0/24
```

Useful options:

- `--apply`: execute requested changes. Must run as root. Destructive/lockout-sensitive actions require interactive typed confirmation.
- `--set-account-policy`: plans or applies Debian/Ubuntu PAM password quality, history, faillock, and login.defs settings. Apply requires `pam_pwquality`, `pam_faillock`, a recognized Debian PAM layout, root, and an interactive terminal; it backs up files and verifies changes. Fedora/RHEL/Oracle Linux PAM changes are intentionally refused by this path.
- `--apply-host-firewall --management-cidr CIDR`: audit or apply a host nftables firewall. Repeat `--management-cidr` for multiple ranges. Requires `ss`, `nft`, Python 3, and for apply: root, systemd, `systemd-run`, an interactive terminal, and a successful nft syntax check. A rollback timer is armed before applying.
- `--disable-smbv1`: if Samba is installed, requires `crudini` and `testparm`, and asks for typed confirmation before changing Samba settings.
- `--kill-persistence --remove-unit UNIT --remove-cron-file /etc/cron.d/FILE`: targets only explicitly named systemd units and regular non-symlink files under `/etc/cron.d`. Repeat target options as needed. Apply disables/masks units or removes the named cron files after confirmation.
- `--rotate-passwords --include-account NAME --exclude-account NAME --exclude-account NAME`: rotate selected eligible local interactive accounts. At least one include and two distinct exclusions are required. Apply requires root, an interactive terminal, `openssl`, and `chpasswd`; it asks for typed confirmation and writes a protected credential file.
- `--allow-rerotate`: explicit override of the one-shot password rotation ledger; use only after manual review and confirmation.
- `--report-dir PATH`: change report/backup directory. Default is `$CCDC_REPORT_DIR` if set, otherwise `./ccdc-reports`.
- `--help`: print the script's usage summary.

Apply examples (use only after validating the plan and values):

```bash
sudo bash scripts/linux/first-hour.sh --apply --set-account-policy
sudo bash scripts/linux/first-hour.sh --apply --apply-host-firewall --management-cidr 10.20.30.0/24
```

The host-firewall mode discovers listener ports and creates rules to allow them; it scopes SSH port 22 to the management CIDRs. Do not assume the discovered listeners are safe or that the CIDR is correct. Confirm scoring and management connectivity before keeping the firewall rules.

### Standalone Linux firewall script

Entry point: `linux/apply-firewall.sh`. It uses `config/firewall.example.json` by default. Replace every `REPLACE_` placeholder and validate scoring/admin ranges and service ports before applying.

```bash
sudo bash scripts/linux/apply-firewall.sh --help
sudo bash scripts/linux/apply-firewall.sh --config config/firewall.example.json
```

The second command validates the config, generates nftables rules under `/run`, and checks syntax; it does not apply rules. Apply only after editing and reviewing the config:

```bash
sudo bash scripts/linux/apply-firewall.sh --apply --config config/firewall.example.json
```

Apply requires root, `nft`, Python 3, a running systemd manager, and an interactive terminal. The script arms the configured rollback timer before applying. It defaults to drop for inbound and outbound traffic, so incomplete allowlists can break services or access. Keep the rollback armed until scoring and administration are verified. To keep the rules after verification, the script prints the exact systemd timer/service command; to roll back immediately, it prints the nft delete command.

### PAM helper

`linux/pam_policy.py` is called by `first-hour.sh`; normally do not invoke it directly. It can be used for fixture-based testing with `--root` pointed at a disposable tree and a fresh `--backup-dir`. It edits only the listed PAM/login.defs files, rejects unrecognized PAM layouts and symlinked files, creates backups, verifies edits, and attempts rollback on failure.

## Splunk forwarding and configuration

For your assigned machines, use [Set-WindowsForwarder.ps1](splunk/Set-WindowsForwarder.ps1)
and [setup-debian-receiver.sh](splunk/setup-debian-receiver.sh).
The [full playbook](splunk/PLAYBOOK.md) is the authoritative step-by-step operator
procedure for those scripts; the commands below are a shorter reference.

### Older configuration generator

This is a separate workflow, not a required step for the packet-specific scripts.
Do not layer its configs onto the new apps without reviewing precedence and
duplicate collection.

`splunk/generate-configs.py` reads `config/splunk.json` and writes deployment artifacts into `generated/splunk/`. It does not install or deploy them.

1. Set `indexer_host`, `indexer_port`, `time_window`, and exactly the required index names in `config/splunk.json`.
1. From the repository root, run:

```bash
python scripts/splunk/generate-configs.py
```

1. Review the generated files: `outputs.conf`, `windows-inputs.conf`, `linux-inputs.conf`, `indexes.conf`, and `first-hour-searches.md`.
1. Deploy each file to the appropriate Splunk forwarder/indexer configuration location for your environment, then restart/reload Splunk according to your deployment process.
1. Verify indexes, sourcetypes, event channels, and field extractions using real events before enabling searches or alerts. The egress query requires normalized flow data; the USB query requires forwarded Windows device-event channels.

The generator validates indexer host/port, time window and index names. Generated searches include index, sourcetype, and time constraints before the first pipe.

### Team-packet deployment: AD / MSSQL / Windows workstation -> Debian Splunk

The 2026 Midwest Invitational team packet (VM table, page 13) lists:

| Your systems | OS | Internal address | Forwarding profile |
|---|---|---|---|
| AD | Windows Server 2022 Standard | `172.20.240.100` | `AD` |
| MSSQL | Windows Server 2019 Standard | `172.20.240.120` | `MSSQL` |
| Windows workstation | Windows 11 | DHCP | `Wkst` |
| Receiving Splunk server | Debian 12 / Splunk 10.0.2 | `172.20.240.20` | Existing Splunk Enterprise |

These are packet defaults, not proof of the live topology. Confirm the NETLAB/portal
values before applying. Use the internal Splunk address, not a team-number-derived
public/NAT address. Nothing here changes hostnames, addresses, users or passwords.
These scripts live entirely in this repository; they do not depend on the older
generator's parent-folder `config/` or `generated/` directories.

**Scoring guardrails from pages 14-17:** preserve MSSQL SMB (including planted SOP
files), RDP/3389, SQL/1433 and their authentication; AD WinRM; Splunk queries and
management/8089; and ping. The packet prohibits source-IP knife-edge filtering of
public services. Do not blindly run the older generic firewall or account-rotation
scripts on these systems. In particular, do not disable SMB on MSSQL or scope
scored RDP/WinRM to only team management IPs. These forwarding scripts do not touch
those rules or rotate any accounts.

#### 1. Prepare the existing Debian Splunk receiver first

Detailed behavior and failure handling:
[Debian receiver procedure](splunk/PLAYBOOK.md#4-debian-receiver-procedure).

Copy the `splunk/` directory to Debian. Splunk Enterprise is already supplied by
the packet; this script does **not** reinstall it, change licenses, reset its
administrator/scoring accounts, or replace its configuration.

```bash
cd splunk
# Inspect the existing unit name first; it might be splunk instead of Splunkd.
systemctl list-unit-files --type=service | grep -i splunk
sudo bash setup-debian-receiver.sh --audit-only --service Splunkd
sudo bash setup-debian-receiver.sh --allow-plaintext --service Splunkd
```

Default home is `/opt/splunk`; override with `--splunk-home` if needed. The script
verifies that the selected unit actually runs that installation's `splunkd`.
It creates a dedicated `etc/apps/ccdc_windows_receiver/local/` app with the TCP
9997 receiver, missing `wineventlog`, `sysmon`, `mssql` indexes and the custom SQL
ERRORLOG parsing settings. Existing index storage/retention is preserved.
It validates effective configuration, restarts **only Splunk** when app files
change, then checks that the Splunk process owns the listening port. Failed
apply attempts restore its previous app and attempt to restart the previous config.

**Schedule the initial restart:** queries and port 8089 may be briefly unavailable
during it. Repeat runs with identical settings do not restart. Backups and apply
logs default to `/var/log/ccdc-splunk`; override `--output-directory`. Audit mode
does not create reports or directories. Review disk space and index retention
after deployment; this is not an index-capacity sizing tool.

**Transport:** this baseline uses **unencrypted TCP**, not TLS. Both scripts
require explicit plaintext approval to apply. ACKs are not encryption or sender
authentication. Use this only where approved for the internal competition network.
For TLS requirements, provision certificates and a matching Splunk TLS receiver/
forwarder configuration instead; these scripts do not configure TLS.

No firewall is changed automatically. If necessary, coordinate Windows egress and
Debian/PA ingress for TCP 9997. Do not flush firewall rules or restrict scored
public services to particular source IPs.

#### 2. Install/configure each Windows forwarder

Detailed behavior, parameter reference, and role differences:
[Windows procedure](splunk/PLAYBOOK.md#5-windows-forwarder-procedure).

Use **x64 elevated Windows PowerShell 5.1 or x64 PowerShell 7**. Copy the complete
`splunk/` directory to each Windows host. Stage a Splunk Universal Forwarder x64
MSI approved for the server version (10.0.x for this packet unless organizers say
otherwise); never use an unpinned download. The script can launch the vendor
installer interactively when UF is missing. It verifies the Splunk signature and,
if `-InstallerSha256` is supplied, the approved hash. It does not silently pass a
password to `msiexec`, generate a password file, or accept a license for you.

In the installer, use the expected install directory
`C:\Program Files\SplunkUniversalForwarder`, grant the service the required event-log
read privileges, and set a unique **UF-local** administrator password. Local System
is simplest for the competition lab, especially for DC Security logs; a
least-privilege service identity requires explicit verification of channel and SQL
file read access. Do not use a domain administrator or scoring password.
Do not configure a separate forwarding destination/deployment server in the wizard;
this script will configure the destination. `-Force` skips script confirmation,
**not** the interactive installer.

From the repository root on the appropriate machine:

```powershell
# AD host (172.20.240.100)
.\splunk\Set-WindowsForwarder.ps1 -Role AD -AuditOnly
.\splunk\Set-WindowsForwarder.ps1 -Role AD -AllowPlaintext

# MSSQL host (172.20.240.120)
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -AuditOnly
.\splunk\Set-WindowsForwarder.ps1 -Role MSSQL -AllowPlaintext

# Windows 11 workstation (DHCP)
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -AuditOnly
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -AllowPlaintext

# If UF is not installed yet, supply the ACTUAL staged installer filename:
$msi = 'C:\Staging\splunkforwarder-approved-x64.msi'
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -InstallerPath $msi -AllowPlaintext
```

All three profiles default to `172.20.240.20:9997`; override `-Indexer`/`-Port` if
the portal changes. `-AuditOnly`/`-PlanOnly` and `-WhatIf` make no configuration or
service changes. Apply requires confirmation unless `-Force` is supplied.
If UF is missing, audit reports that prerequisite rather than installing anything.
Apply refuses an unreachable receiver. The app is backed up before editing;
effective `btool` settings are checked for overrides; only the `SplunkForwarder`
service is started/restarted and set to Automatic. No OS reboot is initiated.
Apply attempts create an ACL-restricted backup and `run.json` under
`%ProgramData%\CCDC\Splunk`; use `-OutputDirectory` to override.
Rollback restores the app, channel enabled states and service startup mode;
it does not uninstall an MSI installed earlier in the run.

**Collected sources:**
- All roles: Security, System, Application, classic/operational PowerShell,
  Task Scheduler, WMI activity, Defender, RDP and Sysmon (if installed).
- AD additionally: Directory Service, DNS Server, DFS Replication when available.
- Workstation additionally: device setup/driver channels when available.
- MSSQL additionally: text ERRORLOG paths discovered from SQL instance startup
  parameters, or explicit `-SqlLogPath 'C:\path\ERRORLOG'` (array supported).
  File events use `index=mssql sourcetype=ccdc:mssql:errorlog`.
  Binary `.xel`/`.trc` files are not monitored as text.

Missing optional channels are reported and skipped. Existing disabled channels
selected for collection are enabled during apply. New event subscriptions start
at **newest** to avoid a historical-event flood; subsequent reads use checkpoints.
SQL ERRORLOG monitoring can ingest existing file content initially. No wildcard
monitor recursively scans an entire SQL installation.

The script does **not** install Sysmon, turn on SQL Server Audit, alter SQL login
auditing, or change domain audit policy. Forwarding cannot create events that
the source never generates. Event 4104 needs Script Block Logging enabled; 4688
needs Process Creation auditing; Sysmon events need Sysmon installed/configured.
SQL ERRORLOG/Application logs are not a record of every SQL statement.
Install/verify the compatible Splunk Add-on for Microsoft Windows on the proper
search/parsing tiers for XML field extraction. Verify `EventCode` and account
fields on actual events before relying on detections. Check the custom SQL
timestamp, multiline and character-encoding behavior on an actual ERRORLOG.

If existing `defaultGroup` forwards elsewhere, the script refuses to silently
replace it. Inspect `btool outputs list --debug` and coordinate an explicit
migration, especially if existing data is scored. Likewise review any
higher-precedence `system/local` or deployment-server settings before removing
them. Do not blindly overwrite existing `inputs.conf`/`outputs.conf`.

#### 3. Prove end-to-end receipt (not just a green service)

Expected results and troubleshooting:
[Verification procedure](splunk/PLAYBOOK.md#7-prove-end-to-end-delivery) and
[troubleshooting matrix](splunk/PLAYBOOK.md#8-troubleshooting-by-symptom).

On each Windows host, after installation/configuration:

```powershell
$uf = 'C:\Program Files\SplunkUniversalForwarder'
Get-Service SplunkForwarder
Test-NetConnection 172.20.240.20 -Port 9997
& "$uf\bin\splunk.exe" btool outputs list --debug
& "$uf\bin\splunk.exe" btool inputs list --debug
& "$uf\bin\splunk.exe" list forward-server
# Last command may prompt for the UF-local Splunk administrator; no -auth user:pass.
Get-Content "$uf\var\log\splunk\splunkd.log" -Tail 100 |
    Select-String 'TcpOutputProc|ERROR|WARN|WinEventLog'
```

In Splunk Search on Debian, confirm all three **actual Windows hostnames** appear
with recent timestamps (the script preserves hostnames):

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

For a harmless, explicit delivery test, run on each Windows host:

```powershell
eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /SO CCDC-Forwarder-Test /D "CCDC forwarding verification"
```

Then search:

```spl
index=wineventlog sourcetype=XmlWinEventLog* earliest=-10m latest=now "CCDC forwarding verification"
| stats count latest(_time) as newest by host
```

Only treat deployment as verified once a newly generated event from each host is
searchable. If field extraction is configured, also verify parsed `EventCode=100`.
No fresh SQL log messages may mean no results in the SQL query, not necessarily
broken forwarding; compare source activity, service permissions and `splunkd.log`.
Keep scored Splunk query/8089 checks green after the initial receiver restart.

Offline checks (no target services changed):

```powershell
.\splunk\Test-WindowsForwarder.ps1
```

```bash
bash splunk/test-debian-receiver.sh
```

## Tests and validation

For the Splunk workflow, use the included offline tests from the repository root:

```powershell
.\splunk\Test-WindowsForwarder.ps1
```

```bash
bash splunk/test-debian-receiver.sh
```

The Windows test uses fixture files and mocked system operations to exercise
rendering, audit, fail-closed checks, repeat apply and rollback. The Bash test
checks syntax, rendering and invalid arguments. Neither proves MSI installation,
live Debian receiver startup, event-read permissions, SQL parsing, or VM-to-indexer
delivery. The older broader test runner is not present in every checkout; do not
assume an external `tests/` tree was included. Practice on matching noncompetition
VMs before applying to scored systems.

For Linux, first run `bash -n scripts/linux/first-hour.sh scripts/linux/apply-firewall.sh`, then use an isolated VM matching the target distribution for audit/plan tests. PAM policy is distribution-specific, and nftables apply should only be exercised with console access and rollback verified.

After changes, inspect the report directory specified for the run. Reports may contain sensitive account, host, service, task, or configuration information; restrict access and handle them as sensitive operational data.

## Extra hardening switches (first-hour.ps1)

These apply by default when selected. Add `-PlanOnly` to preview. Each change is logged as `CHANGE` and verified after writing.

| Switch | What it does | What can break |
|---|---|---|
| `-RequireSmbSigning` | Runs `Set-SmbServerConfiguration` and `Set-SmbClientConfiguration` with `-RequireSecuritySignature $true`, then re-reads both and fails if either is not required. | Old SMB clients, NAS devices, and unsigned third-party SMB tools can no longer connect. |
| `-DisableSpooler` | Stops the Print Spooler service and sets it to Disabled, then verifies the startup type. Skipped if already stopped and disabled. Removes the PrintNightmare attack surface. | Printing stops until you run `Set-Service Spooler -StartupType Automatic; Start-Service Spooler`. |
| `-ScopeSystemPorts` | Used with `-EnforceHostFirewall`. Allow rules for SMB/RPC/system ports (135, 137-139, 445, 5040, 5050, 5353, 7680, 1900, 3702) and dynamic RPC ports (49152+) use `-ManagementRange` as the remote address instead of `Any`. Rules for 3389, 5985 and 5986 were already scoped. | Machines outside the management range cannot reach those ports. Set `-ManagementRange` correctly first. |

`auto-harden.ps1` enables `-RequireSmbSigning` and `-DisableSpooler` on every role, and `-ScopeSystemPorts` on non-servers only. Use `-KeepSpooler` to skip the Spooler change.

## Passwords and what to watch for

### Passwords
Nothing rotates passwords automatically, so `auto-harden.ps1` never generates any. To rotate:

```powershell
.\windows\first-hour.ps1 -RotatePasswords -IncludeAccount kali -ExcludeAccount scoring,breakglass
```

- At least one `-IncludeAccount` and two `-ExcludeAccount` values are required, and you must type a confirmation.
- New passwords are written to `%LOCALAPPDATA%\CCDC\Reports\rotated-credentials-<stamp>.txt` (for example `C:\Users\kali\AppData\Local\CCDC\Reports`). The file is readable only by the current user and SYSTEM. A `password-rotation-ledger.txt` records what was rotated.
- Passwords in the file are obfuscated (XOR + Base64, prefixed `obf:`), so they are not readable at a glance. This is obfuscation, not encryption: anyone with the scripts can decode it. View them on screen with `.\windows\Show-RotatedCredentials.ps1` (latest file, or pass `-Path`). Record them in your team's secure store, then delete the file.
- Rotating the account you are logged in as is risky: write the new password down before logging out. Keep scoring and break-glass accounts excluded.

### After a hardening run
- **Reboot:** required for LSASS protection (RunAsPPL) to take effect.
- **Auto-logon is turned off:** you must know the local account password to sign in again.
- **Scored services:** confirm each still works after the firewall changes. Port 445 inbound is blocked unless allowed explicitly, and system/RPC ports are limited to the management range on workstations.
- **Legacy auth:** LmCompatibilityLevel 5 means NTLMv1 clients fail; SMB signing means old SMB clients fail.
- **Printing:** stops if the Spooler was disabled.
- **Accounts:** `SecAdmin_Local` (the disabled built-in administrator) remains in the local Administrators group; review it.
- **Logs and rollback:** reports, baselines and the firewall `.wfw` backup are in `%LOCALAPPDATA%\CCDC\Reports`, and a restore point is created before changes on workstations.




## Standalone hardening modules (`windows\lib\`)

Each module runs on its own, in PowerShell 5.1 or 7+, as Administrator. All support:
`-AuditOnly` (no changes; reports what would change), `-Force` (skip the typed `APPLY` prompt), `-OutputDirectory <path>` (logs/reports; ACL-locked to SYSTEM + Administrators).
**Always run `-AuditOnly` first**, then apply.

| Script | What it does |
|---|---|
| `harden-credentials.ps1` | Renames built-in Administrator to `SecAdmin_Local` (`-NewAdminName`), disables Guest, optional mass password rotation (`-RotateAllEnabledUsers -ExcludeUsers a,b`), LSA `RunAsPPL=1`, `LmCompatibilityLevel=5`, WDigest off, UAC `EnableLUA=1`/`ConsentPromptBehaviorAdmin=2`, disables PowerShell v2, Defender cloud protection. Rotated passwords go to an AES-256 encrypted `credstore-*.dat` (passphrase prompt); view with `-ShowCredentials`. Never rotates the current user or accounts used by services/password-logon tasks. |
| `disable-legacy-protocols.ps1` | Disables SMB1 (feature + server config), LLMNR, NetBIOS over TCP/IP. Firewall: backs up first (`.wfw`), keeps ICMP echo (v4 and v6) allowed, allows listening scoring ports, scopes RDP/WinRM to `-ManagementSubnets`, then sets all profiles Enabled / inbound Block / outbound Allow. Extra ports: `-AllowTcpPorts`, `-AllowUdpPorts`; `-AllowSmb` keeps 139/445. |
| `harden-ad.ps1` | Domain controllers only. Audits Kerberoastable accounts (SPNs), DES-only accounts and privileged group membership; LDAP signing (`LDAPServerIntegrity=2`) + channel binding (`-LdapChannelBinding`); AES-only Kerberos. `-ResetKrbtgt` does the double reset with typed confirmation (`RESET KRBTGT`, required even with `-Force`). |
| `audit-windows-persistence.ps1` | Sweeps non-Microsoft scheduled tasks, Run/RunOnce, Winlogon, Startup folders, IFEO, WMI subscriptions, services outside System32/Program Files. Enables script block logging (4104) and transcription (`-TranscriptDirectory`). Saves a JSON summary object. |
| `apply-gpo-baselines.ps1` | Backs up and imports a GPO backup with `LGPO.exe /g` (`-GpoBackupPath`, `-LgpoPath`), and sets Defender ASR rules (`-AsrMode Enabled|AuditMode|Warn`). |

Notes:
- "ICMP v4/v5" is implemented as ICMPv4 + ICMPv6 (there is no ICMP v5).
- ASR GUIDs used are the ones Microsoft publishes: LSASS `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`, email executable content `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`, Office child processes `d4f940ab-401b-4efc-aadc-ad5f3c50688a`.
- Reboot needed for RunAsPPL, UAC, SMB1 and PowerShell v2 changes.
- Scoring risks: `LDAPServerIntegrity=2` breaks unsigned LDAP binds; `LmCompatibilityLevel=5` breaks NTLMv1 clients; inbound Block drops any port not listening/allowed.
