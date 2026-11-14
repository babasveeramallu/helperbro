# Seven-machine operator runbooks

[Repository guide](../../README.md) | [Generic service guides](../services/README.md)

Use the README for the machine in front of you, not every command in this
directory. These are operating procedures for **existing competition machines**,
not unattended installers or proof that a live host is secure.

## 1. Pick your machine

| Diagram machine | Dedicated README | Documented defaults, NOT live verification |
|---|---|---|
| Ecom / Rocky Linux | [Rocky e-commerce](ecommerce-rocky/README.md) | Rocky; version, address and application stack unknown |
| Email / Ubuntu Server | [Ubuntu email](email-ubuntu/README.md) | Ubuntu Server; version, address and mail stack unknown |
| Splunk / Debian | [Debian Splunk](splunk-debian/README.md) | Packet: Debian 12, Splunk 10.0.2, `172.20.240.20` |
| AD / Windows | [Windows AD/DNS](ad-windows/README.md) | Packet: Server 2022, `172.20.240.100` |
| MSSQL / Windows | [Windows SQL/SMB/RDP](mssql-windows/README.md) | Packet: Server 2019, `172.20.240.120` |
| Wkst / Ubuntu | [Ubuntu workstation](workstation-ubuntu/README.md) | Ubuntu; version and address unknown; verify DHCP |
| Wkst / Windows | [Windows workstation](workstation-windows/README.md) | Packet: Windows 11, DHCP |

The supplied diagram establishes the seven roles. The existing
[Splunk playbook](../../splunk/PLAYBOOK.md#1-mission-topology-and-scoring-boundaries)
records packet defaults for four of them. The supplied Splunk reference informed
the operational checklist, but its passwords, account-removal assumptions,
version-specific mitigation claims and example addresses are not deployment
authority. Confirm current rules, accounts, products and vendor guidance.

`REPLACE_...` means **stop and supply the real value**. Example addresses are not
scoring-source allowlists. A role label is not necessarily a hostname.

## 2. First-hour order

1. Assign an operator and a console/recovery contact to each host.
2. Record current scoring, service transactions, hostnames, addresses, DNS,
   routes, account dependencies and clock/timezone. Identify existing failures.
3. Use an approved copy of the complete repository. Follow
   [toolkit staging](../services/README.md#obtain-the-toolkit-when-downloads-are-permitted);
   record the approved commit with `git rev-parse HEAD` where Git is available.
   Do not update the copy in the middle of a pending firewall run.
4. Keep a working session and console access. Verify an allowed recovery method;
   the documented packet does **not** provide event-time snapshot/scrub recovery.
5. Bring the existing Debian receiver into a known state, then onboard Windows
   AD, MSSQL and workstation senders one at a time.
6. Inventory Rocky, email and Ubuntu workstation logging separately. The Windows
   forwarder and Debian receiver scripts do not install Linux senders.
7. Prove a fresh event from each onboarded host is searchable. Record gaps.
8. Select one approved hardening category, preview it, apply it, verify actual
   functionality and log receipt, then record its rollback details.
9. Keep an independent operator watching scoring while changes are in progress.

Do not run auto-hardening just to obtain logs. Do not rename hosts/accounts,
replace routes, expire passwords or reboot as an undocumented shortcut.

## 3. Where and how commands run

- Start every machine README at the **repository root**. Keep `windows/lib`,
  `splunk/WindowsForwarder.Common.ps1` and bundled configuration files with their
  entry points. A copied single script may be incomplete.
- Bash blocks run on the named Linux machine, not in Windows PowerShell.
- PowerShell blocks run on the named Windows machine. Use elevated **x64**
  Windows PowerShell 5.1 or x64 PowerShell 7 for forwarding/packet firewall.
  Windows modules must actually be available; syntax compatibility is not proof
  that every module works identically on every OS/PowerShell version.
- Commands marked **APPLY**, configuration edits, verification-event creation,
  installations and restarts are writes. They are never prerequisites for simply
  reading these documents.
- Read command errors. Missing tools or denied access mean incomplete inspection,
  not a healthy host. Do not suppress a failure and continue hardening.

### Execution modes are deliberately different

| Entry point | Inspection / preview | What authorizes writes | Audit artifacts |
|---|---|---|---|
| [Windows first-hour](../../windows/first-hour.ps1) | No categories = audit; categories plus `-PlanOnly` = preview | Selecting a category **without `-PlanOnly` applies it**; `-Apply` is also accepted | Creates protected log/baseline files |
| [Windows role scripts](../../windows/workstation/harden-workstation.ps1) | Omit `-Apply`; category switches then describe a plan | `-Apply` plus selected category | Creates protected reports/baselines |
| [Windows packet firewall](../../windows/Set-PacketFirewall.ps1) | `-AuditOnly` / `-PlanOnly`; elevated | Omit audit and confirm; independent timer required | Audit creates no run directory/task |
| [Windows forwarder](../../splunk/Set-WindowsForwarder.ps1) | `-AuditOnly` / `-PlanOnly` | Confirm apply and supply `-AllowPlaintext` for this baseline | Audit creates no script backup/report |
| [Linux first-hour](../../linux/first-hour.sh) | Omit `--apply` | `--apply` plus selected categories; sensitive steps have typed prompts | Writes protected report; firewall preview also writes `/run` rules and checks syntax |
| [Standalone Linux firewall](../../linux/apply-firewall.sh) | Omit `--apply`; root still required | `--apply`, reviewed JSON and typed prompt | Preview writes `/run/ccdc-first-hour.nft` |
| [Debian receiver](../../splunk/setup-debian-receiver.sh) | `--audit-only` / `--plan-only` | Omit audit, supply `--allow-plaintext`, type `APPLY` | Audit creates no script reports/backups |
| [Five standalone Windows modules](../../README.md#standalone-hardening-modules-windowslib) | `-AuditOnly` | Default non-audit mode; typed `APPLY` unless `-Force` | Audit still creates protected reports |
| [Windows auto-hardener](../../windows/auto-harden.ps1) | `-PlanOnly` | Default invocation applies many categories without individual confirmation | Reports per invoked step |

`-WhatIf` is not a universal sandbox. Discovery and report creation can still
occur, and scripts have different confirmation boundaries. Prefer their explicit
audit/plan modes and do not assume one script's flags work on another.

## 4. Ports, scoring and dependencies

The supplied scoreboard confirms these **19 check names across five server
roles**. Its `ecomm` prefix maps to the diagram's Ecom machine and `webmail` to
the Email machine; these prefixes do not establish actual hostnames or addresses.

| Machine | Exact scored checks visible in the supplied scoreboard |
|---|---|
| AD / Windows | `ad-dns`, `ad-ping`, `ad-winrm` |
| Ecom / Rocky | `ecomm-http`, `ecomm-ping` |
| MSSQL / Windows | `mssql-mssql`, `mssql-ping`, `mssql-rdp`, `mssql-smb` |
| Splunk / Debian | `splunk-chrony`, `splunk-mgmt`, `splunk-ping`, `splunk-query`, `splunk-ssh` |
| Email / Ubuntu Server | `webmail-imap`, `webmail-interactive`, `webmail-ping`, `webmail-smtp`, `webmail-ssh` |
| Ubuntu workstation | No workstation check shown |
| Windows workstation | No workstation check shown |

This confirms **which checks exist**, not their exact ports, credentials,
transactions, source addresses or current health. Red/green history is not a
live diagnosis. Confirm the current portal definitions before changing access.

| Role | Port/protocol candidates to verify against those definitions |
|---|---|
| E-commerce | HTTP usually TCP 80; verify vhost, path, content and any HTTPS redirect/dependency |
| Email | IMAP TCP 143/993; SMTP usually TCP 25 (465/587 if the actual check uses submission); SSH usually TCP 22; interactive endpoint/port unknown |
| Splunk | Chrony/NTP usually UDP 123; SSH usually TCP 22; packet API/search TCP 8089 and Web TCP 8000 need check-by-check mapping |
| AD | DNS TCP/UDP 53; packet WinRM TCP 5985, or 5986 only if configured |
| MSSQL | Packet SQL TCP 1433, SMB TCP 445, RDP TCP 3389; named-instance ports may differ |
| Ping on all five scored servers | ICMP echo, not a TCP/UDP port |

Do not assume `splunk-mgmt` means Web 8000 or that management and query use
different ports. The packet describes authenticated management/search on 8089,
but the screenshot does not assign ports to either check. Likewise,
`webmail-interactive` does not identify a URL, port or login workflow; if it is
browser-based, verify the actual HTTP(S) endpoint and full transaction.

Separate these checks from **dependencies**, administration and ingestion.
AD authentication/replication, DNS, time, mail relays, application backends,
DHCP and workstation access can still be essential without their own column.
FTP, POP3 and additional listeners are not confirmed scored by this screenshot;
do not enable them merely as guesses or remove them without dependency review.
This table is not a replacement for a dependency-aware firewall plan.

Windows-to-Splunk TCP 9997 is an **ingestion** default, not a scored login endpoint.
Plain TCP syslog, for example 20514, is a different input and is not created by
the receiver script. Neither ingestion port is a named check in this scoreboard.
Verify the live scoring sheet before changing any port.
Do not source-restrict a public/scored service to the scoring engine or team
subnet when current rules require general reachability.

## 5. Shared script map

### Linux tools used by the three Linux clients and Debian

| Script | What it actually does | Important boundary |
|---|---|---|
| [first-hour.sh](../../linux/first-hour.sh) | Inventory local accounts, key-file metadata/fingerprints, crontabs, timers and Samba; optional policy, firewall, explicit persistence removal and password rotation | Not an application installer or automatic malware remover; some scans can be lengthy |
| [pam_policy.py](../../linux/pam_policy.py) | Back up/edit recognized Debian PAM files and `login.defs`; verify and attempt restore on failure | Called by first-hour; do not invoke against `/` as an audit |
| [apply-firewall.sh](../../linux/apply-firewall.sh) | Validate JSON, render/check nftables, optionally add timed input/output policy | Outbound default drop can break DNS, mail, app backends and logging |
| [service-probe.sh](../../linux/service-probe.sh) | One authorized HTTP(S), DNS, TCP or plaintext banner probe | Does not prove authentication, complete transactions, scoring or ingestion |

First-hour's Linux account-policy category is **not the Windows policy**:
on supported Debian/Ubuntu layouts it bundles quality/history, five-attempt
faillock with 1800-second unlock and new-account aging defaults 60/7/7 days.
It is not opt-in per individual PAM setting. It refuses unrecognized/authselect
layouts; Rocky gets manual guidance and exit 2, not applied PAM.

Linux password rotation writes a **restricted plaintext** recovery file, unlike
Windows first-hour DPAPI. Dependency checks are limited; explicitly exclude
scoring, service and recovery accounts and use an approved secret store.

### Windows tools

| Script/group | Purpose and caveat |
|---|---|
| [first-hour.ps1](../../windows/first-hour.ps1) | General inventory and individually selected categories; account policy on a domain member targets the **default domain password policy**, not just the local host |
| [harden-addns.ps1](../../windows/addns/harden-addns.ps1) | AD/DNS inventory and selected DNS/authentication/Spooler/audit changes; source target is Server 2019, packet DC is 2022 |
| [harden-workstation.ps1](../../windows/workstation/harden-workstation.ps1) | Credential protection, PowerShell logging, AutoRun, Defender and audit categories for Windows workstation |
| [Set-PacketFirewall.ps1](../../windows/Set-PacketFirewall.ps1) and [recovery](../../windows/Invoke-PacketFirewallRecovery.ps1) | Additive role firewall with apply/verify/commit timer; not a strict allowlist |
| [Set-WindowsForwarder.ps1](../../splunk/Set-WindowsForwarder.ps1) | Configure UF event subscriptions and MSSQL text logs; does not configure complete source auditing |
| [Show-RotatedCredentials.ps1](../../windows/Show-RotatedCredentials.ps1) | Recover first-hour DPAPI records using the same account/machine; protect displayed secrets |
| [Rotate-LocalPasswords.ps1](../../windows/Rotate-LocalPasswords.ps1) | Separate explicitly selected local-account rotation and passphrase-encrypted store; refuses DCs; dependencies are the operator's responsibility |
| [New-DecoyCredentialFile.ps1](../../windows/New-DecoyCredentialFile.ps1) | Write labeled fake values only; not password recovery and not access monitoring |
| [Start-WindowsDecoy.ps1](../../windows/Start-WindowsDecoy.ps1) and [cleanup](../../windows/Invoke-DecoyCleanup.ps1) | Approved temporary metadata-only canaries, no default ports; see [defense playbook](../../windows/DEFENSE-PLAYBOOK.md) |
| [Invoke-ServiceProbe.ps1](../../windows/Invoke-ServiceProbe.ps1) | Single-target checks with the same functional limits as the Linux probe |
| [auto-harden.ps1](../../windows/auto-harden.ps1) | Broad role-detecting wrapper; continues after child failures; not the default procedure for these runbooks |

The five separately executable modules under `windows/lib` are:

| Module | What non-audit mode can change |
|---|---|
| [harden-credentials.ps1](../../windows/lib/harden-credentials.ps1) | Credential/UAC/legacy PowerShell/Defender settings; Guest disabling; explicitly opted-in Administrator rename/rotation and selected bulk rotation |
| [disable-legacy-protocols.ps1](../../windows/lib/disable-legacy-protocols.ps1) | Legacy protocols **and firewall**, including scoped management; not interchangeable with packet firewall |
| [harden-ad.ps1](../../windows/lib/harden-ad.ps1) | LDAP signing/channel binding and Kerberos encryption; optional disruptive `krbtgt` reset |
| [audit-windows-persistence.ps1](../../windows/lib/audit-windows-persistence.ps1) | Persistence inventory **plus logging/transcription changes**; the filename does not make default mode read-only |
| [apply-gpo-baselines.ps1](../../windows/lib/apply-gpo-baselines.ps1) | LGPO import and Defender ASR settings; requires approved backup/tooling and compatibility review |

Other `windows/lib` files provide reporting, baselines, policy, protocol,
firewall, credential-store, Sysinternals, restore-point, USB and decoy helpers.
Do not run them as independent hardening entry points. Do not layer multiple
firewall implementations or password stores without a deliberate migration.
IIS web/FTP scripts exist, but **do not run them on Rocky or Ubuntu**.

## 6. Linux syslog is a separate, optional manual setup

This is not performed by any first-hour script. First confirm an approved
receiver input, index, transport and sender identity. Use an existing Linux
forwarder instead when that is already the supported deployment; do not collect
the same logs twice.

For an approved **plaintext TCP syslog** path only:

1. On Splunk, create/verify the chosen raw TCP input, source type `syslog`, and
   actual destination index. See the [Debian runbook](splunk-debian/README.md#6-linux-logs-are-a-different-input).
2. On the sender, inspect the existing service and forwarding rules:

   ```bash
   systemctl is-active rsyslog
   sudo grep -R -n -E 'omfwd|@@|target=' /etc/rsyslog.conf /etc/rsyslog.d
   ```

3. If rsyslog is absent, obtain approval to install the distribution package.
   Record/secure a copy of the exact existing configuration before editing.
4. Use `sudoedit /etc/rsyslog.d/60-ccdc-forward.conf` only after confirming that
   filename is not already owned by another deployment. Adapt this **template**:

   ```text
   *.* action(
       type="omfwd"
       target="REPLACE_VERIFIED_SPLUNK_HOST"
       port="20514"
       protocol="tcp"
       action.resumeRetryCount="-1"
       queue.type="LinkedList"
       queue.size="10000"
   )
   ```

5. Validate with `sudo rsyslogd -N1`. Stop on errors. In an approved logging
   change window, restart only rsyslog and inspect its journal.
6. Send a unique harmless event and find it centrally:

   ```bash
   marker="CCDC-LINUX-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)-$$"
   logger -t CCDC-Verify "$marker"
   printf '%s\n' "$marker"
   ```

7. Search the **actual index** and `sourcetype=syslog` over the last ten minutes
   for that marker. Verify host attribution and timestamp. This proves only
   that selected syslog path, not collection of web/mail/application files.

The example queue is bounded and memory-backed, not a durable delivery guarantee.
Plain TCP provides no TLS or sender authentication. For protected transport,
design approved certificates and matching sender/receiver settings separately.
To recover, restore/remove only the changed forwarding fragment, validate again,
then restart rsyslog in a coordinated window. Preserve original logs.

## 7. Recovery boundaries and handoff

| Change | Recovery boundary |
|---|---|
| Packet Windows firewall | Run-specific rules and changed supported local profile fields; not applications, accounts or GPO |
| Older Windows host firewall | Apply-failure recovery can import the entire `.wfw`, overwriting later edits; no independent confirmation timer |
| Linux first-hour firewall | Timer deletes `inet ccdc_host`; other firewall managers/chains still apply |
| Standalone Linux firewall | Timer deletes `inet ccdc_first_hour`; output restrictions and existing rules require separate review |
| Splunk receiver/UF | Managed app/service/channel recovery attempts; not a complete installation/data restore |
| PAM, registry, DNS, SQL or mail | Component-specific backup and tested restore; firewall recovery does not undo these |

Do not assume automatic rollback succeeded. A task/service/provider, permissions,
conflicting edit or unsupported `NotConfigured` restore can prevent it.
Keep console access and inspect the saved state and errors.

For each machine record: actual OS/hostname/IP, owner, required transactions,
approved commit, selected commands, before/after health, changed files, backup/run
path, timer deadline/commit result, unique log marker/search, and unresolved gaps.
Do not put real passwords, private keys or recovery-store contents in Git,
team chat or incident reports. Use the approved secret store and scoring
credential-update process.

For confirmed incidents use [incident report](../../templates/incident-report.md);
for recovery planning use [disaster recovery](../../templates/disaster-recovery.md).
An unknown listener, young file or alert is a lead, not proof of compromise.
