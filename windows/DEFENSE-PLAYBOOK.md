# Packet-aware Windows firewall and detection-decoy playbook

For **AD Server 2022, MSSQL Server 2019 and the Windows 11 workstation** in the
supplied 2026 Midwest Invitational packet. Start with the
[operator guide](../README.md) and establish
[Windows-to-Debian Splunk forwarding](../splunk/PLAYBOOK.md) first.

## 1. Scope and deliberate limitations

You selected an **additive firewall baseline**: keep existing rules and legitimate
administration, add explicit packet dependencies, enable the firewall on all
profiles with inbound default Block and outbound default Allow, and report
remaining exposure. This is **not a strict allowlist**, an outbound restriction,
or a promise to close every unnecessary listening port. Existing broad allows
still allow traffic. Explicit blocks/GPO policy can override local allows.

You also selected **detection-only decoys**. These are bounded foreground TCP
canaries on explicitly approved unused ports, not protocol-emulating Windows
services. They accept and immediately close connections, recording endpoint
metadata. They do not authenticate, read commands, collect passwords, send exploit
content, execute scanner input, impersonate genuine SMB/RDP/WinRM/SQL endpoints,
or hold scanners in slow-response tarpits.

Whether a scanner uses AI does not change this network policy or make it
identifiable as AI. A canary hit is a lead to investigate, **not proof of compromise
or attribution**. Organizer traffic, your tests and inventory tools can trigger it.
No automatic IP blocking or credential disablement is implemented.

No decoy port is configured by default. Organizer approval is currently unknown.
Audit is safe to use now; do not activate decoys until their use and specific
unused ports are approved. Do not copy the example ports into a live deployment
as if this document were approval.

## 2. Before touching a competition host

1. Confirm live NETLAB/portal data, not just the packet inventory:
   - AD: packet default `172.20.240.100`.
   - MSSQL: packet default `172.20.240.120`.
   - Workstation: DHCP; record its current actual address.
   - Debian Splunk: packet default `172.20.240.20`, receiving TCP 9997.
2. Record current scoring, remote administration and Splunk receipt from each host.
3. Keep NETLAB console access. Practice on noncompetition VMs first.
4. Coordinate a short firewall-change window with the network/system owners.
5. Keep other firewall edits paused until the run is committed or reverted:
   rollback imports the **entire pre-change local firewall policy**.
6. Do not stack this script with the older auto-hardening/host-firewall scripts.
7. Retain the complete `windows` directory including its `lib` helpers.
8. Use **x64 elevated Windows PowerShell 5.1 or x64 PowerShell 7**.

Packet constraints still apply: preserve MSSQL SMB/SOP access, RDP/3389, SQL/1433,
AD WinRM, Splunk query/8089, ping and requested organizer access. Do not restrict
public services to scoring-engine-only source addresses. The packet does not
provide snapshot/scrub recovery during the event.

## 3. Files and entry points

| File | Purpose |
|---|---|
| [Set-PacketFirewall.ps1](Set-PacketFirewall.ps1) | Audit/apply the additive role-specific firewall baseline |
| [Invoke-PacketFirewallRecovery.ps1](Invoke-PacketFirewallRecovery.ps1) | Commit/revert a pending run; also called by its rollback task |
| [Start-WindowsDecoy.ps1](Start-WindowsDecoy.ps1) | Run approved bounded foreground detection listeners |
| [Invoke-DecoyCleanup.ps1](Invoke-DecoyCleanup.ps1) | Remove a run's exact temporary decoy exceptions; used by its cleanup task |
| [PacketDefense.ps1](lib/PacketDefense.ps1) | Shared plan/port/path/ACL helpers; do not invoke directly |
| [DecoyListener.ps1](lib/DecoyListener.ps1) | Bounded listener loop; do not invoke directly |
| [Test-PacketDefense.ps1](Test-PacketDefense.ps1) | Isolated mock tests and a short local loopback socket test |

These are separate tools from the Splunk installer. Firewall setup does not
install/configure Splunk, generate passwords or change AD/SQL services.

## 4. Firewall: audit first

From the repository root, on each appropriate machine:

```powershell
# Run ONLY the matching role on its corresponding host.
.\windows\Set-PacketFirewall.ps1 -Role AD -AuditOnly
.\windows\Set-PacketFirewall.ps1 -Role MSSQL -AuditOnly
.\windows\Set-PacketFirewall.ps1 -Role Wkst -AuditOnly
```

Audit requires elevation to inspect effective policy. It creates no report
directory, firewall rule or scheduled task. It returns an object containing:

| Property | Interpretation |
|---|---|
| `Computer`, `Role` | Actual hostname and requested role |
| `Plan` | Exact rules the script proposes |
| `Profiles` | Current effective profile settings |
| `ExistingInboundAllows` | Enabled inbound allows with protocol, ports, remote addresses and policy source type |
| `ExistingExplicitBlocks` | Active explicit blocks that can defeat added allows |
| `UnplannedListeners` | TCP listeners not covered by the proposed inbound TCP port plan |

Inspect nested properties explicitly rather than trusting the default display:

```powershell
$audit = .\windows\Set-PacketFirewall.ps1 -Role MSSQL -AuditOnly
$audit.Plan | Format-Table Name,Direction,Protocol,Port,Remote -AutoSize
$audit.ExistingInboundAllows | Format-List
$audit.ExistingExplicitBlocks | Format-Table -AutoSize
$audit.UnplannedListeners | Format-Table -AutoSize
```

An unplanned listener is **not necessarily blocked**: an existing rule can allow
it. A planned port is not a verified working service: a process must be listening,
authentication must work, and upstream policy must permit the path. Review
unplanned applications, custom SQL instance ports and other real business
dependencies before apply. Add only known legitimate exceptions, not every PID.

## 5. Firewall: proposed rules and effects

All added rules apply to Domain, Private and Public profiles. Required inbound
services use remote address `Any`, preserving the packet's general availability
requirement rather than knife-edge scoring filters.

| Role | Added inbound TCP | Added inbound UDP |
|---|---|---|
| AD | 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5722, 5985, 5986, 49152-65535 | 53, 68, 88, 123, 137, 138, 389, 464, 546 |
| MSSQL | 139, 445, 1433, 3389 | 68, 137, 138, 546, 1434 |
| Wkst | No unconditional TCP server ports | 68, 546 |

In addition, **all roles** get:

- Inbound TCP 3389/5985/5986 **if currently listening**, preserving local remote
  administration when enabling the firewall.
- All inbound ICMPv4/ICMPv6 types, preserving ping and essential ICMP/IPv6 behavior.
- An outbound TCP rule to the selected Splunk IP/port.
- Explicit extra ports/ranges supplied by the operator.

The AD plan uses the standard modern dynamic RPC range. This is a deliberately
broad availability allowance, not a granular RPC restriction. Customized RPC
ports, nonstandard applications and other replication requirements need separate
validation. Ports for optional services are allowed but this script never starts
those services or turns on a protocol.

The MSSQL profile preserves SQL Browser UDP 1434 and legacy SMB/NetBIOS-related
ports for availability; it does not enable them or require that you leave
unneeded protocols running indefinitely. Review any later tightening separately.

Workstation outbound Allow preserves DNS, Kerberos, LDAP and other client-initiated
domain traffic. Existing file-sharing, management and application rules remain.
If a legitimate currently stopped admin service has no existing rule, explicitly
add its required port after review; listener discovery cannot know future needs.

### Changes the firewall script makes

1. Validate x64/elevation, DC role, and SQL engine-service presence for MSSQL.
2. Discover listeners, effective profiles, explicit blocks and inbound allows.
3. Stop apply if **any active explicit block exists**. This conservative guard
   avoids pretending an allow defeats a block; audit lists the rule names.
   Review legitimate blocks with their owner, not by deleting them wholesale.
4. Refuse policy that disables local-rule merging/inbound exceptions.
5. Refuse another pending packet rollback task, unsafe output paths, or an
   unrelated rule using one of this script's reserved names.
6. Ask for PowerShell confirmation unless `-Force` was supplied.
7. Create a protected unique run directory and export `before.wfw`.
8. Save the audit, copied recovery script/helper, checksum and Pending state.
9. Register a one-shot **SYSTEM / highest-privilege** scheduled rollback task,
   with start-when-available, battery allowances and retry settings; check Ready.
10. Lock the run so apply/commit/rollback cannot modify the run simultaneously.
11. Add the named packet rules, refreshing only previously owned matching rules.
12. Enable all three profiles, then set inbound Block/outbound Allow.
13. Check effective profiles and rule direction, enabled/action, protocol,
    port and address settings.
14. Leave the timer armed and print the exact commit command.

No existing unrelated rule is disabled/deleted. Existing explicit outbound
restrictions are not bypassed. A local firewall rule does not configure the Palo
Alto or Debian firewall. Neither authentication policy nor source audit policy
is changed.

### Parameters

| Parameter | Default / meaning |
|---|---|
| `-Role AD\|MSSQL\|Wkst` | Required; AD must run on a DC, other roles must not |
| `-Indexer` | `172.20.240.20`; literal IPv4/IPv6 address, not a hostname |
| `-IndexerPort` | 9997 |
| `-AdditionalTcpPorts` | Array of extra literal ports/ranges, such as `'1555','20000-20010'` |
| `-AdditionalUdpPorts` | Same format for UDP |
| `-RollbackMinutes` | 10; permitted range 3-30 |
| `-OutputDirectory` | `%ProgramData%\CCDC\Firewall`; trusted local-drive path |
| `-AuditOnly`, `-PlanOnly` | Inspect only |
| `-WhatIf` | Preview without applying |
| `-Force` | Skip confirmation, not timer/role/backup/GPO checks |

## 6. Firewall: apply, verify, then commit

Do this **one host at a time**, from console:

```powershell
.\windows\Set-PacketFirewall.ps1 -Role MSSQL -RollbackMinutes 10
```

Use the corresponding `AD`/`Wkst` role on those machines. Review the confirmation
prompt. Record the printed run directory and deadline.

Before that deadline, test from the appropriate **external client/network**:

| Host | Verify before committing |
|---|---|
| AD | Domain/DNS functionality, scored authenticated WinRM command, existing admin path, ping and a fresh Splunk event |
| MSSQL | Authenticated SQL query, real SOP share/file access, authenticated RDP, ping and fresh Splunk events |
| Wkst | Domain/user access, legitimate admin path, ping and fresh Splunk events |

Use real service functionality and current portal results, not just localhost
TCP tests. Coordinate with your teammate who can perform those checks.
Do not pass `-ScoringVerified` merely because the script printed no errors.

After verification, run the **exact printed recovery command**, for example:

```powershell
# Replace with the actual run directory printed on THIS host:
$run = 'C:\ProgramData\CCDC\Firewall\run-ACTUAL_GUID'
& "$run\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $run -Action Commit -ScoringVerified
```

The helper takes an exclusive lock, refuses confirmation after the deadline,
writes `Committed`, then unregisters its rollback task. A racing timer cannot
import the policy after seeing terminal Committed state.

If a check fails, revert immediately:

```powershell
& "$run\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $run -Action Revert
```

If connectivity is lost, the independent scheduled task attempts to restore the
snapshot at the deadline. It does not depend on the originating PowerShell
window staying open. Keep console access: Task Scheduler, SYSTEM privileges,
backup integrity, disk health and local Windows services must still work.
Administrative attackers can disable a task; this is an operational safety net,
not tamper-proof containment.

### Files, rollback scope and reruns

```text
%ProgramData%\CCDC\Firewall\run-<guid>\
    before.wfw
    audit.json
    state.json
    operation.lock
    Invoke-PacketFirewallRecovery.ps1
    lib\PacketDefense.ps1
```

The leaf run directory grants SYSTEM and built-in Administrators full access
and disables inherited access. Use a trusted administrator-controlled parent.
Do not move/edit these files while the timer is armed.

The state records deadline, computer/role, task name, backup hash and one of
Pending/Committed/Reverted. The checksum detects backup corruption; it is not
protection against an administrator who can replace both state and backup.
The audit is pre-change evidence, not a full transcript of every command.
An arming failure before any policy changes is also marked Reverted and its
unused task is removed where possible; review the reported failure rather than
treating that status as a successful apply. Recovery supports `-AuditOnly`
to inspect a saved run without importing policy or canceling its task.

Rollback imports the **whole exported local firewall policy**, including profile
settings. Concurrent legitimate changes made after export can be lost. It cannot
override centrally enforced GPO policy. Apply errors trigger an immediate
restore attempt; if that fails, the scheduled task remains the fallback.
Inspect reported failures rather than assuming rollback succeeded.

Once committed, a later apply can refresh this script's owned rule names without
duplicating them; it creates a new snapshot/timer and needs fresh confirmation.
Rules added by a prior run but omitted from a later plan are preserved, not
automatically pruned. Do not change roles casually. Outstanding/failed tasks
must be investigated or resolved before another apply.

## 7. Decoys: approval and audit

These are not a hidden backdoor or installed Windows service. They intentionally
leave visible process/task/event evidence for your blue team. Obscure naming
would not protect them from an administrator or a public-repository reader.

First, audit with no ports:

```powershell
.\windows\Start-WindowsDecoy.ps1 -AuditOnly
```

Expected: warning that no ports are configured; **nothing is opened or registered**.

After approval, inspect explicit proposed ports and a specific local bind IP:

```powershell
# EXAMPLES ONLY: replace the address/ports with approved, unused live values.
.\windows\Start-WindowsDecoy.ps1 -ListenAddress '172.20.240.120' -Ports 2222,2323 -AuditOnly
```

The script refuses:

- No ports in apply, duplicates, or more than 8 ports.
- Privileged ports below 1024, the dynamic range 49152-65535, and known protected
  AD/SQL/RDP/WinRM/Splunk ports.
- Any requested port already listening anywhere on that host.
- Wildcard/nonlocal/IPv6 bind addresses; this implementation binds a specific
  local IPv4 address only (loopback is supported).
- An existing `CCDC-Decoy` source registered outside the Application log.

The protected list is a guardrail, not a complete catalog of every application
port. Your explicit approval/review is still required. Ports 2222/2323 are not
“guaranteed unused,” and these listeners do not emulate SSH/Telnet.

## 8. Decoys: explicit opt-in execution

Only after organizer approval and review:

```powershell
# EXAMPLE ONLY; requires actual approval and correct address/ports.
.\windows\Start-WindowsDecoy.ps1 `
    -ListenAddress '172.20.240.120' -Ports 2222,2323 `
    -DurationMinutes 15 -MaxConnectionEventsPerMinute 30 `
    -ApprovedByWhiteTeam -OpenFirewall
```

`-ApprovedByWhiteTeam` is your acknowledgment, not a check against an approval
service. Omitting `-OpenFirewall` makes **no** inbound exception; use that when
testing through an already approved path or on loopback. `-OpenFirewall` is
refused for a loopback-only bind.

### Execution and bounds

1. Require elevated x64 PowerShell and validate ports/bind address.
2. Report intended settings; audit returns before event-source/socket changes.
3. Require explicit approval and PowerShell confirmation (unless forced).
4. Refuse a pending packet-firewall rollback to avoid concurrent policy changes.
5. Register `CCDC-Decoy` in Application if needed. This event source persists.
6. Exclusively bind all selected ports before opening exceptions. If any bind
   fails, stop already-created listeners and report the error.
7. Emit a start event.
8. With `-OpenFirewall`, create a protected run and an independent SYSTEM cleanup
   timer at approximately the requested duration plus one minute. Require Ready
   **before** creating exceptions.
9. Create uniquely named inbound TCP exceptions limited to the running PowerShell
   executable, selected local IP/port and all profiles. No existing rule changes.
10. Accept then close clients immediately. Never receive payload bytes or reply.
11. Emit up to the configured per-minute connection-event count **across the run**;
    count suppressed events and emit a periodic/final aggregate.
12. At the duration limit, stop sockets, remove the recorded exceptions, cancel
    the cleanup task and emit a stop event.

The loop checks sockets every 100 ms and handles at most four pending connections
per listener per tick. Backlog is 8 per listener. The selected duration is 1-120
minutes (default 15); the connection-event cap is 1-120 per minute (default 30).
This bounds queueing/work/log growth but does not guarantee every flood packet
or attempted TCP connection is recorded. An idle client never occupies a handler.
No per-IP unbounded dictionary or payload store is kept.

The foreground process is not installed as a service and does not auto-start.
Keep its console open. Normal error/expiry/Ctrl+C cleanup is best effort;
forced process termination, power loss or a crash cannot guarantee a final stop
event. The independently scheduled cleanup removes remaining exceptions after
the deadline when Windows/Task Scheduler is available; it does **not** kill a
process. OS process termination itself closes that process's sockets.

### Parameters and temporary exceptions

| Parameter | Default / meaning |
|---|---|
| `-Ports` | Empty; explicit approved unused port array required to apply |
| `-ListenAddress` | `127.0.0.1`; specific local IPv4 address |
| `-DurationMinutes` | 15; 1-120 |
| `-MaxConnectionEventsPerMinute` | 30; 1-120 connection records across all listeners |
| `-ApprovedByWhiteTeam` | Required approval acknowledgment to apply |
| `-OpenFirewall` | Opt-in temporary exceptions; requires scheduled cleanup |
| `-OutputDirectory` | `%ProgramData%\CCDC\Decoys`; run files for exception cleanup |
| `-AuditOnly`, `-PlanOnly` | Inspect only |
| `-WhatIf` | No apply/registration/listeners |
| `-Force` | Skip PowerShell confirmation, not approval/port checks |

When opening exceptions:

```text
%ProgramData%\CCDC\Decoys\run-<guid>\
    decoy.json
    Invoke-DecoyCleanup.ps1
    lib\PacketDefense.ps1
```

The cleanup script checks each recorded rule's exact run-specific name and group
before removal. An operator can inspect or remove these exceptions manually:

```powershell
$run = 'C:\ProgramData\CCDC\Decoys\run-ACTUAL_GUID'
& "$run\Invoke-DecoyCleanup.ps1" -RunDirectory $run -AuditOnly
& "$run\Invoke-DecoyCleanup.ps1" -RunDirectory $run
```

Do not delete the run directory before cleanup completes. It removes only
exceptions/tasks, not the Application event source, history or a live process.
Do not kill unrelated PowerShell processes. Use the actual decoy console to stop
the listener, or identify its precise PID if that console is unavailable.

## 9. Splunk telemetry and alerts

The existing forwarder profile already collects Application into
`index=wineventlog sourcetype=XmlWinEventLog:Application`. No new custom index is
needed. Verify a fresh canary event reaches Debian before configuring alerts.

| Application event ID | JSON `Kind` | Meaning |
|---|---|---|
| 9100 | `Started` | Listener run initialized |
| 9101 | `Connection` | Accepted connection endpoint metadata |
| 9102 | `RateLimited` | Suppressed connection records and/or aborted/reset socket count |
| 9103 | `Stopped` | Normal/finally shutdown attempted |

Connection records contain UTC time, run ID, host, local/remote IP/port and kind.
No client payload or credential is stored. The source name is `CCDC-Decoy`.
Ordinary aborted/reset connections are summarized as `AbortedConnections`;
other socket faults terminate the listener with an explicit error.
Logging failures terminate listening rather than silently pretending monitoring
continues. Monitor the console for startup/write/cleanup errors.

### First verify locally

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'CCDC-Decoy'
    StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 30 | Select-Object TimeCreated,Id,Message
```

From another authorized host, make **one** connection to an approved decoy port:

```powershell
# Replace with the actual approved destination; this test intentionally generates a hit.
Test-NetConnection 172.20.240.120 -Port 2222
```

The TCP handshake may succeed and then close immediately. A scanner may identify
an open/unknown service, or only a reset. This is expected, not a failed protocol
implementation. SYN-only/blocked probes that never become accepted connections
do not produce a connection event.

### Connection investigation search

```spl
index=wineventlog sourcetype=XmlWinEventLog:Application earliest=-15m latest=now "CCDC-Decoy"
| rex field=_raw "(?<canary_json>\{\"Kind\":[^{}\r\n]*\})"
| spath input=canary_json
| where Kind="Connection"
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(LocalPort) as ports values(RunId) as runs by host RemoteAddress
| convert ctime(first_seen) ctime(last_seen)
```

This extracts the script's compressed JSON from the XML text before parsing it.
Verify that actual UF rendering preserves the JSON as shown; if your add-on
extracts it into a Message/Data field or XML-escapes it differently, adapt the
extraction to that observed field. Test before relying on an alert.

### Alert: canary connection

- Search above with `earliest=-2m latest=now`.
- Schedule every minute; trigger if at least one result is returned.
- Initial severity: **medium**, triage required.
- Suppress/throttle for **10 minutes by `host` and `RemoteAddress`**.
- Document expected team tests/organizer traffic; add reviewed exclusions only
  after identifying the source. Never automatically block public scoring paths.
- Counted events can be capped by the source rate limit, so do not equate event
  count with total scan volume.

### Alert: decoy event rate cap reached

```spl
index=wineventlog sourcetype=XmlWinEventLog:Application earliest=-2m latest=now "CCDC-Decoy"
| rex field=_raw "(?<canary_json>\{\"Kind\":[^{}\r\n]*\})"
| spath input=canary_json
| where Kind="RateLimited"
| stats sum(SuppressedConnections) as suppressed by host RunId
| where suppressed>0
```

Schedule every minute, trigger on results, medium severity, throttle 10 minutes
by `host`/`RunId`. This says detailed logging was limited, not that every
connection was recorded or an attacker succeeded. Investigate with other
network/host telemetry.

Start/stop events are useful operational evidence, but missing stop alone is not
proof that Red Team killed the process. The source may have crashed, logs may be
delayed, or the forwarder may be down. These alert definitions are documentation:
the scripts do not create saved searches, recipients or alert actions in Splunk.

## 10. Recovery and acceptance

Before calling the firewall complete:

- [ ] Pending rollback task existed before changes.
- [ ] Packet-required service functionality verified from the appropriate paths.
- [ ] Existing admin access and fresh Splunk receipt verified.
- [ ] Commit completed before its deadline; state is Committed.
- [ ] Expected task was removed; backup/audit retained securely.
- [ ] Remaining inbound exposure and AD RPC allowance reviewed/documented.

Before calling decoy monitoring complete:

- [ ] Organizer approval and specific unused ports recorded.
- [ ] Real/scored service ports not replaced or intercepted.
- [ ] A test hit appears in local Application and central Splunk.
- [ ] Rate cap, duration, console/process and cleanup timer are understood.
- [ ] Exceptions disappear after normal stop; scheduled cleanup tested on a lab VM.
- [ ] Scoring remains healthy; false-positive sources recorded.
- [ ] No credential/payload collection or automatic retaliation is enabled.

For an actual incident, preserve event IDs/UTC times, run IDs and relevant
Splunk searches and use your team's incident report. Distinguish a decoy hit
from established account access or compromise.

## 11. Validation and reference

```powershell
.\windows\Test-PacketDefense.ps1
```

The test uses mocked firewall/netsh/scheduler operations in a disposable fixture,
plus a four-second loopback-only listener test. It checks plans, scoring ports,
audit/WhatIf, rollback/commit, expiration/checksum rejection, exception cleanup,
rate caps and socket termination. It does not modify real firewall profiles,
create SYSTEM tasks or register Application event sources.

Run the real integration checks on matching lab VMs before competition. Offline
tests do not establish that your GPO, scheduler, service permissions, network
path, XML extraction or portal scoring will behave correctly on target hosts.

References consulted:

- [Winterknight CCDC hub](https://www.winterknight.net/ccdc/).
- [How to Win CCDC: Scoring](https://www.winterknight.net/how-to-win-ccdc-scoring/):
  uptime, prioritization and documenting incidents matter; avoid self-inflicted
  service outages.
- [How to Win CCDC: Dealing With Red Team](https://www.winterknight.net/how-to-win-ccdc-red-team/):
  prepare for common tooling, persistence and service disruption rather than
  assuming a novel AI scanner requires a special countermeasure.

These articles informed the operational priorities, not organizer approval for
decoys or a replacement for your event's rules. No third-party code was copied.
