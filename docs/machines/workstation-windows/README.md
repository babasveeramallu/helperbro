# Windows workstation

[All machines](../README.md) | [Generic workstation guide](../../services/windows-workstation.md)

## 1. Mission and defaults

The documented packet default is **Windows 11 with DHCP**, not a verified live
version/address. Keep the team's interactive user login, browser, remote
administration, domain connectivity and telemetry working. Record the actual
hostname/build, membership, DHCP/static owner, DNS/gateway, approved users,
management tools, console access and any scored workstation services.

No Windows workstation check is shown in the supplied 19-check scoreboard.
Do not invent a scored RDP/WinRM server requirement from the role alone, but
preserve actual administration, domain, DNS, time and logging dependencies.
Recheck the portal for later additions; absence here is not a removal order.

Do not change the computer name, join state, IP, accounts or trusted keys/
certificates as a routine baseline. A running desktop may be the only control
seat for multiple systems. Confirm another recovery path before any change.

## 2. Audit from the correct shell

Use elevated **x64** PowerShell at the repository root:

```powershell
[Environment]::Is64BitProcess
$PSVersionTable.PSVersion
hostname
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption,Version,BuildNumber
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name,Domain,PartOfDomain,DomainRole
Get-NetIPConfiguration
Get-NetRoute -DestinationPrefix '0.0.0.0/0'
.\windows\first-hour.ps1
.\windows\workstation\harden-workstation.ps1
.\windows\Set-PacketFirewall.ps1 -Role Wkst -AuditOnly
```

The host must not be a DC for `Wkst` forwarding/firewall roles. Those labels do
not themselves validate every Windows edition/application prerequisite.
General/role audits create protected logs/baselines and restrict the report
directory ACL. Packet-firewall audit creates no run directory/task.

Record a successful new user login and authorized access to assigned systems
before applying changes. Treat unavailable modules and denied reads as gaps.

## 3. Script map

| Entry point | What it actually does |
|---|---|
| [harden-workstation.ps1](../../../windows/workstation/harden-workstation.ps1) | Workstation-specific inventory plus selected credential/logging/AutoRun/Defender/audit categories |
| [first-hour.ps1](../../../windows/first-hour.ps1) | Broad host/account/task/startup/service/WMI inventory and optional selected common changes |
| [Set-WindowsForwarder.ps1](../../../splunk/Set-WindowsForwarder.ps1) | UF app, channel and service configuration; `Wkst` adds available device channels |
| [Set-PacketFirewall.ps1](../../../windows/Set-PacketFirewall.ps1) and [recovery](../../../windows/Invoke-PacketFirewallRecovery.ps1) | Additive role baseline and independent apply/verify/commit timer |
| [Invoke-ServiceProbe.ps1](../../../windows/Invoke-ServiceProbe.ps1) | One authorized TCP/content/DNS/banner test; not full authentication/scoring |
| [Show-RotatedCredentials.ps1](../../../windows/Show-RotatedCredentials.ps1) | First-hour DPAPI recovery, same account/machine |
| [Rotate-LocalPasswords.ps1](../../../windows/Rotate-LocalPasswords.ps1) | Separate explicit local rotation with passphrase-encrypted store |
| [New-DecoyCredentialFile.ps1](../../../windows/New-DecoyCredentialFile.ps1) | Labeled fake credentials only, no password changes or access monitoring |

The [auto-hardener](../../../windows/auto-harden.ps1) and five
[standalone modules](../README.md#5-shared-script-map) have broader/default-apply
behavior. They are not required to use the role script or forwarder.
Do not start a canary or create firewall exceptions without explicit approval.

## 4. Establish and prove forwarding

Have the Debian operator verify receiver readiness first. These are **packet
defaults only**, to be replaced after verifying live configuration:

```powershell
$Indexer = '172.20.240.20'
$Port = 9997
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -Indexer $Indexer -Port $Port -AuditOnly
```

Audit does not install missing UF or create its reports. Use the approved x64
vendor-signed MSI, optional trusted expected hash and
[interactive installer procedure](../../../splunk/PLAYBOOK.md#5-windows-forwarder-procedure)
if required. Choose a unique UF-local administrator credential and verify the
service identity's read access; do not reuse domain/scoring credentials.

**APPLY when approved for the internal plaintext baseline:**

```powershell
.\splunk\Set-WindowsForwarder.ps1 -Role Wkst -Indexer $Indexer -Port $Port -AllowPlaintext
```

This writes its dedicated UF app, enables selected existing disabled channels,
sets UF startup Automatic and starts/restarts only SplunkForwarder when needed.
It does not change firewall, hostname, IP, Windows accounts, domain policies or
install Sysmon. Backups and `run.json` default to
`%ProgramData%\CCDC\Splunk\forwarder-...`.

The role includes Security/System/Application, available PowerShell/task/WMI/
Defender/RDP/Sysmon, and available DeviceSetupManager/Admin and
DriverFrameworks-UserMode/Operational channels. Sysmon must already exist.
Source-channel subscription does not enable every generating audit policy.
Windows inputs are live-event-only while UF runs; old history and events written
while UF is stopped are not collected by this baseline.

Generate one new harmless Application event, an explicit test write:

```powershell
$Marker = "CCDC-WKST-$env:COMPUTERNAME-$([guid]::NewGuid().ToString('N'))"
eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /SO CCDC-Forwarder-Test /D $Marker
if ($LASTEXITCODE -ne 0) { throw 'Verification event creation failed.' }
$Marker
```

Find that exact marker in the actual host's `wineventlog` XML events over the last
ten minutes using the [receiver queries](../splunk-debian/README.md#7-verification-three-independent-levels).
An active service or connected port is not enough.

## 5. Workstation role: selected controls, not one giant switch

Without `-Apply`, selected categories preview policy changes. Both audit and
preview can still write reports. Apply requires elevation and uses PowerShell
confirmation. The role attempts before/after client restore points unless
`-SkipRestorePoint` is explicitly supplied; availability is not guaranteed and
this is not a full machine backup.

| Switch | Actual changes | Compatibility / recovery consideration |
|---|---|---|
| `-HardenCredentials` | WDigest credential caching off, NTLM compatibility level 5, LSA `RunAsPPL=1`, turn off existing AutoAdminLogon | Legacy NTLMv1 clients fail; LSA change needs reboot; know a working password before losing auto-logon |
| `-EnablePowerShellLogging` | Enable Script Block Logging registry policy | Can record sensitive commands; protect logs and prove new 4104 events |
| `-DisableAutorun` | Set `NoDriveTypeAutoRun=255` | Changes AutoRun behavior, not all device/USB access |
| `-EnableDefender` | Enable real-time/behavior protection and advanced cloud reporting; verify real-time state | Tamper/GPO/other AV can prevent changes; do not disable protections to make a script pass |
| `-EnableAuditPolicy` | Back up advanced audit policy; selected success/failure categories and process-command-line policy | More data/sensitive command lines; backup is not a full registry restore |
| `-SkipRestorePoint` | Omit restore-point attempts | Does not create another recovery method |
| `-ReportDirectory` | Override protected log/baseline destination | Keep on a trusted local path and record it |

The credential category is not a guarantee of full Credential Guard/UAC policy,
disk encryption or removal of stored secrets. Those are different controls.

Example: preview **only** PowerShell logging:

```powershell
.\windows\workstation\harden-workstation.ps1 -EnablePowerShellLogging
```

**APPLY only after approval and recovery review:**

```powershell
.\windows\workstation\harden-workstation.ps1 -Apply -EnablePowerShellLogging
```

Then generate an approved harmless PowerShell action, verify the expected
Operational events locally and centrally, and recheck user/admin access.
Do not force a reboot during scoring just because another category recommends it.

## 6. General first-hour options are a different apply model

Preview selected common controls:

```powershell
.\windows\first-hour.ps1 -PlanOnly -DisableUsbStorage -RequireSmbSigning
```

**Removing `-PlanOnly` applies selected categories**, even without `-Apply`.
Do not copy the role script's no-Apply assumptions to this tool.

| Category / parameter | Important behavior |
|---|---|
| `-DisableUsbStorage` | Sets USBSTOR driver startup to Disabled; not every USB device or proof all mounted storage is disconnected |
| `-RequireSmbSigning` | Require client/server SMB signing; verify older NAS/SMB tools still work |
| `-DisableLegacyProtocols` | Disable SMBv1/LLMNR/NetBIOS controls; some changes need reboot and can break legacy discovery/auth |
| `-DisableSpooler` | Stop and disable printing service |
| `-SetAccountPolicy` | Standalone: local policy; domain member with RSAT: **domain** default policy, not workstation-only |
| `-EnableAccountLockout` | Separate opt-in with configurable threshold/duration/window; deliberate failures can deny service |
| `-MaxPasswordAgeDays` | Separate opt-in; older passwords may require immediate change at next login |
| `-KillPersistence -DisableTask` | Disable exact identified non-Microsoft task paths, not all suspicious-looking tasks |
| `-InstallSysmon` | Requires staged signed binary via `-SysinternalsPath` and valid `-SysmonConfig`; not automatic |
| `-EnforceHostFirewall` | Different discovered-service firewall; no independent packet confirmation timer |

The general firewall preserves existing allows/scopes by default, re-enables
disabled detected helper allows without widening scopes, and uses protocol-
specific management helper identities. Its explicit narrowing switches can break
scored services; do not stack it with packet firewall.

## 7. Packet firewall and timed confirmation

With the previously verified receiver IP/port:

```powershell
$Plan = .\windows\Set-PacketFirewall.ps1 -Role Wkst -Indexer $Indexer -IndexerPort $Port -AuditOnly
$Plan.Plan | Format-Table Direction,Protocol,Port,Remote -AutoSize
$Plan.ExistingExplicitBlocks | Format-List
$Plan.UnplannedListeners | Format-Table -AutoSize
```

`Wkst` has no unconditional TCP server-port list. It preserves existing rules,
adds DHCP/ICMP, currently listening RDP/WinRM and any reviewed explicit extra
ports, plus selected Splunk egress. It enables all profiles with inbound Block/
outbound Allow. Existing broad rules/GPO remain; it is not a strict allowlist.
A currently stopped management service might need a separately reviewed extra.

**APPLY from console only after approval:**

```powershell
.\windows\Set-PacketFirewall.ps1 -Role Wkst -Indexer $Indexer -IndexerPort $Port -RollbackMinutes 10
```

Record the printed run directory/deadline. Verify new user/domain login, actual
admin/browser paths, DHCP/DNS, ping, scoring if applicable and new log receipt.
Then run the exact printed recovery command, using this host's actual path:

```powershell
$Run = 'C:\ProgramData\CCDC\Firewall\run-REPLACE_ACTUAL_RUN_ID'
& "$Run\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $Run -Action Commit -ScoringVerified
```

On failed checks use `-Action Revert` instead. Uncommitted runs have an independent
SYSTEM rollback task. It attempts scoped rule/profile recovery, not workstation
policy or UF recovery. Original local `NotConfigured` values and concurrent
same-field edits can leave recovery incomplete and Pending; keep run files/task
and console while investigating. Older pending runs may restore a full snapshot.
See [detailed boundaries](../../../windows/DEFENSE-PLAYBOOK.md#6-firewall-apply-verify-then-commit).

## 8. Password tools and decoys are optional separate workflows

Do not rotate current, scoring, service, scheduled-task or break-glass identities
as a shortcut. First-hour rotation needs explicit includes/two distinct exclusions,
dependency review and confirmation. It writes current-user DPAPI recovery records
before each attempted password change. Recover with
`Show-RotatedCredentials.ps1` as the same Windows account on the same machine;
loss/reset of that profile/credential context can prevent decryption.

The standalone local-password tool uses a **different passphrase-encrypted**
store and does not discover all service/task dependencies. Preview only:

```powershell
.\windows\Rotate-LocalPasswords.ps1 -Account 'REPLACE_APPROVED_LOCAL_ACCOUNT' -WhatIf
```

It rejects wildcards and DCs; `-Action Show` recovers its own selected store,
not first-hour DPAPI records. Protect the passphrase and any displayed passwords.
Do not delete stores until valid records are securely recovered and partial
failures investigated.

Fake credential files never hold real passwords or install detection. Network
decoys require approved unused ports and explicit organizer approval; no default
port is approved by these docs. Read the
[defense playbook](../../../windows/DEFENSE-PLAYBOOK.md#7-decoys-approval-and-audit)
before considering them.

## 9. Troubleshooting and handoff

| Symptom | First action |
|---|---|
| x86/module errors | Use correct x64 shell and verify required Windows modules; do not call the wrong role to bypass validation |
| Auto-logon stopped | Use recorded authorized credentials; credential hardening does not reset them |
| Defender setting refused | Inspect actual AV/tamper/GPO ownership; no exclusion/protection-bypass workaround |
| Sign-in/domain access fails | DNS/time, account/lockout/expiry, new auth policy and actual network path |
| New event missing centrally | Verify local generation, selected channel, UF identity/output, receiver/index and time |
| Firewall Pending after attempted revert | Inspect original profile values/conflicts and saved state from console |

Save reports from `%LOCALAPPDATA%\CCDC\Reports` or the explicit path, UF backups,
firewall run state and original setting values. Role registry changes need their
own exact restore; audit-policy CSV does not undo every registry change.
No universal rollback command restores accounts, local policy, profiles and
forwarding together.

- [ ] Original and replacement user/admin sessions work; DHCP/DNS/membership unchanged.
- [ ] Selected changes verified, reboot requirements scheduled rather than assumed complete.
- [ ] New workstation marker searchable and optional channel gaps recorded.
- [ ] Timer deliberately committed/reverted; recovery location and owner recorded.
- [ ] Credentials, keys and sensitive output kept out of Git/chat.
