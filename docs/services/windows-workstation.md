# Windows workstation deployment

Use the [shared preflight](README.md#shared-preflight). Verify whether this
is a domain member, its current DHCP address and its assigned management
tasks. Do not change the address, join state, identity or user configuration
without approval.

## Audit

Open x64 PowerShell on the workstation; the firewall audit requires
administrator elevation:

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,PartOfDomain,DomainRole
Get-NetIPConfiguration
.\windows\workstation\harden-workstation.ps1
.\windows\Set-PacketFirewall.ps1 -Role Wkst -AuditOnly
```

The role audit writes reports and restricts their directory ACL. `Wkst` is not
a complete workstation OS check. Confirm the machine is not a DC. The
firewall audit lists effective rules but does not prove a future apply is safe.

## Optional changes and verification

Choose at most one approved hardening category after reviewing `-WhatIf` and
recovery; enabling credential protection or logging can change compatibility
and expose sensitive command lines in logs. Restore points are not guaranteed.
Use the firewall playbook's timer if a firewall change is authorized. For
forwarding, follow [Splunk](splunk.md) with role `Wkst`.

New packet-firewall runs roll back only their own rules and changed local profile
fields. Coordinate changes to those same profile fields while the timer is
active; a conflicting change can prevent automatic recovery. Older pending runs
use their saved recovery scripts and can still import the entire snapshot.
If an original local field was `NotConfigured`, recovery skips that unsupported
write, restores supported fields and removes run-specific rules, but reports
failure and keeps the run pending with its watchdog registered. The skipped
fields retain the applied values; coordinate manual recovery from the console
using the [recovery limits](../../windows/DEFENSE-PLAYBOOK.md).

Before and after: test the intended user login, DNS, access to the assigned
management interfaces and a new forwarded event. Confirm DHCP and routes
remain correct. Keep a second session until access is proven. Use the tested
recovery for the affected component; firewall rollback does not undo
workstation hardening or forwarding.
