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

Before and after: test the intended user login, DNS, access to the assigned
management interfaces and a new forwarded event. Confirm DHCP and routes
remain correct. Keep a second session until access is proven. Revert only the
documented change with its tested recovery; a firewall rollback does not undo
workstation hardening or forwarding.
