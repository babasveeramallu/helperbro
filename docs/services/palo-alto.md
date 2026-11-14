# Palo Alto firewall deployment

Use the [shared preflight](README.md#shared-preflight). Helperbro has no
Palo Alto deployment script. Use the actual PAN-OS version's supported
management interface and recovery process; this guide does not imply a
specific version or address.

## Before any change

1. Establish console and an independently verified management path. Verify
   the management certificate fingerprint through a trusted channel.
2. Record interfaces, routes, security policy, NAT, logging destination,
   administrator access, current active configuration and pending changes.
3. Coordinate with other administrators. A commit can include their pending
   candidate changes; preview the complete diff before committing.
4. Back up the active configuration through the approved method and verify
   who can restore it. Confirm the effect of any staged/confirmed-commit
   mechanism on this exact PAN-OS version in a lab.

## Change and validate

Change one approved item at a time. Preserve public scored services for the
required source addresses, official access, ping, return traffic, NAT and
management. A workstation address may come from DHCP; do not assume it is
fixed. Review both rule order and translations rather than judging by a single
port. Do not disable a rule solely because it is not shown as scored.

From authorized sources, test real web/mail/FTP/SQL or management transactions
through the intended path, inspect session and traffic logs, and confirm the
scoring portal. Generate a test log and confirm Splunk receives it. If access
or a service breaks, use the tested device-specific recovery and retest;
host firewall rollback cannot undo a Palo Alto commit.
