# Linux workstation deployment

Use the [shared preflight](README.md#shared-preflight). A workstation may be
the only management path to an appliance; do not change addressing, DNS,
routes or firewall defaults before confirming another recovery path.

## Inspect from the workstation

```bash
hostname
ip -br address
ip route
id
```

Confirm the live DHCP address and default route with the environment owner.
On the appropriate workstation, test access only to authorized management
interfaces and hosts. Verify certificate identity through a trusted channel;
do not blindly bypass browser warnings.

## Toolkit and logging

`linux/first-hour.sh` is a general Linux host audit, not a workstation
provisioner. It creates a protected report directory even without `--apply`;
read `bash linux/first-hour.sh --help` before use and obtain the owner's
approval. Do not use its firewall or account-change categories as a quick
workstation setup. Helperbro does not install a Linux syslog forwarder.

After any approved change, retest the intended user login, DNS, management
interface and logging path. Check that the workstation can still reach the
assigned devices and that a real test event arrives in Splunk. Restore only
the changed configuration using a tested procedure; restart neither network
services nor appliances as an unplanned recovery step.
