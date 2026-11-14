# Splunk receiver and forwarder deployment

Use the [shared preflight](README.md#shared-preflight) and the detailed
[Windows-to-Debian playbook](../../splunk/PLAYBOOK.md). These scripts configure
an existing Splunk Enterprise receiver and Windows Universal Forwarders;
they do not install Splunk Enterprise or configure Linux syslog senders.

## Receiver first

Confirm the live receiver hostname/address, installation path, systemd unit,
indexes, available disk, receiving port and scoring/management endpoints.
The configured defaults are examples: set the actual values. On the existing
Debian receiver, from the repository root:

```bash
sudo bash splunk/setup-debian-receiver.sh --audit-only
```

If the home, unit or port differs, pass `--splunk-home`, `--service` or
`--port`. Audit requires the installed service to be active. Review existing
inputs before adding another. Apply may restart the Splunk service; coordinate
the window and inspect the backup location. Unencrypted TCP requires explicit
`--allow-plaintext`; use only if approved, otherwise arrange protected transport.

## One Windows sender at a time

On each target, open x64 PowerShell at the repository root. Set `$Indexer` to
the verified receiver address or name, then select the correct role:

```powershell
.\splunk\Set-WindowsForwarder.ps1 -Role AD -Indexer $Indexer -AuditOnly
```

Use `MSSQL` or `Wkst` instead where appropriate. Audit reports a missing
forwarder and does not install it. For apply, see the playbook's installer,
signature, permissions, backup, confirmation and restart steps. Confirm the
forwarder's service identity can read the Security channel and SQL log files;
the script does not grant those permissions. No Sysmon installation is implied.

## Linux and appliance logs

An ordinary TCP syslog listener such as port 20514 is a separate input from
Splunk forwarder receiving, commonly port 9997. Verify each sender's actual
configuration, input, index and permissions before creating anything; avoid
duplicate inputs and monitors. These transports are not automatically
encrypted or authenticated. Firewall and network changes need separate review.

## Prove and recover

Generate a harmless, distinctive new event on each sender and find it in the
expected index, host and bounded time range. Check the real SQL ERRORLOG,
Security channel and appliance logs where applicable. A TCP connection, running
forwarder or old event is not proof of end-to-end ingestion.

Recheck Splunk's real query/management scoring function and disk space after
the change. If it fails, follow the playbook's receiver/forwarder backup and
rollback boundaries; undo receiver and senders separately. Restore neither
unrelated firewall rules nor Splunk credentials blindly.
