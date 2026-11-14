# SQL Server, SMB and RDP deployment

Use the [shared preflight](README.md#shared-preflight). Helperbro does not
install SQL Server or repair SQL accounts, databases, shares or RDP.

## Inventory and backup

Record the SQL instance name, listener and authentication mode, database and
share paths, service accounts, remote access and logging destination. Check
the current account/scoring requirements before changing passwords. Verify
restorable database and share backups with the service owner.

## Audit

From elevated x64 PowerShell at the repository root:

```powershell
Get-Service 'MSSQLSERVER','MSSQL$*' -ErrorAction SilentlyContinue
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-SmbShare
.\windows\Set-PacketFirewall.ps1 -Role MSSQL -AuditOnly
```

The firewall audit checks that a SQL engine service exists but does not check
the database, share content or login. It preserves existing broad allow rules.
If forwarding is approved, follow [Splunk](splunk.md) with role `MSSQL` and
confirm the actual SQL ERRORLOG location and forwarder read permissions.

## Verify before and after each change

1. From an authorized client, perform the real SQL login and approved
   read-only query against the correct instance and database.
2. Open the required SMB share and verify the expected file and content with
   the intended account. Do not modify the business file as a test.
3. Open and authenticate a second RDP session; retain the first session.
4. Confirm new SQL and Windows events reach their expected Splunk indexes.
5. Confirm current scoring checks, not just listener ports.

For firewall apply/commit/rollback, use the
[Windows defense playbook](../../windows/DEFENSE-PLAYBOOK.md) and its
independent timer. A firewall rollback does not restore a database, share,
SQL login or changed service account. Stop and use the relevant tested
recovery procedure if any transaction fails.
