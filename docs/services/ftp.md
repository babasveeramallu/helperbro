# FTP deployment

Use the [shared preflight](README.md#shared-preflight). First locate the actual
FTP host, implementation, required accounts and files. Determine whether the
client expects FTP, explicit FTPS or implicit FTPS, and whether active or
passive transfers are used. Do not assume the FTP host or data-port range.

## Inventory

On Linux, identify the service, listeners, configured data range and NAT
mapping without restarting it:

```bash
hostname
sudo ss -lntup
sudo systemctl --failed
```

On an IIS FTP host, from elevated x64 PowerShell at the repository root:

```powershell
Get-Service FTPSVC -ErrorAction SilentlyContinue
.\windows\ftpserver\harden-ftpserver.ps1
```

The IIS audit writes a protected report and is not an installer. Do not
disable anonymous access or require FTPS until the required clients and
scoring behavior are verified. Preserve the existing files, account
permissions, control port and actual active/passive data path.

## Verify and recover

With an approved client and designated test account, authenticate, list the
required directory and retrieve a known test file. Test the actual data
transfer through the same firewall/NAT path as clients. Do not use command-line
passwords or upload over a production file. A banner probe checks only the
initial response and does not prove a login or transfer.

Back up the FTP configuration and data with a tested restore. After any
approved change, repeat login, listing, transfer, content and scoring checks.
If the test fails, restore the changed component using the agreed procedure;
a firewall rollback does not restore files or FTP settings.
