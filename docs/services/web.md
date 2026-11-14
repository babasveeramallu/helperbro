# Web and e-commerce deployment

Use the [shared preflight](README.md#shared-preflight). Confirm the web host,
application, virtual host, TLS certificate, database, content and required
URLs; a TCP connection or generic home page does not prove an order workflow.

## Inventory

On Linux, inspect without changing services:

```bash
hostname
sudo ss -lntup
sudo systemctl --failed
```

On an IIS host, use elevated PowerShell at the repository root:

```powershell
Get-Service W3SVC
.\windows\webserver\harden-webserver.ps1
```

The IIS role audit writes a protected report; it targets IIS on Server 2019
and is not a Linux web-server installer. Review its plan and compatibility
before choosing any `-Apply` category. TLS changes and application restarts
can break scoring; coordinate them separately.

## Verify

From an authorized client, request the actual hostname and path with a trusted
certificate, validate response code and expected page content, and exercise
the approved application flow and backend connection without altering live
orders. The optional [service probe](README.md#optional-service-probes) checks
one URL and expected text only. If FTP shares the host, follow [FTP](ftp.md)
and preserve its control and data ports.

## Recover

Back up and test restoration of application files, configuration, certificates
and database separately. If a change breaks the application, use the tested
component-specific rollback and recheck content, authenticated workflows,
logs and the real scoring portal. Do not flush firewall rules as recovery.
