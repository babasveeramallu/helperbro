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

## Database dependencies

Identify the database engine and host, actual listening address, authorized
application clients, service account, connection method and backup owner.
Test a permitted application transaction before changing database access.
MySQL/MariaDB and PostgreSQL are not interchangeable with SQL Server and may
use different configuration paths and access controls.

Do not blindly bind a database to localhost or restrict PostgreSQL access to
local connections: a separate application host or scored check may need
remote access. Likewise, don't run interactive database hardening tools or
change passwords until dependencies, approved credential handling and rollback
are established. Never copy example passwords into commands or reports. If an
approved restriction is made, preserve the original configuration, validate
the engine-specific syntax and reload procedure, then test the application
and database authentication from each required client.

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
