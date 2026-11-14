# Service deployment guides

These are generic procedures for existing services, not evidence that a
particular host, packet or scoring check has been verified. Replace every
operator-supplied value with the live, authorized value. Consult the current
event rules and service owner before acting.

| Service | Guide |
|---|---|
| Domain controller and DNS | [AD/DNS](ad-dns.md) |
| SQL Server, SMB and RDP | [MSSQL](mssql.md) |
| Windows workstation | [Windows workstation](windows-workstation.md) |
| Linux workstation | [Linux workstation](linux-workstation.md) |
| Outside test workstation | [Outside workstation](kali.md) |
| Web / e-commerce | [Web](web.md) |
| Mail | [Email](email.md) |
| FTP | [FTP](ftp.md) |
| Splunk receiver and forwarders | [Splunk](splunk.md) |
| Palo Alto firewall | [Palo Alto](palo-alto.md) |
| VyOS router | [VyOS](vyos.md) |

## Shared preflight

1. Verify the current host, OS, address, service owner, official access,
   actual scoring checks, dependencies and allowed change window. Record
   working service transactions before making a change.
2. Keep console access and an existing administrator session. Agree a tested
   recovery method and an escalation contact. Snapshots and system-state
   backups are not interchangeable; do not assume either is available.
3. Use an approved copy of the complete repository. If the host is offline,
   ask officials or the environment owner for an approved transfer or
   network-restoration method. Do not assume removable media, private
   staging, shares or an upload-only portal are authorized.
4. Start from the repository root. Linux examples are for Bash on the Linux
   host; Windows examples are for x64 Windows PowerShell 5.1 or PowerShell 7
   on the Windows host. Elevation is identified per command.
5. Review the script's help and plan, verify backups and recovery, then apply
   only an approved category. Don't run `auto-harden.ps1` as a prerequisite.
   Record before/after health, errors, changed files and rollback location.
6. Preserve ping, scored/public services, authentication, logs and other
   dependencies. Do not assume a firewall allows traffic merely because a
   port rule was added; existing block rules and upstream devices also matter.
7. Keep credentials and reports protected. Do not paste passwords into
   command lines, shared chat or incident reports. Coordinate any scoring
   credential update through the approved process before changing it.

## Obtain the toolkit when downloads are permitted

The following examples download the current `main` branch, which can change.
Check the approved release/version with the operator first; use a declared
version if the event requires one. The new service guides and probes are
available from `main` only after their pull request is merged.

On Windows, in x64 PowerShell, download to a **new** staging directory. Use
an elevated session only when the role's audit or apply instructions require
it. This does not install or run the toolkit:

```powershell
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Stage = Join-Path $env:ProgramData 'CCDC\Toolkit'
if (Test-Path -LiteralPath $Stage) { throw "Staging directory already exists: $Stage" }
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
$Archive = Join-Path $Stage 'helperbro.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/babasveeramallu/helperbro/archive/refs/heads/main.zip' -OutFile $Archive -ErrorAction Stop
Expand-Archive -LiteralPath $Archive -DestinationPath $Stage -ErrorAction Stop
Set-Location -LiteralPath (Join-Path $Stage 'helperbro-main')
```

Confirm `README.md`, `windows`, `linux`, `splunk` and `vendor` are present;
retain the whole folder rather than copying one script. If the download or
extraction fails, stop and resolve it using an approved method. Do not assume
enabling TLS 1.2 repairs an internet outage, and don't overwrite an existing
staging folder. Downloading over HTTPS is not a substitute for checking the
approved version or authenticating its published release.

On Linux, if Git and an approved public download path already exist:

```bash
git clone https://github.com/babasveeramallu/helperbro.git "$HOME/helperbro"
cd "$HOME/helperbro"
git rev-parse HEAD
```

`git clone` fails if the destination already exists and is not empty. Confirm
the reported commit against the approved version, and run commands from this
directory. Do not install Git or use an alternate transfer method without
appropriate approval.

## Optional service probes

These single-target probes must be used only against systems you own or are
authorized to test. They do not authenticate, perform a complete business
transaction, validate file contents beyond the supplied text, or prove scoring
or log ingestion. TCP is a connection test; mail/FTP checks are banners.
HTTPS verifies the server certificate and hostname; use the actual DNS name
and a trusted certificate. Redirects are not followed. DNS expects an A or
AAAA answer; on Windows, only DNS port 53 is supported.

On Linux, set `TARGET` to the authorized host and `EXPECTED` to the exact
expected text or `name=address` DNS answer before using these examples:

```bash
bash linux/service-probe.sh https "$TARGET" 443 --path / --expect "$EXPECTED"
bash linux/service-probe.sh dns "$TARGET" 53 --expect "$EXPECTED"
```

On Windows, set `$Target` and `$Expected` first:

```powershell
.\windows\Invoke-ServiceProbe.ps1 -Protocol https -Target $Target -Port 443 -Expect $Expected
.\windows\Invoke-ServiceProbe.ps1 -Protocol dns -Target $Target -Port 53 -Expect $Expected
```

Protocols are `http`, `https`, `dns`, `tcp`, `smtp`, `pop3`, `imap`, and
`ftp`. Default timeout is five seconds; `--timeout` or `-Timeout` accepts
1–30 seconds. Windows DNS uses `Resolve-DnsName -QuickTimeout`, not the
requested `-Timeout` value. The command emits `pass`, `fail`, or `unknown`: exit code 0
means pass, 1 means a failed check, and 2 means unknown. Invalid input exits
nonzero, and on Linux also uses code 2. A missing tool may produce `unknown`,
not a pass. These are point-in-time
checks; repeat actual business and scoring transactions after changes.

## Local regression checks

Run these in a noncompetition environment; they use fixture files and local
loopback, not a real service configuration:

```bash
bash linux/test-service-probe.sh
```

```powershell
.\windows\Test-ServiceProbe.ps1
.\windows\Test-AddnsGuard.ps1
```

These tests do not establish production DNS, SQL, mail, appliance, firewall,
Splunk ingestion or OS compatibility.
