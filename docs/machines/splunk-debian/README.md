# Debian Splunk machine

[All machines](../README.md) | [Full forwarding playbook](../../../splunk/PLAYBOOK.md)

## 1. Role, defaults and protected services

This machine is the central log receiver and search system. The documented
packet default is **Debian 12 / Splunk Enterprise 10.0.2 / `172.20.240.20`**.
Those are **unverified packet values**, not a live inventory or a claim that the
installed version is patched. Record the real version, hostname, address,
installation owner, unit name, storage paths, license and scoring checks.

The supplied scoreboard confirms **five** checks: **`splunk-chrony`,
`splunk-mgmt`, `splunk-ping`, `splunk-query`, `splunk-ssh`**. Chrony and SSH
are explicitly scored, not optional housekeeping. The screenshot does not show
ports, accounts or transactions; do not infer those from the column names alone.

| Endpoint | Purpose / boundary |
|---|---|
| UDP 123 usual NTP default | Verify `splunk-chrony` against the real time service and remote client path |
| TCP 8089 packet default | Management API/search and authentication; verify both `splunk-mgmt` and `splunk-query` definitions |
| TCP 8000, if configured | Splunk Web; the screenshot does not establish whether either check uses it |
| TCP 9997 default | Splunk-to-Splunk forwarder receiving, not raw syslog |
| TCP 20514 example | Separate optional plaintext syslog input; **not** configured by the script |
| SSH actual port, usually TCP 22 | `splunk-ssh`: verify a new authorized login |
| ICMP echo | `splunk-ping`; not a TCP/UDP port |

Management and query may share an endpoint; do not invent a separate port for
each. TCP 9997 and example 20514 support logging but are not named scored checks
in this snapshot. No script here configures or hardens chrony.

Never delete indexed data, reset a scoring password, change the machine identity
or source-limit public services as a routine hardening step. Coordinate any
restart with all operators: both scoring and ingestion can pause.

## 2. Inspect the existing installation first

Run on Debian, from the approved repository root:

```bash
cat /etc/os-release
hostname
ip -br address
ip route
timedatectl
systemctl list-unit-files --type=service | grep -i splunk
sudo ss -lntup
df -h
df -i
sudo /opt/splunk/bin/splunk version
```

Use the **actual** home if not `/opt/splunk`. Record the systemd unit whose main
process is that installation's `splunkd`; it may not be `Splunkd`.
Inspect index storage mounts as well as the installation filesystem.
Check query/login and existing sender freshness before making a change.

Do not copy a version-specific mitigation from an old runbook without verifying
the installed product, current vendor advisory and feature dependencies.
In particular, this procedure does not disable internal database/helper services,
delete apps or upgrade Enterprise automatically.

## 3. Which scripts belong here

| File | Actual behavior |
|---|---|
| [setup-debian-receiver.sh](../../../splunk/setup-debian-receiver.sh) | Audit/configure an **existing running** Splunk Enterprise installation; manage a dedicated receiver app |
| [mssql-props.conf](../../../splunk/mssql-props.conf) | SQL text ERRORLOG encoding, record boundaries and timestamp parsing; copied by setup |
| [Set-WindowsForwarder.ps1](../../../splunk/Set-WindowsForwarder.ps1) | Runs on the three Windows senders, **not** on Debian |
| [WindowsForwarder.Common.ps1](../../../splunk/WindowsForwarder.Common.ps1) | Forwarder rendering/discovery helpers; not a Debian entry point |
| [Linux first-hour](../../../linux/first-hour.sh) | Optional host audit/selected hardening; does not configure Splunk or Linux log forwarding |
| [generate-configs.py](../../../splunk/generate-configs.py) | Older renderer requiring `config/splunk.json` in the repository's **parent** workspace; writes there under `generated/splunk`; not deployment |

Do not layer the older generator's outputs over the dedicated receiver/forwarder
apps. They use different configuration assumptions and may duplicate collection.

## 4. Receiver: audit, then approved apply

After confirming these values, set them consistently in the current Bash session:

```bash
# Documented defaults ONLY; replace after verifying this installation.
SPLUNK_HOME=/opt/splunk
SPLUNK_UNIT=Splunkd
SPLUNK_PORT=9997

sudo bash splunk/setup-debian-receiver.sh \
  --audit-only --splunk-home "$SPLUNK_HOME" \
  --service "$SPLUNK_UNIT" --port "$SPLUNK_PORT"
```

Audit checks the installation, loaded/active unit and main process, then reads
merged inputs/indexes with `btool`. It creates no script report/backup/app.
It refuses an inactive installation or wrong unit; start by diagnosing those,
not reinstalling Splunk.

**APPLY only in the approved restart window**, and only if plaintext internal
transport is authorized:

```bash
sudo bash splunk/setup-debian-receiver.sh \
  --allow-plaintext --splunk-home "$SPLUNK_HOME" \
  --service "$SPLUNK_UNIT" --port "$SPLUNK_PORT"
```

Type `APPLY`. Do not add `--force` casually. Plaintext approval acknowledges
unencrypted, unauthenticated transport; ACKs do not provide TLS or sender trust.
For TLS requirements stop and design matching certificates/inputs/outputs.

### What apply does, in order

1. Require root and valid paths/unit/port; reject checked managed symlinks.
2. Create a protected unique backup/log directory and preserve an existing app.
3. Render a `splunktcp` receiver, needed index definitions and SQL parsing.
4. Preserve externally provisioned index paths and existing managed definitions.
5. Compare the three managed files with desired contents.
6. If identical, verify effective configuration and its owned listener; avoid
   restarting merely because the script was rerun.
7. Otherwise install configs with ownership matching the existing Splunk process.
8. Recheck effective settings; fail on overriding disabled receiver/indexes.
9. Restart **only the selected Splunk service** and wait up to 60 one-second
   attempts for an active service and port owned by its main PID.
10. Print readiness. You must still prove fresh event ingestion and scoring.

### Files and parameters

| Location | Contents |
|---|---|
| `$SPLUNK_HOME/etc/apps/ccdc_windows_receiver/local/` | `inputs.conf`, `indexes.conf`, `props.conf` |
| `/var/log/ccdc-splunk/receiver-XXXXXXXX/` default | `apply.log`, `desired/`, and `app/` if an app existed |

Backups use restrictive permissions; live app directories/files are installed
as 0750/0640. Protect them as sensitive operational data.

| Flag | Default / effect |
|---|---|
| `--audit-only`, `--plan-only` | Inspect only |
| `--splunk-home` | `/opt/splunk`; absolute existing home |
| `--service` | `Splunkd`; must match the running installation |
| `--port` | 9997, range 1-65535 |
| `--output-directory` | `/var/log/ccdc-splunk`; absolute backup/log parent |
| `--allow-plaintext` | Required for this baseline's apply |
| `--force` | Skip typed confirmation, not other safety checks |
| `--render-only` | Write sample files to a **new absolute directory** without live validation; not audit or deployment |

The script does not install Enterprise, enable its unit at boot, change licenses,
size retention, configure Web/8089, rotate accounts or modify any firewall.

## 5. Windows senders and data semantics

After receiver readiness, follow each Windows README:
[AD](../ad-windows/README.md), [MSSQL](../mssql-windows/README.md),
[workstation](../workstation-windows/README.md).

| Destination index | Data from the managed Windows app |
|---|---|
| `wineventlog` | XML Security/System/Application and available selected operational channels |
| `sysmon` | Sysmon Operational **if already installed** |
| `mssql` | Selected SQL **text ERRORLOG** files, not complete SQL statement auditing |

Windows event subscriptions use `start_from=oldest` with `current_only=1`:
they collect events arriving while UF runs, **not old history or the stopped-UF
window**. SQL file monitoring can ingest existing text initially. Do not call
these settings a lossless history archive or clear checkpoints as a quick fix.

The receiver does not install Windows field extractions. Validate compatible
Windows add-on/knowledge objects and real `EventCode`/user fields before trusting
field-based alerts. SQL timestamps, encoding, multiline behavior and timezone
must be checked against the actual ERRORLOG.

## 6. Linux logs are a different input

The managed TCP 9997 input accepts Splunk forwarder protocol. Do not send rsyslog
text to it. For approved raw TCP syslog:

1. Inspect existing Splunk inputs and sender configs to avoid duplicates.
2. In Splunk Web, use **Settings > Data inputs > TCP** to create/verify the chosen
   input, for example 20514, with `sourcetype=syslog` and the approved index.
3. Confirm that index exists and its retention/access are appropriate. The
   Windows receiver script creates missing `wineventlog`, `sysmon`, `mssql`
   definitions only; it does not provision an arbitrary Linux index.
4. Coordinate network policy for actual senders and selected port separately.
5. Follow [Linux sender setup](../README.md#6-linux-syslog-is-a-separate-optional-manual-setup)
   and search a newly generated marker from each sender.

Debian may have only journald rather than `/var/log/auth.log`. Inspect existing
logging before adding rsyslog or file monitors. Do not recursively monitor all
of `/var/log` without reviewing duplicates, volume, access and unwanted data.
Host syslog ingestion is not proof that web/mail application files are monitored.

## 7. Verification: three independent levels

### A. Receiver health and original scoring

With the previously verified variables still set:

```bash
sudo systemctl is-active "$SPLUNK_UNIT"
sudo ss -ltnp "sport = :${SPLUNK_PORT:?Set the verified receiving port}"
sudo "$SPLUNK_HOME/bin/splunk" btool inputs list --debug
sudo "$SPLUNK_HOME/bin/splunk" btool indexes list --debug
sudo tail -n 100 "$SPLUNK_HOME/var/log/splunk/splunkd.log"
```

Confirm correct process ownership, index state, disk health and actual query/
management login. A socket or Web login alone does not establish scoring.

Also verify **both** management and query definitions, a new SSH login, ping
and chrony. Do not mark the machine healthy solely because ingestion works.

For an existing chrony installation, inspect without changing the clock/config:

```bash
# Confirm the actual unit name first; Debian commonly uses chrony.service.
systemctl status chrony --no-pager
chronyc tracking
chronyc sources -v
sudo ss -lunp 'sport = :123'
```

Missing commands, an inactive unit or a different configured time product need
investigation, not a blind chrony installation/replacement. Local synchronization
and a UDP listener do not prove that the scorer can receive an NTP reply. From
an authorized client, verify the actual scored NTP transaction and access policy.
Do not enable chrony's remote command port merely because NTP is scored, force
a clock step or overwrite time sources as routine hardening. Time changes also
affect log correlation and domain authentication.

### B. New Windows marker

Have each sender operator generate the marker shown in their README, then
replace the literal marker below in Splunk Search:

```spl
index=wineventlog sourcetype=XmlWinEventLog* earliest=-10m latest=now "REPLACE_EXACT_NEW_MARKER"
| stats count latest(_time) as newest by host sourcetype
| eval newest=strftime(newest,"%F %T")
```

Confirm the real source host and timestamp. Save marker/search/time, not
passwords. Old events from the right host are not deployment verification.

### C. Coverage and SQL parsing

```spl
(index=wineventlog OR index=sysmon) sourcetype=XmlWinEventLog* earliest=-15m latest=now
| stats count latest(_time) as newest by host index sourcetype
| eval newest=strftime(newest,"%F %T")
```

```spl
index=mssql sourcetype=ccdc:mssql:errorlog earliest=-15m latest=now
| stats count latest(_time) as newest by host source
| eval newest=strftime(newest,"%F %T")
```

A quiet SQL ERRORLOG or absent Sysmon can legitimately yield no recent results.
Check source activity and prerequisites rather than restarting SQL or pretending
every channel is present. For Linux use the actual approved index, source type
and exact new marker; the index name is not known in advance.

## 8. Failure, reruns and rollback

| Symptom | Check first |
|---|---|
| Script refuses service/home | Actual unit's main PID/executable and existing active installation |
| Port absent after restart | Apply log, effective inputs and `journalctl -u ACTUAL_UNIT` |
| Files match but port absent | Runtime errors/overrides; rerunning is not a guaranteed repair |
| TCP works, search empty | Source event, output route, index enabled/permissions, license, disk, time and parsing |
| One sender silent | That host's UF state/identity/channels and `TcpOutputProc` errors |
| Scoring red after receiver change | Identify which of the five checks failed; inspect its actual endpoint/authentication and coordinated recovery; stop further changes |
| Chrony check fails | Actual NTP daemon, synchronization, UDP bind, client access rules and network policy; Web/API tests are unrelated |
| Disk nearly full | Index storage and retention owner; never delete buckets as emergency housekeeping |

The receiver attempts app restoration on errors after its rollback trap is armed,
and attempts to restart restored configuration if restart was attempted.
Inspect `ROLLBACK ... FAILED` messages; it is not transactional.

After a successful deployment there is **no `--rollback` flag**. Preserve current
evidence, identify that run's correct `app/` backup, restore only the managed
configuration with correct ownership, validate effective settings and restart
only Splunk in an approved window. If the app was new, remove only its identified
managed configuration after preserving it and checking for later changes.
Do not delete `etc/apps`, index directories or the whole installation.
See [detailed recovery](../../../splunk/PLAYBOOK.md#9-rollback-reruns-and-recovery-limits).

## 9. Toolkit checks and handoff

In a noncompetition environment:

```bash
bash splunk/test-debian-receiver.sh
```

This checks syntax/rendering/arguments, not live restart, permissions or delivery.
Do not run a real receiver apply as a documentation test.

- [ ] Actual home, version, unit, process owner, ports and index paths recorded.
- [ ] Restart window, backup path and transport approval recorded.
- [ ] AD, MSSQL, Windows workstation and each configured Linux sender proved a new marker.
- [ ] Windows XML fields and actual SQL log parsing checked; gaps explicit.
- [ ] All five named checks verified: chrony, management, query, SSH and ping.
- [ ] Actual Web/API port mapping, disk health and ingestion verified separately.
- [ ] No passwords, raw secret-bearing logs or private keys committed.
