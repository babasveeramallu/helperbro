# Rocky Linux e-commerce runbook

[All machines](README.md) | [Generic web guide](../docs/services/web.md)

## 1. Mission and facts to fill in

Keep the existing store, its required content, authentication and backend
transactions available while collecting evidence and making controlled changes.
The diagram says **Rocky Linux**; the version, address, web server, application,
database and container layout are **unknown**. Do not assume WordPress, Apache,
Nginx, MariaDB or Docker is installed.

The supplied scoreboard confirms **`ecomm-http` and `ecomm-ping`**.
The `ecomm` prefix maps to this role, not a verified hostname. HTTP commonly
uses TCP 80, but the screenshot does not give the port, vhost, path, expected
content or redirect behavior. Ping is ICMP, not a TCP/UDP port. SSH, HTTPS and
FTP are not separate named checks in this snapshot; preserve any required
administration and application dependencies rather than guessing extra services.

| Record before changing anything | Actual value |
|---|---|
| Hostname / Rocky version / IP / default route | `REPLACE_VERIFIED_VALUES` |
| Store hostname, HTTP(S) port, required path and expected page text | `REPLACE_VERIFIED_VALUES` |
| Web service / document root / application owner | `REPLACE_VERIFIED_VALUES` |
| Database/cache/API endpoints and service accounts | `REPLACE_VERIFIED_VALUES` |
| FTP control/passive range, if actually scored | `REPLACE_OR_NOT_APPLICABLE` |
| Container-published ports / active firewall owner | `REPLACE_OR_NOT_APPLICABLE` |
| Backup, console contact and approved maintenance window | `REPLACE_VERIFIED_VALUES` |

HTTP 80 and HTTPS 443 are common defaults, not verified scoring ports. Keep required
ping, SSH authentication, DNS and backend paths. Public services must remain
generally reachable where required by current event rules.

## 2. Read-only inventory

Run on Rocky, from the approved repository root:

```bash
cat /etc/os-release
hostname
ip -br address
ip route
timedatectl
sudo ss -lntup
sudo systemctl --failed --no-pager
sudo systemctl list-units --type=service --state=running --no-pager
df -h
findmnt
getenforce
```

Use the observed service names. Inspect configuration with the installed
server's own check, such as `sudo nginx -t` or `sudo apachectl configtest`,
**only if that product is installed**. These checks do not reload it.
If containers are present, inventory their published ports and volumes using
their actual engine; a host socket list alone can miss forwarded traffic.

Record the current firewall manager before touching it:

```bash
sudo nft list ruleset
systemctl is-active firewalld
```

An inactive/missing firewalld service does not mean there is no firewall.
Do not flush nftables or disable SELinux to make the application work.

## 3. Relevant scripts and actual effects

| Script | What it does here | What it does not do |
|---|---|---|
| [Linux first-hour](../linux/first-hour.sh) | Account/key metadata, cron/timer inventory; optional reviewed host changes | Install or harden the store, patch the app, remove web shells automatically |
| [Service probe](../linux/service-probe.sh) | Check one authorized HTTP(S) path and expected text | Authenticate a shopper, validate checkout/database state or prove scoring |
| [Standalone firewall](../linux/apply-firewall.sh) | JSON-driven timed nftables input/output policy | Know the store's database, DNS, payment, update or container dependencies |
| [PAM helper](../linux/pam_policy.py) | Debian-style helper used elsewhere | Support automatic Rocky PAM edits |

Windows IIS hardening scripts are **not applicable**. Database, web vhost,
certificate, SELinux context and application changes need product-specific
procedures after the actual stack is identified.

### Baseline audit

```bash
sudo bash linux/first-hour.sh --report-dir /root/ccdc-reports/ecommerce
```

No hardening category is selected. It creates a mode-700 report directory and a
`linux-first-hour-<time>.log`; it still reads account/key metadata and schedules.
Keep reports private. Review findings with the service owner before acting.

### Rocky password policy: manual, not applied

```bash
sudo bash linux/first-hour.sh --set-account-policy --report-dir /root/ccdc-reports/ecommerce-pam-review
```

Expect manual authselect guidance and **exit 2**, including without `--apply`.
The script has not applied PAM. This stops later categories in the same run;
do not combine it with firewall work.

The printed procedure checks packages, current authselect profile/features and
backups before editing quality/history settings. Keep the identity provider and
existing features; do not force-select SSSD or edit generated PAM blindly.
Lockout is a separate manual approval decision. Aging defaults do not prove
existing accounts changed. The end of the printed procedure is **recovery**,
not another apply step. Review it rather than pasting the whole output.

## 4. Firewall: preview before considering apply

Use only after identifying active rules, business dependencies, an approved
change window and console access. Do not stack this with firewalld or the
standalone firewall without understanding the combined rules.

If SSH is scored, the first-hour preview is:

```bash
sudo bash linux/first-hour.sh --apply-host-firewall --public-ssh --report-dir /root/ccdc-reports/ecommerce-firewall-plan
```

Despite its name, `--apply-host-firewall` selects a category; **without `--apply`
it only renders/checks the plan**. Root is useful/needed for privileged discovery,
`/run` output and nftables syntax validation. Inspect every discovered listener:
the script would allow an attacker's listener too unless explicitly skipped.

If SSH is confirmed administration-only, use verified ranges instead:

```bash
: "${MGMT_CIDR:?Set MGMT_CIDR to an approved administration CIDR}"
sudo bash linux/first-hour.sh --apply-host-firewall --management-cidr "$MGMT_CIDR" --report-dir /root/ccdc-reports/ecommerce-firewall-plan-private-ssh
```

Do not combine `--public-ssh` and `--management-cidr`. Repeat
`--management-cidr` for multiple approved networks. Preview
`--skip-port tcp:PORT` or `udp:PORT` only for an identified unauthorized listener;
it drops even existing inbound connections to that port.

### APPLY, only after the plan is accepted

For the approved public-SSH case:

```bash
sudo bash linux/first-hour.sh --apply --apply-host-firewall --public-ssh --report-dir /root/ccdc-reports/ecommerce-firewall-apply
```

Type the requested confirmation, then have another authorized client verify the
store and SSH immediately. A systemd timer removes `inet ccdc_host` after
**180 seconds** unless you run the **exact printed keep command** after checks.
Record the deadline and use the exact printed rollback command on failure.
Do not guess a unit name or stop unrelated timers.

This policy filters **host input only**. It does not create an output/forward
chain, preserve a reboot-persistent deployment, or override another chain's drop.
Docker-published and routed traffic need their own verification.
The script refuses to reuse an existing `ccdc_host` table.

The separate JSON firewall adds **outbound default drop** as well as input
filtering. Do not use its example JSON unchanged. See
[standalone firewall behavior](../README.md#standalone-linux-firewall-script)
for every required field, timer and container-egress caveat.

## 5. Verify the store, not just its port

On an authorized client, set the actual hostname and required text:

```bash
: "${STORE_HOST:?Set STORE_HOST to the actual certificate hostname}"
: "${PAGE_TEXT:?Set PAGE_TEXT to approved expected page text}"
bash linux/service-probe.sh https "$STORE_HOST" 443 --path / --expect "$PAGE_TEXT"
```

Change the port/path to the real service. HTTPS verifies the certificate and
hostname and does not follow redirects. An HTTP redirect may be correct; check
the expected final URL separately rather than weakening verification.
Probe exit 0 = pass, 1 = fail, 2 = unknown/invalid; missing tools are not success.

Before and after each change verify:

- Correct virtual host, required content, status and certificate chain.
- Approved test login and non-destructive cart/application workflow.
- Correct backend access using the intended service identity.
- Required FTP login/listing/data transfer, if applicable; control port alone
  does not prove passive/active data access.
- Fresh access/error/authentication logs, central receipt if configured, and the
  actual scoring portal from the correct network.

Do not place real orders, clear carts/mailboxes/databases, or restart a backend
solely to generate verification traffic.

## 6. Logging and investigation

Follow [optional Linux syslog](README.md#6-linux-syslog-is-a-separate-optional-manual-setup)
only after the Debian operator confirms the input and destination index.
Ordinary syslog forwarding does not automatically monitor application files.
Identify the actual web access/error logs, reverse-proxy logs and application
audit trail. Do not guess paths or install duplicate monitors.

Review unexpected accounts, SSH key fingerprints, changed startup/cron entries,
unknown listeners and suspicious web content. Preserve hashes, timestamps and
copies before isolating a confirmed malicious file. A recent modification time
alone is not evidence that a file belongs to an attacker.

Never apply `--kill-persistence` to a web/database unit merely because you do not
recognize its name. Named removal can stop/mask a service; its backups do not
restore database state or application transactions.

## 7. Failure and recovery

| Symptom | First checks / recovery boundary |
|---|---|
| Works locally, fails externally | Bind address, DNS/vhost, upstream rules, host firewall manager and actual path |
| HTTP answers but store is broken | Backend identity, application error log, expected URL/content and approved test transaction |
| Breaks after firewall | Use printed timer/rollback procedure; inspect other firewall chains; do not flush the ruleset |
| Login fails after PAM work | Keep console; use the specific authselect/PAM backup and distribution recovery procedure |
| App config fails validation | Restore the exact changed file with ownership/SELinux metadata; validate before any reload |
| Missing central logs | Prove local generation, sender, input/index and marker search separately |

Take product-supported backups of content, configuration, certificates/secrets
and databases with a tested consistent restore. A copy of `/etc` or a firewall
snapshot is not a complete e-commerce backup. Record prior service states before
restarting anything; coordinate downtime rather than repeatedly restarting.

## 8. Handoff

- [ ] Actual stack/version, endpoints, database and firewall owner recorded.
- [ ] Scored content/transactions and administrative access still work.
- [ ] Selected script categories, report/backup paths and recovery commands saved.
- [ ] Firewall timer deliberately committed or recovery verified; no guesswork.
- [ ] New log marker searchable, or missing coverage assigned to an owner.
- [ ] No credential or private key copied into reports, chat or Git.
