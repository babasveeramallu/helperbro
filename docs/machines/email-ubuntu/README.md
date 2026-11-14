# Ubuntu Server email machine

[All machines](../README.md) | [Generic email guide](../../services/email.md)

## 1. Mission and inventory

Keep the existing mail system accepting, delivering and retrieving the expected
messages with the expected users. The diagram identifies Ubuntu Server, but its
version, address, mail products, domains and authentication provider are
**unknown**. Postfix/Dovecot commands below apply only if those products are found.
Helperbro does not install or configure a mail server.

| Record | Actual value |
|---|---|
| Hostname / Ubuntu version / IP / gateway / DNS | `REPLACE_VERIFIED_VALUES` |
| Mail domain / MX hostname and address / external relay | `REPLACE_VERIFIED_VALUES` |
| SMTP/submission service and port/TLS mode | `REPLACE_VERIFIED_VALUES` |
| POP/IMAP/webmail services and scored ports | `REPLACE_VERIFIED_VALUES` |
| Mailbox storage, ownership, quotas and service accounts | `REPLACE_VERIFIED_VALUES` |
| Authentication source and approved test mailboxes | `REPLACE_VERIFIED_VALUES` |
| Consistent mail/config backup and console contact | `REPLACE_VERIFIED_VALUES` |

Typical ports are SMTP 25, submission 587 or implicit TLS 465, IMAP 143/993,
POP3 110/995 and webmail 80/443. These are **possibilities**, not an instruction
to enable all of them. Preserve actual scoring protocols, ping, SSH and outbound
DNS/relay traffic. Changing an account password can break mailbox checks even
when the mail daemons remain healthy.

## 2. Establish working behavior first

On the mail server:

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
df -i
```

Identify the actual mailbox and queue filesystems. Disk **or inode** exhaustion
can stop delivery. Record the current MX/A/AAAA answers and expected TLS names
using an available DNS client or the authorized workstation.

If installed, these inspect common stacks without applying configuration:

```bash
# Postfix only; configuration can contain sensitive operational information.
sudo postfix check
sudo postconf -n
sudo postqueue -p

# Dovecot only; review configuration privately.
sudo doveconf -n
```

Do not install these packages simply because an example names them. A different
MTA, containerized stack, directory integration or webmail application needs its
own supported commands. Do not delete/flush a queue or mailbox to fix disk space.

## 3. Script map and first audit

| Script | Relevant behavior | Limit |
|---|---|---|
| [first-hour.sh](../../../linux/first-hour.sh) | Account/key metadata, cron/timer inventory; explicitly selected changes | Does not understand mailbox dependencies, MTA relay policy or spam filtering |
| [pam_policy.py](../../../linux/pam_policy.py) | Recognized Debian-style PAM policy, called by first-hour | Can break mail authentication; not a mail-account manager |
| [service-probe.sh](../../../linux/service-probe.sh) | Single-target TCP/HTTP(S)/DNS and plaintext mail-banner checks | Does not authenticate, send mail or read a mailbox |
| [apply-firewall.sh](../../../linux/apply-firewall.sh) | Reviewed JSON input/output firewall with timer | Incomplete output policy can block mail delivery, DNS and logging |

From the repository root:

```bash
sudo bash linux/first-hour.sh --report-dir /root/ccdc-reports/email
```

No category is selected, so this is a host audit, not mail hardening. The script
writes a protected log and may spend time finding key files and reading schedules.
Findings require investigation; they are not automatic account-removal orders.

## 4. Optional host changes: choose one at a time

### Password policy is a bundled, high-impact change

Preview only:

```bash
sudo bash linux/first-hour.sh --set-account-policy --report-dir /root/ccdc-reports/email-pam-plan
```

The script requires installed `pam_pwquality`/`pam_faillock` modules and a
recognized non-authselect Debian PAM layout. Missing prerequisites are an error,
not permission to replace a customized stack.

On a supported layout, apply would:

- Back up `common-auth`, `common-account`, `common-password` and `login.defs`
  under the report directory's `pam-backup-<time>`.
- Configure minimum length 8 and upper/lower/digit/other-character requirements.
- Set password history 5 and faillock deny 5/unlock 1800 seconds.
- Set new-account aging defaults to maximum 60/minimum 7/warning 7 days.
- Verify selected edits and attempt file restoration if the helper fails.

Unlike Windows first-hour, Linux does **not** make lockout a separate switch.
If mail authentication uses PAM, repeated bad passwords can lock a scored
mailbox. Existing domain/LDAP/SQL/virtual-mail authentication may not use this
stack at all. Do not apply without reviewing those paths and a console restore.
An approved apply uses the same category plus `--apply` and typed confirmation;
test only a disposable account, not an operator/scoring mailbox.

### Persistence removal and password rotation

`--kill-persistence` acts only on exact `--remove-unit` and
`--remove-cron-file` targets, but can stop a legitimate mail/backup job.
Removed files are saved and hashed under `persistence-<time>`; this is evidence,
not a full mailbox or original-service-state restore.

`--rotate-passwords` needs explicit include values and at least two distinct
exclusions. It checks some local-account/process dependencies, not all mail,
directory, application or scheduled dependencies. Its recovery file is
restricted **plaintext**, not encrypted. Never treat it as safe bulk mailbox
rotation. Keep scored accounts and all service/recovery accounts excluded.

## 5. Firewall and recovery timer

Inspect the active manager first:

```bash
sudo nft list ruleset
sudo ufw status verbose
```

Run the UFW command only if installed. UFW/firewalld/container rules can interact
with added nftables chains; one allow does not defeat another chain's drop.
Do not disable a manager or flush the ruleset to simplify the plan.

If SSH is scored, preview:

```bash
sudo bash linux/first-hour.sh --apply-host-firewall --public-ssh --report-dir /root/ccdc-reports/email-firewall-plan
```

The script discovers currently listening TCP/UDP ports, names their owning
processes and would open them publicly. It does not recognize a malicious SMTP
proxy or a missing legitimate service. Review all listeners and future service
needs before apply. A temporarily stopped service may not be discovered.

If SSH is administration-only, use verified `--management-cidr` values instead;
never combine them with `--public-ssh`. Do not scope scored SSH to a team subnet.
Use `--skip-port` only for an identified unauthorized listener; it can terminate
existing inbound connections.

**APPLY only after approval**, using the same reviewed SSH policy:

```bash
sudo bash linux/first-hour.sh --apply --apply-host-firewall --public-ssh --report-dir /root/ccdc-reports/email-firewall-apply
```

It requires root, an interactive terminal, nftables and a working systemd
rollback mechanism. The timer removes `inet ccdc_host` after **180 seconds**.
Verify real send/retrieve/login paths and SSH from another machine, then use the
exact printed keep command. On failure use the printed immediate rollback.
This firewall does not add an output/forward chain or install a persistent
boot configuration. Existing managers still matter.

The standalone JSON firewall is a different workflow: it also defaults output
to drop. Mail relays may use many external recipients/MX addresses. Do not assume
a static incomplete outbound list is workable, and do not stack both tools.

## 6. End-to-end mail acceptance

From an authorized workstation, use designated test mailboxes and the actual
service protocol/TLS mode. Enter passwords interactively, never in arguments.

1. Confirm domain/MX and mail-host DNS answers from the required network.
2. Connect using the expected certificate hostname; verify trust and expiry.
3. Perform the required authenticated submission or approved inbound delivery.
4. Retrieve the new message over the actual POP/IMAP/webmail path.
5. Check sender, recipient, unique subject/body, arrival time and mailbox.
6. Confirm required relay behavior with the service owner; do not make the
   server an open relay or probe unrelated third-party mail systems.
7. Check queue growth, local logs, fresh central receipt and current scoring.

For a **plaintext SMTP greeting** only, if that endpoint is expected:

```bash
: "${MAIL_HOST:?Set MAIL_HOST to the authorized mail host}"
bash linux/service-probe.sh smtp "$MAIL_HOST" 25
```

Use the actual port. Do not use this plaintext banner test as proof that an
implicit-TLS endpoint such as 465/993/995 is broken. Exit 0 is only the probe's
limited pass; exit 1 is failure and 2 is unknown/invalid.

## 7. Logs, troubleshooting and recovery

Follow the [manual Linux syslog procedure](../README.md#6-linux-syslog-is-a-separate-optional-manual-setup)
after the receiver exists. First-hour does not deploy a Linux forwarder.
Verify whether mail writes to journald, `/var/log/mail.log`, a product log or
container stdout; file paths are not universal.

| Symptom | Investigate before changing anything |
|---|---|
| SMTP connects but messages never arrive | Queue/deferred reason, relay DNS, recipient routing, mailbox quota and disk/inodes |
| Send works, retrieval fails | Correct protocol/TLS mode, mailbox identity, auth provider and storage permissions |
| Login fails after hardening | PAM/lockout, expired credentials, LDAP/AD reachability and client TLS compatibility |
| External check fails, local check works | Bind address, DNS/MX, NAT/upstream policy and active host chains |
| Plaintext banner probe fails on TLS port | Wrong probe type, not proof the encrypted service is down |
| Central mail logs absent | Local log generation, sender input, raw TCP versus Splunk receiving input, index and time range |

For rollback, restore only the modified configuration from its actual backup,
validate with the installed product's checker, then reload/restart only that
service in an approved window. Restore mailbox data through a consistent,
product-supported procedure. Firewall rollback restores neither mailboxes nor
passwords. PAM file backups do not undo password rotation.

## 8. Handoff

- [ ] Mail product/version, domains, ports/TLS modes and auth source recorded.
- [ ] A new message completed the required delivery and retrieval flow.
- [ ] Queue/disk/inodes, scoring and SSH remain healthy.
- [ ] Backups, changed files, timers and recovery scope recorded.
- [ ] A fresh central marker is searchable, or missing coverage is assigned.
- [ ] No mailbox content/passwords committed to Git or pasted into team chat.
