# Ubuntu workstation

[All machines](../README.md) | [Generic Linux workstation guide](../../services/linux-workstation.md)

## 1. Mission and facts to confirm

Keep the team's Linux desktop, browser, SSH and authorized service-checking paths
available. It may be the only working administration path to another machine or
an appliance. The diagram says Ubuntu workstation; its version, IP, DHCP/static
configuration, domain membership and installed tools are **unknown**.

| Record | Actual value |
|---|---|
| Hostname / Ubuntu version / desktop user | `REPLACE_VERIFIED_VALUES` |
| IP, gateway, DNS, interface and DHCP/static owner | `REPLACE_VERIFIED_VALUES` |
| Approved SSH key/account and console recovery path | `REPLACE_VERIFIED_VALUES` |
| Browser management URLs and expected certificates | `REPLACE_VERIFIED_VALUES` |
| Any scored workstation listener and its account | `REPLACE_OR_NOT_APPLICABLE` |
| Log receiver/input/index and staging location | `REPLACE_VERIFIED_VALUES` |

Do not copy a server's static address onto this host. Do not remove browser
profiles, keys, trusted certificates, routes or users merely because they are
unfamiliar. Verify ownership and official-access requirements first.

## 2. Establish working user and network access

Run on the Ubuntu workstation:

```bash
cat /etc/os-release
hostname
id
ip -br address
ip route
timedatectl
sudo ss -lntup
sudo systemctl --failed --no-pager
df -h
```

If installed and used by this desktop, inspect `resolvectl status` and
`nmcli connection show --active`. Do not replace `/etc/resolv.conf` or restart
NetworkManager as a generic repair; a resolver or connection manager may own it.

Verify authorized browser/SSH access to assigned systems before touching
firewall or authentication settings. Check host-key/certificate identity
through a trusted channel, not by accepting every warning.

## 3. Script map: what runs here

| Script | Purpose | What it does not provide |
|---|---|---|
| [Linux first-hour](../../../linux/first-hour.sh) | Host audit and explicitly selected policy/firewall/persistence/password/Samba categories | Desktop provisioning, network configuration or automatic Linux log forwarding |
| [Service probe](../../../linux/service-probe.sh) | Authorized single-target connectivity/content checks | Full service login, complete scoring or an intrusion scan |
| [PAM helper](../../../linux/pam_policy.py) | Supported Debian-style auth edits when called by first-hour | An audit-only command or support for every custom/domain PAM stack |
| [Standalone firewall](../../../linux/apply-firewall.sh) | Reviewed JSON-based input/output policy with timer | Automatic discovery of all browser, package, DNS, SSH and backend needs |

Windows `.ps1` hardeners and `Set-WindowsForwarder.ps1` do not configure this
Linux machine. Do not run them through a compatibility shell as a substitute.

### Baseline host audit

From the approved repository root:

```bash
sudo bash linux/first-hour.sh --report-dir /root/ccdc-reports/ubuntu-workstation
```

It creates a protected report and inventories local accounts, authorized-key
metadata/fingerprints, crontabs, timers and Samba if present. It does not print
key material, but the report can still reveal sensitive users/paths/schedules.
Do not upload it automatically or put it in Git.

Without sudo an audit can be incomplete. Review permission errors; absence of
visible findings is not proof every user's schedules/keys were inspected.

## 4. Use this machine to verify the environment

Use only authorized single targets and the live inventory. The packet defaults
in the [machine index](../README.md#1-pick-your-machine) are starting points,
not proof that those addresses still belong to the intended hosts.

For already-installed probe dependencies:

```bash
: "${AD_HOST:?Set AD_HOST to the verified AD host}"
: "${SQL_HOST:?Set SQL_HOST to the verified SQL host}"
: "${SPLUNK_HOST:?Set SPLUNK_HOST to the verified Splunk host}"
bash linux/service-probe.sh tcp "$AD_HOST" 5985
bash linux/service-probe.sh tcp "$SQL_HOST" 1433
bash linux/service-probe.sh tcp "$SPLUNK_HOST" 8089
```

These are only TCP connection checks. They do **not** prove authenticated
WinRM, a SQL query, a Splunk query/login or scoring. Use the actual protocols,
accounts and authorized clients for those acceptance checks.

For a real HTTPS page and known DNS answer:

```bash
: "${STORE_HOST:?Set STORE_HOST to the actual HTTPS certificate hostname}"
: "${PAGE_TEXT:?Set PAGE_TEXT to approved expected page text}"
: "${DNS_SERVER:?Set DNS_SERVER to the authorized DNS server}"
: "${DNS_ANSWER:?Set DNS_ANSWER to the expected name=address pair}"
bash linux/service-probe.sh https "$STORE_HOST" 443 --path / --expect "$PAGE_TEXT"
bash linux/service-probe.sh dns "$DNS_SERVER" 53 --expect "$DNS_ANSWER"
```

Adjust ports/paths to the real services. DNS expects an A/AAAA answer and needs
Python 3 on Linux. HTTPS checks trust/hostname and does not follow redirects.
Mail/FTP probes inspect plaintext banners only, not encrypted endpoints/logins.
Default timeout is five seconds; `--timeout` accepts 1-30.

Exit 0 = limited probe pass, 1 = fail, 2 = unknown/invalid. Missing tooling does
not produce a genuine pass. Record timestamp, source network, target and actual
functional checks. Ask the owner before installing new test clients.

## 5. Optional hardening and exact boundaries

### Authentication policy

Preview, not apply:

```bash
sudo bash linux/first-hour.sh --set-account-policy --report-dir /root/ccdc-reports/ubuntu-workstation-pam-plan
```

On supported non-authselect Debian/Ubuntu PAM, the selected category bundles:
minimum length 8 with character-class requirements, history 5, faillock deny 5/
unlock 1800 seconds, and new-account aging defaults 60/7/7 days.
It requires the modules and a recognized simple layout. A desktop using domain
SSSD, smartcards, fingerprint or custom PAM may be refused or need a separate
supported procedure; do not remove those integrations to satisfy the helper.

Apply additionally needs `--apply`, root, an interactive terminal and typed
confirmation. Backups go under `pam-backup-<time>` and failure attempts file
restoration. It is not a full identity or password rollback. Test a disposable
account and a new legitimate login before closing the original session.

### Other first-hour categories

| Option | Actual effect / caution |
|---|---|
| `--disable-smbv1` | If Samba exists, validate/edit its minimum protocols and restart an active Samba service; not a Linux SMB client-wide audit |
| `--kill-persistence` | Requires exact named units or regular `/etc/cron.d` files; stop/mask/remove only after investigation |
| `--remove-unit`, `--remove-cron-file` | Repeatable exact targets; removal saves/hashes files but does not restore all previous service state |
| `--rotate-passwords` | Explicit included local users plus two distinct exclusions; protected **plaintext** recovery file and one-shot ledger |
| `--allow-rerotate` | Manual override, not a way around missing dependency review |
| `--report-dir` | Trusted private directory; rejects unsafe parent ownership/permissions and symlinks it checks |

Do not rotate your current desktop/recovery/scoring account through a bulk
operation. The script's checks are not complete discovery of stored credentials
or application dependencies.

## 6. Firewall: do not cut off the team's control seat

First inspect existing nftables/UFW rules and authorized incoming needs.
The host may not require a public SSH server; do not start one to match a recipe.

If SSH is administration-only and an actual SSH listener must be preserved:

```bash
: "${MGMT_CIDR:?Set MGMT_CIDR to a verified approved administration network}"
sudo bash linux/first-hour.sh --apply-host-firewall --management-cidr "$MGMT_CIDR" --report-dir /root/ccdc-reports/ubuntu-workstation-firewall-plan
```

This is a **preview** without `--apply`; it still writes candidate `/run` rules
and checks nft syntax. If SSH is scored, use `--public-ssh` instead of management
CIDRs, never both. Review every discovered listener; an unknown process can be
allowed unless explicitly skipped.

**APPLY only after console and another working management path are confirmed:**

```bash
sudo bash linux/first-hour.sh --apply --apply-host-firewall --management-cidr "$MGMT_CIDR" --report-dir /root/ccdc-reports/ubuntu-workstation-firewall-apply
```

Use the same reviewed SSH policy as preview. The input-only `inet ccdc_host`
policy preserves required ICMP and listener-based allows; other chains still
apply. It does not add an output/forward chain or install a boot-persistent
firewall. It requires a working systemd rollback timer.

Within **180 seconds**, verify new SSH/user access where relevant, browser/
appliance access, name resolution, scoring and logs from the proper clients.
Only then run the exact printed keep command. On failure, use the exact printed
rollback; do not flush the ruleset. Existing `ccdc_host` must be investigated
before rerunning.

The separate standalone firewall defaults output to drop. That can block this
desktop's browser/SSH/DNS/update/logging paths and is not the recommended quick
workstation baseline. Do not layer it with another manager.

## 7. Logging and everyday checks

Use the [optional manual syslog setup](../README.md#6-linux-syslog-is-a-separate-optional-manual-setup)
only after receiver/index/transport approval. Verify one new local marker is
searchable centrally with the correct host and timestamp. This does not install
application-file monitoring, auditd or a Linux Universal Forwarder.

During the event, watch:

- Unexpected logged-in users, new listeners and service failures.
- DNS/routes/proxy changes relative to the recorded baseline.
- New or unexplained cron/timer/startup and authorized-key changes.
- Missing central logs, time drift and low disk/inodes.

Preserve evidence before disabling anything. A new key or program can also be
an authorized teammate's work. Do not remove an admin tool merely because it
appears in a suspicious-tool checklist.

## 8. Recovery and handoff

| Problem | Recovery boundary |
|---|---|
| Remote access lost after input policy | Console plus exact saved timer/rollback; verify existing manager as well |
| Browser cannot reach management | Check routes/DNS/proxy/certificate and egress policy before editing the remote machine |
| PAM/login changed | Restore the specific backed-up paths through the console; validate a new login |
| Key/account removed | Firewall rollback cannot restore it; use approved identity/key recovery |
| Log sender edit fails | Restore the exact forwarding fragment, validate and restart only the logging service |

Record actual workstation identity/network, authorized admin paths, approved
commit, reports/backups, timer outcome, source-to-target tests and central marker.
Keep original sessions until replacement access works, and keep all credentials,
private keys and raw sensitive reports out of Git/chat.
