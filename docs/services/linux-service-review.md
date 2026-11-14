# Linux service and persistence review

Use the [shared preflight](README.md#shared-preflight). This is an inspection
and change-review procedure for an existing Linux host, not a list of services
to disable. Know the scored transactions, management access, dependencies and
recovery path before changing anything. An unfamiliar process, port or job
is a lead, not proof of compromise or proof that it is unnecessary.

## Inventory

Run on the authorized host. These commands inspect state; `sudo` is needed
for process ownership and some logs. Some commands require systemd and may be
unavailable on other distributions. Record errors and review the host's
actual init and firewall tools instead of assuming missing output is clean.

```bash
hostname
cat /etc/os-release
ps -p 1 -o comm=
sudo ss -lntup
sudo ss -ntup
sudo systemctl list-units --type=service --state=running --no-pager
sudo systemctl list-unit-files --type=service --no-pager
sudo systemctl list-sockets --all --no-pager
sudo systemctl list-timers --all --no-pager
sudo systemctl --failed --no-pager
```

`ss` shows a point in time, not every dependency. A listener, its firewall
opening and its application are separate things. Check the actual firewall
backend and both IPv4 and IPv6; don't introduce UFW or firewalld on top of
an existing nftables policy without understanding the combined rules.

Helperbro's `bash linux/first-hour.sh` also inventories accounts, key
fingerprints, user crontabs and timers. It creates a protected report even
without `--apply`; read `--help` and obtain approval first. Review
`/etc/crontab`, `/etc/cron.d`, periodic cron directories, relevant user
crontabs, system and user systemd units and `at` jobs where present. The
script's inventory is not exhaustive. `crontab -l` alone shows only the
invoking user's table; account for privileges and errors.

## Investigate a candidate

For each listener or job, identify its owner, execution account, executable
and arguments, trigger, package, configuration, expected purpose and
dependencies. Record the original service, timer, socket and firewall state
and the exact recovery steps. Confirm a PID is still the same process before
inspecting it. Substitute a verified PID or unit name below:

```bash
ps -fp PID
sudo readlink -f /proc/PID/exe
systemctl status EXAMPLE.service --no-pager
systemctl cat EXAMPLE.service
systemctl show EXAMPLE.service -p FragmentPath -p DropInPaths -p ExecStart -p User -p TriggeredBy
systemctl list-dependencies --reverse EXAMPLE.service --no-pager
sudo journalctl -u EXAMPLE.service --since '1 hour ago' --no-pager
```

Inspect referenced scripts, symlinks, parent-directory permissions and
overrides without executing unknown content. Where supported, compare package
ownership and file integrity with a trusted baseline. Names, file locations
and package ownership alone do not prove trustworthiness. A timer or socket
may start a service even if it is not currently running.

For authentication and incident context, check the applicable journal,
authentication logs and, where available, login records. `last` and `lastb`
depend on local records and permissions; absence of a record is not proof
that a login did not happen. Avoid unbounded filesystem scans during scoring:
they can consume I/O, cross mounts and miss evidence hidden from the host.
Preserve suspect files, metadata and logs under the event's incident process;
don't execute or delete a suspicious job merely to identify it.

Reports and logs can contain credentials, commands and personal data. Store
them with restricted access and review before any approved sharing. Use the
required competition change log; record time, host, action, reason, result and
undo without including secrets.

## Change one item only after review

1. Agree with the owner whether to keep, investigate or retire the item.
   Treat remote access, DNS, time, logging, applications and scoring as
   required until proven otherwise. Identify an alternate access path.
2. Obtain approval, preserve the original configuration and state, and
   document an exact undo for this host. Do not mask units or remove a
   crontab wholesale as a shortcut. Keep suspect evidence for incident
   response rather than automatically deleting it.
3. If an item is confirmed unnecessary, change only that item. Review related
   sockets, timers and dependencies separately. For firewall changes, use the
   installed backend's tested rollback; don't flush a ruleset. A port or SSH
   restriction must not block scored paths, including required ping.
4. From another authorized host, test fresh administration connections,
   actual application transactions, DNS and logging. Recheck the item and
   firewall state, including after any approved persistence change or reload.
   Observe the relevant schedule where feasible.
5. On failure, stop and execute the recorded, tested undo; restore the
   original enablement and running state rather than blindly enabling every
   component. Retest both management and scoring.

For a distribution-specific worked example, see the
[service and job review procedure](https://github.com/RichMix/CCDC-Playbook/blob/main/guides/retire-unneeded-jobs-services-ports.md).
Its firewalld and RPM steps do not apply unchanged to every host.
