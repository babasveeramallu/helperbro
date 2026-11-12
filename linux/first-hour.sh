#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

apply=false
rotate=false
allow_rerotate=false
disable_smbv1=false
kill_persistence=false
set_account_policy=false
host_firewall=false
management_cidr=()
public_ssh=false
skip_ports=()
exclude=()
include=()
changed=0
flagged=0
skipped=0
remove_units=()
remove_cron_files=()
report_dir="${CCDC_REPORT_DIR:-$PWD/ccdc-reports}"
while (($#)); do
    case "$1" in
        --apply) apply=true ;;
        --rotate-passwords) rotate=true ;;
        --allow-rerotate) allow_rerotate=true ;;
        --disable-smbv1) disable_smbv1=true ;;
        --kill-persistence) kill_persistence=true ;;
        --set-account-policy) set_account_policy=true ;;
        --apply-host-firewall) host_firewall=true ;;
        --management-cidr) (($# > 1)) || exit 2; management_cidr+=("$2"); shift ;;
        --public-ssh) public_ssh=true ;;
        --skip-port) (($# > 1)) || exit 2; skip_ports+=("$2"); shift ;;
        --include-account) (($# > 1)) || exit 2; include+=("$2"); shift ;;
        --exclude-account) (($# > 1)) || exit 2; exclude+=("$2"); shift ;;
        --remove-unit) (($# > 1)) || exit 2; remove_units+=("$2"); shift ;;
        --remove-cron-file) (($# > 1)) || exit 2; remove_cron_files+=("$2"); shift ;;
        --report-dir) (($# > 1)) || exit 2; report_dir="$2"; shift ;;
        --help|-h) printf '%s\n' 'Audit only by default. Categories: --set-account-policy, --apply-host-firewall with --management-cidr CIDR (repeat; SSH only from these ranges) or --public-ssh (SSH from anywhere, for a scored SSH service), plus --skip-port tcp:PORT or udp:PORT (repeat; leave a listener you do not trust closed), --rotate-passwords --include-account NAME --exclude-account NAME (repeat), --disable-smbv1, --kill-persistence --remove-unit NAME --remove-cron-file FILE. All changes require --apply.'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
# Walk from a trusted ancestor before creating anything. Reject symlinks and
# writable parents, including sticky directories: chmod alone cannot secure them.
report_error() { printf 'Unsafe report storage: %s\n' "$1" >&2; exit 2; }
[[ "$report_dir" == /* ]] || report_dir="$PWD/$report_dir"
[[ "$report_dir" != *$'\n'* ]] || report_error 'newlines in directory paths are not supported'
IFS=/ read -r -a report_parts <<< "$report_dir"
report_dir=/
for part in "${report_parts[@]}"; do
    [[ -n "$part" && "$part" != . ]] || continue
    [[ "$part" != .. ]] || report_error 'parent traversal (..) is not supported'
    [[ ! -L "$report_dir" && -d "$report_dir" ]] || report_error "$report_dir is not a real directory"
    read -r owner mode < <(stat -c '%u %a' -- "$report_dir")
    (( (owner == 0 || owner == EUID) && (8#$mode & 0022) == 0 )) || report_error "untrusted directory $report_dir"
    report_dir="${report_dir%/}/$part"
    if [[ ! -e "$report_dir" && ! -L "$report_dir" ]]; then
        mkdir -m 700 -- "$report_dir"
    fi
done
[[ ! -L "$report_dir" && -d "$report_dir" ]] || report_error "$report_dir is not a real directory"
read -r owner mode < <(stat -c '%u %a' -- "$report_dir")
(( owner == EUID && (8#$mode & 0022) == 0 )) || report_error "untrusted report directory $report_dir"
chmod 700 -- "$report_dir"
stamp="$(date +%Y%m%d-%H%M%S)"
report="$report_dir/linux-first-hour-$stamp.log"
ledger="$report_dir/password-rotation-ledger.tsv"
credentials="$report_dir/rotated-credentials-$stamp.txt"
# noclobber rejects existing files (including dangling symlinks); keep the
# descriptor so subsequent writes never resolve the report pathname again.
[[ ! -e "$report" && ! -L "$report" ]] || report_error "report already exists: $report"
(set -C; : > "$report")
exec {report_fd}>> "$report"
log() {
    local LC_ALL=C message="$2"
    # Keep untrusted filenames and command output within one printable record.
    if [[ "$message" == *[![:print:]]* ]]; then
        printf -v message '%q' "$message"
    fi
    case "$1" in
        CHANGE) changed=$((changed + 1)) ;;
        FLAG) flagged=$((flagged + 1)) ;;
        SKIP) skipped=$((skipped + 1)) ;;
    esac
    printf '[%s] %-6s %s\n' "$(date '+%F %T%z')" "$1" "$message" | tee -a "/dev/fd/$report_fd"
}

configure_host_firewall() {
    command -v ss >/dev/null 2>&1 || { log ERROR 'ss is required to discover host listeners.'; return 2; }
    command -v nft >/dev/null 2>&1 || { log ERROR 'nft is unavailable; host firewall was not changed.'; return 2; }
    listeners="$(ss -H -lntunp 2>&1)" || { log ERROR "Could not enumerate listeners: $listeners"; return 2; }
    ports=()
    while read -r netid _ _ _ local_addr _ owner_process; do
        [[ "$netid" == tcp || "$netid" == udp ]] || continue
        port="${local_addr##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        # Name the program behind every listener: a port is not safe just because it is open.
        skip=false
        for skip_entry in ${skip_ports[@]+"${skip_ports[@]}"}; do
            if [[ "$skip_entry" == "$netid:$port" ]]; then skip=true; fi
        done
        if [[ "$skip" == true ]]; then
            log FLAG "Listener $netid:$port (${owner_process:-program unknown}) stays CLOSED because of --skip-port."
            continue
        fi
        log INFO "Listener $netid:$port (${owner_process:-program unknown}) would be opened."
        ports+=("$netid:$port")
    done <<< "$listeners"
    mapfile -t ports < <(printf '%s\n' "${ports[@]}" | sort -u)
    log INFO "Detected host listeners: ${ports[*]:-(none)}"
    rules="/run/ccdc-host-$stamp.nft"
    {
        printf '%s\n' 'table inet ccdc_host {' ' chain input { type filter hook input priority -20; policy drop;' '  iifname lo accept' '  ct state established,related accept' '  icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept' '  meta l4proto ipv6-icmp icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept'
        for entry in "${ports[@]}"; do
            proto="${entry%%:*}"
            port="${entry#*:}"
            if [[ "$port" == 22 && "$proto" == tcp && "$public_ssh" != true ]]; then
                for cidr in "${management_cidr[@]}"; do
                    family="$(python3 -c 'import ipaddress,sys;print("ip" if ipaddress.ip_network(sys.argv[1],strict=False).version == 4 else "ip6")' "$cidr")"
                    printf '  %s saddr %s tcp dport 22 accept\n' "$family" "$cidr"
                done
            else
                printf '  %s dport %s accept\n' "$proto" "$port"
            fi
        done
        printf '%s\n' ' }' ' chain forward { type filter hook forward priority -20; policy drop; }' '}'
    } > "$rules"
    nft -c -f "$rules" || { log ERROR "nft rejected candidate host rules $rules"; return 2; }
    log INFO "Candidate host rules (audit-only unless --apply): $rules"
    cat "$rules" | tee -a "/dev/fd/$report_fd"
    [[ "$apply" == true ]] || return 0
    command -v systemd-run >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1 || { log ERROR 'Host firewall apply requires systemd-run for rollback.'; return 2; }
    nft list table inet ccdc_host >/dev/null 2>&1 && { log ERROR 'inet ccdc_host already exists; inspect/remove it explicitly.'; return 2; }
    (( EUID == 0 )) || { log ERROR 'Host firewall apply requires root.'; return 2; }
    [[ -t 0 ]] || { log ERROR 'Host firewall apply requires an interactive terminal.'; return 2; }
    backup="$report_dir/host-firewall-before-$stamp.nft"
    [[ ! -e "$backup" && ! -L "$backup" ]] || report_error "backup already exists: $backup"
    (set -C; nft list ruleset > "$backup")
    printf 'Type APPLY HOST FIREWALL AND KEEP ROLLBACK: '
    IFS= read -r answer
    [[ "$answer" == 'APPLY HOST FIREWALL AND KEEP ROLLBACK' ]] || { log INFO 'Host firewall cancelled.'; return 0; }
    unit="ccdc-host-firewall-rollback-$stamp"
    systemd-run --quiet --unit="$unit" --on-active=180s "$(command -v nft)" delete table inet ccdc_host || { log ERROR 'Could not arm rollback; no rules applied.'; return 2; }
    nft -f "$rules"
    log CHANGE "Applied host firewall; rollback=$unit.timer backup=$backup"
    log INFO 'Verify ping, every scored service and your own SSH access from another machine before cancelling rollback.'
}

configure_account_policy() {
    [[ -r /etc/os-release ]] || { log ERROR 'Cannot identify Linux distribution; PAM policy not changed.'; return 2; }
    . /etc/os-release
    case "${ID:-}" in debian|ubuntu) ;; *) log ERROR "Automatic PAM edits support Debian/Ubuntu only; detected ${ID:-unknown}. No files changed."; return 2 ;; esac
    if command -v authselect >/dev/null 2>&1; then log ERROR 'authselect-managed PAM detected; use the distribution profile workflow. No files changed.'; return 2; fi
    for file in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/login.defs; do
        [[ -f "$file" && ! -L "$file" ]] || { log ERROR "Missing/linked PAM file $file; refusing direct edits."; return 2; }
    done
    pwquality="$(find /lib /usr/lib -type f -name pam_pwquality.so -print -quit 2>/dev/null || true)"
    faillock_module="$(find /lib /usr/lib -type f -name pam_faillock.so -print -quit 2>/dev/null || true)"
    [[ -n "$pwquality" && -n "$faillock_module" ]] || { log ERROR 'pam_pwquality and pam_faillock modules must both be installed; no files changed.'; return 2; }
    helper="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/pam_policy.py"
    [[ -f "$helper" ]] || { log ERROR "PAM helper missing: $helper"; return 2; }
    if [[ "$apply" != true ]]; then
        log FLAG "PLAN ONLY: supported Debian/Ubuntu PAM stack detected; would set pwquality/history/faillock/login.defs. Modules: $pwquality ; $faillock_module"
        return 0
    fi
    (( EUID == 0 )) || { log ERROR 'PAM policy apply requires root.'; return 2; }
    [[ -t 0 ]] || { log ERROR 'PAM policy apply requires an interactive terminal.'; return 2; }
    printf 'Type APPLY PAM ACCOUNT POLICY: '
    IFS= read -r answer
    [[ "$answer" == 'APPLY PAM ACCOUNT POLICY' ]] || { log INFO 'PAM policy apply cancelled.'; return 0; }
    backup_dir="$report_dir/pam-backup-$stamp"
    if python3 "$helper" --root / --backup-dir "$backup_dir"; then
        log CHANGE "PAM policy applied and verified; backup=$backup_dir"
        log INFO 'Run a controlled test-account lockout validation; do not test a scored/operator account.'
    else
        log ERROR "PAM helper failed and attempted rollback; inspect $backup_dir and console output."
        return 1
    fi
}

fail() { code=$?; log ERROR "Failure at line ${BASH_LINENO[0]} (exit $code); stopping."; exit "$code"; }
trap fail ERR
if [[ "$apply" == true ]] && (( EUID != 0 )); then log ERROR 'Apply mode requires root.'; exit 2; fi
if (( EUID != 0 )); then log FLAG 'Audit is unprivileged; some user crontabs, keys, and system paths may be inaccessible.'; fi
if [[ "$host_firewall" == true ]]; then
    if [[ "$public_ssh" == true ]]; then
        ((${#management_cidr[@]} == 0)) || { log ERROR 'Use --public-ssh or --management-cidr, not both: they give opposite answers for SSH.'; exit 2; }
    else
        ((${#management_cidr[@]} > 0)) || { log ERROR '--apply-host-firewall needs --management-cidr CIDR (SSH only from that range) or --public-ssh (SSH from anywhere, for a scored SSH service).'; exit 2; }
        command -v python3 >/dev/null 2>&1 || { log ERROR 'python3 is required to validate management CIDRs.'; exit 2; }
        python3 - "${management_cidr[@]}" <<'PY'
import ipaddress, sys
for value in sys.argv[1:]: ipaddress.ip_network(value, strict=False)
PY
    fi
    for skip_entry in ${skip_ports[@]+"${skip_ports[@]}"}; do
        [[ "$skip_entry" =~ ^(tcp|udp):([1-9][0-9]{0,4})$ ]] || { log ERROR "--skip-port takes tcp:PORT or udp:PORT, for example tcp:4444; got: $skip_entry"; exit 2; }
        skip_port="${BASH_REMATCH[2]}"
        (( 10#$skip_port <= 65535 )) || { log ERROR "--skip-port port must be between 1 and 65535; got: $skip_entry"; exit 2; }
    done
fi
if [[ "$rotate" == true && ( ${#exclude[@]} -lt 2 || "${exclude[0]:-}" == "${exclude[1]:-}" || ${#include[@]} -eq 0 || ( "$apply" == true && ! -t 0 ) ) ]]; then log ERROR 'Rotation plan/apply needs two distinct scoring/break-glass exclusions and at least one --include-account; apply also needs an interactive terminal.'; exit 2; fi
if [[ "$kill_persistence" == true && ${#remove_units[@]} -eq 0 && ${#remove_cron_files[@]} -eq 0 ]]; then log ERROR 'Persistence removal requires explicitly named targets.'; exit 2; fi
os=unknown
[[ ! -r /etc/os-release ]] || { . /etc/os-release; os="${PRETTY_NAME:-$ID}"; }
init="$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || true)"
log INFO "OS=$os init=${init:-unknown} apply=$apply"
if [[ "$apply" != true ]]; then
    [[ "$rotate" != true ]] || for name in "${include[@]}"; do log FLAG "PLAN ONLY: would rotate explicitly selected account $name after per-account confirmation."; done
    [[ "$kill_persistence" != true ]] || log FLAG "PLAN ONLY: would disable/remove only the ${#remove_units[@]} named units and ${#remove_cron_files[@]} named cron files after confirmation."
    [[ "$set_account_policy" != true ]] || log FLAG 'PLAN ONLY: would configure pam_pwquality, pam_unix history, pam_faillock, and login.defs after preflight/backups.'
    [[ "$host_firewall" != true ]] || log FLAG "PLAN ONLY: would default-drop inbound, keep ping, allow detected listeners from every source (minus any --skip-port), allow SSH from ${management_cidr[*]:-every source (--public-ssh)}, and arm rollback."
fi
if [[ "$set_account_policy" == true ]]; then configure_account_policy; fi
if [[ "$host_firewall" == true ]]; then configure_host_firewall; fi
log INFO 'Read-only fingerprint commands: cat /etc/os-release; ps -p 1 -o comm='
log INFO 'Local account review from /etc/passwd:'
while IFS=: read -r name _ uid _ _ home shell; do
    if (( uid < 1000 )) || [[ "$name" == root || "$shell" =~ (nologin|/false)$ ]]; then log SKIP "Non-login/system user $name uid=$uid shell=$shell"; else log FLAG "Review login user $name uid=$uid home=$home shell=$shell"; fi
done < /etc/passwd
log INFO 'authorized_keys paths (key material is not printed):'
while IFS= read -r -d '' path; do
    details="$(stat -c 'owner=%U group=%G mode=%a' "$path" 2>/dev/null || printf 'stat=unavailable')"
    fingerprints="$(ssh-keygen -lf "$path" 2>/dev/null | tr '\n' ';' || true)"
    log FLAG "$path $details fingerprints=${fingerprints:-unreadable-or-empty}"
done < <(find / -type d \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media \) -prune -o -type f -name authorized_keys -print0 2>&"$report_fd" || true)
log INFO 'Per-user crontabs:'
if command -v crontab >/dev/null 2>&1; then
    while IFS=: read -r name _ _ _ _ _ _; do
        entries="$(crontab -u "$name" -l 2>/dev/null || true)"
        [[ -z "$entries" ]] || { log FLAG "crontab for $name"; printf '%s\n' "$entries" | tee -a "/dev/fd/$report_fd"; }
    done < /etc/passwd
else
    log INFO 'crontab unavailable'
fi
if [[ "$init" == systemd ]] && command -v systemctl >/dev/null 2>&1; then
    log INFO 'systemd timers:'
    systemctl list-timers --all --no-pager 2>&1 | tee -a "/dev/fd/$report_fd"
    log INFO 'Cron entries also present on systemd hosts:'
    for path in /etc/crontab /etc/cron.d/*; do [[ -f "$path" ]] || continue; log FLAG "Review $path"; sed -n '1,160p' "$path" | tee -a "/dev/fd/$report_fd"; done
else
    log INFO "non-systemd init ($init); cron.d and SysV init inventory:"
    for path in /etc/crontab /etc/cron.d/* /etc/init.d/*; do
        [[ -f "$path" ]] || continue
        log FLAG "Review $path"
        case "$path" in /etc/cron.d/*|/etc/crontab) sed -n '1,160p' "$path" | tee -a "/dev/fd/$report_fd" ;; esac
    done
fi
if command -v testparm >/dev/null 2>&1 && [[ -r /etc/samba/smb.conf ]]; then
    log INFO 'Samba detected; effective configuration follows:'
    testparm -s /etc/samba/smb.conf 2>&1 | tee -a "/dev/fd/$report_fd"
    if [[ "$disable_smbv1" == true && "$apply" != true ]]; then log FLAG 'PLAN ONLY: would set Samba client/server minimum protocol to SMB2_02 after validation and confirmation.'; fi
    if [[ "$disable_smbv1" == true && "$apply" == true ]]; then
        (( EUID == 0 )) || { log ERROR 'Samba change needs root'; exit 2; }
        command -v crudini >/dev/null 2>&1 || { log ERROR 'Install crudini before applying; refusing unsafe text edits.'; exit 2; }
        [[ -t 0 ]] || { log ERROR 'Samba change requires an interactive terminal'; exit 2; }
        printf 'Type SET SAMBA MINIMUM TO SMB2_02: '
        IFS= read -r answer
        [[ "$answer" == 'SET SAMBA MINIMUM TO SMB2_02' ]] || { log INFO 'Samba change cancelled'; exit 0; }
        backup="/etc/samba/smb.conf.ccdc-$stamp.bak"
        cp -p /etc/samba/smb.conf "$backup"
        if ! crudini --set /etc/samba/smb.conf global 'server min protocol' SMB2_02 || ! crudini --set /etc/samba/smb.conf global 'client min protocol' SMB2_02; then
            cp -p "$backup" /etc/samba/smb.conf
            log ERROR "Samba edit failed; restored $backup"
            exit 1
        fi
        if ! testparm -s /etc/samba/smb.conf >/dev/null 2>&1; then
            cp -p "$backup" /etc/samba/smb.conf
            log ERROR "testparm rejected the change; restored $backup"
            exit 1
        fi
        if [[ "$init" == systemd ]]; then
            for service in smbd smb samba; do
                if systemctl is-active --quiet "$service"; then systemctl restart "$service"; log CHANGE "Restarted Samba service $service"; break; fi
            done
        fi
        log CHANGE "Set Samba server/client minimum protocol to SMB2_02; backup=$backup"
    fi
elif command -v smbd >/dev/null 2>&1; then
    log FLAG 'Samba binary exists but config/testparm is unavailable; not changing protocol settings.'
elif [[ "$disable_smbv1" == true ]]; then
    log INFO 'Samba is not installed; protocol step skipped.'
fi

for unit in "${remove_units[@]}"; do
    [[ "$init" == systemd ]] || { log ERROR "Cannot manage systemd unit on init=$init: $unit"; exit 2; }
    systemctl cat "$unit" >/dev/null 2>&1 || { log ERROR "Unknown systemd unit: $unit"; exit 2; }
    log FLAG "Named unit selected for removal: $unit"
done
for path in "${remove_cron_files[@]}"; do
    [[ "$path" == /etc/cron.d/* && -f "$path" && ! -L "$path" ]] || { log ERROR "Cron target must be a regular non-symlink file under /etc/cron.d: $path"; exit 2; }
    log FLAG "Named cron file selected for removal: $path"
done
if [[ "$kill_persistence" == true && "$apply" == true ]]; then
    (( EUID == 0 )) || { log ERROR 'Persistence removal needs root'; exit 2; }
    [[ -t 0 ]] || { log ERROR 'Persistence removal requires an interactive terminal'; exit 2; }
    printf 'Type REMOVE ONLY NAMED TARGETS: '
    IFS= read -r answer
    [[ "$answer" == 'REMOVE ONLY NAMED TARGETS' ]] || { log INFO 'Persistence removal cancelled'; exit 0; }
    for unit in "${remove_units[@]}"; do systemctl disable --now "$unit"; systemctl mask "$unit"; log CHANGE "Disabled and masked $unit"; done
    for path in "${remove_cron_files[@]}"; do rm -- "$path"; log CHANGE "Removed $path"; done
fi
if [[ "$rotate" == true && "$apply" == true ]]; then
    (( EUID == 0 )) || { log ERROR 'Rotation needs root'; exit 2; }
    command -v openssl >/dev/null 2>&1 || { log ERROR 'openssl is required for secure password generation.'; exit 2; }
    command -v chpasswd >/dev/null 2>&1 || { log ERROR 'chpasswd is unavailable; refusing password rotation.'; exit 2; }
    # The ledger persists across runs; refuse links, shared files, and files
    # owned by anyone else before opening it in the now trusted directory.
    if [[ -e "$ledger" || -L "$ledger" ]]; then
        [[ -f "$ledger" && ! -L "$ledger" ]] || report_error 'ledger is not a regular file'
        read -r owner mode links < <(stat -c '%u %a %h' -- "$ledger")
        (( owner == EUID && links == 1 && (8#$mode & 0077) == 0 )) || report_error 'untrusted rotation ledger'
    else
        (set -C; : > "$ledger")
    fi
    exec {ledger_fd}>> "$ledger"
    users=()
    for name in "${include[@]}"; do
        account="$(awk -F: -v wanted="$name" '$1 == wanted { print; exit }' /etc/passwd)"
        [[ -n "$account" ]] || { log ERROR "Unknown account: $name"; exit 2; }
        IFS=: read -r actual _ uid _ _ _ shell <<< "$account"
        [[ "$actual" == "$name" && "$name" != root && "$shell" != */nologin && "$shell" != */false ]] || { log ERROR "Not an eligible interactive local account: $name"; exit 2; }
        printf '%s\n' "${exclude[@]}" | grep -Fxq -- "$name" && { log ERROR "Cannot both include and exclude $name"; exit 2; }
        (( uid >= 1000 )) || { log ERROR "System account UID is not eligible: $name"; exit 2; }
        if grep -Fq -- "$name"$'\t' "$ledger" 2>/dev/null; then
            [[ "$allow_rerotate" == true ]] || { log ERROR "$name is in the one-shot ledger; use --allow-rerotate only after manual review."; exit 2; }
        fi
        if ps -eo user= | grep -Fxq -- "$name"; then
            log SKIP "Password rotation candidate $name owns a running process; possible service dependency."
            continue
        fi
        users+=("$name")
    done
    ((${#users[@]} > 0)) || { log ERROR 'No eligible selected accounts remain after dependency checks.'; exit 2; }
    if [[ "$allow_rerotate" == true ]]; then
        printf 'Manual override enabled. Type ALLOW PASSWORD REROTATION: '
        IFS= read -r override
        [[ "$override" == 'ALLOW PASSWORD REROTATION' ]] || { log INFO 'Rerotation override cancelled'; exit 0; }
    fi
    printf 'Accounts to rotate: %s\nType ROTATE %s LOCAL PASSWORDS: ' "${users[*]:-(none)}" "${#users[@]}"
    IFS= read -r answer
    [[ "$answer" == "ROTATE ${#users[@]} LOCAL PASSWORDS" ]] || { log INFO 'Rotation cancelled'; exit 0; }
    [[ ! -e "$credentials" && ! -L "$credentials" ]] || report_error "credentials already exist: $credentials"
    set -C
    exec {credentials_fd}> "$credentials"
    set +C
    for name in "${users[@]}"; do
        password="$(openssl rand -base64 36 | tr -d '\n')"
        printf 'account=%s\tpassword=%s\tstatus=PENDING\n' "$name" "$password" >&"$credentials_fd"
        printf '%s\t%s\n' "$name" "$stamp" >&"$ledger_fd"
        if printf '%s:%s\n' "$name" "$password" | chpasswd; then
            printf 'account=%s\tstatus=CHANGED\n' "$name" >&"$credentials_fd"
            log CHANGE "Rotated $name; protected file=$credentials"
        else
            printf 'account=%s\tstatus=FAILED; verify manually\n' "$name" >&"$credentials_fd"
            log ERROR "Rotation failed for $name"
        fi
        unset password
    done
fi
log INFO "Complete. Changed=$changed flagged=$flagged skipped=$skipped report=$report credentials=$credentials"
