#!/usr/bin/env bash
# Configure EXISTING Splunk Enterprise on the packet's Debian 12 server.
# No packages, host firewall rules, users, passwords or scoring endpoints are changed.
set -Eeuo pipefail
umask 077

home=/opt/splunk
port=9997
service=Splunkd
output=/var/log/ccdc-splunk
audit=0
force=0
plaintext=0
render=0
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
usage() {
    cat <<'EOF'
Usage: sudo bash setup-debian-receiver.sh [options]
  --audit-only | --plan-only   Read-only inspection
  --force                     Skip typed APPLY confirmation
  --allow-plaintext           Explicitly accept unencrypted internal TCP transport
  --splunk-home PATH          Existing Splunk Enterprise home (default /opt/splunk)
  --service NAME              Existing systemd unit (default Splunkd)
  --port NUMBER               Receiving TCP port (default 9997)
  --output-directory PATH     Protected backup/log directory
  --render-only PATH          Write desired configs to PATH, without touching Splunk
EOF
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n $2 ]] || die "Missing value for $1"; }
while (($#)); do
    case "$1" in
        --audit-only|--plan-only) audit=1; shift ;;
        --force) force=1; shift ;;
        --allow-plaintext) plaintext=1; shift ;;
        --splunk-home) need_value "$@"; home=$2; shift 2 ;;
        --service) need_value "$@"; service=$2; shift 2 ;;
        --port) need_value "$@"; port=$2; shift 2 ;;
        --output-directory) need_value "$@"; output=$2; shift 2 ;;
        --render-only) need_value "$@"; render=1; render_dir=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[[ $port =~ ^[0-9]{1,5}$ ]] || die 'Port must be 1..65535'
port=$((10#$port))
((port >= 1 && port <= 65535)) || die 'Port must be 1..65535'
[[ $home == /* && $output == /* ]] || die 'Home and output directory must be absolute paths'
[[ $service =~ ^[A-Za-z0-9_.@-]+$ && $service != -* ]] || die 'Invalid systemd unit name'
((audit == 0 || render == 0)) || die '--render-only cannot be combined with --audit-only'

write_configs() {
    local dest=$1 index
    mkdir -p -- "$dest"
    # Only add a receiving input. Do not bind or change Splunk Web or management.
    printf '[splunktcp://%s]\ndisabled = 0\n' "$port" > "$dest/inputs.conf"
    cp -- "$script_dir/mssql-props.conf" "$dest/props.conf"
    : > "$dest/indexes.conf"
    for index in wineventlog sysmon mssql; do
        cat >> "$dest/indexes.conf" <<EOF
[$index]
homePath = \$SPLUNK_DB/$index/db
coldPath = \$SPLUNK_DB/$index/colddb
thawedPath = \$SPLUNK_DB/$index/thaweddb

EOF
    done
}
if ((render)); then
    [[ $render_dir == /* && ! -L $render_dir ]] || die 'Render directory must be absolute and not a symlink'
    [[ ! -e $render_dir ]] || die 'Render destination must not already exist'
    write_configs "$render_dir"
    printf 'Rendered configs only: %s\n' "$render_dir"
    exit 0
fi

exe="$home/bin/splunk"
app="$home/etc/apps/ccdc_windows_receiver"
[[ -x $exe ]] || die "Splunk Enterprise is not installed at $home"
[[ -d $home/etc/apps && ! -L $app ]] || die 'Invalid apps directory or receiver app symlink'
for managed in "$app/local" "$app/local/inputs.conf" "$app/local/indexes.conf" "$app/local/props.conf"; do
    [[ ! -L $managed ]] || die "Refusing managed symlink: $managed"
done
command -v systemctl >/dev/null || die 'systemctl is required'
command -v ss >/dev/null || die 'ss (iproute2) is required'
systemctl show "$service" --property=LoadState --value | grep -qx loaded || die "Unit $service not loaded; specify --service"
systemctl is-active --quiet "$service" || die "Existing Splunk service $service must be active"
# Refuse a wrong unit before restarting any service.
unit_pid=$(systemctl show "$service" --property=MainPID --value)
[[ $unit_pid =~ ^[1-9][0-9]*$ ]] || die "Cannot identify $service process"
[[ $(readlink -f "/proc/$unit_pid/exe") == "$(readlink -f "$home/bin/splunkd")" ]] ||
    die "Unit $service does not run $home/bin/splunkd"
inputs=$("$exe" btool inputs list)
indexes=$("$exe" btool indexes list)
conf_value() {
    local text=$1 section=$2 key=$3
    awk -v s="[$section]" -v k="$key" '
      /^\[/ {inside=($0==s); next}
      inside && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
        sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*$/, ""); print; exit
      }' <<< "$text"
}
receiver_ready() {
    local pid sockets
    pid=$(systemctl show "$service" --property=MainPID --value)
    sockets=$(ss -H -ltnp "sport = :$port")
    # Check the owner, not merely that some unrelated process has the port.
    [[ $pid =~ ^[1-9][0-9]*$ && $sockets == *"pid=$pid,"* ]]
}
validate_effective() {
    local index
    [[ $(conf_value "$inputs" "splunktcp://$port" disabled) =~ ^(0|false)$ ]] || {
        printf 'ERROR: higher-precedence configuration disables the receiver\n' >&2; return 1;
    }
    for index in wineventlog sysmon mssql; do
        [[ -n $(conf_value "$indexes" "$index" homePath) ]] &&
            [[ ! $(conf_value "$indexes" "$index" disabled) =~ ^(1|true)$ ]] || {
            printf 'ERROR: index %s is missing or disabled in effective configuration\n' "$index" >&2; return 1;
        }
    done
}
printf 'Receiver target: TCP %s; existing Splunk service: %s\n' "$port" "$service"
printf 'WARNING: TCP transport is UNENCRYPTED; only use on the approved competition network.\n'
printf 'Existing receiver disabled=%s\n' "$(conf_value "$inputs" "splunktcp://$port" disabled)"
for index in wineventlog sysmon mssql; do
    printf 'Index %s: homePath=%s\n' "$index" "$(conf_value "$indexes" "$index" homePath)"
done
if ((audit)); then
    printf 'AUDIT ONLY: would configure receiver/index app and restart only Splunk if effective settings change.\n'
    printf 'No firewall changes planned. Preserve scored query access and TCP 8089.\n'
    exit 0
fi
((EUID == 0)) || die 'Apply requires root'
((plaintext)) || die 'Apply requires --allow-plaintext after reviewing transport risk'
if ((!force)); then
    read -r -p 'Restarting Splunk may briefly interrupt scored queries/8089. Type APPLY: ' answer
    [[ $answer == APPLY ]] || die 'Not confirmed'
fi
[[ ! -L $output ]] || die 'Output directory must not be a symlink'
install -d -m 0700 -- "$output"
backup=$(mktemp -d "$output/receiver-XXXXXXXX")
exec > >(tee -a "$backup/apply.log") 2>&1
printf 'Backup/log: %s\n' "$backup"
had_app=0
if [[ -e $app ]]; then
    [[ -d $app ]] || die 'Receiver app is not a directory'
    cp -a -- "$app" "$backup/app"
    had_app=1
fi
write_configs "$backup/desired"
# Existing index storage/retention is owned by the site; never relocate it.
# Declare only missing indexes, preserving any already provisioned elsewhere.
: > "$backup/desired/indexes.conf"
for index in wineventlog sysmon mssql; do
    if ! grep -Fxq "[$index]" <<< "$indexes"; then
        cat >> "$backup/desired/indexes.conf" <<EOF
[$index]
homePath = \$SPLUNK_DB/$index/db
coldPath = \$SPLUNK_DB/$index/colddb
thawedPath = \$SPLUNK_DB/$index/thaweddb

EOF
    elif [[ -f $app/local/indexes.conf ]] && grep -Fxq "[$index]" "$app/local/indexes.conf"; then
        # Retain this script's earlier definitions on repeat runs.
        awk -v section="[$index]" '
          /^\[/ {inside=($0==section)} inside {print}
        ' "$app/local/indexes.conf" >> "$backup/desired/indexes.conf"
    fi
done
if [[ -f $app/local/inputs.conf && -f $app/local/indexes.conf && -f $app/local/props.conf ]] &&
    cmp -s "$backup/desired/inputs.conf" "$app/local/inputs.conf" &&
    cmp -s "$backup/desired/indexes.conf" "$app/local/indexes.conf" &&
    cmp -s "$backup/desired/props.conf" "$app/local/props.conf"; then
    validate_effective || die 'Effective receiver/index config is not usable'
    receiver_ready || die 'Config matches but Splunk is not listening; inspect splunkd.log'
    printf 'Already configured and listening; no restart.\n'
    exit 0
fi
restarted=0
rollback() {
    local rc=$?
    trap - ERR
    printf 'ERROR: apply failed (exit %s), restoring receiver app from %s\n' "$rc" "$backup" >&2
    if ((had_app)); then
        for file in inputs.conf indexes.conf props.conf; do
            if [[ ! -f $backup/app/local/$file ]]; then rm -f -- "$app/local/$file"; fi
        done
        if ! cp -a -- "$backup/app/." "$app/"; then
            printf 'ROLLBACK COPY FAILED; restore manually from %s\n' "$backup" >&2
        fi
    else
        # Only remove the two files created here, never a broad directory tree.
        rm -f -- "$app/local/inputs.conf" "$app/local/indexes.conf" "$app/local/props.conf"
    fi
    if ((restarted)); then
        systemctl restart "$service" || printf 'ROLLBACK RESTART FAILED; inspect service immediately\n' >&2
    fi
    exit "$rc"
}
trap rollback ERR
owner=$(stat -c '%u' "/proc/$unit_pid")
group=$(stat -c '%g' "/proc/$unit_pid")
install -d -m 0750 -o "$owner" -g "$group" -- "$app" "$app/local"
install -m 0640 -o "$owner" -g "$group" "$backup/desired/inputs.conf" "$app/local/inputs.conf"
install -m 0640 -o "$owner" -g "$group" "$backup/desired/indexes.conf" "$app/local/indexes.conf"
install -m 0640 -o "$owner" -g "$group" "$backup/desired/props.conf" "$app/local/props.conf"
inputs=$("$exe" btool inputs list)
indexes=$("$exe" btool indexes list)
validate_effective
restarted=1
systemctl restart "$service"
for ((attempt=0; attempt<60; attempt++)); do
    if systemctl is-active --quiet "$service" && receiver_ready; then
        trap - ERR
        printf 'Splunk active; receiver TCP %s is listening. Verify NEW Windows events in Search next.\n' "$port"
        printf 'Firewall unchanged: permit Windows-to-Debian TCP %s if needed, without restricting scored services.\n' "$port"
        exit 0
    fi
    sleep 1
done
printf 'ERROR: receiver failed to become ready within 60 seconds\n' >&2
false
