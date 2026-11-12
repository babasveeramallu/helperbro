#!/usr/bin/env bash
set -Eeuo pipefail

script="${1:-$(dirname "$0")/first-hour.sh}"
tmp="$(mktemp -d)"
trap 'rm -f -- "$tmp/rules"; rmdir -- "$tmp"' EXIT
export TEST_RULES="$tmp/rules"

source <(sed 's/\r$//' "$script" | sed -n '/^configure_host_firewall() {$/,/^}$/p' |
    sed 's@rules="/run/ccdc-host-$stamp.nft"@rules="$TEST_RULES"@')

ss() {
    if [[ "$listener" == present ]]; then
        printf '%s\n' 'tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("test",pid=1,fd=1))'
    fi
}
nft() {
    [[ "$1" == -c && "$2" == -f && "$3" == "$TEST_RULES" ]]
    ! grep -Eq '^  ([[:space:]]*dport|[^ ]+ dport[[:space:]]+accept)' "$TEST_RULES"
}
log() {
    if [[ "$1" == SKIP ]]; then skipped=$((skipped + 1)); fi
}

run_plan() {
    listener="$1"
    skip_ports=("${@:2}")
    skipped=0
    stamp=test
    public_ssh=true
    apply=false
    exec {report_fd}>/dev/null
    configure_host_firewall >/dev/null
    exec {report_fd}>&-
    log SKIP 'test counter'
    [[ "$skipped" == 1 ]]
}

run_plan none
if grep -q ' dport ' "$TEST_RULES"; then
    echo 'No listeners should produce no port rules.' >&2
    exit 1
else
    status=$?
    (( status == 1 )) || exit "$status"
fi
run_plan present tcp:4444
if ! grep -Fxq '  tcp dport 4444 drop' "$TEST_RULES"; then
    echo 'A skipped TCP listener should have an explicit drop rule.' >&2
    exit 1
fi
skip_line="$(grep -nFx '  tcp dport 4444 drop' "$TEST_RULES" | cut -d: -f1)"
established_line="$(grep -nFx '  ct state established,related accept' "$TEST_RULES" | cut -d: -f1)"
if (( skip_line >= established_line )); then
    echo 'Skipped-port drops must precede the established-connection accept.' >&2
    exit 1
fi
if grep -Fxq '  tcp dport 4444 accept' "$TEST_RULES"; then
    echo 'A skipped TCP listener must not have an accept rule.' >&2
    exit 1
fi
run_plan present udp:4444
grep -q '^  tcp dport 4444 accept$' "$TEST_RULES"
grep -Fxq '  udp dport 4444 drop' "$TEST_RULES"

validate() (
    host_firewall=true
    public_ssh=true
    management_cidr=()
    skip_ports=("$1")
    skipped=0
    source <(sed 's/\r$//' "$script" | sed -n '/^if \[\[ "$host_firewall" == true \]\]; then$/,/^if \[\[ "$rotate" == true /p' | sed '$d')
    log SKIP 'test counter'
    [[ "$skipped" == 1 ]]
)

for port in tcp:1 udp:65535 tcp:4444; do validate "$port"; done
for port in tcp:0 tcp:04444 udp:65536 tcp:999999 tcp:x; do
    if validate "$port"; then
        printf 'Invalid skip port accepted: %s\n' "$port" >&2
        exit 1
    fi
done
echo 'First-hour firewall regression tests passed.'
