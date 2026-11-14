#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf '%s\n' 'Usage: service-probe.sh PROTOCOL HOST PORT [--expect TEXT] [--path /PATH] [--timeout SECONDS]' \
        'Protocols: http, https, dns, tcp, smtp, pop3, imap, ftp. DNS requires --expect NAME=ADDRESS.' \
        'Only probe hosts you own or are explicitly authorized to test.'
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
(($# >= 3)) || { usage >&2; exit 2; }
protocol=$1 host=$2 port=$3
shift 3
expect=- path=/ timeout=5
while (($#)); do
    case "$1" in
        --expect|--path|--timeout)
            (($# >= 2)) || die "Missing value for $1"
            case "$1" in
                --expect) expect=$2 ;;
                --path) path=$2 ;;
                --timeout) timeout=$2 ;;
            esac
            shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$protocol" in http|https|dns|tcp|smtp|pop3|imap|ftp) ;; *) die 'Unsupported protocol' ;; esac
[[ $host =~ ^[A-Za-z0-9_][A-Za-z0-9_.:-]*$ || $host =~ ^:[A-Fa-f0-9:.]+$ ]] || die 'Invalid host'
[[ $port =~ ^[0-9]{1,5}$ ]] || die 'Invalid port'
port=$((10#$port))
((port >= 1 && port <= 65535)) || die 'Port must be 1..65535'
[[ $timeout =~ ^[0-9]{1,2}$ ]] || die 'Invalid timeout'
timeout=$((10#$timeout))
((timeout >= 1 && timeout <= 30)) || die 'Timeout must be 1..30 seconds'
[[ -n $expect && $expect != *$'\n'* && $expect != *$'\r'* ]] || die 'Invalid expected text'
[[ $path == /* && $path != *[[:space:][:cntrl:]]* ]] || die 'Invalid HTTP path'
if [[ $protocol == dns ]]; then
    [[ $expect =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*=([0-9A-Fa-f:.]+)$ ]] || die 'DNS requires --expect NAME=ADDRESS'
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../vendor/labyrinth/core/probe/probe.sh
source "$script_dir/../vendor/labyrinth/core/probe/probe.sh"
result=$(lab_probe_service "$protocol" "$host" "$port" "$expect" "$timeout" "$path")
printf '%s\n' "$result"
case "$result" in
    'pass '*) exit 0 ;;
    'fail '*) exit 1 ;;
    'unknown '*) exit 2 ;;
    *) die 'Probe returned an invalid result' ;;
esac
