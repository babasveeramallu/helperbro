#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/bin"
cat > "$fixture/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$PROBE_ARGS"
if [[ ${PROBE_CURL_FAIL:-0} == 1 ]]; then echo 'certificate rejected' >&2; exit 60; fi
printf '%s\n%s' "${PROBE_BODY:-Welcome}" "${PROBE_CODE:-200}"
EOF
cat > "$fixture/bin/dig" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '192.0.2.10'
EOF
chmod +x "$fixture/bin/curl" "$fixture/bin/dig"
export PATH="$fixture/bin:$PATH" PROBE_ARGS="$fixture/curl-args"
probe="$root/linux/service-probe.sh"
check() {
    local expected=$1 text=$2 result code
    shift 2
    if result=$(bash "$probe" "$@" 2>&1); then code=0; else code=$?; fi
    [[ $code == "$expected" && $result == *"$text"* ]] ||
        { printf 'FAIL: expected %s/%s; got %s/%s\n' "$expected" "$text" "$code" "$result" >&2; exit 1; }
}
check 0 'pass status 200' https example.test 443 --expect Welcome --path /health
grep -qx -- '--noproxy' "$PROBE_ARGS"
grep -qx -- '--max-filesize' "$PROBE_ARGS"
if grep -qx -- '-k' "$PROBE_ARGS"; then echo 'FAIL: TLS verification disabled' >&2; exit 1; fi
check 1 'expected text is missing' http example.test 80 --expect Missing
PROBE_CODE=503 check 1 'fail status 503' http example.test 80
PROBE_CURL_FAIL=1 check 1 'certificate rejected' https example.test 443
check 0 'pass example.test answered 192.0.2.10' dns example.test 53 --expect example.test=192.0.2.10
check 1 'did not answer' dns example.test 53 --expect example.test=192.0.2.11
check 2 'DNS requires' dns example.test 53
check 2 'DNS requires' dns example.test 53 --expect '-bad=192.0.2.10'
check 2 'Invalid host' http '-bad' 80
check 2 'Port must be' http example.test 0
check 2 'Invalid HTTP path' http example.test 80 --path $'/health\r\nHost: bad'
(
    source "$root/vendor/labyrinth/core/probe/probe.sh"
    command() {
        if [[ ${1:-} == -v && ${2:-} == curl ]]; then return 1; fi
        builtin command "$@"
    }
    lab_probe_exchange() {
        printf '%s' "$4" > "$fixture/request"
        printf 'HTTP/1.0 200 OK\r\n\r\nWelcome'
    }
    [[ $(lab_probe_http http ::1 8080 Welcome 5 /) == 'pass status 200' ]]
    grep -Fxq $'Host: [::1]:8080\r' "$fixture/request"
)
printf 'PASS service probe checks\n'
