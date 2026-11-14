#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
real_curl=$(command -v curl || true)
fixture=$(mktemp -d)
server_pid=
cleanup() {
    if [[ -n $server_pid ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    rm -rf -- "$fixture"
}
trap cleanup EXIT
mkdir -p "$fixture/bin"
cat > "$fixture/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$PROBE_ARGS"
if [[ ${PROBE_CURL_FAIL:-0} == 1 ]]; then echo 'certificate rejected' >&2; printf '\n000'; exit 60; fi
if [[ ${PROBE_CURL_NO_DIAG:-0} == 1 ]]; then printf '\n000'; exit 7; fi
printf '%s\n%s' "${PROBE_BODY:-Welcome}" "${PROBE_CODE:-200}"
EOF
cat > "$fixture/bin/dig" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$PROBE_DIG_ARGS"
if [[ ${PROBE_DIG_FAIL:-0} == 1 ]]; then exit 1; fi
printf '%s\n' "${PROBE_DNS_ANSWER:-192.0.2.10}"
EOF
chmod +x "$fixture/bin/curl" "$fixture/bin/dig"
export PATH="$fixture/bin:$PATH" PROBE_ARGS="$fixture/curl-args" PROBE_DIG_ARGS="$fixture/dig-args"
probe="$root/linux/service-probe.sh"
check() {
    local expected=$1 text=$2 result code
    shift 2
    if result=$(bash "$probe" "$@" 2>&1); then code=0; else code=$?; fi
    [[ $code == "$expected" && $result == *"$text"* ]] ||
        { printf 'FAIL: expected %s/%s; got %s/%s\n' "$expected" "$text" "$code" "$result" >&2; exit 1; }
}
check 0 'pass status 200' https example.test 443 --expect Welcome --path /health
[[ $(head -n 1 "$PROBE_ARGS") == '-q' ]]
grep -qx -- '--globoff' "$PROBE_ARGS"
grep -qx -- '--noproxy' "$PROBE_ARGS"
grep -qx -- '--max-filesize' "$PROBE_ARGS"
if grep -qx -- '-k' "$PROBE_ARGS"; then echo 'FAIL: TLS verification disabled' >&2; exit 1; fi
if grep -qx -- '-L' "$PROBE_ARGS"; then echo 'FAIL: redirects followed' >&2; exit 1; fi
grep -Fxq -- 'https://example.test:443/health' "$PROBE_ARGS"
PROBE_CODE=299 check 0 'pass status 299' http example.test 80
PROBE_CODE=300 check 0 'pass status 300' http example.test 80
PROBE_CODE=399 check 0 'pass status 399' http example.test 80
PROBE_CODE=400 check 1 'fail status 400' http example.test 80
PROBE_CODE=199 check 1 'fail status 199' http example.test 80
check 1 'expected text is missing' http example.test 80 --expect Missing
PROBE_CODE=503 check 1 'fail status 503' http example.test 80
PROBE_CURL_FAIL=1 check 1 'curl exited 60: certificate rejected' https example.test 443
PROBE_CURL_NO_DIAG=1 check 1 'curl exited 7: no diagnostic' https example.test 443
check 0 'pass example.test answered 192.0.2.10' dns example.test 53 --expect example.test=192.0.2.10
check 1 'did not answer' dns example.test 53 --expect example.test=192.0.2.11
PROBE_DNS_ANSWER=$'192.0.2.1\n2001:DB8::1' check 0 'answered 2001:db8::1' dns example.test 5353 --expect example.test=2001:db8::1
grep -Fxq -- 'AAAA' "$PROBE_DIG_ARGS"
grep -Fxq -- '5353' "$PROBE_DIG_ARGS"
PROBE_DNS_ANSWER=$'alias.example.test.\n2001:db8::1' check 0 'answered 2001:0db8:0:0:0:0:0:1' dns example.test 53 --expect example.test=2001:0db8:0:0:0:0:0:1
PROBE_DNS_ANSWER='192.0.2.10.' check 1 'did not answer' dns example.test 53 --expect example.test=192.0.2.10
PROBE_DIG_FAIL=1 check 1 'no answer from example.test' dns example.test 53 --expect example.test=192.0.2.10
check 2 'DNS requires' dns example.test 53
check 2 'DNS requires' dns example.test 53 --expect '-bad=192.0.2.10'
rm -f -- "$PROBE_DIG_ARGS"
check 2 'valid IPv4 or IPv6' dns example.test 53 --expect example.test=face
check 2 'valid IPv4 or IPv6' dns example.test 53 --expect example.test=999.999.999.999
[[ ! -e "$PROBE_DIG_ARGS" ]] || { echo 'FAIL invalid DNS triggered a lookup' >&2; exit 1; }
check 2 'Invalid host' http '-bad' 80
check 2 'Port must be' http example.test 0
check 2 'Port must be' http example.test 65536
check 2 'Invalid port' http example.test -1
check 0 'pass status 200' http example.test 00001 --timeout 01
grep -Fxq -- 'http://example.test:1/' "$PROBE_ARGS"
check 0 'pass status 200' http example.test 65535 --timeout 30
check 2 'Timeout must be' http example.test 80 --timeout 0
check 2 'Timeout must be' http example.test 80 --timeout 31
check 2 'Invalid timeout' http example.test 80 --timeout bad
check 2 'Invalid expected text' http example.test 80 --expect ''
check 2 'Invalid expected text' http example.test 80 --expect $'ok\nInjected'
check 2 'Missing value' http example.test 80 --timeout
check 2 'Unknown option' http example.test 80 --bogus
check 2 'Unsupported protocol' ssh example.test 22
check 2 'Invalid HTTP path' http example.test 80 --path health
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
    lab_probe_exchange() { printf 'HTTP/1.0 200 OK\r\nX-Health: Welcome\r\n\r\nMaintenance'; }
    [[ $(lab_probe_http http example.test 80 Welcome 5 /) == 'fail status 200 but the expected text is missing' ]]
    lab_probe_exchange() { printf 'HTTP/1.0 200 OK\r\nX-Health: Welcome'; }
    [[ $(lab_probe_http http example.test 80 Welcome 5 /) == 'fail incomplete HTTP headers' ]]
    lab_probe_exchange() { printf 'HTTP/1.0 200 OK\r\n\r\n'; }
    [[ $(lab_probe_http http example.test 80 - 5 /) == 'pass status 200' ]]
    lab_probe_exchange() { printf 'garbage'; }
    [[ $(lab_probe_http http example.test 80 - 5 /) == 'fail not an HTTP response' ]]
    lab_probe_exchange() { return 1; }
    [[ $(lab_probe_http http example.test 80 - 5 /) == 'fail no HTTP response' ]]
    [[ $(lab_probe_http https example.test 443 - 5 /) == 'unknown no tool on this host can probe https' ]]
)
cat > "$fixture/banner-server.py" <<'EOF'
import socket
import sys

port_file, mode = sys.argv[1:]
with socket.socket() as server:
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    with open(port_file, "w", encoding="ascii") as output:
        output.write(str(server.getsockname()[1]))
    server.settimeout(10)
    with server.accept()[0] as client:
        client.settimeout(5)
        banner = {
            "short": b"220 ready\r\n",
            "near": b"2" * 65534 + b"\n",
            "limit": b"2" * 65535 + b"\n",
            "nul": b"\0" * 65535 + b"\n",
        }[mode]
        client.sendall(banner)
        if mode in ("short", "near") and client.recv(32) != b"QUIT\r\n":
            raise RuntimeError("incorrect closing command")
EOF
(
    source "$root/vendor/labyrinth/core/probe/probe.sh"
    for mode in short near limit nul; do
        port_file="$fixture/$mode.port"
        python3 "$fixture/banner-server.py" "$port_file" "$mode" &
        server_pid=$!
        for _ in {1..100}; do [[ -s "$port_file" ]] && break; sleep 0.05; done
        if [[ ! -s "$port_file" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" || true; echo 'FAIL banner server' >&2; exit 1; fi
        port=$(cat "$port_file")
        if banner=$(lab_probe_banner 127.0.0.1 "$port" 5); then code=0; else code=$?; fi
        wait "$server_pid"
        server_pid=
        if [[ $mode == short ]]; then
            [[ $code == 0 && $banner == $'220 ready\r' ]] || { echo 'FAIL short banner' >&2; exit 1; }
        elif [[ $mode == near ]]; then
            [[ $code == 0 && ${#banner} == 65534 ]] || { echo 'FAIL near-limit banner' >&2; exit 1; }
        else
            [[ $code != 0 ]] || { echo 'FAIL oversized banner' >&2; exit 1; }
        fi
    done
)
(
    source "$root/vendor/labyrinth/core/probe/probe.sh"
    command() {
        if [[ ${1:-} == -v && ${2:-} == dig ]]; then return 1; fi
        builtin command "$@"
    }
    timeout() { shift; "$@"; }
    nslookup() {
        printf '%s\n' "$@" > "$fixture/nslookup-args"
        printf 'Server: resolver\nAddress: 192.0.2.11\nName: example.test\nAddress: 192.0.2.10\n'
    }
    [[ $(lab_probe_dns resolver 5353 example.test=192.0.2.10 2) == 'pass example.test answered 192.0.2.10' ]]
    [[ $(lab_probe_dns resolver 5353 example.test=192.0.2.11 2) == 'fail example.test did not answer 192.0.2.11' ]]
    grep -Fxq -- '-port=5353' "$fixture/nslookup-args"
    command() {
        if [[ ${1:-} == -v && ( ${2:-} == dig || ${2:-} == nslookup ) ]]; then return 1; fi
        builtin command "$@"
    }
    [[ $(lab_probe_dns resolver 53 example.test=192.0.2.10 2) == 'unknown no dig or nslookup on this host' ]]
    command() {
        if [[ ${1:-} == -v && ${2:-} == python3 ]]; then return 1; fi
        builtin command "$@"
    }
    [[ $(lab_probe_dns resolver 53 example.test=192.0.2.10 2) == 'unknown Python 3 is required for DNS address validation' ]]
)
(
    source "$root/vendor/labyrinth/core/probe/probe.sh"
    lab_probe_banner() {
        printf '%s' "${4:-QUIT}" > "$fixture/quit"
        printf '%s' "$BANNER"
    }
    for protocol in smtp ftp; do
        BANNER=$'220 ready\r' ; export BANNER
        [[ $(lab_probe_service "$protocol" example.test 25 ready 1) == 'pass banner received' ]]
        [[ $(cat "$fixture/quit") == QUIT ]]
        BANNER='500 rejected'
        [[ $(lab_probe_service "$protocol" example.test 25 - 1) == 'fail unexpected banner' ]]
    done
    BANNER='+OK ready'
    [[ $(lab_probe_service pop3 example.test 110 ready 1) == 'pass banner received' ]]
    BANNER='* OK ready'
    [[ $(lab_probe_service imap example.test 143 ready 1) == 'pass banner received' ]]
    [[ $(cat "$fixture/quit") == 'a1 LOGOUT' ]]
    [[ $(lab_probe_service imap example.test 143 missing 1) == 'fail the banner lacks the expected text' ]]
    BANNER=''; [[ $(lab_probe_service tcp example.test 1234 ready 1) == 'fail no banner' ]]
    BANNER='custom ready'; [[ $(lab_probe_service tcp example.test 1234 ready 1) == 'pass banner received' ]]
    lab_probe_connect() { return 0; }
    [[ $(lab_probe_service tcp example.test 1234 - 1) == 'pass connected' ]]
    lab_probe_connect() { return 1; }
    [[ $(lab_probe_service tcp example.test 1234 - 1) == 'fail no connection' ]]
    [[ $(lab_probe_service bogus example.test 1234 - 1) == 'unknown unsupported protocol bogus' ]]
    command() {
        if [[ ${1:-} == -v && ${2:-} == timeout ]]; then return 1; fi
        builtin command "$@"
    }
    [[ $(lab_probe_service tcp example.test 1234 - 1) == 'unknown no timeout command on this host' ]]
)
if [[ -n "$real_curl" ]] && command -v openssl >/dev/null 2>&1; then
    mkdir -p "$fixture/realbin" "$fixture/curl-home"
    ln -s "$real_curl" "$fixture/realbin/curl"
    printf 'insecure\nlocation\n' > "$fixture/curl-home/.curlrc"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
        -keyout "$fixture/key.pem" -out "$fixture/cert.pem" > /dev/null 2>&1
    cat > "$fixture/curl-server.py" <<'EOF'
import http.server
import ssl
import sys

port_file, mode, cert, key = sys.argv[1:]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/welcome")
            body = b"Moved"
        else:
            self.send_response(200)
            body = b"Welcome"
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
    if mode == "https":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.timeout = 3
    with open(port_file, "w", encoding="ascii") as output:
        output.write(str(server.server_port))
    server.handle_request()
    if mode == "http":
        server.handle_request()
EOF
    for mode in https http; do
        port_file="$fixture/curl-$mode.port"
        python3 "$fixture/curl-server.py" "$port_file" "$mode" "$fixture/cert.pem" "$fixture/key.pem" &
        server_pid=$!
        for _ in {1..100}; do [[ -s "$port_file" ]] && break; sleep 0.05; done
        if [[ ! -s "$port_file" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" || true; echo 'FAIL curl server' >&2; exit 1; fi
        port=$(cat "$port_file")
        if [[ $mode == https ]]; then
            PATH="$fixture/realbin:$PATH" CURL_HOME="$fixture/curl-home" \
                check 1 'curl exited 60:' https 127.0.0.1 "$port" --expect Welcome
        else
            PATH="$fixture/realbin:$PATH" CURL_HOME="$fixture/curl-home" \
                check 1 'expected text is missing' http 127.0.0.1 "$port" --path /redirect --expect Welcome
        fi
        wait "$server_pid"
        server_pid=
    done
    echo 'PASS real curl ignores unsafe configuration'
else
    echo 'SKIP real curl configuration test: curl or openssl unavailable'
fi
printf 'PASS service probe checks\n'
