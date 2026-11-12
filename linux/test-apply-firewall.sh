#!/usr/bin/env bash
set -Eeuo pipefail

script="${1:-$(dirname "$0")/apply-firewall.sh}"
tmp="$(mktemp -d)"
trap 'rm -f -- "$tmp/ss" "$tmp/sockets" "$tmp/config.json" "$tmp/rules"; rmdir -- "$tmp"' EXIT
export PATH="$tmp:$PATH" SS_OUTPUT="$tmp/sockets"
CONFIG="$tmp/config.json"
RULES="$tmp/rules"

cat >"$tmp/ss" <<'SH'
#!/usr/bin/env bash
[[ "$*" == '-Hnt state established' ]]
if [[ "${SS_FAIL:-false}" == true ]]; then
    echo 'simulated ss failure' >&2
    exit 1
fi
cat "$SS_OUTPUT"
SH
chmod +x "$tmp/ss"
cat >"$CONFIG" <<'JSON'
{
  "admin_sources": ["192.0.2.0/24", "2001:db8:1::/48", "fe80::/10"],
  "admin_services": [{"protocol": "tcp", "port": 22}],
  "inbound_services": [{"protocol": "tcp", "port": 80}, {"protocol": "udp", "port": 53}],
  "outbound_allow": []
}
JSON
cat >"$SS_OUTPUT" <<'SOCKETS'
0 0 10.0.0.2:22 192.0.2.7:54321
0 0 10.0.0.2:22 192.0.3.8:54322
0 0 10.0.0.2:80 203.0.113.8:55000
0 0 [::ffff:10.0.0.2]:80 [::ffff:203.0.113.9]:50002
0 0 [2001:db8:100::10]:22 [2001:db8:1::2]:50003
0 0 [fe80::10]%enp0s8:22 [fe80::20]:50005
0 0 [fe80::10]%2:22 [fe80::21]:50006
0 0 10.0.0.2:53 203.0.113.10:50004
SOCKETS

source <(sed 's/\r$//' "$script" | sed -n '/^generate_rules() {$/,/^}$/p')
generate_rules
grep -Fxq '  ip saddr 10.0.0.2 ip daddr 192.0.2.7 tcp sport 22 tcp dport 54321 ct state new tcp flags & (syn | ack) == ack accept' "$RULES"
grep -Fxq '  ip saddr 10.0.0.2 ip daddr 203.0.113.8 tcp sport 80 tcp dport 55000 ct state new tcp flags & (syn | ack) == ack accept' "$RULES"
grep -Fxq '  ip saddr 10.0.0.2 ip daddr 203.0.113.9 tcp sport 80 tcp dport 50002 ct state new tcp flags & (syn | ack) == ack accept' "$RULES"
grep -Fxq '  ip6 saddr 2001:db8:100::10 ip6 daddr 2001:db8:1::2 tcp sport 22 tcp dport 50003 ct state new tcp flags & (syn | ack) == ack accept' "$RULES"
grep -Fxq '  ip6 saddr fe80::10 ip6 daddr fe80::20 oifname "enp0s8" tcp sport 22 tcp dport 50005 ct state new tcp flags & (syn | ack) == ack accept' "$RULES"
grep -Fxq '  ip6 saddr fe80::10 ip6 daddr fe80::21 oif 2 tcp sport 22 tcp dport 50006 ct state new tcp flags & (syn | ack) == ack accept' "$RULES"
! grep -qE '192\.0\.3\.8|tcp sport 53' "$RULES"

: >"$SS_OUTPUT"
generate_rules
! grep -q 'ct state new tcp flags' "$RULES"
printf '%s\n' 'malformed socket data' >"$SS_OUTPUT"
if generate_rules 2>/dev/null; then
    echo 'Malformed ss output was accepted.' >&2
    exit 1
fi
printf '%s\n' '0 0 [fe80::10]:22 [fe80::20]:50005' >"$SS_OUTPUT"
if generate_rules 2>/dev/null; then
    echo 'Unscoped link-local connection was accepted.' >&2
    exit 1
fi
: >"$SS_OUTPUT"
export SS_FAIL=true
if generate_rules 2>/dev/null; then
    echo 'ss failure was ignored.' >&2
    exit 1
fi
echo 'Standalone firewall regression tests passed.'
