#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
APPLY=false
CONFIG="$(dirname "$0")/firewall.example.json"
while (($#)); do case "$1" in --apply) APPLY=true ;; --config) (($# > 1)) || exit 2; CONFIG="$2"; shift ;; --help|-h) printf '%s\n' 'Audit by default. Apply with --apply --config FILE only after replacing every placeholder. inbound_services are opened to every source and ping stays on; admin_services are opened only to admin_sources.'; exit 0 ;; *) echo "Unknown option: $1" >&2; exit 2 ;; esac; shift; done
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 2; }
command -v nft >/dev/null && command -v python3 >/dev/null && command -v ss >/dev/null || { echo 'nft, python3 and ss are required.' >&2; exit 2; }
[[ -r "$CONFIG" ]] || { echo "Cannot read config: $CONFIG" >&2; exit 2; }
python3 - "$CONFIG" <<'PY'
import ipaddress, json, sys
with open(sys.argv[1], encoding="utf-8") as f: cfg = json.load(f)
if cfg.get("scoring_sources"): print("Note: scoring_sources is no longer used. inbound_services are opened to every source.")
for section in ("admin_sources",):
    if not cfg.get(section): raise SystemExit(f"{section} must not be empty")
    for value in cfg[section]:
        if "REPLACE_" in value: raise SystemExit(f"Unfilled placeholder in {section}: {value}")
        ipaddress.ip_network(value, strict=False)
if not cfg.get("inbound_services"): raise SystemExit("inbound_services must not be empty")
if not cfg.get("admin_services"): raise SystemExit("admin_services must not be empty")
for item in cfg["inbound_services"] + cfg["admin_services"] + cfg.get("outbound_allow", []):
    if item.get("protocol") not in ("tcp", "udp"): raise SystemExit("Only tcp/udp entries are accepted")
    if not 1 <= int(item.get("port", 0)) <= 65535: raise SystemExit("Invalid port")
    for key in ("destination",):
        if key in item:
            if "REPLACE_" in item[key]: raise SystemExit(f"Unfilled placeholder: {key}")
            ipaddress.ip_network(item[key], strict=False)
for item in cfg.get("verification_targets", []):
    if "REPLACE_" in item.get("host", ""): raise SystemExit("Unfilled verification target")
    if not 1 <= int(item.get("port", 0)) <= 65535: raise SystemExit("Invalid verification port")
if int(cfg.get("rollback_seconds", 0)) < 60: raise SystemExit("rollback_seconds must be at least 60")
PY
RULES=/run/ccdc-first-hour.nft
generate_rules() {
python3 - "$CONFIG" "$RULES" <<'PY'
import ipaddress, json, re, subprocess, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
out = ["table inet ccdc_first_hour {", " chain input { type filter hook input priority -10; policy drop;", "  iifname lo accept", "  ct state established,related accept", "  icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept", "  meta l4proto ipv6-icmp icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept"]
# Public (scored) services answer every source: limiting them to the scoring addresses is not allowed.
for rule in cfg["inbound_services"]:
    out.append(f"  {rule['protocol']} dport {int(rule['port'])} accept")
for source in cfg["admin_sources"]:
    net = ipaddress.ip_network(source, strict=False)
    fam = "ip" if net.version == 4 else "ip6"
    for rule in cfg["admin_services"]:
        out.append(f"  {fam} saddr {net} {rule['protocol']} dport {int(rule['port'])} accept")
out += [" }", " chain output { type filter hook output priority -10; policy drop;", "  oifname lo accept", "  ct state established,related accept"]
# Connections established before conntrack hooks exist can initially be classified as new.
public_ports = {int(rule["port"]) for rule in cfg["inbound_services"] if rule["protocol"] == "tcp"}
admin_ports = {int(rule["port"]) for rule in cfg["admin_services"] if rule["protocol"] == "tcp"}
admin_sources = [ipaddress.ip_network(source, strict=False) for source in cfg["admin_sources"]]

def endpoint(value):
    address, port = value.rsplit(":", 1)
    address, _, scope = address.partition("%")
    address = ipaddress.ip_address(address.strip("[]"))
    scope = scope.rstrip("]")
    return getattr(address, "ipv4_mapped", None) or address, int(port), scope

sockets = subprocess.run(["ss", "-Hnt", "state", "established"], check=True, stdout=subprocess.PIPE, text=True)
for line in sockets.stdout.splitlines():
    fields = line.split()
    if len(fields) != 4:
        raise SystemExit(f"Unexpected ss output: {line}")
    local, local_port, local_scope = endpoint(fields[2])
    peer, peer_port, peer_scope = endpoint(fields[3])
    if local.version != peer.version:
        raise SystemExit(f"Mixed address families in ss output: {line}")
    authorized = local_port in public_ports or (
        local_port in admin_ports and any(peer in net for net in admin_sources if net.version == peer.version)
    )
    if authorized:
        if local_scope and peer_scope and local_scope != peer_scope:
            raise SystemExit(f"Conflicting interface scopes in ss output: {line}")
        scope = peer_scope or local_scope
        if peer.version == 6 and peer.is_link_local and not scope:
            raise SystemExit(f"Missing link-local interface scope in ss output: {line}")
        if scope and not re.fullmatch(r"[A-Za-z0-9_.-]+", scope):
            raise SystemExit(f"Invalid interface scope in ss output: {line}")
        interface = ""
        if scope:
            interface = f" oif {scope}" if scope.isdecimal() else f' oifname "{scope}"'
        fam = "ip" if local.version == 4 else "ip6"
        out.append(f"  {fam} saddr {local} {fam} daddr {peer}{interface} tcp sport {local_port} tcp dport {peer_port} ct state new tcp flags & (syn | ack) == ack accept")
for item in cfg.get("outbound_allow", []):
    net = ipaddress.ip_network(item["destination"], strict=False)
    fam = "ip" if net.version == 4 else "ip6"
    out.append(f"  {fam} daddr {net} {item['protocol']} dport {int(item['port'])} accept")
out += ["  meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept", "  reject", " }", " chain forward { type filter hook forward priority -10; policy drop; }", "}"]
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
}
generate_rules
nft -c -f "$RULES"
echo 'Observed listening TCP/UDP sockets:'
ss -lntup || true
echo "Config=$CONFIG; generated rules=$RULES"
if [[ "$APPLY" != true ]]; then echo 'Audit only: no firewall rules changed.'; exit 0; fi
command -v systemd-run >/dev/null && systemctl is-system-running >/dev/null 2>&1 || { echo 'A running systemd manager is required for automatic rollback; refusing apply.' >&2; exit 2; }
if nft list table inet ccdc_first_hour >/dev/null 2>&1; then echo 'The CCDC firewall table already exists; inspect/remove it explicitly before retrying.' >&2; exit 2; fi
rollback_unit="ccdc-firewall-rollback-$(date +%s)"
rollback_seconds="$(python3 -c 'import json,sys;print(int(json.load(open(sys.argv[1]))["rollback_seconds"]))' "$CONFIG")"
NFT_PATH="$(command -v nft)"
printf 'Validated admin sources and ports loaded from %s\nType APPLY FIREWALL AND KEEP ROLLBACK to continue: ' "$CONFIG"
IFS= read -r answer
if [[ "$answer" != 'APPLY FIREWALL AND KEEP ROLLBACK' ]]; then echo 'Cancelled; rules unchanged.'; exit 0; fi
generate_rules
nft -c -f "$RULES"
systemd-run --quiet --unit="$rollback_unit" --on-active="${rollback_seconds}s" "$NFT_PATH" delete table inet ccdc_first_hour || { echo 'Could not arm rollback timer; refusing to apply.' >&2; exit 2; }
nft -f "$RULES"
echo "Applied. Automatic rollback is armed for ${rollback_seconds}s (${rollback_unit}.timer). Verify ping, scored services and management access now."
echo "To keep rules after successful verification: systemctl stop ${rollback_unit}.timer ${rollback_unit}.service"
echo 'To roll back immediately: nft delete table inet ccdc_first_hour'
