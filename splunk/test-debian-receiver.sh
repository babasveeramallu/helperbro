#!/usr/bin/env bash
# Offline rendering/argument tests. Never starts Splunk or modifies system config.
set -Eeuo pipefail
dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-receiver-test-XXXXXXXX")
cleanup() {
    rm -f -- "$fixture/render/inputs.conf" "$fixture/render/indexes.conf" "$fixture/render/props.conf" "$fixture/invalid-output"
    if [[ -d $fixture/render ]]; then rmdir -- "$fixture/render"; fi
    rmdir -- "$fixture"
}
trap cleanup EXIT
bash -n "$dir/setup-debian-receiver.sh"
bash "$dir/setup-debian-receiver.sh" --render-only "$fixture/render"
grep -Fxq '[splunktcp://9997]' "$fixture/render/inputs.conf"
grep -Fxq 'disabled = 0' "$fixture/render/inputs.conf"
for index in wineventlog sysmon mssql; do
    grep -Fxq "[$index]" "$fixture/render/indexes.conf"
    grep -Fq "\$SPLUNK_DB/$index/db" "$fixture/render/indexes.conf"
done
grep -Fxq '[ccdc:mssql:errorlog]' "$fixture/render/props.conf"
cmp "$dir/mssql-props.conf" "$fixture/render/props.conf"
for invalid in 0 65536 -1 not-a-port; do
    if bash "$dir/setup-debian-receiver.sh" --port "$invalid" --render-only "$fixture/invalid-output"; then
        printf 'FAIL: invalid port accepted: %s\n' "$invalid" >&2; exit 1
    fi
done
if bash "$dir/setup-debian-receiver.sh" --audit-only --render-only "$fixture/invalid-output"; then
    printf 'FAIL: audit allowed render writes\n' >&2; exit 1
fi
[[ ! -e $fixture/invalid-output ]]
printf 'PASS: receiver syntax, rendering, indexes/props and invalid argument checks. No live Splunk test.\n'
