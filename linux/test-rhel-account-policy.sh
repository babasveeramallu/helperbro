#!/usr/bin/env bash
set -Eeuo pipefail

script="${1:-$(dirname "$0")/first-hour.sh}"
tmp="$(mktemp -d)"
trap 'rm -f -- "$tmp/os-release" "$tmp/report" "$tmp/output" "$tmp/commands" "$tmp/unexpected"; rmdir -- "$tmp"' EXIT

source <(sed 's/\r$//' "$script" |
    sed -n '/^rhel_account_policy_guidance() {$/,/^}$/p')
source <(sed 's/\r$//' "$script" |
    sed -n '/^configure_account_policy() {$/,/^}$/p' |
    sed 's@/etc/os-release@"$tmp/os-release"@g')

log() { printf '%s %s\n' "$1" "$2" | tee -a "$tmp/report"; }
unexpected() { printf '%s\n' 'Unexpected system-changing command' > "$tmp/unexpected"; return 99; }
sudo() { unexpected; }
authselect() { unexpected; }
dnf() { unexpected; }
python3() { unexpected; }

for distro in rocky almalinux rhel fedora centos ol; do
    for apply in false true; do
        printf 'ID=%s\nVERSION_ID=9\n' "$distro" > "$tmp/os-release"
        : > "$tmp/report"
        code=0
        configure_account_policy > "$tmp/output" || code=$?
        [[ "$code" == 2 ]] || { echo "Expected manual-action failure for $distro apply=$apply" >&2; exit 1; }
        grep -Fq 'MANUAL ACTION REQUIRED' "$tmp/report"
        grep -Fq 'sudo authselect check' "$tmp/report"
        grep -Fq 'sudoedit /etc/security/pwquality.conf' "$tmp/report"
        grep -Fq 'sudoedit /etc/security/faillock.conf' "$tmp/report"
        grep -Fq 'sudo authselect enable-feature with-faillock --backup=' "$tmp/report"
        grep -Fq 'sudo authselect enable-feature with-pwhistory --backup=' "$tmp/report"
        grep -Fq 'OPTIONAL LOCKOUT ONLY' "$tmp/report"
        grep -Fq 'no PAM policy was applied' "$tmp/report"
        grep -Fq 'sudo cp -a "$backup/login.defs" /etc/login.defs' "$tmp/report"
        ! grep -Eq '^INFO sudo authselect select|^CHANGE ' "$tmp/report"
        [[ ! -e "$tmp/unexpected" ]]
        printf 'PASS %s apply=%s guidance only\n' "$distro" "$apply"
    done
done

printf 'ID=unsupported\n' > "$tmp/os-release"
: > "$tmp/report"
code=0
configure_account_policy > "$tmp/output" || code=$?
[[ "$code" == 2 ]]
grep -Fq 'detected unsupported' "$tmp/report"
! grep -Fq 'MANUAL ACTION REQUIRED' "$tmp/report"
[[ ! -e "$tmp/unexpected" ]]
echo 'PASS unsupported distribution still refused'

for distro in debian ubuntu; do
    printf 'ID=%s\n' "$distro" > "$tmp/os-release"
    : > "$tmp/report"
    code=0
    configure_account_policy > "$tmp/output" || code=$?
    [[ "$code" == 2 ]]
    grep -Fq 'authselect-managed PAM detected' "$tmp/report"
    ! grep -Fq 'MANUAL ACTION REQUIRED' "$tmp/report"
    [[ ! -e "$tmp/unexpected" ]]
    printf 'PASS %s authselect-managed guard preserved\n' "$distro"
done

# The printed commands are syntax-checked, never executed.
: > "$tmp/report"
rhel_account_policy_guidance > "$tmp/output"
sed -n 's/^INFO //p' "$tmp/report" > "$tmp/commands"
bash -n "$tmp/commands"
echo 'PASS printed Bash procedure syntax'
