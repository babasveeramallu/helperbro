#!/usr/bin/env python3
"""Apply the CCDC Debian-style PAM/account policy to a supplied root tree."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import tempfile
from pathlib import Path

FILES = (
    Path("etc/pam.d/common-auth"),
    Path("etc/pam.d/common-account"),
    Path("etc/pam.d/common-password"),
    Path("etc/login.defs"),
)


def atomic_write(path: Path, content: str) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        shutil.copystat(path, tmp_name, follow_symlinks=False)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def set_login_value(text: str, key: str, value: int) -> str:
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.M)
    replacement = f"{key}\t{value}"
    if pattern.search(text):
        return pattern.sub(replacement, text, count=1)
    return text.rstrip() + f"\n{replacement}\n"


def rewrite_auth(text: str) -> str:
    """Only rewrite the simple Debian stack or our exact previous output.

    Module arguments must never be used to identify a provider. Validate the
    entire sequence, including controls, before removing or inserting rules.
    Includes, continuations and other layouts require manual configuration.
    """
    rules = []
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if not line.strip(" \t") or line.lstrip(" \t").startswith("#"):
            continue
        match = re.fullmatch(
            r"[ \t]*auth[ \t]+(\[[^\]\r\n]+\]|[a-z]+)[ \t]+"
            r"([^ \t\r\n]+)(?:[ \t]+([^\r\n]*))?[ \t]*", line
        )
        if not match or "\\" in line:
            raise RuntimeError("common-auth has unsupported syntax; no files edited")
        control, module, arguments = match.groups()
        rules.append((index, " ".join(control.split()), module,
                      tuple((arguments or "").split())))

    unix = ("[success=1 default=ignore]", "pam_unix.so")
    deny = ("requisite", "pam_deny.so", ())
    permit = ("required", "pam_permit.so", ())
    preauth = ("required", "pam_faillock.so", ("preauth", "silent", "deny=5", "unlock_time=1800"))
    authfail = ("[default=die]", "pam_faillock.so", ("authfail", "deny=5", "unlock_time=1800"))
    # Jump only over pam_deny, then run pam_permit and the optional pam_cap.
    authsucc = ("[success=1 default=ignore]", "pam_faillock.so", ("authsucc", "deny=5", "unlock_time=1800"))
    legacy_authsucc = ("sufficient", *authsucc[1:])
    sequence = [(control, module, args) for _, control, module, args in rules]
    if sequence and sequence[-1][:2] == ("optional", "pam_cap.so"):
        sequence = sequence[:-1]
    # pam_unix options are retained verbatim, but its identity/control is exact.
    normalized = [unix if rule[:2] == unix else rule for rule in sequence]
    if normalized not in (
        [unix, deny, permit],
        [preauth, unix, authfail, authsucc, deny, permit],
        [preauth, unix, authfail, legacy_authsucc, deny, permit],
    ):
        raise RuntimeError("common-auth is not a recognized Debian simple pam_unix stack; no files edited")

    def render(rule: tuple) -> str:
        return "auth " + " ".join((rule[0], rule[1], *rule[2]))

    for index, control, module, _ in rules:
        if module == "pam_faillock.so":
            lines[index] = None
        elif module == "pam_unix.so":
            lines[index] = "\n".join((render(preauth), lines[index], render(authfail), render(authsucc)))
    return "\n".join(line for line in lines if line is not None)


def apply(root: Path, backup_dir: Path) -> None:
    paths = [root / relative for relative in FILES]
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Unsupported/missing PAM file (symlinks are refused): {path}")
    common_auth, common_account, common_password, login_defs = [p.read_text(encoding="utf-8") for p in paths]
    common_auth = rewrite_auth(common_auth)
    if not re.search(r"^\s*account\s+.*pam_unix\.so", common_account, re.M):
        raise RuntimeError("common-account has no pam_unix entry; unsupported PAM stack")
    password_unix = re.compile(r"^\s*password\s+([^\n]*pam_unix\.so[^\n]*)$", re.M)
    if len(list(password_unix.finditer(common_password))) != 1:
        raise RuntimeError("common-password must have exactly one pam_unix entry")

    common_account = re.sub(r"(?m)^\s*account\s+.*pam_faillock\.so.*\n", "", common_account)
    unix_account = re.search(r"^\s*account\s+.*pam_unix\.so.*$", common_account, re.M)
    common_account = common_account[:unix_account.start()] + "account required pam_faillock.so deny=5 unlock_time=1800\n" + common_account[unix_account.start():]

    common_password = re.sub(r"(?m)^\s*password\s+.*pam_pwquality\.so.*\n", "", common_password)
    password_match = password_unix.search(common_password)
    unix_password = password_match.group(1)
    if not re.search(r"\buse_authtok\b", unix_password):
        unix_password += " use_authtok"
    if not re.search(r"\bremember=\d+", unix_password):
        unix_password += " remember=5"
    else:
        unix_password = re.sub(r"\bremember=\d+", "remember=5", unix_password)
    common_password = common_password[:password_match.start()] + "password requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\npassword " + unix_password + common_password[password_match.end():]

    updated = [common_auth, common_account, common_password]
    updated.append(set_login_value(set_login_value(set_login_value(login_defs, "PASS_MAX_DAYS", 60), "PASS_MIN_DAYS", 7), "PASS_WARN_AGE", 7))
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in paths:
        shutil.copy2(path, backup_dir / path.name)
    try:
        for path, text in zip(paths, updated):
            atomic_write(path, text)
        for path in paths[:3]:
            if "pam_faillock.so" not in path.read_text(encoding="utf-8") and path.name != "common-password":
                raise RuntimeError(f"faillock setting verification failed: {path}")
        if "pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" not in paths[2].read_text(encoding="utf-8"):
            raise RuntimeError("pwquality verification failed")
        verify_defs = paths[3].read_text(encoding="utf-8")
        for key, expected in (("PASS_MAX_DAYS", 60), ("PASS_MIN_DAYS", 7), ("PASS_WARN_AGE", 7)):
            if not re.search(rf"(?m)^\s*{key}\s+{expected}\s*$", verify_defs):
                raise RuntimeError(f"login.defs verification failed: {key}")
    except Exception:
        for original in paths:
            shutil.copy2(backup_dir / original.name, original)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/"), help="Root directory (useful for isolated fixture tests)")
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()
    apply(args.root.resolve(), args.backup_dir.resolve())
    print(f"PAM/account policy applied and verified; backups={args.backup_dir}")


if __name__ == "__main__":
    main()
