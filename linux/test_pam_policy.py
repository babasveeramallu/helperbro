"""Offline regression tests; never modify the host's PAM configuration."""
import tempfile
import unittest
from pathlib import Path

from pam_policy import FILES, apply, rewrite_auth


BASE = """# Debian simple stack
auth [success=1 default=ignore] pam_unix.so nullok
auth requisite pam_deny.so
auth required pam_permit.so
auth optional pam_cap.so
"""


class PamPolicyTests(unittest.TestCase):
    def fixture(self, root, auth):
        contents = (auth, "account required pam_unix.so\n",
                    "password required pam_unix.so obscure yescrypt\n",
                    "PASS_MAX_DAYS 99999\n")
        for relative, content in zip(FILES, contents):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return contents

    def test_apply_and_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            originals = self.fixture(root, BASE)
            apply(root, root / "backup")
            first = [(root / path).read_bytes() for path in FILES]
            self.assertEqual(first[0].decode(), rewrite_auth(BASE))
            for path, content in zip(FILES, originals):
                self.assertEqual((root / "backup" / path.name).read_text(), content)
            apply(root, root / "backup2")
            self.assertEqual(first, [(root / path).read_bytes() for path in FILES])

    def test_unsupported_stacks_leave_all_files_unchanged(self):
        bad_rules = (
            "auth required pam_exec.so /check/pam_unix.so",
            "auth required pam_other.so # pam_permit.so",
            "auth required pam_unix.so",
            "auth required pam_cap.so",
            "-auth required pam_other.so",
            "@include other-auth",
            "auth include other-auth",
            "auth substack other-auth",
            "auth required /lib/security/pam_other.so pam_deny.so",
            "auth required pam_unix.so.evil",
            "auth required pam_faillock.so authsucc",
            "auth optional pam_permit.so",
            "auth [success=done default=ignore] pam_cap.so",
        )
        stacks = [BASE + rule + "\n" for rule in bad_rules]
        stacks += [rule + "\n" + BASE for rule in bad_rules]
        stacks += [BASE.replace("success=1", "success=2"),
                   BASE.replace("requisite", "optional"),
                   BASE.replace("auth required pam_permit.so\n", ""),
                   BASE.replace("auth requisite pam_deny.so\n", ""),
                   BASE.replace("pam_unix.so nullok", "pam_unix.so.evil nullok"),
                   BASE.replace("pam_unix.so nullok", "pam_unix.so nullok\\\n auth required pam_other.so")]
        for auth in stacks:
            with self.subTest(auth=auth), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, auth)
                original = [(root / path).read_bytes() for path in FILES]
                with self.assertRaises(RuntimeError):
                    apply(root, root / "backup")
                self.assertEqual(original, [(root / path).read_bytes() for path in FILES])
                self.assertFalse((root / "backup").exists())

    def test_legacy_output_and_whitespace(self):
        fixed = rewrite_auth(BASE)
        legacy = fixed.replace("auth [success=1 default=ignore] pam_faillock.so authsucc",
                               "auth sufficient pam_faillock.so authsucc")
        self.assertEqual(rewrite_auth(legacy), fixed)
        self.assertEqual(rewrite_auth(fixed), fixed)
        self.assertIn("pam_unix.so\tnullok", rewrite_auth(BASE.replace(" ", "\t")))
        self.assertIn("pam_permit.so", rewrite_auth(BASE.replace("auth optional pam_cap.so\n", "")))

    def test_success_path_runs_tail_and_failure_reaches_deny(self):
        # Model the documented PAM controls for each possible authentication result.
        lines = [line.split() for line in rewrite_auth(BASE).splitlines()
                 if line.startswith("auth")]
        for locked in (False, True):
            for password_ok in (False, True):
                for success_ok in (False, True):
                    with self.subTest(locked=locked, password_ok=password_ok, success_ok=success_ok):
                        failed, index, visited = False, 0, []
                        while index < len(lines):
                            line = " ".join(lines[index])
                            visited.append(line)
                            if " preauth " in line:
                                failed |= locked
                            elif "pam_unix.so" in line:
                                if password_ok:
                                    index += 1  # skip authfail
                            elif " authfail " in line or "pam_deny.so" in line:
                                failed = True
                                break
                            elif " authsucc " in line:
                                if success_ok:
                                    index += 1  # skip deny, retaining permit/cap
                            index += 1
                        self.assertEqual(not failed, not locked and password_ok and success_ok)
                        if not failed:
                            self.assertTrue(any("pam_cap.so" in line for line in visited))
                            self.assertTrue(any("pam_permit.so" in line for line in visited))


if __name__ == "__main__":
    unittest.main()
