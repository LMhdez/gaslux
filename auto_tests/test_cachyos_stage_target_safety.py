"""Non-destructive fail-closed checks for experimental CachyOS pacstrap gate."""

import os
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "assets/live/cachyos-stage-target.sh"
RUN_ID = "gaslux-lab-test-123"
ROOT_UUID = "01234567-89ab-cdef-0123-456789abcdef"


def invoke(*args, marker=None):
    env = os.environ.copy()
    env.pop("GASLUX_DISPOSABLE_VM", None)
    if marker is not None:
        env["GASLUX_DISPOSABLE_VM"] = marker
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
        env=env,
    )


class StageTargetSafetyTests(unittest.TestCase):
    def test_shell_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_validate_target_requires_vm_consent(self):
        result = invoke("--validate-target", RUN_ID, ROOT_UUID)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disposable VM", result.stderr)

    def test_validate_target_rejects_incorrect_consent(self):
        result = invoke("--validate-target", RUN_ID, ROOT_UUID, marker="true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disposable VM", result.stderr)

    def test_install_requires_vm_consent_before_host_or_disk(self):
        result = invoke(
            "--install",
            "testuser",
            "testhost",
            "en_US.UTF-8",
            "Europe/Lisbon",
            "/nonexistent",
            RUN_ID,
            ROOT_UUID,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disposable VM", result.stderr)

    def test_invalid_validate_arguments_do_not_write(self):
        for args in (
            ("--validate-target",),
            ("--validate-target", RUN_ID),
            ("--validate-target", RUN_ID, ROOT_UUID, "extra"),
        ):
            with self.subTest(args=args):
                result = invoke(*args)
                self.assertEqual(result.returncode, 2)

    def test_no_unknown_mode_is_accepted(self):
        result = invoke("--erase-disk", RUN_ID, ROOT_UUID)
        self.assertEqual(result.returncode, 2)

    def test_help_describes_explicit_vm_target_validation(self):
        result = invoke("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--validate-target", result.stdout)

    def test_official_cachyos_archiso_identity_is_fail_closed(self):
        source = SCRIPT.read_text()
        host = source.split("check_host() {", 1)[1].split("\n}\n", 1)[0]
        # Pinned official CachyOS 260809: ID=cachyos and ID_LIKE=arch.
        self.assertIn('[ "$host_id" = cachyos ]', host)
        self.assertIn('[ "$host_like" = arch ]', host)
        self.assertIn('[ "$host_name" = CachyOS ]', host)
        self.assertNotIn('[ "$host_id" = arch ]', host)
        self.assertIn("not official CachyOS Archiso", host)

    def test_static_guard_remains_before_pacstrap(self):
        source = SCRIPT.read_text()
        install = source.split("install_target() {", 1)[1].split("\ncase ", 1)[0]
        self.assertLess(
            install.index("check_disposable_vm"),
            install.index("check_target "),
        )
        self.assertLess(
            install.index("check_target "),
            install.index("pacstrap -K"),
        )
        self.assertIn('check_target_isolated_disk "$source"', source)
        self.assertIn("^/dev/vd[b-z][1-9][0-9]*$", source)
        self.assertIn("target has foreign or multiple mountpoints", source)


if __name__ == "__main__":
    unittest.main()
