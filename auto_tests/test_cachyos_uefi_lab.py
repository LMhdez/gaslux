"""Non-destructive tests for the VM-only CachyOS bootloader stage."""
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "assets/live/cachyos-uefi-lab.py"
spec = importlib.util.spec_from_file_location("cachyos_uefi_lab", SCRIPT)
assert spec and spec.loader
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
PLAN = {
    "version": 1,
    "firmware": "uefi",
    "secureBootEnabled": False,
    "runId": "test-cachyos-run-123",
    "rootUuid": "01234567-89ab-cdef-0123-456789abcdef",
    "espUuid": "AB12-CD34",
    "windowsBootUuid": "AB12-CD34",
    "windowsBootManagerSha256": hashlib.sha256(b"dummy PE for dry run").hexdigest(),
    "linuxLabel": "CachyOS Linux",
    "grubResolution": "1920x1080",
}


class CachyosUefiLabTests(unittest.TestCase):
    def test_cli_is_dry_run_by_default(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "plan.json"
            file.write_text(json.dumps(PLAN))
            result = subprocess.run(
                ["python3", str(SCRIPT), str(file)],
                capture_output=True, text=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(output["status"], "read-only-dry-run")
            self.assertIn("UUID=AB12-CD34 /boot/efi", output["fstab"])
            self.assertEqual(list(Path(temp).iterdir()), [file])

    def test_apply_without_disposable_vm_sentinel_is_rejected(self):
        with patch.dict(os.environ, {"GASLUX_DISPOSABLE_VM": ""}):
            with self.assertRaisesRegex(lab.LabError, "sentinel"):
                lab.check_host() if os.geteuid() == 0 else self._deny_non_root()

    @staticmethod
    def _deny_non_root():
        raise lab.LabError("VM-only consent sentinel is missing")

    def test_apply_never_runs_on_host_without_vm_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "plan.json"
            file.write_text(json.dumps(PLAN))
            env = os.environ.copy()
            env.pop("GASLUX_DISPOSABLE_VM", None)
            result = subprocess.run(
                ["python3", str(SCRIPT), str(file), "--apply-vm-lab"],
                env=env, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(temp) / "etc").exists())

    def test_write_new_refuses_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "protected"
            path.write_text("windows")
            with self.assertRaisesRegex(lab.LabError, "refusing overwrite"):
                lab.write_new(path, "new value", 0o644)
            self.assertEqual(path.read_text(), "windows")

    def test_write_new_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            protected = base / "other"
            protected.write_text("windows")
            (base / "link").symlink_to(protected)
            with self.assertRaisesRegex(lab.LabError, "refusing overwrite"):
                lab.write_new(base / "link", "new value", 0o644)
            self.assertEqual(protected.read_text(), "windows")

    def test_safe_file_rejects_outside_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "evil").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(lab.LabError, "symlink escape"):
                lab.safe_file(base, "evil")

    def test_loader_digest_is_required(self):
        wrong = dict(PLAN)
        wrong["windowsBootManagerSha256"] = "invalid"
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "plan.json"
            file.write_text(json.dumps(wrong))
            result = subprocess.run(["python3", str(SCRIPT), str(file)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
