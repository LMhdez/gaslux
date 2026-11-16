"""Pure fixture tests for the read-only CachyOS post-boot auditor.

These DO NOT prove an actual UEFI boot or any Windows recovery path.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "assets/live/cachyos-first-boot-audit.py"
spec = importlib.util.spec_from_file_location("cachyos_first_boot_audit", FILE)
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

WINDOWS = b"MZ" + b"Windows fixture only"
RUN_ID = "gaslux-boot-test-1234"
PLAN = {
    "version": 1,
    "firmware": "uefi",
    "secureBootEnabled": False,
    "runId": RUN_ID,
    "rootUuid": "01234567-89ab-cdef-0123-456789abcdef",
    "espUuid": "AB12-CD34",
    "windowsBootUuid": "AB12-CD34",
    "windowsBootManagerSha256": hashlib.sha256(WINDOWS).hexdigest(),
    "linuxLabel": "CachyOS Linux",
    "grubResolution": "1920x1080",
}


class FirstBootAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put(".libertix-stage-owner", RUN_ID)
        self.put("etc/os-release", 'NAME="CachyOS"\nID=cachyos\n')
        self.put("boot/vmlinuz-linux-cachyos", b"kernel")
        self.put("boot/initramfs-linux-cachyos.img", b"initrd")
        self.put("boot/efi/EFI/Gaslux-CachyOS/.gaslux-owner", RUN_ID)
        self.put("boot/efi/EFI/Gaslux-CachyOS/grubx64.efi", b"MZ" + b"grub")
        self.put("boot/efi/EFI/Microsoft/Boot/bootmgfw.efi", WINDOWS)
        self.put("boot/grub/grub.cfg",
                 'menuentry "CachyOS" { linux /boot/vmlinuz-linux-cachyos }\n'
                 'menuentry "Windows Boot Manager" --id gaslux-windows {}\n')
        self.mappings = {
            str(self.root): "/dev/vda3 ext4",
            str(self.root / "boot/efi"): "/dev/vda1 vfat",
        }
        self.uuids = {
            "/dev/vda3": PLAN["rootUuid"],
            "/dev/vda1": PLAN["espUuid"],
        }
        self.kernel = "6.17.4-1-cachyos"

    def put(self, relative, content):
        file = self.root / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content if isinstance(content, bytes) else content.encode())
        return file

    def runner(self, args, **kwargs):
        if args[0] == "findmnt":
            output = self.mappings.get(args[args.index("-M") + 1], "")
        elif args[0] == "blkid":
            output = self.uuids.get(args[-1], "")
        elif args[0] == "uname":
            output = self.kernel
        elif args[:2] == ["pacman", "-Qq"]:
            output = "linux-cachyos"
        else:
            return subprocess.CompletedProcess(args, 1, "", "unexpected")
        return subprocess.CompletedProcess(args, 0, output + "\n", "")

    def check(self):
        return audit.read_only_boot_audit(PLAN, root=self.root, runner=self.runner)

    def test_fixture_audit_does_not_claim_real_boot(self):
        result = self.check()
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "offline-fixture-audited")
        self.assertFalse(result["runningLinuxRootVerified"])
        self.assertFalse(result["firmwareBootOrderVerified"])
        self.assertFalse(result["windowsRollbackVerified"])
        self.assertFalse(result["installationStable"])

    def test_wrong_root_uuid(self):
        self.uuids["/dev/vda3"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        with self.assertRaisesRegex(audit.AuditError, "UUID mismatch at /"):
            self.check()

    def test_wrong_esp_filesystem(self):
        self.mappings[str(self.root / "boot/efi")] = "/dev/vda1 ext4"
        with self.assertRaisesRegex(audit.AuditError, "wrong filesystem"):
            self.check()

    def test_wrong_kernel(self):
        self.kernel = "6.17.4-1-arch"
        with self.assertRaisesRegex(audit.AuditError, "running kernel"):
            self.check()

    def test_windows_loader_modified(self):
        self.put("boot/efi/EFI/Microsoft/Boot/bootmgfw.efi", WINDOWS + b"changed")
        with self.assertRaisesRegex(audit.AuditError, "Windows Boot Manager has changed"):
            self.check()

    def test_efi_ownership_mismatch(self):
        self.put("boot/efi/EFI/Gaslux-CachyOS/.gaslux-owner", "another-run")
        with self.assertRaisesRegex(audit.AuditError, "EFI ownership"):
            self.check()

    def test_previously_valid_root_no_windows_entry(self):
        self.put("boot/grub/grub.cfg", "menuentry Linux { linux /boot/vmlinuz-linux-cachyos }\n")
        with self.assertRaisesRegex(audit.AuditError, "GRUB menu"):
            self.check()

    def test_offline_fixture_cannot_modify_files(self):
        before = {
            str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).digest()
            for p in self.root.rglob("*") if p.is_file()
        }
        self.check()
        after = {
            str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).digest()
            for p in self.root.rglob("*") if p.is_file()
        }
        self.assertEqual(before, after)

    def test_duplicate_windows_plan_path_rejected(self):
        bad_plan = dict(PLAN, windowsBootUuid="FF11-2233")
        with self.assertRaisesRegex(ValueError, "share"):
            audit.read_only_boot_audit(bad_plan, root=self.root, runner=self.runner)


if __name__ == "__main__":
    unittest.main()
