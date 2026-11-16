"""Zero-disk GRUB generation tests; do not assert real VM boot or Windows health."""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_generated_boot_config.py"
_SPEC = importlib.util.spec_from_file_location("gaslux_generated_boot", _SOURCE)
assert _SPEC and _SPEC.loader
boot = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(boot)

HASH = hashlib.sha256(b"synthetic, not an ISO").hexdigest()
UUID = "01234567-89ab-cdef-0123-456789abcdef"


def fake_handoff(plan, **_kwargs):
    kernel = "arch/boot/x86_64/vmlinuz-linux-cachyos-lts"
    initramfs = "arch/boot/x86_64/initramfs-linux-cachyos-lts.img"
    return {
        "ok": True,
        "isoSha256Verified": True,
        "isoLayoutVerified": True,
        "windowsRecoveryVerified": False,
        "productionInstallSupported": False,
        "grubEntry": (
            "# backend owned\n"
            "menuentry 'CachyOS Archiso (experimental)' --id gaslux-cachyos-archiso {\n"
            f"    search --no-floppy --fs-uuid --set=gaslux_iso_dev {plan['isoStorageUuid']}\n"
            "    loopback gaslux_iso ($gaslux_iso_dev)/cachyos.iso\n"
            f"    linux (gaslux_iso)/{kernel} "
            f"archisobasedir=arch img_dev=UUID={plan['isoStorageUuid']} "
            "img_loop=/cachyos.iso cow_spacesize=10G copytoram=auto\n"
            f"    initrd (gaslux_iso)/{initramfs}\n"
            "}\n"
        ),
        "liveKernelPath": kernel,
        "liveInitramfsPath": initramfs,
    }


class GeneratedBootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / "cachyos.iso"
        self.file.write_bytes(b"synthetic, not an ISO")
        self.mount = self.root / "mounted"
        self.mount.mkdir()

    def generate(self, **changes):
        values = {
            "iso_path": self.file,
            "pinned_sha256": HASH,
            "volume_uuid": UUID,
            "iso_root": self.mount,
        }
        values.update(changes)
        with patch.object(boot._HANDOFF, "prepare", side_effect=fake_handoff) as mocked:
            result = boot.generate(**values)
            self.assertEqual(mocked.call_count, 1)
            return result

    def test_real_backend_output_is_used_not_manual_test_grub(self):
        cfg, report = self.generate()
        self.assertIn("# backend owned", cfg)
        self.assertIn("set default=gaslux-cachyos-archiso", cfg)
        self.assertIn("loopback gaslux_iso ($gaslux_iso_dev)/cachyos.iso", cfg)
        self.assertIn("img_dev=UUID=" + UUID, cfg)
        self.assertIn("systemd.unit=multi-user.target", cfg)
        self.assertTrue(report["generatedFromBackend"])
        self.assertFalse(report["windowsRecoveryVerified"])
        self.assertFalse(report["sourcePlanSigned"])
        self.assertFalse(report["actualBootVerified"])
        self.assertFalse(report["stable"])
        self.assertEqual(hashlib.sha256(cfg.encode()).hexdigest(), report["grubSha256"])

    def test_only_kernel_console_line_is_extended(self):
        cfg, _ = self.generate()
        unchanged = fake_handoff({"isoStorageUuid": UUID})["grubEntry"].splitlines()
        new = cfg.splitlines()[5:]
        self.assertEqual(len(unchanged), len(new))
        changed = [(old, actual) for old, actual in zip(unchanged, new) if old != actual]
        self.assertEqual(len(changed), 1)
        self.assertTrue(changed[0][0].startswith("    linux (gaslux_iso)/"))
        self.assertEqual(changed[0][1], changed[0][0] + boot._DIAGNOSTIC_FLAGS)

    def test_bad_hash_rejected_before_backend(self):
        with self.assertRaisesRegex(boot.LabBootError, "SHA-256"):
            self.generate(pinned_sha256="not-a-digest")

    def test_bad_uuid_rejected_before_backend(self):
        with self.assertRaisesRegex(boot.LabBootError, "UUID"):
            self.generate(volume_uuid="; reboot")

    def test_symlink_to_iso_rejected(self):
        old = self.file
        self.file = self.root / "copied-iso"
        self.file.write_bytes(b"synthetic")
        old.unlink()
        old.symlink_to(self.file)
        with self.assertRaisesRegex(boot.LabBootError, "regular"):
            self.generate(iso_path=old)

    def test_wrong_iso_filename_rejected(self):
        with self.assertRaisesRegex(boot.LabBootError, "cachyos.iso"):
            self.generate(iso_path=self.root / "wrong.iso")

    def test_source_directory_same_as_iso_root_rejected(self):
        with self.assertRaisesRegex(boot.LabBootError, "distinct"):
            self.generate(iso_root=self.root)

    def test_backend_cannot_claim_production_support(self):
        def unsafe(plan, **kwargs):
            return {**fake_handoff(plan, **kwargs), "productionInstallSupported": True}
        with patch.object(boot._HANDOFF, "prepare", side_effect=unsafe):
            with self.assertRaisesRegex(boot.LabBootError, "backend readiness"):
                boot.generate(self.file, HASH, UUID, self.mount)

    def test_backend_missing_initramfs_rejected(self):
        def no_initrd(plan, **kwargs):
            obj = fake_handoff(plan, **kwargs)
            obj["grubEntry"] = obj["grubEntry"].replace("    initrd ", "    absent ")
            return obj
        with patch.object(boot._HANDOFF, "prepare", side_effect=no_initrd):
            with self.assertRaisesRegex(boot.LabBootError, "exactly one"):
                boot.generate(self.file, HASH, UUID, self.mount)

    def test_backend_wrong_uuid_rejected(self):
        def stale(plan, **kwargs):
            obj = fake_handoff(plan, **kwargs)
            obj["grubEntry"] = obj["grubEntry"].replace(
                "img_dev=UUID=" + UUID, "img_dev=UUID=" + "0" * 36
            )
            return obj
        with patch.object(boot._HANDOFF, "prepare", side_effect=stale):
            with self.assertRaisesRegex(boot.LabBootError, "img_dev"):
                boot.generate(self.file, HASH, UUID, self.mount)


if __name__ == "__main__":
    unittest.main()
