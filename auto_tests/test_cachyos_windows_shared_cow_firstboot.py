"""Synthetic contracts for the installed-root read-only QEMU boot smoke.

No disks, partitions, or guest machines are started by these unit tests.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import cachyos_windows_shared_cow_firstboot as firstboot
import cachyos_windows_shared_root_pacstrap_host as host

ROOT_UUID = "a1111111-2222-4333-8444-55555555555a"
RUN_ID = "gaslux-test-run-01"


def witness(uuid=ROOT_UUID):
    # Modeled on the genuine independent installed-CachyOS first boot
    # from Actions #43991443719 (artifact #14289991307); no fabricated
    # "Linux version" or "Powering off." line which that COM1 lacks.
    return (
        "GASLUX_VM_INSTALLED_ROOT_UUID_SELECTED:" + uuid + "\n"
        "[    0.699368] virt/tdx: TDX not supported by the host platform\n"
        "\x1b]3008;user=root;pid=1;comm=systemd;type=boot\x1b\\\n"
        "Welcome to \x1b[0m\x1b[38;2;23;147;209mCachyOS\x1b[0m!\n"
        "[ OK ] Reached target System Power Off.\n"
        "[   45.058170] reboot: Power down\n"
    ).encode("ascii")


class InstalledReadOnlyFirstbootContracts(unittest.TestCase):
    def test_grub_uses_only_canonical_root_uuid_and_linux_kernel(self):
        cfg = firstboot.installed_poweroff_grub_config(ROOT_UUID)
        for part in (
            "search --no-floppy --fs-uuid --set=gaslux_linux_root " + ROOT_UUID,
            "vmlinuz-linux-cachyos-lts",
            "initramfs-linux-cachyos-lts.img",
            "root=UUID=" + ROOT_UUID,
            "systemd.unit=poweroff.target",
            " ro console=ttyS0",
        ):
            self.assertIn(part, cfg)
        for forbidden in ("(hd0", "/dev/sda", "grub-install", "efibootmgr",
                          "sgdisk --clear", "rw console", "chainloader"):
            self.assertNotIn(forbidden, cfg)
        for uuid in ("../../etc/passwd", ROOT_UUID.upper(), "bad", "", ROOT_UUID+" "):
            with self.subTest(uuid=uuid), self.assertRaises(
                    firstboot.InstalledReadOnlyBootError):
                firstboot.installed_poweroff_grub_config(uuid)

    def test_native_kernel_systemd_and_clean_poweroff_are_all_required(self):
        firstboot.verify_installed_poweroff_serial(witness(), ROOT_UUID)
        for failure in (
            witness().replace(b"[    0.699368] virt/tdx",
                              b"GRUB version plus virt/tdx").replace(
                b"[   45.058170] reboot: Power down", b"reboot: Power down"),
            witness().replace(b"comm=systemd;type=boot",
                              b"comm=not-systemd;type=boot"),
            witness().replace(b"CachyOS", b"foreign-os"),
            witness().replace(b"System Power Off", b"Shutdown incomplete"),
            witness().replace(b"reboot: Power down", b"Guest restarted"),
            witness().replace(b"GASLUX_VM_INSTALLED_ROOT_UUID_SELECTED:",
                              b"GASLUX_VM_INSTALLED_ROOT_UUID_SELECTED:other-"),
            witness()+b"Kernel panic",
            witness()+b"GASLUX_VM_INSTALLED_ROOT_KERNEL_MISSING",
            witness()+witness(),
            b"",
            b"A"*(firstboot.MAX_SERIAL_BYTES+1),
        ):
            with self.subTest(length=len(failure)), self.assertRaises(
                    firstboot.InstalledReadOnlyBootError):
                firstboot.verify_installed_poweroff_serial(failure, ROOT_UUID)

    def test_missing_runner_consent_refuses_before_any_qemu_command(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=True), \
             mock.patch.object(firstboot, "_run") as run, \
             mock.patch.object(firstboot.subprocess, "Popen") as popen, \
             self.assertRaises(firstboot.InstalledReadOnlyBootError):
            firstboot.probe_installed_root_readonly(
                overlay=Path("/not-a-real-cow"), base=Path("/not-a-real-base"),
                nvram=Path("/not-a-real-vars"), ovmf_code=Path("/not-a-real-efi"),
                workspace=Path("/not-a-real-workspace"), plan={}, run_id="")
        run.assert_not_called()
        popen.assert_not_called()

    def test_mocked_qemu_can_only_read_windows_cow_and_uses_fresh_efi(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ro-firstboot-fixture-") as td:
            temp = Path(td)
            workspace = temp / "gaslux-win-x64-fixture"
            workspace.mkdir(mode=0o700)
            checkpoint = workspace / host.CHECKPOINT_DIR
            checkpoint.mkdir(mode=0o700)
            base = workspace / "only-disposable-windows-target.qcow2"
            base.write_bytes(b"private dummy Windows backing")
            base.chmod(0o400)
            overlay = checkpoint / host.OVERLAY_NAME
            overlay.write_bytes(b"dummy owned QCOW2 overlay")
            overlay.chmod(0o600)
            nvram = workspace / "ovmf-variables.fd"
            nvram.write_bytes(b"original Windows variables")
            code = workspace / "OVMF_CODE.fd"
            code.write_bytes(b"C" * 500_001)
            vars_template = workspace / "OVMF_VARS.fd"
            vars_template.write_bytes(b"V" * 131072)
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(argv)
                if argv[:2] == ["qemu-img", "info"]:
                    return subprocess.CompletedProcess(
                        argv, 0, json.dumps({
                            "format": "qcow2", "virtual-size": firstboot.VIRTUAL_BYTES,
                            "backing-filename": str(base),
                            "backing-filename-format": "qcow2",
                        }), "")
                if argv[0] == "grub-mkstandalone":
                    output = next(x.partition("=")[2] for x in argv
                                  if x.startswith("--output="))
                    Path(output).write_bytes(b"GRUB_EFI_OWNED")
                if argv[0] == "truncate":
                    Path(argv[-1]).write_bytes(b"private FAT32 fixture")
                return subprocess.CompletedProcess(argv, 0, "", "")

            class FakeVM:
                returncode = 0
                def wait(self, timeout=None):
                    self.returncode = 0
                    return 0

            def fake_popen(argv, **kwargs):
                calls.append(argv)
                serial_path = next(x[5:] for idx, x in enumerate(argv)
                                   if idx > 0 and argv[idx-1] == "-serial"
                                   and x.startswith("file:"))
                Path(serial_path).write_bytes(witness())
                return FakeVM()

            env = {
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "GITHUB_REPOSITORY": "LMhdez/gaslux",
                "RUNNER_TEMP": str(temp),
                "GASLUX_CACHYOS_INSTALLED_RO_BOOT_CONSENT": firstboot.CONSENT,
            }
            with mock.patch.dict(os.environ, env), \
                 mock.patch.object(firstboot, "_run", side_effect=fake_run), \
                 mock.patch.object(host, "_run", side_effect=fake_run), \
                 mock.patch.object(firstboot.subprocess, "Popen",
                                   side_effect=fake_popen), \
                 mock.patch.object(firstboot, "qcow2_file_identity",
                                   return_value="owned-baseline"), \
                 mock.patch.object(firstboot, "OVMF_VARS", str(vars_template)), \
                 mock.patch.object(firstboot.Path, "is_char_device",
                                   return_value=True):
                result = firstboot.probe_installed_root_readonly(
                    overlay=overlay, base=base, nvram=nvram, ovmf_code=code,
                    workspace=workspace,
                    plan={"labOnly": True, "writeAuthority": False,
                          "runId": RUN_ID, "rootFsUuid": ROOT_UUID},
                    run_id=RUN_ID)
            self.assertIs(result["minimalInstalledReadOnlyBootVerified"], True)
            self.assertFalse(result["sameDiskDualBootVerified"])
            self.assertFalse(result["firstBootWithWritableSystemVerified"])
            qemu = next(x for x in calls if x[0] == "qemu-system-x86_64")
            self.assertIn("if=none,id=installedroot,format=qcow2,file="
                          + str(overlay) + ",readonly=on", qemu)
            self.assertIn("if=none,id=installedefi,format=raw,file="
                          + str(workspace/"cachyos-installed-readonly-efi.raw")
                          + ",readonly=on", qemu)
            self.assertIn("usb-storage,drive=installedroot,bootindex=2", qemu)
            self.assertIn("-net", qemu)
            self.assertEqual(qemu[qemu.index("-net")+1], "none")
            self.assertNotIn(str(nvram), " ".join(qemu))
            self.assertFalse(any(x[0] in {"sgdisk", "parted", "grub-install"}
                                 for x in calls))

    def test_firstboot_module_cannot_claim_windows_rollback_or_full_dualboot(self):
        source = (TOOLS / "cachyos_windows_shared_cow_firstboot.py").read_text()
        host_source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        self.assertIn("read_windows_file_hashes(overlay)", host_source)
        self.assertIn("probe_installed_root_readonly(", host_source)
        self.assertIn("minimalInstalledReadOnlyBootVerified", source)
        self.assertIn('"sameDiskDualBootVerified": False', source)
        self.assertIn('"productionStorageWritesAuthorized": False', source)
        self.assertIn("firstBootWithWritableSystemVerified", source)
        self.assertIn('"minimalInstalledReadOnlyBootVerified": False', host_source)


if __name__ == "__main__":
    unittest.main()
