"""No-host-disk contract/negative tests for discardable CachyOS RW child."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys
from unittest import mock
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
import cachyos_windows_shared_cow_rw_child as child

UUID = "a1111111-2222-4333-8444-55555555555a"
RUN = "gaslux-test-run-01"


def witness(uuid=UUID, run_id=RUN, *, second_boot=False) -> bytes:
    return (
        "GASLUX_VM_INSTALLED_RW_ROOT_UUID_SELECTED:" + uuid + "\n"
        "[    0.000000] Linux version 6.18.60-2-cachyos-lts (CachyOS)\n"
        "[    0.114074] Kernel command line: root=UUID=" + uuid
        + " rw console=ttyS0,115200n8 systemd.unit=multi-user.target\n"
        "[ OK ] Reached target Switch Root.\n"
        "Welcome to CachyOS!\n"
        "GASLUX_VM_INSTALLED_CONFIGURED_DESKTOP_ACCOUNT_PASS:" + run_id + ":" + uuid + "\n"
        + ("GASLUX_VM_INSTALLED_RW_CHILD_SECONDBOOT_PASS:" if second_boot
           else "GASLUX_VM_INSTALLED_RW_CHILD_FIRSTBOOT_PASS:")
        + run_id + ":" + uuid + "\n"
        + "[ OK ] Reached target System Power Off.\n"
        + "[   45.058170] reboot: Power down\n"
    ).encode("ascii")


class WritableChildContracts(unittest.TestCase):
    def test_grub_uses_only_owned_uuid_and_rw_to_multi_user(self):
        cfg = child.writable_boot_grub(UUID)
        self.assertIn("search --no-floppy --fs-uuid --set=gaslux_linux_root " + UUID, cfg)
        self.assertIn("GASLUX_VM_INSTALLED_RW_ROOT_UUID_SELECTED:" + UUID, cfg)
        self.assertIn(" root=UUID=" + UUID + " rw", cfg)
        self.assertIn("systemd.unit=multi-user.target", cfg)
        self.assertNotIn("systemd.unit=poweroff.target", cfg)
        self.assertNotIn(" root=UUID=" + UUID + " ro", cfg)
        for keyword in ("(hd0", "/dev/sda", "grub-install", "efibootmgr"):
            self.assertNotIn(keyword, cfg)
        for bad in ("", UUID.upper(), "not-a-uuid", UUID + " "):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                child.writable_boot_grub(bad)

    def test_service_validates_os_uuid_mount_and_owner_before_writing(self):
        script, unit = child.installed_rw_service(RUN, UUID)
        for item in (
            b"cat /.gaslux-lab-root-owner",
            b"findmnt -nr -o SOURCE --target /",
            b"blkid -s UUID -o value",
            b"findmnt -nr -o FSTYPE --target /",
            b"findmnt -nr -o OPTIONS --target /",
            b"root_uuid='" + UUID.encode() + b"'",
            b"root=UUID=$root_uuid",
            b"systemd.unit=multi-user.target",
            b"cat /etc/hostname",
            b"LANG=en_US.UTF-8",
            b"locale -a",
            b"substr($2,1,3) == \"$6$\"",
            b"KEYMAP=us",
            b"gaslux-lab",
            b"plasma-desktop",
            b"NetworkManager.service",
            b"child-rw-firstboot",
            b'[[ ",$options," == *,rw,* ]]',
            b'set -Eeuo pipefail',
            b'sync',
        ):
            self.assertIn(item, script)
        self.assertIn(b"RequiresMountsFor=/var/lib/gaslux-lab", unit)
        self.assertIn(b"StandardOutput=journal+console", unit)
        self.assertIn(b"ExecStartPost=/usr/bin/systemctl --no-block poweroff", unit)
        self.assertNotIn(b"grub-install", script)
        self.assertNotIn(b"mkfs", script)
        with self.assertRaises(ValueError):
            child.installed_rw_service("../../bad", UUID)

    def test_rw_serial_requires_native_kernel_root_switch_and_guest_write_marker(self):
        child.verify_rw_serial(witness(), RUN, UUID)
        for invalid in (
            witness().replace(b"Linux version", b"GRUB version"),
            witness().replace(b"Kernel command line", b"GRUB command line"),
            witness().replace(b"root=UUID=", b"root=PARTUUID="),
            witness().replace(b" rw ", b" ro "),
            witness().replace(b"systemd.unit=multi-user.target",
                              b"systemd.unit=poweroff.target"),
            witness().replace(b"Switch Root", b"Initrd Only"),
            witness().replace(b"Welcome to CachyOS", b"Welcome to Ubuntu"),
            witness().replace(b"RW_CHILD_FIRSTBOOT_PASS", b"RW_CHILD_FIRSTBOOT_MISSING"),
            witness().replace(b"System Power Off", b"Incomplete Shutdown"),
            witness().replace(b"reboot: Power down", b"reboot: Restarting"),
            witness().replace(b"GASLUX_VM_INSTALLED_RW_ROOT_UUID_SELECTED:",
                              b"GASLUX_VM_INSTALLED_RW_ROOT_UUID_SELECTED:wrong-"),
            witness()+witness(),
            witness()+b"Kernel panic",
            b"",
            b"x"*(child.MAX_SERIAL_BYTES+1),
        ):
            with self.subTest(len=len(invalid)), self.assertRaises(child.ChildCOWBootError):
                child.verify_rw_serial(invalid, RUN, UUID)

    def test_second_rw_boot_requires_distinct_marker_and_rejects_first_replay(self):
        child.verify_rw_serial(witness(second_boot=True), RUN, UUID,
                               second_boot=True)
        with self.assertRaises(child.ChildCOWBootError):
            child.verify_rw_serial(witness(), RUN, UUID, second_boot=True)
        with self.assertRaises(child.ChildCOWBootError):
            child.verify_rw_serial(witness(second_boot=True), RUN, UUID)
        for altered in (
            witness(second_boot=True).replace(
                b"RW_CHILD_SECONDBOOT_PASS", b"RW_CHILD_FIRSTBOOT_PASS"),
            witness(second_boot=True) + witness(),
            witness(second_boot=True).replace(RUN.encode(), b"foreign-run"),
            witness(second_boot=True).replace(
                b"System Power Off", b"Poweroff Incomplete"),
            witness(second_boot=True).replace(
                b"rw console", b"ro console"),
            witness(second_boot=True) + b"Kernel panic",
        ):
            with self.subTest(sample=len(altered)), self.assertRaises(
                    child.ChildCOWBootError):
                child.verify_rw_serial(altered, RUN, UUID, second_boot=True)

    def test_second_rw_marker_can_only_follow_owned_first(self):
        script, _ = child.installed_rw_service(RUN, UUID)
        for required in (
            b'if [[ -e "$first" || -L "$first" ]]; then',
            b'[[ -f "$first" && ! -L "$first" && ! -e "$second" && ! -L "$second" ]]',
            b'[[ "$(cat "$first")" == "$run_id" ]]',
            b'printf \x27%s\\n\x27 "$run_id" > "$second"',
            b'GASLUX_VM_INSTALLED_RW_CHILD_SECONDBOOT_PASS:',
        ):
            self.assertIn(required, script)
        source = (TOOLS / "cachyos_windows_shared_cow_rw_child.py").read_text()
        self.assertIn("second_boot=True", source)
        self.assertIn("installedWritableChildSecondBootVerified", source)
        self.assertIn("installedWritableChildSecondBootPersistentMarkerVerified", source)
        self.assertIn("second_serial.read_bytes()", source)
        self.assertIn("_read_child_marker(child, root_uuid, run_id, second_boot=True)", source)
        self.assertIn("child.unlink()", source)
        self.assertIn('"-net", "none"', source)

    def test_invalid_lab_context_does_not_create_child_or_launch_qemu(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=True), \
             mock.patch.object(child, "_run") as run, \
             mock.patch.object(child.subprocess, "Popen") as vm, \
             self.assertRaises(child.ChildCOWBootError):
            child.probe_owned_rw_child(
                overlay=Path("/fake/parent.qcow2"),
                base=Path("/fake/windows.qcow2"),
                nvram=Path("/fake/vars.fd"),
                ovmf_code=Path("/fake/ovmf.fd"),
                workspace=Path("/fake"),
                plan={},
                run_id=RUN,
            )
        run.assert_not_called()
        vm.assert_not_called()

    def test_only_nested_child_is_guest_writable_and_is_always_discarded(self):
        s=(TOOLS / "cachyos_windows_shared_cow_rw_child.py").read_text()
        parent=(TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        workflow=(TOOLS.parent.parent/".github/workflows/"
                  "cachyos-windows10-shared-root-pacstrap.yml").read_text()
        self.assertIn('"if=none,id=rwchild,format=qcow2,file=" + str(child)', s)
        self.assertIn('"-device", "usb-storage,drive=rwchild,bootindex=2"', s)
        self.assertIn('str(overlay), str(child)', s)
        self.assertIn('info.get("backing-filename") == str(overlay)', s)
        self.assertIn('g.mount(fifth, "/")', s)
        self.assertIn('g.vfs_uuid(fifth).lower() == root_uuid', s)
        self.assertIn('read_windows_file_hashes(child) == plan["windowsHashes"]', s)
        self.assertIn('plan["gptWindowsSha256"]', s)
        self.assertIn('child.unlink()', s)
        self.assertIn('_sha(overlay) == old_parent', s)
        self.assertIn('_sha(base) == old_base', s)
        self.assertIn('"-net", "none"', s)
        self.assertIn('"productionStorageWritesAuthorized": False', s)
        self.assertIn('"firstBootWithWritableSystemVerified": False', s)
        self.assertIn('if firstboot_status.get("minimalInstalledReadOnlyBootVerified") is True:', parent)
        self.assertIn('read_windows_file_hashes(overlay) == plan["windowsHashes"]', parent)
        self.assertIn("--run-cachyos-shared-root-pacstrap", workflow)


if __name__ == "__main__":
    unittest.main()
