from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))

import cachyos_windows_shared_root_pacstrap_host as host


class SharedRootPacstrapHostContracts(unittest.TestCase):
    def test_iso_private_loop_permission_fix_requires_exact_backing_identity(self):
        # Sparse 4 GiB private *file*, never a real block device/mount.
        with tempfile.TemporaryDirectory(prefix="gaslux-iso-test-") as td:
            workspace = Path(td)
            image = workspace / "cachyos-iso-source.raw"
            with image.open("xb") as file:
                file.truncate(4 * 1024**3)
            mountpoint = workspace / "cachyos-iso-storage"
            mountpoint.mkdir(mode=0o700)

            def run(argv, **kwargs):
                if argv[0] == "findmnt":
                    return subprocess.CompletedProcess(
                        argv, 0, "/dev/loop73 ext4 rw,relatime\n", "")
                if argv[0] == "losetup":
                    return subprocess.CompletedProcess(
                        argv, 0, str(image) + "\n", "")
                if argv[0] == "sudo":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                raise AssertionError("unexpected command " + str(argv))

            with mock.patch.object(host, "_run", side_effect=run) as commands:
                host._permit_owned_iso_staging_write(image, mountpoint)
                seen = [call.args[0] for call in commands.call_args_list]
                self.assertEqual(seen[0][0], "findmnt")
                self.assertEqual(seen[1],
                                 ["losetup", "--noheadings", "--output",
                                  "BACK-FILE", "/dev/loop73"])
                self.assertEqual(seen[2],
                                 ["sudo", "chown", "--",
                                  f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
                self.assertEqual(seen[3],
                                 ["sudo", "chmod", "--", "0700", str(mountpoint)])

    def test_iso_private_loop_fails_before_chown_if_device_is_foreign(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-iso-deny-") as td:
            workspace = Path(td)
            image = workspace / "cachyos-iso-source.raw"
            with image.open("xb") as f:
                f.truncate(4 * 1024**3)
            mountpoint = workspace / "cachyos-iso-storage"
            mountpoint.mkdir(mode=0o700)
            for source, kind, options, actual_backing in (
                    ("/dev/sda", "ext4", "rw,relatime", str(image)),
                    ("/dev/loop4", "vfat", "rw,relatime", str(image)),
                    ("/dev/loop4", "ext4", "ro,relatime", str(image)),
                    ("/dev/loop4", "ext4", "rw,relatime", "/tmp/foreign.img")):
                def run(argv, **kwargs):
                    if argv[0] == "findmnt":
                        return subprocess.CompletedProcess(
                            argv, 0, f"{source} {kind} {options}\n", "")
                    if argv[0] == "losetup":
                        return subprocess.CompletedProcess(
                            argv, 0, actual_backing + "\n", "")
                    raise AssertionError("must refuse before any privileged write")
                with self.subTest(source=source, kind=kind, options=options,
                                  backing=actual_backing), \
                     mock.patch.object(host, "_run", side_effect=run) as commands, \
                     self.assertRaises(host.SharedRootPacstrapError):
                    host._permit_owned_iso_staging_write(image, mountpoint)
                self.assertFalse(any(x.args[0][0] == "sudo" for x in
                                     commands.call_args_list))

    def test_iso_private_mount_cannot_use_symlink_image(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-iso-linked-") as td:
            folder = Path(td)
            real = folder / "real-image.raw"
            real.touch()
            path = folder / "cachyos-iso-source.raw"
            path.symlink_to(real)
            mountpoint = folder / "cachyos-iso-storage"
            mountpoint.mkdir()
            with mock.patch.object(host, "_run") as commands, \
                 self.assertRaises(host.SharedRootPacstrapError):
                host._permit_owned_iso_staging_write(path, mountpoint)
            commands.assert_not_called()

    def test_genuine_vm_apt_stalls_are_bounded_and_guest_is_security_held(self):
        workflow = (TOOLS.parent.parent / ".github/workflows/"
                    "cachyos-windows10-shared-root-pacstrap.yml").read_text()
        self.assertIn("timeout --kill-after=10s 300s sudo apt-get", workflow)
        self.assertIn("timeout --kill-after=10s 1800s sudo DEBIAN_FRONTEND=noninteractive apt-get", workflow)
        self.assertIn("Acquire::https::Timeout=60", workflow)
        self.assertIn("mirrorlist=/etc/apt/apt-mirrors.txt", workflow)
        self.assertIn("sources=/etc/apt/sources.list.d/ubuntu.sources", workflow)
        self.assertIn("Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg", workflow)
        self.assertIn("grep -Fxq 'https://archive.ubuntu.com/ubuntu/'", workflow)
        # Fail if the mirrorlist has a literal backslash-n rather than newline.
        mirror_line = "printf '%s" + chr(92) + "n' 'https://archive.ubuntu.com/ubuntu/'"
        self.assertIn(mirror_line, workflow)
        self.assertNotIn("printf '%s" + chr(92) * 2 + "n' 'https://archive.ubuntu.com/ubuntu/'", workflow)
        self.assertNotIn("--allow-unauthenticated", workflow)
        self.assertNotIn("Acquire::AllowInsecureRepositories", workflow)
        # The firmware meta depends on hundreds of MB of unrelated GPU,
        # Wi-Fi, and device firmware. The guestfs Linux VM needs only the
        # authenticated kernel image and matching signed module packages.
        self.assertIn("apt-cache depends linux-image-generic", workflow)
        self.assertIn('extra_modules="linux-modules-extra-', workflow)
        self.assertIn('"$generic_kernel" "$extra_modules"', workflow)
        self.assertNotIn('libguestfs-tools linux-image-generic', workflow)
        self.assertIn("Kernel packaging unexpectedly requires firmware", workflow)
        self.assertIn("real-windows10-archiso-pacstrap-and-discard:", workflow)
        # The previous A/B run changed protected ESP BCD. Keep the
        # expensive KVM/pacstrap job unconditionally held until independent
        # Safety review; only static and synthetic contracts may run meanwhile.
        self.assertIn(
            "  real-windows10-archiso-pacstrap-and-discard:\\n"
            "    # SECURITY HOLD: genuine A/B Windows #44900941635 modified protected ESP",
            workflow,
        )
        self.assertIn(
            "    if: false\\n    needs: static-and-synthetic-contracts",
            workflow,
        )
        self.assertNotIn("    if: >-", workflow)

    def test_trial_firmware_uses_fresh_ovmf_template_not_windows_bootorder(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ovmf-template-") as temp:
            root = Path(temp)
            template = root / "OVMF_VARS_4M.fd"
            destination = root / "trial-vars.fd"
            template.write_bytes(b"fresh-ovmf-template" * 8192)
            digest = host._copy_fresh_ovmf_vars(template, destination)
            self.assertEqual(destination.read_bytes(), template.read_bytes())
            self.assertEqual(len(digest), 64)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_trial_firmware_refuses_symlink_and_reused_destination(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-ovmf-reject-") as temp:
            root = Path(temp)
            template = root / "OVMF_VARS_4M.fd"
            template.write_bytes(b"fresh-ovmf-template" * 8192)
            destination = root / "trial-vars.fd"
            destination.write_bytes(b"existing")
            with self.assertRaises(host.SharedRootPacstrapError):
                host._copy_fresh_ovmf_vars(template, destination)
            destination.unlink()
            linked = root / "linked-template.fd"
            linked.symlink_to(template)
            with self.assertRaises(host.SharedRootPacstrapError):
                host._copy_fresh_ovmf_vars(linked, destination)

    def test_archiso_efi_loader_has_explicit_qemu_boot_priority(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        self.assertIn("from cachyos_windows_shared_archiso_handoff import", source)
        self.assertIn("from windows_x64_qemu_host_gate import OVMF_VARS", source)
        self.assertIn('"usb-storage,drive=liveefi,bootindex=1"', source)
        self.assertNotIn('"order=c"', source)
        self.assertIn("_copy_fresh_ovmf_vars(Path(OVMF_VARS), trial_vars)", source)
        self.assertNotIn("shutil.copyfile(nvram, trial_vars)", source)

    def test_iso_transport_is_uefi_visible_but_only_windows_cow_is_writable(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        self.assertIn('"usb-storage,drive=liveefi,bootindex=1"', source)
        self.assertIn('"usb-storage,drive=iso_source,bootindex=2"', source)
        self.assertIn('"if=none,id=iso_source,format=raw,file=" + str(iso_image) + ",readonly=on"', source)
        self.assertIn('"virtio-blk-pci,drive=windows_cow,serial=" + SERIAL', source)
        self.assertNotIn('"virtio-blk-pci,drive=iso_source"', source)
        self.assertIn("before_iso_image_sha", source)

    def test_grub_missing_iso_uuid_emits_diagnostic_without_fallback(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-grub-iso-uuid-") as td:
            root = Path(td)
            iso = root / "cachyos.iso"
            iso.touch()
            iso_mount = root / "iso-mounted"
            iso_mount.mkdir()
            workspace = root / "work"
            workspace.mkdir()
            volume_uuid = "01234567-89ab-cdef-0123-456789abcdef"
            generated = (
                "menuentry 'CachyOS Archiso (experimental)' {\n"
                "    search --no-floppy --fs-uuid --set=gaslux_iso_dev " + volume_uuid + "\n"
                "    loopback gaslux_iso ($gaslux_iso_dev)/cachyos.iso\n"
                "    linux (gaslux_iso)/arch/boot/x86_64/vmlinuz-linux-cachyos-lts "
                "archisobasedir=arch img_dev=UUID=" + volume_uuid + " img_loop=/cachyos.iso\n"
                "    initrd (gaslux_iso)/arch/boot/x86_64/initramfs-linux-cachyos-lts.img\n"
                "}\n"
            )

            def run(argv, **kwargs):
                if argv[0] == "python3":
                    Path(argv[-2]).write_text(generated)
                    Path(argv[-1]).write_text("{}")
                elif argv[0] != "grub-script-check":
                    raise AssertionError("unexpected command " + str(argv))
                return subprocess.CompletedProcess(argv, 0, "", "")

            with mock.patch.object(host, "_run", side_effect=run):
                cfg = host._create_boot_config(
                    iso=iso, iso_sha256="a" * 64, iso_uuid=volume_uuid,
                    iso_mount=iso_mount, workspace=workspace, run_id="run-12345",
                    nonce="nonce-12345", plan_sha="b" * 64, key_sha="c" * 64,
                ).read_text()
            self.assertIn("GASLUX_VM_ISO_UUID_SEARCH_BEGIN", cfg)
            self.assertIn("GASLUX_VM_ISO_UUID_NOT_VISIBLE", cfg)
            self.assertEqual(cfg.count("search --no-floppy --fs-uuid"), 1)
            self.assertIn('if [ -z "$gaslux_iso_dev" ]; then', cfg)
            self.assertIn("img_dev=UUID=" + volume_uuid, cfg)
            self.assertNotIn("set gaslux_iso_dev=hd", cfg)
            self.assertLess(cfg.index("search --no-floppy --fs-uuid"),
                            cfg.index("GASLUX_VM_ISO_UUID_NOT_VISIBLE"))

    def test_grub_multiple_iso_uuid_searches_are_rejected_before_boot(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-grub-dup-search-") as td:
            root = Path(td)
            iso = root / "cachyos.iso"
            iso.touch()
            mounted = root / "iso-mounted"
            mounted.mkdir()
            workspace = root / "work"
            workspace.mkdir()
            line = "    search --no-floppy --fs-uuid --set=gaslux_iso_dev 01234567-89ab-cdef-0123-456789abcdef\n"

            def run(argv, **kwargs):
                if argv[0] == "python3":
                    Path(argv[-2]).write_text(line + line)
                    Path(argv[-1]).write_text("{}")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with mock.patch.object(host, "_run", side_effect=run):
                with self.assertRaisesRegex(host.SharedRootPacstrapError, "ISO device lookup is ambiguous"):
                    host._create_boot_config(
                        iso=iso, iso_sha256="a" * 64,
                        iso_uuid="01234567-89ab-cdef-0123-456789abcdef",
                        iso_mount=mounted, workspace=workspace, run_id="run-12345",
                        nonce="nonce-12345", plan_sha="b" * 64, key_sha="c" * 64,
                    )

    def test_host_keeps_checkpoint_and_readonly_media_integrity_guards(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        for token in (
            '(handoff / "host-checkpoint.json", "host-checkpoint.json")',
            '(handoff / "host-overlay-backing-proof.json", "host-overlay-backing-proof.json")',
            'post_info_doc.get("backing-filename")',
            "before_iso_image_sha",
            "before_control_sha",
            "before_boot_efi_sha",
            'require(created.returncode == 0, "could not create isolated UEFI fallback directory")',
        ):
            self.assertIn(token, source)

    def test_pacstrap_and_discard_evidence_are_valid_json_whitespace(self):
        source = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        self.assertNotIn('+ "' + chr(92) * 2 + 'n"', source)
        self.assertIn("json.dumps(pacstrap_proof, sort_keys=True, indent=2)", source)
        self.assertIn("json.dumps(discard_proof, sort_keys=True, indent=2)", source)
        self.assertIn('+ "' + chr(92) + 'n"', source)

    def test_guest_installer_remains_root_only_and_never_installs_efi(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn('"pacstrap", "-K", "-C", str(strict_config), str(ROOT)', source)
        self.assertIn('verify_mounted_source(ROOT, root_partition, "ext4", readonly=False)', source)
        self.assertIn("GASLUX_SHARED_COW_ESP_BOOTLOADER_NOT_INSTALLED=1", source)
        for forbidden in ("sgdisk --clear", "grub-install", "efibootmgr -c", "mkfs.ext4"):
            self.assertNotIn(forbidden, source)


    def test_boot_config_failure_surfaces_sanitized_generator_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-boot-diagnostic-") as td:
            root = Path(td)
            iso = root / "cachyos.iso"
            iso.touch()
            iso_mount = root / "mounted-iso"
            iso_mount.mkdir()
            workspace = root / "workspace"
            workspace.mkdir()
            raw_error = (
                f"unsafe ISO directory: {iso_mount}; token=private-token-value"
            )
            result = subprocess.CompletedProcess(
                [], 1, "", json.dumps({"ok": False, "error": raw_error})
            )
            with mock.patch.object(host, "_run", return_value=result):
                with self.assertRaises(host.SharedRootPacstrapError) as caught:
                    host._create_boot_config(
                        iso=iso, iso_sha256="a" * 64, iso_uuid="01234567-89ab-cdef-0123-456789abcdef",
                        iso_mount=iso_mount, workspace=workspace, run_id="run-12345",
                        nonce="nonce-12345", plan_sha="b" * 64, key_sha="c" * 64,
                    )
            message = str(caught.exception)
            self.assertIn("unsafe ISO directory", message)
            self.assertIn("<private-path>", message)
            self.assertNotIn(str(iso_mount), message)
            self.assertNotIn("private-token-value", message)

    def test_boot_config_failure_does_not_publish_unstructured_output(self):
        with tempfile.TemporaryDirectory(prefix="gaslux-boot-unstructured-") as td:
            root = Path(td)
            iso = root / "cachyos.iso"
            iso.touch()
            iso_mount = root / "mounted-iso"
            iso_mount.mkdir()
            workspace = root / "workspace"
            workspace.mkdir()
            result = subprocess.CompletedProcess(
                [], 1, "", "Traceback at /home/runner/work/private/path " + "x" * 5000
            )
            with mock.patch.object(host, "_run", return_value=result):
                with self.assertRaises(host.SharedRootPacstrapError) as caught:
                    host._create_boot_config(
                        iso=iso, iso_sha256="a" * 64, iso_uuid="01234567-89ab-cdef-0123-456789abcdef",
                        iso_mount=iso_mount, workspace=workspace, run_id="run-12345",
                        nonce="nonce-12345", plan_sha="b" * 64, key_sha="c" * 64,
                    )
            message = str(caught.exception)
            self.assertIn("without bounded structured diagnostics", message)
            self.assertNotIn("/home/runner", message)
            self.assertNotIn("Traceback", message)


    def test_deferred_root_requires_orderly_shutdown_and_offline_ext4_state(self):
        source = (TOOLS / "cachyos_windows_shared_root_pacstrap_host.py").read_text()
        guest = (TOOLS / "cachyos_windows_shared_root_pacstrap.py").read_text()
        self.assertIn("ordinary_umount + deferred_umount == 1", source)
        self.assertIn("All filesystems, swaps, loop devices, MD devices and DM devices detached.", source)
        self.assertIn('fs_state.get("Filesystem state") == "clean"', source)
        self.assertIn("qemu-img", source)
        self.assertIn("read_windows_file_hashes(overlay)", source)
        self.assertIn("_verify_installed_root(overlay, plan, run_id)", source)
        self.assertIn("defer_busy_owned_root=verified_native_root", guest)
        self.assertIn("verified_native_root = True", guest)
        self.assertIn("GASLUX_SHARED_COW_ROOT_UNMOUNT_DEFERRED_TO_POWEROFF=1", guest)
        self.assertNotIn("umount -R", source)
        self.assertNotIn('["umount", "-l"', guest)
        self.assertNotIn('["umount", "-f"', guest)



    def test_fifth_windows_serial_manifest_name_matches_evidence_producer(self):
        workflow = (TOOLS.parent.parent / ".github/workflows/"
                    "cachyos-windows10-shared-root-pacstrap.yml").read_text()
        producer = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        self.assertIn('manifest = fifth.with_suffix(".sha256")', workflow)
        self.assertIn('assert manifest.is_file() and not manifest.is_symlink()', workflow)
        self.assertIn('recorded == hashlib.sha256(fifth.read_bytes()).hexdigest()', workflow)
        self.assertIn('f"{args.profile}-{suffix}.sha256"', producer)
        self.assertIn('f"{digest}  {dest.name}', producer)
        self.assertNotIn('fifth.name + ".sha256"', workflow)


if __name__ == "__main__":
    unittest.main()
