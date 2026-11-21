"""Fail-closed unit/contract regressions for disposable Pop full reuse VM.

No QEMU, ISO, host devices, partition writers or Windows are invoked by tests.
"""
import json
import os
import struct
from unittest.mock import patch
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
from gaslux_popos_reuse_snapshot_gate import (  # noqa: E402
    Refusal, regular, new_file, classify_owned_write, hosted, system_ovmf_template,
    get_plan, SIZE, ESP, ROOT, DISK_GUID, ESP_GUID, ROOT_GUID,
    SERIAL,
)

import gaslux_popos_reuse_snapshot_gate as snapshot
from gaslux_popos_reuse_guest_bio_monitor import classify_bio_operation  # noqa: E402

INSTALL = TOOLS / "gaslux_popos_reuse_full_install_guest.sh"
BOOT = TOOLS / "gaslux_popos_reuse_firstboot_guest.sh"
RUNNER = TOOLS / "gaslux_popos_reuse_full_firstboot_vm.sh"
GATE = TOOLS / "gaslux_popos_reuse_snapshot_gate.py"
MONITOR = TOOLS / "gaslux_popos_reuse_guest_bio_monitor.py"
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/popos-full-reuse-linux-only.yml"


class FullReuseContractTests(unittest.TestCase):
    def test_full_distinst_uses_exact_two_reuse_targets_never_test_or_format(self):
        s = INSTALL.read_text()
        invocation = s.split("1500s /usr/bin/distinst", 1)[1].split(
            '> "$log" 2>&1', 1)[0]
        self.assertIn('--block "$disk"', invocation)
        self.assertIn('--no-efi-vars', invocation)
        self.assertIn('--use "$disk:1:reuse:mount=/boot/efi"', invocation)
        self.assertIn('--use "$disk:2:reuse:mount=/"', invocation)
        for bad in ("--test", "--new-table", "--new ", "--delete",
                    "--modify-boot", ":ext4:mount=/", ":fat32:mount="):
            self.assertNotIn(bad, invocation)
        self.assertIn("owned root is not preformatted ext4", s)
        self.assertIn("foreign disk GPT GUID", s)
        self.assertIn("foreign ESP PARTUUID", s)
        self.assertIn("foreign root PARTUUID", s)
        self.assertIn("GASLUX_POP_FULL_BIO_JSON=", s)

    def test_full_reuse_uses_historical_authentic_signed_shell_handoff(self):
        s = RUNNER.read_text()
        for marker in ("sha256sum -c", "lab.sha256", "agent.sha256",
                       "grub-mkstandalone", "GASLUXLAB", "ovmf-install.fd",
                       "ovmf-firstboot.fd", "native_install_serial",
                       "gaslux_popos_reuse_install_serial.py",
                       "gaslux_popos_reuse_snapshot_gate.py prepare",
                       "GASLUX_POP_FULL_VM_EVIDENCE_DIR"):
            if marker == "native_install_serial":
                continue
            self.assertIn(marker, s)
        self.assertIn("readonly=on,file=$work/lab-efi.raw", s)
        self.assertIn("readonly=on,format=raw,file=$iso", s)
        self.assertIn("format=qcow2,file=$target", s)
        self.assertIn('target="$work/pop-owned-child.qcow2"', s)
        self.assertIn('base="$work/pop-prepared.raw"', s)
        self.assertNotIn('format=raw,file=$target', s)
        self.assertNotIn("gaslux_popos_native_full_install_guest.sh", s)

    def test_post_install_and_firstboot_both_audited_independently(self):
        s = RUNNER.read_text()
        self.assertIn("--phase install --bio-transcript", s)
        self.assertIn("--phase firstboot", s)
        self.assertIn("install.qemu.trace", s)
        self.assertIn("firstboot.qemu.trace", s)
        self.assertIn("-net none", s)
        self.assertIn("virtio_blk_handle_write", s)
        self.assertIn("pflash_data_write", s)
        second = s.split("# The SECOND QEMU has NO lab EFI disk and NO live ISO.", 1)[1]
        self.assertNotIn("drive=labefi", second)
        self.assertNotIn("drive=verifiediso", second)
        self.assertIn("drive=popinstalled", second)

    def test_offline_native_efi_probe_refuses_missing_or_invalid_boot_files(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            raw = new_file(work / "installed-view.raw", SIZE)
            with raw.open("r+b") as f:
                f.seek(ESP[0] * 512)
                boot = bytearray(512)
                boot[82:90] = b"FAT32   "
                boot[510:512] = b"\x55\xaa"
                struct.pack_into("<H", boot, 11, 512)
                boot[13] = 8
                struct.pack_into("<H", boot, 14, 32)
                boot[16] = 2
                struct.pack_into("<I", boot, 28, 0)
                struct.pack_into("<I", boot, 32, 2097144)
                struct.pack_into("<I", boot, 36, 2048)
                struct.pack_into("<I", boot, 44, 2)
                f.write(boot)

            def fake_command(*args, **kwargs):
                if args[0] == "mdir":
                    return "pop-current.conf" if args[-1] == "::/loader/entries" else "EFI files"
                if args[0] == "mcopy":
                    data = bytearray(512)
                    data[:2] = b"MZ"
                    struct.pack_into("<I", data, 0x3c, 0x80)
                    data[0x80:0x84] = b"PE\x00\x00"
                    struct.pack_into("<H", data, 0x84, 0x8664)
                    struct.pack_into("<H", data, 0x80+24+68, 10)
                    Path(args[-1]).write_bytes(data)
                    return ""
                raise AssertionError("unexpected tool")

            with patch.object(snapshot, "command", side_effect=fake_command):
                proof = snapshot.probe_installed_esp_boot(raw, work)
                self.assertEqual(proof["status"], "PASS_OFFLINE_EFI_ARTIFACTS_ONLY")
                self.assertFalse(proof["firmwareDiscoveryProven"])
                self.assertFalse(proof["nativeFirstBootProven"])
                self.assertFalse((work / "probe-fallback.efi").exists())

            with raw.open("r+b") as f:
                f.seek(ESP[0] * 512 + 82)
                f.write(b"NOTFAT32")
            with patch.object(snapshot, "command", side_effect=fake_command):
                with self.assertRaises(Refusal):
                    snapshot.probe_installed_esp_boot(raw, work)

            with raw.open("r+b") as f:
                f.seek(ESP[0] * 512 + 82)
                f.write(b"FAT32   ")
            def no_entry(*args, **kwargs):
                if args[0] == "mdir":
                    return "no entries"
                raise AssertionError("unexpected tool")
            with patch.object(snapshot, "command", side_effect=no_entry):
                with self.assertRaises(Refusal):
                    snapshot.probe_installed_esp_boot(raw, work)

    def test_bad_fat32_auto_clusters_are_refused_before_install_or_boot(self):
        gate = GATE.read_text()
        self.assertIn('"-s", "8"', gate)
        self.assertIn("esp_fat32 = fat32_boot_geometry(base)", gate)
        self.assertIn("fat32 = fat32_boot_geometry(raw)", gate)
        with tempfile.TemporaryDirectory() as folder:
            raw = new_file(Path(folder) / "synthetic-owned.raw", SIZE)
            boot = bytearray(512)
            boot[82:90] = b"FAT32   "
            boot[510:512] = b"\x55\xaa"
            struct.pack_into("<H", boot, 11, 512)
            boot[13] = 32
            struct.pack_into("<H", boot, 14, 32)
            boot[16] = 2
            struct.pack_into("<I", boot, 32, 2097144)
            struct.pack_into("<I", boot, 36, 512)
            struct.pack_into("<I", boot, 44, 2)

            def write_bpb():
                with raw.open("r+b") as f:
                    f.seek(ESP[0] * 512)
                    f.write(boot)

            write_bpb()
            with self.assertRaisesRegex(Refusal, "ESP FAT32 BPB geometry"):
                snapshot.fat32_boot_geometry(raw)
            # Actual 4-way OVMF diagnostic: 65502 clusters cannot mount;
            # -s 8 with 261627 clusters loads an EFI test payload.
            boot[13] = 8
            struct.pack_into("<I", boot, 36, 2048)
            write_bpb()
            info = snapshot.fat32_boot_geometry(raw)
            self.assertEqual(info["clusterCount"], 261627)
            self.assertEqual(info["rootDataStartLba"], 6176)
            self.assertFalse(info["firmwareExecutableProven"])
            for offset, bad, message in (
                (13, b"\x20", "BPB geometry"),
                (16, b"\x03", "BPB geometry"),
                (28, (4096).to_bytes(4, "little"), "BPB geometry"),
                (32, (2097153).to_bytes(4, "little"), "BPB geometry"),
                (36, (1).to_bytes(4, "little"), "cluster count"),
            ):
                original = boot[offset:offset + len(bad)]
                boot[offset:offset + len(bad)] = bad
                write_bpb()
                with self.subTest(offset=offset):
                    with self.assertRaisesRegex(Refusal, message):
                        snapshot.fat32_boot_geometry(raw)
                boot[offset:offset + len(bad)] = original

    def test_native_efi_probe_and_firmware_read_trace_are_required(self):
        runner = RUNNER.read_text()
        gate = GATE.read_text()
        self.assertIn("virtio_blk_handle_read", runner)
        self.assertIn("install.esp-boot.json", runner)
        self.assertIn("probe_installed_esp_boot(exported, work)", gate)
        self.assertIn("firmwareDiscoveryProven", gate)
        self.assertIn("nativeFirstBootProven", gate)
        self.assertIn("REFUSE_NATIVE_EFI_BOOT_UNPROVEN", gate)

    def test_native_firstboot_is_pop_with_installed_root_partuuid(self):
        s = BOOT.read_text()
        self.assertIn("GASLUX_POP_NATIVE_FIRSTBOOT_OS_ID=pop", s)
        self.assertIn("GASLUX_POP_NATIVE_FIRSTBOOT_VERIFIED=1", s)
        self.assertIn("EFI/systemd/systemd-bootx64.efi", s)
        self.assertIn(ROOT_GUID, s)
        self.assertIn("systemd-detect-virt", s)

    def test_native_firstboot_requests_controlled_shutdown_not_host_kill(self):
        guest = BOOT.read_text()
        runner = RUNNER.read_text()
        self.assertIn("GASLUX_POP_NATIVE_FIRSTBOOT_CONTROLLED_SHUTDOWN_REQUESTED=1", guest)
        self.assertIn("systemctl --no-block poweroff -i", guest)
        self.assertIn("Installed Pop did not shut down", runner)
        self.assertIn('[[ "$qemu_rc" == 0 ]]', runner)
        self.assertIn("GASLUX_POP_NATIVE_FIRSTBOOT_CONTROLLED_SHUTDOWN_REQUESTED=1", runner)

    def test_guest_streaming_bio_has_no_false_completion_claim(self):
        s = MONITOR.read_text()
        self.assertIn("block_bio_queue", s)
        self.assertIn("foreignWritableEvents", s)
        self.assertIn('bioCompletionVerified":False', s)
        self.assertIn("dropped events", s)
        self.assertIn("writeCoverageSha256", s)
        self.assertIn("discard/write-zeroes", s)

    def test_foreign_iso_reads_not_misclassified_as_guest_writes(self):
        for flags in ("R", "RA", "RS"):
            with self.subTest(flags=flags):
                self.assertEqual(classify_bio_operation(flags, 2048, 8), "read")
        self.assertEqual(classify_bio_operation("W", 2048, 8), "write")
        self.assertEqual(classify_bio_operation("FWS", 0, 0), "flush")
        source = MONITOR.read_text()
        self.assertLess(source.index('if operation=="read":'),
                        source.index('if (m,n)!=(major,minor):\n                    stats["foreignWritableEvents"]'))
        self.assertIn('fail("write/flush BIO on unowned guest block device")', source)

    def test_discard_or_malformed_bio_is_never_a_legitimate_read(self):
        for flags, sector, count in (
            ("D", 2048, 8), ("Z", 2048, 8), ("RZ", 2048, 8),
            ("WD", 2048, 8), ("", 2048, 8), ("R", 0, 0),
            ("W", 0, 0), ("FWS", 1, 0), ("RW", 2048, 8),
            ("F", 0, 0), ("S", 2048, 8), ("R", -1, 1),
        ):
            with self.subTest(flags=flags,sector=sector,count=count):
                with self.assertRaises(ValueError):
                    classify_bio_operation(flags,sector,count)

    def test_writes_restricted_to_entirely_owned_esp_and_root(self):
        for lo, size in (ESP, ROOT):
            for start, length in ((lo, 1), (lo+size-1, 1), (lo, size)):
                self.assertIn(classify_owned_write(start, length), ("esp", "root"))
        for start, count in ((0, 1), (1, 33), (34, 1), (ESP[0]-1, 2),
                             (ESP[0]+ESP[1]-1, 2), (ROOT[0]-1, 2),
                             (ROOT[0]+ROOT[1]-1, 2), (SIZE//512-33, 33),
                             (-1, 1), (0, -1), (ROOT[0], 0),
                             (SIZE//512, 1), (ROOT[0], "8")):
            with self.subTest(start=start, count=count), self.assertRaises(Refusal):
                classify_owned_write(start, count)

    def test_symlink_and_hardlink_and_non_regular_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            d = Path(folder)
            p = new_file(d/"owned.raw", 512)
            self.assertEqual(regular(p, length=512), p)
            with self.assertRaises(Refusal):
                regular(p, length=256)
            os.symlink(p, d/"spoof.raw")
            with self.assertRaises(Refusal):
                regular(d/"spoof.raw")
            os.link(p, d/"second-link.raw")
            with self.assertRaises(Refusal):
                regular(p)
            with self.assertRaises(Refusal):
                regular(d)
            with self.assertRaises(FileExistsError):
                new_file(p, 512)

    def test_root_owned_ovmf_template_is_separate_from_user_file_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            d = Path(folder)
            fake = new_file(d/"OVMF_VARS_4M.fd", 4*1024*1024)
            with self.assertRaises(Refusal):
                system_ovmf_template(fake)
            with self.assertRaises(Refusal):
                system_ovmf_template(d/"OVMF_VARS_4M.fd.link")
            os.symlink(fake, d/"OVMF_VARS_4M.fd.link")
            with self.assertRaises(Refusal):
                system_ovmf_template(d/"OVMF_VARS_4M.fd.link")
        source = GATE.read_text()
        self.assertIn('st.st_uid == 0', source)
        self.assertIn('st.st_mode & 0o022 == 0', source)
        self.assertIn('st.st_nlink == 1', source)
        self.assertIn('template = system_ovmf_template(template)', source)

    def test_run_is_disallowed_without_hosted_explicit_consent(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(Refusal):
                hosted(Path(folder))

    def test_mutated_plan_never_authorizes_windows(self):
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder)
            plan={
                "schemaVersion":1,"scenario":"pop-full-reuse-only",
                "transactionId":"synthetic-only","serial":SERIAL,
                "diskGuid":DISK_GUID,"espPartuuid":ESP_GUID,
                "rootPartuuid":ROOT_GUID,"diskSizeBytes":SIZE,
                "logicalSectorBytes":512,"firmware":"UEFI",
                "partitionTable":"GPT","backingSha256":"f"*64,
                "checkpointProven":True,
                "diskWritesAuthorizedForWindows":False,
                "productionInstallationAuthorized":False,
            }
            path=d/"pop-reuse-transaction.json"
            for name,value in (
                ("diskWritesAuthorizedForWindows", True),
                ("productionInstallationAuthorized", True),
                ("diskGuid", "foreign"),
                ("serial", "FOREIGN"),
                ("checkpointProven", False),
                ("backingSha256", "unknown")
            ):
                bad=plan.copy(); bad[name]=value
                path.write_text(json.dumps(bad))
                with self.subTest(name=name), self.assertRaises(Refusal):
                    get_plan(d)
            path.write_text(json.dumps(plan))
            self.assertEqual(get_plan(d)["diskGuid"], DISK_GUID)

    def test_workflow_is_only_linux_hosted_and_single_experiment(self):
        s=WORKFLOW.read_text()
        self.assertIn("runs-on: ubuntu-24.04", s)
        self.assertIn("cancel-in-progress: false", s)
        self.assertIn("  actions: read", s)
        self.assertIn("GASLUX_POP_ACTIONS_READ_TOKEN:", s)
        self.assertIn('"Authorization":"Bearer "+os.environ["GASLUX_POP_ACTIONS_READ_TOKEN"]', s)
        self.assertNotIn("  actions: write", s)
        self.assertIn("GASLUX_POP_FULL_REUSE_CONSENT:", s)
        self.assertNotIn("windows-latest", s)
        self.assertNotIn("pull_request:", s)
        self.assertNotIn("merge", s)

    def test_signed_iso_and_distinst_hashes_do_not_change(self):
        s=WORKFLOW.read_text()
        self.assertIn("a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c", s)
        self.assertIn("8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5", s)
        self.assertIn("get_official_pop_iso", s)

    def test_host_audit_keeps_operation_proof_unproven(self):
        s=GATE.read_text()
        self.assertIn('"fullOperationObservationProven": False', s)
        self.assertIn('"productionInstallationAuthorized": False', s)
        self.assertIn('"guestBioCompletionVerified": False', s)
        self.assertIn('"transientGptWritesObserved": 0', s)
        self.assertIn('"ovmfTransientWritesProvenAbsent": False', s)
        self.assertIn("qemu-img", s)
        self.assertIn("pop-owned-child.qcow2", s)
        self.assertIn("injected-failure.qcow2", s)


if __name__ == "__main__":
    unittest.main()
