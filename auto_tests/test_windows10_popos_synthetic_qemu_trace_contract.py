"""Adversarial source-of-truth QEMU write monitoring: no real disks or writer."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / "tools"))
from windows_x64_installed_gpt_ro_audit import DiskAuditError
from windows10_popos_synthetic_qemu_trace_contract import (
    classify_trace, synthetic_plan, SERIAL, DISK_SIZE,
    SMOKE_OFFSET, SMOKE_LENGTH,
)

DISK = "a6784e03-11a6-4544-b61c-87b66db8e117"
ESP = "ae228a25-0ecd-4f62-83b4-88dd48b88edd"
ROOT = "f81482ad-e0e1-491a-8ea5-9c246f82ded8"
SHA = "a" * 64
NV = "b" * 64
TRACE = (
    "12345@42.01:qemu virtio_blk_handle_write vdev 0x10 "
    "req 0x20 sector 196608 nsectors 8\n"
)


class QemuSyntheticTraceTest(unittest.TestCase):
    def setUp(self):
        self.plan = synthetic_plan(
            DISK, ESP, ROOT, SHA, "gaslux-pop-synthetic-write-child.qcow2")
        self.kwargs = {
            "reported_serial": SERIAL, "base_sha_after": SHA,
            "nvram_sha_before": NV, "nvram_sha_after": NV,
            "child_discarded": True, "guest_probe_ok": True,
            "process_name": "python3", "installer_elf_sha256": None,
        }

    def observe(self, trace=TRACE, plan=None, **kwargs):
        opts = {**self.kwargs, **kwargs}
        return classify_trace(trace, self.plan if plan is None else plan, **opts)

    def test_known_independent_qemu_trace_is_inert(self):
        proof = self.observe()
        self.assertTrue(proof["guestWriteRequestsObserved"])
        self.assertEqual(proof["events"][0]["offsetBytes"], SMOKE_OFFSET)
        self.assertEqual(proof["events"][0]["lengthBytes"], SMOKE_LENGTH)
        for key in ("distinstExecutionAuthorized",
                    "productionInstallationAuthorized",
                    "diskWritesAuthorizedForWindows",
                    "windowsEspWritesAuthorized",
                    "installerWritesObserved",
                    "nvramWriteSetAttested",
                    "windowsWriteSetMatchProven"):
            self.assertFalse(proof[key])

    def test_no_provenance_no_write_trace_and_unknown_io_refused(self):
        for trace in ("", "qemu something-other-than-write",
                      "blk_co_pwritev blk 0x1 bs 0x2 offset 100663296 bytes 512 flags 0x0",
                      "virtio_blk_handle_write vdev 0x1 sector bad nsectors 1",
                      "virtio_blk_handle_discard disk 0x1 sector 196608 nsectors 1",
                      "virtio_blk_handle_write_zeroes sector 196608 nsectors 1",
                      "virtio_blk_handle_write vdev 0x1 sector 196608 nsectors 0"):
            with self.subTest(trace=trace), self.assertRaises(DiskAuditError):
                self.observe(trace)

    def test_foreign_process_elf_or_vm_identity_refused(self):
        for change in (
            {"process_name": "distinst"},
            {"process_name": "/usr/bin/distinst"},
            {"installer_elf_sha256": "f" * 64},
            {"reported_serial": "OTHERDISK"},
            {"guest_probe_ok": False},
            {"trace_untruncated": False},
        ):
            with self.subTest(change=change), self.assertRaises(DiskAuditError):
                self.observe(**change)

    def test_explicit_gpt_primary_and_backup_and_esp_traces_denied(self):
        cases = [0, 1, 2, 33, (DISK_SIZE // 512) - 33,
                 (DISK_SIZE // 512) - 1, 2048, 262144]
        for sector in cases:
            text = f"virtio_blk_handle_write vdev 0x1 sector {sector} nsectors 1\n"
            with self.subTest(sector=sector), self.assertRaises(DiskAuditError):
                self.observe(text)

    def test_incomplete_write_set_unknown_operation_and_wrong_geometry(self):
        for change in (
            ("expectedOperation", None),
            ("expectedOperation", {"operation": "format"}),
            ("windowsDiskAttached", True),
            ("diskWritesAuthorizedForWindows", True),
            ("windowsEspWritesAuthorized", True),
            ("distinstExecutionAuthorized", True),
            ("sizeBytes", 1),
            ("logicalSectorBytes", 4096),
            ("serial", "OTHER"),
            ("diskGuid", "00000000-0000-0000-0000-000000000000"),
            ("esp", {"partitionIndex": 1, "partuuid": ROOT,
                     "offsetBytes": 1024**2, "lengthBytes": 64 * 1024**2}),
            ("root", {"partitionIndex": 2, "partuuid": ESP,
                      "offsetBytes": 128 * 1024**2, "lengthBytes": 2 * 1024**3}),
        ):
            plan = copy.deepcopy(self.plan)
            plan[change[0]] = change[1]
            with self.subTest(change=change), self.assertRaises(DiskAuditError):
                self.observe(plan=plan)

    def test_wrong_extent_and_partial_install_declined(self):
        cases = [
            "virtio_blk_handle_write vdev 0x10 sector 196608 nsectors 1\n",
            "virtio_blk_handle_write vdev 0x10 sector 196608 nsectors 2\n",
            "virtio_blk_handle_write vdev 0x10 sector 8193 nsectors 1\n",
            TRACE + "virtio_blk_handle_write vdev 0x10 sector 8193 nsectors 1\n",
            "virtio_blk_handle_write vdev 0x10 sector 196608 nsectors 100000000\n",
        ]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(DiskAuditError):
                self.observe(data)

    def test_forged_discard_changed_backing_and_unbounded_trace_rejected(self):
        for kw in (
            {"child_discarded": False}, {"base_sha_after": "0" * 64},
            {"base_sha_after": ""}, {"nvram_sha_before": "not a hash"},
            {"nvram_sha_after": ""},
        ):
            with self.subTest(kw=kw), self.assertRaises(DiskAuditError):
                self.observe(**kw)
        with self.assertRaises(DiskAuditError):
            self.observe(TRACE * 1001)

    def test_nvram_change_requires_independent_pflash_trace(self):
        with self.assertRaises(DiskAuditError):
            self.observe(nvram_sha_after="c" * 64)
        trace = (TRACE +
                 "12345@42.01:pflash_data_write system.flash1 "
                 "data offset:0x1000 size:8 value:0x00000001\n")
        result = self.observe(trace=trace, nvram_sha_after="c" * 64)
        self.assertTrue(result["ovmfVarsChanged"])
        self.assertTrue(result["ovmfPflashWriteRequestsObserved"])
        self.assertEqual(result["ovmfPflashWriteEventCount"], 1)
        self.assertFalse(result["nvramWriteSetAttested"])

    def test_pflash_command_without_data_or_erase_does_not_attest_nvar_mutation(self):
        trace = (TRACE +
                 "12345@42.01:pflash_write system.flash1: single byte program (0)\n")
        with self.assertRaises(DiskAuditError):
            self.observe(trace=trace, nvram_sha_after="c" * 64)

    def test_pflash_code_device_mutation_is_refused(self):
        trace = (TRACE +
                 "12345@42.01:pflash_data_write system.flash0: "
                 "data offset:0x1000 size:8 value:0x00000001\n")
        with self.assertRaises(DiskAuditError):
            self.observe(trace=trace, nvram_sha_after="c" * 64)

    def test_no_windows_six_gpt_claim_from_independent_synthetic(self):
        result = self.observe()
        self.assertFalse(result["windowsWriteSetMatchProven"])
        self.assertFalse(result["installerProcessObserved"])
        self.assertFalse(result["rollbackAfterNativeInstallVerified"])


if __name__ == "__main__":
    unittest.main()
