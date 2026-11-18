"""Static fixture tests for the Proxmox Windows 10/11 lab readiness probe."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_lab_readiness.py"
spec = importlib.util.spec_from_file_location("gaslux_readiness", SOURCE)
assert spec and spec.loader
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class FakeProxmox:
    def __init__(self, snapshot_ok=True, bios="ovmf", tpm=True):
        self.requests = []
        self.snapshot_ok = snapshot_ok
        self.bios = bios
        self.tpm = tpm

    def locate_vm(self, vmid):
        self.requests.append(("GET", f"vm/{vmid}"))
        return "labnode"

    def assert_snapshot(self, node, vmid, snapshot):
        self.requests.append(("GET", f"vm/{vmid}/snapshot/{snapshot}"))
        if not self.snapshot_ok:
            raise lab.LabReadinessError("snapshot missing")

    def _request(self, method, path, *, step):
        self.requests.append((method, path))
        return {
            "bios": self.bios, "efidisk0": "local:vm-efivars",
            "scsi0": "local:vm-disk",
            "tpmstate0": "local:vm-tpm" if self.tpm else "",
        }

    def get_vm_status(self, node, vmid, *, step):
        self.requests.append(("GET", f"vm/{vmid}/status"))
        return {"status": "running"}


def settings():
    return SimpleNamespace(
        proxmox_verify_tls=True,
        proxmox_ca_bundle=None,
        repository_url="https://github.com/LMhdez/gaslux.git",
        allowed_proxmox_vmids=(501, 502),
        reset_snapshot="clean2",
        vms=(
            SimpleNamespace(os="Windows 10 UEFI", vmid=501, firmware="uefi",
                            automation_enabled=True),
            SimpleNamespace(os="Windows 11 UEFI", vmid=502, firmware="uefi",
                            automation_enabled=True),
            SimpleNamespace(os="Windows 10 BIOS", vmid=500, firmware="bios",
                            automation_enabled=False),
        ),
    )


class ProxmoxReadinessTests(unittest.TestCase):
    def test_read_only_valid_lab_configuration(self):
        client = FakeProxmox()
        result = lab.probe(settings(), client)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["vmProfiles"]), 2)
        self.assertFalse(result["fullInstallationExecuted"])
        self.assertFalse(result["dualBootVerified"])
        self.assertFalse(result["windowsRecoveryVerified"])
        self.assertTrue(all(method == "GET" for method, _ in client.requests))

    def test_missing_windows11_vm_rejected(self):
        values = settings()
        values.vms = values.vms[:1]
        with self.assertRaisesRegex(lab.LabReadinessError, "Windows 10 and Windows 11"):
            lab.probe(values, FakeProxmox())

    def test_non_authorized_vm_rejected(self):
        values = settings()
        values.allowed_proxmox_vmids = (501,)
        with self.assertRaisesRegex(lab.LabReadinessError, "allowlist"):
            lab.probe(values, FakeProxmox())

    def test_must_be_isolated_fork(self):
        values = settings()
        values.repository_url = "https://github.com/ekimiateam/libertix"
        with self.assertRaisesRegex(lab.LabReadinessError, "Gaslux repository"):
            lab.probe(values, FakeProxmox())

    def test_tls_required(self):
        values = settings()
        values.proxmox_verify_tls = False
        with self.assertRaisesRegex(lab.LabReadinessError, "TLS"):
            lab.probe(values, FakeProxmox())

    def test_missing_snapshot_rejected(self):
        with self.assertRaisesRegex(lab.LabReadinessError, "snapshot missing"):
            lab.probe(settings(), FakeProxmox(snapshot_ok=False))

    def test_uefi_is_required(self):
        with self.assertRaisesRegex(lab.LabReadinessError, "UEFI/OVMF"):
            lab.probe(settings(), FakeProxmox(bios="seabios"))

    def test_windows11_requires_tpm(self):
        with self.assertRaisesRegex(lab.LabReadinessError, "vTPM"):
            lab.probe(settings(), FakeProxmox(tpm=False))

    def test_firmware_mismatch_not_a_match(self):
        vm = SimpleNamespace(os="Windows 11 UEFI", vmid=502, firmware="bios",
                             automation_enabled=True)
        self.assertIsNone(lab.classify_vm(vm))

    def test_duplicate_windows10_profile_rejected(self):
        values = settings()
        values.vms = (*values.vms, SimpleNamespace(
            os="Windows 10 UEFI", vmid=503, firmware="uefi",
            automation_enabled=True))
        with self.assertRaisesRegex(lab.LabReadinessError, "ambiguous"):
            lab.probe(values, FakeProxmox())


if __name__ == "__main__":
    unittest.main()
