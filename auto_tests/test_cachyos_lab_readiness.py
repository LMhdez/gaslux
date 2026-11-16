"""Read-only Proxmox Windows UEFI readiness and VM disk isolation fixtures.

Fake Proxmox responses cannot prove a real VM, Windows boot or snapshot.
"""
from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1] / "auto_tests/tools/cachyos_lab_readiness.py"
spec = importlib.util.spec_from_file_location("gaslux_readiness", SOURCE)
assert spec and spec.loader
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class FakeProxmox:
    def __init__(
        self, snapshot_ok=True, bios="ovmf", tpm=True, *,
        config_patch=None, current_patch=None, snapshot_patch=None,
    ):
        self.requests = []
        self.snapshot_ok = snapshot_ok
        self.bios = bios
        self.tpm = tpm
        self.config_patch = config_patch
        self.current_patch = current_patch
        self.snapshot_patch = snapshot_patch

    def locate_vm(self, vmid):
        self.requests.append(("GET", f"vm/{vmid}"))
        return "labnode"

    def assert_snapshot(self, node, vmid, snapshot):
        self.requests.append(("GET", f"vm/{vmid}/snapshot/{snapshot}"))
        if not self.snapshot_ok:
            raise lab.LabReadinessError("snapshot missing")

    def _request(self, method, path, *, step):
        self.requests.append((method, path))
        result = re.search(r"/qemu/([0-9]+)/", path)
        assert result, path
        vmid = int(result.group(1))
        config = {
            "bios": self.bios,
            "efidisk0": f"local-lvm:vm-{vmid}-disk-1,efitype=4m,size=4M",
            "scsi0": f"local-lvm:vm-{vmid}-disk-0,cache=writeback",
        }
        if self.tpm:
            config["tpmstate0"] = f"local-lvm:vm-{vmid}-disk-2,size=4M,version=v2.0"
        patch = self.config_patch
        if "/snapshot/" in path:
            patch = self.snapshot_patch or patch
        elif "current=1" in path:
            patch = self.current_patch or patch
        if patch:
            config = patch(vmid, config)
        return config

    def get_vm_status(self, node, vmid, *, step):
        self.requests.append(("GET", f"vm/{vmid}/status"))
        return {"status": "running", "qmpstatus": "running"}


def settings():
    return SimpleNamespace(
        proxmox_verify_tls=True,
        proxmox_ca_bundle=None,
        repository_url="https://github.com/LMhdez/gaslux.git",
        allowed_proxmox_vmids=(501, 502),
        reset_snapshot="clean2",
        vms=(
            SimpleNamespace(
                os="Windows 10 UEFI", vmid=501, firmware="uefi", automation_enabled=True
            ),
            SimpleNamespace(
                os="Windows 11 UEFI", vmid=502, firmware="uefi", automation_enabled=True
            ),
            SimpleNamespace(
                os="Windows 10 BIOS", vmid=500, firmware="bios", automation_enabled=False
            ),
        ),
    )


def patch_setting(key, value, *, only_vmid=None):
    def patch(vmid, config):
        if only_vmid is None or vmid == only_vmid:
            config[key] = value
        return config

    return patch


class ProxmoxReadinessTests(unittest.TestCase):
    def assert_refused(self, patch=None, *, reason=None, current=None, snapshot=None):
        client = FakeProxmox(
            config_patch=patch, current_patch=current, snapshot_patch=snapshot
        )
        with self.assertRaises(lab.LabReadinessError) as raised:
            lab.probe(settings(), client)
        if reason:
            self.assertIn(reason, str(raised.exception))
        self.assertTrue(all(method == "GET" for method, _ in client.requests))

    def test_read_only_valid_lab_configuration(self):
        client = FakeProxmox()
        result = lab.probe(settings(), client)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["vmProfiles"]), 2)
        self.assertTrue(result["noHostDiskPassthrough"])
        self.assertTrue(result["snapshotDiskOwnershipVerified"])
        self.assertEqual(result["vmProfiles"][0]["exclusiveVirtualDiskCount"], 3)
        self.assertFalse(result["fullInstallationExecuted"])
        self.assertFalse(result["dualBootVerified"])
        self.assertFalse(result["windowsRecoveryVerified"])
        self.assertFalse(result["installerStable"])
        self.assertTrue(all(method == "GET" for method, _ in client.requests))
        self.assertEqual(
            len([path for _, path in client.requests if "/snapshot/clean2/config" in path]), 2
        )

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
        vm = SimpleNamespace(
            os="Windows 11 UEFI", vmid=502, firmware="bios", automation_enabled=True
        )
        self.assertIsNone(lab.classify_vm(vm))

    def test_duplicate_windows10_profile_rejected(self):
        values = settings()
        values.vms = (
            *values.vms,
            SimpleNamespace(
                os="Windows 10 UEFI", vmid=503, firmware="uefi", automation_enabled=True
            ),
        )
        with self.assertRaisesRegex(lab.LabReadinessError, "ambiguous"):
            lab.probe(values, FakeProxmox())

    def test_proxmox_file_volume_is_allowed(self):
        client = FakeProxmox(
            config_patch=lambda vmid, cfg: {
                **cfg,
                "scsi0": f"local:{vmid}/vm-{vmid}-disk-0.qcow2,discard=on",
                "ide2": "local:iso/Windows-Install.iso,media=cdrom",
            },
        )
        output = lab.probe(settings(), client)
        self.assertTrue(output["snapshotDiskOwnershipVerified"])

    def test_host_block_device_pass_through_refused(self):
        self.assert_refused(
            patch_setting("scsi0", "/dev/disk/by-id/ata-REAL_DISK"),
            reason="not an exclusive",
        )

    def test_alternate_file_host_block_device_refused(self):
        self.assert_refused(
            patch_setting("scsi0", "file=/dev/disk/by-id/ata-REAL_DISK"),
            reason="not an exclusive",
        )

    def test_attached_disk_belongs_to_different_vm(self):
        self.assert_refused(
            patch_setting("scsi0", "local-lvm:vm-999-disk-0"),
            reason="not an exclusive",
        )

    def test_mismatched_directory_owner_refused(self):
        self.assert_refused(
            patch_setting("scsi0", "local:999/vm-501-disk-0.qcow2", only_vmid=501),
            reason="not an exclusive",
        )

    def test_non_snapshotted_disk_refused(self):
        self.assert_refused(
            patch_setting("scsi0", "local-lvm:vm-501-disk-0,snapshot=0", only_vmid=501),
            reason="non-snapshot",
        )

    def test_shared_disk_flag_refused(self):
        self.assert_refused(
            patch_setting("scsi0", "local-lvm:vm-501-disk-0,shared=1", only_vmid=501),
            reason="shared",
        )

    def test_raw_host_cdrom_passthrough_refused(self):
        self.assert_refused(
            patch_setting("ide2", "/dev/sr0,media=cdrom"),
            reason="CD-ROM",
        )

    def test_usb_passthrough_refused(self):
        self.assert_refused(patch_setting("usb0", "host=1-1"), reason="passthrough")

    def test_host_pci_controller_passthrough_refused(self):
        self.assert_refused(patch_setting("hostpci0", "host=01:00.0"), reason="passthrough")

    def test_custom_qemu_args_refused(self):
        self.assert_refused(
            patch_setting("args", "-drive file=/dev/sda"), reason="passthrough"
        )

    def test_hookscript_refused(self):
        self.assert_refused(
            patch_setting("hookscript", "local:snippets/guest.sh"),
            reason="passthrough",
        )

    def test_unused_disk_refused(self):
        self.assert_refused(
            patch_setting("unused0", "local-lvm:vm-501-disk-3"),
            reason="passthrough",
        )

    def test_virtiofs_host_share_refused(self):
        self.assert_refused(patch_setting("virtiofs0", "dirid=hostdata"), reason="passthrough")

    def test_host_serial_passthrough_refused(self):
        self.assert_refused(patch_setting("serial0", "/dev/ttyS0"), reason="passthrough")

    def test_duplicate_writable_volume_in_same_vm_refused(self):
        self.assert_refused(
            lambda vmid, cfg: {**cfg, "sata1": cfg["scsi0"]},
            reason="share a backing",
        )

    def test_non_vm_owned_efi_vars_refused(self):
        self.assert_refused(patch_setting("efidisk0", "local-lvm:vm-999-disk-1"),
                            reason="not an exclusive")

    def test_wrong_snapshot_efi_volume_refused(self):
        self.assert_refused(
            snapshot=lambda vmid, cfg: {
                **cfg, "efidisk0": f"local-lvm:vm-{vmid}-disk-9"
            },
            reason="snapshot volume bindings",
        )

    def test_wrong_snapshot_partition_disk_refused(self):
        self.assert_refused(
            snapshot=lambda vmid, cfg: {
                **cfg, "scsi0": f"local-lvm:vm-{vmid}-disk-8"
            },
            reason="snapshot volume bindings",
        )

    def test_wrong_running_disk_mapping_refused(self):
        self.assert_refused(
            current=lambda vmid, cfg: {
                **cfg, "scsi0": f"local-lvm:vm-{vmid}-disk-8"
            },
            reason="current volume bindings",
        )

    def test_wrong_running_firmware_refused(self):
        self.assert_refused(
            current=patch_setting("bios", "seabios"),
            reason="current firmware",
        )

    def test_host_disk_added_only_to_snapshot_refused(self):
        self.assert_refused(
            snapshot=patch_setting("hostpci0", "host=01:00.0"),
            reason="passthrough",
        )

    def test_windows11_tpm_volume_not_owned_by_vm_refused(self):
        self.assert_refused(
            patch_setting("tpmstate0", "local-lvm:vm-501-disk-2", only_vmid=502),
            reason="not an exclusive",
        )

    def test_no_writable_installation_disk_refused(self):
        self.assert_refused(
            lambda vmid, cfg: {
                **cfg, "scsi0": "none,media=cdrom"
            },
            reason="installation disk",
        )


if __name__ == "__main__":
    unittest.main()
