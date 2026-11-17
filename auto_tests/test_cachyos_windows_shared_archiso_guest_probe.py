"""No disk writes: match signed Windows GPT to Archiso lsblk guest facts."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/"tools"))
import cachyos_windows_shared_archiso_guest_probe as guest
from test_cachyos_windows_shared_archiso_handoff import fixture


def evidence():
    plan = fixture()
    entries = []
    for idx, row in enumerate(plan["partitions"]):
        fstype = ("vfat", None, "ntfs", "ntfs", "ext4")[idx]
        data = {
            "type": "part",
            "path": f"/dev/vdb{idx+1}", "name": f"vdb{idx+1}",
            "partuuid": row["uniqueGuid"],
            "parttype": row["typeGuid"],
            "start": row["firstLba"],
            "size": (row["lastLba"] - row["firstLba"] + 1)*512,
            "fstype": fstype,
            "uuid": plan["rootFsUuid"] if idx == 4 else None,
            "mountpoints": [None],
        }
        entries.append(data)
    observed={"blockdevices": [
        {
            "type": "disk", "serial": "GASLUXWINDOWSCOWLAB",
            "size": 128*1024**3, "log-sec": 512,
            "path": "/dev/vdb", "children": entries,
        },
        {
            "type": "disk", "serial": "ARCHISO_LIVE_SOURCE",
            "size": 6*1024**3, "log-sec": 512,
            "path": "/dev/vda",
        },
    ]}
    return plan, observed


class NativeArchisoGuestLayoutTests(unittest.TestCase):
    def test_single_owned_disk_with_live_source_satisfies_readonly_contract(self):
        plan, observed=evidence()
        status=guest.validate_lsblk_readonly(plan, observed)
        self.assertIs(status["observedFivePartitionLayoutMatchesSignedPlan"],True)
        for guard in ("pacstrapAuthorized", "storageWritesAuthorized",
                      "releaseEligible", "sameDiskDualBootVerified",
                      "guestDiskOriginAuthenticated",
                      "gptPrimaryAndBackupCrcsIndependentlyVerified"):
            self.assertIs(status[guard],False)

    def test_duplicate_serial_does_not_select_arbitrary_disk(self):
        plan, observed=evidence()
        observed["blockdevices"].append(copy.deepcopy(observed["blockdevices"][0]))
        with self.assertRaisesRegex(guest.SharedDiskHandoffRejected,"ambiguous"):
            guest.validate_lsblk_readonly(plan,observed)

    def test_foreign_or_aliased_guest_partition_device_rejected(self):
        for index in range(5):
            for key, value in (("path", "/dev/vdc1"),
                               ("path", "/dev/vdb"),
                               ("path", f"/dev/vdb{(index + 1) % 5 + 1}"),
                               ("name", "vdc1"),
                               ("name", f"vdb{(index + 1) % 5 + 1}"),
                               ("path", None), ("name", None)):
                plan, observed = evidence()
                observed["blockdevices"][0]["children"][index][key] = value
                with self.subTest(partition=index+1, key=key, value=value), \
                     self.assertRaisesRegex(
                         guest.SharedDiskHandoffRejected, "partition device path"):
                    guest.validate_lsblk_readonly(plan, observed)

    def test_disk_path_cannot_be_partition_or_foreign_storage(self):
        for bad in ("/dev/vdb1", "/dev/sda", "/dev/mapper/root",
                    "/dev/vdb/../sda", "/dev/vdb ", "/dev/vd"):
            plan, observed = evidence()
            observed["blockdevices"][0]["path"] = bad
            with self.subTest(path=bad), self.assertRaises(
                    guest.SharedDiskHandoffRejected):
                guest.validate_lsblk_readonly(plan, observed)

    def test_wrong_target_disk_capacity_or_sector_size_rejected(self):
        for key,value in (("size",64*1024**3),("log-sec",4096),
                          ("path",""),("serial","GASLUXLABTARGET")):
            plan,observed=evidence()
            observed["blockdevices"][0][key]=value
            with self.subTest(field=key),self.assertRaises(
                    guest.SharedDiskHandoffRejected):
                guest.validate_lsblk_readonly(plan,observed)

    def test_windows_esp_ntfs_recovery_and_linux_ext4_roles_fixed(self):
        for idx,bad_type in ((0,"ext4"),(1,"vfat"),(2,"ext4"),
                             (3,"ext4"),(4,"ntfs")):
            plan,observed=evidence()
            observed["blockdevices"][0]["children"][idx]["fstype"]=bad_type
            with self.subTest(index=idx),self.assertRaisesRegex(
                    guest.SharedDiskHandoffRejected,"filesystem"):
                guest.validate_lsblk_readonly(plan,observed)

    def test_refuse_wrong_gpt_guid_or_partition_type(self):
        for idx in range(5):
            for key,wrong in (("partuuid","00000000-0000-0000-0000-000000000000"),
                              ("parttype",guest.SERIAL)):
                plan,observed=evidence()
                observed["blockdevices"][0]["children"][idx][key]=wrong
                with self.subTest(index=idx,key=key),self.assertRaisesRegex(
                        guest.SharedDiskHandoffRejected,"GUID or GPT type"):
                    guest.validate_lsblk_readonly(plan,observed)

    def test_refuse_wrong_extent_size_or_missing_fifth(self):
        for idx in range(5):
            for key in ("start","size"):
                plan,observed=evidence()
                observed["blockdevices"][0]["children"][idx][key]+=512
                with self.subTest(index=idx,key=key),self.assertRaisesRegex(
                        guest.SharedDiskHandoffRejected,"sector offset/size"):
                    guest.validate_lsblk_readonly(plan,observed)
        plan,observed=evidence()
        observed["blockdevices"][0]["children"].pop()
        with self.assertRaisesRegex(guest.SharedDiskHandoffRejected,"foreign/missing"):
            guest.validate_lsblk_readonly(plan,observed)

    def test_mounted_windows_or_target_root_always_rejected(self):
        for idx in range(5):
            plan,observed=evidence()
            observed["blockdevices"][0]["children"][idx]["mountpoints"]=["/mnt/windows"]
            with self.subTest(index=idx),self.assertRaisesRegex(
                    guest.SharedDiskHandoffRejected,"mounted"):
                guest.validate_lsblk_readonly(plan,observed)

    def test_wrong_root_filesystem_uuid_or_unexpected_fields_rejected(self):
        plan,observed=evidence()
        observed["blockdevices"][0]["children"][4]["uuid"]="11111111-1111-4111-8111-111111111111"
        with self.assertRaisesRegex(guest.SharedDiskHandoffRejected,"UUID"):
            guest.validate_lsblk_readonly(plan,observed)
        plan,observed=evidence()
        observed["forgedAuthority"]=True
        with self.assertRaisesRegex(guest.SharedDiskHandoffRejected,"unexpected lsblk"):
            guest.validate_lsblk_readonly(plan,observed)

    def test_unsigned_or_secureboot_plan_never_passes_layout_check(self):
        for key,value in (("writeAuthority",True),
                          ("secureBootEnabled",True),
                          ("isoSha256","0"*64),
                          ("targetVirtioSerial","GASLUXLABTARGET")):
            plan,observed=evidence()
            plan[key]=value
            with self.subTest(field=key),self.assertRaises(
                    guest.SharedDiskHandoffRejected):
                guest.validate_lsblk_readonly(plan,observed)

    def test_guest_probe_rejects_local_non_archiso_before_any_disk_access(self):
        source=(HERE/"tools/cachyos_windows_shared_archiso_guest_probe.py").read_text()
        self.assertIn("require_live_archiso()",source)
        self.assertIn("efi_mode_readonly()",source)
        self.assertIn('"pacstrapAuthorized": False',source)
        self.assertIn('"storageWritesAuthorized": False',source)
        for forbidden in ("sgdisk --clear","pacstrap -K",
                          "mkfs.ext4","mkfs.vfat","guest.pwrite_device"):
            self.assertNotIn(forbidden,source)


if __name__=="__main__":
    unittest.main()
