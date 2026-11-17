"""Signed shared-Windows-disk Archiso handoff tests; no disk mutations."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "tools/cachyos_windows_shared_archiso_handoff.py"
SPEC = importlib.util.spec_from_file_location("signed_shared_archiso", SCRIPT)
assert SPEC and SPEC.loader
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

ROOT = 170801152
SECTORS = guard.ROOT_BYTES // guard.SECTOR_BYTES
GUIDS = [
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
]
WINDOWS = [(2048, 206847), (206848, 239615),
           (239616, 170000000), (170000001, 170800000)]
RUN_ID = "gaslux-shared-lab-20261117"
UUID = "01234567-89ab-cdef-0123-456789abcdef"


def fixture():
    ranges = WINDOWS + [(ROOT, ROOT+SECTORS-1)]
    rows = [{
        "index": i + 1,
        "role": guard.ROLES[i],
        "typeGuid": guard.WIN_TYPES[i] if i < 4 else guard.LINUX_TYPE,
        "uniqueGuid": GUIDS[i],
        "firstLba": start,
        "lastLba": end,
    } for i,(start,end) in enumerate(ranges)]
    return {
        "schemaVersion": 1, "backend": "archiso-cachyos-windows-cow-lab",
        "distribution": "cachyos", "labOnly": True, "runId": RUN_ID,
        "bootNonce": "1" * 32, "firmware": "uefi",
        "partitionStyle": "gpt", "secureBootEnabled": False,
        "targetVirtioSerial": guard.SERIAL,
        "diskVirtualBytes": guard.VIRTUAL_BYTES,
        "logicalSectorBytes": guard.SECTOR_BYTES,
        "diskGuidSha256": "a" * 64,
        "gptWindowsSha256": "b" * 64,
        "isoSha256": guard.ISO_SHA256, "rootFsUuid": UUID,
        "partitions": rows,
        "windowsHashes": {
            "espBootManagerSha256": "c" * 64, "espBcdSha256": "d" * 64,
            "windowsLoaderSha256": "e" * 64, "winreImageSha256": "f" * 64,
        },
        "writeAuthority": False,
    }


class SignedSharedArchisoTests(unittest.TestCase):
    def test_valid_nonwriting_layout_contract(self):
        plan = fixture()
        guard.validate_plan(plan)
        self.assertEqual(guard.canonical(plan)[-1:], b"\n")
        self.assertEqual(len(plan["partitions"]), 5)

    def test_refuse_noncanonical_firmware_or_storage_write_flag(self):
        for key, value in (
            ("firmware", "bios"), ("partitionStyle", "mbr"),
            ("secureBootEnabled", True), ("labOnly", False),
            ("writeAuthority", True),
            ("targetVirtioSerial", "GASLUXLABTARGET"),
            ("diskVirtualBytes", 1), ("logicalSectorBytes", 4096),
            ("backend", "debian-ubuntu"), ("distribution", "arch"),
            ("isoSha256", "0" * 64),
        ):
            with self.subTest(key=key):
                plan=fixture()
                plan[key] = value
                with self.assertRaises(guard.SharedDiskHandoffRejected):
                    guard.validate_plan(plan)

    def test_refuse_missing_or_extra_partition_or_duplicate_guid(self):
        for transform in (
            lambda p: p["partitions"].pop(),
            lambda p: p["partitions"].append(dict(p["partitions"][-1])),
            lambda p: p["partitions"][4].update(uniqueGuid=GUIDS[3]),
            lambda p: p["partitions"][4].update(typeGuid=guard.WIN_TYPES[3]),
            lambda p: p["partitions"][4].update(index=4),
            lambda p: p["partitions"][4].update(role="recovery"),
            lambda p: p["partitions"][0].update(firstLba=0),
            lambda p: p["partitions"][4].update(lastLba=2**32),
            lambda p: p["partitions"][4].update(firstLba=ROOT+1),
            lambda p: p["partitions"][4].update(firstLba=169000000),
        ):
            plan = fixture()
            transform(plan)
            with self.assertRaises(guard.SharedDiskHandoffRejected):
                guard.validate_plan(plan)

    def test_refuse_bad_partition_types_and_forged_bcd_hashes(self):
        for field, value in (
            ("rootFsUuid", "../tmp"),
            ("diskGuidSha256", "0"),
            ("gptWindowsSha256", True),
        ):
            plan=fixture()
            plan[field]=value
            with self.assertRaises(guard.SharedDiskHandoffRejected):
                guard.validate_plan(plan)
        plan=fixture()
        plan["windowsHashes"]["espBcdSha256"]="0"*64
        with self.assertRaises(guard.SharedDiskHandoffRejected):
            guard.validate_plan(plan)

    def test_kernel_cmdline_rejects_duplicate_unknown_and_missing_values(self):
        good=("quiet gaslux.run="+RUN_ID
              +" gaslux.nonce="+("1"*32)
              +" gaslux.plan_sha256="+("2"*64)
              +" gaslux.key_sha256="+("3"*64))
        self.assertEqual(guard.parse_kernel_cmdline(good)["gaslux.run"],RUN_ID)
        for corrupt in (
            good+" gaslux.run=other",
            good+" gaslux.disable_protections=1",
            good.replace("gaslux.key_sha256=","gaslux.unknown="),
            good.replace("gaslux.nonce=","bad-key="),
            good.replace("gaslux.plan_sha256="+("2"*64),"gaslux.plan_sha256=bad"),
        ):
            with self.subTest(corrupt=corrupt[-30:]), self.assertRaises(
                    guard.SharedDiskHandoffRejected):
                guard.parse_kernel_cmdline(corrupt)

    def test_real_ephemeral_ed25519_signature_is_required(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl unavailable on this host")
        with tempfile.TemporaryDirectory() as root:
            wd=Path(root)
            key=wd/"one-use-private.pem"
            pub=wd/"one-use-public.pem"
            sig=wd/"signed-plan.sig"
            plan=wd/"signed-plan.json"
            p=fixture()
            plan.write_bytes(guard.canonical(p))
            subprocess.run(["openssl","genpkey","-algorithm","ED25519",
                            "-out",str(key)],check=True,capture_output=True)
            subprocess.run(["openssl","pkey","-in",str(key),"-pubout",
                            "-out",str(pub)],check=True,capture_output=True)
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(key),
                            "-rawin","-in",str(plan),"-out",str(sig)],
                           check=True,capture_output=True)
            args=("console=ttyS0 gaslux.run="+RUN_ID+
                  " gaslux.nonce="+p["bootNonce"]+
                  " gaslux.plan_sha256="+guard.sha(plan.read_bytes())+
                  " gaslux.key_sha256="+guard.sha(pub.read_bytes()))
            status=guard.verify(plan,sig,pub,args,
                                independent_run_id=RUN_ID,
                                independent_root_uuid=UUID)
            self.assertTrue(status["signedPlanAndIsolatedDiskContractVerified"])
            for flag in ("pacstrapAuthorized", "storageWritesAuthorized",
                         "windowsRecoveryVerified", "sameDiskDualBootVerified",
                         "releaseEligible"):
                self.assertIs(status[flag], False)

            # A correct signature/plan cannot bless a different root or
            # transaction than the independent Windows stage expected.
            with self.assertRaises(guard.SharedDiskHandoffRejected):
                guard.verify(plan,sig,pub,args,
                             independent_run_id="gaslux-foreign-20261117",
                             independent_root_uuid=UUID)
            with self.assertRaises(guard.SharedDiskHandoffRejected):
                guard.verify(plan,sig,pub,args,
                             independent_run_id=RUN_ID,
                             independent_root_uuid="22222222-2222-4222-8222-222222222222")
            # A matching new hash does not make an edited plan valid unless
            # its detached signature is also regenerated by the signer.
            bad = copy.deepcopy(p)
            bad["windowsHashes"]["espBcdSha256"]="9"*64
            plan.write_bytes(guard.canonical(bad))
            changed=args.replace("gaslux.plan_sha256="+guard.sha(guard.canonical(p)),
                                 "gaslux.plan_sha256="+guard.sha(plan.read_bytes()))
            with self.assertRaisesRegex(guard.SharedDiskHandoffRejected, "signature"):
                guard.verify(plan,sig,pub,changed,
                             independent_run_id=RUN_ID,
                             independent_root_uuid=UUID)

    def test_reject_duplicate_json_keys_even_with_valid_hash_format(self):
        with self.assertRaisesRegex(guard.SharedDiskHandoffRejected,"duplicate"):
            json.loads('{"a":1,"a":2}',object_pairs_hook=guard._unique_pairs)

    def test_new_lab_contract_has_no_install_or_disk_writing_calls(self):
        code=SCRIPT.read_text()
        for forbidden in ("sgdisk --clear", "pacstrap -K",
                          "mkfs.ext4", "mkfs.vfat", "efibootmgr -c",
                          "guest.pwrite_device", "os.open('/dev/"):
            self.assertNotIn(forbidden,code)
        self.assertIn('"pacstrapAuthorized": False',code)
        self.assertIn('"storageWritesAuthorized": False',code)


if __name__=="__main__":
    unittest.main()
