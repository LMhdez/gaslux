"""Adversarial offline tests on the REAL pinned CachyOS laboratory source files."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import cachyos_uefi_writeset_readonly as gate
from test_cachyos_uefi_config import GOOD

REPO = Path(__file__).resolve().parents[1]
GUID = "d84daec5-2209-5df5-a10f-0327c8cbc278"
PARTUUID = "cbb3d10a-6881-5dc8-b976-20d2098756fa"
BINDING = {
    "transactionId": GOOD["runId"],
    "diskGuid": GUID,
    "espPartuuid": PARTUUID,
    "espVfatUuid": GOOD["espUuid"],
    "espOffsetBytes": 2048 * 512,
    "espLengthBytes": 528480 * 512,
    "sectorBytes": 512,
    "diskBytes": 128 * 1024 ** 3,
}


class CachyosUefiWriteSetTests(unittest.TestCase):
    def build(self, *, plan=None, expected=None, observed=None, repo=REPO):
        return gate.build_manifest(
            repo,
            deepcopy(GOOD) if plan is None else plan,
            deepcopy(BINDING) if expected is None else expected,
            deepcopy(BINDING) if observed is None else observed,
        )

    def proposal(self, manifest, path="/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi",
                 operation="GRUB_EFI_INSTALL", scope="WINDOWS_ESP",
                 **changes):
        item = {
            "path": path, "operation": operation, "scope": scope,
            "transactionId": manifest["transactionId"],
            "espPartuuid": manifest["esp"]["espPartuuid"],
        }
        item.update(changes)
        return gate.check_proposal(manifest, item)

    def test_valid_shared_esp_claim_is_structural_model_only(self):
        m = self.build()
        self.assertEqual(m["status"], "BOOT_WRITESET_MODEL_ONLY_DENY_NO_WRITER")
        self.assertEqual(m["bootloaderId"], "Gaslux-CachyOS")
        self.assertEqual(m["espIdentityAuthority"], "CLAIMED_NOT_FD_AUTHENTICATED")
        self.assertTrue(m["windowsGrubEntryIsTextOnly"])
        self.assertEqual(len(m["sourceBlobs"]), 4)
        self.assertEqual(len(m["operations"]), 13)
        self.assertTrue(all(row["authorization"] is False and
                            row["ownershipVerified"] is False
                            for row in m["operations"]))
        for key in ("authorization", "approvedMutation",
                    "productionStorageWritesAuthorized", "releaseEligible",
                    "stable", "sameDiskDualBootVerified", "rollbackProven",
                    "windowsEfiMutationAuthorized", "bootOrderMutationAuthorized",
                    "bootNextMutationAuthorized", "fallbackEfiMutationAuthorized",
                    "rootAndEspOwnershipIndependentlyProven",
                    "kernelUpdateHooksVerified", "efiUpdateHooksVerified",
                    "efiRollbackOwnershipVerified", "uefiBootCurrentVerified"):
            self.assertIs(m[key], False, key)
        self.assertIn("--no-nvram", m["grubCommands"]["grub-install"])
        self.assertIn("--no-extra-removable", m["grubCommands"]["grub-install"])

    def test_nominal_efi_file_proposal_is_never_authorized(self):
        m = self.build()
        result = self.proposal(m)
        self.assertEqual(result["path"],
                         "/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi")
        self.assertIs(result["authorization"], False)
        self.assertIs(result["ownershipVerified"], False)

    def test_foreign_esp_disk_guid_partuuid_and_vfat_rejected(self):
        for field, value in (
            ("diskGuid", "f5d4b59f-4b35-54c1-9359-ae2b823bbf31"),
            ("espPartuuid", "89e7af7c-7bf7-52d7-9cfa-727d24d292e1"),
            ("espVfatUuid", "BEEF-CAFE"),
        ):
            with self.subTest(field=field):
                foreign = deepcopy(BINDING)
                foreign[field] = value
                with self.assertRaisesRegex(gate.WriteSetRefused, "FOREIGN"):
                    self.build(observed=foreign)

    def test_foreign_transaction_rejected(self):
        foreign = deepcopy(BINDING)
        foreign["transactionId"] = "different-owner-2026"
        with self.assertRaisesRegex(gate.WriteSetRefused, "FOREIGN"):
            self.build(observed=foreign)
        m = self.build()
        with self.assertRaisesRegex(gate.WriteSetRefused, "FOREIGN_TRANSACTION"):
            self.proposal(m, transactionId="different-owner-2026")

    def test_proposal_foreign_esp_partuuid_rejected(self):
        m = self.build()
        with self.assertRaisesRegex(gate.WriteSetRefused, "FOREIGN_ESP"):
            self.proposal(
                m, espPartuuid="89e7af7c-7bf7-52d7-9cfa-727d24d292e1"
            )

    def test_protected_microsoft_bootloader_and_bcd_denied(self):
        m = self.build()
        for path in (
            "/boot/efi/EFI/Microsoft/Boot/bootmgfw.efi",
            "/boot/efi/EFI/Microsoft/Boot/BCD",
            "/boot/efi/efi/MICROSOFT/Boot/BCD",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                    gate.WriteSetRefused, "WINDOWS_OEM_FALLBACK"
                ):
                    self.proposal(m, path=path)

    def test_efi_fallback_and_oem_recovery_denied(self):
        m = self.build()
        for path in (
            "/boot/efi/EFI/BOOT/BOOTX64.EFI",
            "/boot/efi/EFI/OEM/Boot.efi",
            "/boot/efi/EFI/Recovery/boot.efi",
            "/boot/efi/EFI/Libertix/shimx64.efi",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                    gate.WriteSetRefused, "WINDOWS_OEM_FALLBACK"
                ):
                    self.proposal(m, path=path)

    def test_nvram_bootorder_bootnext_efibootmgr_rejected(self):
        m = self.build()
        for operation, path in (
            ("BOOTORDER_WRITE", "/sys/firmware/efi/efivars/BootOrder"),
            ("BOOTNEXT_WRITE", "/sys/firmware/efi/efivars/BootNext"),
            ("EFIBOOTMGR", "/sys/firmware/efi/efivars/Boot0005"),
            ("GRUB_INSTALL_WITH_NVRAM",
             "/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi"),
        ):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(
                    gate.WriteSetRefused, "UNVERIFIED_FIRMWARE"
                ):
                    self.proposal(m, path=path, operation=operation)

    def test_unexpected_grub_update_or_foreign_efi_path_rejected(self):
        m = self.build()
        for path, operation in (
            ("/boot/grub/grub.cfg", "UNEXPECTED_GRUB_UPDATE"),
            ("/boot/grub/grub.cfg", "REPLACE"),
            ("/boot/efi/EFI/CachyOS/grubx64.efi", "GRUB_EFI_INSTALL"),
            ("/boot/efi/EFI/Gaslux-CachyOS/unsigned.efi", "GRUB_EFI_INSTALL"),
        ):
            with self.subTest(path=path, operation=operation):
                with self.assertRaises(gate.WriteSetRefused):
                    self.proposal(m, path=path, operation=operation)

    def test_secure_boot_enabled_or_unknown_rejected(self):
        for state in (True, None, "false", 1):
            with self.subTest(secure=state):
                p = deepcopy(GOOD)
                p["secureBootEnabled"] = state
                with self.assertRaises(gate.WriteSetRefused):
                    self.build(plan=p)

    def test_linux_bios_or_separate_esp_rejected(self):
        for key, value in (("firmware", "bios"),
                           ("windowsBootUuid", "BEEF-CAFE")):
            with self.subTest(key=key):
                p = deepcopy(GOOD)
                p[key] = value
                with self.assertRaises(gate.WriteSetRefused):
                    self.build(plan=p)

    def test_noncanonical_disk_uuid_and_outside_gpt_geometry_rejected(self):
        for field, value in (
            ("diskGuid", GUID.upper()),
            ("espOffsetBytes", -512),
            ("espOffsetBytes", 123),
            ("espLengthBytes", 512 * (128 * 1024 ** 3)),
            ("sectorBytes", True),
            ("diskBytes", 0),
        ):
            with self.subTest(field=field):
                v = deepcopy(BINDING)
                v[field] = value
                with self.assertRaises(gate.WriteSetRefused):
                    self.build(expected=v, observed=v)

    def test_no_self_claimed_authentication_flag_allowed(self):
        v = deepcopy(BINDING)
        v["gptIndependentlyAuthenticated"] = True
        with self.assertRaisesRegex(gate.WriteSetRefused, "FIELDS"):
            self.build(expected=v, observed=v)

    def test_proposal_traversal_and_absolute_ambiguity_refused(self):
        m = self.build()
        for p in (
            "/boot/efi/EFI/Gaslux-CachyOS/../Microsoft/Boot/BCD",
            "/boot/efi//EFI/Gaslux-CachyOS/grubx64.efi",
            "EFI/Gaslux-CachyOS/grubx64.efi",
            "/boot/efi/EFI/Gaslux-CachyOS/./grubx64.efi",
        ):
            with self.subTest(path=p):
                with self.assertRaisesRegex(gate.WriteSetRefused,
                                             "INVALID_TARGET_PATH"):
                    self.proposal(m, path=p)

    def test_source_change_detected_on_real_pinned_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for p in gate.SOURCE_BLOBS:
                destination = root / p
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / p, destination)
            self.build(repo=root)
            target = root / "assets/live/cachyos-uefi-lab.py"
            with target.open("ab") as stream:
                stream.write(b"\n# unexpected grub-install --removable\n")
            with self.assertRaisesRegex(
                gate.WriteSetRefused, "AUDITED_SOURCE_VERSION_CHANGED"
            ):
                self.build(repo=root)

    def test_symlink_source_rejected_even_when_bytes_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for p in gate.SOURCE_BLOBS:
                destination = root / p
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / p, destination)
            target = root / "assets/live/cachyos-uefi-lab.py"
            spare = root / "same-bytes.py"
            target.replace(spare)
            target.symlink_to(spare)
            with self.assertRaisesRegex(
                gate.WriteSetRefused, "SOURCE_ALIAS"
            ):
                self.build(repo=root)

    def test_extra_proposal_keys_cannot_grant_authority(self):
        m = self.build()
        p = {
            "operation": "GRUB_EFI_INSTALL",
            "scope": "WINDOWS_ESP",
            "path": "/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi",
            "espPartuuid": m["esp"]["espPartuuid"],
            "transactionId": m["transactionId"],
            "authorized": True,
        }
        with self.assertRaisesRegex(gate.WriteSetRefused,
                                     "UNEXPECTED_WRITESET_PROPOSAL"):
            gate.check_proposal(m, p)

    def test_boot_update_proposals_always_fail_closed(self):
        m = self.build()
        for p in (
            ("/boot/vmlinuz-linux-cachyos", "PACMAN_S_YU"),
            ("/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi", "REPLACE"),
            ("/boot/grub/grub.cfg", "GRUB_UPDATE_HOOK"),
        ):
            with self.subTest(proposal=p):
                with self.assertRaises(gate.WriteSetRefused):
                    self.proposal(m, path=p[0], operation=p[1])


if __name__ == "__main__":
    unittest.main()
