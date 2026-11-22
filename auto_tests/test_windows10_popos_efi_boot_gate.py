"""Adversarial offline EFI consistency tests: no images, VMs or writes."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from windows10_popos_efi_boot_gate import (  # noqa: E402
    BootGateRefusal,
    assess_efi_boot_chain,
)

WIN = "11111111-1111-4111-8111-111111111111"
POP = "22222222-2222-4222-8222-222222222222"


def pair(topology="separate"):
    esp = WIN if topology == "shared" else POP
    before = {
        "windowsEspPartuuid": WIN,
        "popEspPartuuid": esp,
        "microsoftFiles": {
            "EFI/Microsoft/Boot/bootmgfw.efi": "a" * 64,
            "EFI/Microsoft/Boot/BCD": "b" * 64,
        },
        "bootEntries": {
            "0001": {
                "espPartuuid": WIN,
                "loaderPath": "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            },
        },
        "bootOrder": ["0001"],
        "bootNext": None,
    }
    after = copy.deepcopy(before)
    after["bootEntries"]["0002"] = {
        "espPartuuid": esp,
        "loaderPath": "\\EFI\\systemd\\systemd-bootx64.efi",
    }
    after["bootOrder"].append("0002")
    return before, after


class EfiBootGateTests(unittest.TestCase):
    def test_separate_esp_requires_explicit_firmware_windows_entry(self):
        before, after = pair()
        result = assess_efi_boot_chain(before, after, topology="separate")
        self.assertFalse(result["systemdBootWindowsAutodiscoveryAssumed"])
        self.assertFalse(result["dualBootProven"])
        self.assertFalse(result["distinstExecutionAuthorized"])

    def test_shared_esp_keeps_microsoft_inventory(self):
        before, after = pair("shared")
        self.assertTrue(
            assess_efi_boot_chain(before, after, topology="shared")[
                "offlineConsistencyChecksPassed"
            ]
        )

    def test_adversarial_refusals(self):
        changes = [
            (
                "BCD tamper",
                lambda s: s["microsoftFiles"].update({"EFI/Microsoft/Boot/BCD": "0" * 64}),
            ),
            ("BCD removed", lambda s: s["microsoftFiles"].pop("EFI/Microsoft/Boot/BCD")),
            (
                "case alias",
                lambda s: s["microsoftFiles"].update({"efi/microsoft/boot/bcd": "f" * 64}),
            ),
            ("Windows retarget", lambda s: s["bootEntries"]["0001"].update({"espPartuuid": POP})),
            ("Windows BootOrder removal", lambda s: s.update({"bootOrder": ["0002"]})),
            ("Pop BootOrder removal", lambda s: s.update({"bootOrder": ["0001"]})),
            ("BootNext changed", lambda s: s.update({"bootNext": "0002"})),
            ("unknown BootNext", lambda s: s.update({"bootNext": "9999"})),
            ("missing Pop entry", lambda s: s["bootEntries"].pop("0002")),
            ("wrong Pop device", lambda s: s["bootEntries"]["0002"].update({"espPartuuid": WIN})),
            (
                "foreign Pop loader",
                lambda s: s["bootEntries"]["0002"].update(
                    {"loaderPath": "\\EFI\\foreign\\loader.efi"}
                ),
            ),
            ("duplicate BootOrder", lambda s: s.update({"bootOrder": ["0001", "0001"]})),
            ("Pop ESP drift", lambda s: s.update({"popEspPartuuid": WIN})),
        ]
        for label, mutation in changes:
            before, after = pair()
            mutation(after)
            with self.subTest(label=label), self.assertRaises(BootGateRefusal):
                assess_efi_boot_chain(before, after, topology="separate")

    def test_missing_windows_entry_or_topology_mismatch(self):
        before, after = pair("shared")
        after["bootEntries"].pop("0001")
        after["bootOrder"].remove("0001")
        with self.assertRaises(BootGateRefusal):
            assess_efi_boot_chain(before, after, topology="shared")
        before, after = pair("shared")
        with self.assertRaises(BootGateRefusal):
            assess_efi_boot_chain(before, after, topology="separate")


if __name__ == "__main__":
    unittest.main()
