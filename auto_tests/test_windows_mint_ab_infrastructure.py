"""Pure, fail-closed infrastructure qualification tests. Never start QEMU."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))

import windows_mint_ab_infrastructure as infra
from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES
from windows_mint_ab_capacity import EARLY_IMAGES, EARLY_RESERVE


def good_capacity() -> dict:
    full = VIRTUAL_BYTES + 32 * 1024 * 1024
    required = full * EARLY_IMAGES + EARLY_RESERVE
    return {
        "schema": "gaslux-mint-ab-capacity-v1",
        "phase": "early",
        "result": "PASS",
        "qemuFullyAllocatedImageBytes": full,
        "worstCaseRemainingStandaloneImagesAndRestores": EARLY_IMAGES,
        "minimumFreeBytesRequired": required,
        "effectiveAvailableBytes": required,
        "processAvailableBytes": required,
        "capacityShortfallBytes": 0,
        "compressionAssumedForCapacity": False,
        "filesystemTotalBytes": required * 2,
        "filesystemFreeBytes": required,
        "quotaRemainingBytes": required,
        "nonImageReserveBytes": EARLY_RESERVE,
    }


def evaluate(capacity: dict | None, **changes) -> dict:
    data = {
        "identity": {"runId": "123", "sourceCommit": "a" * 40, "profile": infra.PROFILE},
        "capacity": capacity,
        "tools": {"qemu-img": True, "qemu-io": True, "qemu-system-x86_64": True},
        "kvm": True,
        "ovmf": True,
        "private_files": True,
        "quota_observed": True,
    }
    data.update(changes)
    return infra.classify(**data)


class InfrastructureContracts(unittest.TestCase):
    def test_budget_pass_without_authorizing_windows(self) -> None:
        result = evaluate(good_capacity())
        self.assertEqual(result["result"], "PASS")
        for key in (
            "windowsGuestBootsAuthorized",
            "productionInstallAuthorized",
            "checkpointReadyForReview",
            "storageWritesAuthorized",
            "releaseEligible",
        ):
            self.assertIs(result[key], False, key)

    def test_fail_closed_unknown_quota_and_all_missing_components(self) -> None:
        scenarios = (
            {"quota_observed": False},
            {"kvm": False},
            {"ovmf": False},
            {"private_files": False},
            {"tools": {"qemu-img": True, "qemu-io": False, "qemu-system-x86_64": True}},
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result = evaluate(good_capacity(), **scenario)
                self.assertEqual(result["result"], "BLOCKED_CAPACITY")
                self.assertTrue(result["failedConditions"])
                self.assertFalse(result["windowsGuestBootsAuthorized"])

    def test_inconsistent_capacity_pass_never_qualifies(self) -> None:
        overrides = (
            {"minimumFreeBytesRequired": 1},
            {"qemuFullyAllocatedImageBytes": VIRTUAL_BYTES - 1},
            {"capacityShortfallBytes": 1},
            {"compressionAssumedForCapacity": True},
            {"phase": "late"},
            {"worstCaseRemainingStandaloneImagesAndRestores": 3},
            {"processAvailableBytes": 1},
            {"result": "BLOCKED_CAPACITY"},
        )
        for tamper in overrides:
            with self.subTest(tamper=tamper):
                data = good_capacity() | tamper
                self.assertEqual(evaluate(data)["result"], "BLOCKED_CAPACITY")

    def test_missing_capacity_does_not_fabricate_numeric_measurements(self) -> None:
        report = evaluate(None)
        self.assertIsNone(report["capacityBytes"]["qemuFullyAllocatedImageBytes"])
        self.assertIn("capacity_not_demonstrated", report["failedConditions"])

    def test_host_identity_rejects_wrong_account_before_disk_touch(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "other-user/gaslux",
            "GITHUB_REF": infra.BRANCH,
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(infra.ROOT),
            "GITHUB_WORKSPACE": str(infra.WORKSPACE),
            "GITHUB_RUN_ID": "12345",
            "GITHUB_SHA": "a" * 40,
        }
        with patch.object(infra, "exclusive_storage_probe") as probe:
            with self.assertRaisesRegex(infra.QualificationError, "unverified"):
                infra.check_host_identity(env, infra.ROOT, infra.WORKSPACE)
            probe.assert_not_called()

    def test_private_exclusive_file_probe_rejects_untrusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(infra.QualificationError, "unapproved"):
                infra.exclusive_storage_probe(root, "123")

    def test_owned_exclusive_probe_is_removed_after_use(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(infra, "ROOT", root):
                self.assertTrue(infra.exclusive_storage_probe(root, "123"))
            self.assertFalse((root / "gaslux-mint-ab-probe-123").exists())

    def test_preexisting_foreign_probe_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            foreign = root / "gaslux-mint-ab-probe-123"
            foreign.mkdir()
            (foreign / "foreign").write_text("preserve", encoding="utf-8")
            with (
                patch.object(infra, "ROOT", root),
                self.assertRaisesRegex(infra.QualificationError, "foreign"),
            ):
                infra.exclusive_storage_probe(root, "123")
            self.assertEqual((foreign / "foreign").read_text(encoding="utf-8"), "preserve")

    def test_invalid_run_id_rejected_before_private_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(infra, "ROOT", root),
                self.assertRaisesRegex(infra.QualificationError, "unapproved"),
            ):
                infra.exclusive_storage_probe(root, "../dev/sda")

    def test_no_pseudo_pass_when_ovmf_or_kvm_is_inaccessible(self) -> None:
        for value in ("kvm", "ovmf"):
            with self.subTest(value=value):
                data = {value: False}
                self.assertEqual(
                    evaluate(good_capacity(), **data)["result"],
                    "BLOCKED_CAPACITY",
                )


if __name__ == "__main__":
    unittest.main()
