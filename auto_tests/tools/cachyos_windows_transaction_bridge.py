#!/usr/bin/env python3
"""Read-only compatibility bridge: Windows Libertix plan -> CachyOS signed handoff.

This is an EXPERIMENTAL, FAIL-CLOSED audit, not an installation authorization.
The existing Windows plan, execution ledger and a Windows baseline must agree
with an Ed25519-authenticated Archiso handoff. A JSON baseline alone cannot
prove its own provenance, a Windows boot, BCD/WinRE restoration or rollback.
No disk/firmware/BCD writer imports or mutations are permitted in this module.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HEX_SHA = re.compile(r"[0-9a-f]{64}\Z")
FAT_UUID = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}\Z")
WINDOWS_STEPS = (
    "windows.preflight-verified",
    "windows.artifacts-verified",
    "windows.recovery-armed",
    "windows.system-volume-shrunk",
    "windows.installer-partition-created",
    "windows.live-media-prepared",
    "windows.temporary-boot-prepared",
)
BASELINE_FIELDS = frozenset({
    "schemaVersion", "planId", "diskUniqueId", "partitionTableId",
    "logicalSectorSizeBytes", "firmware", "partitionStyle",
    "windowsPartition", "bootPartition", "recoveryPartition",
    "espUuid", "windowsLoaderSha256", "bcdSha256", "winreEnabled",
    "bitlockerState",
})


class BridgeError(ValueError):
    """The proposed handoff does not match the frozen Windows transaction."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BridgeError(message)


def load_helper(name: str, relative_path: str) -> Any:
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


PLAN = load_helper("gaslux_windows_plan_bridge", "assets/live/libertix-installation-plan.py")
STATE = load_helper("gaslux_windows_state_bridge", "assets/live/libertix-installation-state.py")
AUTH = load_helper("gaslux_archiso_auth_bridge", "assets/live/cachyos-handoff-auth.py")


def read_regular_json(path: Path, max_bytes: int = 262_144) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "missing/linked evidence document")
    require(0 < path.stat().st_size <= max_bytes, "evidence document size invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as error:
        raise BridgeError("malformed evidence JSON") from error
    require(isinstance(value, dict), "evidence document must be an object")
    return value


def evaluate(
    plan: dict[str, Any],
    state: dict[str, Any],
    baseline: dict[str, Any],
    envelope: Path,
    signature: Path,
    public_key: Path,
    cmdline: str,
    observed_root_uuid: str,
) -> dict[str, Any]:
    """Cross-check three identities; NEVER return permission to modify storage."""
    # Reuse existing Windows/Linux validators; do not fork their geometry rules.
    validated_plan = PLAN.validate_plan(copy.deepcopy(plan), require_installer=True)
    validated_state = STATE.validate_state(copy.deepcopy(state))
    require(validated_plan["firmware"] == "uefi" and
            validated_plan["disk"]["partitionStyle"] == "GPT",
            "only the experimental UEFI/GPT path is defined")
    require(validated_plan["runtime"]["secureBootEnabled"] is False,
            "Secure Boot must be verified disabled before any future mutation")
    distro = validated_plan["distribution"]
    require(distro["id"] == "cachyos" and distro["osReleaseId"] == "cachyos",
            "Windows plan is not explicitly for CachyOS")
    require(validated_plan["runtime"]["recoveryRootWindows"] is not None and
            validated_plan["runtime"]["recoveryRunId"] is not None,
            "Windows recovery session is not identified in the plan")
    require(validated_state["planId"] == validated_plan["planId"],
            "state and Windows plan IDs differ")
    require(validated_state["status"] == "running" and
            validated_state["phase"] == "live" and
            validated_state["failure"] is None and
            not validated_state["compensatedSteps"],
            "Windows transaction is not an uncompensated live handoff")
    completed = validated_state["completedSteps"]
    require(completed[:len(WINDOWS_STEPS)] == list(WINDOWS_STEPS) and
            len(completed) in (len(WINDOWS_STEPS), len(WINDOWS_STEPS) + 1) and
            validated_state["activeStep"] in (
                "live.preflight-verified", "live.installer-partition-expanded"
            ),
            "Windows preflight/recovery/boot stages lack ordered durable checkpoints")

    require(isinstance(baseline, dict) and set(baseline) == BASELINE_FIELDS,
            "Windows baseline has missing or foreign fields")
    require(type(baseline["schemaVersion"]) is int and baseline["schemaVersion"] == 1,
            "Windows baseline schema is unknown")
    disk = validated_plan["disk"]
    for key, expected in (
        ("planId", validated_plan["planId"]),
        ("diskUniqueId", disk["uniqueId"]),
        ("partitionTableId", disk["partitionTableId"]),
        ("logicalSectorSizeBytes", disk["logicalSectorSizeBytes"]),
        ("firmware", "uefi"),
        ("partitionStyle", "GPT"),
        ("bitlockerState", validated_plan["runtime"]["windowsBitLockerState"]),
    ):
        require(type(baseline[key]) is type(expected) and baseline[key] == expected,
                "Windows baseline does not match " + key)
    for field, plan_field in (
        ("windowsPartition", "windows"),
        ("bootPartition", "boot"),
        ("recoveryPartition", "recovery"),
    ):
        require(type(baseline[field]) is dict and
                baseline[field] == disk[plan_field],
                "Windows baseline partition geometry differs: " + field)
    require(baseline["winreEnabled"] is True,
            "Windows recovery was not observed enabled")
    require(isinstance(baseline["espUuid"], str) and
            FAT_UUID.fullmatch(baseline["espUuid"]) is not None,
            "Windows EFI filesystem identity missing")
    for name in ("windowsLoaderSha256", "bcdSha256"):
        value = baseline[name]
        require(isinstance(value, str) and HEX_SHA.fullmatch(value) is not None
                and value != "0" * 64,
                "missing Windows boot artifact digest: " + name)

    # AUTH verifies canonical Ed25519 envelope, public key pin, cmdline,
    # signed transaction and independently observed installed-root identity.
    auth_result = AUTH.verify(
        envelope, signature, public_key, cmdline,
        expected_run_id=validated_plan["planId"],
        expected_root_uuid=observed_root_uuid,
    )
    signed = read_regular_json(envelope, max_bytes=16_384)
    AUTH.validate_document(signed)
    require(signed["runId"] == validated_plan["planId"] and
            signed["targetDiskId"] == disk["uniqueId"] and
            signed["isoSha256"] == distro["installerIsoSha256"] and
            signed["firmware"] == "uefi" and signed["partitionStyle"] == "gpt" and
            signed["secureBootEnabled"] is False,
            "signed CachyOS handoff differs from the Windows plan/disk/ISO")
    require(signed["windowsEspUuid"] == baseline["espUuid"] and
            signed["windowsLoaderSha256"] == baseline["windowsLoaderSha256"],
            "signed handoff does not protect original Windows EFI identity")
    require(auth_result["verified"] is True and
            auth_result["runId"] == validated_plan["planId"] and
            auth_result["rootUuid"] == observed_root_uuid and
            auth_result["isoSha256"] == distro["installerIsoSha256"] and
            auth_result["windowsEspUuid"] == baseline["espUuid"] and
            auth_result["windowsLoaderSha256"] == baseline["windowsLoaderSha256"],
            "authenticated result does not match independent Windows evidence")

    # Unsupported trust links remain explicit: the original plan has no ISO
    # byte length or ESP loader hash; the baseline lacks an independent reviewer
    # attestation. Linux first boot does not demonstrate Windows boot/rollback.
    return {
        "contractMatched": True,
        "planId": validated_plan["planId"],
        "windowsRecoverySessionIdentified": True,
        "windowsBaselineSelfReported": True,
        "windowsBootVerified": False,
        "windowsBcdAndWinreRestorationVerified": False,
        "firmwareBootOrderRestorationVerified": False,
        "linuxKernelUpdateCrossbootVerified": False,
        "uninstallVerified": False,
        "transactionIntegratedIntoProductionInstaller": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-plan", required=True, type=Path)
    parser.add_argument("--execution-state", required=True, type=Path)
    parser.add_argument("--windows-baseline", required=True, type=Path)
    parser.add_argument("--signed-handoff", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--observed-root-uuid", required=True)
    args = parser.parse_args(argv)
    try:
        result = evaluate(
            read_regular_json(args.windows_plan),
            read_regular_json(args.execution_state),
            read_regular_json(args.windows_baseline),
            args.signed_handoff, args.signature, args.public_key,
            Path("/proc/cmdline").read_text(encoding="ascii"),
            args.observed_root_uuid,
        )
    except (BridgeError, AUTH.AuthError, PLAN.PlanValidationError,
            STATE.StateTransitionError, OSError, KeyError, ValueError, TypeError) as error:
        print(json.dumps({"contractMatched": False, "storageWritesAuthorized": False,
                          "releaseEligible": False, "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
