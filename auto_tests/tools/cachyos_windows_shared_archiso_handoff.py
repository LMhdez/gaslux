#!/usr/bin/env python3
"""Signed plan verifier for a future CachyOS Archiso on a Windows 10 QCOW2.

Read-only, fail-closed laboratory contract. This does NOT perform pacstrap,
format a partition, write an ESP or authorize disk mutation.

The Ed25519 key hash and plan hash MUST be anchored independently by an
authenticated boot chain. Merely verifying a user-controlled kernel command
line is not authentication of the Windows boot chain or of guest disk origin.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

SHA = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
RUN = re.compile(r"[a-z0-9-]{12,80}\Z")
SERIAL = "GASLUXWINDOWSCOWLAB"
ISO_SHA256 = "959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c"
VIRTUAL_BYTES = 128 * 1024**3
SECTOR_BYTES = 512
ROOT_BYTES = 24 * 1024**3
WIN_TYPES = (
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",  # ESP
    "e3c9e316-0b5c-4db8-817d-f92df00215ae",  # MSR
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",  # Windows
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac",  # Recovery
)
LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
ROLES = ("esp", "msr", "windows", "recovery", "cachyos-root")
PART_KEYS = {"index", "role", "typeGuid", "uniqueGuid", "firstLba", "lastLba"}
HASH_KEYS = {
    "espBootManagerSha256", "espBcdSha256",
    "windowsLoaderSha256", "winreImageSha256",
}
PLAN_KEYS = {
    "schemaVersion", "backend", "distribution", "labOnly", "runId",
    "bootNonce", "firmware", "partitionStyle", "secureBootEnabled",
    "targetVirtioSerial", "diskVirtualBytes", "logicalSectorBytes",
    "diskGuidSha256", "gptWindowsSha256", "isoSha256",
    "rootFsUuid", "partitions", "windowsHashes", "writeAuthority",
}
CMD_KEYS = {
    "gaslux.run", "gaslux.nonce",
    "gaslux.plan_sha256", "gaslux.key_sha256",
}


class SharedDiskHandoffRejected(ValueError):
    """Untrusted or ambiguous Windows/CachyOS shared-disk plan."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SharedDiskHandoffRejected(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def safe_positive_lba(value: Any) -> bool:
    return type(value) is int and value > 0


def validate_parts(rows: Any) -> None:
    require(type(rows) is list and len(rows) == 5,
            "five exact Windows+CachyOS GPT entries required")
    seen: set[str] = set()
    end = 0
    last_usable = VIRTUAL_BYTES // SECTOR_BYTES - 34
    for i, p in enumerate(rows):
        require(type(p) is dict and set(p) == PART_KEYS,
                "unexpected GPT entry fields")
        require(type(p["index"]) is int and p["index"] == i+1
                and p["role"] == ROLES[i],
                "unexpected partition ordering or role")
        expected_type = WIN_TYPES[i] if i < 4 else LINUX_TYPE
        require(p["typeGuid"] == expected_type and
                isinstance(p["uniqueGuid"], str)
                and UUID.fullmatch(p["uniqueGuid"]) is not None
                and p["uniqueGuid"] != "00000000-0000-0000-0000-000000000000"
                and p["uniqueGuid"] not in seen,
                "foreign, duplicate or malformed GPT partition identity")
        seen.add(p["uniqueGuid"])
        require(safe_positive_lba(p["firstLba"]) and
                safe_positive_lba(p["lastLba"]) and
                2048 <= p["firstLba"] <= p["lastLba"] <= last_usable
                and p["firstLba"] > end,
                "overlapping, invalid or out-of-disk partition geometry")
        end = p["lastLba"]
    root = rows[4]
    require(root["firstLba"] % 2048 == 0
            and (root["lastLba"] - root["firstLba"] + 1)
                * SECTOR_BYTES == ROOT_BYTES
            and (last_usable - root["lastLba"]) * SECTOR_BYTES
                >= 16 * 1024**3,
            "fifth CachyOS root is unaligned, wrong size or consumes recovery reserve")


def validate_plan(plan: Any) -> None:
    require(type(plan) is dict and set(plan) == PLAN_KEYS,
            "unexpected/missing shared-disk plan fields")
    require(type(plan["schemaVersion"]) is int and plan["schemaVersion"] == 1
            and plan["backend"] == "archiso-cachyos-windows-cow-lab"
            and plan["distribution"] == "cachyos"
            and plan["labOnly"] is True
            and plan["firmware"] == "uefi"
            and plan["partitionStyle"] == "gpt"
            and plan["secureBootEnabled"] is False
            and plan["writeAuthority"] is False,
            "plan is not a non-mutating shared-disk UEFI/GPT lab contract")
    require(plan["targetVirtioSerial"] == SERIAL and
            type(plan["diskVirtualBytes"]) is int
            and plan["diskVirtualBytes"] == VIRTUAL_BYTES
            and type(plan["logicalSectorBytes"]) is int
            and plan["logicalSectorBytes"] == SECTOR_BYTES,
            "wrong disposable Windows QEMU disk identity or geometry")
    require(isinstance(plan["runId"], str) and
            RUN.fullmatch(plan["runId"]) is not None and
            isinstance(plan["bootNonce"], str) and
            NONCE.fullmatch(plan["bootNonce"]) is not None,
            "missing or malformed transaction/boot nonce")
    for field in ("diskGuidSha256", "gptWindowsSha256", "rootFsUuid"):
        val = plan.get(field)
        expression = UUID if field == "rootFsUuid" else SHA
        require(isinstance(val, str) and expression.fullmatch(val) is not None,
                "invalid shared-disk identity field: " + field)
    require(plan["isoSha256"] == ISO_SHA256,
            "CachyOS ISO differs from the official pinned release")
    hashes = plan["windowsHashes"]
    require(type(hashes) is dict and set(hashes) == HASH_KEYS and all(
        isinstance(v, str) and SHA.fullmatch(v) is not None
        and v != "0" * 64 for v in hashes.values()
    ), "missing or forged-looking Windows EFI/BCD/WinRE digest fields")
    validate_parts(plan["partitions"])


def parse_kernel_cmdline(value: str) -> dict[str, str]:
    require(type(value) is str and len(value) < 8192,
            "invalid kernel cmdline")
    seen: dict[str, str] = {}
    for field in value.split():
        key, sep, item = field.partition("=")
        if key.startswith("gaslux."):
            require(key in CMD_KEYS and sep == "=" and bool(item)
                    and key not in seen,
                    "unknown, malformed or repeated signed kernel argument")
            seen[key] = item
    require(set(seen) == CMD_KEYS, "incomplete signed boot arguments")
    require(RUN.fullmatch(seen["gaslux.run"]) is not None and
            NONCE.fullmatch(seen["gaslux.nonce"]) is not None and
            SHA.fullmatch(seen["gaslux.plan_sha256"]) is not None and
            SHA.fullmatch(seen["gaslux.key_sha256"]) is not None,
            "invalid signed boot argument type")
    return seen


def file_bytes(path: Path, maximum: int) -> bytes:
    require(isinstance(path, Path) and path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= maximum,
            "missing, linked or oversized handoff artifact")
    return path.read_bytes()


def verify(
    document_path: Path, sig_path: Path, pub_path: Path,
    cmdline: str, *, independent_run_id: str, independent_root_uuid: str,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    boot = parse_kernel_cmdline(cmdline)
    require(isinstance(independent_run_id, str)
            and RUN.fullmatch(independent_run_id) is not None
            and isinstance(independent_root_uuid, str)
            and UUID.fullmatch(independent_root_uuid) is not None,
            "independent signed handoff expectation missing")
    raw = file_bytes(document_path, 16384)
    signature = file_bytes(sig_path, 64)
    pub = file_bytes(pub_path, 4096)
    require(len(signature) == 64,
            "Ed25519 signature is not exactly 64 bytes")
    require(sha(raw) == boot["gaslux.plan_sha256"]
            and sha(pub) == boot["gaslux.key_sha256"],
            "handoff plan or public key differs from authenticated boot arguments")
    try:
        plan = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise SharedDiskHandoffRejected("invalid, duplicate or non-JSON handoff") from exc
    validate_plan(plan)
    require(canonical(plan) == raw, "noncanonical handoff JSON")
    require(plan["runId"] == boot["gaslux.run"] == independent_run_id
            and plan["bootNonce"] == boot["gaslux.nonce"]
            and plan["rootFsUuid"] == independent_root_uuid,
            "signed handoff target differs from independent transaction expectation")
    try:
        outcome = run([
            "openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
            str(pub_path), "-sigfile", str(sig_path), "-rawin", "-in",
            str(document_path),
        ], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SharedDiskHandoffRejected("Ed25519 verification unavailable") from exc
    require(outcome.returncode == 0, "Ed25519 signature verification failed")
    # A signed LAB plan by itself NEVER authorizes a disk write. Real-device
    # identity, Windows encryption, recovery and ESP boot proofs are separate.
    return {
        "signedPlanAndIsolatedDiskContractVerified": True,
        "transactionBound": True,
        "officialCachyosIsoPinned": True,
        "fivePartitionWindowsLayoutContractVerified": True,
        "guestDiskOriginAuthenticated": False,
        "windowsBootChainAuthenticated": False,
        "windowsRecoveryVerified": False,
        "pacstrapAuthorized": False,
        "storageWritesAuthorized": False,
        "linuxBootVerified": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        require(name not in result, "duplicate handoff JSON field")
        result[name] = value
    return result


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--plan", required=True, type=Path)
    cli.add_argument("--signature", required=True, type=Path)
    cli.add_argument("--public-key", required=True, type=Path)
    cli.add_argument("--expected-run-id", required=True)
    cli.add_argument("--expected-root-uuid", required=True)
    args = cli.parse_args()
    try:
        # Intentionally no --cmdline option: a guest must read its running
        # kernel, not an untrusted argument supplied by the caller.
        cmdline = Path("/proc/cmdline").read_text(encoding="utf-8")
        status = verify(args.plan, args.signature, args.public_key, cmdline,
                        independent_run_id=args.expected_run_id,
                        independent_root_uuid=args.expected_root_uuid)
        print(json.dumps(status, sort_keys=True))
    except (OSError, SharedDiskHandoffRejected, TypeError, KeyError,
            UnicodeError, ValueError) as exc:
        print(json.dumps({"signedPlanAndIsolatedDiskContractVerified": False,
                          "pacstrapAuthorized": False,
                          "storageWritesAuthorized": False,
                          "releaseEligible": False,
                          "error": str(exc)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
