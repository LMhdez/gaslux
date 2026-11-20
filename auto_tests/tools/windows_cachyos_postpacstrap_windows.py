#!/usr/bin/env python3
"""Experimental Windows re-entry while pacstrapped CachyOS remains on GPT #5.

One disposable Windows 10 QCOW2 overlay only. Windows boots via its own
unchanged Boot Manager; CachyOS has NO installed Windows-ESP bootloader.
Do not treat independent VM boots as persistent dual boot or production proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any

from cachyos_windows_shared_archiso_handoff import (
    _unique_pairs, canonical, validate_plan,
)
from cachyos_windows_archiso_signed_plan_lab import read_windows_file_hashes
from cachyos_windows_shared_root_pacstrap_host import _verify_installed_root
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, sha256_file,
    validate_workspace,
)
from windows_cachyos_overlay_reboot import gpt_windows
from windows_cachyos_postext4_windows import verify_windows_post_ext4
from windows_cachyos_qcow2_gpt_readonly import qcow2_file_identity

CONSENT = "I_ACCEPT_WIN10_BOOT_WITH_INSTALLED_CACHYOS_FIFTH_ROOT_ON_DISPOSABLE_COW"


class PostPacstrapWindowsError(ValueError):
    def __init__(self, message: str, *, diagnostics: dict[str, Any] | None = None):
        super().__init__(message)
        # Only bounded digests/offsets; never BCD bytes, Windows content or keys.
        self.diagnostics = diagnostics


def _read_bcd_readonly(overlay: Path) -> bytes:
    """Read only the Microsoft ESP BCD hive on the already-owned QCOW2.

    Never mount the ESP writable, repair a hive or inspect a physical device.
    """
    import guestfs
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(overlay), format="qcow2", readonly=1)
        g.launch()
        parts = g.list_partitions()
        require(len(parts) == 5, "read-only BCD witness missing five GPT partitions")
        g.mount_ro(parts[0], "/")
        bcd = "/EFI/Microsoft/Boot/BCD"
        require(g.is_file(bcd), "protected BCD missing for read-only forensic")
        size = g.statns(bcd)["st_size"]
        require(type(size) is int and 4096 <= size <= 2 * 1024 * 1024,
                "protected BCD size outside forensic bounds")
        raw = g.read_file(bcd)
        require(type(raw) is bytes and len(raw) == size and raw[:4] == b"regf",
                "invalid Windows BCD registry hive read-only witness")
        return raw
    finally:
        try:
            g.shutdown()
        finally:
            g.close()


def summarize_bcd_difference(before: bytes, after: bytes) -> dict[str, Any]:
    """Only SHA-256, lengths and bounded byte offsets; no hive bytes are emitted.

    Pure diagnostic, never an authorization to disregard a changed signed hash.
    """
    require(type(before) is bytes and type(after) is bytes
            and 4096 <= len(before) <= 2 * 1024 * 1024
            and 4096 <= len(after) <= 2 * 1024 * 1024
            and before[:4] == b"regf" and after[:4] == b"regf",
            "invalid BCD forensic inputs")
    spans: list[dict[str, int]] = []
    changes = 0
    start = None
    for offset in range(min(len(before), len(after))):
        different = before[offset] != after[offset]
        if different:
            changes += 1
            if start is None:
                start = offset
        elif start is not None:
            if len(spans) < 24:
                spans.append({"offset": start, "length": offset - start})
            start = None
    if start is not None and len(spans) < 24:
        spans.append({"offset": start, "length": min(len(before),len(after))-start})
    changes += abs(len(before)-len(after))
    if len(before) != len(after) and len(spans) < 24:
        spans.append({"offset": min(len(before),len(after)),
                      "length": abs(len(before)-len(after))})
    return {
        "prebootBcdSha256": hashlib.sha256(before).hexdigest(),
        "postbootBcdSha256": hashlib.sha256(after).hexdigest(),
        "prebootBcdBytes": len(before),
        "postbootBcdBytes": len(after),
        "changedByteCount": changes,
        "firstChangedByteSpans": spans,
        "truncatedToFirst24Spans": len(spans) == 24,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
    }

def require(ok: bool, message: str) -> None:
    if not ok:
        raise PostPacstrapWindowsError(message)


def preflight(pacstrap: dict[str, Any], fourth: dict[str, Any],
              ext4: dict[str, Any]) -> str:
    """No filesystem/VM operations before all lab proof and consent checks."""
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_CACHYOS_POST_PACSTRAP_WINDOWS_CONSENT") == CONSENT,
        "separate disposable post-pacstrap Windows boot consent required",
    )
    required = (
        "rootWriteGrantIssued", "pacstrapExecuted", "labOnlyPacstrapCompleted",
        "cachyosRootPacstrapped", "nativeCachyOSOsReleaseVerified",
        "nativeKernelAndInitramfsPresent", "strictInstalledPacmanPolicyVerified",
        "minimalInstalledReadOnlyBootVerified",
        "installedWritableChildKernelAndSystemdBootVerified",
        "installedWritableChildSecondBootVerified",
        "installedWritableChildSecondBootPersistentMarkerVerified",
        "installedWritableChildOverlayDiscarded",
        "windowsGptUnchangedAfterPacstrap",
        "windowsProtectedHashesUnchangedAfterPacstrap",
        "windowsBaseSha256UnchangedAfterPacstrap",
        "originalWindowsUefiUnchangedAfterPacstrap",
    )
    require(
        type(pacstrap) is dict and all(pacstrap.get(name) is True for name in required)
        and pacstrap.get("sameDiskDualBootVerified") is False
        and pacstrap.get("windowsEspWritesAllowed") is False
        and pacstrap.get("efiBootloaderInstalled") is False
        and pacstrap.get("releaseEligible") is False
        and pacstrap.get("productionStorageWritesAuthorized") is False
        and type(fourth) is dict
        and fourth.get("windowsBootAfterExt4Verified") is True
        and fourth.get("windowsGptUnchangedAfterExt4Boot") is True
        and type(ext4) is dict
        and ext4.get("onlyOwnedOverlayFifthPartitionFormatted") is True,
        "missing authenticated pacstrap, installed-root and Windows preconditions",
    )
    root = ext4.get("rootFilesystem", {}).get("filesystemUuid")
    require(type(root) is str and len(root) == 36
            and pacstrap.get("installedWritableChildRunId")
            and type(pacstrap["installedWritableChildRunId"]) is str,
            "missing fifth ext4 or owner transaction identity")
    return root.lower()


def signed_lab_plan(workspace: Path, root_uuid: str,
                    run_id: str) -> dict[str, Any]:
    """Recheck signed canonical plan bytes independently before Windows reboot."""
    handoff = workspace / "cachyos-root-write-handoff"
    require(handoff.is_dir() and not handoff.is_symlink()
            and handoff.stat().st_uid == os.getuid()
            and stat.S_IMODE(handoff.stat().st_mode) == 0o700,
            "unowned signed plan directory")
    files = [handoff / item for item in ("plan.json", "plan.sig", "public.pem")]
    for file in files:
        owned_regular(file, handoff, file.name)
    plan_path, sig_path, public_path = files
    require(plan_path.stat().st_size <= 16384
            and sig_path.stat().st_size == 64
            and public_path.stat().st_size <= 4096,
            "unbounded or invalid signed handoff")
    raw = plan_path.read_bytes()
    try:
        plan = json.loads(raw, object_pairs_hook=_unique_pairs)
        validate_plan(plan)
    except (ValueError, TypeError, UnicodeError) as error:
        raise PostPacstrapWindowsError("invalid signed plan") from error
    require(canonical(plan) == raw
            and plan["runId"] == run_id
            and plan["rootFsUuid"] == root_uuid,
            "changed target or noncanonical signed plan")
    try:
        verify = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
             str(public_path), "-sigfile", str(sig_path),
             "-rawin", "-in", str(plan_path)],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PostPacstrapWindowsError("plan signature verifier unavailable") from error
    require(verify.returncode == 0, "signed plan verification rejected")
    return plan


def verify_windows_with_installed_root(
    original: list[str], base: Path, nvram: Path,
    geometry: dict[str, Any], cow: dict[str, Any],
    staged: dict[str, Any], third: dict[str, Any],
    ext4: dict[str, Any], fourth: dict[str, Any],
    pacstrap: dict[str, Any], *, timeout: int = 1200,
    tpm_socket: Path | None = None,
    trace_events_file: Path | None = None,
    trace_file: Path | None = None,
) -> dict[str, Any]:
    root_uuid = preflight(pacstrap, fourth, ext4)
    require(type(timeout) is int and 120 <= timeout <= 1800,
            "post-pacstrap Windows guest timeout outside safe bounds")
    validate_workspace(base, nvram)
    workspace = base.parent
    overlay = workspace / CHECKPOINT_DIR / OVERLAY_NAME
    owned_regular(overlay, workspace / CHECKPOINT_DIR, OVERLAY_NAME)
    require(stat.S_IMODE(overlay.stat().st_mode) == 0o600
            and stat.S_IMODE(base.stat().st_mode) == 0o400,
            "unprotected Windows backing or CachyOS trial overlay")
    before_base = sha256_file(base)
    before_nvram = sha256_file(nvram)
    before_base_identity = qcow2_file_identity(base)
    plan = signed_lab_plan(workspace, root_uuid, pacstrap["installedWritableChildRunId"])
    print("GASLUX_CACHYOS_WIN10_REENTRY_SIGNED_PLAN_VERIFIED=1", flush=True)
    with tempfile.TemporaryDirectory(prefix="gaslux-postpacstrap-before-",
                                     dir=workspace) as scratch:
        front, back = gpt_windows(overlay, Path(scratch))
    require(hashlib.sha256(front + back).hexdigest() == plan["gptWindowsSha256"],
            "primary/secondary GPT differ from signed plan")
    require(read_windows_file_hashes(overlay) == plan["windowsHashes"],
            "protected Windows files differ before post-pacstrap boot")
    before_root = _verify_installed_root(overlay, plan, plan["runId"])
    before_bcd = _read_bcd_readonly(overlay)
    require(hashlib.sha256(before_bcd).hexdigest()
            == plan["windowsHashes"]["espBcdSha256"],
            "preboot read-only BCD bytes differ from signed file hash")
    print("GASLUX_CACHYOS_WIN10_REENTRY_PREBOOT_GPT_FILES_ROOT_VERIFIED=1", flush=True)

    # Existing fourth-boot verifier enforces a single genuine Windows COM1
    # witness, clean QEMU shutdown and unchanged fifth ext4 UUID/GPT.
    boot = verify_windows_post_ext4(
        original, base, nvram, geometry, cow, staged, third, ext4,
        timeout=timeout, evidence_stem="sixth-post-pacstrap",
        tpm_socket=tpm_socket, trace_events_file=trace_events_file,
        trace_file=trace_file,
    )
    require(boot["windowsBootAfterExt4Verified"] is True
            and boot["fifthExt4UuidSurvivedWindowsBoot"] is True,
            "Windows did not boot with installed CachyOS root present")
    print("GASLUX_CACHYOS_WIN10_REENTRY_WINDOWS_BOOT_AND_EXT4_UUID_VERIFIED=1", flush=True)
    with tempfile.TemporaryDirectory(prefix="gaslux-postpacstrap-after-",
                                     dir=workspace) as scratch:
        after_front, after_back = gpt_windows(overlay, Path(scratch))
    require((after_front, after_back) == (front, back),
            "primary or backup GPT bytes changed after Windows re-entry")
    require(hashlib.sha256(after_front + after_back).hexdigest()
            == plan["gptWindowsSha256"],
            "postboot GPT windows no longer match signed plan")
    postboot_hashes = read_windows_file_hashes(overlay)
    protected_keys = (
        "espBootManagerSha256", "espBcdSha256",
        "windowsLoaderSha256", "winreImageSha256",
    )
    require(type(plan.get("windowsHashes")) is dict
            and set(plan["windowsHashes"]) == set(protected_keys)
            and type(postboot_hashes) is dict
            and set(postboot_hashes) == set(protected_keys),
            "postboot protected Windows hash manifest missing or unexpected")
    # Recheck installed root even if the Windows boot mutated its BCD.
    # Never turn a changed protected BCD hash into an accepted result.
    after_root = _verify_installed_root(overlay, plan, plan["runId"])
    require(before_root == after_root
            and sha256_file(base) == before_base
            and sha256_file(nvram) == before_nvram
            and qcow2_file_identity(base) == before_base_identity,
            "CachyOS root identity or protected Windows backing/NVRAM changed")
    print("GASLUX_CACHYOS_WIN10_REENTRY_POSTBOOT_NATIVE_ROOT_AND_BACKING_VERIFIED=1",
          flush=True)
    mismatches = [key for key in protected_keys
                  if postboot_hashes[key] != plan["windowsHashes"][key]]
    after_bcd = _read_bcd_readonly(overlay)
    require(hashlib.sha256(after_bcd).hexdigest()
            == postboot_hashes["espBcdSha256"],
            "postboot read-only BCD bytes differ from protected file hash")
    bcd_forensic = summarize_bcd_difference(before_bcd, after_bcd)
    if mismatches:
        diagnosis: dict[str, Any] = {
            "protectedFileHashMismatchKeys": mismatches,
            "postbootGptMatchesSignedPlan": True,
            "postbootInstalledRootAndBackingPreserved": True,
            "protectedFilesUnchanged": False,
            "windowsWithInstalledLinuxFullyVerified": False,
            "releaseEligible": False,
            "bcdReadOnlyForensic": bcd_forensic,
            "qemuWriteTraceSha256": boot.get("qemuWriteTraceSha256"),
            "qemuWriteTraceBytes": boot.get("qemuWriteTraceBytes"),
        }
        raise PostPacstrapWindowsError(
            "Windows protected file hash changed after Windows re-entry: "
            + mismatches[0], diagnostics=diagnosis)
    print("GASLUX_CACHYOS_WIN10_REENTRY_POSTBOOT_GPT_AND_WINDOWS_FILES_VERIFIED=1",
          flush=True)
    serial = workspace / "sixth-post-pacstrap-windows-serial.log"
    require(serial.is_file() and not serial.is_symlink(),
            "missing independent Windows re-entry witness")
    return {
        "windowsBootWithPacstrappedCachyosOnSameDiskVerified": True,
        "windowsPostPacstrapSerialSha256": sha256_file(serial),
        "installedCachyosRootSurvivedWindowsBoot": True,
        "windowsProtectedFilesAndGptAfterReentryUnchanged": True,
        "windowsBaseAndOriginalNvramAfterReentryUnchanged": True,
        "windowsEfiBootManagerUsed": True,
        "bcdReadOnlyForensic": bcd_forensic,
        "qemuWriteTraceSha256": boot.get("qemuWriteTraceSha256"),
        "qemuWriteTraceBytes": boot.get("qemuWriteTraceBytes"),
        "cachyosBootloaderInstalledToWindowsEsp": False,
        "sameDiskDualBootVerified": False,
        "updatesVerified": False,
        "rollbackProven": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Lab module only; requires authenticated disposable Windows QCOW2.")
