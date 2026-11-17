#!/usr/bin/env python3
"""Issue #3: sign an inert Archiso plan for a verified Windows 10 QCOW2 COW.

No write permission to the shared disk is ever granted. Only the exact,
already-verified COW file can be inspected read-only through libguestfs.
The ephemeral Ed25519 private key is local to the disposable runner, never
copied into the guest or uploaded with evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import uuid

from cachyos_windows_shared_archiso_handoff import (
    ISO_SHA256, SERIAL, VIRTUAL_BYTES, ROLES, canonical, validate_plan,
)
from cachyos_windows_shared_gpt_raw_audit import inspect_bound_gpt_windows
from windows_cachyos_overlay_reboot import gpt_windows
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular,
    require as checkpoint_require, sha256_file,
)

class ReadonlyLabError(ValueError):
    pass


def require(ok: bool, explanation: str) -> None:
    if not ok:
        raise ReadonlyLabError(explanation)


def read_windows_file_hashes(cow: Path) -> dict[str, str]:
    """Host libguestfs uses only read-only mounts; fail if WinRE/BCD is absent."""
    import guestfs
    g = guestfs.GuestFS(python_return_dict=True)
    result: dict[str, str] = {}
    try:
        g.add_drive_opts(str(cow), format="qcow2", readonly=1)
        g.launch()
        devices = g.list_devices()
        require(len(devices) == 1 and
                g.blockdev_getsize64(devices[0]) == VIRTUAL_BYTES,
                "read-only Windows guestfs disk identity/size invalid")
        parts = g.list_partitions()
        require(len(parts) == 5, "unexpected Windows+CachyOS partition count")
        for index, names in (
            (0, {"espBootManagerSha256": "/EFI/Microsoft/Boot/bootmgfw.efi",
                 "espBcdSha256": "/EFI/Microsoft/Boot/BCD"}),
            (2, {"windowsLoaderSha256": "/Windows/System32/winload.efi"}),
            (3, {"winreImageSha256": "/Recovery/WindowsRE/Winre.wim"}),
        ):
            g.mount_ro(parts[index], "/")
            try:
                for name, path in names.items():
                    require(g.is_file(path), "missing protected Windows file: " + name)
                    digest = g.checksum("sha256", path)
                    require(type(digest) is str and len(digest) == 64 and
                            digest != "0" * 64, "invalid actual Windows file hash")
                    result[name] = digest
            finally:
                g.umount_all()
    finally:
        try:
            g.shutdown()
        finally:
            g.close()
    require(len(result) == 4, "incomplete real Windows hash evidence")
    return result


def prepare(cow: Path, workspace: Path, expected_root_uuid: str,
            expected_root_partuuid: str, pinned_iso: str,
            windows_fourth_verified: bool) -> dict[str, str]:
    """Build signature and inert plan, never accessing a physical block disk."""
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux" and
            os.environ.get("GASLUX_CACHYOS_ARCHISO_READONLY_CONSENT")
              == "I_ACCEPT_PINNED_ARCHISO_READONLY_WINDOWS10_QCOW2_COW",
            "hosted Archiso read-only Windows COW consent required")
    require(windows_fourth_verified is True and pinned_iso == ISO_SHA256,
            "real Windows fourth boot or official ISO pin missing")
    require(type(expected_root_uuid) is str and
            type(expected_root_partuuid) is str, "root identity missing")
    require(cow.is_absolute() and not cow.is_symlink() and cow.is_file()
            and cow.name == OVERLAY_NAME
            and cow.parent.name == CHECKPOINT_DIR
            and stat.S_IMODE(cow.stat().st_mode) == 0o600
            and workspace.is_absolute() and workspace.is_dir()
            and not workspace.is_symlink()
            and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
            "unsafe disposable COW or signing directory")
    owned_regular(cow, cow.parent, OVERLAY_NAME)
    base = cow.parent.parent / "only-disposable-windows-target.qcow2"
    require(base.is_file() and not base.is_symlink()
            and stat.S_IMODE(base.stat().st_mode) == 0o400,
            "protected Windows backing missing")
    info = json.loads(subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(cow)],
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout)
    require(info.get("format") == "qcow2"
            and info.get("virtual-size") == VIRTUAL_BYTES
            and info.get("backing-filename") == str(base)
            and info.get("backing-filename-format") == "qcow2"
            and not info.get("encrypted", False),
            "Windows COW backing path/size differs")
    backing_digest = sha256_file(base)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gaslux-signed-windows-gpt-",
                                     dir=cow.parent.parent) as tmp:
        front, back = gpt_windows(cow, Path(tmp))
    rows = []
    for index in range(5):
        raw = front[1024 + index * 128:1024 + (index+1) * 128]
        lo, hi = struct.unpack_from("<QQ", raw, 32)
        rows.append({
            "index": index+1, "role": ROLES[index],
            "typeGuid": str(uuid.UUID(bytes_le=raw[:16])),
            "uniqueGuid": str(uuid.UUID(bytes_le=raw[16:32])),
            "firstLba": lo, "lastLba": hi,
        })
    require(rows[4]["uniqueGuid"] == expected_root_partuuid,
            "fifth PARTUUID no longer matches Windows checkpoint")
    windows = read_windows_file_hashes(cow)
    run_id = "gaslux-archiso-" + secrets.token_hex(12)
    nonce = secrets.token_hex(16)
    plan = {
        "schemaVersion": 1,
        "backend": "archiso-cachyos-windows-cow-lab",
        "distribution": "cachyos", "labOnly": True,
        "runId": run_id, "bootNonce": nonce,
        "firmware": "uefi", "partitionStyle": "gpt",
        "secureBootEnabled": False, "writeAuthority": False,
        "targetVirtioSerial": SERIAL,
        "diskVirtualBytes": VIRTUAL_BYTES, "logicalSectorBytes": 512,
        "diskGuidSha256": hashlib.sha256(front[568:584]).hexdigest(),
        "gptWindowsSha256": hashlib.sha256(front + back).hexdigest(),
        "isoSha256": ISO_SHA256,
        "rootFsUuid": expected_root_uuid, "partitions": rows,
        "windowsHashes": windows,
    }
    validate_plan(plan)
    inspect_bound_gpt_windows(front, back, plan)
    require(sha256_file(base) == backing_digest,
            "protected Windows backing changed during read-only measurement")
    for fname in ("plan.json", "plan.sig", "public.pem", "private.pem"):
        require(not (workspace / fname).exists(), "refusing reused signer state")
    (workspace / "plan.json").write_bytes(canonical(plan))
    private_key = workspace / "private.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(private_key)], check=True, timeout=15,
                   stdout=subprocess.DEVNULL)
    os.chmod(private_key, 0o600)
    subprocess.run(["openssl", "pkey", "-in", str(private_key),
                    "-pubout", "-out", str(workspace / "public.pem")],
                   check=True, timeout=15, stdout=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                    str(private_key), "-rawin", "-in",
                    str(workspace / "plan.json"), "-out",
                    str(workspace / "plan.sig")],
                   check=True, timeout=15, stdout=subprocess.DEVNULL)
    return {
        "runId": run_id, "bootNonce": nonce,
        "rootUuid": expected_root_uuid, "rootPartuuid": expected_root_partuuid,
        "planSha256": sha256_file(workspace / "plan.json"),
        "pubSha256": sha256_file(workspace / "public.pem"),
        "windowsBackingSha256": backing_digest,
        "pacstrapAuthorized": False,
        "storageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: invoked by validated Windows fourth-boot workflow")
