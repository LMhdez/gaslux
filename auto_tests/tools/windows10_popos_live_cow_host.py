#!/usr/bin/env python3
"""Windows COW -> official Pop live ISO read-only QEMU handoff experiment.

The true Windows QCOW2 is NEVER attached to Linux; only its exact child is,
and even that child is attached read-only. No install or rollback claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from windows10_popos_gpt_mirror_gate import (
    SECTOR, TOTAL_BYTES, WINDOW_SECTORS, WINDOW_BYTES,
    capture_owned_qcow2,
)
from windows10_popos_independent_esp_root_stage import reconcile_owned_pair
from windows_x64_installed_gpt_ro_audit import require

CONSENT = "I_ACCEPT_SIGNED_POP_ISO_READ_ONLY_GENUINE_WINDOWS_COW_VM"
ISO_SHA256 = "a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c"
HEX = re.compile("[0-9a-f]{64}\\Z")


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for data in iter(lambda: src.read(4 * 1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def gpt_windows_cow_live_manifest(
    before: dict, after: dict, plan: dict,
    front: bytes, back: bytes,
) -> dict:
    """Pure contract: two measured GPT windows never authorize disk writes."""
    require(
        len(front) == WINDOW_BYTES and len(back) == WINDOW_BYTES
        and type(before) is dict and type(after) is dict
        and type(plan) is dict,
        "invalid Windows/Pop host GPT window input",
    )
    reconcile_owned_pair(before, after, plan)
    import windows10_popos_gpt_mirror_gate as gpt
    observed = gpt.parse_windows_pop_gpt(front, back, expected_count=6)
    reconcile_owned_pair(before, observed, plan)
    require(
        observed["diskGuid"] == after["diskGuid"]
        and observed["windowsEntryHex"] == after["windowsEntryHex"]
        and observed["windowsPartitions"] == after["windowsPartitions"]
        and observed["popEsp"] == after["popEsp"]
        and observed["linuxRoot"] == after["linuxRoot"]
        and observed["mbrSha256"] == after["mbrSha256"],
        "Pop live handoff digest sampled foreign GPT layout",
    )
    return {
        "scenario": "pop-live-genuine-windows10-pair-readonly",
        "diskGuid": observed["diskGuid"],
        "diskSerial": "GASLUX_POP_WIN10_COW",
        "diskSizeBytes": TOTAL_BYTES,
        "frontMiBSha256": hashlib.sha256(front).hexdigest(),
        "backMiBSha256": hashlib.sha256(back).hexdigest(),
        "windowsFourEntriesSha256": hashlib.sha256(
            front[2*SECTOR:2*SECTOR + 4*128],
        ).hexdigest(),
        "popEspGuid": after["popEsp"]["guid"],
        "popRootGuid": after["linuxRoot"]["guid"],
        "expectedSectorBytes": SECTOR,
        "ownedIndexes": [5, 6],
        "windowsIndexes": [1, 2, 3, 4],
        "productionInstallationAuthorized": False,
    }


def _gpt_qcow2_window(overlay: Path, dest: Path, start: int) -> bytes:
    require(start in (0, TOTAL_BYTES // SECTOR - WINDOW_SECTORS)
            and not dest.exists() and not dest.is_symlink(),
            "invalid or reused GPT sampling output")
    args = ["qemu-img", "dd", "-f", "qcow2", "-O", "raw",
            f"bs={SECTOR}"]
    if start == 0:
        args.append(f"count={WINDOW_SECTORS}")
    args.extend((f"skip={start}", f"if={overlay}", f"of={dest}"))
    subprocess.run(args, check=True, capture_output=True, timeout=80)
    require(dest.is_file() and dest.stat().st_size == WINDOW_BYTES,
            "QEMU COW GPT sample truncated")
    return dest.read_bytes()


def run_official_pop_windows_cow_live_probe(
    overlay: Path, plan: dict, before: dict, after: dict,
    workspace: Path, evidence: Path,
) -> dict:
    """Only explicit hosted KVM, genuine post-Windows COW, signed pinned ISO."""
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GASLUX_POP_WIN10_LIVE_CONSENT") == CONSENT
        and workspace.parent == Path("/home/runner/work/_temp")
        and re.fullmatch(r"gaslux-win-x64-[a-z0-9_]+", workspace.name) is not None
        and overlay == workspace / "gaslux-pop-stage.qcow2"
        and overlay.is_file() and not overlay.is_symlink()
        and stat.S_ISREG(overlay.stat().st_mode)
        and overlay.stat().st_nlink == 1
        and evidence == Path(os.environ.get("GITHUB_WORKSPACE", "")) / "windows-x64-tcg-evidence"
        and evidence.is_dir() and not evidence.is_symlink(),
        "not an explicitly owned hosted Windows/Pop COW live experiment",
    )
    reconcile_owned_pair(before, after, plan)
    require(
        capture_owned_qcow2(overlay, expected_count=6) == after,
        "owned COW changed after genuine Windows reboot",
    )
    with tempfile.TemporaryDirectory(
        prefix="pop-gpt-", dir=workspace,
    ) as tmp:
        temp = Path(tmp)
        front = _gpt_qcow2_window(overlay, temp/"front.raw", 0)
        back = _gpt_qcow2_window(
            overlay, temp/"back.raw", TOTAL_BYTES//SECTOR - WINDOW_SECTORS,
        )
        manifest = gpt_windows_cow_live_manifest(
            before, after, plan, front, back,
        )
    path = workspace / "pop-live-six-gpt.json"
    with path.open("x", encoding="utf-8") as out:
        json.dump(manifest, out, sort_keys=True, indent=2)
    script = Path(os.environ.get("GITHUB_WORKSPACE", "")) / (
        "auto_tests/tools/windows10_popos_signed_live_cow_vm.sh"
    )
    require(script.is_file() and not script.is_symlink(),
            "tracked Pop live QEMU lab script missing")
    before_sha = _sha(overlay)
    subprocess.run(
        ["bash", str(script), str(overlay), str(path),
         str(workspace), str(evidence)],
        check=True, timeout=2700,
    )
    result = evidence / "pop-live-windows-cow-result.json"
    transcript = evidence / "pop-live-windows-cow-serial.trace"
    require(
        result.is_file() and not result.is_symlink()
        and result.stat().st_size <= 4096
        and transcript.is_file() and transcript.stat().st_size <= 9_000_000,
        "Pop genuine Windows live guest evidence absent or unbounded",
    )
    witness = json.loads(result.read_text("utf-8"))
    require(
        witness.get("pinnedPopIsoSha256") == ISO_SHA256
        and witness.get("officialSignedManifestVerified") is True
        and witness.get("popOfficialLiveIsoBootedSameWindowsCowReadOnly") is True
        and witness.get("sixGptPartitionGuestAudit") is True
        and witness.get("nativeDistinstExecuted") is False
        and witness.get("popInstalled") is False
        and witness.get("dualBootVerified") is False
        and witness.get("rollbackVerified") is False
        and _sha(overlay) == before_sha
        and capture_owned_qcow2(overlay, expected_count=6) == after,
        "Pop official live guest did not preserve Windows/Pop COW",
    )
    return {
        "popOfficialLiveIsoBootedSameWindowsCowReadOnly": True,
        "livePopVerifiedSha256": ISO_SHA256,
        "windowsCOWQcow2UnchangedByPopLive": True,
        "distinstExecutionAuthorized": False,
        "productionInstallationAuthorized": False,
        "sameDiskDualBootVerified": False,
        "rollbackVerified": False,
        "stable": False,
    }
