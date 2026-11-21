#!/usr/bin/env python3
"""Read-only qualification of a fixed, FREE GitHub-hosted Mint A/B lab.

No Windows Setup, QEMU guest boot, runner registration or paid resources.
A PASS is ONLY infrastructure readiness, never permission to install Windows.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess

from windows_mint_ab_capacity import (
    CapacityError,
    measure_capacity,
    qemu_fully_allocated_bytes,
)

PROFILE = "github-hosted-ubuntu-24.04-standard-observation-v1"
BRANCH = "refs/heads/test/mint-cow-ab-checkpoint-20261120"
ROOT = Path("/home/runner/work/_temp")
WORKSPACE = Path("/home/runner/work/gaslux/gaslux")
REPORT_NAME = "mint-ab-infrastructure.json"
OVMF_PAIRS = (
    ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"),
    ("OVMF_CODE.fd", "OVMF_VARS.fd"),
)
RESERVED = ("BLOCKED_CAPACITY", "PASS")


class QualificationError(RuntimeError):
    """Unsafe host identity or invalid, forged qualification input."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise QualificationError(reason)


def check_host_identity(env: dict[str, str], root: Path, repo: Path) -> dict:
    """Fail before filesystem probing if host/account/branch is ambiguous."""
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "LMhdez/gaslux",
        "GITHUB_REF": BRANCH,
        "RUNNER_OS": "Linux",
        "RUNNER_TEMP": str(ROOT),
        "GITHUB_WORKSPACE": str(WORKSPACE),
    }
    require(all(env.get(k) == v for k, v in expected.items())
            and re.fullmatch(r"[0-9]+", env.get("GITHUB_RUN_ID", "")) is not None
            and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", "")) is not None
            and platform.machine() == "x86_64",
            "wrong or unverified GitHub-hosted A/B qualification identity")
    for candidate in (root, repo):
        require(candidate.is_dir() and not candidate.is_symlink()
                and candidate.stat().st_uid == os.getuid()
                and (stat.S_IMODE(candidate.stat().st_mode) & 0o002) == 0,
                "foreign, writable-by-others or symlinked qualification directory")
    return {
        "runId": env["GITHUB_RUN_ID"],
        "sourceCommit": env["GITHUB_SHA"],
        "profile": PROFILE,
        "hostedAccount": "LMHDEZ",
        "repository": "LMhdez/gaslux",
        "ubuntuRunnerLabel": "ubuntu-24.04",
    }


def exclusive_storage_probe(root: Path, run_id: str) -> bool:
    """Create and delete a single private scratch byte, not a guest image."""
    require(root == ROOT and re.fullmatch(r"[0-9]+", run_id) is not None,
            "unapproved exclusive-file scratch location")
    work = root / ("gaslux-mint-ab-probe-" + run_id)
    require(not work.exists() and not work.is_symlink(),
            "reused or foreign qualification probe")
    work.mkdir(mode=0o700)
    try:
        require(stat.S_IMODE(work.stat().st_mode) == 0o700
                and work.stat().st_dev == root.stat().st_dev,
                "private qualification scratch is not on target filesystem")
        file = work / "owned-probe"
        with file.open("xb") as handle:
            handle.write(b"Q")
            handle.flush()
            os.fsync(handle.fileno())
        meta = file.lstat()
        require(stat.S_ISREG(meta.st_mode)
                and meta.st_uid == os.getuid() and meta.st_nlink == 1
                and meta.st_dev == root.stat().st_dev
                and file.read_bytes() == b"Q",
                "exclusive file ownership/identity failed")
        file.unlink()
        return True
    finally:
        # The sole owned private probe directory can be removed, nothing else.
        work.rmdir()


def tool_available(name: str) -> bool:
    path = shutil.which(name)
    return bool(path and Path(path).is_file() and os.access(path, os.X_OK))


def ovmf_available() -> bool:
    prefix = Path("/usr/share/OVMF")
    for code, vars_file in OVMF_PAIRS:
        p, q = prefix / code, prefix / vars_file
        try:
            if (
                all(
                    x.is_file() and not x.is_symlink() and os.access(x, os.R_OK)
                    for x in (p, q)
                )
                and p.stat().st_size > 1048576
                and q.stat().st_size >= 65536
            ):
                return True
        except OSError:
            continue
    return False


def kvm_accessible() -> bool:
    p = Path("/dev/kvm")
    try:
        return (not p.is_symlink()
                and stat.S_ISCHR(p.stat().st_mode)
                and os.access(p, os.R_OK | os.W_OK))
    except OSError:
        return False


def _capacity_is_proven(capacity: dict | None) -> bool:
    from windows_mint_ab_capacity import EARLY_IMAGES, EARLY_RESERVE
    from windows_cachyos_qcow2_gpt_readonly import VIRTUAL_BYTES
    if not isinstance(capacity, dict):
        return False
    values = (
        "qemuFullyAllocatedImageBytes", "minimumFreeBytesRequired",
        "effectiveAvailableBytes", "processAvailableBytes",
        "capacityShortfallBytes",
    )
    if any(type(capacity.get(key)) is not int for key in values):
        return False
    full = capacity["qemuFullyAllocatedImageBytes"]
    required = EARLY_IMAGES * full + EARLY_RESERVE
    return (
        capacity.get("schema") == "gaslux-mint-ab-capacity-v1"
        and capacity.get("phase") == "early"
        and capacity.get("compressionAssumedForCapacity") is False
        and capacity.get("worstCaseRemainingStandaloneImagesAndRestores")
        == EARLY_IMAGES
        and full >= VIRTUAL_BYTES
        and capacity["minimumFreeBytesRequired"] == required
        and capacity["effectiveAvailableBytes"] >= required
        and capacity["processAvailableBytes"] >= required
        and capacity["capacityShortfallBytes"] == 0
        and capacity.get("result") == "PASS"
    )


def classify(*, identity: dict, capacity: dict | None,
             tools: dict[str, bool], kvm: bool, ovmf: bool,
             private_files: bool, quota_observed: bool) -> dict:
    """One bounded public report. Unknown quota is never a proof of PASS."""
    failed = []
    if not _capacity_is_proven(capacity):
        failed.append("capacity_not_demonstrated")
    if not quota_observed:
        failed.append("effective_quota_not_demonstrated")
    if not all(tools.values()):
        failed.append("required_qemu_tools_missing")
    if not kvm:
        failed.append("unprivileged_kvm_not_accessible")
    if not ovmf:
        failed.append("ovmf_not_accessible")
    if not private_files:
        failed.append("exclusive_scratch_not_proven")
    result = "BLOCKED_CAPACITY" if failed else "PASS"
    report = {
        "schema": "gaslux-mint-ab-infrastructure-qualification-v1",
        **identity,
        "result": result,
        "failedConditions": failed,
        "capacityBytes": {
            key: capacity.get(key) if capacity is not None else None
            for key in (
                "filesystemTotalBytes", "filesystemFreeBytes",
                "processAvailableBytes", "quotaRemainingBytes",
                "qemuFullyAllocatedImageBytes", "minimumFreeBytesRequired",
                "nonImageReserveBytes", "capacityShortfallBytes",
            )
        },
        "quotaProven": quota_observed,
        "toolsPresent": tools,
        "kvmCharacterDeviceAccessibleUnprivileged": kvm,
        "ovmfFirmwarePresentReadable": ovmf,
        "privateExclusiveFileProbePassed": private_files,
        "runnerIsDedicatedToThisJob": "GitHub-hosted ephemeral, not independently audited",
        "writesPerformed": "one private scratch byte only",
        "realWindowsSetupExecuted": False,
        "mintRootBootVerified": False,
        "productionInstallAuthorized": False,
        "windowsGuestBootsAuthorized": False,
        "checkpointReadyForReview": False,
        "storageWritesAuthorized": False,
        "releaseEligible": False,
    }
    require(result in RESERVED and len(json.dumps(report)) < 8192,
            "qualification report not bounded")
    return report


def qualify() -> dict:
    identity = check_host_identity(os.environ, ROOT, WORKSPACE)
    tools = {name: tool_available(name)
             for name in ("qemu-img", "qemu-io", "qemu-system-x86_64")}
    capacity = None
    if tools["qemu-img"]:
        try:
            capacity = measure_capacity(
                directory=ROOT, phase="early",
                full_allocated_bytes=qemu_fully_allocated_bytes(),
            )
        except (OSError, subprocess.CalledProcessError, ValueError, CapacityError):
            pass
    # No assumption that an unknown quota can be spent. It is only recorded
    # as unknown; a hosting plan or a paid larger runner is NEVER inferred.
    quota_observed = bool(
        capacity is not None and capacity.get("quotaStatus") == "measured"
    )
    private_files = exclusive_storage_probe(ROOT, identity["runId"])
    return classify(
        identity=identity, capacity=capacity, tools=tools,
        kvm=kvm_accessible(), ovmf=ovmf_available(),
        private_files=private_files, quota_observed=quota_observed,
    )


def main() -> None:
    report = qualify()
    destination = WORKSPACE / "windows-x64-tcg-evidence"
    require(destination.is_dir() and not destination.is_symlink()
            and destination.stat().st_uid == os.getuid(),
            "unknown qualification evidence directory")
    # Publish one exclusive, small read-only diagnostic JSON.
    # No Windows media, full disk paths, environmental secrets or GUIDs.
    record = destination / REPORT_NAME
    require(not record.exists() and not record.is_symlink(), "reused report")
    # Restrict output to one owned directory; no generic configurable path.
    with record.open("xb") as fp:
        fp.write((json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
        fp.flush()
        os.fsync(fp.fileno())
    require(record.stat().st_uid == os.getuid()
            and record.stat().st_nlink == 1
            and record.stat().st_size < 16384, "invalid qualification artifact")
    print("GASLUX_MINT_AB_INFRA_RESULT=" + report["result"])
    print("GASLUX_MINT_AB_INFRA_REPORT=" + json.dumps(report, sort_keys=True))
    print("Qualification NEVER authorizes real Windows Setup or paid runners")


if __name__ == "__main__":
    main()
