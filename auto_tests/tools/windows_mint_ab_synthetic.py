#!/usr/bin/env python3
"""Small, fixed GPT synthetic A/B experiment; NEVER a Windows guest.

Own 64-MiB file with its own five-partition GPT, separate standalone qcow2
arms, exclusive OVMF copies and the SAME verified atomic restore helper as
the genuine Windows path. Does not install or boot any operating system.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

from windows_mint_ab_checkpoint import (
    atomic_restore_owned_arm,
    clone_vars,
    command,
    equivalent,
    file_guard,
    image_info,
    require,
    sha256_file,
    standalone,
)

MiB = 1024 * 1024
SECTOR = 512


@dataclass(frozen=True)
class FixedSyntheticProfile:
    name: str = "mint-ab-fixed-synthetic-gpt-64m-v1"
    virtual_bytes: int = 64 * MiB
    fifth_first_lba: int = 61440
    fifth_last_lba: int = 77823
    scratch_bytes: int = 4096


PROFILE = FixedSyntheticProfile()


def validate_profile(profile: FixedSyntheticProfile) -> None:
    require(
        type(profile) is FixedSyntheticProfile
        and profile == PROFILE
        and profile.virtual_bytes == 64 * MiB
        and profile.fifth_first_lba == 61440
        and profile.fifth_last_lba == 77823
        and profile.scratch_bytes == 4096,
        "unsupported or forged synthetic GPT profile",
    )


def validate_scratch(last_lba: int, profile: FixedSyntheticProfile) -> int:
    """Use exactly the fifth partition end reported by sgdisk validation."""
    validate_profile(profile)
    require(type(last_lba) is int and last_lba == profile.fifth_last_lba,
            "synthetic GPT fifth partition end changed")
    after_fifth = (last_lba + 1) * SECTOR + MiB
    offset = ((after_fifth + MiB - 1) // MiB) * MiB
    require(
        offset > last_lba * SECTOR
        and offset + profile.scratch_bytes < profile.virtual_bytes - 34 * SECTOR,
        "synthetic scratch overlaps partition or backup GPT",
    )
    return offset


def _run(arguments: list[str]) -> str:
    return subprocess.run(
        arguments, check=True, capture_output=True, text=True, timeout=120
    ).stdout


def generate_private_gpt(raw: Path, directory: Path) -> tuple[int, str]:
    require(raw.parent == directory and not raw.exists()
            and not raw.is_symlink(), "foreign synthetic disk source")
    fd = os.open(raw, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        os.ftruncate(fd, PROFILE.virtual_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)
    file_guard(raw, directory, 0o600)
    _run([
        "sgdisk", "-o",
        "-n", "1:2048:18431", "-t", "1:ef00",
        "-n", "2:18432:20479", "-t", "2:0c01",
        "-n", "3:20480:53247", "-t", "3:0700",
        "-n", "4:53248:61439", "-t", "4:2700",
        "-n", "5:61440:77823", "-t", "5:8300",
        str(raw),
    ])
    _run(["sgdisk", "-v", str(raw)])
    item = _run(["sgdisk", "-i", "5", str(raw)])
    match = re.search(r"Last sector:\\s*(\\d+)", item)
    require(match is not None, "synthetic GPT sector inspection unavailable")
    last_lba = int(match.group(1))
    validate_scratch(last_lba, PROFILE)
    return last_lba, sha256_file(raw)


def _ovmf_source() -> Path:
    base = Path("/usr/share/OVMF")
    for name in ("OVMF_VARS_4M.fd", "OVMF_VARS.fd"):
        candidate = base / name
        try:
            actual = candidate.resolve(strict=True)
            if (actual.parent == base and actual.is_file()
                    and actual.stat().st_size >= 1024 * 1024):
                return actual
        except OSError:
            pass
    raise RuntimeError("no usable packaged OVMF_VARs file for synthetic probe")


def synthetic_full_bound() -> int:
    output = json.loads(_run([
        "qemu-img", "measure", "--output=json", "-O", "qcow2",
        "--size", str(PROFILE.virtual_bytes),
    ]))
    size = output.get("fully-allocated")
    require(type(size) is int and size >= PROFILE.virtual_bytes,
            "synthetic QCOW2 full allocation size unknown")
    return size


def arm_fault_and_restore(
    reference: Path, arm: Path, other: Path, directory: Path,
    *, offset: int, full_bound: int,
) -> None:
    require(
        0 < offset < PROFILE.virtual_bytes - PROFILE.scratch_bytes,
        "synthetic scratch bounds unknown",
    )
    untouched_digest = sha256_file(other)
    reference_digest = sha256_file(reference)
    command([
        "qemu-io", "-f", "qcow2", "-c",
        f"write -P 0xa5 {offset} {PROFILE.scratch_bytes}", str(arm),
    ], timeout=60)
    changed = command(
        ["qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
         str(reference), str(arm)],
        timeout=180, check=False,
    )
    require(changed.returncode == 1,
            "synthetic arm corruption was not independently observed")
    require(
        sha256_file(other) == untouched_digest
        and sha256_file(reference) == reference_digest,
        "synthetic control/treatment images were not independent",
    )
    atomic_restore_owned_arm(
        reference, arm, directory,
        expected_virtual_bytes=PROFILE.virtual_bytes,
        fully_allocated_bound=full_bound,
    )
    equivalent(reference, arm)
    require(
        sha256_file(other) == untouched_digest
        and sha256_file(reference) == reference_digest,
        "synthetic atomic restore mutated the other arm/reference",
    )


def restore_ovmf(source: Path, copy: Path, directory: Path) -> None:
    """Never destroy a VARS arm until its owned replacement is verified."""
    temp = directory / (copy.name + ".restore.tmp")
    clone_vars(source, temp, directory)
    file_guard(copy, directory, 0o600)
    require(sha256_file(temp) == sha256_file(source),
            "synthetic OVMF replacement differs")
    os.replace(temp, copy)
    require(sha256_file(copy) == sha256_file(source),
            "synthetic OVMF atomic restore failed")


def run_fixed_synthetic() -> dict:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REF")
        == "refs/heads/test/mint-cow-ab-checkpoint-20261120"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and os.environ.get("GASLUX_MINT_AB_SYNTHETIC_CONSENT")
        == "I_ACCEPT_64M_PRIVATE_SYNTHETIC_GPT_AB_ONLY",
        "no fixed disposable synthetic CI laboratory consent",
    )
    validate_profile(PROFILE)
    work_root = Path(os.environ["RUNNER_TEMP"])
    require(
        work_root.is_dir() and not work_root.is_symlink()
        and work_root.stat().st_uid == os.getuid(),
        "foreign synthetic scratch filesystem",
    )
    with tempfile.TemporaryDirectory(
        prefix="gaslux-mint-ab-synthetic-gpt-", dir=work_root
    ) as temp:
        directory = Path(temp)
        require(
            stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "synthetic A/B scratch not private",
        )
        raw = directory / "synthetic-gpt.raw"
        last, raw_hash = generate_private_gpt(raw, directory)
        offset = validate_scratch(last, PROFILE)
        source = directory / "source.qcow2"
        _run([
            "qemu-img", "convert", "-f", "raw", "-O", "qcow2",
            str(raw), str(source),
        ])
        source.chmod(0o600)
        image_info(source, PROFILE.virtual_bytes)
        reference = directory / "reference.qcow2"
        a, b = directory / "arm-a.qcow2", directory / "arm-b.qcow2"
        standalone(source, reference, directory, PROFILE.virtual_bytes)
        reference.chmod(0o400)
        for arm in (a, b):
            standalone(reference, arm, directory, PROFILE.virtual_bytes)
            image_info(arm, PROFILE.virtual_bytes)
            equivalent(reference, arm)
        require(
            len({x.stat().st_ino for x in (reference, a, b)}) == 3,
            "synthetic A/B images alias",
        )
        original_vars = directory / "original-ovmf-vars.fd"
        with _ovmf_source().open("rb") as inp, original_vars.open("xb") as out:
            shutil.copyfileobj(inp, out)
            out.flush()
            os.fsync(out.fileno())
        original_vars.chmod(0o600)
        va = directory / "arm-a-vars.fd"
        vb = directory / "arm-b-vars.fd"
        for copy in (va, vb):
            clone_vars(original_vars, copy, directory)
        initial_vars_hash = sha256_file(original_vars)
        full_bound = synthetic_full_bound()
        arm_fault_and_restore(reference, a, b, directory,
                              offset=offset, full_bound=full_bound)
        arm_fault_and_restore(reference, b, a, directory,
                              offset=offset, full_bound=full_bound)
        for copy in (va, vb):
            with copy.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"SYNTHETIC_FIRMWARE_STATE_CHANGE")
                handle.flush()
                os.fsync(handle.fileno())
            require(sha256_file(copy) != initial_vars_hash,
                    "synthetic OVMF changed-state witness absent")
            restore_ovmf(original_vars, copy, directory)
        all_ok = (
            all(sha256_file(x) == initial_vars_hash for x in (va, vb))
            and all(
                sha256_file(x) == sha256_file(reference)
                for x in (a, b)
            )
        )
        require(all_ok, "synthetic A/B recovery hashes did not match")
        return {
            "schema": "gaslux-mint-fixed-synthetic-ab-recovery-v1",
            "transactionId": str(uuid.uuid4()),
            "runId": os.environ.get("GITHUB_RUN_ID"),
            "sourceCommit": os.environ.get("GITHUB_SHA"),
            "profile": PROFILE.name,
            "syntheticVirtualBytes": PROFILE.virtual_bytes,
            "partitionCount": 5,
            "fifthPartitionLastLba": last,
            "scratchOffsetBytes": offset,
            "referenceSha256": sha256_file(reference),
            "rawFixtureSha256": raw_hash,
            "originalOvmfVarsSha256": initial_vars_hash,
            "threeStandaloneIndependentQcowsVerified": True,
            "bothArmsCorruptedAndRestoredAtomically": True,
            "initialAndRestoredOvmfArmHashesIdentical": True,
            "noGuestBootOccurred": True,
            "realWindowsBootVerified": False,
            "realMintBootVerified": False,
            "productionInstallAuthorized": False,
            "releaseEligible": False,
        }


if __name__ == "__main__":
    result = run_fixed_synthetic()
    print("GASLUX_MINT_AB_FIXED_SYNTHETIC=" + json.dumps(
        result, sort_keys=True
    ))
