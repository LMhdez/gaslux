"""Real *paused* QEMU + disposable FAT32 ESP/GPT file descriptor evidence.

Runs only in explicitly scoped GitHub-hosted CI. No guest/Windows boots, ETW,
Archiso, pacstrap, NVRAM, KVM or physical device accesses. Microsoft EFI file
is a clearly labeled synthetic *sentinel*, NOT a genuine Windows loader.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import cachyos_bcd_fat32_offline as fat

from auto_tests.installer_observer.host_qemu_fd_evidence import borrowed_readonly_proc_fd
from auto_tests.installer_observer.qemu_local_disk_witness import (
    QemuDiskRefused,
    QemuLocalDiskWitness,
)
# Reuse, not copy, the exact pinned dev QEMU supervisor test helpers.
# Candidate auto_tests is a different package root from observer-dev.
DEV_ROOT = Path(os.environ.get("GITHUB_WORKSPACE", "/nonexistent")) / "observer-dev"
sys.path.insert(0, str(DEV_ROOT / "auto_tests" / "tests"))
from test_observer_qemu_real_disk_readonly import (  # noqa: E402
    load, make_qcow, pins_for, shutdown, start_qemu,
)

DISK_BYTES = 64 * 1024 * 1024
ESP_START = 2048
ESP_SECTORS = 69300
ESP_END = ESP_START + ESP_SECTORS - 1
ESP_BYTES = ESP_SECTORS * 512
SECTOR = 512
BOOT_SENTINEL = b"MZ" + b"NOT_AN_AUTHENTIC_MICROSOFT_WINDOWS_LOADER" + b"\0" * 984
BCD_SENTINEL = b"regf" + b"\0" * (4096 - 4)
PIN286 = "9aed36cfdb8c09a461dc38811c326c54180273de"
PIN267 = "0be04192acd542646a5b6cd952e01620379edf5d"


def run(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(
        list(args), text=True, capture_output=True, timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, (
        "disposable image tool failed: " + str(args[0]) +
        " status=" + str(result.returncode) + " stderr=" + result.stderr[-1000:]
    )
    return result.stdout


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()


def require_hosted() -> None:
    assert os.environ.get("GASLUX_QEMU_NO_GUEST") == "1"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
    assert os.environ.get("RUNNER_OS") == "Linux"
    assert os.getuid() != 0
    assert os.path.exists("/usr/bin/qemu-system-x86_64")
    for tool in ("mkfs.fat", "mmd", "mcopy", "sgdisk", "qemu-img"):
        assert shutil.which(tool), tool


def pinned_parsers():
    root286 = Path(os.environ["GASLUX_QEMU_PIN286_ROOT"]).resolve(strict=True)
    root267 = Path(os.environ["GASLUX_QEMU_PIN267_ROOT"]).resolve(strict=True)
    for root, sha in ((root286, PIN286), (root267, PIN267)):
        assert run("git", "-C", str(root), "rev-parse", "HEAD").strip() == sha
        assert run("git", "-C", str(root), "status", "--porcelain").strip() == ""
    gate = load("libertix_disk_identity_gate_cachyos", root286 /
                "assets/live/libertix_disk_identity_gate.py")
    sys.path.insert(0, str(root267 / "assets/live"))
    try:
        safety = load("safety_cachyos_real_qemu", root267 /
                      "auto_tests/tools/safety_qemu_gpt_host_guest.py")
    finally:
        sys.path.remove(str(root267 / "assets/live"))
    return gate, safety


def create_synthetic_esp(workspace: Path) -> tuple[Path, str, str]:
    volume = workspace / "synthetic-esp-fat32.img"
    with volume.open("xb") as out:
        out.truncate(ESP_BYTES)
    run("mkfs.fat", "-F", "32", "-S", "512", "-s", "1",
        "-R", "32", "-f", "2", "-n", "GASLUXESP", str(volume))
    target = str(volume)
    for directory in ("::/EFI", "::/EFI/Microsoft", "::/EFI/Microsoft/Boot"):
        run("mmd", "-i", target, directory)
    bcd = workspace / "dummy-regf-not-windows-bcd.bin"
    loader = workspace / "dummy-not-microsoft-bootmgfw.efi"
    bcd.write_bytes(BCD_SENTINEL)
    loader.write_bytes(BOOT_SENTINEL)
    run("mcopy", "-i", target, str(bcd), "::/EFI/Microsoft/Boot/BCD")
    run("mcopy", "-i", target, str(loader),
        "::/EFI/Microsoft/Boot/bootmgfw.efi")
    # mtools may update primary FSInfo but leave the spec's backup FSInfo
    # behind. Reconcile them only while BUILDING this private test fixture.
    with volume.open("r+b") as stream:
        boot = stream.read(512)
        fsinfo = int.from_bytes(boot[48:50], "little")
        backup_boot = int.from_bytes(boot[50:52], "little")
        assert fsinfo > 0 and backup_boot > 0
        stream.seek(fsinfo * 512)
        primary = stream.read(512)
        stream.seek((backup_boot + fsinfo) * 512)
        stream.write(primary)
    esp = volume.read_bytes()
    assert len(esp) == ESP_BYTES
    # This is the existing checked FAT32 parser, NOT a new one.
    mapped = fat.map_bcd_fat32(
        esp, esp_start_lba=ESP_START,
        esp_end_lba=ESP_END, disk_bytes=DISK_BYTES,
    )
    assert mapped["bcdSizeBytes"] == len(BCD_SENTINEL)
    assert sum(x["length"] for x in mapped["bcdDataExtents"]) == len(BCD_SENTINEL)
    assert mapped["imageProvenanceAuthenticated"] is False
    restored_bcd = workspace / "readback-bcd.bin"
    restored_loader = workspace / "readback-loader.bin"
    run("mcopy", "-i", target, "::/EFI/Microsoft/Boot/BCD", str(restored_bcd))
    run("mcopy", "-i", target, "::/EFI/Microsoft/Boot/bootmgfw.efi",
        str(restored_loader))
    assert restored_bcd.read_bytes() == BCD_SENTINEL
    assert restored_loader.read_bytes() == BOOT_SENTINEL
    assert restored_loader.read_bytes().startswith(b"MZ")
    return volume, file_sha(volume), file_sha(restored_loader)


def create_owned_raw(workspace: Path, esp: Path) -> Path:
    raw = workspace / "disk.raw"
    with raw.open("xb") as out:
        out.truncate(DISK_BYTES)
    disk_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-cachyos-real-qemu-synthetic-disk"))
    part_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, "gaslux-cachyos-real-qemu-synthetic-esp"))
    run("sgdisk", "--clear", f"--new=1:{ESP_START}:{ESP_END}",
        "--typecode=1:EF00", f"--disk-guid={disk_guid}",
        f"--partition-guid=1:{part_guid}", str(raw))
    assert raw.stat().st_size == DISK_BYTES
    with raw.open("r+b") as target:
        target.seek(ESP_START * SECTOR)
        with esp.open("rb") as source:
            shutil.copyfileobj(source, target, 1048576)
        target.flush()
        os.fsync(target.fileno())
    return raw


def read_exact_gpt_esp(fd: int, gate, baseline: dict, expected_esp: str) -> dict:
    stat_before = os.fstat(fd)
    gate.assert_snapshot_matches(
        baseline, gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
    )
    assert baseline["partitionTableId"] is not None
    esp = os.pread(fd, ESP_BYTES, ESP_START * SECTOR)
    assert len(esp) == ESP_BYTES
    assert hashlib.sha256(esp).hexdigest() == expected_esp
    mapped = fat.map_bcd_fat32(
        esp, esp_start_lba=ESP_START,
        esp_end_lba=ESP_END, disk_bytes=DISK_BYTES,
    )
    bcd_bytes = b"".join(
        os.pread(fd, extent["length"], extent["diskOffset"])
        for extent in mapped["bcdDataExtents"]
    )
    assert bcd_bytes == BCD_SENTINEL
    assert len(os.pread(fd, ESP_BYTES, ESP_START * SECTOR)) == ESP_BYTES
    assert os.pread(fd, ESP_BYTES, ESP_START * SECTOR) == esp
    gate.assert_snapshot_matches(
        baseline, gate.inspect_gpt_fd(fd, logical_sector_size=SECTOR)
    )
    stat_after = os.fstat(fd)
    assert (
        stat_before.st_dev, stat_before.st_ino, stat_before.st_size,
        stat_before.st_ctime_ns, stat_before.st_mtime_ns,
    ) == (
        stat_after.st_dev, stat_after.st_ino, stat_after.st_size,
        stat_after.st_ctime_ns, stat_after.st_mtime_ns,
    )
    return {
        "espSha256": hashlib.sha256(esp).hexdigest(),
        "bcdFileSha256": hashlib.sha256(bcd_bytes).hexdigest(),
        "gptDiskGuid": baseline["partitionTableId"],
        "espPartuuid": baseline["partitions"][0]["partGuid"],
        "bcdDataExtentCount": len(mapped["bcdDataExtents"]),
        "bcdIsFragmented": mapped["bcdFragmented"],
        "gptFromOpenedFdMeasured": True,
        "historicalEspSourceAuthenticated": False,
    }


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux procfs only")
def test_actual_stopped_qemu_raw_qcow2_fat32_gpt_readonly(tmp_path):
    require_hosted()
    root = tmp_path.resolve(strict=True)
    root.chmod(0o700)
    assert root.owner() and root.stat().st_uid == os.getuid()
    gate, safety = pinned_parsers()
    esp, esp_hash, loader_hash = create_synthetic_esp(root)
    raw = create_owned_raw(root, esp)
    baseline = gate.inspect_gpt_image(raw, logical_sector_size=SECTOR)
    assert len(baseline["partitions"]) == 1
    assert baseline["partitions"][0]["offsetBytes"] == ESP_START * SECTOR
    assert baseline["partitions"][0]["sizeBytes"] == ESP_BYTES
    raw_before = file_sha(raw)
    assert len(raw_before) == 64
    run("qemu-img", "info", "-f", "raw", str(raw))
    child = start_qemu(root, raw, "raw")
    try:
        pins = pins_for(child, root, raw, "raw")
        with QemuLocalDiskWitness(pins) as observer:
            # Exact existing HOST/FD witness must refuse wrong inode and
            # ambiguous QMP identity while the genuine QEMU is still alive.
            with pytest.raises(QemuDiskRefused):
                QemuLocalDiskWitness(replace(pins, media_inode=pins.media_inode + 1))
            with pytest.raises(QemuDiskRefused):
                QemuLocalDiskWitness(replace(pins, qmp_device="foreign-device"))
            # The inherited HOST/FD module reads the real QEMU-owned RAW FD;
            # the canonical #286 parser authenticates structural GPT bytes.
            with borrowed_readonly_proc_fd(
                child.pid, observer._fd_number, raw,
                expected_dev=pins.media_dev,
                expected_inode=pins.media_inode,
                expected_size=pins.media_size,
                expected_start_ticks=pins.process.start_ticks,
            ) as fd:
                measured = read_exact_gpt_esp(fd, gate, baseline, esp_hash)
            witnessed = observer.finish()
            assert witnessed["localQemuReadonlyDiskFdOpenProven"] is True
            assert witnessed["localQmpPeerProcessMatched"] is True
            assert witnessed["qemuBackendToFdBindingIndependentlyProven"] is False
            shutdown(child)
            assert observer.assert_stopped()["qemuProcessReaped"] is True
    finally:
        shutdown(child)
    assert file_sha(raw) == raw_before

    # Use existing pinned Safety #267 QCOW2 chain helper. A QCOW2 container
    # must NEVER be interpreted with raw GPT offsets.
    qcow = make_qcow(root, safety, raw)
    chain_before = safety.verify_chain(qcow, raw, root)
    assert chain_before["backingSha256"] == raw_before
    effective = root / "effective-guest-disk.raw"
    qcow_gpt = safety.host_snapshot(qcow, effective, root)
    gate.assert_snapshot_matches(baseline, qcow_gpt)
    with effective.open("rb") as f:
        effective_measured = read_exact_gpt_esp(f.fileno(), gate, baseline, esp_hash)
    assert effective_measured["espSha256"] == measured["espSha256"]
    child = start_qemu(root, qcow, "qcow2")
    try:
        pins = pins_for(child, root, qcow, "qcow2")
        with QemuLocalDiskWitness(pins) as observer:
            witnessed_qcow = observer.finish()
            assert witnessed_qcow["localQemuReadonlyDiskFdOpenProven"] is True
            assert witnessed_qcow["disk"]["format"]["value"] == "qcow2"
            assert witnessed_qcow["qemuBackendToFdBindingIndependentlyProven"] is False
            shutdown(child)
            assert observer.assert_stopped()["qemuProcessReaped"] is True
    finally:
        shutdown(child)
    assert safety.verify_chain(qcow, raw, root) == chain_before
    assert file_sha(raw) == raw_before
    assert file_sha(effective) == raw_before

    evidence = {
        "status": "REAL_PAUSED_QEMU_RAW_QCOW2_FAT32_READONLY_DIAGNOSTIC_ONLY",
        "testMedia": "SELF_GENERATED_SYNTHETIC_NOT_WINDOWS",
        "qemuActualProcessObserved": True,
        "qmpKernelPeerMatched": True,
        "qemuOriginalImageFdReadOnlyMeasured": True,
        "gptFromPinnedQemuRawFd": True,
        "gptFromQcow2EffectiveConvertedRaw": True,
        "rawDiskSha256": raw_before,
        "qcow2ContainerSha256": chain_before["overlaySha256"],
        "qemuQcow2BackingSha256": chain_before["backingSha256"],
        "espSha256": esp_hash,
        "gptDiskGuid": measured["gptDiskGuid"],
        "espPartuuid": measured["espPartuuid"],
        "espOffsetBytes": ESP_START * 512,
        "espLengthBytes": ESP_BYTES,
        "bcdFileSha256": measured["bcdFileSha256"],
        "efiLoaderSentinelSha256": loader_hash,
        "windowsBootmgfwAuthentic": False,
        "windowsBcdAuthentic": False,
        "historicalWindowsEspAuthenticated": False,
        "independentQmpNodeToFdBindingProven": False,
        "qemuTraceBlkPointerBound": False,
        "qemuWriteTracePresent": False,
        "guestBooted": False,
        "archisoPacstrapExecuted": False,
        "processAttributionProven": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "rollbackProven": False,
        "releaseEligible": False,
        "stable": False,
    }
    assert all(evidence[k] is False for k in (
        "independentQmpNodeToFdBindingProven",
        "qemuTraceBlkPointerBound", "qemuWriteTracePresent",
        "windowsBootmgfwAuthentic", "historicalWindowsEspAuthenticated",
        "approvedMutation", "sameDiskDualBootVerified", "rollbackProven",
    ))
    print("GASLUX_CACHY_REAL_QEMU_ESP_DIAGNOSTIC " +
          json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    output = os.environ.get("GASLUX_CACHY_EVIDENCE_OUT")
    if output:
        destination = Path(output)
        assert destination.parent.is_dir() and not destination.is_symlink()
        assert not destination.exists()
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(evidence, stream, sort_keys=True, indent=2)
            stream.write("\n")


def test_read_only_identity_negative_cases_without_guest(tmp_path):
    """Reuse #286/GPT and FAT32 negatives without running another QEMU."""
    require_hosted()
    gate, _ = pinned_parsers()
    workspace = tmp_path.resolve(strict=True)
    workspace.chmod(0o700)
    esp, digest, _ = create_synthetic_esp(workspace)
    raw = create_owned_raw(workspace, esp)
    baseline = gate.inspect_gpt_image(raw, logical_sector_size=512)
    with raw.open("rb") as pinned:
        assert read_exact_gpt_esp(pinned.fileno(), gate, baseline, digest)
        with pytest.raises((AssertionError, ValueError)):
            read_exact_gpt_esp(pinned.fileno(), gate, baseline, "a" * 64)
    with pytest.raises(fat.Fat32MapError):
        fat.map_bcd_fat32(
            esp.read_bytes()[:-512], esp_start_lba=ESP_START,
            esp_end_lba=ESP_END, disk_bytes=DISK_BYTES,
        )
    with raw.open("r+b") as disk:
        disk.seek(SECTOR + 56)
        disk.write(b"\x00" * 16)
    with raw.open("rb") as pinned:
        with pytest.raises((ValueError, AssertionError)):
            read_exact_gpt_esp(pinned.fileno(), gate, baseline, digest)
