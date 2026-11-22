"""Real stopped-QEMU, private RAW/QCOW2 and procfs/QMP adversarial witnesses.

Only test-owned regular files in pytest tmp_path. Never launch a guest OS.
Safety #267 and canonical GPT FD #286 are imported from exact pinned trees.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from auto_tests.installer_observer.host_fd_boundary import process_seal
from auto_tests.installer_observer.host_qemu_fd_evidence import (
    HostEvidenceRefused,
    HostPins,
    borrowed_readonly_proc_fd,
    correlate_qmp_fd,
)
from auto_tests.installer_observer.qemu_local_disk_witness import (
    QemuDiskPins,
    QemuDiskRefused,
    QemuLocalDiskWitness,
)

PIN286 = "9aed36cfdb8c09a461dc38811c326c54180273de"
PIN267 = "0be04192acd542646a5b6cd952e01620379edf5d"
SIZE = 64 * 1024 * 1024
QEMU = "/usr/bin/qemu-system-x86_64"
EXE_QEMU_IMG = "/usr/bin/qemu-img"
TX = "lab-owned-transaction-not-attested"


def load(name: str, path: Path):
    assert path.is_file(), path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


@pytest.fixture(scope="module")
def pinned():
    root267 = Path(os.environ["GASLUX_QEMU_PIN267_ROOT"]).resolve(strict=True)
    root286 = Path(os.environ["GASLUX_QEMU_PIN286_ROOT"]).resolve(strict=True)
    for root, sha in ((root267, PIN267), (root286, PIN286)):
        assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip() == sha
        assert not subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)
    gate = load(
        "libertix_disk_identity_gate",
        root286 / "assets/live/libertix_disk_identity_gate.py",
    )
    sys.path.insert(0, str(root267 / "assets/live"))
    try:
        lab = load(
            "safety_qemu_gpt_host_guest_local_test",
            root267 / "auto_tests/tools/safety_qemu_gpt_host_guest.py",
        )
    finally:
        sys.path.remove(str(root267 / "assets/live"))
    return gate, lab


@pytest.fixture
def workspace(tmp_path):
    folder = tmp_path.resolve(strict=True)
    folder.chmod(0o700)
    assert folder.parent.is_dir()
    assert folder.stat().st_uid == os.getuid()
    return folder


def make_raw(folder: Path, lab) -> Path:
    path = folder / "disk.raw"
    lab.make_raw(
        path,
        folder,
        disk_guid=str(uuid.uuid4()),
        part_guid=str(uuid.uuid4()),
    )
    assert path.stat().st_size == SIZE
    return path


def make_qcow(folder: Path, lab, raw: Path) -> Path:
    overlay = folder / "overlay.qcow2"
    lab.make_qcow(overlay, raw, folder)
    # The inherited HOST reference uses logical-sector-aligned file sizes;
    # QCOW2 host length need not naturally be aligned. All padding is PRIVATE.
    trailing = (-overlay.stat().st_size) % 512
    if trailing:
        with overlay.open("ab") as fd:
            fd.write(bytes(trailing))
    assert overlay.stat().st_size % 512 == 0
    lab.verify_chain(overlay, raw, folder)
    return overlay


def wait_qmp(path: Path, child: subprocess.Popen, timeout=12):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if child.poll() is not None:
            raise AssertionError(f"QEMU EXITED BEFORE QMP: {child.returncode}")
        if path.is_socket():
            return
        time.sleep(0.05)
    raise AssertionError("REAL_QEMU_QMP_SOCKET_NOT_READY")


def start_qemu(folder: Path, media: Path, disk_format: str) -> subprocess.Popen:
    assert os.environ["GASLUX_QEMU_NO_GUEST"] == "1"
    assert os.environ["GITHUB_ACTIONS"] == "true"
    assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
    assert str(media.parent) == str(folder)
    assert media.is_file() and media.stat().st_nlink == 1
    assert Path(QEMU).is_file()
    assert Path(EXE_QEMU_IMG).is_file()
    qmp = folder / "monitor.sock"
    assert not qmp.exists()
    args = [
        QEMU,
        "-machine", "q35,accel=tcg",
        "-S",
        "-m", "64",
        "-nodefaults",
        "-no-user-config",
        "-display", "none",
        "-monitor", "none",
        "-serial", "none",
        "-parallel", "none",
        "-nic", "none",
        "-qmp", f"unix:{qmp},server=on,wait=off",
        "-drive", f"file={media},format={disk_format},if=none,id=disk0,readonly=on",
        "-device", "virtio-blk-pci,drive=disk0",
    ]
    previous = os.umask(0o077)
    try:
        child = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            cwd=folder,
            start_new_session=True,
        )
    finally:
        os.umask(previous)
    try:
        wait_qmp(qmp, child)
        return child
    except BaseException:
        shutdown(child)
        raise


def shutdown(child: subprocess.Popen) -> None:
    if child.poll() is None:
        child.terminate()
    try:
        child.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate(timeout=5)


def pins_for(child: subprocess.Popen, folder: Path, media: Path, kind: str) -> QemuDiskPins:
    st = media.stat()
    return QemuDiskPins(
        process=process_seal(child.pid),
        media_path=media,
        workspace=folder,
        qmp_socket=folder / "monitor.sock",
        media_dev=st.st_dev,
        media_inode=st.st_ino,
        media_size=st.st_size,
        disk_format=kind,
        qmp_device="disk0",
        transaction_id=TX,
        vm_label="synthetic-qemu-paused-no-guest",
    )


def validate_never_auth(report: dict) -> None:
    assert report["status"] == "BLOCKED_TRUST_ROOT"
    assert report["classification"] == "NOT_INDEPENDENT"
    assert report["safetyAssessment"] == "DIAGNOSTIC_ONLY"
    assert report["localQemuReadonlyDiskFdOpenProven"] is True
    assert report["localQmpPeerProcessMatched"] is True
    assert report["qmpReply"]["payload"]["assurance"] == "CLAIMED"
    assert report["transactionId"]["assurance"] == "CLAIMED"
    assert report["vmLabel"]["assurance"] == "CLAIMED"
    for key in (
        "qemuBackendToFdBindingIndependentlyProven",
        "qcow2BackingChainAuthenticated",
        "guestEffectiveGptAuthenticated",
        "guestChannelAuthenticated",
        "anacondaProcessVerified",
        "diskWriteAuthorized",
        "inputAuthorized",
        "productionInstallationAuthorized",
        "productionWriteAuthorized",
        "rollbackProven",
        "stable",
        "externallyAttested",
        "freshnessAuthenticated",
        "replayProtected",
    ):
        assert report[key] is False, key


@pytest.mark.parametrize("format", ["raw", "qcow2"])
def test_real_paused_qemu_opens_exact_regular_image_and_reports_qmp(
    workspace, pinned, format
):
    gate, lab = pinned
    raw = make_raw(workspace, lab)
    expected = gate.inspect_gpt_image(raw, logical_sector_size=512)
    image = raw if format == "raw" else make_qcow(workspace, lab, raw)
    if format == "qcow2":
        chain = lab.verify_chain(image, raw, workspace)
        assert chain["backingSha256"] == lab.sha256(raw)
        # Valid effective virtual disk is read into a DIFFERENT disposable
        # regular file by pinned #267, not interpreted from QCOW2 as raw.
        effective = workspace / "effective.raw"
        actual = lab.host_snapshot(image, effective, workspace)
        gate.assert_snapshot_matches(expected, actual)
    child = start_qemu(workspace, image, format)
    try:
        pins = pins_for(child, workspace, image, format)
        with QemuLocalDiskWitness(pins) as witness:
            report = witness.finish()
            validate_never_auth(report)
            if format == "raw":
                with borrowed_readonly_proc_fd(
                    child.pid,
                    report["disk"]["fdNumber"],
                    image,
                    expected_dev=pins.media_dev,
                    expected_inode=pins.media_inode,
                    expected_size=pins.media_size,
                    expected_start_ticks=pins.process.start_ticks,
                ) as fd:
                    gate.assert_snapshot_matches(
                        expected, gate.inspect_gpt_fd(fd, logical_sector_size=512)
                    )
            else:
                # The QEMU overlay and actual backing are checked as separate
                # host files; no claim of authenticated guest effective GPT.
                assert report["disk"]["format"]["value"] == "qcow2"
            with pytest.raises(QemuDiskRefused, match="LOCAL_OBSERVATION_ALREADY_USED"):
                witness.finish()
            with pytest.raises(QemuDiskRefused, match="QEMU_CLEANUP_NOT_CONFIRMED"):
                witness.assert_stopped()
            shutdown(child)
            assert witness.assert_stopped() == {
                "qemuPidfdExited": True,
                "qemuProcessReaped": True,
                "guestAuthenticated": False,
                "windowsRollbackProven": False,
            }
    finally:
        shutdown(child)
    assert image.stat().st_ino == pins.media_inode


@pytest.mark.parametrize(
    "case",
    ["start_ticks", "pid", "exe", "media_inode", "media_size", "device", "format"],
)
def test_real_qemu_wrong_process_disk_or_block_graph_refuses(workspace, pinned, case):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    child = start_qemu(workspace, raw, "raw")
    try:
        pins = pins_for(child, workspace, raw, "raw")
        if case == "start_ticks":
            pins = replace(
                pins, process=replace(pins.process, start_ticks=pins.process.start_ticks + 1)
            )
        elif case == "pid":
            pins = replace(pins, process=replace(pins.process, pid=child.pid + 100000))
        elif case == "exe":
            pins = replace(
                pins,
                process=replace(
                    pins.process, executable_ino=pins.process.executable_ino + 1
                ),
            )
        elif case == "media_inode":
            pins = replace(pins, media_inode=pins.media_inode + 1)
        elif case == "media_size":
            pins = replace(pins, media_size=pins.media_size + 512)
        elif case == "device":
            pins = replace(pins, qmp_device="foreign-disk0")
        else:
            pins = replace(pins, disk_format="qcow2")
        with pytest.raises(QemuDiskRefused):
            QemuLocalDiskWitness(pins)
    finally:
        shutdown(child)


def test_two_real_qemu_concurrent_wrong_qmp_socket_and_same_disk_basename(
    tmp_path, pinned
):
    _, lab = pinned
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir(mode=0o700)
    two.mkdir(mode=0o700)
    make_raw(one, lab)
    make_raw(two, lab)
    a = start_qemu(one, one / "disk.raw", "raw")
    b = start_qemu(two, two / "disk.raw", "raw")
    try:
        pins_a = pins_for(a, one, one / "disk.raw", "raw")
        pins_b = pins_for(b, two, two / "disk.raw", "raw")
        with QemuLocalDiskWitness(pins_a) as x:
            validate_never_auth(x.finish())
        with QemuLocalDiskWitness(pins_b) as x:
            validate_never_auth(x.finish())
        with pytest.raises(QemuDiskRefused):
            QemuLocalDiskWitness(
                replace(pins_a, qmp_socket=two / "monitor.sock")
            )
        with pytest.raises(QemuDiskRefused):
            QemuLocalDiskWitness(
                replace(pins_a, media_path=two / "disk.raw", workspace=two)
            )
    finally:
        shutdown(a)
        shutdown(b)


def test_real_qemu_media_path_swap_between_samples_refused(workspace, pinned):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    child = start_qemu(workspace, raw, "raw")
    try:
        pins = pins_for(child, workspace, raw, "raw")
        with QemuLocalDiskWitness(pins) as witness:
            removed = workspace / "previous.raw"
            os.replace(raw, removed)
            shutil.copyfile(removed, raw)
            with pytest.raises(QemuDiskRefused):
                witness.finish()
    finally:
        shutdown(child)


def test_real_qemu_died_between_samples_refused(workspace, pinned):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    child = start_qemu(workspace, raw, "raw")
    try:
        pins = pins_for(child, workspace, raw, "raw")
        with QemuLocalDiskWitness(pins) as witness:
            shutdown(child)
            with pytest.raises(QemuDiskRefused):
                witness.finish()
    finally:
        shutdown(child)


def test_qcow2_wrong_backing_fails_pinned_safety_verifier(workspace, pinned):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    overlay = make_qcow(workspace, lab, raw)
    wrong = workspace / "wrong.raw"
    shutil.copyfile(raw, wrong)
    with pytest.raises(lab.PrewriteDenied):
        lab.verify_chain(overlay, wrong, workspace)


def test_fabricated_qmp_reply_is_never_kernel_authenticated(workspace, pinned):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    st = raw.stat()
    from auto_tests.installer_observer.host_fd_boundary import ProcessSeal

    pins = HostPins(
        ProcessSeal(3333, 1000, 45, "a" * 64, 1, 1),
        "b" * 64,
        TX,
        "fake-vm",
        "untrusted",
        "disk0",
        "serial",
        12,
        raw,
        st.st_dev,
        st.st_ino,
        st.st_size,
    )
    reply = [
        {
            "device": "disk0",
            "inserted": {
                "file": str(raw),
                "ro": True,
                "image": {"filename": str(raw), "format": "raw"},
            },
        }
    ]
    relation = correlate_qmp_fd(
        pins,
        {"fileDev": st.st_dev, "fileInode": st.st_ino, "fileSizeBytes": st.st_size},
        reply,
    )
    assert relation["claimedQmpFdConsistency"] is True
    assert relation["localQmpFdConsistency"] is False
    assert relation["deviceFdAssociationProven"] is False


def test_rogue_qmp_peer_and_truncated_greeting_refused(workspace, pinned):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    child = start_qemu(workspace, raw, "raw")
    try:
        pins = pins_for(child, workspace, raw, "raw")
        foreign = workspace / "foreign.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(foreign))
            server.listen(1)
            with pytest.raises(QemuDiskRefused):
                QemuLocalDiskWitness(replace(pins, qmp_socket=foreign))
    finally:
        shutdown(child)


def test_qemu_cleanup_unconfirmed_is_explicit_refusal(workspace, pinned):
    _, lab = pinned
    raw = make_raw(workspace, lab)
    child = start_qemu(workspace, raw, "raw")
    try:
        pins = pins_for(child, workspace, raw, "raw")
        with QemuLocalDiskWitness(pins) as witness:
            validate_never_auth(witness.finish())
            with pytest.raises(QemuDiskRefused, match="QEMU_CLEANUP_NOT_CONFIRMED"):
                witness.assert_stopped()
            shutdown(child)
            assert witness.assert_stopped()["qemuProcessReaped"] is True
    finally:
        shutdown(child)
