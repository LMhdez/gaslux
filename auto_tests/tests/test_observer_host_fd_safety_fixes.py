"""Adversarial F-01/F-02/F-03 against the REAL #292 Observer HOST module.

The original HEAD must fail all three tests; no QEMU process is launched.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auto_tests.installer_observer.host_qemu_fd_evidence import (
    HostEvidenceRefused,
    HostPins,
    borrowed_readonly_proc_fd,
    correlate_qmp_fd,
    observe_pinned_qcow2_chain,
)
from auto_tests.installer_observer.lab_identity import ProcessSeal


def _seal(pid: int) -> ProcessSeal:
    proc = Path("/proc") / str(pid)
    raw = (proc / "stat").read_text()
    fields = raw[raw.rfind(")") + 2 :].split()
    exe = (proc / "exe").stat()
    return ProcessSeal(
        pid,
        proc.stat().st_uid,
        int(fields[19]),
        hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest(),
        exe.st_dev,
        exe.st_ino,
    )


def _pins(path: Path, fd: int, pid: int) -> HostPins:
    st = path.stat()
    return HostPins(
        process=_seal(pid),
        qemu_executable_sha256="a" * 64,
        transaction_id="synthetic-transaction",
        vm_uuid="synthetic-vm",
        challenge="synthetic-challenge",
        device_name="disk0",
        serial="synthetic-serial",
        fd_number=fd,
        media_path=path,
        expected_dev=st.st_dev,
        expected_inode=st.st_ino,
        expected_size=st.st_size,
    )


def test_f01_forged_qmp_cannot_self_certify_local_measurement(tmp_path):
    """Caller-supplied dicts must never become LOCALLY_MEASURED via a kwarg."""
    path = tmp_path / "mock.raw"
    path.write_bytes(bytes(1024 * 1024))
    with path.open("rb") as opened:
        pins = _pins(path, opened.fileno(), os.getpid())
        claims = [
            {
                "device": "disk0",
                "inserted": {
                    "file": str(path),
                    "ro": True,
                    "image": {"filename": str(path), "format": "raw"},
                },
            }
        ]
        descriptor = {
            "fileDev": pins.expected_dev,
            "fileInode": pins.expected_inode,
            "fileSizeBytes": pins.expected_size,
        }
        try:
            result = correlate_qmp_fd(pins, descriptor, claims, provenance="LOCALLY_MEASURED")
        except (HostEvidenceRefused, TypeError):
            return
        assert result["qmpDeviceName"]["assurance"] == "CLAIMED"
        assert result["deviceFdAssociationProven"] is False


def test_f02_forged_qcow2_verifier_cannot_self_certify_local_chain(tmp_path):
    """Magic bytes plus a forged verify_chain must never prove backing."""
    workspace = tmp_path
    overlay = workspace / "overlay.qcow2"
    backing = workspace / "base.raw"
    overlay.write_bytes(bytes.fromhex("514649fb") + bytes(1024 * 1024 - 4))
    backing.write_bytes(bytes(1024 * 1024))

    class ForgedSafety:
        called = False

        def verify_chain(self, _overlay, _backing, _workspace):
            self.called = True
            return {
                "format": "qcow2",
                "backingFormat": "raw",
                "backingFilename": str(backing),
                "virtualSizeBytes": 64 * 1024 * 1024,
            }

    fake = ForgedSafety()
    with overlay.open("rb") as opened:
        pins = _pins(overlay, opened.fileno(), os.getpid())
        try:
            report = observe_pinned_qcow2_chain(pins, backing, workspace, fake)
        except HostEvidenceRefused:
            return
        assert report.get("assurance") != "LOCALLY_MEASURED"
        assert report.get("backingChainVerified") is not True
        assert report.get("guestEffectiveGptProven") is False
        assert report.get("qcow2HeaderMagic", {}).get("assurance") == "LOCALLY_MEASURED"
        assert report.get("backingChainVerified") is False
    assert fake.called is False


CHILD = """
import os
import sys

path, other = sys.argv[1:]
fd = os.open(path, os.O_RDONLY)
rw = os.open(path, os.O_RDWR)
other_fd = os.open(other, os.O_RDONLY)
print(fd, flush=True)
for line in sys.stdin:
    operation = line.strip()
    if operation == "rw":
        os.dup2(rw, fd)
    elif operation == "close":
        os.close(fd)
    elif operation == "other":
        os.dup2(other_fd, fd)
    elif operation == "exit":
        print("ACK", flush=True)
        break
    print("ACK", flush=True)
"""


@pytest.fixture
def disposable_child(tmp_path):
    source = tmp_path / "owned.raw"
    other = tmp_path / "other.raw"
    source.write_bytes(bytes(1024 * 1024))
    other.write_bytes(bytes(1024 * 1024))
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(source), str(other)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        close_fds=True,
    )
    try:
        assert child.stdin is not None and child.stdout is not None
        fd = int(child.stdout.readline().strip())
        pins = _pins(source, fd, child.pid)
        yield child, pins
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=3)


def _command(child: subprocess.Popen, name: str) -> None:
    assert child.stdin is not None and child.stdout is not None
    child.stdin.write(name + "\n")
    child.stdin.flush()
    assert child.stdout.readline().strip() == "ACK"


def test_f03_remote_original_fd_reopened_readwrite_same_inode_refused(disposable_child):
    """Real Linux child swaps fd via dup2(O_RDWR) during an existing observation."""
    child, pins = disposable_child
    with (
        pytest.raises(HostEvidenceRefused),
        borrowed_readonly_proc_fd(
            pins.process.pid,
            pins.fd_number,
            pins.media_path,
            expected_dev=pins.expected_dev,
            expected_inode=pins.expected_inode,
            expected_size=pins.expected_size,
        ) as observed,
    ):
        assert os.fstat(observed).st_ino == pins.expected_inode
        _command(child, "rw")


@pytest.mark.parametrize("operation", ["close", "other", "exit"])
def test_f03_remote_fd_closed_reused_or_process_gone(disposable_child, operation):
    """Real child changes the original remote FD while local reopen stays pinned."""
    child, pins = disposable_child
    with (
        pytest.raises(HostEvidenceRefused),
        borrowed_readonly_proc_fd(
            pins.process.pid,
            pins.fd_number,
            pins.media_path,
            expected_dev=pins.expected_dev,
            expected_inode=pins.expected_inode,
            expected_size=pins.expected_size,
            expected_start_ticks=pins.process.start_ticks,
        ) as opened,
    ):
        assert os.fstat(opened).st_ino == pins.expected_inode
        _command(child, operation)
        if operation == "exit":
            child.wait(timeout=3)


def test_f03_externally_wrong_start_ticks_refused(disposable_child):
    child, pins = disposable_child
    with (
        pytest.raises(HostEvidenceRefused, match="PROCESS_START_TICKS_MISMATCH"),
        borrowed_readonly_proc_fd(
            child.pid,
            pins.fd_number,
            pins.media_path,
            expected_dev=pins.expected_dev,
            expected_inode=pins.expected_inode,
            expected_size=pins.expected_size,
            expected_start_ticks=pins.process.start_ticks + 1,
        ),
    ):
        pass


@pytest.mark.parametrize("mutation", ["wrong-device", "wrong-serial", "duplicate"])
def test_f01_forged_qmp_mismatch_or_duplicate_denied(tmp_path, mutation):
    image = tmp_path / "test.raw"
    image.write_bytes(bytes(1024 * 1024))
    with image.open("rb") as opened:
        pins = _pins(image, opened.fileno(), os.getpid())
        descriptor = {
            "fileDev": pins.expected_dev,
            "fileInode": pins.expected_inode,
            "fileSizeBytes": pins.expected_size,
        }
        block = {
            "device": pins.device_name,
            "inserted": {
                "file": str(image),
                "ro": True,
                "image": {"filename": str(image), "format": "raw"},
            },
        }
        if mutation == "wrong-device":
            block["device"] = "other-device"
        elif mutation == "wrong-serial":
            block["inserted"]["serial"] = "different-serial"
        else:
            with pytest.raises(HostEvidenceRefused):
                correlate_qmp_fd(pins, descriptor, [block, block])
            return
        with pytest.raises(HostEvidenceRefused):
            correlate_qmp_fd(pins, descriptor, [block])


def test_f01_matching_claims_remain_claims(tmp_path):
    image = tmp_path / "test.raw"
    image.write_bytes(bytes(1024 * 1024))
    with image.open("rb") as opened:
        pins = _pins(image, opened.fileno(), os.getpid())
        descriptor = {
            "fileDev": pins.expected_dev,
            "fileInode": pins.expected_inode,
            "fileSizeBytes": pins.expected_size,
        }
        blocks = [
            {
                "device": pins.device_name,
                "inserted": {
                    "file": str(image),
                    "ro": True,
                    "image": {"filename": str(image), "format": "raw"},
                },
            }
        ]
        report = correlate_qmp_fd(pins, descriptor, blocks)
        assert report["qmpDeviceName"]["assurance"] == "CLAIMED"
        assert report["claimedQmpFdConsistency"] is True
        assert report["localQmpFdConsistency"] is False
        assert report["deviceFdAssociationProven"] is False
        assert report["vmDiskBindingProven"] is False
