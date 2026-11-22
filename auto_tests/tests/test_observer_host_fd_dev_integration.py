"""Deny-only composite HOST/FD regression tests on the current dev checkout.

Synthetic disposable files and Python subprocesses; no QEMU, guest, disk or UI input.
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auto_tests.installer_observer.host_fd_boundary import (
    HostBoundaryRefused,
    ProcessSeal,
    _execute,
    process_seal,
)
from auto_tests.installer_observer.host_qemu_fd_evidence import (
    HostEvidenceRefused,
    HostPins,
    borrowed_readonly_proc_fd,
    correlate_qmp_fd,
    declared_context,
    observe_descriptor,
    observe_host_qemu,
    query_qemu_block_readonly,
)

ROOT = Path(__file__).resolve().parents[2]


def _pins_for_file(path: Path, fd_number: int) -> HostPins:
    pid = os.getpid()
    proc = Path("/proc") / str(pid)
    content = (proc / "stat").read_text(encoding="ascii")
    ticks = int(content[content.rfind(") ") + 2 :].split()[19])
    exe = (proc / "exe").stat()
    seal = ProcessSeal(
        pid,
        proc.stat().st_uid,
        ticks,
        hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest(),
        exe.st_dev,
        exe.st_ino,
    )
    st = path.stat()
    return HostPins(
        seal, "a" * 64, "synthetic-tx", "synthetic-vm", "synthetic-challenge",
        "disk0", "synthetic-serial", fd_number, path, st.st_dev, st.st_ino, st.st_size,
    )


@pytest.mark.skipif(os.name != "posix" or not Path("/proc").is_dir(), reason="Linux procfs only")
def test_real_readonly_fd_proves_only_local_measurement(tmp_path):
    image = tmp_path / "owned.raw"
    image.write_bytes(b"synthetic" + bytes(1024 * 1024 - 9))
    original = hashlib.sha256(image.read_bytes()).hexdigest()
    with image.open("rb") as source:
        pins = _pins_for_file(image, source.fileno())
        evidence = observe_descriptor(pins)
        assert evidence["assurance"] == "LOCALLY_MEASURED"
        assert evidence["fileInode"] == pins.expected_inode
        assert evidence["readMethod"] == "proc-fd-reopened-readonly-pread"
        assert all(v is not True for k, v in evidence.items() if "Authorized" in k)
        with borrowed_readonly_proc_fd(
            os.getpid(), source.fileno(), image, expected_dev=pins.expected_dev,
            expected_inode=pins.expected_inode, expected_size=pins.expected_size,
            expected_start_ticks=pins.process.start_ticks,
        ) as fd:
            assert os.pread(fd, 9, 0) == b"synthetic"
    assert hashlib.sha256(image.read_bytes()).hexdigest() == original


@pytest.mark.skipif(os.name != "posix" or not Path("/proc").is_dir(), reason="Linux procfs only")
def test_closed_fd_wrong_identities_and_symlinks_are_refused(tmp_path):
    image = tmp_path / "owned.raw"
    image.write_bytes(bytes(1024 * 1024))
    with image.open("rb") as source:
        pins = _pins_for_file(image, source.fileno())
        fd = source.fileno()
    kwargs = {
        "expected_dev": pins.expected_dev,
        "expected_inode": pins.expected_inode,
        "expected_size": pins.expected_size,
        "expected_start_ticks": pins.process.start_ticks,
    }
    with (
        pytest.raises(HostEvidenceRefused),
        borrowed_readonly_proc_fd(os.getpid(), fd, image, **kwargs),
    ):
        pytest.fail("Closed descriptor was accepted")
    with (
        pytest.raises(HostEvidenceRefused, match="INVALID_PID_OR_FD"),
        borrowed_readonly_proc_fd(0, 4, image, **kwargs),
    ):
        pytest.fail("Invalid PID was accepted")
    with (
        pytest.raises(HostEvidenceRefused, match="INVALID_PID_OR_FD"),
        borrowed_readonly_proc_fd(os.getpid(), -1, image, **kwargs),
    ):
        pytest.fail("Invalid FD was accepted")
    link = tmp_path / "symlink.raw"
    link.symlink_to(image)
    with (
        pytest.raises(HostEvidenceRefused, match="UNSAFE_MEDIA_PATH"),
        borrowed_readonly_proc_fd(os.getpid(), fd, link, **kwargs),
    ):
        pytest.fail("Symlink was accepted")
    with image.open("rb") as source:
        incorrect = {**kwargs, "expected_inode": pins.expected_inode + 1}
        with (
            pytest.raises(HostEvidenceRefused),
            borrowed_readonly_proc_fd(os.getpid(), source.fileno(), image, **incorrect),
        ):
            pytest.fail("Wrong inode was accepted")


def test_clean_python_import_without_experimental_authority_modules():
    script = """
import sys
from auto_tests.installer_observer.host_qemu_fd_evidence import HostPins, declared_context
from auto_tests.installer_observer.host_fd_boundary import ProcessSeal
from auto_tests.installer_observer.screenshot import Screenshot
for forbidden in ("lab_identity", "state_machine", "gpt_lab_provenance",
                  "gpt_readonly_producer", "remote_verifier", "transport_vnc",
                  "isolation_host", "controller_lease"):
    assert not any(name.endswith("." + forbidden) for name in sys.modules), forbidden
print("HOST_FD_READONLY_IMPORT")
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, env=env,
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "HOST_FD_READONLY_IMPORT" in result.stdout


def test_no_transitive_operational_imports_and_no_writer_calls():
    for filename in ("host_fd_boundary.py", "host_qemu_fd_evidence.py"):
        path = ROOT / "auto_tests" / "installer_observer" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        for forbidden in (
            "lab_identity", "state_machine", "gpt_lab_provenance",
            "gpt_readonly_producer", "remote_verifier", "transport_vnc",
            "controller_lease", "subprocess", "libguestfs",
        ):
            assert all(not name.endswith(forbidden) for name in imports)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                assert not (
                    node.value.id == "os"
                    and node.attr in {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"}
                )


@pytest.mark.parametrize(
    "name",
    ("system_powerdown", "send-key", "human-monitor-command", "query-vnc", "migrate", "quit"),
)
def test_qmp_control_commands_rejected_without_sending(name):
    class DoNotSend:
        def sendall(self, _message):
            pytest.fail("Unapproved QMP command escaped the allowlist")

    with pytest.raises(HostBoundaryRefused, match="QMP_COMMAND_NOT_ALLOWLISTED"):
        _execute(DoNotSend(), None, name)


def test_no_qemu_or_guest_or_external_approval_from_synthetic_claims(tmp_path):
    path = tmp_path / "fake.raw"
    fake = ProcessSeal(os.getpid(), os.geteuid(), 100, "x", 1, 1)
    pins = HostPins(
        fake, "a" * 64, "synthetic-tx", "synthetic-vm", "synthetic-challenge",
        "disk0", "synthetic-serial", 4, path.absolute(), 1, 2, 1024 * 1024,
    )
    context = declared_context(pins)
    assert all(item["assurance"] == "CLAIMED" for item in context.values())
    qmp_claims = [{
        "device": "disk0", "inserted": {
            "file": str(pins.media_path), "ro": True,
            "image": {"filename": str(pins.media_path), "format": "raw"},
        },
    }]
    result = correlate_qmp_fd(
        pins, {"fileDev": 1, "fileInode": 2, "fileSizeBytes": 1024 * 1024}, qmp_claims,
    )
    assert result["claimedQmpFdConsistency"] is True
    for key in ("localQmpFdConsistency", "deviceFdAssociationProven", "vmDiskBindingProven"):
        assert result[key] is False
    with pytest.raises((HostBoundaryRefused, HostEvidenceRefused)):
        observe_host_qemu(pins, gpt_fd_gate=None, qmp_blocks=[])
    with pytest.raises(HostEvidenceRefused):
        query_qemu_block_readonly(pins, path / "nonexistent.sock")
    with pytest.raises(HostBoundaryRefused):
        process_seal(os.getpid())


def test_absent_gpt_verifier_cannot_promote_synthetic_file(tmp_path):
    fake = ProcessSeal(os.getpid(), os.geteuid(), 100, "x", 1, 1)
    path = (tmp_path / "absent.raw").absolute()
    pins = HostPins(
        fake, "a" * 64, "synthetic-tx", "synthetic-vm", "synthetic-challenge",
        "disk0", "synthetic-serial", 4, path, 1, 2, 1024 * 1024,
    )
    with pytest.raises((HostBoundaryRefused, HostEvidenceRefused)):
        observe_host_qemu(pins, gpt_fd_gate=None, qmp_blocks=[])
