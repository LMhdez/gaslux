"""Clean-dev minimal copy integration proof, no QEMU and no test doubles.

The CI passes GASLUX_PINNED_DEV_ROOT as a clean, exact-SHA checkout.
Each subprocess has a fresh interpreter, unchanged module search path and
only the two integration files copied into an isolated dev-based package.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DEV_SHA = "af5c28c5c66e6fe294bd7f768ea13467aa0db3f6"
MODULES = (
    "host_fd_boundary.py",
    "host_qemu_fd_evidence.py",
)
FORBIDDEN = (
    "lab_identity",
    "state_machine",
    "evidence",
    "gpt_lab_provenance",
    "gpt_readonly_producer",
    "remote_verifier",
)


@pytest.fixture
def staged_dev(tmp_path):
    source = Path(os.environ["GASLUX_PINNED_DEV_ROOT"]).resolve(strict=True)
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    assert head == DEV_SHA
    assert not subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True
    )
    stage = tmp_path / "dev-overlay"
    base_package = stage / "auto_tests" / "installer_observer"
    base_package.mkdir(parents=True)
    # If dev has a package initializer, preserve exactly its existing content.
    for name in ("auto_tests/__init__.py", "auto_tests/installer_observer/__init__.py"):
        existing = source / name
        if existing.is_file():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(existing, target)
    original = Path(__file__).resolve().parents[2] / "auto_tests" / "installer_observer"
    for name in MODULES:
        assert not (source / "auto_tests" / "installer_observer" / name).exists()
        shutil.copy2(original / name, base_package / name)
    assert set(p.name for p in base_package.iterdir() if p.suffix == ".py") <= (
        set(MODULES) | {"__init__.py"}
    )
    yield stage
    assert (
        subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        == DEV_SHA
    )
    assert not subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True
    )


def _isolated(stage: Path, script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    # cwd is normal Python module lookup, not manipulation of sys.path.
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=stage,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def test_clean_dev_minimal_import_and_pure_claimed_diagnostics(staged_dev):
    code = """
import os
import sys
from pathlib import Path
from auto_tests.installer_observer.host_qemu_fd_evidence import (
    HostPins, ProcessSeal, correlate_qmp_fd, declared_context,
    require_process_identity, HostEvidenceRefused,
)
for bad in ("lab_identity", "evidence", "state_machine", "gpt_lab_provenance",
            "gpt_readonly_producer", "remote_verifier"):
    assert not any(name.endswith("." + bad) for name in sys.modules), bad
seal = ProcessSeal(222, 1000, 77, "abc", 12, 34)
pins = HostPins(seal, "0" * 64, "tx", "vm", "challenge", "disk0", "serial",
                4, Path("/tmp/example.raw"), 1, 2, 1024 * 1024)
assert declared_context(pins)["vmUuid"]["assurance"] == "CLAIMED"
report = correlate_qmp_fd(
    pins, {"fileDev": 1, "fileInode": 2, "fileSizeBytes": 1024 * 1024},
    [{"device": "disk0", "inserted":
        {"file": "/tmp/example.raw", "ro": True,
         "image": {"filename": "/tmp/example.raw", "format": "raw"}}}],
)
assert report["qmpDeviceName"]["assurance"] == "CLAIMED"
assert report["claimedQmpFdConsistency"] is True
assert report["localQmpFdConsistency"] is False
assert report["deviceFdAssociationProven"] is False
assert report["vmDiskBindingProven"] is False
assert not any(name.endswith("." + bad) for name in sys.modules
               for bad in ("lab_identity", "state_machine", "gpt_lab_provenance"))
print("MINIMAL_DEV_IMPORT_DENY_ONLY")
"""
    p = _isolated(staged_dev, code)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "MINIMAL_DEV_IMPORT_DENY_ONLY" in p.stdout


def test_clean_dev_operational_route_refuses_without_qemu(staged_dev):
    code = """
import os
import sys
from pathlib import Path
from auto_tests.installer_observer.host_qemu_fd_evidence import (
    HostPins, ProcessSeal, HostEvidenceRefused, observe_host_qemu,
    query_qemu_block_readonly,
)
from auto_tests.installer_observer.host_fd_boundary import (
    HostBoundaryRefused, process_seal, _execute,
)
from io import BytesIO
class ForbiddenSend:
    def sendall(self, value):
        raise AssertionError("unauthorized QMP command was sent")
seal = ProcessSeal(os.getpid(), os.geteuid(), 1, "a", 1, 1)
pins = HostPins(seal, "0"*64, "tx", "vm", "challenge", "disk", "serial",
                4, Path("/tmp/absent.raw"), 1, 2, 1024*1024)
try:
    process_seal(os.getpid())
except HostBoundaryRefused:
    pass
else:
    raise AssertionError("Python process must never be treated as QEMU")
try:
    _execute(ForbiddenSend(), BytesIO(b""), "system_powerdown")
except HostBoundaryRefused:
    pass
else:
    raise AssertionError("non allowlisted QMP command accepted")
try:
    observe_host_qemu(pins, gpt_fd_gate=None, qmp_blocks=[])
except (HostBoundaryRefused, HostEvidenceRefused):
    pass
else:
    raise AssertionError("fake operational QEMU run must be refused")
try:
    query_qemu_block_readonly(pins, Path("/tmp/absent-qmp.sock"))
except HostEvidenceRefused:
    pass
else:
    raise AssertionError("absent authenticated socket must be refused")
for forbidden in ("lab_identity", "state_machine", "gpt_lab_provenance"):
    assert not any(name.endswith("." + forbidden) for name in sys.modules)
print("OPERATIONAL_PATH_DENIED")
"""
    p = _isolated(staged_dev, code)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "OPERATIONAL_PATH_DENIED" in p.stdout


def test_original_294_import_dependency_fails_in_clean_dev(staged_dev):
    """Real previous blob fails without lab_identity; corrected blob does not."""
    original_root = Path(os.environ["GASLUX_ORIGINAL_294_ROOT"]).resolve(strict=True)
    sha = subprocess.check_output(
        ["git", "-C", str(original_root), "rev-parse", "HEAD"], text=True
    ).strip()
    assert sha == "e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9"
    assert not subprocess.check_output(
        ["git", "-C", str(original_root), "status", "--porcelain"], text=True
    )
    original = original_root / "auto_tests/installer_observer/host_qemu_fd_evidence.py"
    target = staged_dev / "auto_tests/installer_observer/host_qemu_fd_evidence.py"
    shutil.copy2(original, target)
    p = _isolated(
        staged_dev,
        "from auto_tests.installer_observer import host_qemu_fd_evidence",
    )
    assert p.returncode != 0
    assert "ModuleNotFoundError" in p.stderr
    assert "lab_identity" in p.stderr
    assert not subprocess.check_output(
        ["git", "-C", str(original_root), "status", "--porcelain"], text=True
    )
