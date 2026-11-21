"""Adversarial Q4OS supermin/kernel contracts; appliance mock is NOT boot proof."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
PINNED = os.environ.get("GASLUX_Q4OS_PINNED_SAFETY_SOURCE_DIR")
if PINNED is None or not Path(PINNED).is_dir():
    if os.environ.get("GASLUX_Q4OS_WINDOWS_BOUNDARY_EVIDENCE"):
        pytest.fail("Pinned Safety #267 source required by Q4OS CI")
    pytest.skip(
        "Pinned Safety #267 contract tests run in Q4OS workflow, not generic media CI",
        allow_module_level=True,
    )
sys.path.insert(0, PINNED)
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
sys.path.insert(0, str(ROOT / "auto_tests/tests"))

from q4os_libguestfs_preflight import (  # noqa: E402
    ApplianceDenied,
    classify_diagnostic,
    inspect_kernel,
    observe_appliance,
)
from test_q4os_windows_boundary import SECTORS, make_image  # noqa: E402


@pytest.fixture
def kernel_fixture(tmp_path):
    version = "6.8.0-99-generic"
    kernel_dir = tmp_path / "private-kernel"
    kernel_dir.mkdir(mode=0o700)
    kernel = kernel_dir / ("vmlinuz-" + version)
    kernel.write_bytes(b"synthetic-not-bootable-kernel")
    kernel.chmod(0o600)
    module_root = tmp_path / "lib" / "modules"
    modules = module_root / version
    modules.mkdir(parents=True)
    (modules / "modules.dep").write_text("synthetic\n", encoding="ascii")
    env = {
        "SUPERMIN_KERNEL": str(kernel),
        "SUPERMIN_MODULES": str(modules),
        "SUPERMIN_KERNEL_VERSION": version,
        "LIBGUESTFS_BACKEND": "direct",
    }
    return env, module_root, kernel, modules


def test_kernel_modules_matching_contract_only(kernel_fixture):
    env, root, _kernel, _modules = kernel_fixture
    result = inspect_kernel(env, root)
    assert result["modulesVersionMatches"]
    assert result["kernelReadable"]
    assert result["kernelPrivateCopy"]
    assert result["guestfsBackend"] == "direct"


@pytest.mark.parametrize(
    ("field", "bad", "reason"),
    [
        ("SUPERMIN_KERNEL", "/nonexistent/kernel", "KERNEL_MISSING"),
        ("SUPERMIN_KERNEL_VERSION", "wrong", "KERNEL_VERSION_INVALID"),
        ("SUPERMIN_MODULES", "/nonexistent/modules", "MODULES_MISSING_OR_MISMATCH"),
        ("LIBGUESTFS_BACKEND", "libvirt", "GUESTFS_BACKEND_UNSUPPORTED"),
    ],
)
def test_missing_mismatched_and_unsupported_inputs(kernel_fixture, field, bad, reason):
    env, root, _kernel, _modules = kernel_fixture
    env[field] = bad
    with pytest.raises(ApplianceDenied, match=reason):
        inspect_kernel(env, root)


def test_private_kernel_unreadable_or_unsafe(kernel_fixture):
    env, root, kernel, _modules = kernel_fixture
    kernel.chmod(0)
    with pytest.raises(ApplianceDenied, match="KERNEL_MISMATCH_OR_UNREADABLE"):
        inspect_kernel(env, root)
    kernel.chmod(0o600)
    kernel.parent.chmod(0o755)
    with pytest.raises(ApplianceDenied, match="KERNEL_NOT_PRIVATE"):
        inspect_kernel(env, root)


def test_modules_dependency_file_missing(kernel_fixture):
    env, root, _kernel, modules = kernel_fixture
    (modules / "modules.dep").unlink()
    with pytest.raises(ApplianceDenied, match="MODULES_MISSING_OR_MISMATCH"):
        inspect_kernel(env, root)


def test_kernel_symlink_denied(kernel_fixture):
    env, root, kernel, _modules = kernel_fixture
    alias = kernel.with_name(kernel.name + "-alias")
    kernel.rename(alias)
    kernel.symlink_to(alias)
    with pytest.raises(ApplianceDenied, match="KERNEL_MISSING"):
        inspect_kernel(env, root)


def _fake_guest(
    monkeypatch,
    synthetic: Path,
    *,
    drives=1,
    sector=512,
    launch_error=None,
    shutdown_error=None,
    missing_tail=False,
):
    calls: list[dict] = []
    status = {"shutdown": False, "close": False}
    size = synthetic.stat().st_size

    class FakeGuest:
        def __init__(self, **opts):
            assert opts["python_return_dict"] is True

        def set_backend(self, backend):
            assert backend == "direct"

        def add_drive_opts(self, path, **opts):
            calls.append(opts)
            assert path == str(synthetic)
            assert opts["format"] == "raw"
            assert opts["readonly"] == 1
            # libguestfs rejects digits and punctuation in disk labels.
            assert re.fullmatch(r"gaslux[a-f]{12}", opts["label"])

        def launch(self):
            if launch_error is not None:
                raise RuntimeError(launch_error)

        def list_devices(self):
            return ["/dev/diagnostic"] * drives

        def blockdev_getsize64(self, device):
            return size

        def blockdev_getss(self, device):
            return sector

        def pread_device(self, _device, length, offset):
            if missing_tail and offset > 0:
                return b""
            with synthetic.open("rb") as src:
                src.seek(offset)
                return src.read(length)

        def shutdown(self):
            status["shutdown"] = True
            if shutdown_error is not None:
                raise RuntimeError(shutdown_error)

        def close(self):
            status["close"] = True

    monkeypatch.setitem(sys.modules, "guestfs", SimpleNamespace(GuestFS=FakeGuest))
    return calls, status


def test_mock_observer_reconciles_gpt_but_not_trust_boundary(tmp_path, monkeypatch):
    synthetic = tmp_path / "synthetic-gpt.raw"
    make_image(synthetic)
    assert synthetic.stat().st_size == SECTORS * 512
    calls, status = _fake_guest(monkeypatch, synthetic)
    report = observe_appliance(synthetic, tmp_path)
    assert report["hostGuestGptMatches"] is True
    assert report["guestDiskSerialAuthenticated"] is False
    assert report["guestAttachedDrives"] == 1
    assert report["applianceShutdownVerified"] is True
    assert calls[0]["readonly"] == 1
    assert status == {"shutdown": True, "close": True}


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"drives": 2}, "GUESTFS_MULTIPLE_OR_MISSING_DISKS"),
        ({"sector": 4096}, "GUESTFS_GEOMETRY_OR_LABEL_MISMATCH"),
        ({"missing_tail": True}, "GUESTFS_GPT_WITNESS_INCOMPLETE"),
        (
            {"launch_error": "supermin exited with error status 1"},
            "GUESTFS_LAUNCH_RuntimeError_SUPERMIN_EXIT",
        ),
        ({"shutdown_error": "shutdown failure"}, "GUESTFS_SHUTDOWN_FAILED"),
    ],
)
def test_appliance_missing_disk_wrong_sector_failed_boot_cleanup(
    tmp_path, monkeypatch, settings, message
):
    synthetic = tmp_path / "synthetic-gpt.raw"
    make_image(synthetic)
    calls, status = _fake_guest(monkeypatch, synthetic, **settings)
    with pytest.raises((ApplianceDenied, RuntimeError), match=message):
        observe_appliance(synthetic, tmp_path)
    assert calls[0]["readonly"] == 1
    assert status["close"] is True


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ("supermin exited with error status 1", "SUPERMIN_EXIT_NONZERO_CAUSE_UNCLASSIFIED"),
        ("supermin: no suitable kernel", "KERNEL_NOT_FOUND_BY_SUPERMIN"),
        ("Permission denied", "KERNEL_OR_MODULES_UNREADABLE"),
        ("Module dependency not found", "MODULE_DEPENDENCY_MISSING"),
        ("timed out", "APPLIANCE_BOOT_TIMEOUT"),
    ],
)
def test_only_bounded_supermin_error_categories(detail, expected):
    assert classify_diagnostic(detail) == expected


def test_no_real_disk_or_writer_in_preflight_source():
    content = (ROOT / "auto_tests/tools/q4os_libguestfs_preflight.py").read_text(encoding="utf-8")
    assert "readonly=1" in content
    assert "label=name" in content
    assert "guestfs.GuestFS" in content
    for forbidden in ["grub-install", "mkfs.", "mount -o rw", "sudo fsck", "efibootmgr"]:
        assert forbidden not in content


def test_windows_workflow_requires_actual_guestfs_gate_before_iso_and_no_auto_run():
    import yaml

    workflow_path = ROOT / ".github/workflows/gaslux-q4os-windows10-qcow2.yml"
    document = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    on = document.get("on", document.get(True, {}))
    assert "workflow_dispatch" in on
    assert "pull_request" not in on and "push" not in on
    names = [step.get("name", "") for step in document["jobs"]["windows10-uefi-gpt"]["steps"]]
    assert names.index(
        "BLOCKED_GUESTFS_APPLIANCE unless real synthetic QEMU GPT observer passes"
    ) < names.index(
        "Download Microsoft Windows 10 Enterprise Evaluation 22H2 and verify official SHA-256"
    )
    preflight = document["jobs"]["windows10-uefi-gpt"]["steps"][
        names.index("BLOCKED_GUESTFS_APPLIANCE unless real synthetic QEMU GPT observer passes")
    ]["run"]
    assert "windows_x64_libguestfs_kernel.sh" in preflight
    assert "q4os_libguestfs_preflight.py" in preflight
    assert "f55633c90973f633dda678f583f7730fc2cdc0ce" in preflight
    assert "test -s" in preflight
    assert "LIBGUESTFS_TMPDIR" in preflight
    assert "GASLUX_WIN10_LAB_PASSWORD" not in workflow_path.read_text(encoding="utf-8")
