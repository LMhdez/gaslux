"""Fail-closed tests for the synthetic Windows-sized QEMU/OVMF startup gate."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))

import q4os_win10_qemu_ovmf_preflight as probe  # noqa: E402


@pytest.mark.parametrize(
    ("stderr", "code"),
    [
        (b"qemu: failed to initialize kvm: permission denied", "QEMU_KVM_INITIALIZATION_FAILED"),
        (b"qemu: cannot allocate memory", "QEMU_HOST_MEMORY_UNAVAILABLE"),
        (b"Bus 'sata.0' not found", "QEMU_SATA_BUS_NOT_FOUND"),
        (b"Property 'pflash.foo' not found", "QEMU_DEVICE_OPTION_UNSUPPORTED"),
        (b"Could not open media: permission denied", "QEMU_FILE_ACCESS_DENIED"),
        (b"failed to open an owned file", "QEMU_MEDIA_OPEN_FAILED"),
        (b"Host secret /tmp/token-A", "QEMU_EARLY_EXIT_UNCLASSIFIED"),
    ],
)
def test_only_allowlisted_ovmf_error_codes(stderr, code):
    result = probe.classify_qemu_error(stderr)
    assert result == code
    assert "/" not in result and "token" not in result.lower()


def test_disallow_unapproved_hosted_scope(tmp_path):
    with pytest.raises(probe.QemuStartupDenied, match="UNAUTHORIZED_QEMU_LAB"):
        probe.require_hosted_scope({"GITHUB_ACTIONS": "true"}, tmp_path)


def _fake_qemu(monkeypatch, tmp_path, *, exit_early=False):
    code = tmp_path / "OVMF_CODE_4M.fd"
    vars_file = tmp_path / "OVMF_VARS_4M.fd"
    code.write_bytes(b"synthetic-code")
    vars_file.write_bytes(b"synthetic-vars")
    monkeypatch.setattr(probe, "OVMF_CODE", code)
    monkeypatch.setattr(probe, "OVMF_VARS", vars_file)

    seen = []

    def create_disk(args, **kwargs):
        assert args[:4] == ["/usr/bin/qemu-img", "create", "-f", "qcow2"]
        assert args[-1] == "48G"
        Path(args[-2]).write_bytes(b"synthetic-qcow2")
        assert kwargs["timeout"] == 20
        return SimpleNamespace(returncode=0)

    class FakeProcess:
        def __init__(self, args, **kwargs):
            seen.append(args)
            assert kwargs["stdin"] == probe.subprocess.DEVNULL
            assert kwargs["cwd"] == tmp_path
            qmp_arg = args[args.index("-qmp") + 1]
            assert qmp_arg.startswith("unix:") and "server=on" in qmp_arg
            self.socket = Path(qmp_arg.removeprefix("unix:").split(",")[0])
            if exit_early:
                kwargs["stdout"].write(b"qemu: failed to initialize kvm\n")
                kwargs["stdout"].flush()
            else:
                self.socket.touch()
            self.terminated = False

        def poll(self):
            return 1 if exit_early else (0 if self.terminated else None)

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            assert timeout <= 8
            return 1 if exit_early else 0

        def kill(self):
            self.terminated = True

    class FakeQmp:
        def __init__(self, socket):
            assert socket.is_file()  # Test substitute, not a real QMP socket.
            self.closed = False

        def close(self):
            self.closed = True

    monkeypatch.setattr(probe.subprocess, "run", create_disk)
    monkeypatch.setattr(probe.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(probe, "Qmp", FakeQmp)
    return seen


def test_actual_machine_graph_would_start_but_only_synthetic_inputs(tmp_path, monkeypatch):
    seen = _fake_qemu(monkeypatch, tmp_path)
    report = probe._run_qemu(tmp_path)
    args = seen[0]
    assert report["qmpHandshakeAndRunningVerified"]
    assert report["qmpKeySent"] is False
    assert report["syntheticQcow2VirtualBytes"] == 48 * 1024**3
    assert args[args.index("-m") + 1] == "6144"
    assert args[args.index("-accel") + 1] == "kvm"
    assert args[args.index("-cpu") + 1] == "host"
    assert "ich9-ahci,id=sata" in args
    assert sum(x == "-device" for x in args) == 4
    assert all("Windows10_Enterprise" not in x for x in args)
    assert all("/dev/nbd" not in x for x in args)


def test_early_qemu_exit_has_bounded_causal_code(tmp_path, monkeypatch):
    _fake_qemu(monkeypatch, tmp_path, exit_early=True)
    with pytest.raises(probe.QemuStartupDenied, match="QEMU_KVM_INITIALIZATION_FAILED"):
        probe._run_qemu(tmp_path)


def test_no_new_writers_or_windows_data_in_synthetic_probe():
    source = (ROOT / "auto_tests/tools/q4os_win10_qemu_ovmf_preflight.py").read_text(
        encoding="utf-8"
    )
    assert "qemu-system-x86_64" in source
    assert "SYNTHETIC_QEMU_OVMF_QMP_PASS_NO_WRITER" in source
    assert "GASLUX_Q4OS_OVMF_EVIDENCE" in source
    for forbidden in ("grub-install ", "calamares --", "efibootmgr ", "mkfs.", "/dev/sda", "/dev/nbd"):
        assert forbidden not in source.lower()


def test_genuine_windows_workflow_requires_smoke_before_iso():
    import yaml

    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/gaslux-q4os-windows10-qcow2.yml").read_text(
            encoding="utf-8"
        )
    )
    names = [x.get("name", "") for x in workflow["jobs"]["windows10-uefi-gpt"]["steps"]]
    synthetic_index = names.index(
        "BLOCKED_GUESTFS_APPLIANCE unless real synthetic QEMU GPT observer passes"
    )
    qemu_index = names.index(
        "BLOCKED_QEMU_OVMF_STARTUP unless full-size synthetic QMP smoke passes"
    )
    iso_index = names.index(
        "Download Microsoft Windows 10 Enterprise Evaluation 22H2 and verify official SHA-256"
    )
    assert synthetic_index < qemu_index < iso_index
    run = workflow["jobs"]["windows10-uefi-gpt"]["steps"][qemu_index]["run"]
    assert "q4os_win10_qemu_ovmf_preflight.py" in run
    assert "timeout" in run
    assert "LIBGUESTFS" not in run
