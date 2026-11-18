"""Fail-closed tests for the Q4OS Windows 10 OVMF DVD prompt lab."""

from __future__ import annotations

from pathlib import Path

import pytest

from auto_tests.tools.gaslux_q4os_win10_ovmf_dvd_input import (
    WindowsDvdRefusal,
    _validate_lab,
    inspect_serial_for_boot_prompt,
    run,
)


def test_windows_ovmf_cd_prompt_detected():
    raw = b"\x1b[01;01HPress any key to boot from CD or DVD......"
    assert inspect_serial_for_boot_prompt(raw) == "prompt"


@pytest.mark.parametrize(
    "raw",
    [
        b"BdsDxe: failed to start Boot0001",
        b"UEFI Interactive Shell v2.2",
        b"Press any key to boot from CD or DVD......UEFI Interactive Shell",
    ],
)
def test_efi_shell_or_boot_timeout_never_count_as_windows_install(raw):
    with pytest.raises(WindowsDvdRefusal):
        inspect_serial_for_boot_prompt(raw)


def test_no_prompt_is_pending():
    assert inspect_serial_for_boot_prompt(b"BdsDxe: loading Boot0001") == "pending"


def make_args(root: Path) -> list[str]:
    return [
        "qemu-system-x86_64",
        "-no-user-config",
        "-no-reboot",
        "-monitor",
        f"unix:{root / 'windows10-qemu-hmp.sock'},server=on,wait=off",
        "-net",
        "none",
        "-drive",
        (
            f"if=none,id=system,file={root / 'windows10-enterprise-eval-22h2-uefi-gpt.qcow2'},"
            "format=qcow2"
        ),
        "-drive",
        (
            f"if=none,id=install,file={root / 'Windows10_Enterprise_22H2_Eval_EN-US_x64.iso'},"
            "format=raw,readonly=on"
        ),
        "-drive",
        f"if=none,id=answer,file={root / 'unattend.iso'},format=raw,readonly=on",
        "-drive",
        "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
        "-drive",
        f"if=pflash,format=raw,unit=1,file={root / 'OVMF_VARS.fd'}",
    ]


@pytest.fixture
def paths(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GASLUX_WIN10_UEFI_OPTICAL_INPUT_LAB_ONLY", "yes")
    return (
        tmp_path,
        tmp_path / "windows10-qemu-serial.log",
        tmp_path / "windows10-qemu-hmp.sock",
        tmp_path / "windows10-qemu-process.log",
    )


def test_private_qemu_only_authorized_in_actions(paths):
    root, serial, monitor, log = paths
    _validate_lab(root, serial, monitor, log, make_args(root))


@pytest.mark.parametrize(
    "name,change",
    [
        ("non-qemu", lambda a: ["echo", *a[1:]]),
        ("no-monitor", lambda a: [x for x in a if not x.startswith("unix:")]),
        ("host-device", lambda a: [*a, "-drive", "file=/dev/sda,if=none"]),
        ("network", lambda a: [*a, "-netdev", "user,id=untrusted"]),
        ("missing-iso", lambda a: [x for x in a if "id=install" not in x]),
        ("missing-disk", lambda a: [x for x in a if "id=system" not in x]),
        ("missing-answer", lambda a: [x for x in a if "id=answer" not in x]),
        ("extra-drive", lambda a: [*a, "-drive", "if=none,id=other,file=/tmp/foreign.img"]),
    ],
)
def test_qemu_argv_refuses_foreign_targets(paths, name, change):
    root, serial, monitor, log = paths
    with pytest.raises(WindowsDvdRefusal):
        _validate_lab(root, serial, monitor, log, change(make_args(root)))


def test_lab_refuses_without_separate_optin(monkeypatch, paths):
    root, serial, monitor, log = paths
    monkeypatch.delenv("GASLUX_WIN10_UEFI_OPTICAL_INPUT_LAB_ONLY")
    with pytest.raises(WindowsDvdRefusal, match="lab-only"):
        _validate_lab(root, serial, monitor, log, make_args(root))


def test_lab_refuses_nonowned_or_unbounded_input(paths):
    root, serial, monitor, log = paths
    with pytest.raises(WindowsDvdRefusal, match="bounded"):
        run(root, serial, monitor, log, make_args(root), prompt_seconds=3600)
    with pytest.raises(WindowsDvdRefusal, match="Foreign"):
        _validate_lab(root, root / "foreign.log", monitor, log, make_args(root))


def test_efi_prompt_gate_never_runs_actual_installer_in_unit_tests(monkeypatch, paths):
    root, serial, monitor, log = paths
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    with pytest.raises(WindowsDvdRefusal, match="lab-only"):
        run(root, serial, monitor, log, make_args(root))
    assert not log.exists()
    assert not serial.exists()
    assert not monitor.exists()


def test_workflow_uses_only_private_monitor_and_bounded_cycles():
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/gaslux-q4os-windows10-qcow2.yml").read_text()
    assert "gaslux_q4os_win10_ovmf_dvd_input.py" in workflow
    assert "GASLUX_WIN10_UEFI_OPTICAL_INPUT_LAB_ONLY: 'yes'" in workflow
    assert "timeout-minutes: 90" in workflow
    assert "windows10-qemu-hmp.sock" in workflow
    assert "cycle_limit" in workflow
    assert "-no-reboot" in workflow
    assert "qemu-nbd --read-only" in workflow
