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
        "-device",
        "qemu-xhci,id=usbctrl",
        "-device",
        "usb-kbd,bus=usbctrl.0",
        "-qmp",
        f"unix:{root / 'windows10-qemu-qmp.sock'},server=on,wait=off",
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
        tmp_path / "windows10-qemu-qmp.sock",
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
    with pytest.raises(WindowsDvdRefusal, match="Unexpected Windows QEMU evidence path"):
        _validate_lab(root, root / "foreign.log", monitor, log, make_args(root))


def test_efi_prompt_gate_never_runs_actual_installer_in_unit_tests(monkeypatch, paths):
    root, serial, monitor, log = paths
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    with pytest.raises(WindowsDvdRefusal, match="lab-only"):
        run(root, serial, monitor, log, make_args(root))
    assert not log.exists()
    assert not serial.exists()
    assert not monitor.exists()


def test_workflow_reuses_pinned_proven_microsoft_efi_noprompt_code():
    """The verified Microsoft ISO, not a fabricated EFI binary, is the origin."""
    import yaml

    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/gaslux-q4os-windows10-qcow2.yml").read_text()
    assert "ref: 1b01b7a697326bba00ab114d7843464fbfbf4fee" in workflow
    assert "from windows_x64_tcg_firstboot import derive_no_prompt_uefi_lab_iso" in workflow
    assert "ef7312733a9f5d7d51cfa04ac497671995674ca5e1058d5164d6028f0938d668" in workflow
    assert "GASLUX_WIN10_ORIGINAL_OFFICIAL_ISO_UNMODIFIED=PASS" in workflow
    assert "GASLUX_WIN10_NOPROMPT_SHA256" in workflow
    assert "GASLUX_WIN10_ACCEL\" == kvm" in workflow
    assert "GASLUX_WINDOWS_KVM_CONSENT: I_ACCEPT_DISPOSABLE_GITHUB_KVM_ONLY" in workflow
    assert "-no-reboot" in workflow
    assert "qemu-nbd --read-only" in workflow
    assert "timeout-minutes: 90" in workflow
    assert "Press any key to boot from CD or DVD" in workflow
    assert "windows10-qemu-qmp.sock" not in workflow
    assert "windows10-qemu-hmp.sock" not in workflow
    assert "gaslux_q4os_win10_ovmf_dvd_input.py \\" not in workflow
    doc = yaml.safe_load(workflow)
    assert "windows10-uefi-gpt" in doc["jobs"]
    steps = doc["jobs"]["windows10-uefi-gpt"]["steps"]
    uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact")]
    assert len(uploads) == 2
    for step in uploads:
        for line in step["with"]["path"].splitlines():
            assert not line.strip().endswith(".iso")
            assert "Autounattend.xml" not in line
    assert any(
        "if-no-files-found" in step.get("with", {})
        for step in uploads
    )


def test_proven_no_prompt_workflow_never_disables_windows_recovery_assertions():
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/gaslux-q4os-windows10-qcow2.yml").read_text()
    for witness in (
        "GASLUX_WINDOWS_FIRST_LOGON=PASS",
        "GASLUX_WINDOWS_WINRE=PASS",
        "sgdisk --verify /dev/nbd0",
        "bootmgfw.efi",
        "winload.efi",
        "Winre.wim",
        "Windows/System32",
        "qemu-img check",
        "no backing",
    ):
        # The QCOW2 no-backing check is expressed as an exact JSON property.
        if witness == "no backing":
            assert 'not x.get("backing-filename")' in workflow
        else:
            assert witness in workflow


def test_helper_rejects_mismatched_qemu_monitor_path_even_when_owned(paths):
    root, serial, monitor, log = paths
    wrong = root / "windows10-qemu-hmp.sock"
    with pytest.raises(WindowsDvdRefusal, match="Unexpected Windows QEMU evidence path"):
        _validate_lab(root, serial, wrong, log, make_args(root))


def test_qmp_hid_hold_survives_firmware_polling_interval(tmp_path):
    """Actual Unix QMP frames must hold Space before releasing it."""
    import json
    import os
    import socket
    import threading
    import time

    from auto_tests.tools.gaslux_q4os_win10_ovmf_dvd_input import _send_key

    endpoint = tmp_path / "windows10-qemu-qmp.sock"
    observed = []
    failures = []
    ready = threading.Event()

    def fake_qmp():
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(endpoint))
                server.listen(1)
                ready.set()
                connection, _ = server.accept()
                with connection, connection.makefile("rwb", buffering=0) as stream:
                    stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
                    for expected in (
                        "gaslux-capabilities",
                        "gaslux-ovmf-space-down",
                        "gaslux-ovmf-space-up",
                    ):
                        request = json.loads(stream.readline())
                        assert request["id"] == expected
                        observed.append((time.monotonic(), request))
                        reply = json.dumps({"return": {}, "id": expected}).encode()
                        stream.write(reply + b"\r\n")
        except Exception as exc:
            failures.append(exc)

    server_thread = threading.Thread(target=fake_qmp, daemon=True)
    server_thread.start()
    assert ready.wait(timeout=2)
    _send_key(endpoint, os.getpid())
    server_thread.join(timeout=3)
    assert not server_thread.is_alive()
    assert not failures
    assert len(observed) == 3
    down = observed[1][1]["arguments"]["events"]
    up = observed[2][1]["arguments"]["events"]
    assert len(down) == len(up) == 1
    assert down[0]["data"] == {"key": {"type": "qcode", "data": "spc"}, "down": True}
    assert up[0]["data"] == {"key": {"type": "qcode", "data": "spc"}, "down": False}
    assert observed[2][0] - observed[1][0] >= 0.24


def test_qmp_hid_refuses_foreign_peer_without_input(tmp_path):
    """SO_PEERCRED must reject the wrong QEMU PID before pressing a key."""
    import os
    import socket
    import threading

    from auto_tests.tools.gaslux_q4os_win10_ovmf_dvd_input import _send_key

    endpoint = tmp_path / "windows10-qemu-qmp.sock"
    ready = threading.Event()

    def fake_server():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(endpoint))
            server.listen(1)
            ready.set()
            connection, _ = server.accept()
            connection.close()

    thread = threading.Thread(target=fake_server, daemon=True)
    thread.start()
    assert ready.wait(timeout=2)
    with pytest.raises(WindowsDvdRefusal, match="peer does not match"):
        _send_key(endpoint, os.getpid() + 100)
    thread.join(timeout=2)
    assert not thread.is_alive()
