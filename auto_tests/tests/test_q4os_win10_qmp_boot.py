"""Disposable QMP protocol regressions; no real Windows ISO or guest disk."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "auto_tests/tools"))

from q4os_win10_qmp_boot import BootRefusal, supervise  # noqa: E402


class FakeQemu:
    def __init__(self, socket_path: Path, disk: Path, *, error=False, corrupt=False, grow=True):
        self.socket_path = socket_path
        self.disk = disk
        self.error = error
        self.corrupt = corrupt
        self.grow = grow
        self.commands: list[str] = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(socket_path))
        self.server.listen(1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        client, _ = self.server.accept()
        with client:
            greeting = {
                "QMP": {
                    "version": {"qemu": {"major": 9, "minor": 0, "micro": 0}},
                    "capabilities": [],
                }
            }
            if self.corrupt:
                greeting = {"unexpected": True}
            client.sendall(json.dumps(greeting).encode() + b"\r\n")
            reader = client.makefile("rb")
            try:
                while True:
                    line = reader.readline()
                    if not line:
                        break
                    request = json.loads(line)
                    cmd = request["execute"]
                    self.commands.append(cmd)
                    if cmd == "send-key" and self.error:
                        answer = {"error": {"class": "GenericError", "desc": "unavailable"}}
                    elif cmd == "query-status":
                        answer = {"return": {"running": True, "status": "running"}}
                    else:
                        answer = {"return": {}}
                    answer["id"] = request["id"]
                    client.sendall(json.dumps(answer).encode() + b"\r\n")
                    if cmd == "send-key":
                        assert request["arguments"]["keys"] == [{"type": "qcode", "data": "ret"}]
                        if self.grow and not self.error:
                            self.disk.write_bytes(b"x" * (5 * 1024 * 1024))
                        break
            finally:
                reader.close()

    def close(self):
        self.server.close()
        self.thread.join(timeout=1)


@pytest.fixture
def lab(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    disk = root / "windows-synthetic.qcow2"
    disk.write_bytes(b"qcow-synthetic")
    serial = root / "firmware.log"
    serial.write_bytes(b"")
    qmp = root / "qmp.sock"
    return qmp, serial, disk


def run(lab, **overrides):
    qmp, serial, disk = lab
    return supervise(
        qmp,
        serial,
        disk,
        connect_seconds=0.25,
        prompt_seconds=0.25,
        progress_seconds=0.25,
        tick=0.01,
        **overrides,
    )


def test_prompt_detected_key_acknowledged_progress_observed_once(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"\x1b[2JPress any key to boot from CD or DVD......")
    server = FakeQemu(qmp, disk)
    try:
        result = run(lab)
        assert result["decision"] == "dvd_key_sent_once"
        assert result["qmpSendKeyAcknowledged"] is True
        assert result["windowsSetupVerified"] is False
        assert server.commands == ["qmp_capabilities", "query-status", "send-key"]
    finally:
        server.close()


def test_prompt_missing_is_refused_without_keyboard_input(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"BdsDxe: starting DVD")
    server = FakeQemu(qmp, disk)
    try:
        with pytest.raises(BootRefusal, match="dvd_prompt_not_detected"):
            run(lab)
        assert "send-key" not in server.commands
    finally:
        server.close()


def test_qmp_unavailable_refused(lab):
    with pytest.raises(BootRefusal, match="qmp_socket_unavailable"):
        run(lab)


def test_malformed_qmp_greeting_refused(lab):
    qmp, serial, disk = lab
    server = FakeQemu(qmp, disk, corrupt=True)
    try:
        with pytest.raises(BootRefusal, match="invalid_qmp_greeting"):
            run(lab)
        assert "send-key" not in server.commands
    finally:
        server.close()


def test_qmp_key_send_error_refused(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"Press any key to boot from CD or DVD")
    server = FakeQemu(qmp, disk, error=True)
    try:
        with pytest.raises(BootRefusal, match="qmp_send_key_failed"):
            run(lab)
        assert server.commands.count("send-key") == 1
    finally:
        server.close()


def test_efi_shell_detected_before_prompt_is_refused(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"UEFI Interactive Shell v2.2\nShell> ")
    server = FakeQemu(qmp, disk)
    try:
        with pytest.raises(BootRefusal, match="uefi_shell_detected"):
            run(lab)
        assert "send-key" not in server.commands
    finally:
        server.close()


def test_boot_timeout_marker_refused(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"BdsDxe: failed to start Boot0001: Time out")
    server = FakeQemu(qmp, disk)
    try:
        with pytest.raises(BootRefusal, match="uefi_boot_timeout"):
            run(lab)
        assert "send-key" not in server.commands
    finally:
        server.close()


def test_dvd_key_not_taken_no_disk_progress_refused(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"Press any key to boot from CD or DVD")
    server = FakeQemu(qmp, disk, grow=False)
    try:
        with pytest.raises(BootRefusal, match="no_disk_progress_after_dvd_key"):
            run(lab)
        assert server.commands.count("send-key") == 1
    finally:
        server.close()


def test_later_reboot_never_receives_second_key(lab):
    qmp, serial, disk = lab
    serial.write_bytes(b"Press any key to boot from CD or DVD")
    server = FakeQemu(qmp, disk)
    try:
        assert run(lab)["decision"] == "dvd_key_sent_once"
        with serial.open("ab") as stream:
            stream.write(b"\nPress any key to boot from CD or DVD......")
        time.sleep(0.01)
        assert server.commands.count("send-key") == 1
    finally:
        server.close()


def test_serial_log_symlink_refused(lab):
    qmp, serial, disk = lab
    elsewhere = serial.with_suffix(".elsewhere")
    elsewhere.write_bytes(b"Press any key to boot from CD or DVD")
    serial.unlink()
    serial.symlink_to(elsewhere)
    server = FakeQemu(qmp, disk)
    try:
        with pytest.raises(BootRefusal, match="unsafe_serial_path"):
            run(lab)
        assert "send-key" not in server.commands
    finally:
        server.close()


def test_private_directory_required(lab):
    qmp, serial, disk = lab
    os.chmod(qmp.parent, 0o755)
    with pytest.raises(BootRefusal, match="nonprivate_lab_directory"):
        run(lab)


def test_workflow_runs_qmp_once_and_never_exports_vm_password():
    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/gaslux-q4os-windows10-qcow2.yml"
    ).read_text(encoding="utf-8")
    assert "GASLUX_WIN10_LAB_PASSWORD" not in workflow
    assert "q4os_win10_qmp_boot.py" in workflow
    assert '--qmp "$qmp" --serial "$serial" --disk "$image"' in workflow
    assert "unix:$qmp,server=on,wait=off" in workflow
    assert "qemu_timeout=7200" in workflow
    assert "qemu_timeout=14400" in workflow
    assert "tail -n 120" not in workflow
    assert "name: q4os-windows10-genuine-readonly-safety-refusal-text" in workflow
    assert "boot-controller.json" in workflow


def test_windows_qemu_workflow_bash_scripts_parse_without_execution():
    workflow_path = (
        Path(__file__).resolve().parents[2] / ".github/workflows/gaslux-q4os-windows10-qcow2.yml"
    )
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["windows10-uefi-gpt"]["steps"]
    assert len(steps) >= 8
    for step in steps:
        if step.get("shell") != "bash":
            continue
        result = subprocess.run(
            ["bash", "-n"],
            input=step["run"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0, (step["name"], result.stderr)
