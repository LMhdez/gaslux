"""Adversarial QEMU surface contracts. No guest events are sent."""

from dataclasses import replace
from pathlib import Path

import pytest

from auto_tests.installer_observer import qemu_surface
from auto_tests.installer_observer.evidence import Refusal
from auto_tests.installer_observer.lab_identity import ProcessSeal


def sample(monkeypatch):
    process = ProcessSeal(12345, 1000, 123, "a" * 64, 1, 1)
    qmp = Path("/private/qmp.sock")
    args = (
        "qemu-system-x86_64", "-no-user-config", "-nodefaults",
        "-machine", "pc", "-accel", "tcg", "-m", "128",
        "-vga", "std", "-display", "none", "-monitor", "none",
        "-serial", "none", "-net", "none", "-vnc", "127.0.0.1:0",
        "-qmp", f"unix:{qmp},server=on,wait=off",
        "-drive", "file=/tmp/empty.qcow2,if=virtio,format=qcow2,cache=none",
        "-drive", "file=/tmp/fixture.iso,media=cdrom,format=raw,readonly=on",
        "-boot", "order=d",
    )
    monkeypatch.setattr(qemu_surface, "process_seal", lambda _pid: process)
    original = Path.read_bytes

    def read_bytes(self):
        if str(self) == "/proc/12345/cmdline":
            return b"\\0".join(part.encode() for part in args) + b"\\0"
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    return process, args, qmp


def test_live_contract_always_blocks_loopback_rfb(monkeypatch):
    process, args, qmp = sample(monkeypatch)
    result = qemu_surface.inspect_input_surface(process, args, qmp)
    assert result.hmp_disabled and result.spice_disabled
    assert len(result.blockers) == 3
    with pytest.raises(Refusal, match="Unisolated guest input"):
        result.require_exclusive_input()


@pytest.mark.parametrize(
    ("index", "value"),
    [
        (14, "stdio"),  # HMP
        (12, "gtk"),  # graphical display
        (16, "pty"),  # serial
        (18, "user"),  # guest network
        (20, "0.0.0.0:0"),  # exposed VNC
        (22, "tcp:127.0.0.1:4444,server=on"),  # QMP TCP
    ],
)
def test_extra_or_reconfigured_channels_refused(monkeypatch, index, value):
    process, args, qmp = sample(monkeypatch)
    modified = list(args)
    modified[index] = value
    with pytest.raises(Refusal, match="recorded launch"):
        qemu_surface.inspect_input_surface(process, tuple(modified), qmp)


def test_qemu_process_change_revokes_surface(monkeypatch):
    process, args, qmp = sample(monkeypatch)
    with pytest.raises(Refusal, match="identity changed"):
        qemu_surface.inspect_input_surface(replace(process, start_ticks=456), args, qmp)


def test_forged_session_command_is_refused(monkeypatch):
    process, args, qmp = sample(monkeypatch)
    with pytest.raises(Refusal, match="recorded launch"):
        qemu_surface.inspect_input_surface(process, args[:-2], qmp)


def test_unverified_qmp_socket_refused(monkeypatch):
    process, args, _qmp = sample(monkeypatch)
    with pytest.raises(Refusal, match="unsupported monitor"):
        qemu_surface.inspect_input_surface(process, args, Path("/private/replaced.sock"))


def test_incomplete_frame_action_has_no_authority(monkeypatch):
    process, args, qmp = sample(monkeypatch)
    surface = qemu_surface.inspect_input_surface(process, args, qmp)
    # Even a forged audit with no remaining known channel blockers is not
    # an authorization: an atomic capture-and-input primitive is absent.
    with pytest.raises(Refusal, match="No atomic framebuffer"):
        replace(surface, blockers=()).require_exclusive_input()
