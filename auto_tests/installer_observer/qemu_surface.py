"""Independent audit of the disposable QEMU laboratory's input channels.

This module reports *exposure*, never permission to send input. A process
fingerprint and cooperative flock do not prevent same-UID QMP/RFB clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .evidence import Refusal
from .lab_identity import ProcessSeal, process_seal


@dataclass(frozen=True)
class InputSurface:
    qmp_unix: str
    rfb_listener: str
    hmp_disabled: bool
    spice_disabled: bool
    serial_disabled: bool
    display_disabled: bool
    guest_network_disabled: bool
    blockers: tuple[str, ...]

    def require_exclusive_input(self) -> None:
        """Fail closed. An audit is not an atomic framebuffer/input primitive."""
        if self.blockers:
            raise Refusal("Unisolated guest input: " + "; ".join(self.blockers))
        raise Refusal("No atomic framebuffer-and-input capability has been proven")


def inspect_input_surface(
    process: ProcessSeal, launched: tuple[str, ...], qmp_socket: Path
) -> InputSurface:
    """Cross-check actual /proc argv against a tightly reviewed QEMU launch.

    The caller must supply the command independently recorded *before* spawn.
    Unrecognised arguments are not interpreted as harmless: the exact ordered
    launch contract intentionally rejects all deviations.
    """
    if process_seal(process.pid) != process:
        raise Refusal("QEMU process identity changed during channel audit")
    try:
        raw = (Path("/proc") / str(process.pid) / "cmdline").read_bytes()
    except OSError as exc:
        raise Refusal("QEMU process argv unavailable") from exc
    if not raw.endswith(b"\\0"):
        raise Refusal("Malformed QEMU argv")
    try:
        actual = tuple(item.decode("utf-8") for item in raw[:-1].split(b"\\0"))
    except UnicodeDecodeError as exc:
        raise Refusal("QEMU argv has invalid encoding") from exc
    if not launched or actual != launched:
        raise Refusal("Actual QEMU argv differs from recorded launch")
    if (
        len(launched) != 29
        or Path(launched[0]).name != "qemu-system-x86_64"
        or launched[1:3] != ("-no-user-config", "-nodefaults")
        or launched[3:7] != ("-machine", "pc", "-accel", "tcg")
        or launched[7:11] != ("-m", "128", "-vga", "std")
        or launched[11:19]
        != (
            "-display", "none", "-monitor", "none",
            "-serial", "none", "-net", "none",
        )
        or launched[19:23]
        != (
            "-vnc", "127.0.0.1:0",
            "-qmp", f"unix:{qmp_socket},server=on,wait=off",
        )
        or launched[23] != "-drive"
        or launched[25] != "-drive"
        or launched[27:29] != ("-boot", "order=d")
    ):
        raise Refusal("QEMU contains unsupported monitor, display or input channels")
    # Drives and boot configuration are authenticated separately by QMP/procfs;
    # this check does not replace the storage/snapshot attestor.
    return InputSurface(
        qmp_unix=str(qmp_socket),
        rfb_listener="127.0.0.1:5900 (RFB 3.8, no authentication)",
        hmp_disabled=True,
        spice_disabled=True,
        serial_disabled=True,
        display_disabled=True,
        guest_network_disabled=True,
        blockers=(
            "Loopback RFB admits external host clients",
            "QMP Unix socket remains accessible to same-UID processes",
            "Framebuffer comparison and RFB input cannot be atomic",
        ),
    )
