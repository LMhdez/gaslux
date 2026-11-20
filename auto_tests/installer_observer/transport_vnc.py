"""Read-only RFB 3.8 framebuffer adapter for isolated QEMU/VNC laboratories.

There is deliberately no pointer or keyboard encoder. RFB does not provide an
atomic compare-framebuffer-and-click primitive; live input remains disabled.
"""

from __future__ import annotations

import io
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from PIL import Image

from .evidence import Refusal
from .locators import Surface
from .screenshot import Screenshot, Size
from .state_machine import Frame, LabAuthority


class LabAttestor(Protocol):
    def verify(self, deadline: float) -> LabAuthority:
        """Return independently verified VM, snapshot, media and disk provenance."""


class FrameReader(Protocol):
    def read_png(self, deadline: float, size: Size) -> bytes: ...


@dataclass
class RfbReader:
    """Loopback-only, unauthenticated RFB 3.8 RAW full-frame reader (no input API)."""

    host: str = "127.0.0.1"
    port: int = 5900
    dial: Callable[..., socket.socket] = socket.create_connection
    clock: Callable[[], float] = time.monotonic

    def read_png(self, deadline: float, size: Size) -> bytes:
        if self.host not in ("127.0.0.1", "::1") or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise Refusal("Only an explicitly selected loopback VNC endpoint is permitted")
        if (len(size) != 2 or any(type(n) is not int for n in size)
                or not 0 < size[0] * size[1] <= 8_000_000):
            raise Refusal("Invalid framebuffer contract")
        if self.clock() >= deadline:
            raise Refusal("VNC deadline expired")
        try:
            with self.dial((self.host, self.port), timeout=deadline - self.clock()) as sock:
                def take(n: int) -> bytes:
                    if self.clock() >= deadline:
                        raise Refusal("VNC deadline expired")
                    sock.settimeout(max(0.001, deadline - self.clock()))
                    chunks = bytearray()
                    while len(chunks) < n:
                        if self.clock() >= deadline:
                            raise Refusal("VNC deadline expired")
                        sock.settimeout(max(0.001, deadline - self.clock()))
                        data = sock.recv(min(65536, n - len(chunks)))
                        if not data:
                            raise Refusal("VNC frame truncated")
                        chunks.extend(data)
                    return bytes(chunks)

                if take(12) != b"RFB 003.008\n":
                    raise Refusal("Unsupported RFB protocol")
                sock.sendall(b"RFB 003.008\n")
                count = take(1)[0]
                if not count or count > 32 or 1 not in take(count):
                    raise Refusal("VNC requires unsupported authentication")
                sock.sendall(b"\x01")
                if take(4) != b"\x00" * 4:
                    raise Refusal("VNC security negotiation failed")
                sock.sendall(b"\x01")  # shared desktop; never request exclusive ownership
                width, height = struct.unpack(">HH", take(4))
                take(16)  # server pixel format: replaced with a fixed 32-bit true-colour format
                (name_size,) = struct.unpack(">I", take(4))
                if name_size > 256:
                    raise Refusal("Unbounded VNC server name")
                take(name_size)
                if (width, height) != size:
                    raise Refusal("Unexpected VNC framebuffer resolution")
                pixel_format = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
                sock.sendall(b"\x00\x00\x00\x00" + pixel_format)
                sock.sendall(b"\x02\x00\x00\x01" + struct.pack(">i", 0))
                sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))
                message = take(4)
                if message[0] != 0 or message[1] != 0:
                    raise Refusal("Unsupported VNC framebuffer response")
                rectangles = struct.unpack(">H", message[2:])[0]
                if not 1 <= rectangles <= 32:
                    raise Refusal("Invalid VNC rectangle count")
                canvas = Image.new("RGB", size)
                coverage = Image.new("L", size, 0)
                for _ in range(rectangles):
                    x, y, w, h, encoding = struct.unpack(">HHHHi", take(12))
                    if encoding != 0 or not w or not h or x + w > width or y + h > height:
                        raise Refusal("Invalid or non-raw VNC rectangle")
                    pixels = take(w * h * 4)
                    tile = Image.frombytes("RGB", (w, h), pixels, "raw", "BGRX")
                    canvas.paste(tile, (x, y))
                    coverage.paste(255, (x, y, x + w, y + h))
                if coverage.getextrema() != (255, 255):
                    raise Refusal("Incomplete VNC framebuffer")
                encoded = io.BytesIO()
                canvas.save(encoded, format="PNG")
                return encoded.getvalue()
        except (OSError, struct.error, ValueError) as exc:
            raise Refusal(f"VNC observation refused: {type(exc).__name__}") from exc


@dataclass
class ReadOnlyVncTransport:
    """LabTransport-compatible observation; click is unconditionally refused.

    An actual QEMU attestor is NOT provided. Calling code must supply independent
    provenance; the caller's assertion or a JSON flag is not an attestation.
    """

    reader: FrameReader
    attestor: LabAttestor
    expected: LabAuthority
    resolution: Size
    audit: Callable[[str], None] = lambda _message: None
    clock: Callable[[], float] = time.monotonic

    def capture(self, deadline: float) -> Frame:
        if self.clock() >= deadline:
            raise Refusal("Observation timeout")
        if (not self.expected.run_id or not self.expected.snapshot_id or not self.expected.source_commit
                or self.expected.synthetic_cow_only is not True
                or self.expected.physical_disk_attached is not False):
            raise Refusal("Missing disposable lab authorization")
        if self.attestor.verify(deadline) != self.expected:
            raise Refusal("VM, snapshot, ISO or disk provenance changed")
        raw = self.reader.read_png(deadline, self.resolution)
        shot = Screenshot.decode(raw, self.resolution)
        if self.attestor.verify(deadline) != self.expected or self.clock() >= deadline:
            raise Refusal("VM identity diverged during framebuffer capture")
        self.audit("vnc-frame:" + shot.sha256)
        # Scale and guest-side preconditions are unproven through RFB alone.
        # Never fabricate those claims; StateMachine will fail closed.
        return Frame(raw, None, self.expected, Surface(), frozenset())

    def click_if_current(
        self, run_id: str, png_sha256: str, point: tuple[int, int], deadline: float
    ) -> None:
        self.audit("vnc-input-refused")
        raise Refusal(
            "RFB cannot atomically revalidate framebuffer, authority and emit one click"
        )
