from __future__ import annotations

import io
from dataclasses import dataclass

from PIL import Image

from .evidence import Refusal, digest

Box = tuple[int, int, int, int]
Size = tuple[int, int]
MAX_PNG = 2 * 1024 * 1024
IEND = bytes.fromhex("0000000049454e44ae426082")


def valid_box(box: Box, size: Size) -> bool:
    return (
        len(box) == 4
        and all(type(n) is int for n in box)
        and 0 <= box[0] < box[2] <= size[0]
        and 0 <= box[1] < box[3] <= size[1]
    )


@dataclass(frozen=True)
class Screenshot:
    png: bytes
    sha256: str
    image: Image.Image

    @classmethod
    def decode(cls, png: bytes, size: Size, expected: str | None = None) -> Screenshot:
        if not 0 < len(png) <= MAX_PNG or not png.endswith(IEND):
            raise Refusal("Oversized, truncated or trailing PNG data")
        offset = 8
        while offset < len(png):
            length = int.from_bytes(png[offset : offset + 4], "big")
            kind = png[offset + 4 : offset + 8]
            offset += length + 12
            if kind == b"IEND":
                break
        if offset != len(png) or kind != b"IEND":
            raise Refusal("Invalid PNG chunk boundary")
        checksum = digest(png)
        if expected is not None and checksum != expected:
            raise Refusal("Screenshot SHA-256 mismatch")
        try:
            with Image.open(io.BytesIO(png), formats=["PNG"]) as src:
                if src.size != size or src.width * src.height > 8_000_000 or src.n_frames != 1:
                    raise Refusal("Unexpected screenshot dimensions or animation")
                src.verify()
            with Image.open(io.BytesIO(png), formats=["PNG"]) as src:
                image = src.convert("RGB")
        except (OSError, SyntaxError, Image.DecompressionBombError) as exc:
            raise Refusal("Invalid PNG") from exc
        return cls(png, checksum, image)

    def roi(self, box: Box) -> str:
        if not valid_box(box, self.image.size):
            raise Refusal("Region outside screenshot")
        return digest(self.image.crop(box).tobytes())
