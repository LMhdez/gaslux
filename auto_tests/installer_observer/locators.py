"""Resolve a single target on the current authenticated frame."""

from __future__ import annotations

import csv
import io
import math
import subprocess
from dataclasses import dataclass
from enum import StrEnum

from .evidence import Refusal
from .screenshot import Box, Screenshot, valid_box


class Method(StrEnum):
    STRUCTURED = "structured-id"
    ACCESSIBILITY = "accessibility"
    TEXT = "exact-text"
    OCR = "contextual-ocr"
    BOX = "bounding-box"
    POINT = "authenticated-coordinate"


class Availability(StrEnum):
    SUPPORTED = "supported"
    UNAVAILABLE = "unavailable"
    UNPROVEN = "unproven"


@dataclass(frozen=True)
class Candidate:
    name: str
    role: str
    box: Box
    structured_id: str | None = None
    accessible_id: str | None = None


@dataclass(frozen=True)
class Surface:
    # Candidates and capabilities come from the same guest capture transaction.
    controls: tuple[Candidate, ...] = ()
    supported: frozenset[Method] = frozenset()
    unproven: frozenset[Method] = frozenset()

    def status(self, method: Method) -> Availability:
        if method in self.unproven:
            return Availability.UNPROVEN
        return Availability.SUPPORTED if method in self.supported else Availability.UNAVAILABLE


def ocr_words(frame: Screenshot, box: Box, timeout: float) -> tuple[Candidate, ...]:
    if not valid_box(box, frame.image.size):
        raise Refusal("Invalid OCR region")
    crop = io.BytesIO()
    frame.image.crop(box).save(crop, format="PNG")
    try:
        result = subprocess.run(
            ["tesseract", "stdin", "stdout", "--psm", "6", "tsv"],
            input=crop.getvalue(),
            capture_output=True,
            check=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("Contextual OCR unavailable") from exc
    words = []
    for row in csv.DictReader(io.StringIO(result.stdout.decode()), delimiter="\t"):
        if row["level"] != "5" or not row["text"].strip():
            continue
        x, y, w, h = (int(row[k]) for k in ("left", "top", "width", "height"))
        if not valid_box((x, y, x + w, y + h), (box[2] - box[0], box[3] - box[1])):
            raise Refusal("OCR outside trusted region")
        # Keep low-confidence matches as ambiguity, never as an actionable result.
        confidence = float(row["conf"])
        role = "word" if math.isfinite(confidence) and confidence >= 80 else "uncertain"
        words.append(
            Candidate(row["text"], role, (box[0] + x, box[1] + y, box[0] + x + w, box[1] + y + h))
        )
    return tuple(words)


@dataclass(frozen=True)
class Target:
    label: str
    role: str
    box: Box
    pixel_sha256: str
    point: tuple[int, int]
    structured_id: str | None = None
    accessible_id: str | None = None


def resolve(
    frame: Screenshot, surface: Surface, target: Target, order: tuple[Method, ...], timeout: float
) -> tuple[Method, tuple[int, int]]:
    if frame.roi(target.box) != target.pixel_sha256:
        raise Refusal("Current target pixels differ from the reviewed control")
    left, top, right, bottom = target.box
    for method in order:
        if not isinstance(method, Method):
            raise Refusal("Unknown locator method")
        if surface.status(method) is not Availability.SUPPORTED:
            continue
        if method is Method.POINT:
            x, y = target.point
        else:
            if method is Method.STRUCTURED:
                if not target.structured_id:
                    continue
                hits = [c for c in surface.controls if c.structured_id == target.structured_id]
            elif method is Method.ACCESSIBILITY:
                if not target.accessible_id:
                    continue
                hits = [c for c in surface.controls if c.accessible_id == target.accessible_id]
            elif method is Method.OCR:
                hits = [c for c in ocr_words(frame, target.box, timeout) if c.name == target.label]
            elif method is Method.TEXT:
                hits = [c for c in surface.controls if c.name == target.label]
            else:
                hits = [c for c in surface.controls if c.box == target.box]
            if len(hits) != 1:
                raise Refusal(f"{method}: expected one control, found {len(hits)}")
            hit = hits[0]
            if hit.name != target.label or hit.role != (
                "word" if method is Method.OCR else target.role
            ):
                raise Refusal("Control name, role or OCR confidence mismatch")
            x1, y1, x2, y2 = hit.box
            if not valid_box(hit.box, frame.image.size) or not (
                left <= x1 < x2 <= right and top <= y1 < y2 <= bottom
            ):
                raise Refusal("Located control escapes authorized region")
            x, y = (x1 + x2) // 2, (y1 + y2) // 2
        if (
            type(x) is not int
            or type(y) is not int
            or not (left <= x < right and top <= y < bottom)
        ):
            raise Refusal("Point outside authorized control")
        return method, (x, y)
    raise Refusal("No supported and proven locator")
