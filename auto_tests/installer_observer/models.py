from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .evidence import Refusal, regular
from .screenshot import Box, Size


class Action(StrEnum):
    OPEN_WIZARD = "open-wizard"
    NEXT = "next"
    SELECT_PROFILE = "select-profile"
    PREVIEW = "synthetic-proposal"
    FILL_FIXTURE = "synthetic-fields"


@dataclass(frozen=True)
class DistributionIdentity:
    distribution: str
    version: str
    sha256: str
    size_bytes: int

    def verify_iso(self, path: Path) -> None:
        with regular(path, self.size_bytes) as file:
            h = hashlib.sha256()
            remaining = self.size_bytes
            while remaining:
                chunk = file.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise Refusal("ISO truncated")
                remaining -= len(chunk)
                h.update(chunk)
            if file.read(1) or h.hexdigest() != self.sha256:
                raise Refusal("ISO SHA-256 or size mismatch")


@dataclass(frozen=True)
class InstallerIdentity:
    name: str
    package_version: str


@dataclass(frozen=True)
class UIControl:
    label: str
    role: str
    structured_id: str | None
    box: Box | None
    description: str


@dataclass(frozen=True)
class ScreenState:
    id: str
    screenshot: str
    gate: str
    controls: tuple[UIControl, ...]


@dataclass(frozen=True)
class Locator:
    kind: str
    point: tuple[int, int] | None
    box: Box | None


@dataclass(frozen=True)
class Preconditions:
    requirements: tuple[str, ...]


@dataclass(frozen=True)
class Postconditions:
    requirements: tuple[str, ...]


@dataclass(frozen=True)
class Transition:
    id: str
    source: str
    target: str
    action: Action
    locator: Locator
    before: Preconditions
    after: Postconditions
    timeout: int
    verified: bool


@dataclass(frozen=True)
class InterfaceMap:
    identity: DistributionIdentity
    installer: InstallerIdentity
    states: tuple[ScreenState, ...]
    transitions: tuple[Transition, ...]
    terminal: str
    resolution: Size
    scale: float | None
    lab_commit: str
    document: bytes  # Lossless canonical source, including every historical proof.


@dataclass(frozen=True)
class Evidence:
    state: str | None
    sha256: str
    resolution: Size


@dataclass(frozen=True)
class ObservationResult:
    run_id: str
    mode: str
    distribution: DistributionIdentity
    installer: InstallerIdentity
    transition: str
    initial_state: str
    locator: str | None
    authorized_action: Action | None
    before: Evidence | None
    after: Evidence | None
    passed: bool
    elapsed_ms: int | None
    errors: tuple[str, ...]
    final_state: str | None
