"""Contract-only model of a narrow Observer client API.

This is an ARCHITECTURAL SIMULATION, not a privileged daemon, socket server,
QEMU attestor, signature verifier or OS isolation boundary. Peer credentials
are supplied by the test harness; production must obtain them from
SO_PEERCRED and independently pin process start identity.
"""

from __future__ import annotations

import copy
import math
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .evidence import Refusal, canonical, digest

_SHA256 = re.compile(r"[0-9a-f]{64}")
_OPERATIONS = frozenset(
    {"session.identify", "state.read", "frame.read", "session.close"}
)
_FIELDS = frozenset(
    {
        "protocol",
        "operation",
        "session_id",
        "transaction_id",
        "request_id",
        "sequence",
    }
)


@dataclass(frozen=True)
class PeerIdentity:
    """Synthetic peer identity; production source must be kernel peer creds."""

    uid: int
    pid: int
    start_ticks: int


@dataclass(frozen=True)
class BoundaryEvidence:
    """Unverified fixture digests; never interpreted as a signed attestation."""

    controller_artifact_sha256: str
    policy_sha256: str
    qemu_identity_sha256: str
    source_commit: str


class ObservationBoundaryModel:
    """Fail-closed in-memory model of the four-operation client contract."""

    def __init__(
        self,
        *,
        peer: PeerIdentity,
        session_id: str,
        transaction_id: str,
        expires_at: float,
        evidence: BoundaryEvidence,
        state: dict[str, Any],
        framebuffer_png: bytes,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._peer = peer
        self._session_id = self._uuid(session_id, "session")
        self._transaction_id = self._uuid(transaction_id, "transaction")
        self._expires_at = expires_at
        self._evidence = evidence
        self._state = copy.deepcopy(state)
        self._framebuffer = bytes(framebuffer_png)
        self._frame_sha256 = digest(self._framebuffer)
        self._clock = clock
        self._next_sequence = 0
        self._request_ids: set[str] = set()
        self._closed = False
        self._validate_initial()

    @staticmethod
    def _uuid(value: str, label: str) -> str:
        try:
            parsed = str(uuid.UUID(value))
        except (ValueError, TypeError, AttributeError) as exc:
            raise Refusal(f"Invalid {label} identifier") from exc
        if parsed != value:
            raise Refusal(f"Noncanonical {label} identifier")
        return parsed

    def _validate_initial(self) -> None:
        if (
            type(self._peer.uid) is not int
            or self._peer.uid < 1
            or type(self._peer.pid) is not int
            or self._peer.pid <= 1
            or type(self._peer.start_ticks) is not int
            or self._peer.start_ticks <= 0
            or type(self._expires_at) not in (int, float)
            or not math.isfinite(self._expires_at)
            or not self._clock() < self._expires_at
            or not isinstance(self._state, dict)
            or not self._framebuffer
            or any(
                not isinstance(value, str) or not _SHA256.fullmatch(value)
                for value in (
                    self._evidence.controller_artifact_sha256,
                    self._evidence.policy_sha256,
                    self._evidence.qemu_identity_sha256,
                )
            )
            or not isinstance(self._evidence.source_commit, str)
            or not self._evidence.source_commit
        ):
            raise Refusal("Incomplete or invalid simulation fixture")
        # Ensure the state is bounded JSON data, not an object graph.
        encoded = canonical(self._state)
        if len(encoded) > 16_384:
            raise Refusal("Observation state exceeds the contract limit")

    def dispatch(self, peer: PeerIdentity, request: dict[str, Any]) -> dict[str, Any]:
        """Apply a single request; no command execution or guest input exists."""
        if self._closed or self._clock() >= self._expires_at:
            raise Refusal("Observation session is closed or expired")
        if peer != self._peer:
            raise Refusal("Client peer identity mismatch")
        if not isinstance(request, dict) or set(request) != _FIELDS:
            raise Refusal("Request fields differ from the fixed observation contract")
        if type(request["protocol"]) is not int or request["protocol"] != 1:
            raise Refusal("Unsupported observation protocol")
        operation = request["operation"]
        if not isinstance(operation, str) or operation not in _OPERATIONS:
            raise Refusal("Operation is not in the read-only allowlist")
        if request["session_id"] != self._session_id:
            raise Refusal("Stale or foreign observation session")
        if request["transaction_id"] != self._transaction_id:
            raise Refusal("Observation transaction mismatch")
        request_id = self._uuid(request["request_id"], "request")
        if request_id in self._request_ids:
            raise Refusal("Observation request replay")
        sequence = request["sequence"]
        if type(sequence) is not int or sequence != self._next_sequence:
            raise Refusal("Observation request sequence mismatch")

        # Consume before dispatch. A failed response cannot be replayed.
        self._request_ids.add(request_id)
        self._next_sequence += 1

        if operation == "session.identify":
            return {
                "protocol": 1,
                "operation": operation,
                "session_id": self._session_id,
                "transaction_id": self._transaction_id,
                "controller_artifact_sha256": self._evidence.controller_artifact_sha256,
                "policy_sha256": self._evidence.policy_sha256,
                "qemu_identity_sha256": self._evidence.qemu_identity_sha256,
                "source_commit": self._evidence.source_commit,
                "provenance": "synthetic-model-fixture",
                "signature_verified": False,
                "trust_boundary": "not-established-by-this-model",
            }
        if operation == "state.read":
            return {
                "protocol": 1,
                "operation": operation,
                "session_id": self._session_id,
                "transaction_id": self._transaction_id,
                "state": copy.deepcopy(self._state),
            }
        if operation == "frame.read":
            return {
                "protocol": 1,
                "operation": operation,
                "session_id": self._session_id,
                "transaction_id": self._transaction_id,
                "framebuffer_png": self._framebuffer,
                "framebuffer_sha256": self._frame_sha256,
                "provenance": "synthetic-model-fixture",
            }

        # session.close is the only lifecycle operation. It revokes this model
        # session; it cannot terminate QEMU or revoke a real pre-opened FD.
        self._closed = True
        self._framebuffer = b""
        self._state = {}
        return {
            "protocol": 1,
            "operation": operation,
            "session_id": self._session_id,
            "transaction_id": self._transaction_id,
            "closed": True,
            "revocation": "in-memory-model-only",
        }
