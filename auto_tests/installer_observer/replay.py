"""Sequential validation of original frames; this module has no input transport."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from .evidence import Refusal, basename, read
from .models import Evidence, InterfaceMap, ObservationResult, Transition
from .screenshot import MAX_PNG, Box, Screenshot


@dataclass(frozen=True)
class RecordedState:
    id: str
    filename: str
    sha256: str


@dataclass(frozen=True)
class Recording:
    run_id: str
    replica: int
    artifact_id: int
    directory: Path
    states: tuple[RecordedState, ...]
    edges: tuple[tuple[str, str], ...]
    elapsed_ms: tuple[int | None, ...]
    workflow_commit: str


def replay(mapping: InterfaceMap, recording: Recording, recognize: Callable[[Screenshot], Iterable[str]],
           validate_edge: Callable[[Transition, Screenshot, Screenshot], None], region: Box) -> dict:
    """Each recording starts at its own first frame. Never stitch two VM histories."""
    if (not recording.states or len(recording.edges) != len(recording.states)-1
            or len(recording.elapsed_ms) != len(recording.edges)):
        raise Refusal("Incomplete recorded sequence")
    states = {s.id: s for s in mapping.states}
    steps = []
    frames = []
    previous = None
    for i, row in enumerate(recording.states):
        if row.id not in states or states[row.id].screenshot != row.filename:
            raise Refusal("Recording references unknown state or file")
        current = Screenshot.decode(read(recording.directory / basename(row.filename), MAX_PNG),
                                    mapping.resolution, row.sha256)
        matches = tuple(recognize(current))
        if matches != (row.id,):
            raise Refusal(f"Frame {row.id} has unexpected or ambiguous visual identity: {matches}")
        frame = Evidence(row.id, current.sha256, current.image.size)
        if previous is not None:
            source = recording.states[i-1].id
            edges = [t for t in mapping.transitions if (t.source,t.target) == (source,row.id)]
            if (len(edges) != 1 or not edges[0].verified or recording.edges[i-1] != (source,row.id)
                or source == mapping.terminal or previous.roi(region) == current.roi(region)):
                raise Refusal(f"Invalid recorded transition {source} -> {row.id}")
            edge = edges[0]
            validate_edge(edge, previous, current)
            result = ObservationResult(recording.run_id, "historical-replay", mapping.identity,
                mapping.installer, edge.id, source, edge.locator.kind, None, frames[-1],
                frame, True, recording.elapsed_ms[i-1], (), row.id)
            steps.append({**asdict(result), "recorded_action": edge.action})
        frames.append(frame)
        previous = current
    return {"run_id": recording.run_id, "replica": recording.replica,
            "artifact_id": recording.artifact_id, "workflow_commit": recording.workflow_commit,
            "frames": [asdict(f) for f in frames], "steps": steps, "final_state": frames[-1].state}
