from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

from .evidence import Refusal, basename, canonical, digest, parse, read
from .models import (
    Action,
    DistributionIdentity,
    InstallerIdentity,
    InterfaceMap,
    Locator,
    Postconditions,
    Preconditions,
    ScreenState,
    Transition,
    UIControl,
)
from .screenshot import valid_box


@dataclass(frozen=True)
class Profile:
    identity: DistributionIdentity
    installer: InstallerIdentity
    schema: Path
    map_digest: str
    actions: Mapping[str, Action]


def validate(document: dict, schema_file: Path) -> None:
    # The schema is supplied by installed adapter code. Never resolve a URI from a map.
    schema = parse(read(schema_file))
    Draft202012Validator.check_schema(schema)
    errors = Draft202012Validator(schema).iter_errors(document)
    if error := next(errors, None):
        raise Refusal(f"Schema {error.json_path}: {error.message}")


def load_map(path: Path, profile: Profile) -> InterfaceMap:
    d = parse(read(path))
    validate(d, profile.schema)
    iso = d["iso"]
    identity = DistributionIdentity(
        d["distribution"], iso["version"], iso["sha256"], iso["sizeBytes"]
    )
    if identity != profile.identity:
        raise Refusal("Unexpected distribution or ISO identity")
    size = tuple(d["lab"]["resolution"])
    states = []
    for row in d["states"]:
        if row["order"] != len(states):
            raise Refusal("Invalid state order")
        controls = []
        for c in row["controls"]:
            box = tuple(c["boundingBox"]) if c["boundingBox"] is not None else None
            if box is not None and not valid_box(box, size):
                raise Refusal("Control outside display")
            controls.append(UIControl(c["label"], c["type"], c["qtId"], box, c["action"]))
        states.append(
            ScreenState(row["id"], basename(row["screenshot"]), row["visualGate"], tuple(controls))
        )
    ids = {s.id for s in states}
    terminal = d["stopBoundary"]["lastObservedState"]
    if len(ids) != len(states) or terminal not in ids:
        raise Refusal("Duplicate or missing screen")
    edges = []
    for t in d["transitions"]:
        if t["from"] not in ids or t["to"] not in ids or t["from"] in (terminal, t["to"]):
            raise Refusal("Invalid transition endpoints or terminal boundary")
        loc = t["locator"]
        bound = tuple(loc["boundingBox"]) if loc["boundingBox"] is not None else None
        xy = (loc["x"], loc["y"]) if loc["x"] is not None and loc["y"] is not None else None
        if loc["type"] == "none":
            if bound is not None or loc["x"] is not None or loc["y"] is not None:
                raise Refusal("Invalid observation-only locator")
        elif (
            not xy
            or not bound
            or not valid_box(bound, size)
            or not (bound[0] <= xy[0] < bound[2] and bound[1] <= xy[1] < bound[3])
        ):
            raise Refusal("Locator outside bounding box")
        if bound is not None:
            state = next(s for s in states if s.id == t["from"])
            matching = [
                c for c in state.controls if c.box == bound and c.description == t["action"]
            ]
            if len(matching) != 1:
                raise Refusal("Locator must bind one source control and action")
        if t["action"] not in profile.actions:
            raise Refusal("Unknown action")
        timeout = t["configuredCommandTimeoutSeconds"]
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise Refusal("Invalid transition deadline")
        edges.append(
            Transition(
                t["id"],
                t["from"],
                t["to"],
                profile.actions[t["action"]],
                Locator(loc["type"], xy, bound),
                Preconditions(tuple(t["preconditions"])),
                Postconditions(tuple(t["postconditions"])),
                timeout,
                t["status"] == "verified",
            )
        )
    if len({e.id for e in edges}) != len(edges):
        raise Refusal("Duplicate transition")
    raw = canonical(d)
    if digest(raw) != profile.map_digest:
        raise Refusal("Map differs from reviewed adapter contract")
    return InterfaceMap(
        identity,
        profile.installer,
        tuple(states),
        tuple(edges),
        terminal,
        size,
        d["lab"]["displayScaleFactor"],
        d["lab"]["sourceCommit"],
        raw,
    )
