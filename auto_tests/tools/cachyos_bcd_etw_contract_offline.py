#!/usr/bin/env python3
"""Strict read-only normalizer for future *exported* ETW fixture records.

This does not collect ETW, open Windows devices or claim a process wrote BCD.
ETW FileIO and DiskIO contain different identifiers; matching an IRP pointer
is a candidate, not a proof of file->physical sector->writer identity.
"""
from __future__ import annotations

from collections import Counter
import re
from typing import Any

MAX_EVENTS = 100000
EVENT_TYPES = frozenset((
    "ProcessStart", "ProcessStop", "FileIoName", "FileIoWrite",
    "DiskIoWrite",
))
SESSION_ID = re.compile(r"[0-9a-fA-F-]{36}")
POINTER = re.compile(r"0x[0-9a-fA-F]{1,16}")


class EtwContractError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise EtwContractError(reason)


def _int(value: Any, *, min_value: int = 0) -> bool:
    return type(value) is int and value >= min_value


def normalize_etw_fixture(document: dict[str, Any]) -> dict[str, Any]:
    """Validate minimal exported ETW fields, discard PII and deny attribution.

    Fields are normalized *by a future reviewed exporter*, not presumed to
    coexist on one native event. No binary .etl parsing or Windows I/O here.
    """
    require(type(document) is dict and set(document) == {"session", "events"},
            "unknown ETW document shape")
    session, events = document["session"], document["events"]
    require(type(session) is dict and
            set(session) == {
                "sessionId", "windowsBuild", "bootIdentitySha256",
                "clockKind", "sessionStartNs", "sessionEndNs",
                "qpcFrequencyHz", "lostEvents", "lostBuffers",
                "traceSha256",
            },
            "missing ETW collection provenance fields")
    require(type(session["sessionId"]) is str
            and SESSION_ID.fullmatch(session["sessionId"]) is not None
            and session["windowsBuild"] == 19045
            and type(session["clockKind"]) is str
            and session["clockKind"] in ("QPC", "SYSTEM_TIME")
            and (session["qpcFrequencyHz"] is None
                 if session["clockKind"] == "SYSTEM_TIME"
                 else _int(session["qpcFrequencyHz"], min_value=1))
            and _int(session["sessionStartNs"])
            and _int(session["sessionEndNs"])
            and session["sessionEndNs"] >= session["sessionStartNs"]
            and _int(session["lostEvents"])
            and _int(session["lostBuffers"])
            and all(type(session[k]) is str
                    and re.fullmatch(r"[0-9a-f]{64}", session[k]) is not None
                    for k in ("bootIdentitySha256", "traceSha256")),
            "invalid ETW session/clock/loss metadata")
    require(type(events) is list and len(events) <= MAX_EVENTS,
            "unsupported ETW event count")
    counts: Counter[str] = Counter()
    named_files: dict[str, list[tuple[int, bool]]] = {}
    writes: list[dict[str, Any]] = []
    disk_writes: list[dict[str, Any]] = []
    process_start: dict[int, list[int]] = {}
    process_stop: dict[int, list[int]] = {}
    missing_timestamps = 0
    for event in events:
        require(type(event) is dict
                and "kind" in event and event["kind"] in EVENT_TYPES
                and set(event) <= {
                    "kind", "timestampNs", "pid", "fileObject",
                    "irp", "fileName", "diskOffset", "length",
                    "diskNumber",
                },
                "unknown ETW event type or fields")
        kind, timestamp = event["kind"], event.get("timestampNs")
        require(timestamp is None or _int(timestamp),
                "invalid ETW timestamp")
        if timestamp is None:
            missing_timestamps += 1
        else:
            require(session["sessionStartNs"] <= timestamp
                    <= session["sessionEndNs"],
                    "ETW event outside declared session")
        pid = event.get("pid")
        if pid is not None:
            require(_int(pid), "invalid ETW PID")
        for pointer in ("fileObject", "irp"):
            value = event.get(pointer)
            require(value is None or (type(value) is str
                    and POINTER.fullmatch(value) is not None),
                    "invalid ETW pointer")
        counts[kind] += 1
        if kind in ("ProcessStart", "ProcessStop"):
            require(pid is not None and timestamp is not None,
                    "process lifetime requires PID and timestamp")
            target = process_start if kind == "ProcessStart" else process_stop
            target.setdefault(pid, []).append(timestamp)
        elif kind == "FileIoName":
            require(event.get("fileObject") is not None
                    and type(event.get("fileName")) is str
                    and len(event["fileName"]) <= 4096,
                    "FileIoName requires FileObject and bounded name")
            # No file name or path is emitted to reports.
            path = event["fileName"].replace("/", "\\").casefold()
            named_files.setdefault(event["fileObject"], []).append(
                (timestamp if timestamp is not None else -1,
                 path.endswith("\\efi\\microsoft\\boot\\bcd"))
            )
        elif kind == "FileIoWrite":
            require(event.get("fileObject") is not None,
                    "FileIoWrite needs FileObject")
            writes.append(event)
        elif kind == "DiskIoWrite":
            off, length = event.get("diskOffset"), event.get("length")
            require(off is None or _int(off)
                    and length is not None and _int(length, min_value=1)
                    and off + length <= 8 * 1024**4
                    and event.get("diskNumber") is not None
                    and _int(event["diskNumber"]),
                    "DiskIoWrite needs bounded offset and disk number if present")
            disk_writes.append(event)

    candidates = 0
    for file_io in writes:
        ts, pid = file_io.get("timestampNs"), file_io.get("pid")
        obj, irp = file_io["fileObject"], file_io.get("irp")
        if ts is None or pid is None or irp is None:
            continue
        # FileObject can be reused. Accept only one earlier name assertion.
        names = [(t, is_bcd) for t, is_bcd in named_files.get(obj, [])
                 if t >= 0 and t <= ts]
        if len(names) != 1 or not names[0][1]:
            continue
        starts = [t for t in process_start.get(pid, []) if t <= ts]
        stops = [t for t in process_stop.get(pid, []) if t >= ts]
        if len(starts) != 1 or len(stops) != 1:
            continue
        disk_match = [
            event for event in disk_writes
            if event.get("timestampNs") is not None
            and event.get("irp") == irp
            and event.get("diskOffset") is not None
            and starts[0] <= event["timestampNs"] <= stops[0]
        ]
        if len(disk_match) == 1:
            candidates += 1

    complete_session = (
        session["lostEvents"] == session["lostBuffers"] == 0
        and missing_timestamps == 0
    )
    return {
        "status": "PROCESS_ATTRIBUTION_UNPROVEN",
        "normalizedOnly": True,
        "windowsBuild": 19045,
        "eventCounts": dict(sorted(counts.items())),
        "eventCount": len(events),
        "missingTimestampCount": missing_timestamps,
        "sessionCompleteWithinDeclaredWindow": complete_session,
        "eventsBeforeEtwSessionObservable": False,
        "qemuClockAlignedToEtw": False,
        "qemuDiskNodeAuthenticated": False,
        "diskNumberBoundToGptIdentity": False,
        "plausibleIrpLifetimeMatches": candidates,
        "processAttributionProven": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
    }
