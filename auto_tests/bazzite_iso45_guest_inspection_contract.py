#!/usr/bin/env python3
"""Offline ISO45 guest-inspection contract; never grants a guest channel.

All input is untrusted, even when it contains plausible cryptographic digests.
No local runner signature, nonce, or JSON claim is independent attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import TypedDict

from bazzite_anaconda_readonly_capture import DETAIL_READS, READS, SERVICE
from bazzite_gpt_fixture import PARTITIONS

ISO_SHA256 = "6120b6edc2d87e7bdccf8dfddc8b156552cd50b152cb0a9e9dedb37fb947cbe5"
ISO_BYTES = 8377878528
PAYLOAD_DIGEST = "sha256:492f83c738838861464685aed341783c2ea2266c82a9f19f0c867fd301783fd4"
ORIGINAL_ARCHIVE_SHA256 = "ba434ddf46e892c80325608b87cf6933da88bda716e144cfd63df0a49904a00c"
DISK_SERIAL = "GLXBAZRO001"
DISK_BYTES = 70 * 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
OWNER = re.compile(r":1\.[0-9]+\Z")
ALLOWED = frozenset((*READS, *DETAIL_READS))
NO_WRITE = (
    "installationAuthorized",
    "partitionWriteAuthorized",
    "gptMetadataWriteAuthorized",
    "windowsEspWriteAuthorized",
    "nvramWriteAuthorized",
    "secureBootEnrollmentAuthorized",
    "getActionsObserved",
    "writeSetVerified",
    "guestCommandChannelAuthorized",
)
MAX_PROPOSAL_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CALL_MS = 12000


class Refusal(ValueError):
    """Invalid, contradictory, or noncanonical inspection proposal."""


class Decision(TypedDict):
    schemaVersion: int
    status: str
    contractOnly: bool
    structuralChecksPassed: bool
    externallyAuthenticated: bool
    safetyApproved: bool
    observerApproved: bool
    anacondaProcessVerified: bool
    visualLiveDesktopObserved: bool
    installationAuthorized: bool
    partitionWriteAuthorized: bool
    gptMetadataWriteAuthorized: bool
    windowsEspWriteAuthorized: bool
    nvramWriteAuthorized: bool
    secureBootEnrollmentAuthorized: bool
    getActionsObserved: bool
    writeSetVerified: bool
    guestCommandChannelAuthorized: bool


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def exact(value: object, fields: set[str], name: str) -> dict:
    require(type(value) is dict and set(value) == fields, f"Noncanonical {name}")
    return value


def digest(value: object, name: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None, f"Invalid {name}")
    return value


def positive(value: object, name: str) -> int:
    require(type(value) is int and value > 0, f"Invalid {name}")
    return value


def uuid(value: object, name: str) -> str:
    require(isinstance(value, str) and UUID.fullmatch(value) is not None, f"Invalid {name}")
    return value


def disk(value: object, name: str) -> dict:
    data = exact(
        value, {"serial", "guid", "logicalSectorBytes", "sizeBytes", "partitions"}, name
    )
    require(
        data["serial"] == DISK_SERIAL
        and data["logicalSectorBytes"] == 512
        and type(data["sizeBytes"]) is int
        and data["sizeBytes"] == DISK_BYTES,
        f"Foreign {name} geometry or serial",
    )
    uuid(data["guid"], name + " GPT GUID")
    parts = data["partitions"]
    require(isinstance(parts, list) and len(parts) == len(PARTITIONS), f"Foreign {name} partitions")
    known = {data["guid"]}
    for part, expected in zip(parts, PARTITIONS, strict=True):
        entry = exact(
            part, {"number", "typeGuid", "partuuid", "firstSector", "lastSector"}, name + " partition"
        )
        number, type_guid, _label, first, last = expected
        require(
            type(entry["number"]) is int
            and entry["number"] == number
            and entry["typeGuid"] == type_guid.lower()
            and type(entry["firstSector"]) is int
            and entry["firstSector"] == first
            and type(entry["lastSector"]) is int
            and entry["lastSector"] == last,
            f"Foreign {name} partition offset/type",
        )
        guid = uuid(entry["partuuid"], name + " PARTUUID")
        require(guid not in known, f"Duplicate {name} GUID")
        known.add(guid)
    return data


def validate_contract(record: object, *, seen_transactions: frozenset[str] = frozenset()) -> Decision:
    """Check draft structure; ALWAYS return a no-authority refusal.

    A real external verifier and its non-replayable trust root are NOT installed.
    seen_transactions is only a test aid, not persistent anti-replay protection.
    """
    data = exact(
        record,
        {"schemaVersion", "origin", "media", "run", "storage", "collector",
         "installer", "dbus", "provenance", "permissions"},
        "ISO45 proposal",
    )
    require(type(data["schemaVersion"]) is int and data["schemaVersion"] == 1\n            and data["origin"] == "synthetic-untrusted-proposal",
            "Unknown contract version/origin")
    media = exact(data["media"], {"isoSha256", "isoSizeBytes", "version", "payloadDigest",
                                    "sourceRunId", "sourceArtifactId", "sourceArchiveSha256"},
                  "media")
    require(
        media["isoSha256"] == ISO_SHA256
        and type(media["isoSizeBytes"]) is int
        and media["isoSizeBytes"] == ISO_BYTES
        and media["version"] == "45.20261117.1"
        and media["payloadDigest"] == PAYLOAD_DIGEST
        and type(media["sourceRunId"]) is int
        and media["sourceRunId"] == 44822100590
        and type(media["sourceArtifactId"]) is int
        and media["sourceArtifactId"] == 14672623998
        and media["sourceArchiveSha256"] == ORIGINAL_ARCHIVE_SHA256,
        "ISO, Atomic payload or signed-readback lineage mismatch",
    )
    run = exact(data["run"], {"transaction", "challenge", "qemuPid", "qemuStartTicks",
                               "qemuExecutableSha256", "qemuArgvSha256", "hostVmId",
                               "guestVmId", "sequence"}, "run")
    require(
        isinstance(run["transaction"], str)
        and TOKEN.fullmatch(run["transaction"]) is not None
        and run["transaction"] not in seen_transactions,
        "Missing or repeated transaction",
    )
    digest(run["challenge"], "challenge")
    require(positive(run["qemuPid"], "QEMU PID") > 1, "Invalid QEMU PID")
    positive(run["qemuStartTicks"], "QEMU start ticks")
    digest(run["qemuExecutableSha256"], "QEMU executable SHA256")
    digest(run["qemuArgvSha256"], "QEMU argv SHA256")
    require(
        isinstance(run["hostVmId"], str)
        and run["hostVmId"].startswith("gaslux-bazzite-")
        and run["hostVmId"] == run["guestVmId"]
        and type(run["sequence"]) is int
        and run["sequence"] == 1,
        "VM identity or replay sequence mismatch",
    )
    storage = exact(data["storage"], {"firmware", "partitionTable", "diskCount", "hostDisk",
                                        "guestDisk", "additionalDisks", "windowsAttached"},
                    "storage")
    require(
        storage["firmware"] == "uefi"
        and storage["partitionTable"] == "gpt"
        and type(storage["diskCount"]) is int
        and storage["diskCount"] == 1
        and storage["additionalDisks"] == []
        and storage["windowsAttached"] is False,
        "BIOS/MBR, Windows, or unexpected disk refused",
    )
    host = disk(storage["hostDisk"], "host")
    guest = disk(storage["guestDisk"], "guest")
    require(host == guest, "Host/guest GPT identity or geometry mismatch")
    collector = exact(data["collector"], {"path", "hostSha256", "guestSha256",
                                            "transport", "invoked"}, "collector")
    require(collector["path"] == "auto_tests/bazzite_anaconda_readonly_capture.py",
            "Unknown collector")
    require(digest(collector["hostSha256"], "collector host hash")
            == digest(collector["guestSha256"], "collector guest hash"),
            "Collector substituted")
    require(collector["transport"] == "not-established" and collector["invoked"] is False,
            "Guest channel or collector invocation is not authorized")
    installer = exact(data["installer"], {"service", "owner", "pid", "startTicks",
                                            "executableSha256", "version", "servicePresent"},
                      "installer")
    require(installer["service"] == SERVICE and installer["servicePresent"] is True,
            "Anaconda D-Bus service absent")
    require(isinstance(installer["owner"], str)
            and OWNER.fullmatch(installer["owner"]) is not None,
            "Unknown Anaconda unique bus owner")
    require(positive(installer["pid"], "Anaconda PID") > 1, "Invalid Anaconda PID")
    positive(installer["startTicks"], "Anaconda lifetime")
    digest(installer["executableSha256"], "Anaconda binary")
    require(isinstance(installer["version"], str)
            and 1 <= len(installer["version"]) <= 128
            and re.fullmatch(r"[A-Za-z0-9._+:-]+", installer["version"]) is not None,
            "Missing or malformed claimed Anaconda version")
    bus = exact(data["dbus"], {"allowlistedMethods", "replies"}, "D-Bus")
    names = bus["allowlistedMethods"]
    require(
        isinstance(names, list)
        and len(names) == len(set(map(str, names)))
        and all(type(name) is str and name in ALLOWED for name in names)
        and "GetActions" in names
        and "GetDevices" in names,
        "Missing GetActions/GetDevices or non-read-only method",
    )
    responses = bus["replies"]
    require(isinstance(responses, list) and 1 <= len(responses) <= len(names),
            "Missing or excessive bounded D-Bus replies")
    observed = set()
    total = 0
    for item in responses:
        reply = exact(item, {"method", "text", "sha256", "elapsedMs", "truncated", "timedOut"},
                      "D-Bus reply")
        method = reply["method"]
        require(type(method) is str and method in names and method not in observed,
                "Replayed, unexpected or duplicate D-Bus reply")
        observed.add(method)
        body = reply["text"]
        require(isinstance(body, str), "Non-text D-Bus reply")
        size = len(body.encode("utf-8"))
        total += size
        require(size <= MAX_RESPONSE_BYTES and total <= MAX_RESPONSE_BYTES,
                "Unbounded D-Bus response")
        require(digest(reply["sha256"], "D-Bus response digest")
                == hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "Changed D-Bus response")
        require(
            type(reply["elapsedMs"]) is int
            and 0 <= reply["elapsedMs"] <= MAX_CALL_MS
            and reply["truncated"] is False
            and reply["timedOut"] is False,
            "Truncated, timed out or unbounded D-Bus read",
        )
    require("GetActions" in observed, "GetActions reply missing")
    provenance = exact(
        data["provenance"],
        {"source", "independentlyVerified", "trustRoot", "safetyApproved", "observerApproved"},
        "external provenance",
    )
    require(
        provenance["source"] == "untrusted-runner"
        and provenance["independentlyVerified"] is False
        and provenance["trustRoot"] is None
        and provenance["safetyApproved"] is False
        and provenance["observerApproved"] is False,
        "Untrusted claims of external attestation or approval",
    )
    permissions = exact(data["permissions"], set(NO_WRITE), "permissions")
    require(all(permissions[key] is False for key in NO_WRITE),
            "Read-only observation cannot grant writes or claim GetActions")
    return Decision(
        schemaVersion=1,
        status="REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL",
        contractOnly=True,
        structuralChecksPassed=True,
        externallyAuthenticated=False,
        safetyApproved=False,
        observerApproved=False,
        anacondaProcessVerified=False,
        visualLiveDesktopObserved=False,
        **{field: False for field in NO_WRITE},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", type=Path, required=True)
    args = parser.parse_args()
    try:
        path = args.proposal
        require(not path.is_symlink() and path.is_file()
                and 0 < path.stat().st_size <= MAX_PROPOSAL_BYTES,
                "Missing, redirected or oversized proposal")
        record = json.loads(path.read_text(encoding="utf-8"))
        result = validate_contract(record)
    except (Refusal, OSError, ValueError, UnicodeError, TypeError, KeyError) as exc:
        parser.exit(3, f"REFUSED_CONTRACT: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(2)  # Even a well-formed draft must never authorize a guest channel.


if __name__ == "__main__":
    main()
