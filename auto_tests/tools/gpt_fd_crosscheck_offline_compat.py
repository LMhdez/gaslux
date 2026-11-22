"""Experimental offline GPT field reconciliation: no provenance authority or writer.

Import ONLY audited upstream modules at their pinned Git revisions in CI.
Neither a raw-FD snapshot nor a Windows JSON baseline is self-authenticating.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping

ROLES = frozenset({"host", "guest", "guest-immediate"})
CROSSCHECK_ROLES = frozenset({"windows", "host", "guest"})
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TX = re.compile(r"^[0-9a-f]{32}$")
UNVERIFIED = "DENY_UNAUTHENTICATED_PROVENANCE"


class CompatibilityRefused(ValueError):
    """Incomplete or contradictory offline evidence is refused."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise CompatibilityRefused(reason)


def _guid(value: object, reason: str) -> str:
    require(type(value) is str, reason)
    try:
        ident = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise CompatibilityRefused(reason) from exc
    require(ident.int != 0, reason)
    return str(ident)


def _extent_records(records: object, *, sector: int, total: int) -> list[dict]:
    require(type(records) is list and len(records) > 0, "PARTITIONS_ABSENT")
    found = set()
    spans = []
    out = []
    for part in records:
        require(
            type(part) is dict and set(part) == {"id", "typeId", "offsetBytes", "sizeBytes"},
            "PARTITION_FIELDS_INCOMPATIBLE",
        )
        ident = _guid(part["id"], "PARTUUID_INVALID")
        kind = _guid(part["typeId"], "PARTITION_TYPE_INVALID")
        start, length = part["offsetBytes"], part["sizeBytes"]
        require(
            type(start) is int
            and type(length) is int
            and start > 0
            and length > 0
            and start % sector == 0
            and length % sector == 0
            and start <= total - length,
            "PARTITION_GEOMETRY_INVALID",
        )
        require(ident not in found, "PARTUUID_DUPLICATE")
        found.add(ident)
        spans.append((start, start + length))
        out.append({"id": ident, "typeId": kind, "offsetBytes": start, "sizeBytes": length})
    spans.sort()
    require(all(a[1] <= b[0] for a, b in zip(spans, spans[1:], strict=False)), "PARTITION_OVERLAP")
    return sorted(out, key=lambda p: (p["offsetBytes"], p["id"]))


def _projection(
    style: object, disk_id: object, total: object, sector: object, partitions: object
) -> dict:
    require(style == "GPT", "GPT_ONLY")
    require(type(disk_id) is str and disk_id.startswith("gpt:"), "GPT_DISK_ID_INVALID")
    normalized = "gpt:" + _guid(disk_id[4:], "GPT_DISK_ID_INVALID")
    require(
        type(sector) is int
        and sector in (512, 4096)
        and type(total) is int
        and total > sector
        and total % sector == 0,
        "SECTOR_OR_SIZE_INVALID",
    )
    return {
        "partitionStyle": "GPT",
        "partitionTableId": normalized,
        "sizeBytes": total,
        "logicalSectorBytes": sector,
        "partitions": _extent_records(partitions, sector=sector, total=total),
    }


def parser_projection(parser: object, snapshot: dict) -> dict:
    """Use upstream #286 structural validator; never reparse GPT bytes."""
    try:
        parser.assert_snapshot_matches(snapshot, snapshot)
    except (ValueError, TypeError, KeyError) as exc:
        raise CompatibilityRefused("PARSER_SNAPSHOT_INVALID") from exc
    return _projection(
        snapshot["partitionStyle"],
        snapshot["partitionTableId"],
        snapshot["sizeBytes"],
        snapshot["logicalSectorSizeBytes"],
        [
            {
                "id": p["partGuid"],
                "typeId": p["typeGuid"],
                "offsetBytes": p["offsetBytes"],
                "sizeBytes": p["sizeBytes"],
            }
            for p in snapshot["partitions"]
        ],
    )


def windows_projection(disk: dict) -> dict:
    """Map only structural #288 Windows fields. Partition *numbers* are not IDs."""
    require(
        type(disk) is dict and disk.get("inventoryError") is None, "WINDOWS_INVENTORY_UNAVAILABLE"
    )
    require(
        type(disk.get("uniqueId")) is str and bool(disk["uniqueId"].strip()),
        "WINDOWS_PHYSICAL_ID_MISSING",
    )
    logical, physical = disk.get("logicalSectorSizeBytes"), disk.get("physicalSectorSizeBytes")
    require(
        type(logical) is int
        and type(physical) is int
        and physical >= logical
        and physical % logical == 0,
        "WINDOWS_PHYSICAL_SECTOR_INVALID",
    )
    parts = disk.get("partitions")
    require(type(parts) is list, "WINDOWS_PARTITIONS_MISSING")
    converted = []
    for part in parts:
        require(type(part) is dict, "WINDOWS_PARTITION_INVALID")
        converted.append(
            {
                "id": part.get("guid"),
                "typeId": part.get("gptType"),
                "offsetBytes": part.get("offsetBytes"),
                "sizeBytes": part.get("sizeBytes"),
            }
        )
    return _projection(
        disk.get("partitionStyle"),
        "gpt:" + str(disk.get("guid", "")),
        disk.get("sizeBytes"),
        logical,
        converted,
    )


def reconcile_structure(parser: object, snapshots: Mapping, windows_disk: dict) -> dict:
    """Structural equality only; synthetic role names are NOT collection proofs."""
    require(
        isinstance(snapshots, Mapping) and set(snapshots) == ROLES, "FD_ROLES_MISSING_OR_SWAPPED"
    )
    projected = {role: parser_projection(parser, snap) for role, snap in snapshots.items()}
    windows = windows_projection(windows_disk)
    require(
        all(value == windows for value in projected.values()), "WINDOWS_HOST_GUEST_GPT_MISMATCH"
    )
    return {
        "structuralConsistency": True,
        "originAuthenticated": False,
        "guestImmediateIndependentWindows": False,
        "contentHashesPresentFromParser": False,
        "authorization": False,
    }


def _compare_record_projection(record: dict, canonical: dict) -> None:
    require(type(record) is dict, "CROSSCHECK_RECORD_MISSING")
    for key in ("partitionStyle", "partitionTableId", "sizeBytes", "logicalSectorBytes"):
        require(record.get(key) == canonical[key], "CROSSCHECK_GPT_FIELD_MISMATCH")
    supplied = record.get("partitions")
    require(type(supplied) is list, "CROSSCHECK_PARTITIONS_MISSING")
    reduced = []
    for part in supplied:
        require(
            type(part) is dict
            and set(part) == {"id", "typeId", "offsetBytes", "sizeBytes", "contentSha256"},
            "CONTENT_HASH_REQUIRED",
        )
        require(
            type(part["contentSha256"]) is str
            and SHA256.fullmatch(part["contentSha256"]) is not None,
            "CONTENT_HASH_REQUIRED",
        )
        reduced.append({key: part[key] for key in ("id", "typeId", "offsetBytes", "sizeBytes")})
    normalized = _extent_records(
        reduced, sector=canonical["logicalSectorBytes"], total=canonical["sizeBytes"]
    )
    require(normalized == canonical["partitions"], "CROSSCHECK_PARTUUID_OR_EXTENT_MISMATCH")
    require(
        type(record.get("partitionTableSha256")) is str
        and SHA256.fullmatch(record["partitionTableSha256"]) is not None,
        "GPT_TABLE_HASH_REQUIRED",
    )


def refuse_operational_composition(
    *,
    parser: object,
    crosscheck: object,
    snapshots: Mapping,
    windows_disk: dict,
    inventories: Mapping,
    role_context: Mapping,
    claimed_transaction_id: str,
    claimed_vm_id: str,
) -> dict:
    """Check *supplied* inventory consistency, and still deny operational use.

    Claim values are NOT external pins. #289's True means only identical JSON.
    No SHA256 of content or GPT table is constructed from a #286 snapshot.
    """
    structural = reconcile_structure(parser, snapshots, windows_disk)
    require(
        isinstance(inventories, Mapping) and set(inventories) == CROSSCHECK_ROLES,
        "THREE_CROSSCHECK_ROLES_REQUIRED",
    )
    require(
        isinstance(role_context, Mapping) and set(role_context) == ROLES | {"windows"},
        "ROLE_CONTEXT_MISSING",
    )
    require(
        type(claimed_transaction_id) is str
        and TX.fullmatch(claimed_transaction_id) is not None
        and type(claimed_vm_id) is str
        and len(claimed_vm_id) >= 16,
        "TRANSACTION_VM_CLAIMS_INVALID",
    )
    for role, claim in role_context.items():
        require(
            type(claim) is dict
            and set(claim) == {"transactionId", "vmId", "runId", "role"}
            and claim["role"] == role,
            "ROLE_ORIGIN_SWAP",
        )
        require(claim["transactionId"] == claimed_transaction_id, "TRANSACTION_MISMATCH")
        require(claim["vmId"] == claimed_vm_id, "VM_MISMATCH")
        require(type(claim["runId"]) is str and bool(claim["runId"]), "RUN_ID_MISSING")
    require(
        len({claim["runId"] for claim in role_context.values()}) == 1,
        "WORKFLOW_REPLAY_OR_RUN_MISMATCH",
    )
    targets = {"windows": windows_projection(windows_disk)}
    for role in ("host", "guest"):
        targets[role] = parser_projection(parser, snapshots[role])
    for role in CROSSCHECK_ROLES:
        record = inventories[role]
        _compare_record_projection(record, targets[role])
        require(record.get("transactionId") == claimed_transaction_id, "TRANSACTION_MISMATCH")
    try:
        require(crosscheck.compare_evidence(dict(inventories)) is True, "CROSSCHECK_DECLINED")
    except (ValueError, TypeError, KeyError) as exc:
        raise CompatibilityRefused("CROSSCHECK_REJECTED_INCOMPLETE_OR_DIFFERENT") from exc
    # Even full, byte-identical inventories can be forged or replayed.
    # No external Windows probe, VM mapping, nonce ledger or attestations exist.
    return {
        **structural,
        "crosscheckConsistency": True,
        "decision": UNVERIFIED,
        "provenanceIndependent": False,
        "replayProtected": False,
        "windowsOriginVerified": False,
        "guestAttestationVerified": False,
        "writerAuthorized": False,
        "productionInstallationAuthorized": False,
    }


def deny_prewrite_promotion(result: object) -> None:
    """The #267 result ACCEPT_NO_WRITER is NEVER permission to write."""
    require(
        type(result) is dict
        and result.get("decision") == "ACCEPT_NO_WRITER"
        and set(result) == {"decision", "transactionId", "planSha256", "vmId", "writeCount"},
        "NOT_A_VALID_LABORATORY_NO_WRITER_RESULT",
    )
    raise CompatibilityRefused("NO_WRITER_RESULT_CANNOT_AUTHORIZE_EXECUTION")
