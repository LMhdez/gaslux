"""Read-only Q4OS guest-visible virtio identity contract; never grants write authority."""
from __future__ import annotations
import hashlib
import json
import re
import uuid
from typing import Any
from gaslux_q4os_vm_target_plan import Q4osPlanRefusal

_PREFIX = "GASLUXQ4OS-"
_DEVICE = re.compile(r"/dev/vd[a-z]+\\Z")
_ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


def expected_virtio_serial(plan: dict[str, Any]) -> str:
    material = (plan["runId"] + "\\0" + plan["nonce"]).encode("ascii")
    return _PREFIX + hashlib.sha256(material).hexdigest()[:20].upper()


def _refuse(ok: bool, reason: str) -> None:
    if not ok:
        raise Q4osPlanRefusal(reason)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _refuse(key not in result, "Duplicate JSON property: " + key)
        result[key] = value
    return result


def validate_guest_disk_report(raw: bytes, *, plan: dict[str, Any], expected_serial: str) -> dict[str, Any]:
    """Match one guest report to a previously authenticated read-only host plan."""
    _refuse(len(raw) <= 16384, "Guest report exceeds size limit")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Q4osPlanRefusal("Malformed guest identity JSON") from exc
    _refuse(isinstance(data, dict), "Guest report must be an object")
    fields = {
        "schemaVersion", "runId", "nonce", "device", "serial", "sizeBytes",
        "logicalSectorBytes", "physicalSectorBytes", "diskGuid", "partitions",
        "readOnlyProbe", "writeAttempted",
    }
    _refuse(set(data) == fields, "Guest report fields differ from contract")
    _refuse(data["schemaVersion"] == 1, "Unsupported guest report schema")
    _refuse(data["runId"] == plan["runId"] and data["nonce"] == plan["nonce"], "Run/nonce mismatch")
    _refuse(data["serial"] == expected_serial == expected_virtio_serial(plan), "Virtio serial mismatch")
    _refuse(isinstance(data["device"], str) and _DEVICE.fullmatch(data["device"]), "Invalid diagnostic device path")
    _refuse(data["sizeBytes"] == plan["diskSizeBytes"], "Guest disk capacity mismatch")
    _refuse(data["logicalSectorBytes"] == plan["sectorBytes"], "Logical sector size mismatch")
    _refuse(data["physicalSectorBytes"] in (512, 4096), "Unsupported physical sector size")
    _refuse(data["diskGuid"] == plan["diskGuid"], "Guest GPT disk GUID mismatch")
    _refuse(data["readOnlyProbe"] is True and data["writeAttempted"] is False, "Probe is not read-only")
    parts = data["partitions"]
    _refuse(isinstance(parts, list) and len(parts) == 1, "Unexpected guest partition count")
    esp = parts[0]
    expected = {"number", "startLba", "endLba", "typeGuid", "partGuid", "label", "filesystem"}
    _refuse(isinstance(esp, dict) and set(esp) == expected, "Malformed guest ESP record")
    _refuse(esp["number"] == 1, "Unexpected ESP partition number")
    _refuse(esp["startLba"] == plan["espStartLba"] and esp["endLba"] == plan["espEndLba"], "Guest ESP geometry mismatch")
    try:
        type_guid = str(uuid.UUID(esp["typeGuid"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise Q4osPlanRefusal("Malformed guest partition type GUID") from exc
    _refuse(type_guid == _ESP_TYPE, "Guest partition is not an EFI System Partition")
    _refuse(esp["partGuid"] == plan["espGuid"], "Guest ESP GUID mismatch")
    _refuse(esp["label"] == plan["espName"] and esp["filesystem"] == "vfat", "Guest ESP identity mismatch")
    return {
        "schemaVersion": 1,
        "guestDiskIdentityVerified": True,
        "guestReportSha256": hashlib.sha256(raw).hexdigest(),
        "observedSerial": data["serial"],
        "observedDiskGuid": data["diskGuid"],
        "observedEspGuid": esp["partGuid"],
        "readOnlyProbe": True,
        "installationAuthorized": False,
        "diskWritesAuthorized": False,
        "calamaresJobsAuthorized": False,
        "windowsEspWritesAuthorized": False,
        "rollbackVerified": False,
    }


def canonical_guest_json(report: dict[str, Any]) -> bytes:
    value = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return (value + "\\n").encode("utf-8")
