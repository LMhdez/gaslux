"""Q4OS read-only adapter for Safety #265; no GPT parser or writer."""
from __future__ import annotations


def to_safety_snapshot(q4os: dict) -> dict:
    """Project already-inspected Q4OS GPT metadata to Safety's canonical fields."""
    if q4os.get("layout") != "uefi/gpt":
        raise ValueError("unsupported firmware and partition layout")
    sector = q4os["logicalSectorBytes"]
    if type(sector) is not int or sector not in (512, 4096):
        raise ValueError("invalid logical sector")
    parts = []
    for part in q4os["partitions"]:
        first, last = part["first"], part["last"]
        if type(first) is not int or type(last) is not int or first > last:
            raise ValueError("invalid partition geometry")
        parts.append({
            "number": part["index"], "typeGuid": part["type"],
            "partGuid": part["guid"], "offsetBytes": first * sector,
            "sizeBytes": (last - first + 1) * sector,
            "attributes": part["attributes"],
        })
    return {
        "partitionStyle": "GPT",
        "partitionTableId": "gpt:" + q4os["diskGuid"],
        "sizeBytes": q4os["diskSizeBytes"],
        "logicalSectorSizeBytes": sector,
        "partitions": parts,
    }


def refuse_calamares(*, q4os: dict | None, expected: dict | None,
                    safety_observed: dict | None, safety_compare,
                    plan: dict | None, transaction: dict | None,
                    write_set: list | None, calamares: dict | None) -> dict:
    """Diagnose mismatches using Safety comparator; ALWAYS refuse disk/EFI writes.

    Safety's assert_snapshot_matches must be injected by the caller from #265.
    Expected must be independently authenticated; this adapter cannot attest it.
    """
    reasons = []
    try:
        if not callable(safety_compare):
            raise ValueError("Safety #265 comparator unavailable")
        if any(type(item) is not dict for item in
               (q4os, expected, safety_observed, plan, transaction, calamares)):
            raise ValueError("missing required inventory/plan/transaction/config")
        if type(write_set) is not list or not write_set:
            raise ValueError("missing explicit write-set")
        safety_compare(expected, safety_observed)
        safety_compare(to_safety_snapshot(q4os), safety_observed)
        if plan.get("backend") != "q4os-native" or plan.get("firmwareLayout") != "uefi/gpt":
            raise ValueError("wrong backend or firmware")
        if plan.get("diskGuid") != q4os["diskGuid"] or (
            plan.get("observedStateSha256") != q4os.get("observedStateSha256")
        ):
            raise ValueError("plan does not bind observed disk")
        txid = transaction.get("id")
        if not isinstance(txid, str) or not txid or plan.get("transactionId") != txid:
            raise ValueError("unbound transaction")
        if transaction.get("diskGuid") != plan["diskGuid"] or (
            transaction.get("observedStateSha256") != plan["observedStateSha256"]
        ):
            raise ValueError("transaction does not bind disk state")
        for key in ("installationAuthorized", "calamaresJobsAuthorized",
                    "diskWritesAuthorized", "windowsEspWritesAuthorized", "rollbackVerified"):
            if plan.get(key) is not False:
                raise ValueError("writable or incomplete plan: " + key)
        if plan.get("windowsEspFallbackWriteBlocked") is not True or (
            plan.get("efiDebianHookWriteBlocked") is not True
        ):
            raise ValueError("missing EFI protection")
        if calamares.get("nativeCalamaresConfigVerified") is not True or (
            calamares.get("upstreamInstallsEfiFallback") is not True
        ):
            raise ValueError("Calamares provenance/configuration mismatch")
        owned = set()
        protected = {p["partGuid"] for p in safety_observed["partitions"]}
        sector = q4os["logicalSectorBytes"]
        start = plan["proposedRootStartLba"] * sector
        length = (plan["proposedRootEndLba"] - plan["proposedRootStartLba"] + 1) * sector
        for operation in write_set:
            if type(operation) is not dict or set(operation) != {
                "operation", "partGuid", "ownerTransactionId", "startBytes", "sizeBytes"
            }:
                raise ValueError("incomplete write-set entry")
            if operation["operation"] not in {"create-root-ext4", "format-root-ext4"}:
                raise ValueError("unauthorized Calamares operation")
            if operation["partGuid"] in protected:
                raise ValueError("Windows/WinRE/OEM partition targeted")
            if operation["ownerTransactionId"] != txid or operation["operation"] in owned:
                raise ValueError("foreign or duplicate operation")
            if type(operation["startBytes"]) is not int or (
                type(operation["sizeBytes"]) is not int
            ) or operation["startBytes"] != start or operation["sizeBytes"] != length:
                raise ValueError("unexpected write extent")
            owned.add(operation["operation"])
        if calamares.get("fallbackWritePreventedAndVerified") is not True:
            reasons.append("installEFIFallback=true: fallback ESP write not prevented")
        reasons.append("GPT writes, mount, GRUB, EFI and NVRAM not authenticated")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        reasons.append("fail-closed: " + str(exc))
    return {
        "backend": "q4os-native", "decision": "refuse", "reasons": reasons,
        "writerPresent": False, "calamaresJobsAuthorized": False,
        "diskWritesAuthorized": False, "windowsEspWritesAuthorized": False,
        "installationAuthorized": False, "rollbackVerified": False,
    }
