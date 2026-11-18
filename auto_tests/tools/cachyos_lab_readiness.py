#!/usr/bin/env python3
"""Read-only Proxmox readiness probe for CachyOS Windows 10/11 E2E campaigns.

Uses the existing auto_tests/.env configuration and its Proxmox client.
PERFORMS ONLY GET requests; never restores snapshots or starts/stops guests.
Passing this probe is NOT proof of a CachyOS installation or rollback.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable


class LabReadinessError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LabReadinessError(message)


def classify_vm(vm: Any) -> str | None:
    os_label = str(vm.os).strip().lower()
    if vm.firmware != "uefi":
        return None
    if re.fullmatch(r"windows[ ]+10[ ]+uefi", os_label):
        return "windows10-uefi"
    if re.fullmatch(r"windows[ ]+11[ ]+uefi", os_label):
        return "windows11-uefi"
    return None


def select_authorized_lab_vms(settings: Any) -> dict[str, Any]:
    require(bool(settings.proxmox_verify_tls) or
            settings.proxmox_ca_bundle is not None,
            "Proxmox TLS certificate verification is required")
    source = str(settings.repository_url).rstrip("/")
    require(source in (
        "https://github.com/LMhdez/gaslux",
        "https://github.com/LMhdez/gaslux.git",
    ), "automation must use the Gaslux repository, not upstream Libertix")
    allowed = set(settings.allowed_proxmox_vmids)
    selected: dict[str, Any] = {}
    for vm in settings.vms:
        profile = classify_vm(vm)
        if profile is None:
            continue
        require(profile not in selected, "ambiguous Windows UEFI VM inventory")
        require(vm.vmid in allowed, "VM ID is not in the operator-authorized allowlist")
        require(vm.automation_enabled, "Windows UEFI VM is not enabled for lab automation")
        selected[profile] = vm
    require(set(selected) == {"windows10-uefi", "windows11-uefi"},
            "exactly one eligible Windows 10 and Windows 11 UEFI VM are required")
    require(selected["windows10-uefi"].vmid != selected["windows11-uefi"].vmid,
            "Windows test profiles must use different virtual machines")
    return selected


def probe(settings: Any, client: Any) -> dict[str, object]:
    selected = select_authorized_lab_vms(settings)
    guests = []
    for profile in ("windows10-uefi", "windows11-uefi"):
        vm = selected[profile]
        node = client.locate_vm(vm.vmid)
        client.assert_snapshot(node, vm.vmid, settings.reset_snapshot)
        config = client._request(  # Existing client performs strict GET; no VM writes.
            "GET", f"/nodes/{node}/qemu/{vm.vmid}/config",
            step="cachyos.lab_readiness.configuration",
        )
        require(isinstance(config, dict), "invalid Proxmox guest configuration")
        require(str(config.get("bios", "")) == "ovmf",
                f"{profile}: UEFI/OVMF firmware is not configured")
        require(bool(config.get("efidisk0")),
                f"{profile}: independent EFI variable disk is missing")
        require(any(str(key).startswith(("scsi", "sata", "virtio", "ide")) and
                    str(key)[-1].isdigit() for key in config),
                f"{profile}: no virtual installation disk configured")
        if profile == "windows11-uefi":
            require(bool(config.get("tpmstate0")),
                    "Windows 11 guest requires a configured vTPM")
        status = client.get_vm_status(node, vm.vmid, step="cachyos.lab_readiness.status")
        require(status.get("status") in ("running", "stopped"),
                f"{profile}: VM is in an unknown state")
        guests.append({
            "profile": profile, "vmId": vm.vmid,
            "node": node, "snapshot": settings.reset_snapshot,
            "powerState": status["status"],
            "firmware": "uefi",
        })
    return {
        "ok": True,
        "readOnlyProxmoxProbe": True,
        "guestInventoryVerified": True,
        "vmProfiles": guests,
        "fullInstallationExecuted": False,
        "dualBootVerified": False,
        "windowsRecoveryVerified": False,
        "installerStable": False,
    }


def main() -> int:
    try:
        # Deferred imports allow isolated CI tests without live VM credentials.
        from app.config import Settings
        from app.clients.proxmox import ProxmoxClient

        settings = Settings()
        with ProxmoxClient(
            settings.proxmox_url, settings.proxmox_token_id,
            settings.proxmox_token_secret.get_secret_value(),
            timeout=settings.proxmox_timeout_seconds,
            task_timeout=settings.proxmox_task_timeout_seconds,
            verify_tls=settings.proxmox_verify_tls,
            ca_bundle=settings.proxmox_ca_bundle,
        ) as client:
            result = probe(settings, client)
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
