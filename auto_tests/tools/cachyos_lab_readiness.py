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
from typing import Any


class LabReadinessError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LabReadinessError(message)


# A VM can be disposable only if ALL writable block devices belong to its
# exclusive Proxmox image namespace. An allowlisted VMID by itself is
# insufficient: a VM may attach /dev/disk/by-id, a foreign VM disk or USB/PCI
# passthrough. Never run an installer against those configurations.
_DRIVE_KEY = re.compile(r"^(?:scsi|sata|virtio|ide)[0-9]+$")
_IMAGE_VOL = re.compile(
    r"^[A-Za-z0-9_.-]{1,64}:(?:(?P<directory>[0-9]+)/)?"
    r"vm-(?P<owner>[0-9]+)-disk-[0-9]+(?:\.(?:qcow2|raw|vmdk))?$"
)
_ISO_VOL = re.compile(r"^[A-Za-z0-9_.-]{1,64}:iso/[A-Za-z0-9_.-]+\.iso$")
_FORBIDDEN = re.compile(
    r"^(?:hostpci[0-9]+|usb[0-9]+|unused[0-9]+|virtiofs[0-9]+|serial[0-9]+)$"
)
_FORBIDDEN_OTHER = {"args", "hookscript", "ivshmem", "hostusb"}


def _attached_volumes(config: object, vmid: int, profile: str) -> dict[str, str]:
    """Return exclusively VM-owned writable disks from a read-only PVE response."""
    require(isinstance(config, dict), f"{profile}: missing Proxmox VM config")
    volumes: dict[str, str] = {}
    for key, val in config.items():
        require(
            isinstance(key, str)
            and key not in _FORBIDDEN_OTHER
            and _FORBIDDEN.fullmatch(key) is None,
            f"{profile}: host-device passthrough, hooks or unowned disks are forbidden",
        )
        if not (_DRIVE_KEY.fullmatch(key) or key in {"efidisk0", "tpmstate0"}):
            continue
        require(isinstance(val, str) and val.strip(), f"{profile}: empty {key}")
        props = val.split(",")
        identifier = props[0].removeprefix("file=")
        require("shared=1" not in props and "snapshot=0" not in props,
                f"{profile}: shared or non-snapshot disk forbidden")
        if "media=cdrom" in props:
            require(_DRIVE_KEY.fullmatch(key) is not None
                    and (identifier == "none" or _ISO_VOL.fullmatch(identifier)),
                    f"{profile}: untrusted CD-ROM backing device")
            continue
        match = _IMAGE_VOL.fullmatch(identifier)
        require(
            match is not None
            and int(match.group("owner")) == vmid
            and (
                match.group("directory") is None
                or int(match.group("directory")) == vmid
            ),
            f"{profile}: disk {key} is not an exclusive VM-owned storage volume",
        )
        require(identifier not in volumes.values(),
                f"{profile}: multiple guest disks share a backing volume")
        volumes[key] = identifier
    require("efidisk0" in volumes,
            f"{profile}: dedicated snapshot-backed EFI variables are required")
    if profile == "windows11-uefi":
        require("tpmstate0" in volumes,
                f"{profile}: dedicated snapshot-backed vTPM storage required")
    require(any(_DRIVE_KEY.fullmatch(key) for key in volumes),
            f"{profile}: no exclusive writable installation disk")
    return volumes


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
    observed_volumes: set[str] = set()
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
        attached = _attached_volumes(config, vm.vmid, profile)
        # Default config may show PENDING disk attachments. The actual
        # running configuration must match both current and snapshot.
        live_config = client._request(
            "GET", f"/nodes/{node}/qemu/{vm.vmid}/config?current=1",
            step="cachyos.lab_readiness.current_configuration",
        )
        snapshot_config = client._request(
            "GET",
            f"/nodes/{node}/qemu/{vm.vmid}/snapshot/{settings.reset_snapshot}/config",
            step="cachyos.lab_readiness.snapshot_configuration",
        )
        for label, observed in (("current", live_config), ("snapshot", snapshot_config)):
            require(isinstance(observed, dict), f"{profile}: {label} config missing")
            require(str(observed.get("bios", "")) == "ovmf",
                    f"{profile}: {label} firmware is not OVMF")
            require(_attached_volumes(observed, vm.vmid, profile) == attached,
                    f"{profile}: {label} volume bindings differ from VM configuration")
        for volume in attached.values():
            require(volume not in observed_volumes,
                    f"{profile}: guest shares a writable volume with another lab VM")
            observed_volumes.add(volume)
        status = client.get_vm_status(node, vm.vmid, step="cachyos.lab_readiness.status")
        require(status.get("status") in ("running", "stopped"),
                f"{profile}: VM is in an unknown state")
        guests.append({
            "profile": profile, "vmId": vm.vmid,
            "node": node, "snapshot": settings.reset_snapshot,
            "powerState": status["status"],
            "firmware": "uefi",
            "exclusiveVirtualDiskCount": len(attached),
            "vmDiskIsolationVerified": True,
            "snapshotBackingVerified": True,
        })
    return {
        "ok": True,
        "readOnlyProxmoxProbe": True,
        "guestInventoryVerified": True,
        "noHostDiskPassthrough": True,
        "snapshotDiskOwnershipVerified": True,
        "vmProfiles": guests,
        "fullInstallationExecuted": False,
        "dualBootVerified": False,
        "windowsRecoveryVerified": False,
        "installerStable": False,
    }


def main() -> int:
    try:
        # Deferred imports allow isolated CI tests without live VM credentials.
        from app.clients.proxmox import ProxmoxClient
        from app.config import Settings

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
