"""CachyOS UEFI shared-ESP boot write-set model, offline, deny-only.

This is *not* an installer, policy grant or ESP attestor. It reconciles exact
pinned source code with a claimed lab plan and GPT/ESP identity; it refuses
ambiguous proposals, and NEVER gives permission to write any resource.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid
from typing import Any

SOURCE_BLOBS = {
    "assets/live/cachyos-stage-target.sh": "453f04b0a20ffc475ff3b4fc9614c80dc82515fe",
    "assets/live/cachyos-uefi-config.py": "f5743d5ca1e9d7b33f7ac45713bc24aa0776a2ab",
    "assets/live/cachyos-uefi-lab.py": "90bd65a2d2df0ce22a83fc9488dcc03f7b64292d",
    "auto_tests/tools/cachyos_configure_installed.py":
        "979551dc10adff8ad960642026a395ce18f76f57",
}

BINDING_FIELDS = frozenset((
    "transactionId", "diskGuid", "espPartuuid", "espVfatUuid",
    "espOffsetBytes", "espLengthBytes", "sectorBytes", "diskBytes",
))
HASH = re.compile(r"[0-9a-f]{40}\Z")
TX = re.compile(r"[A-Za-z0-9_-]{12,100}\Z")
VFAT = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}\Z")

# The source is a VM-only lab. No package manager or GRUB tool is executed
# by this module, even to discover its effective write set.
OP_SPEC = (
    ("pacstrap", "WRITE_PACKAGES_KERNEL", "/boot/vmlinuz-linux-cachyos",
     "LINUX_ROOT", "kernel from verified Arch package; exact files are version dependent"),
    ("mkinitcpio -P", "GENERATE_INITRAMFS",
     "/boot/initramfs-linux-cachyos.img", "LINUX_ROOT",
     "package hooks and kernel update behavior not audited"),
    ("lab write_new", "CREATE", "/etc/fstab", "LINUX_ROOT", "owned root marker only"),
    ("lab write_new", "CREATE", "/etc/default/grub.d/99-gaslux.cfg",
     "LINUX_ROOT", "GRUB defaults may affect future generated menu"),
    ("lab write_new", "CREATE", "/etc/grub.d/45_gaslux_windows",
     "LINUX_ROOT", "reads Windows loader by chainloader, does not write BCD"),
    ("lab write_new", "CREATE", "/boot/efi/EFI/Gaslux-CachyOS/.gaslux-owner",
     "WINDOWS_ESP", "ESP is shared with Windows; owner marker alone insufficient"),
    ("lab mkdir", "CREATE_DIRECTORY", "/boot/efi/EFI/Gaslux-CachyOS",
     "WINDOWS_ESP", "physical ESP and directory ownership not proven"),
    ("grub-install --no-nvram --no-extra-removable", "GRUB_EFI_INSTALL",
     "/boot/efi/EFI/Gaslux-CachyOS/grubx64.efi",
     "WINDOWS_ESP", "GRUB external binary may write additional files"),
    ("grub-install --no-nvram --no-extra-removable", "GRUB_MODULES_UNBOUNDED",
     "/boot/grub/**", "LINUX_ROOT",
     "external GRUB module tree not exhaustively bounded by caller"),
    ("grub-mkconfig", "GENERATE_CANDIDATE", "/boot/grub/grub.cfg.gaslux-candidate",
     "LINUX_ROOT", "depends on installed /etc/grub.d hooks and target environment"),
    ("os.link", "CREATE_NO_CLOBBER", "/boot/grub/grub.cfg",
     "LINUX_ROOT", "creates second hardlink to verified candidate"),
    ("lab exception cleanup", "REMOVE_CREATED_TREE",
     "/boot/efi/EFI/Gaslux-CachyOS/**",
     "WINDOWS_ESP", "rmtree marker does not prove child-file ownership"),
    ("lab exception cleanup", "REMOVE_OWNED_CANDIDATE",
     "/boot/grub/grub.cfg.gaslux-candidate", "LINUX_ROOT",
     "cleanup must check FD/inode ownership, not only pathname"),
)
ROOT = "LINUX_ROOT"
ESP = "WINDOWS_ESP"
AUTH = False

class WriteSetRefused(ValueError):
    """An unexpected plan, source version, target or operation is denied."""


def deny(test: bool, reason: str) -> None:
    if not test:
        raise WriteSetRefused(reason)


def _sha1_git_blob(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


def _pinned_sources(repo: Path) -> dict[str, Any]:
    deny(type(repo) is Path and repo.is_absolute()
         and repo.is_dir() and not repo.is_symlink(),
         "REPO_ROOT_UNBOUND")
    manifest: dict[str, Any] = {}
    for rel, git_blob in SOURCE_BLOBS.items():
        path = repo / rel
        # Never follow a redirected final path or accept foreign hard links.
        try:
            before = path.lstat()
            deny(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.getuid(), "SOURCE_ALIAS_OR_FOREIGN_OWNER")
            content = path.read_bytes()
            after = path.lstat()
        except OSError as exc:
            raise WriteSetRefused("SOURCE_NOT_READABLE") from exc
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size,
                              s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        deny(identity(before) == identity(after) and len(content) == before.st_size,
             "SOURCE_CHANGED_DURING_INSPECTION")
        deny(_sha1_git_blob(content) == git_blob, "AUDITED_SOURCE_VERSION_CHANGED")
        manifest[rel] = {"gitBlobSha1": git_blob,
                         "sha256": hashlib.sha256(content).hexdigest()}
    return manifest


def _actual_grub_commands(script: bytes) -> dict[str, list[str]]:
    try:
        tree = ast.parse(script, filename="cachyos-uefi-lab.py")
    except SyntaxError as exc:
        raise WriteSetRefused("LAB_SOURCE_NOT_PARSEABLE") from exc
    result = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "run"
                and len(node.args) >= 3):
            continue
        head = node.args[:3]
        if not (all(isinstance(x, ast.Constant) and isinstance(x.value, str)
                    for x in (head[0], head[2]))
                and head[0].value == "arch-chroot"):
            continue
        name = head[2].value
        if name in {"grub-install", "grub-mkconfig", "grub-script-check",
                    "efibootmgr", "bootctl", "pacman", "update-grub"}:
            deny(name not in result, "DUPLICATE_GRUB_COMMAND")
            result[name] = [
                x.value for x in node.args
                if isinstance(x, ast.Constant) and isinstance(x.value, str)
            ]
    deny(set(result) == {"grub-install", "grub-mkconfig",
                         "grub-script-check"}, "UNEXPECTED_EFI_COMMAND")
    gi = result["grub-install"]
    deny(set(gi) == {
        "arch-chroot", "grub-install", "--target=x86_64-efi",
        "--efi-directory=/boot/efi", "--bootloader-id=Gaslux-CachyOS",
        "--no-nvram", "--no-extra-removable", "--recheck",
    }, "UNEXPECTED_GRUB_INSTALL_FLAGS")
    deny(result["grub-mkconfig"] == [
        "arch-chroot", "grub-mkconfig", "-o",
        "/boot/grub/grub.cfg.gaslux-candidate",
    ], "UNEXPECTED_GRUB_CONFIG_TARGET")
    deny(result["grub-script-check"] == [
        "arch-chroot", "grub-script-check",
        "/boot/grub/grub.cfg.gaslux-candidate",
    ], "UNEXPECTED_GRUB_VALIDATE_TARGET")
    return result


def _uuid(value: Any) -> str:
    deny(type(value) is str, "ESP_UUID_OR_GUID_INVALID")
    try:
        u = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise WriteSetRefused("ESP_UUID_OR_GUID_INVALID") from exc
    deny(str(u) == value and u.int != 0, "ESP_UUID_OR_GUID_INVALID")
    return value


def _check_binding(plan: dict, expected: dict, observed: dict) -> dict:
    deny(type(expected) is dict and type(observed) is dict
         and set(expected) == BINDING_FIELDS
         and set(observed) == BINDING_FIELDS,
         "ESP_BINDING_FIELDS_INVALID")
    for value in (expected, observed):
        deny(type(value["transactionId"]) is str
             and TX.fullmatch(value["transactionId"]) is not None,
             "TRANSACTION_INVALID")
        _uuid(value["diskGuid"])
        _uuid(value["espPartuuid"])
        deny(type(value["espVfatUuid"]) is str
             and VFAT.fullmatch(value["espVfatUuid"]) is not None,
             "ESP_VFAT_UUID_INVALID")
        for key in ("espOffsetBytes", "espLengthBytes", "sectorBytes",
                    "diskBytes"):
            deny(type(value[key]) is int and value[key] > 0,
                 "ESP_GEOMETRY_INVALID")
        deny(value["sectorBytes"] == 512
             and value["diskBytes"] % 512 == 0
             and value["espOffsetBytes"] % 512 == 0
             and value["espLengthBytes"] % 512 == 0
             and value["espOffsetBytes"] >= 34 * 512
             and value["espOffsetBytes"] + value["espLengthBytes"]
                 <= value["diskBytes"] - 33 * 512,
             "ESP_GEOMETRY_INVALID")
    deny(expected == observed, "FOREIGN_ESP_OR_TRANSACTION")
    deny(plan["runId"] == observed["transactionId"]
         and plan["espUuid"] == observed["espVfatUuid"]
         and plan["windowsBootUuid"] == observed["espVfatUuid"],
         "ESP_PLAN_BINDING_MISMATCH")
    return dict(observed)


def _source_render(repo: Path, plan: dict) -> dict[str, str]:
    # The renderer was pinned by Git blob SHA, validated before import.
    filename = repo / "assets/live/cachyos-uefi-config.py"
    spec = importlib.util.spec_from_file_location("cachyos_uefi_writeset_pinned", filename)
    deny(spec is not None and spec.loader is not None, "RENDERER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        result = module.render(plan)
    except (ValueError, KeyError, TypeError) as exc:
        raise WriteSetRefused("INVALID_CACHYOS_UEFI_PLAN") from exc
    deny(result["releaseSafe"] == "false"
         and result["bootloaderId"] == "Gaslux-CachyOS"
         and "chainloader /EFI/Microsoft/Boot/bootmgfw.efi"
             in result["windowsGrubEntry"],
         "UNEXPECTED_RENDERED_BOOT_CONFIG")
    return result


def _path_ok(path: object) -> bool:
    if type(path) is not str or not path.startswith("/") or "\0" in path:
        return False
    bits = path.split("/")
    if "." in bits or ".." in bits or "" in bits[1:]:
        return False
    return bool(PurePosixPath(path).is_absolute())


def check_proposal(manifest: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    """Classify an exact audited operation, never approve its execution."""
    deny(type(manifest) is dict
         and manifest.get("status") == "BOOT_WRITESET_MODEL_ONLY_DENY_NO_WRITER"
         and manifest.get("authorization") is False
         and type(manifest.get("operations")) is list,
         "UNVERIFIED_MANIFEST")
    deny(type(proposal) is dict
         and set(proposal) == {"operation", "path", "scope", "transactionId",
                               "espPartuuid"}, "UNEXPECTED_WRITESET_PROPOSAL")
    deny(_path_ok(proposal["path"]), "INVALID_TARGET_PATH")
    deny(proposal["transactionId"] == manifest["transactionId"],
         "FOREIGN_TRANSACTION")
    deny(proposal["espPartuuid"] == manifest["esp"]["espPartuuid"],
         "FOREIGN_ESP")
    deny(not (
        proposal["path"].lower().startswith("/boot/efi/efi/microsoft/")
        or proposal["path"].lower().startswith("/boot/efi/efi/boot/")
        or proposal["path"].lower().startswith("/boot/efi/efi/oem/")
        or proposal["path"].lower().startswith("/boot/efi/efi/recovery/")
        or proposal["path"].lower().startswith("/boot/efi/efi/libertix/")
    ), "WINDOWS_OEM_FALLBACK_OR_FOREIGN_EFI")
    deny(proposal["scope"] != "NVRAM"
         and proposal["operation"] not in {
             "EFIBOOTMGR", "BOOTORDER_WRITE", "BOOTNEXT_WRITE",
             "UNEXPECTED_GRUB_UPDATE", "GRUB_INSTALL_WITH_NVRAM",
         }, "UNVERIFIED_FIRMWARE_OR_UPDATE_WRITE")
    rows = [
        op for op in manifest["operations"]
        if (op["operation"], op["path"], op["scope"])
        == (proposal["operation"], proposal["path"], proposal["scope"])
    ]
    deny(len(rows) == 1, "OPERATION_NOT_IN_PINNED_SOURCE_WRITESET")
    result = dict(rows[0])
    result["authorization"] = False
    result["ownershipVerified"] = False
    return result


def build_manifest(repo: Path, plan: dict, expected_esp: dict,
                   observed_esp: dict) -> dict[str, Any]:
    """Build a source-bound manifest without QEMU/ESP access or any writer."""
    pins = _pinned_sources(repo)
    deny(type(plan) is dict, "INVALID_PLAN_SHAPE")
    render = _source_render(repo, plan)
    esp = _check_binding(plan, expected_esp, observed_esp)
    lab = (repo / "assets/live/cachyos-uefi-lab.py").read_bytes()
    commands = _actual_grub_commands(lab)
    operations = []
    for actor, operation, path, scope, risk in OP_SPEC:
        deny(_path_ok(path), "INVALID_SOURCE_TARGET_PATH")
        operations.append({
            "actor": actor, "operation": operation, "path": path,
            "scope": scope, "risk": risk, "authorization": False,
            "ownershipVerified": False,
            "sourceEvidence": "PINNED_SOURCE_STATIC_ONLY",
            "destinationIdentity": "UNVERIFIED_PHYSICAL_MAPPING",
        })
    return {
        "schemaVersion": 1,
        "status": "BOOT_WRITESET_MODEL_ONLY_DENY_NO_WRITER",
        "transactionId": plan["runId"],
        "esp": esp,
        "espIdentityAuthority": "CLAIMED_NOT_FD_AUTHENTICATED",
        "sourceBlobs": pins,
        "grubCommands": commands,
        "bootloaderId": render["bootloaderId"],
        "windowsGrubEntryIsTextOnly": True,
        "kernelUpdateHooksVerified": False,
        "efiUpdateHooksVerified": False,
        "efiRollbackOwnershipVerified": False,
        "uefiBootCurrentVerified": False,
        "windowsBcdPreservedIndependently": False,
        "bootOrderMutationAuthorized": False,
        "bootNextMutationAuthorized": False,
        "fallbackEfiMutationAuthorized": False,
        "windowsEfiMutationAuthorized": False,
        "rootAndEspOwnershipIndependentlyProven": False,
        "operations": operations,
        "authorization": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "rollbackProven": False,
        "releaseEligible": False,
        "stable": False,
    }
