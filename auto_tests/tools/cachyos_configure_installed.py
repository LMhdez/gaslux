#!/usr/bin/env python3
"""Configure a deterministic, disposable CachyOS lab installation after pacstrap.

Never use this profile for a real user. Production account data must come from
an authenticated typed installation plan and a separate secret-handling path.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Callable

RUN_ID = re.compile(r"[a-z0-9-]{12,80}\Z")
LAB_USER = "gaslux-lab"
HOSTNAME = "gaslux-cachyos-lab"
LOCALE = "en_US.UTF-8"
TIMEZONE = "UTC"
KEYMAP = "us"
DESKTOP_PACKAGES = (
    "plasma-desktop", "sddm", "networkmanager", "konsole", "dolphin",
)


class InstalledConfigurationError(ValueError):
    """Installed CachyOS lab root is not safe to configure."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise InstalledConfigurationError(message)


def _regular(root: Path, relative: str) -> Path:
    path = root / relative
    require(path.is_file() and not path.is_symlink()
            and path.resolve().is_relative_to(root.resolve()),
            "missing, linked or escaped installed file: " + relative)
    return path


def validate_profile(root: Path, run_id: str) -> None:
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id) is not None,
            "invalid lab transaction identifier")
    require(root.is_absolute() and root.is_dir() and not root.is_symlink()
            and root.resolve() == root,
            "installed root must be an explicit canonical directory")
    release = _regular(root, "etc/os-release").read_text(encoding="utf-8")
    require("ID=cachyos" in release.splitlines()
            and "ID_LIKE=arch" in release.splitlines(),
            "target is not a native CachyOS installation")
    owner = _regular(root, ".gaslux-lab-root-owner").read_text(encoding="ascii")
    require(owner == run_id + "\n", "installed root belongs to another transaction")
    require(_regular(root, "var/lib/pacman/local/ALPM_DB_VERSION").is_file(),
            "native pacman database is missing")
    require(_regular(root, "boot/vmlinuz-linux-cachyos-lts").is_file()
            and _regular(root, "boot/initramfs-linux-cachyos-lts.img").is_file(),
            "native CachyOS kernel or initramfs is missing")


def _write_new(path: Path, data: str, mode: int = 0o644) -> None:
    require(not path.exists() and not path.is_symlink(),
            "refusing to replace pre-existing installed configuration: " + path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def configure(root: Path, run_id: str, *,
              runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> dict[str, object]:
    """Configure only a fresh, owner-bound lab root; no ESP or Windows path."""
    validate_profile(root, run_id)
    for relative in ("etc/hostname", "etc/vconsole.conf", "etc/locale.conf",
                     "etc/sudoers.d/10-gaslux-wheel",
                     "etc/systemd/system/graphical.target.wants/sddm.service",
                     "etc/systemd/system/multi-user.target.wants/NetworkManager.service",
                     "etc/systemd/system/multi-user.target.wants/systemd-timesyncd.service",
                     "home/" + LAB_USER):
        path = root / relative
        require(not path.exists() and not path.is_symlink(),
                "target already contains user/configuration state: " + relative)

    # Random password is used only to derive a salted hash; plaintext is never
    # written to disk, argv, logs or workflow outputs.
    transient_password = secrets.token_urlsafe(36)
    hash_result = runner(
        ["openssl", "passwd", "-6", "-stdin"], input=transient_password + "\n",
        capture_output=True, text=True, check=False, timeout=20)
    transient_password = ""
    require(hash_result.returncode == 0, "could not create transient lab password hash")
    password_hash = hash_result.stdout.strip()
    require(re.fullmatch(r"\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{80,}",
                         password_hash) is not None,
            "openssl returned an invalid SHA-512 password hash")

    _write_new(root / "etc/hostname", HOSTNAME + "\n")
    _write_new(root / "etc/vconsole.conf", "KEYMAP=" + KEYMAP + "\n")
    _write_new(root / "etc/locale.conf", "LANG=" + LOCALE + "\n")
    locale_gen = _regular(root, "etc/locale.gen")
    existing = locale_gen.read_text(encoding="utf-8")
    require("en_US.UTF-8 UTF-8" not in existing.splitlines(),
            "locale unexpectedly enabled before configuration")
    with locale_gen.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\nen_US.UTF-8 UTF-8\n")
        stream.flush()
        os.fsync(stream.fileno())
    sudoers = root / "etc/sudoers.d/10-gaslux-wheel"
    _write_new(sudoers, "%wheel ALL=(ALL:ALL) ALL\n", 0o440)

    commands = (
        ["arch-chroot", str(root), "useradd", "--create-home", "--groups", "wheel",
         "--shell", "/bin/bash", LAB_USER],
        ["arch-chroot", str(root), "usermod", "--password", password_hash, LAB_USER],
        ["arch-chroot", str(root), "visudo", "-cf", "/etc/sudoers.d/10-gaslux-wheel"],
        ["arch-chroot", str(root), "locale-gen"],
        ["arch-chroot", str(root), "ln", "-s", "/usr/share/zoneinfo/" + TIMEZONE,
         "/etc/localtime"],
        ["arch-chroot", str(root), "systemctl", "enable", "sddm.service"],
        ["arch-chroot", str(root), "systemctl", "enable", "NetworkManager.service"],
        ["arch-chroot", str(root), "systemctl", "enable", "systemd-timesyncd.service"],
    )
    for argv in commands:
        result = runner(argv, capture_output=True, text=True, check=False, timeout=180)
        require(result.returncode == 0,
                "installed CachyOS configuration command failed: " + argv[3])

    require((root / "etc/localtime").is_symlink()
            and os.readlink(root / "etc/localtime") == "/usr/share/zoneinfo/UTC",
            "installed timezone link is not the requested UTC zone")
    passwd = _regular(root, "etc/passwd").read_text(encoding="utf-8")
    require(any(line.startswith(LAB_USER + ":") and line.split(":")[6] == "/bin/bash"
                for line in passwd.splitlines()),
            "configured lab account is absent")
    shadow = _regular(root, "etc/shadow").read_text(encoding="utf-8")
    require(any(line.startswith(LAB_USER + ":$6$") for line in shadow.splitlines()),
            "configured lab account does not have a salted password hash")
    for service in ("sddm", "NetworkManager", "systemd-timesyncd"):
        result = runner(
            ["arch-chroot", str(root), "systemctl", "is-enabled", "--quiet",
             service + ".service"],
            capture_output=True, text=True, check=False, timeout=60)
        require(result.returncode == 0, "service was not enabled: " + service)
    return {
        "configured": True, "labOnly": True, "user": LAB_USER,
        "hostname": HOSTNAME, "locale": LOCALE, "keyboard": KEYMAP,
        "timezone": TIMEZONE, "desktop": "KDE Plasma", "displayManager": "SDDM",
        "network": "NetworkManager", "passwordPlaintextRetained": False,
        "productionReady": False,
    }
