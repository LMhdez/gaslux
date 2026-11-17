#!/usr/bin/env bash
# Build a minimal, disposable initramfs for the Q4OS virtio identity-only probe.
set -Eeuo pipefail

die() { printf 'GASLUX_Q4OS_INITRAMFS_REFUSED=%s\n' "$*" >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true ]] || die 'Requires disposable GitHub Actions runner'
[[ $# -eq 3 ]] || die 'Usage: gaslux_q4os_identity_initramfs.sh KERNEL ROOTFS_DIR INITRAMFS'
kernel="$1"
rootfs="$2"
output="$3"
[[ "$kernel" == /* && -f "$kernel" && ! -L "$kernel" ]] || die 'Kernel path is not a regular file'
[[ "$rootfs" == /* && ! -e "$rootfs" && ! -L "$rootfs" ]] || die 'Rootfs destination already exists'
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] || die 'Initramfs destination already exists'
command -v cpio >/dev/null || die 'cpio is missing'
command -v gzip >/dev/null || die 'gzip is missing'
[[ -x /usr/bin/python3 ]] || die 'System Python is missing'

kernel_version="${kernel##*/vmlinuz-}"
modules="/lib/modules/$kernel_version"
[[ -d "$modules" && -s "$modules/modules.dep" ]] || die "Kernel modules are missing for $kernel_version"
mkdir -m 0700 -p "$rootfs"

ROOTFS="$rootfs" KERNEL_VERSION="$kernel_version" \
GUEST_AGENT="$(dirname "$0")/q4os_guest_identity_agent.py" \
env -u LD_LIBRARY_PATH /usr/bin/python3 - <<'PY'
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sysconfig
from pathlib import Path

root = Path(os.environ["ROOTFS"])
kernel_version = os.environ["KERNEL_VERSION"]
agent = Path(os.environ["GUEST_AGENT"])
if not agent.is_file() or agent.is_symlink():
    raise SystemExit("guest identity agent missing or symlinked")

for name in ("bin", "sbin", "dev", "proc", "sys", "tmp", "run", "usr/bin", "etc"):
    (root / name).mkdir(parents=True, exist_ok=True)

for name, major, minor, mode in (
    ("console", 5, 1, 0o600),
    ("null", 1, 3, 0o666),
):
    node = root / "dev" / name
    subprocess.run(
        ["sudo", "mknod", str(node), "c", str(major), str(minor)],
        check=True,
    )
    subprocess.run(["sudo", "chmod", format(mode, "o"), str(node)], check=True)

def copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise SystemExit(f"required initramfs file missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source.resolve(), destination)

def copy_ldd_dependencies(binary: Path) -> None:
    clean_env = os.environ.copy()
    clean_env.pop("LD_LIBRARY_PATH", None)
    result = subprocess.run(
        ["ldd", str(binary)], capture_output=True, text=True, env=clean_env
    )
    output = result.stdout + result.stderr
    if "not found" in output:
        raise SystemExit(f"unresolved shared library for {binary}: {output}")
    for line in output.splitlines():
        match = re.search(r"=>\s+(/[^ ]+)", line)
        if match:
            library = Path(match.group(1))
        else:
            match = re.match(r"\s*(/[^ ]+)\s+\(", line)
            if not match:
                continue
            library = Path(match.group(1))
        if library.exists():
            destination = root / library.relative_to("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(library.resolve(), destination)

python = Path("/usr/bin/python3").resolve()
version = f"{sysconfig.get_python_version()}"
stdlib = Path(f"/usr/lib/python{version}")
if not stdlib.is_dir():
    raise SystemExit(f"system Python standard library missing: {stdlib}")
copy_file(python, root / "usr/bin" / python.name)
(root / "usr/bin/python3").symlink_to(python.name)
shutil.copytree(stdlib, root / stdlib.relative_to("/"), symlinks=True)
copy_ldd_dependencies(python)
for extension in (stdlib / "lib-dynload").glob("*.so"):
    copy_ldd_dependencies(extension)

modules = Path("/lib/modules") / kernel_version
shutil.copytree(modules, root / "lib/modules" / kernel_version, symlinks=True)

modprobe = Path(shutil.which("modprobe") or "/usr/sbin/modprobe").resolve()
copy_file(modprobe, root / "usr/bin/kmod")
(root / "sbin/modprobe").symlink_to("../usr/bin/kmod")
copy_ldd_dependencies(modprobe)

busybox = Path(shutil.which("busybox") or "/bin/busybox").resolve()
copy_file(busybox, root / "bin/busybox")
for applet in ("sh", "mount", "mkdir", "cat", "echo", "sleep", "poweroff", "sync", "dmesg", "ls"):
    link = root / "bin" / applet
    if not link.exists():
        link.symlink_to("busybox")

copy_file(agent, root / "guest_probe.py")
init_script = """#!/bin/sh
set -eu
export PATH=/bin:/sbin:/usr/bin
mkdir -p /proc /sys /dev /run
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
/sbin/modprobe virtio_pci
/sbin/modprobe virtio_blk
/sbin/modprobe virtio_console
exec /usr/bin/python3 /guest_probe.py
"""
init_path = root / "init"
init_path.write_text(init_script, encoding="utf-8")
init_path.chmod(0o755)
(root / "guest_probe.py").chmod(0o755)
PY

(
  cd "$rootfs"
  find . -print0 | cpio --null --create --format=newc --quiet
) | gzip -1 > "$output"
[[ -s "$output" ]] || die 'Generated initramfs is empty'
gzip -t "$output" || die 'Generated initramfs gzip stream is invalid'
printf 'GASLUX_Q4OS_INITRAMFS=PASS\n'
printf 'GASLUX_Q4OS_INITRAMFS_KERNEL=%s\n' "$kernel_version"
printf 'GASLUX_Q4OS_INITRAMFS_BYTES=%s\n' "$(stat -c %s "$output")"
