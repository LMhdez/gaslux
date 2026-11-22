"""Fixed, disposable Linux initramfs guest collector and host-only replay gate.

Not production Observer. Ubuntu APT-signed kernel/static BusyBox at CI runtime;
runner-derived hashes are NOT independently attested guest provenance.
"""

from __future__ import annotations

import gzip
import hashlib
import lzma
import os
import re
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

HEX = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


class CollectorLabDenied(ValueError):
    """Explicit fail-closed test-only protocol error."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise CollectorLabDenied(code)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(65536), b""):
            h.update(block)
    return h.hexdigest()


# Fixed shell code: no eval, arbitrary commands, installation or host disk I/O.
# Deliberately separate fixed test collector from init. The port pathname is
# passed as $1; challenge is two inert fields, never a command.
COLLECTOR = r"""#!/bin/busybox sh
echo GASLUX_COLLECTOR_EXECUTED_TEST >/dev/console
PORT="$1"
set -- $(/bin/busybox sha256sum /collector.sh)
HASH="$1"
BOOT="$(/bin/busybox cat /proc/sys/kernel/random/boot_id)"
echo "GASLUX_COLLECTOR_HASH=$HASH" >/dev/console
echo GASLUX_COLLECTOR_READY_TEST >/dev/console
exec 3<>"$PORT" || exit 73
IFS='|' read -r PREFIX SESSION NONCE <&3 || exit 74
[ "$PREFIX" = "GASLUX_CHAL_V1" ] || exit 75
[ "$(/bin/busybox printf '%s' "$NONCE" | /bin/busybox wc -c)" -eq 64 ] || exit 76
/bin/busybox printf 'GASLUX_REPORT_V1|%s|%s|%s|%s|1\n' "$SESSION" "$NONCE" "$HASH" "$BOOT" >&3
echo GASLUX_COLLECTOR_RESPONSE_SENT_TEST >/dev/console
/bin/busybox sleep 12
/bin/busybox poweroff -f
"""

INIT_HEADER = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys /dev /run
/bin/busybox mount -t proc proc /proc || exit 11
/bin/busybox mount -t sysfs sysfs /sys || exit 12
/bin/busybox mount -t devtmpfs devtmpfs /dev || exit 13
echo GASLUX_GUEST_INIT_EXECUTED_TEST >/dev/console
"""

INIT_END = r"""
/bin/busybox mdev -s >/dev/null 2>&1 || true
i=0
PORT=''
while [ "$i" -lt 150 ]; do
  for name in /sys/class/virtio-ports/*/name; do
    [ -f "$name" ] || continue
    if [ "$(/bin/busybox cat "$name")" = "gaslux.observer" ]; then
      name_dir="$(/bin/busybox dirname "$name")"
      port_name="$(/bin/busybox basename "$name_dir")"
      if [ -c "/dev/$port_name" ]; then PORT="/dev/$port_name"; break; fi
    fi
  done
  [ -n "$PORT" ] && break
  /bin/busybox mdev -s >/dev/null 2>&1 || true
  /bin/busybox sleep 0.1
  i=$((i+1))
done
if [ -z "$PORT" ]; then
  echo GASLUX_GUEST_VIRTIO_PORT_MISSING >/dev/console
  /bin/busybox poweroff -f
  exit 14
fi
exec /bin/busybox sh /collector.sh "$PORT"
"""


def _kernel_modules(version: str, name: str) -> list[Path]:
    result = subprocess.run(
        ["modprobe", "-S", version, "--show-depends", name],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    require(result.returncode == 0, "KERNEL_MODULE_UNAVAILABLE")
    modules = []
    for line in result.stdout.splitlines():
        if line.startswith("insmod "):
            path = Path(line[7:].strip())
            require(path.is_file() and path.is_absolute(), "MODULE_FILE_UNAVAILABLE")
            modules.append(path)
        else:
            require(line.startswith("builtin ") or not line.strip(), "UNSAFE_MODULE_COMMAND")
    return modules


def build_guest(workspace: Path) -> dict:
    """Write only test-owned regular files in a private GitHub runner directory."""
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GASLUX_GUEST_COLLECTOR_LAB") == "1",
        "GITHUB_OWNED_LAB_REQUIRED",
    )
    require(
        workspace.is_dir()
        and not workspace.is_symlink()
        and workspace.stat().st_uid == os.getuid()
        and workspace.stat().st_mode & 0o077 == 0,
        "LAB_WORKSPACE_OWNERSHIP_INVALID",
    )
    versions = sorted(
        p.name.removeprefix("vmlinuz-")
        for p in Path("/boot").glob("vmlinuz-*")
        if (Path("/lib/modules") / p.name.removeprefix("vmlinuz-")).is_dir()
    )
    require(bool(versions), "APT_SIGNED_GUEST_KERNEL_NOT_AVAILABLE")
    version = versions[-1]
    kernel = Path("/boot") / ("vmlinuz-" + version)
    require(kernel.is_file(), "KERNEL_NOT_REGULAR")
    busybox = Path("/bin/busybox")
    require(busybox.is_file(), "BUSYBOX_STATIC_NOT_INSTALLED")
    stage = workspace / "initrd-root"
    require(not stage.exists(), "LAB_INITRD_ALREADY_EXISTS")
    for p in ("bin", "modules", "proc", "sys", "dev", "run"):
        (stage / p).mkdir(parents=True, mode=0o700)
    shutil.copyfile(busybox, stage / "bin" / "busybox")
    (stage / "bin" / "busybox").chmod(0o700)
    collector = stage / "collector.sh"
    collector.write_text(COLLECTOR, encoding="ascii")
    collector.chmod(0o700)
    used = []
    for module in ("virtio_pci", "virtio_console"):
        for src in _kernel_modules(version, module):
            if src in used:
                continue
            destination = stage / "modules" / f"{len(used):03d}.ko"
            if src.suffix == ".zst":
                with destination.open("wb") as out:
                    subprocess.run(
                        ["zstd", "-d", "-c", str(src)],
                        stdout=out,
                        stderr=subprocess.PIPE,
                        check=True,
                        timeout=20,
                    )
            elif src.suffix == ".xz":
                with lzma.open(src, "rb") as inp, destination.open("wb") as out:
                    shutil.copyfileobj(inp, out)
            else:
                require(src.suffix == ".ko", "UNSUPPORTED_MODULE_COMPRESSION")
                shutil.copyfile(src, destination)
            used.append(src)
    loads = "".join(
        f"/bin/busybox insmod /modules/{i:03d}.ko || exit {20+i}\n"
        for i in range(len(used))
    )
    entry = stage / "init"
    entry.write_text(INIT_HEADER + loads + INIT_END, encoding="ascii")
    entry.chmod(0o700)
    cpio = workspace / "initrd.cpio"
    with cpio.open("xb") as output:
        source = subprocess.Popen(
            ["find", ".", "-print0"], cwd=stage, stdout=subprocess.PIPE
        )
        assert source.stdout is not None
        try:
            result = subprocess.run(
                ["cpio", "-0", "-o", "-H", "newc", "--quiet"],
                cwd=stage,
                stdin=source.stdout,
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            require(result.returncode == 0, "CPIO_CREATION_FAILED")
        finally:
            source.stdout.close()
            require(source.wait(timeout=5) == 0, "CPIO_INPUT_FAILED")
    initrd = workspace / "initrd.cpio.gz"
    with cpio.open("rb") as source, initrd.open("xb") as target:
        with gzip.GzipFile(fileobj=target, mode="wb", mtime=0) as out:
            shutil.copyfileobj(source, out)
    package_format = "$" + "{Package}=$" + "{Version}"
    return {
        "kernel": kernel,
        "initrd": initrd,
        "kernelSha256": digest(kernel),
        "initrdSha256": digest(initrd),
        "collectorSha256": digest(collector),
        "kernelVersion": version,
        "kernelPackage": subprocess.check_output(
            ["dpkg-query", "-W", "-f", package_format, "linux-image-" + version],
            text=True,
            timeout=10,
        ).strip(),
        "busyboxPackage": subprocess.check_output(
            ["dpkg-query", "-W", "-f", package_format, "busybox-static"],
            text=True,
            timeout=10,
        ).strip(),
    }


def bounded_line(sock, *, max_bytes: int = 256, timeout: float = 15) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    try:
        for _ in range(max_bytes):
            char = sock.recv(1)
            require(bool(char), "TRANSPORT_DISCONNECT")
            if char == b"\n":
                return bytes(data)
            require(32 <= char[0] <= 126, "REPORT_NOT_ASCII_PRINTABLE")
            data.extend(char)
    except (OSError, TimeoutError) as exc:
        raise CollectorLabDenied("TRANSPORT_INTERRUPTED") from exc
    raise CollectorLabDenied("TRUNCATED_OR_OVERSIZED_RESPONSE")


def validate(payload: bytes, session: str, nonce: str, collector_sha: str) -> dict:
    require(type(payload) is bytes and len(payload) <= 256, "RESPONSE_NOT_BOUNDED")
    try:
        components = payload.decode("ascii").split("|")
    except UnicodeDecodeError as exc:
        raise CollectorLabDenied("RESPONSE_NON_ASCII") from exc
    require(len(components) == 6 and components[0] == "GASLUX_REPORT_V1", "RESPONSE_SCHEMA")
    _, sid, observed_nonce, observed_hash, boot_id, count = components
    require(UID.fullmatch(sid) is not None and sid == session, "WRONG_VM_SESSION")
    require(HEX.fullmatch(observed_nonce) is not None and observed_nonce == nonce, "OLD_NONCE_REPLAY")
    require(
        HEX.fullmatch(observed_hash) is not None and observed_hash == collector_sha,
        "COLLECTOR_HASH_MISMATCH",
    )
    require(UID.fullmatch(boot_id) is not None, "BOOT_ID_INVALID")
    require(count == "1", "SESSION_COUNTER_INVALID")
    return {
        "session": sid,
        "nonce": observed_nonce,
        "collector": observed_hash,
        "bootIdClaimed": boot_id,
        "counter": 1,
    }


class LabLedger:
    """Durable local single-use claims, not externally trusted host resistance."""

    def __init__(self, path: Path):
        require(not path.is_symlink(), "LEDGER_SYMLINK")
        self.db = sqlite3.connect(path, isolation_level=None, timeout=10)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS consumed(nonce TEXT PRIMARY KEY, session TEXT NOT NULL)"
        )

    def consume(self, session: str, nonce: str) -> None:
        require(UID.fullmatch(session) is not None and HEX.fullmatch(nonce) is not None, "INVALID_CHALLENGE")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "INSERT INTO consumed(nonce,session) VALUES (?,?)", (nonce, session)
            )
            self.db.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            self.db.execute("ROLLBACK")
            raise CollectorLabDenied("OLD_NONCE_REPLAY") from exc
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.db.close()


def await_boot(serial: Path, process, marker: str, *, seconds: int = 120) -> bytes:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if process.poll() is not None:
            raise CollectorLabDenied("GUEST_EXITED_BEFORE_COLLECTOR")
        if serial.is_file():
            data = serial.read_bytes()
            require(len(data) <= 1024 * 1024, "SERIAL_LOG_TOO_LARGE")
            if marker.encode() in data:
                require(b"Linux version " in data, "LINUX_KERNEL_BOOT_NOT_OBSERVED")
                require(b"GASLUX_GUEST_INIT_EXECUTED_TEST" in data, "GUEST_INIT_NOT_OBSERVED")
                require(b"GASLUX_COLLECTOR_EXECUTED_TEST" in data, "COLLECTOR_EXECUTION_NOT_OBSERVED")
                return data
        time.sleep(0.15)
    raise CollectorLabDenied("GUEST_BOOT_TIMEOUT")
