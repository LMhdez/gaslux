"""Disposable QEMU Linux guest collector: diagnostic only, no guest commands API.

Reuses dev HOST/FD ProcessSeal, QemuLocalDiskWitness and LocalTransportWitness.
The HOST owns the kernel, initramfs, keys and replay ledger: NOT_ATTESTED.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import os
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .guest_transport_peer_boundary import LocalSessionPins, LocalTransportWitness
from .host_fd_boundary import process_seal
from .qemu_local_disk_witness import QemuDiskPins, QemuLocalDiskWitness

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_MAX_FRAME = 512
_TIMEOUT = 75


class GuestCollectorRefused(ValueError):
    """A failed local proof cannot be promoted to guest attestation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(ok: bool, code: str) -> None:
    if not ok:
        raise GuestCollectorRefused(code)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def uuid_ok(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


class LabNonceLedger:
    """SQLite FULL-sync one-use challenges in a private, same-runner workspace."""

    def __init__(self, path: Path, *, existing: bool = False):
        require(path.is_absolute() and not path.is_symlink(), "LEDGER_PATH_UNSAFE")
        require(
            path.parent.is_dir() and path.parent.stat().st_mode & 0o077 == 0, "LEDGER_PARENT_UNSAFE"
        )
        if existing:
            identity = os.lstat(path)
            require(
                stat.S_ISREG(identity.st_mode)
                and identity.st_nlink == 1
                and identity.st_uid == os.getuid()
                and identity.st_mode & 0o077 == 0,
                "LEDGER_FILE_UNSAFE",
            )
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=DELETE")
        if not existing:
            self.db.execute(
                "CREATE TABLE challenge (nonce TEXT PRIMARY KEY, session TEXT NOT NULL, "
                "state TEXT NOT NULL CHECK(state IN ('issued','used')))"
            )

    def issue(self, nonce: str, session: str) -> None:
        require(
            isinstance(nonce, str) and bool(_HEX64.fullmatch(nonce)) and uuid_ok(session),
            "INVALID_CHALLENGE",
        )
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("INSERT INTO challenge VALUES (?, ?, 'issued')", (nonce, session))
            self.db.commit()
        except sqlite3.IntegrityError as exc:
            self.db.rollback()
            raise GuestCollectorRefused("OLD_NONCE_REPLAY") from exc

    def consume(self, nonce: str, session: str) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        cur = self.db.execute(
            "UPDATE challenge SET state='used' WHERE nonce=? AND session=? AND state='issued'",
            (nonce, session),
        )
        if cur.rowcount != 1:
            self.db.rollback()
            raise GuestCollectorRefused("OLD_NONCE_REPLAY")
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def expected_context(collector_sha: str) -> dict:
    require(bool(_HEX64.fullmatch(collector_sha)), "COLLECTOR_HASH_MISMATCH")
    return {
        "nonce": secrets.token_hex(32),
        "session": str(uuid.uuid4()),
        "transaction": str(uuid.uuid4()),
        "vm": secrets.token_hex(8),
        "sequence": 1,
        "collector": collector_sha,
    }


def challenge_line(context: dict) -> bytes:
    require(
        context["sequence"] == 1 and bool(_HEX64.fullmatch(context["nonce"])), "INVALID_CHALLENGE"
    )
    value = (
        " ".join(
            [
                "GCL1",
                context["nonce"],
                context["session"],
                context["transaction"],
                context["vm"],
                str(context["sequence"]),
                context["collector"],
            ]
        )
        + "\n"
    )
    require(len(value.encode("ascii")) <= _MAX_FRAME, "INVALID_CHALLENGE")
    return value.encode("ascii")


def response_line(raw: bytes, expected: dict) -> dict:
    require(
        isinstance(raw, bytes) and 1 <= len(raw) <= _MAX_FRAME and raw.endswith(b"\n"),
        "TRUNCATED_RESPONSE",
    )
    try:
        fields = raw.decode("ascii").strip().split()
    except UnicodeDecodeError as exc:
        raise GuestCollectorRefused("FORGED_GUEST_CLAIMS") from exc
    require(len(fields) == 8 and fields[0] == "GCR1", "FORGED_GUEST_CLAIMS")
    _, nonce, session, transaction, vm, seq, collector, boot_id = fields
    require(bool(_HEX64.fullmatch(nonce)) and nonce == expected["nonce"], "OLD_NONCE_REPLAY")
    require(
        session == expected["session"]
        and transaction == expected["transaction"]
        and vm == expected["vm"],
        "WRONG_VM_SESSION",
    )
    require(seq == str(expected["sequence"]), "FORGED_GUEST_CLAIMS")
    require(
        bool(_HEX64.fullmatch(collector)) and collector == expected["collector"],
        "COLLECTOR_HASH_MISMATCH",
    )
    require(uuid_ok(boot_id), "FORGED_GUEST_CLAIMS")
    return {
        "bootId": boot_id,
        "collectorSha256": collector,
        "sessionId": session,
        "nonce": nonce,
        "sequence": 1,
    }


def bound_host(host: dict, peer: dict, qemu_pid: int, disk_inode: int) -> None:
    require(
        host["process"]["pid"]["value"] == qemu_pid and peer["peer"]["pid"] == qemu_pid,
        "WRONG_QEMU_PROCESS",
    )
    require(
        host["disk"]["inode"]["value"] == disk_inode
        and host["localQemuReadonlyDiskFdOpenProven"] is True,
        "WRONG_DISK_FD",
    )
    require(
        peer["localKernelPeerObserved"] is True
        and peer["localKernelPeerMatchesSuppliedPins"] is True,
        "HOST_PROXY_SPOOF",
    )
    require(host["status"] == peer["status"] == "BLOCKED_TRUST_ROOT", "FORGED_GUEST_CLAIMS")


def read_line(sock: socket.socket) -> bytes:
    data = bytearray()
    try:
        while len(data) <= _MAX_FRAME:
            chunk = sock.recv(1)
            require(bool(chunk), "TRANSPORT_DISCONNECT")
            data.extend(chunk)
            if chunk == b"\n":
                return bytes(data)
    except (OSError, TimeoutError) as exc:
        raise GuestCollectorRefused("TRANSPORT_DISCONNECT") from exc
    raise GuestCollectorRefused("TRUNCATED_RESPONSE")


def wait_file(path: Path, child: subprocess.Popen, *, contains: str | None = None) -> None:
    end = time.monotonic() + _TIMEOUT
    while time.monotonic() < end:
        require(child.poll() is None, "GUEST_PROCESS_EXITED")
        if path.exists() and (contains is None or contains in path.read_text(errors="replace")):
            return
        time.sleep(0.1)
    raise GuestCollectorRefused("GUEST_BOOT_OR_CHANNEL_TIMEOUT")


def module_bytes(path: Path) -> bytes:
    if path.suffix == ".zst":
        return subprocess.check_output(["zstd", "-dc", str(path)], timeout=15)
    if path.suffix == ".xz":
        return lzma.decompress(path.read_bytes())
    if path.suffix == ".gz":
        import gzip

        return gzip.decompress(path.read_bytes())
    return path.read_bytes()


_INIT = """#!/bin/sh
mount -t devtmpfs devtmpfs /dev || exit 11
mount -t proc proc /proc || exit 12
mount -t sysfs sysfs /sys || exit 13
for module in /modules/*.ko; do
    [ -f "$module" ] && insmod "$module" || true
done
i=0
while [ ! -e /dev/virtio-ports/gaslux.observer ]; do
    i=$((i+1))
    [ "$i" -le 25 ] || exit 14
    sleep 1
done
echo "GASLUX_GUEST_BOOT_READY $(cat /proc/sys/kernel/random/boot_id)" > /dev/ttyS0
exec /bin/sh /collector
"""


def make_ramfs(workspace: Path, collector: Path, kernel: Path) -> tuple[Path, dict]:
    require(workspace.is_dir() and workspace.stat().st_mode & 0o077 == 0, "WORKSPACE_UNSAFE")
    release = kernel.name.removeprefix("vmlinuz-")
    require(kernel.is_file() and release != kernel.name, "GUEST_KERNEL_UNAVAILABLE")
    config = Path("/boot") / ("config-" + release)
    require(config.is_file(), "GUEST_KERNEL_CONFIG_MISSING")
    configuration = config.read_text()
    require(
        "CONFIG_VIRTIO_CONSOLE=y" in configuration or "CONFIG_VIRTIO_CONSOLE=m" in configuration,
        "GUEST_VIRTIO_CONSOLE_UNAVAILABLE",
    )
    busybox = Path("/bin/busybox")
    require(busybox.is_file(), "GUEST_STATIC_BUSYBOX_MISSING")
    stage = workspace / "ramfs"
    (stage / "bin").mkdir(parents=True, mode=0o700)
    (stage / "modules").mkdir(mode=0o700)
    for mountpoint in ("dev", "proc", "sys"):
        (stage / mountpoint).mkdir(mode=0o700)
    shutil.copyfile(busybox, stage / "bin" / "busybox")
    (stage / "bin" / "busybox").chmod(0o755)
    (stage / "bin" / "sh").symlink_to("busybox")
    (stage / "bin" / "cat").symlink_to("busybox")
    (stage / "bin" / "sha256sum").symlink_to("busybox")
    (stage / "bin" / "sleep").symlink_to("busybox")
    (stage / "bin" / "insmod").symlink_to("busybox")
    (stage / "bin" / "mount").symlink_to("busybox")
    shutil.copyfile(collector, stage / "collector")
    (stage / "collector").chmod(0o755)
    (stage / "init").write_text(_INIT, encoding="ascii")
    (stage / "init").chmod(0o755)
    module_paths = []
    if "CONFIG_VIRTIO_CONSOLE=m" in configuration:
        depends = subprocess.check_output(
            ["modprobe", "-D", "-S", release, "virtio_console"], text=True, timeout=15
        )
        for line in depends.splitlines():
            if line.startswith("insmod "):
                module_paths.append(Path(line.split()[1]))
        require(bool(module_paths), "GUEST_VIRTIO_MODULE_UNAVAILABLE")
        for i, path in enumerate(module_paths):
            (stage / "modules" / f"{i:03d}.ko").write_bytes(module_bytes(path))
    names = sorted(str(p.relative_to(stage)) for p in stage.rglob("*"))
    archive = subprocess.run(
        ["cpio", "--quiet", "-o", "-H", "newc"],
        input=("\n".join(names) + "\n").encode(),
        cwd=stage,
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    result = workspace / "guest-initrd.cpio"
    result.write_bytes(archive)
    return result, {
        "kernelRelease": release,
        "kernelSha256": sha(kernel),
        "initrdSha256": sha(result),
        "collectorSha256": sha(collector),
        "moduleCount": len(module_paths),
        "guestImagePackage": subprocess.check_output(
            ["dpkg-query", "-S", str(Path("/boot") / kernel.name)], text=True
        ).strip(),
    }


def run_lab(workspace: Path, kernel: Path, collector: Path, output: Path) -> dict:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "UNAUTHORIZED_LAB",
    )
    require(
        workspace.resolve(strict=True) == workspace and workspace.stat().st_mode & 0o077 == 0,
        "WORKSPACE_UNSAFE",
    )
    initrd, image = make_ramfs(workspace, collector, kernel)
    disk = workspace / "scratch.raw"
    subprocess.run(
        ["qemu-img", "create", "-f", "raw", str(disk), "64M"],
        check=True,
        capture_output=True,
        timeout=15,
    )
    disk.chmod(0o600)
    require(
        disk.stat().st_nlink == 1 and disk.stat().st_size == 64 * 1024 * 1024, "DISK_FILE_UNSAFE"
    )
    initial_hash = sha(disk)
    qmp = workspace / "qmp.sock"
    endpoint = workspace / "guest-peer.sock"
    serial = workspace / "guest-serial.log"
    args = [
        "/usr/bin/qemu-system-x86_64",
        "-machine",
        "q35,accel=tcg",
        "-m",
        "384",
        "-smp",
        "1",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-nic",
        "none",
        "-serial",
        f"file:{serial}",
        "-qmp",
        f"unix:{qmp},server=on,wait=off",
        "-drive",
        f"file={disk},format=raw,if=none,id=disk0,readonly=on",
        "-device",
        "virtio-blk-pci,drive=disk0",
        "-chardev",
        f"socket,id=gp0,path={endpoint},server=on,wait=off",
        "-device",
        "virtio-serial-pci",
        "-device",
        "virtserialport,chardev=gp0,name=gaslux.observer",
        "-kernel",
        str(kernel),
        "-initrd",
        str(initrd),
        "-append",
        "console=ttyS0 rdinit=/init panic=1 loglevel=4",
    ]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=workspace,
        start_new_session=True,
    )
    context = expected_context(image["collectorSha256"])
    ledger = LabNonceLedger(workspace / "nonce-ledger.sqlite")
    try:
        wait_file(qmp, proc)
        wait_file(endpoint, proc)
        wait_file(serial, proc, contains="GASLUX_GUEST_BOOT_READY")
        st = disk.stat()
        qemu = QemuDiskPins(
            process=process_seal(proc.pid),
            media_path=disk,
            workspace=workspace,
            qmp_socket=qmp,
            media_dev=st.st_dev,
            media_inode=st.st_ino,
            media_size=st.st_size,
            disk_format="raw",
            qmp_device="disk0",
            transaction_id=context["transaction"],
            vm_label=context["vm"],
        )
        with QemuLocalDiskWitness(qemu) as witness:
            host = witness.finish()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(12)
                conn.connect(str(endpoint))
                socket_stat = os.fstat(conn.fileno())
                pins = LocalSessionPins(
                    process=qemu.process,
                    transport_dev=socket_stat.st_dev,
                    transport_inode=socket_stat.st_ino,
                    session_id=context["session"],
                    transaction_id=context["transaction"],
                    host_vm_id=context["vm"],
                    disk_identity_sha256=initial_hash,
                    collector_sha256=context["collector"],
                    challenge=context["nonce"],
                )
                peer = LocalTransportWitness(conn, pins).finish(
                    {
                        "sessionId": pins.session_id,
                        "transactionId": pins.transaction_id,
                        "hostVmId": pins.host_vm_id,
                        "diskIdentitySha256": pins.disk_identity_sha256,
                        "collectorSha256": pins.collector_sha256,
                        "challenge": pins.challenge,
                        "provenance": "CLAIMED",
                    }
                )
                bound_host(host, peer, proc.pid, st.st_ino)
                ledger.issue(context["nonce"], context["session"])
                conn.sendall(challenge_line(context))
                response = response_line(read_line(conn), context)
                ledger.consume(context["nonce"], context["session"])
            boot = serial.read_text(errors="replace")
            require(
                f"GASLUX_COLLECTOR_EXECUTED {response['bootId']}" in boot,
                "GUEST_BOOT_WITNESS_MISSING",
            )
            require(
                f"GASLUX_GUEST_BOOT_READY {response['bootId']}" in boot,
                "GUEST_BOOT_WITNESS_MISSING",
            )
            result = {
                "schema": "gaslux-guest-collector-origin-lab-v1",
                "status": "BLOCKED_TRUST_ROOT",
                "classification": "NOT_INDEPENDENT",
                "safetyAssessment": "DIAGNOSTIC_ONLY",
                "guestOrigin": "NOT_ATTESTED",
                "guestCollectorExecutedObserved": True,
                "guestMessageReceived": True,
                "guestBooted": True,
                "hostQemuPeerAuthenticated": True,
                "guestOriginIndependentlyAttested": False,
                "guestChannelAuthenticated": False,
                "replayProtectedWithinLab": True,
                "replayProtectedAgainstCompromisedHost": False,
                "inputAuthorized": False,
                "diskWritesAuthorized": False,
                "productionInstallationAuthorized": False,
                "qemuPid": proc.pid,
                "qemuStartTicks": qemu.process.start_ticks,
                "diskDev": st.st_dev,
                "diskInode": st.st_ino,
                "diskSha256Before": initial_hash,
                "bootId": response["bootId"],
                "sessionId": context["session"],
                "transactionId": context["transaction"],
                "challengeSha256": hashlib.sha256(context["nonce"].encode()).hexdigest(),
                "guestImage": image,
                "observerPeerPid": peer["peer"]["pid"],
                "collectorResponseSha256": hashlib.sha256(
                    ("|".join(str(v) for v in response.values())).encode()
                ).hexdigest(),
            }
            proc.terminate()
            proc.communicate(timeout=15)
            require(proc.poll() is not None, "QEMU_NOT_REAPED")
            witness.assert_stopped()
            require(sha(disk) == initial_hash, "TEST_DISK_CHANGED")
            result["qemuReaped"] = True
            result["diskSha256After"] = sha(disk)
            output.mkdir(mode=0o700, exist_ok=False)
            payload = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
            require(len(payload) < 4096, "EVIDENCE_TOO_LARGE")
            (output / "manifest.json").write_bytes(payload)
            (output / "manifest.sha256").write_text(
                hashlib.sha256(payload).hexdigest() + "  manifest.json\n", encoding="ascii"
            )
            return result
    finally:
        ledger.close()
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=10)


if __name__ == "__main__":
    workspace = Path(tempfile.mkdtemp(prefix="gaslux-real-guest-", dir=os.environ["RUNNER_TEMP"]))
    workspace.chmod(0o700)
    result = run_lab(
        workspace,
        Path(os.environ["GASLUX_GUEST_KERNEL"]),
        Path(os.environ["GASLUX_GUEST_COLLECTOR"]).resolve(strict=True),
        Path(os.environ["RUNNER_TEMP"]) / "gaslux-real-guest-evidence",
    )
    print("GASLUX_GUEST_BOOT_TRANSPORT_DIAGNOSTIC " + json.dumps(result, sort_keys=True))
