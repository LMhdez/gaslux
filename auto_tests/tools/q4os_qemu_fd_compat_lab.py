#!/usr/bin/env python3
"""Independent disposable QEMU FD laboratory. Never imports operational QMP.

The guest is permanently stopped (-S), QMP is limited to read-only queries,
and all drive files are freshly created within one private runner directory.
This is evidence about QEMU FD reopening, not Windows/native installation.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

QEMU = "/usr/bin/qemu-system-x86_64"
QEMU_IMG = "/usr/bin/qemu-img"
SIZE = 64 * 1024 * 1024
ALLOWED_QMP = frozenset({"qmp_capabilities", "query-status", "query-block", "query-fdsets"})


class LabRefusal(RuntimeError):
    """Fixed machine-readable refusal; never contains a path or stderr."""


def require(value: bool, reason: str) -> None:
    if not value:
        raise LabRefusal(reason)


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    size = os.fstat(fd).st_size
    for pos in range(0, size, 1024 * 1024):
        digest.update(os.pread(fd, min(1024 * 1024, size - pos), pos))
    return digest.hexdigest()


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()


def pinned(path: Path, writable: bool) -> int:
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    fd_stat, path_stat = os.fstat(fd), path.lstat()
    require(
        stat.S_ISREG(fd_stat.st_mode)
        and fd_stat.st_uid == os.getuid()
        and fd_stat.st_nlink == 1
        and (fd_stat.st_dev, fd_stat.st_ino) == (path_stat.st_dev, path_stat.st_ino),
        "FILE_PROVENANCE_INVALID",
    )
    return fd


def birth(pid: int) -> tuple[int, int]:
    rest = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(rest[19]), int(rest[2])  # start ticks (22), process group (5)


def assert_pidfd(pidfd: int, pid: int, original_birth: tuple[int, int]) -> None:
    require(os.readlink(f"/proc/self/fd/{pidfd}") == "anon_inode:[pidfd]", "PIDFD_TYPE")
    info = Path(f"/proc/self/fdinfo/{pidfd}").read_text()
    target = next(
        (line.split(":", 1)[1].strip() for line in info.splitlines() if line.startswith("Pid:")), ""
    )
    require(target == str(pid), "PIDFD_FOREIGN")
    require(birth(pid) == original_birth, "PROCESS_BIRTH_CHANGED")
    poll = select.poll()
    poll.register(pidfd, select.POLLIN)
    require(not poll.poll(0), "PROCESS_EXITED")


def group_members(pgid: int) -> list[int]:
    result = []
    for item in Path("/proc").iterdir():
        if not item.name.isdecimal():
            continue
        try:
            if birth(int(item.name))[1] == pgid:
                result.append(int(item.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return result


def close_process(
    child: subprocess.Popen | None, pidfd: int | None, start: tuple[int, int] | None
) -> dict:
    evidence = {"directReaped": child is None, "descendantsAbsent": child is None}
    try:
        if child is not None:
            if child.poll() is None:
                require(pidfd is not None and start is not None, "CLEANUP_NO_PIDFD")
                assert_pidfd(pidfd, child.pid, start)
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                require(pidfd is not None and start is not None, "CLEANUP_NO_PIDFD")
                assert_pidfd(pidfd, child.pid, start)
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                child.wait(timeout=4)
            evidence["directReaped"] = child.poll() is not None
            evidence["exitCode"] = child.returncode
            pgid = start[1] if start else -1
            evidence["descendantsAbsent"] = pgid > 0 and not group_members(pgid)
    finally:
        if pidfd is not None:
            os.close(pidfd)
    return evidence


def qmp_readonly(
    child: subprocess.Popen,
    path: Path,
    original_birth: tuple[int, int],
    pidfd: int,
    *,
    use_supervisor: bool = False,
) -> tuple[dict, object]:
    deadline = time.monotonic() + 12
    while not path.exists() and time.monotonic() < deadline:
        require(child.poll() is None, "QEMU_EARLY_EXIT")
        time.sleep(0.04)
    require(path.exists(), "QMP_SOCKET_TIMEOUT")
    observed = path.lstat()
    require(
        stat.S_ISSOCK(observed.st_mode) and observed.st_uid == os.getuid(), "QMP_SOCKET_UNTRUSTED"
    )
    # The shared path uses the *real* production connect-only Qmp transport.
    # Its operational negotiate_protocol/command methods remain unavailable:
    # no _BoundQmpSession can be issued while the global gate is false.
    operational = None
    transport = None
    if use_supervisor:
        import q4os_win10_qmp_supervisor as operational
        from q4os_win10_qmp_boot import Qmp

        require(not operational.QEMU_FD_BACKING_VERIFIED, "PRODUCTION_GATE_OPEN")
        require(operational._birth_identity(child.pid)[1] == original_birth[0], "BIRTH_MISMATCH")
        transport = Qmp(path, negotiate=False)
        channel = transport.socket
        stream = transport.stream
    else:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.settimeout(4)
        stream = None
    try:
        if transport is None:
            channel.connect(str(path))
        if operational is not None:
            operational._witness(child, pidfd)
            operational._peer(transport, child)
            require(
                operational._socket_identity(path, path.parent)
                == (observed.st_dev, observed.st_ino),
                "QMP_SOCKET_REPLACED",
            )
        peer = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer[0] == child.pid and peer[1] == os.getuid(), "QMP_PEER_FOREIGN")
        current = path.lstat()
        require(
            (current.st_dev, current.st_ino) == (observed.st_dev, observed.st_ino),
            "QMP_SOCKET_REPLACED",
        )
        if stream is None:
            stream = channel.makefile("rb")

        def line() -> dict:
            value = json.loads(stream.readline(65536))
            require(isinstance(value, dict), "QMP_INVALID_JSON")
            return value

        greeting = line()
        require(isinstance(greeting.get("QMP"), dict), "QMP_GREETING_INVALID")
        transcript: dict = {
            "peerPidBound": True,
            "queries": [],
            "greetingVerified": True,
            "supervisorConnectOnlyVerified": operational is not None,
            "supervisorPeerVerified": operational is not None,
            "sharedAuthorityIssued": False,
        }

        def command(name: str) -> dict:
            require(name in ALLOWED_QMP, "QMP_COMMAND_FORBIDDEN")
            assert_pidfd(pidfd, child.pid, original_birth)
            if operational is not None:
                # Exactly the same process, PID, pidfd and local QMP-peer
                # witnesses used by the operational supervisor, but no
                # session issuance, guest commands, or production authority.
                operational._witness(child, pidfd)
                require(
                    operational._birth_identity(child.pid)[1] == original_birth[0],
                    "BIRTH_MISMATCH",
                )
                operational._peer(transport, child)
                require(
                    operational._socket_identity(path, path.parent)
                    == (observed.st_dev, observed.st_ino),
                    "QMP_SOCKET_REPLACED",
                )
                transcript["sharedWitnessChecks"] = transcript.get("sharedWitnessChecks", 0) + 1
            now = path.lstat()
            require(
                (now.st_dev, now.st_ino) == (observed.st_dev, observed.st_ino),
                "QMP_SOCKET_REPLACED",
            )
            channel.sendall(json.dumps({"execute": name, "id": name}).encode() + b"\n")
            transcript["queries"].append(name)
            for _ in range(6):
                answer = line()
                if answer.get("id") == name:
                    require("return" in answer and "error" not in answer, "QMP_QUERY_REJECTED")
                    return answer["return"]
            raise LabRefusal("QMP_UNEXPECTED_REPLY")

        command("qmp_capabilities")
        status = command("query-status")
        require(status.get("running") is False, "GUEST_NOT_PAUSED")
        blocks = command("query-block")
        require(isinstance(blocks, list) and len(blocks) >= 2, "BLOCK_GRAPH_MISSING")
        transcript["paused"] = True
        transcript["visibleBlockDevices"] = len(blocks)
        try:
            sets = command("query-fdsets")
            transcript["fdSetsVisible"] = len(sets) if isinstance(sets, list) else 0
        except LabRefusal as exc:
            if str(exc) != "QMP_QUERY_REJECTED":
                raise
            transcript["fdSetsVisible"] = None
        return transcript, transport if transport is not None else channel
    except Exception:
        if transport is not None:
            transport.close()
        else:
            channel.close()
        raise


def fd_inventory(pid: int, roles: dict[str, int]) -> dict[str, int]:
    targets = {name: (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for name, fd in roles.items()}
    matched = {name: 0 for name in roles}
    for item in Path(f"/proc/{pid}/fd").iterdir():
        try:
            observed = item.stat()
        except (OSError, ValueError):
            continue
        for name, identity in targets.items():
            if (observed.st_dev, observed.st_ino) == identity:
                matched[name] += 1
    require(all(matched.values()), "QEMU_FD_NOT_OWNED")
    return matched


def firmware_pair() -> tuple[Path, Path]:
    for suffix in ("_4M", ""):
        code = Path(f"/usr/share/OVMF/OVMF_CODE{suffix}.fd")
        vars_path = Path(f"/usr/share/OVMF/OVMF_VARS{suffix}.fd")
        if code.is_file() and vars_path.is_file():
            return code, vars_path
    raise LabRefusal("OVMF_PAIR_NOT_FOUND")


def verify_qcow2_contract(info: dict) -> None:
    """Require the expected owned backing-free image geometry before spawn."""
    require(
        info.get("format") == "qcow2"
        and info.get("virtual-size") == SIZE
        and info.get("cluster-size") == 65536
        and not info.get("backing-filename")
        and not info.get("full-backing-filename"),
        "QCOW2_GEOMETRY_OR_BACKING_INVALID",
    )


def make_resources(work: Path) -> tuple[dict[str, Path], dict]:
    code_src, vars_src = firmware_pair()
    paths = {name: work / name for name in ("code.fd", "vars.fd", "disk.qcow2", "synthetic.iso")}
    shutil.copyfile(code_src, paths["code.fd"])
    shutil.copyfile(vars_src, paths["vars.fd"])
    paths["synthetic.iso"].write_bytes(b"GASLUX_SYNTHETIC_NOT_BOOTABLE" + b"\0" * 4096)
    subprocess.run(
        [QEMU_IMG, "create", "-f", "qcow2", str(paths["disk.qcow2"]), "64M"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
    )
    info = json.loads(
        subprocess.check_output(
            [QEMU_IMG, "info", "--output=json", str(paths["disk.qcow2"])], timeout=15
        )
    )
    verify_qcow2_contract(info)
    for path in paths.values():
        path.chmod(0o600)
    meta = {
        "virtualBytes": info["virtual-size"],
        "clusterBytes": info.get("cluster-size"),
        "format": "qcow2",
        "backingPresent": False,
        "resources": {
            name: {"bytes": path.stat().st_size, "sha256": sha256(path)}
            for name, path in paths.items()
        },
    }
    return paths, meta


def args_for(
    mode: str,
    sock: Path,
    fds: dict[str, int],
    readonly_fds: dict[str, int],
    paths: dict[str, Path],
) -> list[str]:
    if mode in ("pr_argv", "pr_shared"):
        # Reuse the REAL PR #318 argument builder, never operational run_lab.
        # Production gate stays false; ONLY the independent stopped-guest
        # laboratory is allowed to launch a process.
        import q4os_win10_qmp_supervisor as operational

        require(operational.QEMU_FD_BACKING_VERIFIED is False, "PRODUCTION_GATE_CHANGED")
        require(operational.QEMU == QEMU, "QEMU_EXECUTABLE_CHANGED")
        mapped = {
            "code": fds["code.fd"],
            "vars": fds["vars.fd"],
            "image": fds["disk.qcow2"],
            "iso": fds["synthetic.iso"],
            "answer": fds["answer.iso"],
        }
        args = operational._qemu_args(
            sock.parent,
            paths["code.fd"],
            paths["vars.fd"],
            paths["disk.qcow2"],
            paths["synthetic.iso"],
            paths["answer.iso"],
            "tcg",
            mapped,
        )
        require(args[args.index("-qmp") + 1].startswith(f"unix:{sock},"), "PR_QMP_SOCKET_MISMATCH")
        # Mandatory experiment-only changes: never execute firmware or an
        # installer; reduce CPU/RAM demand of the CI ephemeral runner.
        require("-S" not in args, "PR_ARGV_ALREADY_PAUSED")
        args += ["-S", "-no-reboot"]
        args[args.index("-m") + 1] = "128"
        args[args.index("-smp") + 1] = "1"
        return args
    args = [
        QEMU,
        "-machine",
        "q35",
        "-accel",
        "tcg",
        "-cpu",
        "max",
        "-smp",
        "1",
        "-m",
        "128",
        "-S",
        "-nodefaults",
        "-no-reboot",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-net",
        "none",
        "-qmp",
        f"unix:{sock},server=on,wait=off",
    ]
    backing = {}
    for index, (name, fd) in enumerate(fds.items(), start=1):
        if mode == "fdset" or (mode == "hybrid" and name in ("disk.qcow2", "synthetic.iso")):
            args += ["-add-fd", f"fd={fd},set={index},opaque={name}-native"]
            if name in readonly_fds:
                args += [
                    "-add-fd",
                    f"fd={readonly_fds[name]},set={index},opaque={name}-readonly",
                ]
            backing[name] = f"/dev/fdset/{index}"
        else:
            backing[name] = f"/proc/self/fd/{fd}"
    args += [
        "-drive",
        f"if=pflash,format=raw,unit=0,readonly=on,file={backing['code.fd']}",
        "-drive",
        f"if=pflash,format=raw,unit=1,file={backing['vars.fd']}",
        "-device",
        "ich9-ahci,id=sata",
        "-drive",
        f"if=none,id=system,format=qcow2,file={backing['disk.qcow2']}",
        "-device",
        "ide-hd,drive=system,bus=sata.0",
        "-drive",
        f"if=none,id=install,format=raw,media=cdrom,readonly=on,file={backing['synthetic.iso']}",
        "-device",
        "ide-cd,drive=install,bus=sata.1",
    ]
    return args


def verify_public_deny(work: Path, paths: dict[str, Path]) -> dict:
    """No public run_lab process, media write, or factory side effect."""
    import q4os_win10_qmp_supervisor as operational

    require(not operational.QEMU_FD_BACKING_VERIFIED, "PRODUCTION_GATE_OPEN")
    before = {name: sha256(path) for name, path in paths.items()}
    called = []

    def forbidden_factory(*_args, **_kwargs):
        called.append(True)
        raise LabRefusal("UNAUTHORIZED_FACTORY_CALLED")

    scenarios = ({}, {"popen_factory": forbidden_factory}, {"pidfd_factory": forbidden_factory})
    for injection in scenarios:
        result = operational.run_lab(
            work,
            paths["code.fd"],
            paths["vars.fd"],
            paths["disk.qcow2"],
            paths["synthetic.iso"],
            paths["answer.iso"],
            "tcg",
            **injection,
        )
        require(
            result["decision"] == "refuse"
            and result["qemuSpawned"] is False
            and result["qmpSendKeyAcknowledged"] is False
            and result["diskWritesAuthorized"] is False
            and result["installationAuthorized"] is False,
            "PUBLIC_GATE_NOT_DENIED",
        )
    require(not called, "UNAUTHORIZED_FACTORY_CALLED")
    require(
        all(sha256(paths[name]) == digest for name, digest in before.items()),
        "PUBLIC_GATE_MUTATED_MEDIA",
    )
    require(not (work / "windows10-qemu-process.log").exists(), "PUBLIC_GATE_CREATED_LOG")
    return {"verified": True, "rejectedCalls": 3, "factoryInvoked": False}


def verify_foreign_qmp_peer(work: Path, child: subprocess.Popen) -> dict:
    """A foreign same-UID UNIX peer must receive no QMP commands."""
    import q4os_win10_qmp_supervisor as operational
    from q4os_win10_qmp_boot import Qmp

    path = work / "foreign-peer.sock"
    transcript = work / "foreign-qmp-bytes.bin"
    script = """
import socket,sys
from pathlib import Path
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(sys.argv[1]); server.listen(1); server.settimeout(4)
data=b''
try:
    client,_=server.accept()
    client.settimeout(2)
    try: data=client.recv(4096)
    except (socket.timeout,OSError): pass
    client.close()
except socket.timeout: pass
Path(sys.argv[2]).write_bytes(data)
server.close()
"""
    peer = subprocess.Popen(
        [sys.executable, "-u", "-c", script, str(path), str(transcript)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    peer_fd = None
    peer_birth = None
    rejected = False
    try:
        peer_birth = birth(peer.pid)
        peer_fd = os.pidfd_open(peer.pid)
        deadline = time.monotonic() + 4
        while not path.exists() and time.monotonic() < deadline:
            require(peer.poll() is None, "FOREIGN_QMP_EARLY_EXIT")
            time.sleep(0.01)
        require(path.exists(), "FOREIGN_QMP_NOT_READY")
        transport = Qmp(path, negotiate=False)
        try:
            try:
                operational._peer(transport, child)
            except operational.StartupRefusal:
                rejected = True
            else:
                raise LabRefusal("FOREIGN_QMP_PEER_ACCEPTED")
        finally:
            transport.close()
    finally:
        cleanup = close_process(peer, peer_fd, peer_birth)
    require(cleanup["directReaped"] and cleanup["descendantsAbsent"], "FOREIGN_PEER_CLEANUP")
    require(rejected and transcript.read_bytes() == b"", "FOREIGN_QMP_COMMAND_SENT")
    return {"foreignPeerRejected": True, "zeroQmpBytes": True, "ownPeerReaped": True}


def scenario(root: Path, mode: str, rename: bool) -> dict:
    work = root / mode
    work.mkdir(mode=0o700)
    paths, geometry = make_resources(work)
    if mode in ("pr_argv", "pr_shared"):
        answer = work / "answer.iso"
        answer.write_bytes(b"GASLUX_SYNTHETIC_ANSWER_NOT_BOOTABLE" + bytes(512))
        answer.chmod(0o600)
        paths["answer.iso"] = answer
        geometry["resources"]["answer.iso"] = {
            "bytes": answer.stat().st_size,
            "sha256": sha256(answer),
        }
    qmp_path = work / (
        "q4os-win10-qmp.sock" if mode in ("pr_argv", "pr_shared") else "qmp.sock"
    )
    fds = {}
    readonly_fds = {}
    child = None
    pidfd = None
    start = None
    channel = None
    stale_pidfd = None
    report: dict = {
        "mode": mode,
        "renameAfterPin": rename,
        "geometry": geometry,
        "success": False,
        "qemuBooted": False,
    }
    stderr = work / "private-qemu-stderr.log"
    try:
        if mode == "pr_shared":
            report["publicGate"] = verify_public_deny(work, paths)
            report["publicGateRefused"] = report["publicGate"]["verified"]
        for name, path in paths.items():
            fds[name] = pinned(path, name in ("vars.fd", "disk.qcow2"))
        # QEMU fdsets select descriptors by requested access mode. Supply
        # read-only AND read-write handles for mutable media (QEMU docs).
        # Never turn O_RDWR into O_RDONLY with dup(): it shares access flags.
        if mode in ("fdset", "hybrid"):
            for name in ("vars.fd", "disk.qcow2"):
                readonly_fds[name] = pinned(paths[name], False)
                require(
                    (os.fstat(readonly_fds[name]).st_dev, os.fstat(readonly_fds[name]).st_ino)
                    == (os.fstat(fds[name]).st_dev, os.fstat(fds[name]).st_ino),
                    "ACCESS_MODE_FD_INODE_MISMATCH",
                )
        original = {
            name: (os.fstat(fd).st_dev, os.fstat(fd).st_ino, sha256_fd(fd))
            for name, fd in fds.items()
        }
        if rename:
            disk = paths["disk.qcow2"]
            disk.rename(work / "retained-owned-disk.qcow2")
            disk.write_bytes(b"FOREIGN_SENTINEL_UNMODIFIED")
            foreign_hash = sha256(disk)
            require(
                os.fstat(fds["disk.qcow2"]).st_ino == original["disk.qcow2"][1], "RENAME_PIN_BROKEN"
            )
            report["renameForeignUnchanged"] = False
        with stderr.open("xb") as error_output:
            child = subprocess.Popen(
                args_for(mode, qmp_path, fds, readonly_fds, paths),
                cwd=work,
                start_new_session=True,
                pass_fds=tuple(fds.values()) + tuple(readonly_fds.values()),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=error_output,
            )
        start = birth(child.pid)
        require(start[1] == child.pid, "PROCESS_GROUP_NOT_OWNED")
        pidfd = os.pidfd_open(child.pid)
        assert_pidfd(pidfd, child.pid, start)
        report["kernelPidfdMatched"] = True
        wrong = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        try:
            try:
                assert_pidfd(wrong, child.pid, start)
            except (LabRefusal, OSError):
                report["ordinaryFdRejected"] = True
            else:
                raise LabRefusal("ORDINARY_FD_ACCEPTED")
            try:
                assert_pidfd(pidfd, child.pid + 1, start)
            except LabRefusal:
                report["foreignPidRejected"] = True
            else:
                raise LabRefusal("FOREIGN_PID_ACCEPTED")
        finally:
            os.close(wrong)
        # A real pidfd from an unrelated Python child must never authenticate
        # the live QEMU PID, even though both processes have the same UID.
        other = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        other_fd = None
        other_birth = None
        try:
            other_birth = birth(other.pid)
            other_fd = os.pidfd_open(other.pid)
            try:
                assert_pidfd(other_fd, child.pid, start)
            except LabRefusal:
                report["foreignRealPidfdRejected"] = True
            else:
                raise LabRefusal("FOREIGN_REAL_PIDFD_ACCEPTED")
            if mode == "pr_shared":
                import q4os_win10_qmp_supervisor as operational

                try:
                    operational._pidfd_target(other_fd, child.pid)
                except operational.StartupRefusal:
                    report["supervisorForeignPidfdRejected"] = True
                else:
                    raise LabRefusal("FOREIGN_PIDFD_ACCEPTED")
                # Reproduce the Safety R-02-CLEANUP-01 attempt against
                # the real QEMU child and an unrelated real Python pidfd.
                require(operational._cleanup(child, other_fd) is False, "FOREIGN_CLEANUP_ACCEPTED")
                require(child.poll() is None and other.poll() is None, "FOREIGN_PROCESS_SIGNALED")
                report["supervisorForeignCleanupDenied"] = True
        finally:
            report["foreignPidfdCleanup"] = close_process(other, other_fd, other_birth)
        require(report["foreignPidfdCleanup"]["directReaped"], "FOREIGN_CHILD_NOT_REAPED")
        if mode == "pr_shared":
            report["foreignQmpPeer"] = verify_foreign_qmp_peer(work, child)
        transcript, channel = qmp_readonly(
            child, qmp_path, start, pidfd, use_supervisor=(mode == "pr_shared")
        )
        report["qmp"] = transcript
        report["openedOwnedInodes"] = fd_inventory(child.pid, fds)
        for name, fd in fds.items():
            require(
                (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == original[name][:2],
                "FD_PIN_IDENTITY_CHANGED",
            )
        if rename:
            report["renameForeignUnchanged"] = sha256(paths["disk.qcow2"]) == foreign_hash
            require(report["renameForeignUnchanged"], "FOREIGN_DISK_MODIFIED")
        before_queries = tuple(transcript["queries"])
        socket_path = qmp_path
        identity = socket_path.lstat()
        socket_path.unlink()
        socket_path.symlink_to(paths["synthetic.iso"])
        require(socket_path.is_symlink(), "SOCKET_SWAP_NOT_APPLIED")
        # Reject the swapped pathname without issuing further QMP commands.
        try:
            observed = socket_path.lstat()
            require(
                stat.S_ISSOCK(observed.st_mode)
                and (observed.st_dev, observed.st_ino) == (identity.st_dev, identity.st_ino),
                "SOCKET_SWAP_REJECTED",
            )
        except LabRefusal as exc:
            require(str(exc) == "SOCKET_SWAP_REJECTED", "SOCKET_SWAP_REASON")
            report["socketSwapRejected"] = True
        require(tuple(transcript["queries"]) == before_queries, "QMP_SENT_AFTER_SWAP")
        report["success"] = True
    except (
        LabRefusal,
        OSError,
        ValueError,
        subprocess.SubprocessError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        report["refusal"] = str(exc) if isinstance(exc, LabRefusal) else "QEMU_STARTUP_FAILED"
        if child is not None:
            report["earlyExitCode"] = child.poll()
    finally:
        if channel is not None:
            channel.close()
        if pidfd is not None:
            stale_pidfd = os.dup(pidfd)
        try:
            if mode == "pr_shared" and child is not None:
                import q4os_win10_qmp_supervisor as operational

                # This is the actual production cleanup method, invoked
                # solely on the direct child we created and its kernel pidfd.
                # It is not an alternative operational process launcher.
                supervisor_cleaned = operational._cleanup(child, pidfd)
                report["supervisorCleanupVerified"] = supervisor_cleaned
                require(supervisor_cleaned, "SUPERVISOR_CLEANUP_FAILED")
                pgid = start[1] if start else -1
                report["cleanup"] = {
                    "directReaped": child.poll() is not None,
                    "descendantsAbsent": pgid > 0 and not group_members(pgid),
                    "exitCode": child.returncode,
                }
                os.close(pidfd)
            else:
                report["cleanup"] = close_process(child, pidfd, start)
        except (LabRefusal, OSError, subprocess.SubprocessError) as exc:
            report["cleanup"] = {
                "directReaped": False,
                "descendantsAbsent": False,
                "reason": str(exc) if isinstance(exc, LabRefusal) else "CLEANUP_FAILED",
            }
        if stale_pidfd is not None:
            try:
                assert_pidfd(stale_pidfd, child.pid, start)
            except (LabRefusal, FileNotFoundError, ProcessLookupError, OSError):
                report["stalePidfdRejected"] = True
            finally:
                os.close(stale_pidfd)
        for fd in (*fds.values(), *readonly_fds.values()):
            os.close(fd)
        if stderr.is_file():
            data = stderr.read_bytes()[:8192].lower()
            # Fixed boolean diagnostics only; never leak QEMU stderr or paths.
            report["errorFingerprint"] = {
                "fdset": b"fdset" in data,
                "pflash": b"pflash" in data,
                "qcow2": b"qcow2" in data,
                "noSuchFile": b"no such file" in data,
                "openFailed": b"could not open" in data or b"failed to open" in data,
                "permission": b"permission denied" in data,
                "invalid": b"invalid" in data,
                "alreadyUsed": b"in use" in data,
                "readOnly": b"read-only" in data,
                "fdsetMissing": b"no such fdset" in data or b"not found" in data,
            }
        report["postHash"] = {
            name: sha256(path)
            for name, path in paths.items()
            if path.is_file() and not path.is_symlink()
        }
        pinned_disk = work / "retained-owned-disk.qcow2" if rename else paths["disk.qcow2"]
        report["pinnedDiskAfter"] = sha256(pinned_disk)
        report["qcowUnchanged"] = (
            report["pinnedDiskAfter"] == geometry["resources"]["disk.qcow2"]["sha256"]
        )
        # Quiescent guest: OVMF VARS and QCOW2 must never change unexpectedly.
        report["varsUnchanged"] = (
            report["postHash"]["vars.fd"] == geometry["resources"]["vars.fd"]["sha256"]
        )
        report["codeUnchanged"] = (
            report["postHash"]["code.fd"] == geometry["resources"]["code.fd"]["sha256"]
        )
        report["success"] = (
            report["success"]
            and report["varsUnchanged"]
            and report["codeUnchanged"]
            and report["qcowUnchanged"]
            and report.get("stalePidfdRejected") is True
            and (mode != "pr_shared" or report.get("supervisorCleanupVerified") is True)
            and (mode != "pr_shared" or report.get("publicGateRefused") is True)
            and report["cleanup"].get("directReaped") is True
            and report["cleanup"].get("descendantsAbsent") is True
        )
    return report


def negative_cases(root: Path) -> dict:
    result = {}
    work = root / "negative"
    work.mkdir(mode=0o700)
    paths, _ = make_resources(work)
    original = sha256(paths["vars.fd"])
    with paths["vars.fd"].open("r+b") as out:
        out.seek(0)
        out.write(b"UNEXPECTED_VARIABLE_MUTATION")
    result["varsMutationDetected"] = sha256(paths["vars.fd"]) != original
    qcow = paths["disk.qcow2"]
    foreign = work / "foreign"
    foreign.write_bytes(b"WRONG_IMAGE")
    fd = pinned(foreign, False)
    try:
        result["wrongFdRejected"] = sha256_fd(fd) != sha256(qcow)
    finally:
        os.close(fd)
    # A genuinely closed FD should be rejected by QEMU, not silently reused.
    invalid_fd = 99999
    args = [
        QEMU,
        "-machine",
        "q35",
        "-accel",
        "tcg",
        "-S",
        "-nodefaults",
        "-display",
        "none",
        "-monitor",
        "none",
        "-net",
        "none",
        "-drive",
        f"if=none,id=closed,format=raw,file=/proc/self/fd/{invalid_fd}",
    ]
    done = subprocess.run(
        args,
        cwd=work,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    result["closedFdRejectedByQemu"] = done.returncode != 0
    # A malicious QCOW2 backing dependency is rejected before any VM spawn.
    raw = work / "synthetic-base.raw"
    raw.write_bytes(bytes(4096))
    backed = work / "untrusted-backing.qcow2"
    subprocess.run(
        [
            QEMU_IMG,
            "create",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            str(raw),
            str(backed),
            "64M",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    backed_info = json.loads(
        subprocess.check_output([QEMU_IMG, "info", "--output=json", str(backed)], timeout=15)
    )
    try:
        verify_qcow2_contract(backed_info)
    except LabRefusal:
        result["foreignBackingRejected"] = True
    else:
        result["foreignBackingRejected"] = False
    wrong_geometry = work / "wrong-geometry.qcow2"
    subprocess.run(
        [QEMU_IMG, "create", "-f", "qcow2", str(wrong_geometry), "32M"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    wrong_info = json.loads(
        subprocess.check_output(
            [QEMU_IMG, "info", "--output=json", str(wrong_geometry)], timeout=15
        )
    )
    try:
        verify_qcow2_contract(wrong_info)
    except LabRefusal:
        result["wrongGeometryRejected"] = True
    else:
        result["wrongGeometryRejected"] = False
    try:
        subprocess.Popen(
            [str(work / "not-an-executable")],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        result["spawnFailureDetected"] = True
    # A live, paused QEMU without a QMP listener must not be mistaken for QMP.
    timeout_process = None
    timeout_pidfd = None
    timeout_birth = None
    try:
        timeout_process = subprocess.Popen(
            [
                QEMU,
                "-machine",
                "q35",
                "-accel",
                "tcg",
                "-S",
                "-nodefaults",
                "-display",
                "none",
                "-monitor",
                "none",
                "-net",
                "none",
            ],
            cwd=work,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        timeout_birth = birth(timeout_process.pid)
        timeout_pidfd = os.pidfd_open(timeout_process.pid)
        assert_pidfd(timeout_pidfd, timeout_process.pid, timeout_birth)
        time.sleep(0.25)
        result["noQmpTimeoutRefused"] = (
            timeout_process.poll() is None and not (work / "missing-qmp.sock").exists()
        )
    finally:
        result["timeoutCleanup"] = close_process(timeout_process, timeout_pidfd, timeout_birth)
    require(
        all(
            result[key]
            for key in (
                "varsMutationDetected",
                "wrongFdRejected",
                "closedFdRejectedByQemu",
                "foreignBackingRejected",
                "wrongGeometryRejected",
                "spawnFailureDetected",
                "noQmpTimeoutRefused",
            )
        ),
        "NEGATIVE_CASE_FAILED",
    )
    require(
        result["timeoutCleanup"]["directReaped"] and result["timeoutCleanup"]["descendantsAbsent"],
        "TIMEOUT_CLEANUP_FAILED",
    )
    return result


def main() -> int:
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.geteuid() != 0
    ):
        print("Q4OS_FD_LAB=ENVIRONMENT_DENIED")
        return 2
    evidence_dir = Path(os.environ["GASLUX_Q4OS_FD_EVIDENCE"])
    if evidence_dir.is_symlink() or evidence_dir.parent != Path(os.environ["RUNNER_TEMP"]):
        print("GASLUX_Q4OS_FD_COMPATIBILITY=DENY")
        return 2
    evidence_dir.mkdir(mode=0o700, exist_ok=True)
    observed = evidence_dir.lstat()
    if observed.st_uid != os.getuid() or observed.st_mode & 0o077:
        print("GASLUX_Q4OS_FD_COMPATIBILITY=DENY")
        return 2
    root = Path(tempfile.mkdtemp(prefix="q4os-fd-", dir=os.environ["RUNNER_TEMP"]))
    report: dict = {
        "schemaVersion": 1,
        "fixtureOnly": True,
        "head": os.environ.get("GITHUB_SHA", ""),
        "utc": datetime.now(UTC).isoformat(),
        "qemuBooted": False,
        "guestOsUsed": False,
        "windowsSetupVerified": False,
        "calamaresExecuted": False,
        "productionStorageWritesAuthorized": False,
        "q4osNativeInstallationVerified": False,
        "windowsInPlaceRollbackProven": False,
        "stable": False,
        "qemuVersion": subprocess.check_output([QEMU, "--version"], timeout=5)
        .decode("utf-8", "replace")
        .splitlines()[0][:120],
        "argsContract": "q35 tcg 1vCPU 128MiB -S -nodefaults pflash code/vars "
        "qcow2 synthetic-cdrom QMP-readonly; no guest input",
        "scenarios": {},
    }
    try:
        if os.environ.get("GITHUB_REF") == "refs/heads/test/q4os-runlab-readonly-boundary-20261122":
            # Do not repeat the four previous stopped-QEMU scenarios in CI.
            report["scenarios"]["pr_shared"] = scenario(root, "pr_shared", True)
            report["negative"] = negative_cases(root)
            report["diagnosticOnly"] = True
            report["compatible"] = report["scenarios"]["pr_shared"]["success"]
        else:
            report["scenarios"]["proc"] = scenario(root, "proc", True)
            report["scenarios"]["fdset"] = scenario(root, "fdset", False)
            report["scenarios"]["hybrid"] = scenario(root, "hybrid", False)
            report["scenarios"]["pr_argv"] = scenario(root, "pr_argv", False)
            report["negative"] = negative_cases(root)
            report["compatible"] = all(
                report["scenarios"][name]["success"]
                for name in ("proc", "fdset", "hybrid", "pr_argv")
            )
    except Exception as exc:
        report["compatible"] = False
        report["unexpectedErrorType"] = type(exc).__name__[:50]
    finally:
        (evidence_dir / "q4os-fd-evidence.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print("GASLUX_Q4OS_FD_COMPATIBILITY=" + ("PASS" if report["compatible"] else "DENY"))
    return 0 if report["compatible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
