#!/usr/bin/env python3
"""Exercise a real NTFS-3G ro,norecover mount on a disposable loopback image.

This test never formats or mounts a caller-selected block device. The only block
device it may use is the /dev/loopN returned by its own losetup invocation, and
that device must be proven to reference the exact temporary image before mkfs.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def command(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {arguments!r}\n"
            f"stdout={result.stdout[-2000:]}\nstderr={result.stderr[-4000:]}"
        )
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def backing_file_for(loop_device: str) -> Path:
    if not re.fullmatch(r"/dev/loop[0-9]+", loop_device):
        raise RuntimeError(f"Refusing non-loop block device: {loop_device!r}")
    backing = Path("/sys/class/block") / Path(loop_device).name / "loop/backing_file"
    if not backing.is_file():
        raise RuntimeError(f"Loop backing identity is unavailable: {backing}")
    value = backing.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"Loop device has no backing file: {loop_device}")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = Path("/") / candidate
    return candidate.resolve(strict=True)


def prove_owned_loop(loop_device: str, image: Path, original_stat: os.stat_result) -> None:
    if not re.fullmatch(r"/dev/loop[0-9]+", loop_device):
        raise RuntimeError(f"Refusing non-loop block device: {loop_device!r}")
    device_stat = os.stat(loop_device)
    if not stat.S_ISBLK(device_stat.st_mode):
        raise RuntimeError(f"Returned path is not a block device: {loop_device}")
    kind = command(["lsblk", "--nodeps", "--noheadings", "--output", "TYPE", loop_device]).stdout.strip()
    if kind != "loop":
        raise RuntimeError(f"Block device type is not loop: {kind!r}")
    current = image.stat()
    if (current.st_dev, current.st_ino, current.st_size) != (
        original_stat.st_dev,
        original_stat.st_ino,
        original_stat.st_size,
    ):
        raise RuntimeError("Temporary backing image identity or size changed")
    if backing_file_for(loop_device) != image.resolve(strict=True):
        raise RuntimeError("Loop device does not reference this test's exact backing image")
    size = int(command(["blockdev", "--getsize64", loop_device]).stdout.strip())
    if size != original_stat.st_size:
        raise RuntimeError("Loop device geometry does not match the backing image")


def find_mounts(mountpoint: Path) -> list[dict[str, Any]]:
    result = command(
        [
            "findmnt", "--json", "--mountpoint", str(mountpoint),
            "--output", "SOURCE,FSTYPE,OPTIONS,TARGET",
        ],
        check=False,
    )
    if result.returncode == 1 and not result.stdout.strip():
        return []
    if result.returncode != 0:
        raise RuntimeError(f"Cannot establish mount state: {result.stderr.strip()}")
    payload = json.loads(result.stdout)
    filesystems = payload.get("filesystems")
    if not isinstance(filesystems, list):
        raise RuntimeError("findmnt returned an invalid filesystems collection")
    return filesystems


def validate_real_mount(filesystems: list[dict[str, Any]], mountpoint: Path, loop_device: str) -> dict[str, Any]:
    if len(filesystems) != 1:
        raise RuntimeError(f"Mount state is ambiguous: expected one mount, got {len(filesystems)}")
    filesystem = filesystems[0]
    if filesystem.get("fstype") != "fuseblk":
        raise RuntimeError(f"Expected fuseblk from ntfs-3g, got {filesystem.get('fstype')!r}")
    if Path(str(filesystem.get("target", ""))).resolve() != mountpoint.resolve():
        raise RuntimeError("findmnt target does not match the test mountpoint")
    source = str(filesystem.get("source", ""))
    if not source or os.stat(source).st_rdev != os.stat(loop_device).st_rdev:
        raise RuntimeError("Mounted source is not the loop device created by this test")
    options = filesystem.get("options")
    if not isinstance(options, str):
        raise RuntimeError("findmnt did not provide mount options")
    tokens = options.split(",")
    allowed = {
        "ro", "relatime", "strictatime", "noatime", "nodiratime",
        "nosuid", "nodev", "noexec", "default_permissions", "allow_other",
    }
    if (
        len(tokens) != len(set(tokens))
        or "ro" not in tokens
        or "rw" in tokens
        or any(
            token not in allowed
            and not re.fullmatch(r"(?:user_id|group_id|blksize)=\d+", token)
            for token in tokens
        )
    ):
        raise RuntimeError(f"findmnt does not prove a read-only NTFS-3G mount: {options!r}")
    return {
        "source": source,
        "filesystem": filesystem["fstype"],
        "options": tokens,
        "target": str(mountpoint),
    }


def verify_ntfs3g_execve(trace_path: Path, loop_device: str, mountpoint: Path) -> str:
    trace = trace_path.read_text(encoding="utf-8", errors="replace")
    candidates = [
        line for line in trace.splitlines()
        if "execve(" in line
        and "ntfs-3g" in line
        and "norecover" in line
        and loop_device in line
        and str(mountpoint) in line
    ]
    if not candidates:
        raise RuntimeError(
            "strace did not prove ntfs-3g received ro,norecover for the owned loop device"
        )
    if not any("ro" in line for line in candidates):
        raise RuntimeError("strace did not prove the read-only option reached ntfs-3g")
    return candidates[-1]


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("Run this integration test as root; it must not invoke sudo internally")
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value:
        raise RuntimeError("RUNNER_TEMP is required; refusing to create an image elsewhere")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    if not runner_temp.is_dir():
        raise RuntimeError("RUNNER_TEMP is not a directory")

    workspace = Path(tempfile.mkdtemp(prefix="gaslux-ntfs-loopback-", dir=runner_temp))
    if workspace.parent != runner_temp:
        raise RuntimeError("Temporary workspace escaped RUNNER_TEMP")
    image = workspace / "ntfs-test.img"
    mountpoint = workspace / "mount"
    loop_device: str | None = None
    loop_owned = False
    original_stat: os.stat_result | None = None
    hash_before: str | None = None
    mount_verified = False
    mount_command_succeeded = False
    detached = False
    result: dict[str, Any] = {
        "status": "FAILED",
        "scope": "disposable-loopback-only",
        "runnerTemp": str(runner_temp),
        "image": str(image),
    }
    failure: Exception | None = None

    try:
        descriptor = os.open(image, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.ftruncate(descriptor, 128 * 1024 * 1024)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        original_stat = image.stat()

        loop_device = command(["losetup", "--find", "--show", str(image)]).stdout.strip()
        prove_owned_loop(loop_device, image, original_stat)
        loop_owned = True
        result.update(
            {
                "loopDevice": loop_device,
                "backingFileVerified": True,
                "backingImageBytes": original_stat.st_size,
            }
        )

        formatter = shutil.which("mkfs.ntfs") or shutil.which("mkntfs")
        if not formatter:
            raise RuntimeError("ntfs-3g package did not provide mkfs.ntfs/mkntfs")
        command([formatter, "-F", "-Q", "-L", "GASLUX_TEST", loop_device])
        prove_owned_loop(loop_device, image, original_stat)
        hash_before = sha256_file(image)
        result["sha256Before"] = hash_before

        mountpoint.mkdir(mode=0o700)
        trace_path = workspace / "ntfs3g-execve.trace"
        command([
            "strace", "-f", "-qq", "-e", "trace=execve", "-s", "4096",
            "-o", str(trace_path), "mount", "-t", "ntfs-3g", "-o", "ro,norecover",
            loop_device, str(mountpoint),
        ])
        mount_command_succeeded = True
        helper_execve = verify_ntfs3g_execve(trace_path, loop_device, mountpoint)
        mounted = find_mounts(mountpoint)
        result["findmntObservation"] = mounted
        observed = validate_real_mount(mounted, mountpoint, loop_device)
        mount_verified = True
        prove_owned_loop(loop_device, image, original_stat)
        result.update(
            {
                "loopDevice": loop_device,
                "backingFileVerified": True,
                "backingImageBytes": original_stat.st_size,
                "filesystem": observed["filesystem"],
                "mountOptions": observed["options"],
                "mountSource": observed["source"],
                "ntfs3gExecve": helper_execve,
                "sha256Before": hash_before,
            }
        )
    except Exception as error:
        failure = error
    finally:
        cleanup_errors: list[str] = []
        if loop_device and loop_owned and original_stat is not None:
            try:
                current_mounts = find_mounts(mountpoint) if mountpoint.exists() else []
                if mount_command_succeeded and not current_mounts:
                    raise RuntimeError("Mount command succeeded but findmnt cannot prove its state")
                if current_mounts:
                    if len(current_mounts) != 1:
                        raise RuntimeError("Refusing to unmount an ambiguous mount state")
                    mounted = current_mounts[0]
                    source = str(mounted.get("source", ""))
                    if (
                        Path(str(mounted.get("target", ""))).resolve() != mountpoint.resolve()
                        or not source
                        or os.stat(source).st_rdev != os.stat(loop_device).st_rdev
                        or mounted.get("fstype") != "fuseblk"
                    ):
                        raise RuntimeError("Refusing to unmount a mount not proven to belong to this test")
                    command(["umount", str(mountpoint)])
                if mountpoint.exists() and find_mounts(mountpoint):
                    raise RuntimeError("Test mount remains active; preserving temporary resources")
                if hash_before is not None:
                    hash_after = sha256_file(image)
                    result["sha256After"] = hash_after
                    result["imageUnchanged"] = hash_before == hash_after
                    if hash_before != hash_after and failure is None:
                        failure = RuntimeError("Backing image SHA-256 changed across the read-only mount")
                prove_owned_loop(loop_device, image, original_stat)
                command(["losetup", "--detach", loop_device])
                backing = Path("/sys/class/block") / Path(loop_device).name / "loop/backing_file"
                if backing.exists() and backing.read_text(encoding="utf-8").strip():
                    raise RuntimeError("Loop device still reports a backing file after detach")
                detached = True
            except Exception as error:
                cleanup_errors.append(str(error))
        elif loop_device and not loop_owned:
            cleanup_errors.append("Loop ownership could not be proven; device and image were left untouched")
        elif loop_device is None:
            try:
                if mountpoint.exists():
                    mountpoint.rmdir()
                if image.exists():
                    image.unlink()
                workspace.rmdir()
                result["temporaryResourcesRemoved"] = True
            except Exception as error:
                cleanup_errors.append(f"Temporary cleanup failed before loop allocation: {error}")

        if detached and not cleanup_errors:
            try:
                if mountpoint.exists():
                    mountpoint.rmdir()
                if image.exists():
                    image.unlink()
                workspace.rmdir()
                result["temporaryResourcesRemoved"] = True
            except Exception as error:
                cleanup_errors.append(f"Temporary cleanup failed: {error}")
        else:
            result["temporaryResourcesRemoved"] = False

        result["loopDetached"] = detached
        result["cleanupErrors"] = cleanup_errors

    if failure is not None:
        result["error"] = str(failure)
    if (
        failure is None
        and not result.get("cleanupErrors")
        and result.get("imageUnchanged") is True
        and mount_verified
        and detached
        and result.get("temporaryResourcesRemoved") is True
    ):
        result["status"] = "SUCCESS"
    elif failure is None:
        failure = RuntimeError("Integration acceptance conditions were not all satisfied")
    if failure is not None:
        result["error"] = str(failure)
    print(json.dumps(result, sort_keys=True))
    if failure is not None or result.get("cleanupErrors") or result["status"] != "SUCCESS":
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"NTFS loopback integration failed: {error}", file=sys.stderr)
        raise SystemExit(1)
