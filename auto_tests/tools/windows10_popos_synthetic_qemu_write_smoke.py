#!/usr/bin/env python3
"""QEMU/KVM-only signed Pop live synthetic DISK write smoke, NO Windows.

Only user-owned scratch 8-GiB raw base + QCOW2 child are exposed to guest.
The authentic System76 ELF is identified but NEVER invoked as an installer.
QEMU virtio-blk trace is an *external* write-request observation.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from gaslux_popos_guest_serial import READY, GuestProbeError, wait_for, normalized
from windows10_popos_official_iso_signed_lab import get_official_pop_iso
from windows10_popos_genuine_live_same_cow_vm import _iso_paths
from windows10_popos_distinst_readonly_observer import PINNED_DISTINST_SHA256
from windows10_popos_synthetic_qemu_trace_contract import (
    classify_trace, synthetic_plan, SERIAL, SYNTH_GUID,
    DISK_SIZE, SMOKE_OFFSET, SMOKE_LENGTH,
)
from windows_x64_installed_gpt_ro_audit import require, DiskAuditError

CONSENT = "I_ACCEPT_ONLY_DISPOSABLE_SYNTHETIC_QEMU_WRITE_TRACE"
CHILD = "gaslux-pop-synthetic-write-child.qcow2"
BASE = "gaslux-pop-synthetic-raw-base.img"
P1GUID = "ae228a25-0ecd-4f62-83b4-88dd48b88edd"
P2GUID = "f81482ad-e0e1-491a-8ea5-9c246f82ded8"
MARKER = re.compile(rb"(?m)^GASLUX_POP_SYNTH_KVM_WRITE_SMOKE=1\r?\n")
REFUSAL = re.compile(rb"(?m)^GASLUX_POP_SYNTH_WRITE_REFUSED=([^\r\n]+)\r?\n")
RESULT = re.compile(
    rb"(?m)^GASLUX_POP_SYNTH_(?:KVM_WRITE_SMOKE=1|"
    rb"WRITE_REFUSED=[^\r\n]+)\r?\n"
)


def call(*cmd: str, timeout: int = 120, **kw):
    return subprocess.run(cmd, timeout=timeout, check=True, **kw)


def sha(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def hosted() -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and os.environ.get("GASLUX_POP_SYNTHETIC_WRITE_CONSENT") == CONSENT
            and os.path.exists("/dev/kvm") and stat.S_ISCHR(os.stat("/dev/kvm").st_mode),
            "synthetic write experiment restricted to opted-in hosted KVM only")
    require(Path("/home/runner/work/_temp").is_dir()
            and not Path("/home/runner/work/_temp").is_symlink(),
            "untrusted hosted temporary workspace")


def make_base(work: Path) -> tuple[Path, str, dict]:
    base = work / BASE
    with base.open("xb") as stream:
        stream.truncate(DISK_SIZE)
    # Only a newly opened O_EXCL scratch raw image, NEVER a /dev device.
    call("sgdisk", "--zap-all", "--clear",
         "--disk-guid=" + SYNTH_GUID,
         "--new=1:2048:+64M", "--typecode=1:EF00",
         "--partition-guid=1:" + P1GUID,
         "--new=2:262144:+2G", "--typecode=2:8300",
         "--partition-guid=2:" + P2GUID,
         str(base))
    output = call("sgdisk", "--verify", str(base),
                  capture_output=True, text=True).stdout
    require("No problems found" in output,
            "synthetic GPT primary/backup integrity failed")
    img = sha(base)
    child = work / CHILD
    call("qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(base),
         str(child))
    info = json.loads(call("qemu-img", "info", "--output=json", str(child),
                           capture_output=True, text=True).stdout)
    require(info["format"] == "qcow2" and info["virtual-size"] == DISK_SIZE
            and info["backing-filename"] == str(base)
            and info.get("backing-filename-format") == "raw",
            "untrusted synthetic QCOW2 child/backing chain")
    plan = synthetic_plan(SYNTH_GUID, P1GUID, P2GUID, img, CHILD)
    return base, img, plan


def build_control(work: Path, kernel: Path, initrd: Path) -> Path:
    # A synthetic-only EFI bootstrap/control image, not Windows image code.
    require(len(kernel.parts) == 2 and len(initrd.parts) == 2
            and kernel.parts[0] == initrd.parts[0],
            "untrusted signed ISO kernel/initrd paths")
    prefix = kernel.parts[0]
    grub = r"""serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
menuentry 'Gaslux ONLY SYNTHETIC write smoke (no distinst)' {
  insmod iso9660
  insmod part_gpt
  if ! search --no-floppy --file --set=source /KERNEL; then
    echo 'No signed live kernel'
    halt
  fi
  if [ ! -f ($source)/INITRD ]; then
    echo 'No signed live initrd'
    halt
  fi
  linux ($source)/KERNEL boot=casper live-media-path=/PREFIX console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.unit=multi-user.target systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service
  initrd ($source)/INITRD
}
"""
    for src, val in (("KERNEL", str(kernel)), ("INITRD", str(initrd)),
                     ("PREFIX", prefix)):
        grub = grub.replace(src, val)
    conf = work / "synth-grub.cfg"
    conf.write_text(grub, encoding="utf-8")
    efi = work / "BOOTX64.EFI"
    call("grub-mkstandalone", "--format=x86_64-efi",
         "--output=" + str(efi), "boot/grub/grub.cfg=" + str(conf))
    img = work / "synth-efi-boot.raw"
    esp = work / "synth-control-esp.img"
    call("truncate", "-s", "256M", str(img))
    call("sgdisk", "--zap-all", "--new=1:2048:+128M",
         "--typecode=1:EF00", str(img))
    call("truncate", "-s", "128M", str(esp))
    call("mkfs.vfat", "-F", "32", "-n", "GASLXSYN", str(esp))
    call("mmd", "-i", str(esp), "::/EFI")
    call("mmd", "-i", str(esp), "::/EFI/BOOT")
    call("mcopy", "-i", str(esp), str(efi), "::/EFI/BOOT/BOOTX64.EFI")

    guest = work / "synthetic-smoke.sh"
    guest.write_text(r"""#!/usr/bin/env bash
set -Eeuo pipefail
fail() { printf 'GASLUX_POP_SYNTH_WRITE_REFUSED=%s\n' "$*"; exit 1; }
trap 'rc=$?; printf "GASLUX_POP_SYNTH_WRITE_REFUSED=guest_script_exit_%s\n" "$rc"' ERR
virt="$(systemd-detect-virt --vm)"
printf 'GASLUX_SYNTH_GUEST_VM_TYPE=%s\n' "$virt"
[[ "$virt" == qemu || "$virt" == kvm ]] || fail 'not_qemu_kvm'
byid=/dev/disk/by-id/virtio-GASLUX_POP_SYNTH
[[ -b "$byid" ]] || fail 'synthetic_by_id_device_absent'
serial="$(/usr/bin/lsblk -dn -o SERIAL "$byid" | tr -d '[:space:]')"
printf 'GASLUX_SYNTH_GUEST_SERIAL_SEEN=%s\n' "$serial"
[[ "$serial" == "GASLUX_POP_SYNTH" ]] || fail 'virtio_serial_mismatch'
[[ "$(blockdev --getsize64 "$byid")" == 8589934592 ]] || fail 'disk_byte_size_mismatch'
[[ "$(blockdev --getss "$byid")" == 512 ]] || fail 'logical_sector_mismatch'
rw=""
while read -r name typ ro; do
    [[ "$typ" == disk && "$ro" == 0 ]] || continue
    if [[ "$name" =~ ^zram[0-9]+$ ]]; then
        # Verify in-kernel memory-backed zram identity; never blanket-ignore
        # disk names or allow unknown writable secondary block devices.
        [[ "$(readlink -f "/sys/block/$name")" == "/sys/devices/virtual/block/$name" ]] || fail 'unverified_zram_identity'
        continue
    fi
    rw="${rw:+$rw }$name"
done < <(lsblk -dn -o NAME,TYPE,RO)
printf 'GASLUX_SYNTH_GUEST_RW_DISKS=%s\n' "$rw"
[[ "$rw" == "$(basename "$(readlink -f "$byid")")" ]] || fail 'multiple_or_wrong_writable_disks'
python3 -B - <<'PY'
import os
from pathlib import Path
device = Path("/dev/disk/by-id/virtio-GASLUX_POP_SYNTH").resolve(strict=True)
assert str(device).startswith("/dev/vd")
with device.open("r+b", buffering=0) as disk:
    disk.seek(96*1024*1024)
    data = b"GASLUX_POP_SYNTHETIC_QEMU_WRITE_SMOKE".ljust(4096, b"\x5a")
    assert disk.write(data) == 4096
    os.fsync(disk.fileno())
    disk.seek(96*1024*1024)
    assert disk.read(4096) == data
PY
printf 'GASLUX_POP_SYNTH_KVM_WRITE_SMOKE=1\n'
""", encoding="utf-8")
    call("mcopy", "-i", str(esp), str(guest), "::/synthetic-smoke.sh")
    manifest = work / "lab.sha256"
    manifest.write_text(sha(guest) + "  synthetic-smoke.sh\n", encoding="ascii")
    call("mcopy", "-i", str(esp), str(manifest), "::/lab.sha256")
    call("dd", "if=" + str(esp), "of=" + str(img), "bs=1M",
         "seek=1", "conv=notrunc", "status=none")
    esp.unlink()
    return img


def smoke_console(sock: Path, stream: bytearray) -> None:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        until = time.monotonic() + 30
        while True:
            try:
                connection.connect(str(sock))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                require(time.monotonic() < until, "QEMU synthetic serial unavailable")
                time.sleep(.2)
        wait_for(connection, stream,
                 re.compile(rb"Linux version|systemd\[1\]"),
                 timeout_seconds=200)
        wait_for(connection, stream, re.compile(rb"Startup finished in"),
                 timeout_seconds=350)
        for trial in range(10):
            start = len(stream)
            connection.sendall(b"printf 'GASLUX_POP_LIVE_SHELL_READY\\n'\r")
            try:
                wait_for(connection, stream, READY, timeout_seconds=20, start=start)
                break
            except GuestProbeError:
                require(trial < 9, "synthetic live debug serial never ready")
        steps = [
            (b"mkdir -p /run/gaslux-synth && mount -t vfat -o ro "
             b"/dev/disk/by-label/GASLXSYN /run/gaslux-synth && "
             b"printf 'GASLUX_SYNTH_CONTROL_MOUNTED=1\\n'\r",
             re.compile(rb"(?m)^GASLUX_SYNTH_CONTROL_MOUNTED=1\r?$"), 60),
            (b"cd /run/gaslux-synth && sha256sum -c lab.sha256 && "
             b"bash synthetic-smoke.sh\r", RESULT, 120),
        ]
        for command, marker, limit in steps:
            start = len(stream)
            connection.sendall(command)
            wait_for(connection, stream, marker, timeout_seconds=limit, start=start)
            observed = normalized(bytes(stream[start:]))
            refused = REFUSAL.search(observed)
            require(refused is None,
                    "synthetic guest refused before write: " +
                    (refused.group(1).decode("ascii", errors="replace")
                     if refused else "unknown"))
        connection.sendall(b"sync && systemctl poweroff -i\r")
        until = time.monotonic() + 150
        while time.monotonic() < until:
            connection.settimeout(2)
            try:
                data = connection.recv(16384)
            except TimeoutError:
                continue
            if not data:
                return
            stream.extend(data)
            require(len(stream) <= 5_000_000, "unbounded synthetic serial output")
        raise DiskAuditError("synthetic QEMU poweroff timeout")
    finally:
        connection.close()


def retain_bounded_failure(evidence: Path, stream: bytearray,
                           stderr: Path, trace: Path, reason: str) -> None:
    """Preserve no-media bounded diagnostics BEFORE temp-file cleanup."""
    for name, data in (
        ("synthetic-failure-console.txt", normalized(bytes(stream[-150_000:]))),
        ("synthetic-failure-qemu-stderr.txt",
         stderr.read_bytes()[-100_000:] if stderr.is_file() else b""),
        ("synthetic-failure-trace.txt",
         trace.read_bytes()[-250_000:] if trace.is_file() else b""),
        ("synthetic-failure-reason.txt", reason.encode("utf-8")[:1000]),
    ):
        dst = evidence / name
        dst.write_bytes(data)
        (evidence / (name + ".sha256")).write_text(
            hashlib.sha256(data).hexdigest() + "  " + name + "\n",
            encoding="ascii")


def decode_child_sparse(child: Path, destination: Path) -> Path:
    """Read an offline QCOW2 through qemu-img convert, no host block devices."""
    require(child.is_file() and not child.is_symlink()
            and destination.parent == child.parent and not destination.exists(),
            "unsafe independent QCOW2 conversion destination")
    # qemu-img dd skip does not support random seeking in all QCOW2 builds.
    # Convert only the disposable child to sparse raw (no /dev mapping).
    call("qemu-img", "check", "-f", "qcow2", str(child), timeout=150,
         stdout=subprocess.DEVNULL)
    call("qemu-img", "convert", "-f", "qcow2", "-O", "raw", "-S", "4k",
         str(child), str(destination), timeout=300)
    require(destination.is_file() and not destination.is_symlink()
            and destination.stat().st_size == DISK_SIZE,
            "sparse synthetic decoded raw view has wrong geometry")
    return destination


def extract_smoke(decoded: Path) -> bytes:
    with decoded.open("rb") as source:
        source.seek(SMOKE_OFFSET)
        data = source.read(SMOKE_LENGTH)
    require(len(data) == SMOKE_LENGTH
            and data == b"GASLUX_POP_SYNTHETIC_QEMU_WRITE_SMOKE".ljust(4096, b"\x5a"),
            "independent sparse QCOW2 conversion lacks expected guest sector write")
    return data


def verify_synthetic_gpt_unchanged(base: Path, decoded: Path) -> dict:
    """Check actual PRIMARY+BACKUP GPT bytes via independent QCOW2 readback.

    Do not parse GPT a second time. sgdisk already independently validates
    baseline GPT CRC/geometry, and unchanged byte regions prove intact
    primary+backup tables within this synthetic smoke only.
    """
    regions = (
        ("protective-mbr-primary-gpt", 0, 34),
        ("backup-gpt", DISK_SIZE // 512 - 33, 33),
    )
    out = {}
    for name, start, count in regions:
        length = count * 512
        with base.open("rb") as source:
            source.seek(start * 512)
            original = source.read(length)
        require(len(original) == length, "baseline synthetic GPT truncated")
        with decoded.open("rb") as converted:
            converted.seek(start * 512)
            actual = converted.read(length)
        require(actual == original,
                "unexpected synthetic GPT primary/backup modification: " + name)
        out[name] = hashlib.sha256(original).hexdigest()
    return out


def run(evidence: Path) -> dict:
    hosted()
    require(evidence.is_dir() and not evidence.is_symlink()
            and evidence.name == "pop-synthetic-qemu-evidence"
            and Path(os.environ["GITHUB_WORKSPACE"]) / evidence.name == evidence,
            "untrusted evidence directory")
    parent = Path("/home/runner/work/_temp")
    with tempfile.TemporaryDirectory(prefix="gaslux-win-x64-pop-synth-",
                                     dir=parent) as temp:
        work = Path(temp)
        os.chmod(work, 0o700)
        base, before, plan = make_base(work)
        child = work / CHILD
        require(base.exists() and child.exists(), "synthetic base/child missing")
        # The actual Pop ISO is GPG-authenticated, using the existing trusted
        # pinned-release download and pinned System76 fingerprint validation.
        iso, media = get_official_pop_iso(work)
        kernel, initrd, actual_elf = _iso_paths(work, iso)
        require(actual_elf == PINNED_DISTINST_SHA256,
                "authentic ISO contains different System76 distinst")
        control = build_control(work, kernel, initrd)
        code = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
        vars_template = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
        require(code.is_file() and vars_template.is_file(),
                "independent keyless OVMF not installed")
        nvram = work / "pop-synthetic-only-vars.fd"
        shutil.copyfile(vars_template, nvram)
        nvram_before = sha(nvram)
        code_before = sha(code)
        trace_events = call("qemu-system-x86_64", "-trace", "help",
                            capture_output=True, text=True).stdout
        required_trace_events = (
            "virtio_blk_handle_write", "pflash_data_write",
            "pflash_data_write_block", "pflash_write_block_erase",
            "pflash_write_block_start", "pflash_write_block_flush",
            "pflash_write_block_abort", "pflash_write",
            "pflash_write_failed", "pflash_write_invalid",
            "pflash_write_invalid_command", "pflash_write_invalid_state",
            "pflash_write_start", "pflash_write_unknown",
            "pflash_sector_erase_start", "pflash_chip_erase_start",
            "pflash_erase_complete", "pflash_erase_timeout",
            "pflash_unlock0_failed", "pflash_unlock1_failed",
        )
        require(all(event in trace_events for event in required_trace_events),
                "QEMU build lacks required virtio/pflash write trace events")
        event_file = work / "qemu-events"
        event_file.write_text("\n".join(required_trace_events) + "\n",
                              encoding="ascii")
        trace = work / "qemu-trace.log"
        sock = work / "serial.sock"
        serial_log = work / "serial.log"
        stderr = work / "qemu-stderr.log"
        args = [
            "qemu-system-x86_64", "-machine", "q35,accel=kvm",
            "-cpu", "host", "-smp", "2", "-m", "4096",
            "-display", "none", "-monitor", "none", "-no-reboot",
            "-net", "none",
            "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,file={nvram}",
            "-drive", f"if=none,id=synthefi,format=raw,readonly=on,file={control}",
            "-device", "virtio-blk-pci,drive=synthefi,bootindex=1",
            "-drive", f"if=none,id=verifiediso,format=raw,readonly=on,file={iso}",
            "-device", "virtio-blk-pci,drive=verifiediso,bootindex=2",
            "-drive", f"if=none,id=syntarget,format=qcow2,file={child}",
            "-device", f"virtio-blk-pci,drive=syntarget,serial={SERIAL},bootindex=3",
            "-boot", "order=c,menu=off",
            "-chardev", f"socket,id=popserial,path={sock},server=on,wait=off,logfile={serial_log}",
            "-serial", "chardev:popserial",
            "-trace", f"events={event_file},file={trace}",
        ]
        # No host OS path or any Windows disk may be exposed to QEMU.
        drives = [args[i+1] for i, a in enumerate(args[:-1]) if a == "-drive"]
        require(len(drives) == 5 and
                [("readonly=on" in x) for x in drives] ==
                [True, False, True, True, False]
                and all(",file=/dev/" not in x for x in drives)
                and all(str(x) not in " ".join(args)
                        for x in (Path("/dev/sda"), Path("/dev/nvme0n1")))
                and all("," not in str(p) for p in
                        (work, base, child, iso, control, nvram)),
                "synthetic isolation / QEMU writable-attachment allowlist failed")
        stream = bytearray()
        ok = False
        with stderr.open("xb") as err:
            process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
            try:
                smoke_console(sock, stream)
                require(process.wait(timeout=70) == 0,
                        "synthetic QEMU failed clean poweroff")
                ok = True
            except (DiskAuditError, GuestProbeError, OSError, ValueError,
                    subprocess.TimeoutExpired) as exc:
                retain_bounded_failure(
                    evidence, stream, stderr, trace,
                    type(exc).__name__ + ": " + str(exc))
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=30)
        require(ok and MARKER.search(normalized(stream)) is not None,
                "synthetic actual guest write witness absent")
        decoded = decode_child_sparse(child, work / "decoded-child-sparse.raw")
        actual_data = extract_smoke(decoded)
        gpt_proof = verify_synthetic_gpt_unchanged(base, decoded)
        decoded.unlink()
        after = sha(base)
        nvram_after = sha(nvram)
        code_after = sha(code)
        require(after == before, "immutable synthetic backing base modified")
        require(code_after == code_before,
                "read-only OVMF firmware CODE image changed")
        trace_size = trace.stat().st_size if trace.is_file() and not trace.is_symlink() else -1
        if trace_size < 0 or trace_size > 16_000_000:
            reason = f"independent QEMU trace missing or oversized: bytes={trace_size}"
            retain_bounded_failure(evidence, stream, stderr, trace, reason)
            raise DiskAuditError(reason)
        trace_text = trace.read_text(encoding="utf-8", errors="replace")
        # Classifier needs a discarded child, so discard only AFTER actual
        # smoke-byte extraction and complete QEMU termination.
        child.unlink()
        require(not child.exists() and sha(base) == before,
                "synthetic child not deleted or backing changed")
        try:
            report = classify_trace(
                trace_text, plan, reported_serial=SERIAL,
                base_sha_after=sha(base), nvram_sha_before=nvram_before,
                nvram_sha_after=nvram_after,
                child_discarded=not child.exists(), guest_probe_ok=ok,
                process_name="python3", installer_elf_sha256=None)
        except (DiskAuditError, OSError, ValueError) as exc:
            retain_bounded_failure(
                evidence, stream, stderr, trace,
                "post-write independent QEMU trace refused: " + str(exc))
            raise
        report.update({
            "realQemuKvmGuestBooted": True,
            "signedPopIsoGpgVerified": media["officialIsoSignedMetadataVerified"],
            "pinnedIsoSha256": media["isoSha256"],
            "actualDistinstElfSha256": actual_elf,
            "actualDistinstInvoked": False,
            "actualSyntheticGuestSectorWritePerformed": True,
            "qcow2ReadbackVerified": len(actual_data) == SMOKE_LENGTH,
            "noWindowsBlockDeviceAttached": True,
            "syntheticDiskGuid": SYNTH_GUID,
            "syntheticGptPrimaryAndBackupUnchanged": True,
            "syntheticGptBaselineRegionSha256": gpt_proof,
            "syntheticDiskSerial": SERIAL,
            "syntheticParentSha256": before,
            "ovmfVarsSha256Before": nvram_before,
            "ovmfVarsSha256After": nvram_after,
            "ovmfCodeSha256Before": code_before,
            "ovmfCodeSha256After": code_after,
            "ovmfCodeUnchanged": code_before == code_after,
            "qemuTraceSha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
            "qemuVersion": call("qemu-system-x86_64", "--version",
                                capture_output=True, text=True).stdout.splitlines()[0],
        })
        # Bounded evidence; never retain the ISO, QCOW2, NVRAM or raw target.
        payload = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
        (evidence / "synthetic-qemu-write-report.json").write_text(payload, encoding="utf-8")
        (evidence / "synthetic-qemu-write-report.json.sha256").write_text(
            hashlib.sha256(payload.encode()).hexdigest() +
            "  synthetic-qemu-write-report.json\n", encoding="ascii")
        trace_lines = [line for line in trace_text.splitlines()
                       if re.search(
                           r"\b(?:virtio_blk_handle_write|pflash_(?:data_write|"
                           r"data_write_block|write_block_erase|write_block_start|"
                           r"write_block_flush|write_block_abort|write|write_failed|"
                           r"write_invalid|write_invalid_command|write_invalid_state|"
                           r"write_start|write_unknown|sector_erase_start|"
                           r"chip_erase_start|erase_complete|erase_timeout|"
                           r"unlock0_failed|unlock1_failed))\b", line)]
        bounded = "\n".join(trace_lines[:1000]) + "\n"
        (evidence / "synthetic-qemu-block-write.trace").write_text(
            bounded, encoding="utf-8")
        (evidence / "synthetic-qemu-block-write.trace.sha256").write_text(
            hashlib.sha256(bounded.encode()).hexdigest() +
            "  synthetic-qemu-block-write.trace\n", encoding="ascii")
        print("GASLUX_POP_SYNTH_QEMU_WRITE_MONITOR_REAL=1", flush=True)
        print(payload, flush=True)
        return report


if __name__ == "__main__":
    try:
        output_dir = Path(os.environ["GITHUB_WORKSPACE"]) / "pop-synthetic-qemu-evidence"
        run(output_dir)
    except (DiskAuditError, GuestProbeError, OSError, KeyError, ValueError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print("GASLUX_POP_SYNTH_QEMU_WRITE_MONITOR_REFUSED=" + str(exc),
              file=sys.stderr, flush=True)
        raise SystemExit(1)
