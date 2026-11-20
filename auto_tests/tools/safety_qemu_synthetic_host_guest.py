#!/usr/bin/env python3
"""Real QEMU/KVM synthetic GPT host/guest read-only witness.

The guest emits raw GPT sectors from the virtio disk selected by a unique
virtual-device serial, *not* a self-reported JSON inventory. The same Safety
GPT parser validates both host and guest-read sectors. All authority is in
one GitHub Actions runner: LABORATORY ONLY, NOT_INDEPENDENT.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "assets/live"))
from libertix_disk_identity_gate import (DiskIdentityError, assert_snapshot_matches,
                                         inspect_gpt_image)
from libertix_prewrite_no_writer import (PrewriteDenied, authenticated_record,
                                          canonical, decide_no_writer)

SIZE = 64 * 1024 * 1024
SECTOR = 512
SERIAL = "GASLUXSAFE20261120"


def call(*argv: str, timeout: int = 120) -> str:
    return subprocess.run(argv, check=True, text=True, capture_output=True,
                          timeout=timeout).stdout


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def make_disk(path: Path, *, disk_guid: str, part_guid: str) -> None:
    with path.open("xb") as stream:
        stream.truncate(SIZE)
    call("sgdisk", "--clear", "--new=1:2048:+8M", "--typecode=1:0700",
         "--disk-guid=" + disk_guid, "--partition-guid=1:" + part_guid, str(path))


def make_initramfs(work: Path, module_root: Path) -> Path:
    tree = work / "initramfs"
    tree.mkdir()
    for path in ("bin", "dev", "proc", "sys", "tmp", "lib/modules"):
        (tree / path).mkdir(parents=True, exist_ok=True)
    shutil.copy2("/usr/bin/busybox", tree / "bin/busybox")
    for name in ("sh", "mount", "insmod", "modprobe", "dd", "base64", "cat", "sleep",
                 "poweroff", "mkdir", "basename", "grep"):
        (tree / "bin" / name).symlink_to("busybox")
    version = module_root.name
    dest = tree / "lib/modules" / version
    dest.mkdir(parents=True)
    # Include dependency closure of kernel-matched virtual disk drivers.
    module_names = ("virtio_pci", "virtio_blk")
    for name in module_names:
        commands = call("modprobe", "--set-version", version,
                        "--show-depends", name).splitlines()
        for command in commands:
            if not command.startswith("insmod "):
                continue
            src = Path(command.split()[1])
            relative = src.relative_to(module_root)
            out = dest / relative
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, out)
    for name in ("modules.dep", "modules.dep.bin", "modules.alias",
                 "modules.alias.bin", "modules.symbols.bin", "modules.builtin",
                 "modules.builtin.bin", "modules.softdep"):
        src = module_root / name
        if src.exists():
            shutil.copy2(src, dest / name)
    init = tree / "init"
    init.write_text(
        "#!/bin/sh\n"
        "export PATH=/bin:/sbin\n"
        "mount -t proc proc /proc\n"
        "mount -t sysfs sysfs /sys\n"
        "mount -t devtmpfs devtmpfs /dev\n"
        "modprobe virtio_pci || true\n"
        "modprobe virtio_blk || true\n"
        "echo SAFETY_GUEST_INIT_STARTED\n"
        "i=0\n"
        "while [ \"$i\" -lt 50 ]; do\n"
        "  for x in /sys/block/vd*/serial /sys/block/vd*/device/serial; do\n"
        "    [ -r \"$x\" ] || continue\n"
        "    serial=$(cat \"$x\")\n"
        f"    if [ \"$serial\" = \"{SERIAL}\" ]; then\n"
        "      disk=/dev/$(basename $(basename $(dirname $(dirname \"$x\"))))\n"
        "      # Derive block name from sysfs path, not from enumeration order.\n"
        "      disk=/dev/$(echo \"$x\" | /bin/busybox cut -d/ -f4)\n"
        "      sectors=$(cat /sys/block/$(basename \"$disk\")/size)\n"
        "      echo SAFETY_BEGIN\n"
        "      echo SERIAL=$serial\n"
        "      echo SECTORS=$sectors\n"
        "      echo CMDLINE=$(cat /proc/cmdline)\n"
        "      echo PRIMARY_BEGIN\n"
        "      dd if=\"$disk\" bs=512 count=34 2>/dev/null | base64\n"
        "      echo PRIMARY_END\n"
        "      echo BACKUP_BEGIN\n"
        "      dd if=\"$disk\" bs=512 skip=$((sectors - 33)) count=33 2>/dev/null | base64\n"
        "      echo BACKUP_END\n"
        "      echo SAFETY_END\n"
        "      poweroff -f\n"
        "    fi\n"
        "  done\n"
        "  sleep 1\n"
        "  i=$((i+1))\n"
        "done\n"
        "echo SAFETY_NO_SERIAL\n"
        "poweroff -f\n"
    )
    init.chmod(0o755)
    archive = work / "rootfs.cpio.gz"
    with archive.open("wb") as output:
        producer = subprocess.Popen(["find", ".", "-print0"], cwd=tree, stdout=subprocess.PIPE)
        package = subprocess.Popen(["cpio", "--null", "-o", "-H", "newc", "--quiet"],
                                   cwd=tree, stdin=producer.stdout, stdout=subprocess.PIPE)
        assert producer.stdout is not None
        producer.stdout.close()
        compressor = subprocess.Popen(["gzip", "-1"], stdin=package.stdout, stdout=output)
        assert package.stdout is not None
        package.stdout.close()
        if compressor.wait(timeout=60) or package.wait(timeout=60) or producer.wait(timeout=60):
            raise RuntimeError("initramfs assembly failed")
    return archive


def read_guest_sections(output: str, work: Path, label: str) -> dict:
    if output.count("SAFETY_BEGIN") != 1 or output.count("SAFETY_END") != 1:
        raise DiskIdentityError("incomplete guest read-only witness")
    def field(name: str) -> str:
        values = re.findall(r"^" + re.escape(name) + r"=(.*)$", output, re.MULTILINE)
        if len(values) != 1:
            raise DiskIdentityError("guest witness lacks " + name)
        return values[0].strip()
    if field("SERIAL") != SERIAL or field("SECTORS") != str(SIZE // SECTOR):
        raise DiskIdentityError("guest virtual serial or geometry mismatch")
    def section(name: str, length: int) -> bytes:
        pattern = name + r"_BEGIN\r?\n(.*?)\r?\n" + name + r"_END"
        matches = re.findall(pattern, output, re.DOTALL)
        if len(matches) != 1:
            raise DiskIdentityError("guest GPT sector section missing")
        raw = base64.b64decode(re.sub(r"\s+", "", matches[0]), validate=True)
        if len(raw) != length:
            raise DiskIdentityError("guest sector read truncated")
        return raw
    primary = section("PRIMARY", 34 * SECTOR)
    backup = section("BACKUP", 33 * SECTOR)
    reconstructed = work / (label + "-guest-read.img")
    with reconstructed.open("xb") as stream:
        stream.truncate(SIZE)
        stream.seek(0)
        stream.write(primary)
        stream.seek(SIZE - len(backup))
        stream.write(backup)
    observed = inspect_gpt_image(reconstructed, logical_sector_size=SECTOR)
    reconstructed.unlink()
    return {"snapshot": observed, "cmdline": field("CMDLINE"),
            "guestPrimarySha256": hashlib.sha256(primary).hexdigest(),
            "guestBackupSha256": hashlib.sha256(backup).hexdigest()}


def boot_readonly(work: Path, kernel: Path, initrd: Path, raw: Path,
                  *, label: str, vm_id: str, transaction: str, nonce: str) -> dict:
    overlay = work / (label + ".qcow2")
    call("qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(raw), str(overlay))
    info = json.loads(call("qemu-img", "info", "--output=json", str(overlay)))
    if (info.get("format") != "qcow2" or info.get("backing-filename") != str(raw)
            or info.get("backing-filename-format") != "raw"
            or info.get("virtual-size") != SIZE):
        raise DiskIdentityError("unexpected QCOW2 backing chain")
    before = digest(overlay)
    serial_file = work / (label + "-serial.txt")
    args = [
        "qemu-system-x86_64", "-enable-kvm", "-m", "384", "-smp", "1",
        "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none",
        "-kernel", str(kernel), "-initrd", str(initrd),
        "-append", "console=ttyS0 rdinit=/init quiet safety_tx=" + transaction
                   + " safety_vm=" + vm_id + " safety_nonce=" + nonce,
        "-serial", "file:" + str(serial_file),
        "-drive", "file=" + str(overlay) + ",format=qcow2,if=none,id=safetydrive,readonly=on",
        "-device", "virtio-blk-pci,drive=safetydrive,serial=" + SERIAL,
    ]
    completed = subprocess.run(args, check=False, timeout=90, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True)
    if completed.returncode != 0:
        raise RuntimeError(f"QEMU failed rc={completed.returncode}: {completed.stderr[-3500:]}")
    serial_text = serial_file.read_text(errors="replace")
    if "SAFETY_BEGIN" not in serial_text or "SAFETY_END" not in serial_text:
        raise DiskIdentityError("guest did not produce complete GPT evidence; serial tail: "
                                + serial_text[-3500:])
    witness = read_guest_sections(serial_text, work, label)
    if any(x not in witness["cmdline"] for x in (transaction, vm_id, nonce)):
        raise DiskIdentityError("guest challenge binding mismatch")
    if digest(overlay) != before or info != json.loads(call("qemu-img", "info", "--output=json", str(overlay))):
        raise DiskIdentityError("QEMU overlay altered despite readonly device")
    witness["overlaySha256"] = before
    witness["virtualSerial"] = SERIAL
    witness["backingFormat"] = info["backing-filename-format"]
    witness["virtualSizeBytes"] = info["virtual-size"]
    serial_file.unlink()
    overlay.unlink()
    return witness


def evaluate_gate(host: dict, guest: dict, immediate: dict, nonce: str,
                  transaction: str, vm_id: str) -> dict:
    plan = {"planId": transaction, "firmware": "uefi", "disk": {
        key: host[key] for key in ("partitionStyle", "partitionTableId",
                                  "sizeBytes", "logicalSectorSizeBytes")}}
    data = canonical(plan)
    plan_hash = hashlib.sha256(data).hexdigest()
    host_key, guest_key = secrets.token_bytes(32), secrets.token_bytes(32)
    def record(source, snapshot, key):
        return authenticated_record({
            "source": source, "transactionId": transaction,
            "planSha256": plan_hash, "vmId": vm_id,
            "nonce": nonce, "snapshot": snapshot}, key)
    return decide_no_writer(
        plan=plan, plan_bytes=data, transaction_id=transaction, vm_id=vm_id,
        fresh_nonce=nonce, host_key=host_key, guest_key=guest_key,
        host_evidence=record("host", host, host_key),
        guest_evidence=record("guest", guest, guest_key),
        immediate_evidence=record("guest-immediate", immediate, guest_key),
        owned_regions=[{"offsetBytes": 32 * 1024 * 1024,
                        "sizeBytes": 1024 * 1024, "ownerTransactionId": transaction}],
        write_set=[{"offsetBytes": 32 * 1024 * 1024,
                    "sizeBytes": 1024 * 1024, "operation": "allocate-free-space"}],
    )


def main() -> None:
    if not os.environ.get("GITHUB_ACTIONS") or not os.environ.get("RUNNER_TEMP"):
        raise RuntimeError("Only disposable GitHub-hosted runner is permitted")
    if not Path("/dev/kvm").is_char_device():
        raise RuntimeError("KVM device unavailable, no TCG fallback")
    kernel_candidates = sorted(Path("/boot").glob("vmlinuz-*"))
    kernels = [k for k in kernel_candidates if (Path("/lib/modules") / k.name.removeprefix("vmlinuz-")).is_dir()]
    if not kernels:
        raise RuntimeError("No Linux kernel with corresponding driver modules")
    kernel = kernels[-1]
    modroot = Path("/lib/modules") / kernel.name.removeprefix("vmlinuz-")
    with tempfile.TemporaryDirectory(prefix="gaslux-qemu-safety-", dir=os.environ["RUNNER_TEMP"]) as temp:
        work = Path(temp)
        initrd = make_initramfs(work, modroot)
        readable_kernel = work / "vmlinuz"
        # Ubuntu runner kernels may be root-only (0600); copy into our own
        # RUNNER_TEMP workspace instead of chmod-ing the host kernel.
        call("sudo", "-n", "install", "-m", "0644", str(kernel), str(readable_kernel))
        original = work / "base.raw"
        make_disk(original, disk_guid=str(uuid.uuid4()), part_guid=str(uuid.uuid4()))
        host = inspect_gpt_image(original, logical_sector_size=SECTOR)
        backing_sha = digest(original)
        tx, vm, nonce = secrets.token_hex(16), "safety-qemu-" + secrets.token_hex(12), secrets.token_hex(24)
        guest = boot_readonly(work, readable_kernel, initrd, original, label="valid",
                              vm_id=vm, transaction=tx, nonce=nonce)
        assert_snapshot_matches(host, guest["snapshot"])
        immediate = inspect_gpt_image(original, logical_sector_size=SECTOR)
        assert_snapshot_matches(host, immediate)
        decision = evaluate_gate(host, guest["snapshot"], immediate, nonce, tx, vm)
        if decision["decision"] != "ACCEPT_NO_WRITER":
            raise DiskIdentityError("correct disk did not yield no-writer laboratory decision")
        negatives = {}
        other = work / "other.raw"
        make_disk(other, disk_guid=str(uuid.uuid4()), part_guid=str(uuid.uuid4()))
        swapped = boot_readonly(work, readable_kernel, initrd, other, label="swapped",
                                vm_id=vm, transaction=tx, nonce=nonce)
        try:
            evaluate_gate(host, swapped["snapshot"], immediate, nonce, tx, vm)
        except DiskIdentityError:
            negatives["swappedQcow2"] = "DENY"
        tampered = copy.deepcopy(guest["snapshot"])
        tampered["partitions"][0]["partGuid"] = str(uuid.uuid4())
        try:
            evaluate_gate(host, tampered, immediate, nonce, tx, vm)
        except DiskIdentityError:
            negatives["changedPartuuid"] = "DENY"
        try:
            evaluate_gate(host, guest["snapshot"], immediate, nonce, secrets.token_hex(16), vm)
        except DiskIdentityError:
            negatives["changedTransaction"] = "DENY"
        if len(negatives) != 3:
            raise DiskIdentityError("adversarial refusal failure")
        if digest(original) != backing_sha:
            raise DiskIdentityError("immutable backing content changed")
        result = {
            "classification": "QEMU_SYNTHETIC_LAB_ONLY_NOT_INDEPENDENT",
            "notWindowsGenuine": True, "writerCalled": False,
            "transactionId": tx, "vmId": vm, "nonceSha256": hashlib.sha256(nonce.encode()).hexdigest(),
            "virtualSerial": SERIAL,
            "backingSha256": backing_sha, "backingUnchanged": True,
            "host": host, "guest": guest["snapshot"], "immediate": immediate,
            "guestPrimarySha256": guest["guestPrimarySha256"],
            "guestBackupSha256": guest["guestBackupSha256"],
            "decision": decision["decision"],
            "negativeDecisions": negatives,
            "productionWriteAuthorized": False,
        }
        evidence_path = Path(os.environ["RUNNER_TEMP"]) / "gaslux-safety-qemu-report.json"
        evidence_path.write_text(json.dumps(result, sort_keys=True, indent=2))
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
