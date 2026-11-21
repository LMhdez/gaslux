#!/usr/bin/env python3
"""Owned-file-only 32 GiB Pop VM checkpoint, recovery rehearsal and QEMU audit.

Experimental Linux-only laboratory. No host block device is ever accepted.
All writes are to O_EXCL files beneath a new github-hosted RUNNER_TEMP directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import uuid
import zlib

SECTOR = 512
SIZE = 32 * 1024**3
COUNT = SIZE // SECTOR
ESP = (2048, 2097152)
ROOT = (2099200, 58720256)
DISK_GUID = "6c8e012e-6c29-457e-a119-0cde4fa54dd6"
ESP_GUID = "b65d9228-97af-4b13-b5fa-59f1d8d9653e"
ROOT_GUID = "6a8555cd-6dc0-45fa-8e66-9de78e41557b"
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
ROOT_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"
SERIAL = "GASLUXPOPFULLVM"
CONSENT = "I_ACCEPT_DISPOSABLE_POP_FULL_REUSE_LINUX_ONLY"
SHA = re.compile(r"^[0-9a-f]{64}$")
WRITE = re.compile(r"\bvirtio_blk_handle_write\b.*\bsector\s+(\d+)\s+nsectors\s+(\d+)")
UNSAFE = re.compile(r"\bvirtio_blk_handle_(discard|write_zeroes)\b|\bblk_co_pwritev\b")
PFLASH = ("pflash_data_write", "pflash_data_write_block", "pflash_write_block_erase",
          "pflash_sector_erase_start", "pflash_chip_erase_start", "pflash_erase_complete")


class Refusal(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Refusal(message)


def command(*args, timeout=180, capture=True):
    r = subprocess.run([str(x) for x in args], capture_output=capture, text=True,
                       timeout=timeout, check=False)
    need(r.returncode == 0, f"tool failure: {args[0]} rc={r.returncode}: {r.stderr[-500:] if capture else ''}")
    return r.stdout if capture else ""


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def regular(path, *, write=False, length=None):
    p = Path(path)
    need(not p.is_symlink() and p.is_absolute(), "symlink/relative resource rejected")
    s = p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1,
         "resource is not a private single-link owned regular file")
    if length is not None:
        need(s.st_size == length, "unexpected resource capacity")
    if write:
        need(bool(s.st_mode & stat.S_IWUSR), "unexpected read-only resource")
    return p


def system_ovmf_template(path):
    """Only allow reading Ubuntu's root-owned installed keyless OVMF VARS.

    Crucially distinct from private mutable backing/child resources. A root-
    owned system package is not supposed to be owned by the Actions runner.
    """
    p = Path(path)
    need(str(p) == "/usr/share/OVMF/OVMF_VARS_4M.fd"
         and p.is_absolute() and not p.is_symlink(),
         "REFUSE_IDENTITY_MISMATCH: foreign OVMF template path")
    st = p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and st.st_size == 528*1024
         and st.st_mode & 0o022 == 0,
         "REFUSE_IDENTITY_MISMATCH: OVMF is not a safe root-owned template")
    return p


def new_file(path, length):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, length)
        os.fsync(fd)
    finally:
        os.close(fd)
    return regular(path, write=True, length=length)


def hosted(work):
    need(os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("RUNNER_OS") == "Linux"
         and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
         and os.environ.get("GASLUX_POP_FULL_REUSE_CONSENT") == CONSENT,
         "hosted Linux-only opt-in/identity missing")
    base = Path(os.environ.get("RUNNER_TEMP", "/nonexistent"))
    need(base.is_absolute() and base.is_dir() and not base.is_symlink()
         and Path(os.path.realpath(base)) == base, "untrusted runner temp")
    need(work.parent == base and work.name.startswith("gaslux-pop-full-reuse-")
         and work.is_dir() and not work.is_symlink() and work.stat().st_uid == os.geteuid()
         and stat.S_IMODE(work.stat().st_mode) == 0o700,
         "workdir is not new private hosted runner directory")


def gpt(path):
    regular(path, length=SIZE)
    with open(path, "rb", buffering=0) as f:
        mbr = f.read(SECTOR)
        need(mbr[510:512] == b"\x55\xaa"
             and mbr[446 + 4] == 0xee, "protective MBR absent")
        f.seek(SECTOR)
        a = f.read(SECTOR)
        f.seek((COUNT - 1) * SECTOR)
        b = f.read(SECTOR)
        need(a[:8] == b"EFI PART" and b[:8] == b"EFI PART", "GPT header missing")
        for header, own, other in ((a, 1, COUNT - 1), (b, COUNT - 1, 1)):
            hsize = struct.unpack_from("<I", header, 12)[0]
            need(92 <= hsize <= SECTOR, "invalid GPT header size")
            tmp = bytearray(header[:hsize]); tmp[16:20] = b"\0"*4
            need(zlib.crc32(tmp) == struct.unpack_from("<I", header, 16)[0],
                 "GPT header CRC invalid")
            need(struct.unpack_from("<QQ", header, 24) == (own, other),
                 "GPT primary/secondary coordinates invalid")
            need(str(uuid.UUID(bytes_le=header[56:72])) == DISK_GUID,
                 "foreign disk GUID")
        for hdr, expected_entries_lba in ((a, 2), (b, COUNT - 33)):
            entry_lba = struct.unpack_from("<Q", hdr, 72)[0]
            entries_number, size, crc = struct.unpack_from("<III", hdr, 80)
            need(entry_lba == expected_entries_lba and entries_number == 128
                 and size == 128, "nonstandard GPT entries layout")
            f.seek(entry_lba*SECTOR)
            entries = f.read(entries_number*size)
            need(zlib.crc32(entries) == crc, "GPT partition entries CRC invalid")
            for i, (typ, guid, part) in enumerate((
                    (ESP_TYPE, ESP_GUID, ESP),
                    (ROOT_TYPE, ROOT_GUID, ROOT))):
                p = entries[i*128:(i+1)*128]
                need(str(uuid.UUID(bytes_le=p[:16])) == typ
                     and str(uuid.UUID(bytes_le=p[16:32])) == guid
                     and struct.unpack_from("<QQ", p, 32) ==
                     (part[0], part[0]+part[1]-1),
                     f"partition {i+1} geometry/type/PARTUUID changed")
            need(not any(entries[256:]), "unexpected extra partition entries")
    return {"diskGuid": DISK_GUID, "espPartuuid": ESP_GUID, "rootPartuuid": ROOT_GUID,
            "espStartLba": ESP[0], "espEndLba": ESP[0]+ESP[1]-1,
            "rootStartLba": ROOT[0], "rootEndLba": ROOT[0]+ROOT[1]-1,
            "pmbrAndPrimary": region_hash(path, 0, 34),
            "secondary": region_hash(path, COUNT-33, 33)}


def region_hash(path, sector, count):
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        f.seek(sector*SECTOR)
        for _ in range(count):
            block = f.read(SECTOR)
            need(len(block) == SECTOR, "truncated GPT")
            h.update(block)
    return h.hexdigest()


def filesystem(path, start, count):
    # blkid probes a bounded byte window on this private regular file:
    # no loop/nbd device is ever exposed on the runner.
    result = command("blkid", "-p", "-o", "value", "-s", "TYPE",
                     "-O", str(start*SECTOR), "-S", str(count*SECTOR), str(path))
    return result.strip()


def chain(child, backing):
    regular(child, write=True)
    regular(backing, length=SIZE)
    info = json.loads(command("qemu-img", "info", "--output=json", str(child)))
    need(info.get("format") == "qcow2" and info.get("virtual-size") == SIZE
         and info.get("backing-filename") == str(backing)
         and info.get("backing-filename-format") == "raw",
         "foreign QCOW2 format/backing or capacity")
    command("qemu-img", "check", "-f", "qcow2", str(child))
    return info


def make_child(path, backing):
    need(not path.exists() and not path.is_symlink(), "child must be newly allocated")
    command("qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b",
            str(backing), str(path))
    chain(path, backing)


def plan_path(work):
    return work / "pop-reuse-transaction.json"


def get_plan(work):
    p = regular(plan_path(work))
    x = json.loads(p.read_text())
    need(x.get("schemaVersion") == 1 and x.get("scenario") == "pop-full-reuse-only"
         and x.get("serial") == SERIAL and x.get("diskGuid") == DISK_GUID
         and x.get("espPartuuid") == ESP_GUID and x.get("rootPartuuid") == ROOT_GUID
         and x.get("diskSizeBytes") == SIZE and x.get("logicalSectorBytes") == SECTOR
         and x.get("firmware") == "UEFI" and x.get("partitionTable") == "GPT"
         and x.get("diskWritesAuthorizedForWindows") is False
         and x.get("productionInstallationAuthorized") is False
         and x.get("transactionId") and x.get("checkpointProven") is True
         and SHA.fullmatch(x.get("backingSha256", "")),
         "untrusted transaction plan")
    return x


def verify_owned_filesystems(work, base, label):
    """Read-only fsck on extracted sparse partition images, never host devices.

    Extraction reads the exact owned byte ranges from checkpoint. Copies are
    new O_EXCL regular files under the private lab and immediately discarded.
    """
    results = {}
    for number, (start, sectors), fstype in (
        (1, ESP, "vfat"), (2, ROOT, "ext4")
    ):
        out = work / f"{label}-fsck-{number}.img"
        total = sectors*SECTOR
        new_file(out, total)
        with open(base, "rb", buffering=0) as src, open(out, "r+b", buffering=0) as dst:
            src.seek(start*SECTOR)
            left, offset = total, 0
            while left:
                data = src.read(min(left, 4*1024*1024))
                need(data, "checkpoint short read while preparing read-only fsck")
                if data.count(0) != len(data):
                    dst.seek(offset)
                    dst.write(data)
                left -= len(data)
                offset += len(data)
            dst.flush(); os.fsync(dst.fileno())
        try:
            if fstype == "vfat":
                command("fsck.fat", "-n", str(out), timeout=180)
            else:
                command("e2fsck", "-fn", str(out), timeout=600)
            results[str(number)] = {
                "filesystem": fstype, "sectorCount": sectors,
                "offlineFsckReadOnlyPassed": True,
                "partitionImageSha256": sha(out)
            }
        finally:
            regular(out, length=total).unlink()
    return results


def prepare(work, template):
    base = new_file(work / "pop-prepared.raw", SIZE)
    command("sgdisk", "--zap-all", "--clear", "--disk-guid="+DISK_GUID,
            "--new=1:2048:+1024M", "--typecode=1:EF00",
            "--partition-guid=1:"+ESP_GUID,
            "--change-name=1:GASLUX-OWNED-ESP",
            "--new=2:2099200:+28G", "--typecode=2:8300",
            "--partition-guid=2:"+ROOT_GUID,
            "--change-name=2:GASLUX-OWNED-ROOT", str(base))
    command("sgdisk", "--verify", str(base))
    before = gpt(base)
    # Explicit, bounded native formatters on a newly created regular file.
    # Independent EFI-only OVMF A/B proved mkfs.fat auto-cluster sizing on a
    # 32-GiB containing RAW creates an invalid 1-GiB FAT32 (65,502 clusters).
    # Explicit 4-KiB clusters (-s 8) give 261,627 and a working EFI fallback.
    command("mkfs.fat", "-F", "32", "-s", "8", "-n", "GXPOPFULL",
            "--offset="+str(ESP[0]), str(base), str(ESP[1]//2), timeout=360)
    need(gpt(base) == before, "FAT32 formatter touched GPT")
    esp_fat32 = fat32_boot_geometry(base)
    command("mkfs.ext4", "-F", "-q", "-b", "4096", "-L", "GXPOPROOT",
            "-E", "offset="+str(ROOT[0]*SECTOR),
            str(base), str(ROOT[1]//8), timeout=600)
    need(gpt(base) == before, "ext4 formatter touched GPT")
    need(filesystem(base, *ESP) == "vfat"
         and filesystem(base, *ROOT) == "ext4",
         "preformat did not create FAT32+ext4 in expected byte ranges")
    fs_proof_before = verify_owned_filesystems(work, base, "precheckpoint")
    os.chmod(base, 0o400)
    digest = sha(base)
    template = system_ovmf_template(template)
    master_hash = sha(template)
    vars_install = work / "ovmf-install.fd"
    vars_firstboot = work / "ovmf-firstboot.fd"
    for name in (vars_install, vars_firstboot):
        need(not name.exists(), "OVMF copy path already exists")
        shutil.copyfile(template, name, follow_symlinks=False)
        need(sha(name) == master_hash, "OVMF template copy differs")
    # Rehearse actual recovery on an independent child before any installer.
    failure = work / "injected-failure.qcow2"
    make_child(failure, base)
    offset = (ROOT[0] + 131072)*SECTOR
    command("qemu-io", "-f", "qcow2", "-c",
            f"write -P 0x5a {offset} 4096", str(failure))
    command("qemu-io", "-f", "qcow2", "-c",
            f"read -P 0x5a {offset} 4096", str(failure))
    need(sha(base) == digest, "backing mutated during injected write")
    regular(failure, write=True)
    failure.unlink()
    need(not failure.exists(), "foreign child not discarded")
    make_child(failure, base)
    chain(failure, base)
    # Reconstructed overlay must have no local allocations.
    mapping = json.loads(command("qemu-img", "map", "--output=json", str(failure)))
    need(not any(x.get("depth") == 0 and x.get("data") for x in mapping),
         "recreated child still contains foreign data")
    need(gpt(base) == before and sha(base) == digest,
         "checkpoint GPT or backing changed on recovery")
    need(filesystem(base, *ESP) == "vfat"
         and filesystem(base, *ROOT) == "ext4",
         "recovered filesystem identity missing")
    fs_proof_after = verify_owned_filesystems(work, base, "recovered")
    need(fs_proof_after == fs_proof_before,
         "REFUSE_RECOVERY_UNPROVEN: offline FAT32/ext4 fsck or bytes changed")
    failure.unlink()
    need(not failure.exists(), "failure rehearsal overlay left behind")
    # VM recovery: corrupt disposable install vars, replace exclusively from
    # independently retained template and prove byte-identical restored copy.
    with vars_install.open("r+b") as f:
        f.seek(2048); f.write(b"GASLUX-DISPOSABLE-FAULT"); f.flush()
        os.fsync(f.fileno())
    need(sha(vars_install) != master_hash, "OVMF fault injection ineffective")
    vars_install.unlink()
    shutil.copyfile(template, vars_install, follow_symlinks=False)
    need(sha(vars_install) == master_hash
         and sha(vars_firstboot) == master_hash,
         "OVMF recovery did not restore original snapshot")
    child = work / "pop-owned-child.qcow2"
    make_child(child, base)
    record = {
        "schemaVersion": 1, "scenario": "pop-full-reuse-only",
        "transactionId": str(uuid.uuid4()), "serial": SERIAL,
        "diskGuid": DISK_GUID, "espPartuuid": ESP_GUID, "rootPartuuid": ROOT_GUID,
        "diskSizeBytes": SIZE, "logicalSectorBytes": SECTOR,
        "firmware": "UEFI", "partitionTable": "GPT",
        "partitions": [
            {"number": 1, "startLba": ESP[0], "endLba": ESP[0]+ESP[1]-1,
             "type": ESP_TYPE, "filesystem": "vfat", "mount": "/boot/efi"},
            {"number": 2, "startLba": ROOT[0], "endLba": ROOT[0]+ROOT[1]-1,
             "type": ROOT_TYPE, "filesystem": "ext4", "mount": "/"}],
        "gpt": before, "espFat32BootGeometry": esp_fat32,
        "backingSha256": digest, "ovmfTemplateSha256": master_hash,
        "checkpointProven": True, "syntheticRecoveryProven": True,
        "filesystemIntegrityBeforeAndAfterRecovery": fs_proof_before,
        "recoveryMode": "discard-exclusive-qcow2-recreate",
        "windowsDiskAttached": False, "diskWritesAuthorizedForWindows": False,
        "productionInstallationAuthorized": False
    }
    path = plan_path(work)
    with os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600), "w") as f:
        json.dump(record, f, sort_keys=True, indent=2)
    print("GASLUX_POP_FULL_REUSE_CHECKPOINT_AND_RECOVERY_PROVEN=1", flush=True)
    return record


def classify_owned_write(start, count):
    need(type(start) is int and type(count) is int
         and count > 0 and start >= 0 and start + count <= COUNT,
         "REFUSE_OUT_OF_WRITESET: invalid sector bounds")
    if ESP[0] <= start and start + count <= ESP[0] + ESP[1]:
        return "esp"
    if ROOT[0] <= start and start + count <= ROOT[0] + ROOT[1]:
        return "root"
    raise Refusal("REFUSE_OUT_OF_WRITESET: GPT/unallocated/foreign sector write")




def fat32_boot_geometry(raw):
    """Prove FAT32 cluster and BPB conformance on our disposable ESP only.

    Four-way OVMF boot control: 65,502 FAT32 clusters failed before loading
    EFI; explicit 8 sectors/cluster yielded 261,627 and executed EFI.
    This read-only parser does not itself prove native firmware execution.
    """
    regular(raw, length=SIZE)
    offset = ESP[0] * SECTOR
    with raw.open("rb", buffering=0) as disk:
        disk.seek(offset)
        boot = disk.read(SECTOR)
    need(len(boot) == SECTOR and boot[510:512] == b"\x55\xaa"
         and boot[82:90] == b"FAT32   ",
         "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: ESP is not FAT32")
    u16 = lambda pos: struct.unpack_from("<H", boot, pos)[0]
    u32 = lambda pos: struct.unpack_from("<I", boot, pos)[0]
    bytes_per_sector, spc, reserved = u16(11), boot[13], u16(14)
    fats, hidden, total, fat_sectors, root = (
        boot[16], u32(28), u32(32), u32(36), u32(44))
    need(bytes_per_sector == SECTOR and spc == 8 and reserved >= 2
         and fats == 2 and fat_sectors > 0 and root >= 2
         and hidden in (0, ESP[0])
         and ESP[1] - 63 <= total <= ESP[1],
         "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: unsupported ESP FAT32 BPB geometry")
    data_sectors = total - reserved - fats * fat_sectors
    need(data_sectors > 0, "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: FAT32 data area invalid")
    cluster_count = data_sectors // spc
    need(65525 <= cluster_count <= 268435445
         and fat_sectors * SECTOR // 4 >= cluster_count + 2
         and root <= cluster_count + 1,
         "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: FAT32 cluster count invalid")
    return {
        "bytesPerSector": bytes_per_sector, "sectorsPerCluster": spc,
        "hiddenSectors": hidden, "reservedSectors": reserved,
        "totalSectors": total, "fatSectors": fat_sectors,
        "fatCount": fats, "rootCluster": root,
        "clusterCount": cluster_count,
        "rootDataStartLba": ESP[0] + reserved + fats * fat_sectors,
        "firmwareExecutableProven": False,
    }


def probe_installed_esp_boot(raw, work):
    """Read-only EFI artifact inspection on a verified synthetic RAW export.

    Files copied from the ESP are private disposable evidence, never written
    back to the QCOW2 or checkpoint. This does not prove firmware discovery.
    """
    fat32 = fat32_boot_geometry(raw)
    offset = ESP[0] * SECTOR
    image = f"{raw}@@{offset}"
    result = {"status": "REFUSE_NATIVE_EFI_BOOT_UNPROVEN",
              "readOnly": True, "espOffsetBytes": offset,
              "fat32BootGeometry": fat32,
              "firmwareDiscoveryProven": False, "nativeFirstBootProven": False}
    try:
        command("mdir", "-i", image, "::/EFI/BOOT", timeout=60)
        command("mdir", "-i", image, "::/EFI/systemd", timeout=60)
        entries = command("mdir", "-i", image, "::/loader/entries", timeout=60)
        need(".conf" in entries.lower(),
             "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: loader entry missing")
        for label, efi in (
            ("fallback", "::/EFI/BOOT/BOOTX64.EFI"),
            ("systemdBoot", "::/EFI/systemd/systemd-bootx64.efi"),
        ):
            local = work / f"probe-{label}.efi"
            need(not local.exists() and not local.is_symlink(),
                 "REFUSE_IDENTITY_MISMATCH: EFI probe output exists")
            try:
                command("mcopy", "-i", image, efi, str(local), timeout=60)
                regular(local)
                data = local.read_bytes()
                need(len(data) >= 256 and data[:2] == b"MZ",
                     "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: EFI DOS header invalid")
                pe = struct.unpack_from("<I", data, 0x3c)[0]
                need(0 < pe < len(data) - 96
                     and data[pe:pe+4] == b"PE\x00\x00"
                     and struct.unpack_from("<H", data, pe+4)[0] == 0x8664
                     and struct.unpack_from("<H", data, pe+24+68)[0] == 10,
                     "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: not x86_64 EFI application")
                result[label+"Sha256"] = hashlib.sha256(data).hexdigest()
                result[label+"SizeBytes"] = len(data)
            finally:
                if local.exists():
                    regular(local).unlink()
        result["status"] = "PASS_OFFLINE_EFI_ARTIFACTS_ONLY"
    finally:
        (work/"install.esp-boot.json").write_text(
            json.dumps(result, indent=2) + "\n")
    need(result["status"] == "PASS_OFFLINE_EFI_ARTIFACTS_ONLY",
         "REFUSE_NATIVE_EFI_BOOT_UNPROVEN: offline ESP proof missing")
    return result


def audit(work, phase, bio_transcript=None):
    x = get_plan(work)
    base = regular(work/"pop-prepared.raw", length=SIZE)
    child = regular(work/"pop-owned-child.qcow2", write=True)
    chain(child, base)
    need(sha(base) == x["backingSha256"], "backing mutated")
    need(gpt(base) == x["gpt"], "checkpoint GPT mutated")
    # No claimed proof by final GPT hashes only: independently inspect every
    # external QEMU sector write, including transient writes that were reversed.
    path = regular(work/f"{phase}.qemu.trace")
    need(path.stat().st_size < 128_000_000, "QEMU trace absent or exceeds 128MB")
    writes, total, esp_count, root_count, pflash_vars, pflash_code = 0,0,0,0,0,0
    import hashlib
    digest = hashlib.sha256()
    intervals = []
    with path.open("rb") as f:
        for line in f:
            digest.update(line)
            s = line.decode("ascii", errors="replace")
            need(not UNSAFE.search(s), "REFUSE_OUT_OF_WRITESET: discard/write-zeroes/unmapped write")
            if "pflash_" in s and any(v in s for v in PFLASH):
                if "system.flash0" in s: pflash_code += 1
                if "system.flash1" in s: pflash_vars += 1
            if "virtio_blk_handle_write" not in s:
                continue
            m = WRITE.search(s)
            need(m is not None, "OBSERVATION_INCOMPLETE: unparseable QEMU write")
            start, count = int(m[1]), int(m[2])
            region = classify_owned_write(start, count)
            if region == "esp":
                esp_count += 1
            else:
                root_count += 1
            intervals.append((start,start+count))
            writes += 1; total += count*SECTOR
    need(pflash_code == 0, "REFUSE_OUT_OF_WRITESET: OVMF CODE pflash write")
    need(writes > 0, "OBSERVATION_INCOMPLETE: missing QEMU writes")
    # Historical independent serial controller authenticates installed guest
    # handoff. The complete guest streaming BIO witness is a separate event
    # source from QEMU; neither a final GPT hash nor a guest success marker
    # substitutes for exact independent QEMU/BIO coverage and byte counts.
    bio = None
    if phase == "install":
        need(bio_transcript is not None, "OBSERVATION_INCOMPLETE: missing guest BIO transcript")
        transcript = regular(bio_transcript).read_bytes()
        reports = re.findall(rb"(?m)^GASLUX_POP_FULL_BIO_JSON=(\{[^\r\n]+\})\r?$",
                             transcript.replace(b"\r", b""))
        need(len(reports) == 1, "OBSERVATION_INCOMPLETE: guest BIO report not unique")
        bio = json.loads(reports[0])
        need(bio.get("observationComplete") is True
             and bio.get("foreignWritableEvents") == 0
             and bio.get("unsupportedEvents") == 0
             and bio.get("writeEvents", 0) > 0
             and bio.get("writeBytes") == total,
             "OBSERVATION_INCOMPLETE: guest BIO/QEMU byte count or integrity mismatch")
        grouped = []
        for start, end in sorted(intervals):
            if grouped and start <= grouped[-1][1]:
                grouped[-1] = (grouped[-1][0], max(grouped[-1][1], end))
            else:
                grouped.append((start, end))
        sumhash = hashlib.sha256()
        for lo, hi in grouped:
            sumhash.update(f"{lo}:{hi}\n".encode("ascii"))
        need(bio.get("writeCoverageSha256") == sumhash.hexdigest()
             and bio.get("mergedIntervalCount") == len(grouped),
             "OBSERVATION_INCOMPLETE: guest/QEMU sector coverage diverges")

    # Independent offline child GPT check after QEMU, not merely the backing.
    # Reads only two 17KiB and 16.5KiB windows from the QCOW2 virtual image.
    # qemu-io read -v is not stable across releases: export sparse RAW and parse.
    exported = work / f"{phase}-audit.raw"
    command("qemu-img", "convert", "-f", "qcow2", "-O", "raw", "-S", "4k",
            str(child), str(exported), timeout=1000)
    try:
        need(gpt(exported) == x["gpt"],
             "REFUSE_OUT_OF_WRITESET: final child GPT differs from checkpoint")
        if phase == "install":
            probe_installed_esp_boot(exported, work)
    finally:
        regular(exported, length=SIZE).unlink()
    result = {
        "phase": phase, "qemuWriteEventCount": writes, "qemuWriteBytes": total,
        "espWriteEventCount": esp_count, "rootWriteEventCount": root_count,
        "outOfSetWriteEvents": 0, "primarySecondaryGptUnchanged": True,
        "transientGptWritesObserved": 0,
        "qemuTraceSha256": digest.hexdigest(),
        "qemuTraceBytes": path.stat().st_size,
        "backingUnchanged": True, "checkpointRestorable": True,
        "pflashCodeMutationEvents": pflash_code,
        "pflashVarsMutationEvents": pflash_vars,
        "ovmfTransientWritesProvenAbsent": False,
        "guestBioCorrelated": bool(bio),
        "guestBioWriteEventCount": bio.get("writeEvents") if bio else None,
        "guestBioWriteBytes": bio.get("writeBytes") if bio else None,
        "guestBioCompletionVerified": False,
        "fullOperationObservationProven": False,
        "windowsWriterAuthorized": False,
        "productionInstallationAuthorized": False
    }
    (work / f"{phase}.audit.json").write_text(json.dumps(result, indent=2)+"\n")
    print(f"GASLUX_POP_{phase.upper()}_QEMU_WRITESET_CONFIRMED=1", flush=True)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["prepare", "audit"])
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--ovmf-template", type=Path)
    p.add_argument("--phase", choices=["install", "firstboot"])
    p.add_argument("--bio-transcript", type=Path)
    a = p.parse_args()
    try:
        hosted(a.work)
        if a.action == "prepare":
            need(a.ovmf_template is not None, "OVMF template missing")
            prepare(a.work, a.ovmf_template)
        else:
            need(a.phase is not None, "audit phase missing")
            audit(a.work, a.phase, a.bio_transcript)
    except (Refusal, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("GASLUX_POP_FULL_REUSE_REFUSED=" + str(exc), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
