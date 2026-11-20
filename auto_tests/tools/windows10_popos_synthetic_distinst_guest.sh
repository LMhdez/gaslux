#!/usr/bin/env bash
set -Eeuo pipefail
fail() { printf 'GASLUX_POP_SYNTH_DISTINST_REFUSED=%s\n' "$1" >&2; exit 1; }
trap 'rc=$?; if (( rc != 0 )); then printf "GASLUX_POP_SYNTH_DISTINST_REFUSED=guest-script-exit-%s\n" "$rc" >&2; fi' EXIT
MODE="${1:-}"
[[ "$MODE" == "--preflight" || "$MODE" == "--run" ]] || fail "invalid-mode"

python3 -B - "$MODE" <<'PY'
from __future__ import annotations
import hashlib, json, os, re, shutil, struct, subprocess, sys, time, uuid, zlib
from pathlib import Path

MODE = sys.argv[1]
DEVICE_ID = Path("/dev/disk/by-id/virtio-GASLUX_POP_DIST")
EXPECTED_DEVICE = "/dev/vdc"
EXPECTED_SERIAL = "GASLUX_POP_DIST"
EXPECTED_DISK_GUID = "7d6e5c4b-3a29-4876-9abc-def012345678"
EXPECTED_ESP_GUID = "1a2b3c4d-5e6f-4789-8abc-def012345678"
EXPECTED_ROOT_GUID = "2b3c4d5e-6f70-489a-bcde-f0123456789a"
EXPECTED_SIZE = 8 * 1024**3
SECTOR = 512
PINNED_DISTINST = "8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5"
TRACE_ROOT = Path("/sys/kernel/tracing")
PREFLIGHT = Path("/run/gaslux-pop-distinst-preflight.json")
CONSENT = "I_ACCEPT_ONLY_SYNTHETIC_POP_DISTINST_TEST"

class Refused(RuntimeError):
    pass

def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)

def run(args: list[str], *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, errors="replace")

def sha(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def block_identity() -> dict:
    need(DEVICE_ID.is_symlink() and DEVICE_ID.exists(),
         "synthetic serial by-id link absent")
    device = str(DEVICE_ID.resolve(strict=True))
    need(device == EXPECTED_DEVICE and Path(device).is_block_device(),
         "synthetic serial resolves to an unexpected device")
    serial = run(["lsblk", "-dn", "-o", "SERIAL", device]).stdout.strip()
    size = int(run(["blockdev", "--getsize64", device]).stdout.strip())
    sector = int(run(["blockdev", "--getss", device]).stdout.strip())
    need(serial == EXPECTED_SERIAL and size == EXPECTED_SIZE and sector == SECTOR,
         "synthetic serial/size/logical-sector identity mismatch")
    writable = []
    for line in run(["lsblk", "-dn", "-o", "NAME,TYPE,RO"]).stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise Refused("unparseable block-device inventory")
        name, kind, ro = fields
        if ro == "1":
            continue
        if name == Path(device).name and kind == "disk":
            writable.append(name)
            continue
        if name.startswith("zram") and Path("/sys/devices/virtual/block").joinpath(name).exists():
            continue
        raise Refused("unexpected writable block device " + name + "/" + kind)
    need(writable == [Path(device).name],
         "synthetic target is not the only writable physical block disk")
    st = os.stat(device)
    return {"device": device, "serial": serial, "sizeBytes": size,
            "logicalSectorBytes": sector,
            "major": os.major(st.st_rdev), "minor": os.minor(st.st_rdev)}

def parse_gpt(device: str) -> dict:
    size = int(run(["blockdev", "--getsize64", device]).stdout.strip())
    sectors = size // SECTOR
    with open(device, "rb", buffering=0) as f:
        f.seek(SECTOR)
        primary = f.read(SECTOR)
        need(primary[:8] == b"EFI PART", "primary GPT signature absent")
        hsize = struct.unpack_from("<I", primary, 12)[0]
        stored_hcrc = struct.unpack_from("<I", primary, 16)[0]
        need(92 <= hsize <= SECTOR, "primary GPT header size invalid")
        hcopy = bytearray(primary[:hsize]); hcopy[16:20] = b"\0" * 4
        need(zlib.crc32(hcopy) & 0xffffffff == stored_hcrc,
             "primary GPT header CRC invalid")
        current, backup = struct.unpack_from("<QQ", primary, 24)
        disk_guid = str(uuid.UUID(bytes_le=primary[56:72]))
        entries_lba = struct.unpack_from("<Q", primary, 72)[0]
        entries_count, entry_size, entries_crc = struct.unpack_from("<III", primary, 80)
        need(current == 1 and backup == sectors - 1
             and 0 < entries_count <= 4096 and 128 <= entry_size <= 1024
             and entry_size % 8 == 0,
             "primary GPT geometry invalid")
        entries_len = entries_count * entry_size
        need(entries_len <= 4 * 1024 * 1024, "GPT entry array too large")
        f.seek(entries_lba * SECTOR); entries = f.read(entries_len)
        need(len(entries) == entries_len
             and zlib.crc32(entries) & 0xffffffff == entries_crc,
             "primary GPT entry-array CRC invalid")
        f.seek((sectors - 1) * SECTOR); backup_header = f.read(SECTOR)
        need(backup_header[:8] == b"EFI PART", "backup GPT signature absent")
        backup_size = struct.unpack_from("<I", backup_header, 12)[0]
        backup_hcrc = struct.unpack_from("<I", backup_header, 16)[0]
        need(92 <= backup_size <= SECTOR, "backup GPT header size invalid")
        bcopy = bytearray(backup_header[:backup_size]); bcopy[16:20] = b"\0" * 4
        need(zlib.crc32(bcopy) & 0xffffffff == backup_hcrc,
             "backup GPT header CRC invalid")
        bcurrent, bbackup = struct.unpack_from("<QQ", backup_header, 24)
        bentries_lba = struct.unpack_from("<Q", backup_header, 72)[0]
        bcount, bsize, bcrc = struct.unpack_from("<III", backup_header, 80)
        need(bcount == entries_count and bsize == entry_size,
             "backup GPT entry geometry differs")
        f.seek(bentries_lba * SECTOR); backup_entries = f.read(bcount * bsize)
        need(bcurrent == sectors - 1 and bbackup == 1
             and str(uuid.UUID(bytes_le=backup_header[56:72])) == disk_guid
             and backup_entries == entries
             and zlib.crc32(backup_entries) & 0xffffffff == bcrc,
             "backup GPT identity/entries/CRC mismatch")
        partitions = {}
        for i in range(entries_count):
            raw = entries[i * entry_size:(i + 1) * entry_size]
            if raw[:16] == b"\0" * 16:
                continue
            partitions[i + 1] = {
                "typeGuid": str(uuid.UUID(bytes_le=raw[:16])),
                "partuuid": str(uuid.UUID(bytes_le=raw[16:32])),
                "startLba": struct.unpack_from("<Q", raw, 32)[0],
                "endLba": struct.unpack_from("<Q", raw, 40)[0],
            }
    need(disk_guid == EXPECTED_DISK_GUID, "synthetic GPT disk GUID mismatch")
    esp, root = partitions.get(1), partitions.get(2)
    need(esp is not None and root is not None
         and esp["partuuid"] == EXPECTED_ESP_GUID
         and root["partuuid"] == EXPECTED_ROOT_GUID
         and esp["typeGuid"].lower() == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
         and root["typeGuid"].lower() == "0fc63daf-8483-4772-8e79-3d69d8477de4"
         and esp["startLba"] == 2048 and esp["endLba"] == 1050623
         and root["startLba"] == 1052672 and root["endLba"] == 9431279,
         "synthetic ESP/root GPT entry geometry or PARTUUID mismatch")
    return {"diskGuid": disk_guid, "partitions": partitions,
            "primaryCrcVerified": True, "backupCrcVerified": True,
            "primaryBackupEntriesEqual": True}

def filesystem_type(partition: str) -> str | None:
    obj = run(["blkid", "-p", "-s", "TYPE", "-o", "value", partition], check=False)
    return obj.stdout.strip() or None

def distinst_metadata() -> dict:
    binary = Path("/usr/bin/distinst")
    need(binary.is_file() and not binary.is_symlink(),
         "authentic /usr/bin/distinst missing or symlinked")
    digest = sha(binary)
    need(digest == PINNED_DISTINST, "distinst ELF SHA-256 mismatch")
    owner = run(["dpkg-query", "-S", str(binary)], check=False).stdout.strip()
    package = owner.split(":", 1)[0] if ":" in owner else None
    version = None
    if package:
        version = run(["dpkg-query", "-W", "-f=${Version}", package],
                      check=False).stdout.strip() or None
    build_id = None
    if shutil.which("readelf"):
        notes = run(["readelf", "-n", str(binary)], check=False).stdout
        match = re.search(r"Build ID:\s*([a-f0-9]+)", notes)
        if match:
            build_id = match.group(1)
    return {"exePath": str(binary), "exeSha256": digest,
            "package": package, "packageVersion": version,
            "elfBuildId": build_id, "upstreamCommitMatchProven": False}

def find_iso_inputs() -> tuple[str, str]:
    squash = run(["find", "/cdrom", "-maxdepth", "3", "-type", "f",
                  "-name", "filesystem.squashfs"], check=False).stdout.splitlines()
    remove = run(["find", "/cdrom", "-maxdepth", "3", "-type", "f",
                  "-name", "filesystem.manifest-remove"], check=False).stdout.splitlines()
    need(len(squash) == 1 and len(remove) == 1,
         "unique official Pop squashfs/manifest-remove not found under /cdrom")
    need(Path(squash[0]).is_file() and Path(remove[0]).is_file(),
         "official Pop installer inputs are not regular files")
    return squash[0], remove[0]

def prepare_tracefs() -> None:
    if not (TRACE_ROOT / "trace").exists():
        run(["mount", "-t", "tracefs", "tracefs", str(TRACE_ROOT)])
    for event in ("block/block_bio_queue", "block/block_rq_issue",
                  "sched/sched_process_exec"):
        need((TRACE_ROOT / "events" / event / "enable").is_file(),
             "required tracefs event absent: " + event)
    (TRACE_ROOT / "tracing_on").write_text("0\n")
    (TRACE_ROOT / "trace").write_text("")
    (TRACE_ROOT / "buffer_size_kb").write_text("8192\n")
    for event in ("block/block_bio_queue", "block/block_rq_issue",
                  "sched/sched_process_exec"):
        (TRACE_ROOT / "events" / event / "enable").write_text("1\n")

def preflight() -> None:
    need(os.geteuid() == 0, "guest preflight requires root")
    vm = run(["systemd-detect-virt", "--vm"], check=False).stdout.strip()
    need(vm in ("qemu", "kvm"), "guest is not a QEMU/KVM VM")
    disk = block_identity(); gpt = parse_gpt(disk["device"])
    need(filesystem_type(disk["device"] + "1") is None
         and filesystem_type(disk["device"] + "2") is None,
         "synthetic partitions are not initially blank")
    meta = distinst_metadata(); squash, remove = find_iso_inputs()
    prepare_tracefs()
    report = {
        "guestVmType": vm, "diskSerial": disk["serial"],
        "diskGuid": gpt["diskGuid"], "diskSizeBytes": disk["sizeBytes"],
        "logicalSectorBytes": disk["logicalSectorBytes"],
        "targetDevice": disk["device"],
        "targetMajorMinor": f'{disk["major"]}:{disk["minor"]}',
        "espPartuuid": gpt["partitions"][1]["partuuid"],
        "rootPartuuid": gpt["partitions"][2]["partuuid"],
        "gptPrimaryBackupVerified": True,
        "filesystemTypesBefore": {"1": None, "2": None},
        "distinstElf": meta, "squashfsPath": squash,
        "removePath": remove, "tracefsAvailable": True,
    }
    PREFLIGHT.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
    print("GASLUX_POP_SYNTH_DISTINST_PREFLIGHT_JSON="
          + json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
    print("GASLUX_POP_SYNTH_DISTINST_PREFLIGHT_READY=1", flush=True)

def trace_event(line: str, event_name: str) -> dict | None:
    if event_name + ":" not in line:
        return None
    payload = line.split(event_name + ":", 1)[1]
    match = re.search(
        r"(?P<major>\d+),(?P<minor>\d+)\s+(?P<rwbs>[A-Z]+)\s+"
        r"(?P<sector>\d+)\s+\+\s+(?P<count>\d+)", payload)
    if not match:
        return None
    prefix = line.split(event_name + ":", 1)[0]
    pm = re.search(r"(?P<comm>.+)-(?P<pid>\d+)\s+\[", prefix)
    if not pm:
        return None
    return {"major": int(match["major"]), "minor": int(match["minor"]),
            "rwbs": match["rwbs"], "sector": int(match["sector"]),
            "count": int(match["count"]), "comm": pm["comm"].strip(),
            "pid": int(pm["pid"])}

def tool_hashes() -> dict:
    result = {}
    for name in ("mkfs.fat", "mkfs.vfat", "mkfs.ext4", "mke2fs",
                 "blockdev", "mount", "umount"):
        path = shutil.which(name)
        if path:
            real = str(Path(path).resolve())
            result[name] = {"path": real, "sha256": sha(real)}
    return result

def run_distinst() -> None:
    need(os.environ.get("GASLUX_POP_DISTINST_SYNTHETIC_CONSENT") == CONSENT,
         "explicit synthetic-only distinst consent absent")
    need(PREFLIGHT.is_file(), "guest preflight checkpoint absent")
    pre = json.loads(PREFLIGHT.read_text())
    disk = block_identity(); gpt = parse_gpt(disk["device"])
    need(pre["diskGuid"] == gpt["diskGuid"]
         and pre["targetMajorMinor"] == f'{disk["major"]}:{disk["minor"]}'
         and pre["distinstElf"]["exeSha256"] == PINNED_DISTINST,
         "target or ELF changed after preflight")
    squash, remove = find_iso_inputs()
    need(squash == pre["squashfsPath"] and remove == pre["removePath"],
         "installer payload identity changed after preflight")
    prepare_tracefs()
    trace_file = TRACE_ROOT / "trace"
    trace_file.write_text("")
    (TRACE_ROOT / "tracing_on").write_text("1\n")
    device = disk["device"]
    argv = [
        "/usr/bin/distinst", "--squashfs", squash, "--remove", remove,
        "--hostname", "gaslux-pop-synth", "--block", device,
        "--use", f"{device}:1:fat32:mount=/boot/efi:flags=esp",
        "--use", f"{device}:2:ext4:mount=/",
        "--no-efi-vars", "--test",
    ]
    output_path = Path("/run/gaslux-pop-distinst-output.log")
    started = time.time()
    with output_path.open("wb") as output:
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
                                   close_fds=True)
        pid = process.pid
        exe_path = os.readlink(f"/proc/{pid}/exe")
        exe_hash = sha(f"/proc/{pid}/exe")
        cmdline = [x.decode("utf-8", errors="replace")
                   for x in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if x]
        need(exe_path == "/usr/bin/distinst" and exe_hash == PINNED_DISTINST
             and cmdline == argv, "launched distinst process identity mismatch")
        deadline = time.monotonic() + 600
        timed_out = False
        while process.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                break
            time.sleep(0.1)
        exit_code = process.wait()
    (TRACE_ROOT / "tracing_on").write_text("0\n")
    raw_trace = trace_file.read_text(errors="replace")
    need(len(raw_trace) <= 8_000_000, "guest tracefs buffer exceeded 8MiB")
    stats = [path.read_text(errors="replace")
             for path in sorted((TRACE_ROOT / "per_cpu").glob("cpu*/stats"))]
    need(not any(re.search(r"(?m)^(?:overrun|commit overrun):\s*[1-9]", x)
                 for x in stats), "guest tracefs reported event loss/overrun")
    target_major, target_minor = disk["major"], disk["minor"]
    zram_ids = set()
    for line in run(["lsblk", "-dn", "-o", "NAME,MAJ:MIN,TYPE,RO"]).stdout.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[0].startswith("zram"):
            zram_ids.add(tuple(int(x) for x in fields[1].split(":")))
    bio, rq, other_writes, execs = [], [], [], []
    for line in raw_trace.splitlines():
        for name, dest in (("block_bio_queue", bio), ("block_rq_issue", rq)):
            event = trace_event(line, name)
            if event is None:
                continue
            if "W" not in event["rwbs"] and not any(x in event["rwbs"] for x in ("D", "Z")):
                continue
            if (event["major"], event["minor"]) == (target_major, target_minor):
                dest.append(event)
            elif (event["major"], event["minor"]) in zram_ids:
                continue
            else:
                other_writes.append(event)
        if "sched_process_exec:" in line:
            payload = line.split("sched_process_exec:", 1)[1]
            m = re.search(r"filename=(\S+)\s+pid=(\d+)", payload)
            if m:
                execs.append({"filename": m.group(1), "pid": int(m.group(2))})
    need(not other_writes, "guest tracefs observed write to non-target block device")
    need(len(bio) <= 20000 and len(rq) <= 20000 and len(execs) <= 2000,
         "guest tracefs evidence exceeds bounded event count")
    need(exit_code == 0 and not timed_out,
         "authentic distinst --test failed or exceeded 600-second limit")
    types = {"1": filesystem_type(device + "1"), "2": filesystem_type(device + "2")}
    need(types == {"1": "vfat", "2": "ext4"},
         "distinst did not create expected FAT32/EXT4 filesystems")
    need(not run(["findmnt", "-rn", "-S", device + "1"], check=False).stdout.strip()
         and not run(["findmnt", "-rn", "-S", device + "2"], check=False).stdout.strip(),
         "distinst --test left synthetic target mounted")
    fsck_fat = run(["fsck.fat", "-n", device + "1"], check=False, timeout=60)
    fsck_ext = run(["e2fsck", "-fn", device + "2"], check=False, timeout=90)
    need(fsck_fat.returncode == 0 and fsck_ext.returncode == 0,
         "read-only filesystem consistency check failed")
    gpt_after = parse_gpt(device)
    need(gpt_after == gpt, "distinst --test changed primary/backup GPT metadata")
    meta = pre["distinstElf"]
    report = {
        "guestVmType": pre["guestVmType"], "diskSerial": disk["serial"],
        "diskGuid": gpt_after["diskGuid"], "diskSizeBytes": disk["sizeBytes"],
        "logicalSectorBytes": disk["logicalSectorBytes"],
        "targetDevice": device,
        "targetMajorMinor": f"{target_major}:{target_minor}",
        "espPartuuid": gpt_after["partitions"][1]["partuuid"],
        "rootPartuuid": gpt_after["partitions"][2]["partuuid"],
        "gptPrimaryBackupVerified": True, "filesystemsAfter": types,
        "distinstPhase": "partition-format-mount-test",
        "distinstProcess": {
            "pid": pid, "exePath": exe_path, "exeSha256": exe_hash,
            "argv": cmdline, "exitCode": exit_code,
            "startEpoch": started, "timedOut": timed_out,
            "packageVersion": meta.get("packageVersion"),
            "elfBuildId": meta.get("elfBuildId"),
            "upstreamCommitMatchProven": False,
        },
        "filesystemChecks": {"fsckFatExit": fsck_fat.returncode,
                             "e2fsckExit": fsck_ext.returncode},
        "tracefs": {
            "available": True,
            "targetMajorMinor": f"{target_major}:{target_minor}",
            "blockBioQueue": bio, "blockRqIssue": rq, "execs": execs,
            "otherWritableBlockDeviceEvents": other_writes,
            "rawTraceSha256": hashlib.sha256(raw_trace.encode()).hexdigest(),
            "rawTraceBytes": len(raw_trace.encode()),
            "toolHashes": tool_hashes(),
        },
        "distinstOutputTail": output_path.read_text(errors="replace")[-12000:],
    }
    print("GASLUX_POP_SYNTH_DISTINST_RESULT_JSON="
          + json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
    print("GASLUX_POP_SYNTH_DISTINST_COMPLETE=1", flush=True)

try:
    if MODE == "--preflight":
        preflight()
    else:
        run_distinst()
except Exception as exc:
    print("GASLUX_POP_SYNTH_DISTINST_REFUSED="
          + (str(exc) or type(exc).__name__)[:400], file=sys.stderr, flush=True)
    raise
PY
