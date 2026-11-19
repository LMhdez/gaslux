#!/usr/bin/env python3
"""Run the official signed Pop live ISO against real installed Win10 GPT, READ-ONLY.

The Windows 10 source QCOW2 is never writable. Both transaction-owned Pop
partitions are also presented read-only in this stage, and are unformatted.
The actual System76 native installer is verified, but NOT executed.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

from windows10_popos_official_iso_signed_lab import (
    get_official_pop_iso,
)
from windows10_popos_gpt_mirror_gate import capture_owned_qcow2
from windows10_popos_independent_esp_root_stage import reconcile_owned_pair
from windows10_popos_native_readonly_handoff_candidate import LAB_VIRTIO_SERIAL
from windows_x64_installed_gpt_ro_audit import require, DiskAuditError

LIVE_CONSENT = "I_ACCEPT_AUTHENTIC_POP_LIVE_WITH_READONLY_WIN10_COW"
CONTROL_SOURCES = (
    "windows_x64_installed_gpt_ro_audit.py",
    "windows10_popos_gpt_mirror_gate.py",
    "windows10_popos_same_disk_overlay_stage.py",
    "windows10_popos_independent_esp_plan.py",
    "windows10_popos_independent_esp_root_stage.py",
    "windows10_popos_native_readonly_handoff_candidate.py",
    "windows10_popos_live_readonly_gpt_probe.py",
    "windows10_popos_genuine_live_guest_probe.py",
)
SHA = re.compile(r"[0-9a-f]{64}\Z")


def _run(*cmd: str, timeout: int = 120, **kwargs) -> None:
    subprocess.run(cmd, check=True, timeout=timeout, **kwargs)


def _iso_paths(work: Path, iso: Path) -> tuple[Path, Path, str]:
    """Mount official ISO, extract only the verified kernel/agent identity."""
    mount = work / "mounted-pop-iso"
    mount.mkdir(mode=0o700)
    _run("sudo", "mount", "-o", "loop,ro,nosuid,nodev,noexec",
         str(iso), str(mount))
    try:
        dirs = sorted(x for x in mount.glob("casper_pop-os_24.04_amd64_intel_*")
                      if x.is_dir() and not x.is_symlink())
        require(len(dirs) == 1 and re.fullmatch(
                r"casper_pop-os_24[.]04_amd64_intel_[A-Za-z0-9_.-]+",
                dirs[0].name) is not None,
                "wrong or ambiguous authenticated Pop kernel directory")
        root = dirs[0]
        kernel = root / "vmlinuz.efi"
        initrd = root / "initrd.gz"
        squash = [x for x in root.rglob("filesystem.squashfs")
                  if x.is_file() and not x.is_symlink()]
        require(kernel.is_file() and initrd.is_file()
                and len(squash) == 1
                and kernel.stat().st_size > 2_000_000
                and initrd.stat().st_size > 2_000_000,
                "incomplete genuine Pop live media kernel/initrd/rootfs")
        # Native binary is FROM the SAME GPG-validated ISO squashfs. Never
        # invent SHA-256s or use the host's distinst binary as proxy.
        proc = subprocess.Popen(
            ["unsquashfs", "-cat", str(squash[0]), "usr/bin/distinst"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        digest = hashlib.sha256()
        size = 0
        assert proc.stdout is not None
        with proc.stdout as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= 250 * 1024**2,
                        "unexpected native System76 ELF binary size")
                digest.update(chunk)
        stderr = proc.stderr.read(10000) if proc.stderr else b""
        require(proc.wait(timeout=90) == 0 and size > 10_000
                and len(stderr) < 10000,
                "native distinst could not be extracted from signed ISO")
        return kernel.relative_to(mount), initrd.relative_to(mount), digest.hexdigest()
    finally:
        _run("sudo", "umount", str(mount), timeout=30)


def _source_path(name: str) -> Path:
    root = Path(__file__).parent
    path = root / name
    require(path.is_file() and not path.is_symlink() and path.parent == root,
            "untracked/invalid Pop guest helper " + name)
    return path


def _create_ro_control(work: Path, payload: dict,
                       kernel: Path, initrd: Path) -> Path:
    """Genuine Pop GRUB bootstrap on an independent throwaway EFI disk."""
    config = work / "grub.cfg"
    prefix = kernel.parts[0]
    require(prefix == initrd.parts[0] and len(kernel.parts) == 2
            and len(initrd.parts) == 2,
            "unverified Pop boot source paths")
    grub = r"""serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial
terminal_output serial
set timeout=0
set default=0
menuentry 'Gaslux real Win10 read-only Pop live probe' {
  insmod iso9660
  insmod part_gpt
  if ! search --no-floppy --file --set=source /KERNEL; then
    echo 'Signed Pop live kernel not found'
    halt
  fi
  if [ ! -f ($source)/INITRD ]; then
    echo 'Signed Pop initrd not found'
    halt
  fi
  linux ($source)/KERNEL boot=casper live-media-path=/PREFIX console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.unit=multi-user.target systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service
  initrd ($source)/INITRD
}
"""
    for src, val in (("KERNEL", str(kernel)), ("INITRD", str(initrd)),
                     ("PREFIX", prefix)):
        grub = grub.replace(src, val)
    config.write_text(grub, encoding="utf-8")
    boot = work / "BOOTX64.EFI"
    _run("grub-mkstandalone", "--format=x86_64-efi",
         "--output="+str(boot), "boot/grub/grub.cfg="+str(config), timeout=120)
    target = work / "control-efi.raw"
    esp = work / "control-esp.img"
    _run("truncate", "-s", "256M", str(target))
    _run("sgdisk", "--zap-all", "--new=1:2048:+128M",
         "--typecode=1:EF00", "--change-name=1:GASLUX-LAB-ONLY",
         str(target))
    _run("truncate", "-s", "128M", str(esp))
    _run("mkfs.vfat", "-F", "32", "-n", "GASLUXLAB", str(esp))
    _run("mmd", "-i", str(esp), "::/EFI")
    _run("mmd", "-i", str(esp), "::/EFI/BOOT")
    _run("mcopy", "-i", str(esp), str(boot), "::/EFI/BOOT/BOOTX64.EFI")
    payload_file = work / "win10-six-gpt-input.json"
    payload_file.write_text(json.dumps(payload, sort_keys=True,
                           separators=(",", ":")), encoding="utf-8")
    manifest = []
    sources = [(_source_path(name), name) for name in CONTROL_SOURCES]
    sources.append((payload_file, payload_file.name))
    for src, dst in sources:
        _run("mcopy", "-i", str(esp), str(src), "::/"+dst)
        with src.open("rb") as file:
            manifest.append(hashlib.file_digest(file, "sha256").hexdigest()
                            + "  " + dst)
    manifest_file = work / "lab.sha256"
    manifest_file.write_text("\n".join(manifest)+"\n", encoding="ascii")
    _run("mcopy", "-i", str(esp), str(manifest_file), "::/lab.sha256")
    _run("dd", "if="+str(esp), "of="+str(target), "bs=1M",
         "seek=1", "conv=notrunc", "status=none")
    esp.unlink()
    return target


def live_probe_on_windows(
    base: Path, overlay: Path, workspace: Path, evidence: Path,
    plan: dict, *, windows_postboot_serial_verified: bool,
    original_windows_iso: Path | None = None,
    derived_windows_iso: Path | None = None,
) -> dict:
    require(
        windows_postboot_serial_verified is True
        and os.environ.get("GASLUX_POP_WINDOWS_COW_LIVE_CONSENT") == LIVE_CONSENT
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and base.name == "only-disposable-windows-target.qcow2"
        and overlay == base.parent / "gaslux-pop-stage.qcow2"
        and base.parent == workspace
        and workspace.parent == Path("/home/runner/work/_temp")
        and stat.S_IMODE(workspace.stat().st_mode) == 0o700
        and base.is_file() and overlay.is_file()
        and not base.is_symlink() and not overlay.is_symlink()
        and evidence.name == "windows-x64-tcg-evidence",
        "genuine Pop live VM requires completed Windows boot and owned COW",
    )
    before = capture_owned_qcow2(base, expected_count=4)
    after = capture_owned_qcow2(overlay, expected_count=6)
    reconcile_owned_pair(before, after, plan)
    require(plan["productionInstallationAuthorized"] is False,
            "attempt to promote native Pop lab plan to production")
    # Windows installer media are no longer needed after its two independent
    # verified boots. Deleting ONLY these exact private files frees capacity
    # for the signed Pop ISO, not Windows data/ESP/BCD or any other files.
    if original_windows_iso is not None and derived_windows_iso is not None:
        for path, expected in (
            (original_windows_iso, "verified-microsoft-evaluation.iso"),
            (derived_windows_iso, "derived-microsoft-noprompt-lab.iso"),
        ):
            require(path == workspace / expected and path.is_file()
                    and not path.is_symlink(),
                    "refusing deletion of unexpected Windows installation file")
        original_windows_iso.unlink()
        derived_windows_iso.unlink()
    iso, media = get_official_pop_iso(workspace)
    with _private_workdir(workspace) as work:
        kernel, initrd, digest = _iso_paths(work, iso)
        require(SHA.fullmatch(digest) is not None,
                "missing real native System76 distinst ELF hash")
        media["distinstSha256"] = digest
        payload = {
            "before": before, "after": after, "plan": plan,
            "stageReport": {
                "independentWindowsPostStageBootVerified": True,
                "windowsGuestPostPairBootAndGptReconciled": True,
                "windowsBackingQcow2Sha256Unchanged": True,
                "ownedPopEspAndRootGptEntriesStagedInCOW": True,
                "popEspFormatted": False, "popRootFormatted": False,
                "productionInstallationAuthorized": False,
            },
            "media": media,
            "guest": {
                "hostedDisposableVm": True, "qcow2ChildOnly": True,
                "windowsBackingWritable": False, "firmware": "uefi",
                "partitionStyle": "gpt", "secureBootEnabled": False,
                "diskSerial": LAB_VIRTIO_SERIAL,
                "diskGuid": before["diskGuid"],
                "partitionEntries": [
                    {"index": row["number"], "guid": row["guid"],
                     "typeGuid": row["type"], "firstLba": row["startLba"],
                     "lastLba": row["endLba"]}
                    for row in (after["windowsPartitions"]
                                + [after["popEsp"], after["linuxRoot"]])
                ],
                "popEspFilesystem": None, "popRootFilesystem": None,
                "windowsEspMounted": False, "windowsNtfsMounted": False,
                "networkAttached": False, "efiVariablesWritable": False,
            },
        }
        control = _create_ro_control(work, payload, kernel, initrd)
        code = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
        vars = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
        require(code.is_file() and vars.is_file()
                and not vars.name.endswith(".ms.fd"),
                "missing expected SecureBoot-capable OVMF with keyless vars")
        nvram = work / "pop-only-ovmf-vars.fd"
        shutil.copyfile(vars, nvram)
        socket = work / "live.sock"
        serial = work / "live.serial.log"
        trace = work / "live.console.trace"
        result = work / "live.gpt.json"
        require(not socket.exists() and not serial.exists()
                and not trace.exists() and not result.exists(),
                "refusing to reuse QEMU live evidence")
        args = [
            "qemu-system-x86_64", "-machine", "q35,accel=kvm",
            "-cpu", "host", "-smp", "2", "-m", "4096",
            "-display", "none", "-monitor", "none", "-no-reboot",
            "-net", "none",
            "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,file={nvram}",
            "-drive", f"if=none,id=labefi,format=raw,readonly=on,file={control}",
            "-device", "virtio-blk-pci,drive=labefi,bootindex=1",
            "-drive", f"if=none,id=verifiediso,readonly=on,format=raw,file={iso}",
            "-device", "virtio-blk-pci,drive=verifiediso,bootindex=2",
            "-drive", f"if=none,id=win10readonly,readonly=on,format=qcow2,file={overlay}",
            "-device",
            f"virtio-blk-pci,drive=win10readonly,serial={LAB_VIRTIO_SERIAL},bootindex=3",
            "-boot", "order=c,menu=off",
            "-chardev", f"socket,id=popserial,path={socket},server=on,wait=off,logfile={serial}",
            "-serial", "chardev:popserial",
        ]
        require(all("," not in str(p) for p in (base, overlay, control, iso, nvram)),
                "unsafe raw QEMU parameter separator")
        stderr = work / "qemu-stderr.log"
        with stderr.open("xb") as err:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
            try:
                _run(
                    "python3", str(_source_path("windows10_popos_genuine_live_console.py")),
                    "--socket", str(socket), "--trace", str(trace),
                    "--json-output", str(result), timeout=1100,
                )
                rc = proc.wait(timeout=120)
                require(rc == 0, "Pop guest failed clean virtual ACPI shutdown")
                require(result.is_file() and 0 < result.stat().st_size < 60_000,
                        "unbounded or absent real Pop GPT JSON witness")
                guest = json.loads(result.read_text(encoding="utf-8"))
                measured = guest.get("guestGpt")
                require(
                    guest.get("nativeAgentSha256") == digest
                    and type(measured) is dict
                    and measured["primaryAndBackupGptCrcVerified"] is True
                    and measured["diskGuid"] == after["diskGuid"]
                    and measured["ownedPopEspGuid"] == after["popEsp"]["guid"]
                    and measured["ownedPopRootGuid"] == after["linuxRoot"]["guid"]
                    and measured["diskWritePerformed"] is False
                    and measured["distinstExecutionAuthorized"] is False
                    and guest["nativeInstallationExecuted"] is False,
                    "guest emitted inconsistent Windows/Pop live QEMU witness")
                again = capture_owned_qcow2(overlay, expected_count=6)
                reconcile_owned_pair(before, again, plan)
                require(again == after, "read-only Pop live boot changed staged Win10 GPT")
                for filename, source in (
                    ("win10-pop-live-serial.log", serial),
                    ("win10-pop-live-controller.trace", trace),
                    ("win10-pop-live-gpt.json", result),
                    ("win10-pop-live-qemu-stderr.log", stderr),
                ):
                    require(source.is_file() and not source.is_symlink()
                            and source.stat().st_size <= 2_000_000,
                            "unbounded/unsafe live QEMU evidence")
                    with source.open("rb") as log:
                        data = log.read()
                    (evidence / filename).write_bytes(data)
                    (evidence / (filename + ".sha256")).write_text(
                        hashlib.sha256(data).hexdigest() + "  " + filename + "\n",
                        encoding="ascii",
                    )
                print("GASLUX_POP_LIVE_REAL_WINDOWS10_COW_GPT_READONLY_GUEST=1",
                      flush=True)
                return {
                    "popLiveIsoSha256": media["isoSha256"],
                    "popLiveDistinstSha256": digest,
                    "popSignedIsoGpgVerified": True,
                    "popLiveGenuineWindowsGptGuestVerified": True,
                    "popLiveQemuCleanPoweroffVerified": True,
                    "popInstalled": False, "dualBootVerified": False,
                    "rollbackVerified": False, "productionInstallationAuthorized": False,
                }
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=30)


class _private_workdir:
    def __init__(self, parent: Path):
        self.parent = parent
        self.work: Path | None = None

    def __enter__(self) -> Path:
        name = "pop-genuine-live-" + os.urandom(8).hex()
        self.work = self.parent / name
        self.work.mkdir(mode=0o700)
        return self.work

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.work is not None and self.work.parent == self.parent \
                and self.work.name.startswith("pop-genuine-live-"):
            shutil.rmtree(self.work)
