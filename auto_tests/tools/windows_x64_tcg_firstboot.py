#!/usr/bin/env python3
"""DISPOSABLE GitHub Linux runner ONLY: attempt real x64 Windows Eval install via TCG.

Downloads the original official Microsoft ISO, validates the independently
published SHA-256, and supplies unattended setup ONLY to a newly created
file-backed QCOW2 disk. It MUST NOT be run on any host block device.
Only a marker from inside installed Windows client may establish first boot.
No Windows+Linux dual boot/rollback is attempted here.
"""
from __future__ import annotations

import argparse
import hashlib
import stat
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from windows_x64_qemu_host_gate import load_catalog, EXPECTED, OVMF_CODE, OVMF_VARS

MAX_ISO_SIZE = 9 * 1024**3
MIN_ISO_SIZE = 3 * 1024**3
VM_SIZE = "128G"
WINDOWS_PRIMARY_MB = 73728  # 72 GiB; leave 50+ GiB spare for future Linux VM-only lab
WINRE_PARTITION_MB = 1536  # Microsoft recommends at least 990 MB plus servicing space
EXPECTED_FINAL_HOSTS = {
    "software-static.download.prss.microsoft.com",
    "software.download.prss.microsoft.com",
    "go.microsoft.com",
}
CONSENT = "I_ACCEPT_FILE_BACKED_WINDOWS_EVAL_TCG_ONLY"
MARKER = "GASLUX_WINDOWS_X64_REAL_CLIENT_FIRSTBOOT"
FAILURE = "GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL"


class LabError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LabError(message)


def validate_environment(workspace: Path, accelerator: str = "tcg") -> None:
    require(accelerator in ("tcg", "kvm"), "unknown guest accelerator")
    consent_ok = (
        os.environ.get("GASLUX_WINDOWS_KVM_CONSENT") ==
        "I_ACCEPT_DISPOSABLE_GITHUB_KVM_ONLY"
        if accelerator == "kvm" else
        os.environ.get("GASLUX_WINDOWS_TCG_CONSENT") == CONSENT
    )
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_OS") == "Linux" and consent_ok,
            "not an expressly authorized disposable GitHub Linux VM laboratory")
    if accelerator == "kvm":
        import fcntl  # POSIX only; Windows CI imports this module for PS AST checks.
        require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                "KVM refused on self-hosted or unidentified runner")
        kvm = Path("/dev/kvm")
        require(kvm.exists() and not kvm.is_symlink() and
                stat.S_ISCHR(kvm.stat().st_mode),
                "KVM device missing or unsafe")
        try:
            with kvm.open("rb+") as device:
                require(fcntl.ioctl(device.fileno(), 0xAE00, 0) == 12,
                        "unsupported KVM kernel API")
                guest_fd = fcntl.ioctl(device.fileno(), 0xAE01, 0)
                os.close(guest_fd)
        except OSError as exc:
            raise LabError("KVM inaccessible: use hosted-runner device-group gate") from exc
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "only Linux x64 host is supported")
    host_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    require(os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux" and
            host_temp.is_absolute() and host_temp.is_dir() and
            not host_temp.is_symlink() and
            host_temp == Path("/home/runner/work/_temp") and
            workspace.parent == host_temp and
            workspace.is_absolute() and workspace.is_dir() and
            not workspace.is_symlink() and workspace.resolve() == workspace,
            "not an exclusively file-backed, hosted GitHub-runner temporary workspace")
    require(shutil.disk_usage(workspace).free > 25 * 1024**3,
            "insufficient free storage before official Windows download")
    for binary in ("qemu-img", "qemu-system-x86_64", "mkfs.vfat", "mcopy"):
        require(shutil.which(binary) is not None, f"required CI binary unavailable: {binary}")
    for name in (OVMF_CODE, OVMF_VARS):
        f = Path(name)
        require(f.is_file() and not f.is_symlink() and f.stat().st_size > 500_000,
                f"unsafe OVMF firmware file {name}")
    evidence = Path(os.environ.get("GASLUX_WINDOWS_EVIDENCE", ""))
    require(evidence.is_absolute() and evidence.is_dir() and
            not evidence.is_symlink() and evidence.resolve() == evidence and
            workspace not in evidence.parents and evidence != workspace,
            "separate pristine existing evidence directory required")


class MicrosoftOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow ISO redirects to an unexpected, non-Microsoft origin."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if (parsed.scheme != "https" or
                parsed.hostname not in EXPECTED_FINAL_HOSTS or
                parsed.username is not None or parsed.password is not None):
            raise LabError("Microsoft ISO redirect is not on an approved HTTPS endpoint")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download_verified_iso(profile: dict, destination: Path) -> tuple[str, int]:
    require(not destination.exists() and not destination.is_symlink(),
            "refusing to overwrite ISO")
    opener = urllib.request.build_opener(MicrosoftOnlyRedirect())
    req = urllib.request.Request(
        profile["downloadUrl"],
        headers={"User-Agent": "Gaslux-Disposable-ISO-Evaluation-Lab/1",
                 "Accept-Encoding": "identity"},
    )
    digest = hashlib.sha256()
    size = 0
    with opener.open(req, timeout=90) as response:
        final = urlparse(response.geturl())
        require(final.scheme == "https" and final.hostname in EXPECTED_FINAL_HOSTS,
                "final ISO download origin not Microsoft")
        with destination.open("xb") as file:
            while True:
                data = response.read(1024 * 1024)
                if not data:
                    break
                size += len(data)
                require(size <= MAX_ISO_SIZE, "unbounded Microsoft ISO response")
                digest.update(data)
                file.write(data)
            file.flush()
            os.fsync(file.fileno())
    expected = profile["sha256"]
    require(size >= MIN_ISO_SIZE and digest.hexdigest() == expected,
            "official Microsoft ISO size/hash mismatch; no VM may start")
    return digest.hexdigest(), size


def witness_powershell(profile_key: str, build: str) -> str:
    # Runs ONLY at FirstLogon in the installed Windows evaluation client.
    # The test-only local account has no usable remote credentials.
    return r'''
$ErrorActionPreference = 'Stop'
$ser = $null
try {
  $ser = [System.IO.Ports.SerialPort]::new('COM1',115200,[System.IO.Ports.Parity]::None,8,[System.IO.Ports.StopBits]::One)
  $ser.NewLine = "`n"
  $ser.Open()
  $os = Get-CimInstance -ClassName Win32_OperatingSystem
  if ([int]$os.ProductType -ne 1) { throw 'running OS is not Windows client' }
  if (-not [Environment]::Is64BitOperatingSystem) { throw 'not 64bit OS' }
  if (-not $os.BuildNumber.StartsWith('__BUILD__')) { throw 'unexpected Windows build' }
  $disk = Get-Disk -Number 0
  if ($disk.PartitionStyle -ne 'GPT') { throw 'installed target not GPT' }
  $parts = @(Get-Partition -DiskNumber 0)
  $esp = @($parts | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })
  if ($esp.Count -ne 1) { throw 'missing or multiple Windows ESP' }
  $recovery = @($parts | Where-Object { $_.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' })
  if ($recovery.Count -ne 1) { throw 'missing or multiple Windows Recovery GPT partitions' }
  $windowsPart = Get-Partition -DriveLetter C
  if ($windowsPart.DiskNumber -ne 0 -or $windowsPart.Offset -le $esp[0].Offset -or
      $recovery[0].Offset -lt ($windowsPart.Offset + $windowsPart.Size)) {
    throw 'unexpected Windows/ESP/WinRE partition order'
  }
  if (-not (Test-Path 'C:\Windows\System32\winload.efi')) { throw 'Windows EFI loader missing' }
  $bcd = & bcdedit /enum '{bootmgr}' 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'BCD boot manager enumeration failed' }
  $winre = & reagentc /info 2>&1
  $winreOk = ($LASTEXITCODE -eq 0 -and (($winre -join "`n") -match 'Windows RE status:\s+Enabled'))
  if (-not $winreOk) { throw 'WinRE is missing, disabled or unverifiable' }
  $serialProof = @(
    'GASLUX_WINDOWS_X64_BOOT_BUILD=' + $os.BuildNumber,
    'GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1',
    'GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1',
    'GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1',
    'GASLUX_WINDOWS_X64_BCD_ENUMERATED=1',
    'GASLUX_WINDOWS_X64_WINRE_ENABLED=1',
    '__MARKER__=__PROFILE__'
  )
  foreach ($line in $serialProof) { $ser.WriteLine($line); Start-Sleep -Milliseconds 100 }
} catch {
  if ($ser -and $ser.IsOpen) { $ser.WriteLine('GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL: guest audit rejected') }
} finally {
  if ($ser) { $ser.Close(); $ser.Dispose() }
}
Start-Sleep -Seconds 2
& "$env:WINDIR\System32\shutdown.exe" /s /f /t 0
'''.replace("__BUILD__", build).replace("__PROFILE__", profile_key).replace(
        "__MARKER__", MARKER).strip()


def generate_unattend(profile_key: str, build: str) -> bytes:
    # Windows Setup owns disk partitioning, but can only see the ONE new
    # file-backed QCOW2 and its read-only installer ISO/floppy. Never a host disk.
    ns = "urn:schemas-microsoft-com:unattend"
    wcm = "http://schemas.microsoft.com/WMIConfig/2002/State"
    ET.register_namespace("", ns)
    ET.register_namespace("wcm", wcm)

    def tag(name: str) -> str:
        return "{" + ns + "}" + name

    def child(parent: ET.Element, name: str, val: str | None = None,
              attrs: dict | None = None) -> ET.Element:
        x = ET.SubElement(parent, tag(name), attrs or {})
        if val is not None:
            x.text = val
        return x

    def component(parent: ET.Element, name: str) -> ET.Element:
        return child(parent, "component", attrs={
            "name": name, "processorArchitecture": "amd64",
            "publicKeyToken": "31bf3856ad364e35",
            "language": "neutral", "versionScope": "nonSxS",
        })

    root = ET.Element(tag("unattend"))
    pe = child(root, "settings", attrs={"pass": "windowsPE"})
    intl = component(pe, "Microsoft-Windows-International-Core-WinPE")
    lang = child(intl, "SetupUILanguage")
    child(lang, "UILanguage", "en-US")
    for setting in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        child(intl, setting, "en-US")
    setup = component(pe, "Microsoft-Windows-Setup")
    disk_cfg = child(setup, "DiskConfiguration")
    disk = child(disk_cfg, "Disk", attrs={f"{{{wcm}}}action": "add"})
    child(disk, "DiskID", "0")
    child(disk, "WillWipeDisk", "true")
    create = child(disk, "CreatePartitions")
    # Microsoft GPT layout: ESP, MSR, Windows NTFS, dedicated NTFS WinRE.
    # The remaining unallocated space is reserved for a later *independent*
    # Linux-only VM validation; no Windows partition must be shrunk here.
    for n, typ, size in ((1, "EFI", "260"), (2, "MSR", "16"),
                         (3, "Primary", str(WINDOWS_PRIMARY_MB)),
                         (4, "Primary", str(WINRE_PARTITION_MB))):
        part = child(create, "CreatePartition", attrs={f"{{{wcm}}}action": "add"})
        child(part, "Order", str(n))
        child(part, "Type", typ)
        if size is not None:
            child(part, "Size", size)
        else:
            child(part, "Extend", "true")
    modify = child(disk, "ModifyPartitions")
    # Microsoft Unattend: Order is the SEQUENTIAL *modification index*,
    # not PartitionID. Skip the MSR partition (which cannot be modified)
    # without leaving an Order gap.
    for order, (partition_id, fs, label) in enumerate(
        ((1, "FAT32", "GASLUXCIESP"),
         (3, "NTFS", "GASLUXWIN"),
         (4, "NTFS", "GASLUXWINRE")), start=1
    ):
        part = child(modify, "ModifyPartition", attrs={f"{{{wcm}}}action": "add"})
        child(part, "Order", str(order))
        child(part, "PartitionID", str(partition_id))
        child(part, "Format", fs)
        child(part, "Label", label)
        if partition_id == 4:
            # Microsoft's mandatory Windows Recovery Tools GPT partition ID.
            # Do not invent unsupported unattend GPT attributes; only
            # Windows Setup may populate this disposable recovery volume.
            child(part, "TypeID",
                  "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC")
    child(disk_cfg, "WillShowUI", "OnError")
    install = child(setup, "ImageInstall")
    osimage = child(install, "OSImage")
    from_iso = child(osimage, "InstallFrom")
    md = child(from_iso, "MetaData", attrs={f"{{{wcm}}}action": "add"})
    child(md, "Key", "/IMAGE/INDEX")
    child(md, "Value", "1")
    into = child(osimage, "InstallTo")
    child(into, "DiskID", "0")
    child(into, "PartitionID", "3")
    child(osimage, "WillShowUI", "OnError")
    user = child(setup, "UserData")
    child(user, "AcceptEula", "true")
    child(user, "FullName", "Gaslux disposable VM CI")
    child(user, "Organization", "Gaslux Lab - evaluation only")
    oobe = child(root, "settings", attrs={"pass": "oobeSystem"})
    shell = component(oobe, "Microsoft-Windows-Shell-Setup")
    child(shell, "TimeZone", "UTC")
    conf = child(shell, "OOBE")
    for name in ("HideEULAPage", "HideOnlineAccountScreens",
                 "HideWirelessSetupInOOBE"):
        child(conf, name, "true")
    child(conf, "NetworkLocation", "Work")
    child(conf, "ProtectYourPC", "3")
    accounts = child(shell, "UserAccounts")
    locals_ = child(accounts, "LocalAccounts")
    local = child(locals_, "LocalAccount", attrs={f"{{{wcm}}}action": "add"})
    child(local, "Name", "GasluxDisposableCI")
    child(local, "DisplayName", "Gaslux disposable CI only")
    child(local, "Group", "Administrators")
    password = child(local, "Password")
    child(password, "Value", "GasluxOnlyLocalDisposable2026!")
    child(password, "PlainText", "true")
    login = child(shell, "AutoLogon")
    child(login, "Enabled", "true")
    child(login, "LogonCount", "1")
    child(login, "Username", "GasluxDisposableCI")
    pw = child(login, "Password")
    child(pw, "Value", "GasluxOnlyLocalDisposable2026!")
    child(pw, "PlainText", "true")
    commands = child(shell, "FirstLogonCommands")
    command = child(commands, "SynchronousCommand", attrs={f"{{{wcm}}}action": "add"})
    child(command, "Order", "1")
    child(command, "Description", "Gaslux first boot serial verification")
    # FirstLogonCommands must remain short. Base64-encoding a full witness
    # makes the setup XML command longer than Windows command-line limits.
    # Only a hash-checked, VM-exclusive floppy is available to Windows.
    child(command, "CommandLine", "powershell.exe -NoProfile -NonInteractive "
          "-ExecutionPolicy Bypass -File A:\\GASLUX.PS1")
    child(command, "RequiresUserInput", "false")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)



BOOT_FROM_CD_PROMPT = b"Press any key to boot from CD or DVD"
WINDOWS11_DVD_BOOT_START = b'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM'


def send_first_iso_boot_key(monitor_path: Path, hold_ms: int = 300) -> None:
    """Exactly one QEMU HMP Enter keystroke, to boot the official ISO initially.

    Never send subsequent keys: Windows Setup must reboot autonomously from
    the installed disk. The local Unix HMP socket belongs to the fresh
    0700-permission GitHub-hosted VM temporary directory, never the network.
    """
    require(hold_ms in (300, 6000), "unapproved firmware boot-key duration")
    require(monitor_path.is_absolute() and monitor_path.is_socket() and
            not monitor_path.is_symlink() and
            monitor_path.parent.name.startswith("gaslux-win-x64-") and
            monitor_path.parent.parent == Path("/home/runner/work/_temp"),
            "refusing boot input through an unowned QEMU monitor socket")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
            monitor.settimeout(2)
            monitor.connect(str(monitor_path))
            # HMP emits an initial banner. Consume at most 8 KiB.
            banner = monitor.recv(8192)
            require(b"QEMU" in banner or b"(qemu)" in banner,
                    "unexpected guest monitor protocol banner")
            monitor.sendall(f"sendkey ret {hold_ms}\n".encode("ascii"))
            response = monitor.recv(8192)
            require(b"unknown command" not in response.lower() and
                    b"error:" not in response.lower(),
                    "QEMU refused initial ISO boot key")
    except (TimeoutError, OSError) as exc:
        raise LabError("QEMU HMP failed to deliver initial ISO boot key") from exc


def send_first_iso_boot_key_vnc(monitor_path: Path, hold_ms: int = 300) -> None:
    """Send exactly one local RFB Return key down/up to an isolated QEMU guest.

    The synthetic GRUB EFI witness in the parent PR proved this delivery
    route; an actual Windows firstboot witness is STILL required. Only
    GitHub-hosted KVM and an owned ephemeral HMP socket may authorize input.
    """
    require(hold_ms in (300, 6000), "unapproved firmware boot-key duration")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux",
            "VNC firmware input restricted to hosted GitHub VM laboratory")
    require(monitor_path.is_absolute() and monitor_path.is_socket() and
            not monitor_path.is_symlink() and
            monitor_path.parent.name.startswith("gaslux-win-x64-") and
            monitor_path.parent.parent == Path("/home/runner/work/_temp"),
            "refusing VNC input for an unowned QEMU monitor")

    def receive_exact(conn, count: int) -> bytes:
        result = b""
        while len(result) != count:
            data = conn.recv(count - len(result))
            if not data:
                raise LabError("loopback RFB server disconnected early")
            result += data
        return result

    try:
        # 5979 is QEMU display :79. No Internet, VNC listener is loopback-only.
        with socket.create_connection(("127.0.0.1", 5979), timeout=5) as conn:
            conn.settimeout(5)
            version = receive_exact(conn, 12)
            require(version == b"RFB 003.008\n", "unexpected RFB protocol")
            conn.sendall(version)
            count = receive_exact(conn, 1)[0]
            require(0 < count <= 8, "invalid RFB security option count")
            options = receive_exact(conn, count)
            require(1 in options, "RFB loopback security negotiation refused")
            conn.sendall(b"\x01")  # RFB SecurityType None (localhost only).
            require(receive_exact(conn, 4) == b"\x00" * 4,
                    "RFB security negotiation failed")
            conn.sendall(b"\x01")  # shared framebuffer session
            server_init = receive_exact(conn, 24)
            name_length = struct.unpack(">I", server_init[20:24])[0]
            require(0 < name_length <= 1024, "unexpected RFB desktop identity")
            receive_exact(conn, name_length)
            conn.sendall(struct.pack(">BBHI", 4, 1, 0, 0xFF0D))
            time.sleep(hold_ms / 1000)
            conn.sendall(struct.pack(">BBHI", 4, 0, 0, 0xFF0D))
    except (TimeoutError, OSError) as exc:
        raise LabError("QEMU local RFB failed to deliver initial ISO Return") from exc


def capture_vm_screen(monitor_path: Path, destination: Path) -> str:
    """Read-only framebuffer diagnostic; not evidence of Windows boot."""
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux",
            "GUI capture restricted to hosted Linux runner")
    require(monitor_path.is_absolute() and monitor_path.is_socket() and
            not monitor_path.is_symlink() and
            monitor_path.parent.name.startswith("gaslux-win-x64-") and
            monitor_path.parent.parent == Path("/home/runner/work/_temp"),
            "refusing unowned QEMU diagnostic monitor")
    require(destination.parent == monitor_path.parent and
            destination.name in ("windows-dvd-90s.ppm", "windows-dvd-180s.ppm") and
            not destination.exists() and not destination.is_symlink() and
            stat.S_IMODE(destination.parent.stat().st_mode) == 0o700,
            "refusing unowned framebuffer destination")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
            monitor.settimeout(5)
            monitor.connect(str(monitor_path))
            banner = monitor.recv(8192)
            require(b"QEMU" in banner or b"(qemu)" in banner,
                    "unexpected QEMU HMP monitor")
            # HMP screendump only reads the VM display: no input or disk writes.
            monitor.sendall(f"screendump {destination}\n".encode("ascii"))
            response = monitor.recv(8192)
            require(b"Error:" not in response and b"unknown command" not in response,
                    "QEMU refused read-only screendump")
        for _ in range(40):
            if destination.is_file() and destination.stat().st_size > 100:
                break
            time.sleep(.1)
        require(destination.is_file() and not destination.is_symlink(),
                "missing QEMU framebuffer")
        require(100 < destination.stat().st_size <= 20 * 1024**2,
                "unexpected QEMU framebuffer size")
        with destination.open("rb") as stream:
            require(stream.read(2) == b"P6", "unexpected QEMU framebuffer format")
        return hashlib.sha256(destination.read_bytes()).hexdigest()
    except (TimeoutError, OSError) as exc:
        raise LabError("QEMU read-only screendump failed") from exc


def boot_vm(args: list[str], transcript: Path, limit: int,
            profile_key: str, monitor_socket: Path | None = None,
            boot_key_transport: str = "hmp",
            diagnostic_dir: Path | None = None) -> tuple[bool, str]:
    """Require a real Windows client serial witness AND a clean guest poweroff.

    A serial marker alone is not boot durability. The real guest-side script
    requests ACPI Windows shutdown after the read-only audit, and QEMU must
    exit successfully before the host may claim a clean installed firstboot.
    """
    require(boot_key_transport in ("hmp", "vnc"), "unknown ISO boot input route")
    if boot_key_transport == "vnc":
        require(monitor_socket is not None, "VNC boot key requires owned monitor")
    send_boot_key = (send_first_iso_boot_key_vnc if boot_key_transport == "vnc"
                     else send_first_iso_boot_key)
    build_by_profile = {
        "win10_22h2_en_us_x64": "19045",
        "win11_26h2_en_us_x64": "26300",
    }
    if profile_key not in build_by_profile:
        raise LabError("unknown client profile")
    required = {
        f"{MARKER}={profile_key}".encode(),
        b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
        b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
        b"GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1",
        b"GASLUX_WINDOWS_X64_WINRE_ENABLED=1",
        b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
    }
    build_line = ("GASLUX_WINDOWS_X64_BOOT_BUILD=" +
                  build_by_profile[profile_key]).encode()
    started = time.monotonic()
    witnessed_at: float | None = None
    initial_cd_key_sent = False
    win11_dvd_started_at: float | None = None
    initial_cd_key_at: float | None = None
    captured_times: set[int] = set()
    with (transcript.parent / "qemu-stderr.log").open("xb") as err:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
        try:
            while time.monotonic() - started < limit:
                if transcript.is_file():
                    with transcript.open("rb") as source:
                        source.seek(max(0, transcript.stat().st_size - 400_000))
                        serial_data = source.read(400_000)
                        lines = {
                            line.strip() for line in serial_data.splitlines()
                        }
                    if monitor_socket is not None and not initial_cd_key_sent:
                        if BOOT_FROM_CD_PROMPT in serial_data:
                            send_boot_key(monitor_socket)
                            initial_cd_key_sent = True
                            initial_cd_key_at = time.monotonic()
                            print("GASLUX_VM_INITIAL_OFFICIAL_ISO_PROMPT_KEY_SENT=1",
                                  flush=True)
                        elif (profile_key == "win11_26h2_en_us_x64" and
                              WINDOWS11_DVD_BOOT_START in serial_data):
                            if win11_dvd_started_at is None:
                                win11_dvd_started_at = time.monotonic()
                            # Genuine official Windows 11 ISO emitted firmware
                            # DVD startup, but not a visible serial prompt.
                            # Hold ONE Enter through its VGA-only prompt.
                            if time.monotonic() - win11_dvd_started_at >= 1:
                                send_boot_key(monitor_socket, hold_ms=6000)
                                initial_cd_key_sent = True
                                initial_cd_key_at = time.monotonic()
                                print("GASLUX_VM_INITIAL_OFFICIAL_WIN11_DVD_KEY_SENT=1",
                                      flush=True)
                    if any(line.startswith(FAILURE.encode()) for line in lines):
                        return False, "installed Windows explicitly rejected firstboot audit"
                    if required.issubset(lines) and any(
                        line.startswith(build_line) for line in lines
                    ):
                        if witnessed_at is None:
                            witnessed_at = time.monotonic()
                if (diagnostic_dir is not None and monitor_socket is not None
                        and initial_cd_key_at is not None):
                    for seconds in (90, 180):
                        if (seconds not in captured_times and
                                time.monotonic() - initial_cd_key_at >= seconds):
                            captured_times.add(seconds)
                            screenshot = diagnostic_dir / f"windows-dvd-{seconds}s.ppm"
                            try:
                                digest = capture_vm_screen(monitor_socket, screenshot)
                                print(f"GASLUX_VM_READONLY_SCREEN_{seconds}S_SHA256={digest}",
                                      flush=True)
                            except LabError as exc:
                                print(f"GASLUX_VM_SCREEN_DIAGNOSTIC_FAILED: {exc}",
                                      file=sys.stderr, flush=True)
                rc = proc.poll()
                if rc is not None:
                    if witnessed_at is not None and rc == 0:
                        return True, "installed Windows client audit and clean VM poweroff verified"
                    if witnessed_at is not None:
                        return False, "QEMU exited abnormally after Windows audit"
                    return False, "QEMU exited before installed Windows first-logon witness"
                if (monitor_socket is not None and not initial_cd_key_sent and
                        time.monotonic() - started > 300):
                    return False, "official ISO did not reach UEFI DVD boot or serial prompt"
                if witnessed_at is not None and (
                    time.monotonic() - witnessed_at > 600
                ):
                    return False, "installed Windows reported audit but did not power off cleanly"
                time.sleep(0.1 if monitor_socket is not None and not initial_cd_key_sent else 10)
            return False, "timed out before verified Windows guest audit and shutdown"
        finally:
            if proc.poll() is None:
                proc.kill()  # Only ephemeral QEMU process; never the host disk.
                proc.wait(timeout=30)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=sorted(EXPECTED), required=True)
    ap.add_argument("--fixture-only", action="store_true",
                    help="generate/validate ONLY XML, no download or VM")
    ap.add_argument("--boot-timeout", type=int, default=6300)
    ap.add_argument("--accel", choices=("tcg", "kvm"), default="tcg",
                    help="KVM only after isolated GitHub-hosted kernel VM gate")
    ap.add_argument("--vnc-dvd-enter", action="store_true",
                    help="hosted KVM-only: deliver the original Microsoft DVD prompt Return via loopback RFB")
    ap.add_argument("--diagnostic-screens", action="store_true",
                    help="collect GUI evidence from disposable VM; not boot proof")
    args = ap.parse_args(argv)
    if args.vnc_dvd_enter and args.accel != "kvm":
        raise SystemExit("loopback VNC EFI input requires hosted disposable KVM")
    if args.diagnostic_screens and not (args.vnc_dvd_enter and args.accel == "kvm"):
        raise SystemExit("GUI screenshots require isolated KVM with owned VNC")
    catalog = load_catalog()
    profile = catalog["profiles"][args.profile]
    xml = generate_unattend(args.profile, profile["expectedWindowsBuildPrefix"])
    root = ET.fromstring(xml)
    if args.fixture_only:
        print(json.dumps({
            "ok": True, "profile": args.profile, "xmlBytes": len(xml),
            "windowsClientBootVerified": False, "dualBootVerified": False,
        }))
        return 0
    evidence = Path(os.environ.get("GASLUX_WINDOWS_EVIDENCE", ""))
    report = {
        "profile": args.profile, "accelerator": args.accel, "isoHashVerified": False,
        "windowsClientBootVerified": False, "dualBootVerified": False,
        "winReAndBcdRecovered": False, "stable": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="gaslux-win-x64-", dir=os.environ["RUNNER_TEMP"]) as tmp:
            workspace = Path(tmp)
            validate_environment(workspace, args.accel)
            require(120 <= args.boot_timeout <= 6600,
                    "unbounded or insufficient guest boot timeout")
            iso = workspace / "verified-microsoft-evaluation.iso"
            iso_hash, iso_size = download_verified_iso(profile, iso)
            report.update(isoHashVerified=True, isoSha256=iso_hash,
                          isoSizeBytes=iso_size)
            print("GASLUX_WINDOWS_EVAL_ISO_MICROSOFT_SHA256_VERIFIED=1", flush=True)
            xmlfile = workspace / "Autounattend.xml"
            xmlfile.write_bytes(xml)
            guest_ps1 = workspace / "GASLUX.PS1"
            guest_ps1.write_text(
                witness_powershell(args.profile,
                                   profile["expectedWindowsBuildPrefix"]) + "\n",
                encoding="utf-8")
            report["firstLogonScriptSha256"] = hashlib.sha256(
                guest_ps1.read_bytes()).hexdigest()
            floppy = workspace / "unattend-floppy.img"
            subprocess.run(["truncate", "-s", "1440K", str(floppy)], check=True)
            subprocess.run(["mkfs.vfat", "-F", "12", "-n", "GASLUXCI", str(floppy)],
                           check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["mcopy", "-i", str(floppy), str(xmlfile),
                            "::/Autounattend.xml"], check=True)
            subprocess.run(["mcopy", "-i", str(floppy), str(guest_ps1),
                            "::/GASLUX.PS1"], check=True)
            disk = workspace / "only-disposable-windows-target.qcow2"
            require(not disk.exists(), "refuse to reuse an existing Windows disk")
            subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), VM_SIZE],
                           check=True, stdout=subprocess.DEVNULL)
            code = Path(OVMF_CODE)
            nvram = workspace / "ovmf-variables.fd"
            shutil.copyfile(OVMF_VARS, nvram)
            serial = workspace / "win-guest-serial.log"
            monitor_path = workspace / "initial-installer-hmp.sock"
            require(not monitor_path.exists() and not monitor_path.is_symlink(),
                    "refusing existing QEMU control socket")
            base = [
                "qemu-system-x86_64", "-machine",
                ("q35,accel=kvm,smm=on" if args.accel == "kvm"
                 else "q35,accel=tcg,smm=on"),
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-cpu", ("host" if args.accel == "kvm" else "max"),
                "-smp", "2", "-m", "4096",
                "-display", ("vnc=127.0.0.1:79" if args.vnc_dvd_enter else "none"),
                "-vga", "std",
                "-monitor", f"unix:{monitor_path},server,nowait", "-net", "none",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={nvram}",
                # Explicit USB keyboard input is required in headless OVMF.
                # A QEMU HMP 'sendkey' command being accepted does NOT prove
                # that the guest firmware received the keystroke.
                "-device", "qemu-xhci,id=lab_usb",
                "-device", "usb-kbd,bus=lab_usb.0",
                "-device", "ich9-ahci,id=lab_sata",
                "-drive", f"if=none,id=only_windows,format=qcow2,file={disk}",
                "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
                "-drive", f"if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file={iso}",
                "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
                "-drive", f"if=floppy,format=raw,file={floppy}",
                "-serial", f"file:{serial}",
                "-boot", "order=dc",
            ]
            tpm = None
            if args.profile.startswith("win11"):
                require(shutil.which("swtpm") is not None, "Windows 11 requires TPM 2.0")
                state = workspace / "swtpm-state"
                state.mkdir()
                socket = workspace / "swtpm.sock"
                tpm = subprocess.Popen(
                    ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
                     "--ctrl", f"type=unixio,path={socket}",
                     "--flags", "not-need-init"],
                    stdout=subprocess.DEVNULL,
                    stderr=(workspace / "swtpm-stderr.log").open("xb"),
                )
                for _ in range(50):
                    if socket.is_socket():
                        break
                    time.sleep(.1)
                require(socket.is_socket(), "QEMU TPM 2.0 socket missing")
                base.extend(["-chardev", f"socket,id=chrtpm,path={socket}",
                             "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                             "-device", "tpm-tis,tpmdev=tpm0"])
            try:
                ok, diagnostic = boot_vm(base, serial, args.boot_timeout,
                                         args.profile, monitor_socket=monitor_path,
                                         boot_key_transport=("vnc" if args.vnc_dvd_enter else "hmp"),
                                         diagnostic_dir=(workspace if args.diagnostic_screens
                                                         else None))
                report["windowsClientBootVerified"] = ok
                report["diagnostic"] = diagnostic
            finally:
                if tpm:
                    tpm.terminate()
                    tpm.wait(timeout=10)
            if serial.is_file():
                dest = evidence / f"{args.profile}-serial.log"
                require(not dest.exists(), "existing evidence log")
                shutil.copyfile(serial, dest)
                with dest.open("rb") as logstream:
                    digest = hashlib.file_digest(logstream, "sha256").hexdigest()
                (evidence / f"{args.profile}-serial.sha256").write_text(
                    f"{digest}  {dest.name}\n", encoding="ascii")
            if not ok:
                raise LabError(diagnostic)
    except (LabError, OSError, subprocess.CalledProcessError, ValueError,
            TimeoutError) as exc:
        report["error"] = str(exc)
        print(f"GASLUX_WINDOWS_X64_TCG_LAB_FAILURE: {exc}", file=sys.stderr)
        status = 1
    else:
        status = 0
    # On any preflight failure, never create report paths outside the
    # authorization-controlled GitHub Actions evidence directory.
    if (evidence.is_absolute() and evidence.is_dir() and
            not evidence.is_symlink() and evidence.resolve() == evidence and
            evidence.name == "windows-x64-tcg-evidence"):
        report_path = evidence / f"{args.profile}-result.json"
        if not report_path.exists() and not report_path.is_symlink():
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
