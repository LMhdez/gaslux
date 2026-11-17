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
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable
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


def derive_no_prompt_uefi_lab_iso(original: Path, derived: Path,
                                  workspace: Path) -> str:
    """Rebuild *lab-only* EFI CD from verified official media, avoiding DVD key UI.

    The derivative has a NEW SHA-256. It MUST NOT masquerade as Microsoft's
    pinned original ISO and MUST NOT be used by the production installer.
    Both ISO files are ephemeral regular files owned by a hosted CI runner.
    """
    require(
        original.is_file() and not original.is_symlink()
        and original.parent == workspace
        and derived.parent == workspace
        and not derived.exists() and not derived.is_symlink()
        and workspace.name.startswith("gaslux-win-x64-")
        and workspace.parent == Path("/home/runner/work/_temp")
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GASLUX_WINDOWS_KVM_CONSENT")
        == "I_ACCEPT_DISPOSABLE_GITHUB_KVM_ONLY",
        "derived EFI boot media is forbidden outside an isolated hosted CI lab",
    )
    for command in ("7z", "genisoimage"):
        require(shutil.which(command) is not None,
                f"lab-only UDF remaster dependency missing: {command}")
    unpacked = workspace / "unpacked-official-microsoft-iso"
    require(not unpacked.exists() and not unpacked.is_symlink(),
            "refusing to reuse an extracted Windows ISO directory")
    unpacked.mkdir(mode=0o700)
    subprocess.run(["7z", "x", "-bd", "-y", f"-o{unpacked}", str(original)],
                   stdout=subprocess.DEVNULL, check=True, timeout=600)
    require((unpacked / "sources" / "boot.wim").is_file()
            and ((unpacked / "sources" / "install.wim").is_file()
                 or (unpacked / "sources" / "install.esd").is_file()),
            "official Windows ISO Setup boot/install payloads are missing")
    choices = [
        p for p in unpacked.rglob("efisys_noprompt.bin")
        if tuple(name.lower() for name in p.relative_to(unpacked).parts)
        == ("efi", "microsoft", "boot", "efisys_noprompt.bin")
        and p.is_file() and not p.is_symlink()
    ]
    require(len(choices) == 1 and
            4_096 <= choices[0].stat().st_size <= 32 * 1024**2,
            "official ISO has no unique genuine no-prompt UEFI El Torito image")
    boot_image = choices[0].relative_to(unpacked).as_posix()
    subprocess.run([
        "genisoimage", "-quiet", "-udf", "-allow-limited-size",
        "-iso-level", "3", "-J", "-joliet-long",
        "-V", "GASLUX_VM_EVAL", "-e", boot_image, "-no-emul-boot",
        "-o", str(derived), str(unpacked),
    ], check=True, timeout=900)
    require(derived.is_file() and not derived.is_symlink()
            and derived.stat().st_size >= original.stat().st_size // 2,
            "derived lab UEFI DVD image is missing or unexpectedly truncated")
    with derived.open("rb") as fd:
        return hashlib.file_digest(fd, "sha256").hexdigest()


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
    ('GASLUX_WINDOWS_X64_BOOT_BUILD=' + $os.BuildNumber)
    'GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1'
    'GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1'
    'GASLUX_WINDOWS_X64_RECOVERY_GPT_COUNT=1'
    'GASLUX_WINDOWS_X64_BCD_ENUMERATED=1'
    'GASLUX_WINDOWS_X64_WINRE_ENABLED=1'
    '__MARKER__=__PROFILE__'
  )
  if (@($serialProof).Count -ne 7) { throw 'guest serial proof array invalid' }
  foreach ($line in $serialProof) {
    if ($line -isnot [string] -or $line -match '\s') {
      throw 'guest serial marker is not a standalone token'
    }
    $ser.WriteLine($line)
    Start-Sleep -Milliseconds 100
  }
} catch {
  if ($ser -and $ser.IsOpen) { $ser.WriteLine('GASLUX_WINDOWS_X64_FIRSTBOOT_FAIL: guest audit rejected') }
} finally {
  if ($ser) { $ser.Close(); $ser.Dispose() }
}
Start-Sleep -Seconds 2
& "$env:WINDIR\System32\shutdown.exe" /s /f /t 0
'''.replace("__BUILD__", build).replace("__PROFILE__", profile_key).replace(
        "__MARKER__", MARKER).strip()


def usb_firstlogon_command(profile_key: str, build: str) -> str:
    """Resolve only the unique FAT32 lab answer volume and hash-pin its script.

    The proven historical FAT12 fixture boots from A:, but a QEMU xHCI USB
    mass-storage volume is NOT A:. The isolated Windows guest must locate its
    own volume by the exact GASLUXCI label and verify the bytes it will run.
    The script is itself the existing in-guest firstboot/BCD/WinRE witness.
    """
    payload = (witness_powershell(profile_key, build) + "\n").encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()
    command = (
        'powershell -NoP -EP Bypass -C "'
        '$v=Get-Volume -FileSystemLabel GASLUXCI;'
        # A single volume is mandatory; other/missing labels fail closed.
        # Powershell's PATH-resolved .exe keeps this under the Setup limit.
        'if($v.Count-ne 1){throw};'
        "$p=$v.DriveLetter+':\\GASLUX.PS1';"
        "if((Get-FileHash $p).Hash-ne '" + sha256 + "'){throw};&$p\""
    )
    require(len(command) < 240, "USB firstlogon command exceeds Setup limit")
    return command


def generate_unattend(profile_key: str, build: str, *,
                      usb_answer: bool = False) -> bytes:
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
    # The WinPE locale is not inherited by OOBE. Without this separate
    # International-Core component the installed guest can stop at the
    # interactive region/keyboard pages, never reaching FirstLogonCommands.
    # Microsoft: /windows-hardware/customize/desktop/automate-oobe
    international = component(oobe, "Microsoft-Windows-International-Core")
    for setting in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        child(international, setting, "en-US")
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
    # The old FAT12 baseline must remain unchanged; USB mass storage is
    # mounted under a dynamic drive letter, never the A: floppy path.
    if usb_answer:
        child(command, "CommandLine",
              usb_firstlogon_command(profile_key, build))
    else:
        child(command, "CommandLine", "powershell.exe -NoProfile -NonInteractive "
              "-ExecutionPolicy Bypass -File A:\\GASLUX.PS1")
    child(command, "RequiresUserInput", "false")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def validate_oobe_answer_pass(xml: bytes) -> None:
    """Fail closed if the installed Windows locale/OOBE pass is incomplete.

    An answer file containing only WinPE locale can install Windows but then
    leave the OOBE region screen interactive. Never interpret Setup progress
    as proof that the installed guest applied oobeSystem settings.
    """
    root = ET.fromstring(xml)
    ns = "{urn:schemas-microsoft-com:unattend}"
    passes = [p for p in root.findall(f"{ns}settings")
              if p.attrib.get("pass") == "oobeSystem"]
    require(len(passes) == 1, "missing or ambiguous Windows oobeSystem pass")
    components = passes[0].findall(f"{ns}component")
    international = [c for c in components
                     if c.attrib.get("name") == "Microsoft-Windows-International-Core"]
    shell = [c for c in components
             if c.attrib.get("name") == "Microsoft-Windows-Shell-Setup"]
    require(len(international) == 1 and len(shell) == 1,
            "missing/duplicate Windows OOBE locale or shell setup")
    for key in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        vals = international[0].findall(f"{ns}{key}")
        require(len(vals) == 1 and vals[0].text == "en-US",
                f"Windows OOBE {key} must be set before boot")
    require(shell[0].find(f"{ns}UserAccounts/{ns}LocalAccounts/{ns}LocalAccount")
            is not None and
            shell[0].find(f"{ns}AutoLogon/{ns}Enabled") is not None and
            shell[0].find(f"{ns}FirstLogonCommands/{ns}SynchronousCommand")
            is not None, "Windows OOBE requires local CI user, logon and audit")
    require(not any(element.tag in (f"{ns}SkipMachineOOBE", f"{ns}SkipUserOOBE")
                    for element in root.iter()),
            "unsupported Windows OOBE skip directives are prohibited")


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


def boot_vm(args: list[str], transcript: Path, limit: int,
            profile_key: str, monitor_socket: Path | None = None,
            reject_repeated_dvd_boot: bool = False) -> tuple[bool, str]:
    """Require a real Windows client serial witness AND a clean guest poweroff.

    A serial marker alone is not boot durability. The real guest-side script
    requests ACPI Windows shutdown after the read-only audit, and QEMU must
    exit successfully before the host may claim a clean installed firstboot.
    """
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
                    if reject_repeated_dvd_boot:
                        dvd_starts = re.findall(
                            rb'BdsDxe: starting Boot[0-9]{4} "UEFI QEMU DVD-ROM',
                            serial_data,
                        )
                        if len(dvd_starts) > 1:
                            return False, (
                                "firmware retried one-shot Microsoft DVD after "
                                "initial startup; abort disposable VM"
                            )
                    if monitor_socket is not None and not initial_cd_key_sent:
                        if BOOT_FROM_CD_PROMPT in serial_data:
                            send_first_iso_boot_key(monitor_socket)
                            initial_cd_key_sent = True
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
                                send_first_iso_boot_key(monitor_socket, hold_ms=6000)
                                initial_cd_key_sent = True
                                print("GASLUX_VM_INITIAL_OFFICIAL_WIN11_DVD_KEY_SENT=1",
                                      flush=True)
                    if any(line.startswith(FAILURE.encode()) for line in lines):
                        return False, "installed Windows explicitly rejected firstboot audit"
                    if required.issubset(lines) and any(
                        line.startswith(build_line) for line in lines
                    ):
                        if witnessed_at is None:
                            witnessed_at = time.monotonic()
                rc = proc.poll()
                if rc is not None:
                    if witnessed_at is not None and rc == 0:
                        return True, "installed Windows client audit and clean VM poweroff verified"
                    if witnessed_at is not None:
                        return False, "QEMU exited abnormally after Windows audit"
                    return False, (f"QEMU exited before installed Windows first-logon witness "
                                   f"(QEMU exit code {rc}; Windows still unverified)")
                if (monitor_socket is not None and not initial_cd_key_sent and
                        time.monotonic() - started > 300):
                    return False, "official ISO did not reach UEFI DVD boot or serial prompt"
                if witnessed_at is not None and (
                    time.monotonic() - witnessed_at > 600
                ):
                    return False, "installed Windows reported audit but did not power off cleanly"
                time.sleep(0.1 if monitor_socket is not None and not initial_cd_key_sent
                           else (1 if reject_repeated_dvd_boot else 10))
            return False, "timed out before verified Windows guest audit and shutdown"
        finally:
            if proc.poll() is None:
                proc.kill()  # Only ephemeral QEMU process; never the host disk.
                proc.wait(timeout=30)


def build_two_stage_qemu_args(
    original: list[str], initial_serial: Path,
) -> tuple[list[str], list[str]]:
    """Return independent VM arguments: DVD first, then strictly disk-only."""
    first = list(original)
    second = list(original)
    require(first.count("-boot") == 1 and first.count("-serial") == 1
            and first.count("-monitor") == 1,
            "ambiguous QEMU VM boot/serial/monitor options")
    for args, boot, serial in (
        (first, "order=d", initial_serial),
        (second, "order=c", Path(original[original.index("-serial") + 1][5:])),
    ):
        args[args.index("-boot") + 1] = boot
        args[args.index("-serial") + 1] = "file:" + str(serial)
        # Neither VM uses headless HMP keyboard injection. No stale QEMU
        # Unix monitor socket can be inherited between guests.
        args[args.index("-monitor") + 1] = "none"
    dvd_ids = (
        ("-drive", "if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file="),
        ("-device", "ide-cd,drive=verified_iso,bus=lab_sata.1"),
    )
    for flag, pattern in dvd_ids:
        matches = [
            i for i in range(len(second) - 1)
            if second[i] == flag and second[i + 1].startswith(pattern)
        ]
        require(len(matches) == 1, "missing/ambiguous disposable ISO device")
        i = matches[0]
        del second[i:i + 2]
    first.append("-no-reboot")
    require(
        all("verified_iso" not in arg for arg in second)
        and all(not (arg.startswith("file=") and arg.endswith(".iso")) for arg in second)
        and "order=c" in second
        and "order=d" in first,
        "second-stage Windows VM still exposes the installer DVD",
    )
    return first, second


def restart_owned_swtpm_for_second_guest(
    first_process: subprocess.Popen, workspace: Path,
) -> subprocess.Popen:
    """Reconnect TPM 2.0 to a second QEMU process, preserving the SAME NV state.

    swtpm's Unix control listener can terminate when QEMU -no-reboot closes.
    Reusing its stale socket breaks Windows 11 at QEMU process startup. Never
    remove the TPM state directory or import an unrelated process/socket.
    """
    state_dir = workspace / "swtpm-state"
    endpoint = workspace / "swtpm.sock"
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and workspace.is_absolute()
        and workspace.parent == Path("/home/runner/work/_temp")
        and workspace.name.startswith("gaslux-win-x64-")
        and workspace.is_dir() and not workspace.is_symlink()
        and workspace.resolve() == workspace
        and workspace.stat().st_uid == os.getuid()
        and stat.S_IMODE(workspace.stat().st_mode) == 0o700
        and state_dir.is_dir() and not state_dir.is_symlink()
        and state_dir.stat().st_uid == os.getuid()
        and stat.S_IMODE(state_dir.stat().st_mode) == 0o700,
        "refusing TPM restart outside private owned hosted Windows VM",
    )
    # Never unlink files or sockets that an unrelated process could own.
    require(
        not endpoint.is_symlink()
        and (not endpoint.exists()
             or (endpoint.is_socket()
                 and endpoint.stat().st_uid == os.getuid())),
        "refusing to replace an unowned TPM socket",
    )
    if first_process.poll() is None:
        first_process.terminate()
    try:
        first_process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise LabError("first-stage swtpm did not exit cleanly") from exc
    if endpoint.exists():
        endpoint.unlink()  # Only a validated socket in our private 0700 VM dir.
    require(shutil.which("swtpm") is not None, "Windows 11 TPM 2.0 unavailable")
    stderr_path = workspace / "swtpm-second-stderr.log"
    with stderr_path.open("xb") as err:
        second = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state_dir}",
             "--ctrl", f"type=unixio,path={endpoint}",
             "--flags", "not-need-init"],
            stdout=subprocess.DEVNULL, stderr=err,
        )
    for _ in range(100):
        if second.poll() is not None:
            break
        if endpoint.is_socket() and not endpoint.is_symlink():
            require(endpoint.stat().st_uid == os.getuid(),
                    "second TPM socket owner mismatch")
            print("GASLUX_WINDOWS_VM_SECOND_TPM_SOCKET_RECONNECTED=1", flush=True)
            return second
        time.sleep(0.1)
    if second.poll() is None:
        second.terminate()
        second.wait(timeout=10)
    raise LabError("fresh second-stage swtpm listener unavailable")



DVD_FIRMWARE_START = re.compile(
    rb'BdsDxe: starting Boot[0-9A-Fa-f]{4} "UEFI QEMU DVD-ROM'
)
DVD_SCAN_CARRY_BYTES = 96


def scan_dvd_firmware_starts(chunk: bytes, carry: bytes = b"") -> tuple[int, bytes]:
    """Count full DVD boot markers even when firmware splits them across writes."""
    require(len(carry) <= DVD_SCAN_CARRY_BYTES, "invalid firmware scanner carry")
    data = carry + chunk
    found = sum(
        match.end() > len(carry) for match in DVD_FIRMWARE_START.finditer(data)
    )
    return found, data[-DVD_SCAN_CARRY_BYTES:]


def scan_two_stage_dvd_serial(
    path: Path, offset: int, carry: bytes,
) -> tuple[int, int, bytes, bytes]:
    """Incrementally scan *all* stage-one UEFI DVD starts, plus a bounded tail.

    Never use only the last 400 KiB to decide whether firmware reentered
    setup. No side effects except reading the disposable guest serial file.
    """
    require(offset >= 0 and len(carry) <= DVD_SCAN_CARRY_BYTES,
            "invalid stage-one DVD serial scanner")
    require(path.is_file() and not path.is_symlink(),
            "missing or untrusted initial guest serial")
    count = 0
    with path.open("rb") as stream:
        end = stream.seek(0, os.SEEK_END)
        require(end >= offset, "first Windows guest serial log was truncated")
        stream.seek(offset)
        while offset < end:
            chunk = stream.read(min(65536, end - offset))
            require(bool(chunk), "first Windows serial changed during scan")
            hits, carry = scan_dvd_firmware_starts(chunk, carry)
            count += hits
            offset += len(chunk)
        stream.seek(max(0, end - 400_000))
        tail = stream.read(400_000)
    return count, offset, carry, tail

def boot_two_stage_windows(
    original_args: list[str], disk: Path, final_serial: Path,
    limit: int, profile_key: str,
    restart_tpm: Callable[[], None] | None = None,
) -> tuple[bool, str]:
    """DVD Setup stage exits at guest reboot; independently boot OWNED GPT disk.

    The first VM uses QEMU -no-reboot; the second has NO DVD and keeps the
    same disposable QCOW2, private OVMF variables and answer-file floppy.
    Neither a reboot nor disk activity proves a Windows installation. Only
    the existing inside-Windows first-logon witness plus a clean guest
    poweroff can return True.
    """
    require(
        disk.is_file() and not disk.is_symlink()
        and disk.parent == final_serial.parent
        and disk.parent.name.startswith("gaslux-win-x64-")
        and disk.parent.parent == Path("/home/runner/work/_temp")
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT")
        == "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY",
        "two-stage Windows guest has unowned disk or missing hosted consent",
    )
    require(profile_key != "win11_26h2_en_us_x64" or restart_tpm is not None,
            "Windows 11 second stage requires a fresh owned TPM 2.0 listener")
    initial_serial = final_serial.parent / "initial-dvd-guest-serial.log"
    require(not initial_serial.exists() and not final_serial.exists(),
            "VM serial evidence path was reused")
    first, second = build_two_stage_qemu_args(original_args, initial_serial)
    initial_allocated = disk.stat().st_blocks * 512
    dvd_scan_offset = 0
    dvd_scan_carry = b""
    dvd_start_count = 0
    first_deadline = min(3000, max(900, limit - 800))
    started = time.monotonic()
    stage1_error = final_serial.parent / "first-qemu-stderr.log"
    with stage1_error.open("xb") as err:
        proc = subprocess.Popen(first, stdout=subprocess.DEVNULL, stderr=err)
        try:
            while time.monotonic() - started < first_deadline:
                if proc.poll() is not None:
                    break
                if initial_serial.is_file():
                    (found, dvd_scan_offset, dvd_scan_carry,
                     observed) = scan_two_stage_dvd_serial(
                        initial_serial, dvd_scan_offset, dvd_scan_carry,
                    )
                    dvd_start_count += found
                    if dvd_start_count > 1:
                        return False, "initial Windows Setup retried the DVD boot"
                    if (b"No bootable option or device was found." in observed
                            or b"DVD-ROM" in observed
                            and b"Time out" in observed):
                        return False, "initial Windows Setup UEFI DVD boot failed"
                time.sleep(2)
            if proc.poll() is None:
                return False, "Windows Setup did not reboot its first owned VM"
            if proc.returncode != 0:
                return False, "QEMU exited abnormally during first Windows Setup stage"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
    if not initial_serial.is_file():
        return False, "missing first-stage UEFI DVD serial evidence"
    (found, dvd_scan_offset, dvd_scan_carry,
     _) = scan_two_stage_dvd_serial(
        initial_serial, dvd_scan_offset, dvd_scan_carry,
    )
    dvd_start_count += found
    if dvd_start_count != 1:
        return False, "first-stage UEFI DVD did not start exactly once"
    # Only a newly created CI-owned QCOW2 was writable. Reject guest resets
    # before meaningful Windows disk provisioning was observed. Allocated
    # bytes are a staging heuristic, NOT a Windows installation proof.
    if disk.stat().st_blocks * 512 <= initial_allocated + 256 * 1024**2:
        return False, "first Windows guest reset without staging target GPT/OS data"
    remaining = limit - int(time.monotonic() - started)
    if remaining < 600:
        return False, "not enough time for independent installed Windows boot"
    print("GASLUX_WINDOWS_VM_INITIAL_DVD_STAGE_REBOOT_AND_GPT_WRITES_OBSERVED=1",
          flush=True)
    if restart_tpm is not None:
        restart_tpm()
    # The second VM is constructed without ANY DVD, even if OVMF BootOrder
    # retained an old DVD preference. First Windows client boot must therefore
    # originate from the exact new file-backed GPT target.
    return boot_vm(
        second, final_serial, remaining, profile_key,
        monitor_socket=None, reject_repeated_dvd_boot=True,
    )


def probe_no_prompt_uefi_dvd(args: list[str], serial: Path,
                             seconds: int = 120) -> tuple[bool, str]:
    """Observe only OVMF's DVD bootloader handoff, never infer installed Windows.

    The Microsoft UEFI bootloader emits to firmware serial until loading
    Windows PE, which is VGA-only. No serial witness means firstboot is FALSE.
    """
    require(seconds == 120 and not serial.exists(),
            "unexpected DVD probe or reused guest serial transcript")
    started = time.monotonic()
    begun = False
    with (serial.parent / "qemu-stderr.log").open("xb") as err:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
        try:
            while time.monotonic() - started < seconds:
                if serial.is_file():
                    sample = serial.read_bytes()[-16_384:]
                    if b"BdsDxe: starting Boot0001" in sample:
                        begun = True
                    if (b"BdsDxe: failed to start Boot0001" in sample or
                            b"No bootable option or device was found." in sample):
                        return False, "OVMF reported the Microsoft DVD bootloader failed"
                if proc.poll() is not None:
                    return False, "QEMU exited before lab UEFI DVD observation completed"
                time.sleep(2)
            if not begun:
                return False, "OVMF never reported starting the selected UEFI DVD"
            return True, ("OVMF started derived no-prompt EFI DVD without a "
                          "firmware DVD timeout; Windows Setup/boot NOT verified")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=sorted(EXPECTED), required=True)
    ap.add_argument("--boot-probe-only", action="store_true",
                    help="lab-only: stop after a short OVMF no-prompt DVD check "
                         "and always keep installed Windows proof false")
    ap.add_argument("--two-stage-install-only", action="store_true",
                    help="EXPERIMENTAL hosted KVM: install from DVD in stage 1, "
                         "then start a fresh disk-only guest with no DVD")
    ap.add_argument("--one-shot-install-only", action="store_true",
                    help="EXPERIMENTAL hosted KVM only: initial no-prompt DVD "
                         "then hard disk on reboot, with repeat-DVD abort")
    ap.add_argument("--derived-no-prompt", action="store_true",
                    help="disposable KVM lab ONLY: rebuild Microsoft-sourced UDF "
                         "with official noprompt UEFI image; never release media")
    ap.add_argument("--fixture-only", action="store_true",
                    help="generate/validate ONLY XML, no download or VM")
    ap.add_argument("--boot-timeout", type=int, default=6300)
    ap.add_argument("--accel", choices=("tcg", "kvm"), default="tcg",
                    help="KVM only after isolated GitHub-hosted kernel VM gate")
    args = ap.parse_args(argv)
    if args.boot_probe_only and not args.derived_no_prompt:
        raise SystemExit("DVD probe requires explicit lab-derived no-prompt boot mode")
    if args.two_stage_install_only:
        if not (args.derived_no_prompt and not args.boot_probe_only
                and not args.one_shot_install_only and args.accel == "kvm"
                and os.environ.get("GASLUX_WINDOWS_TWO_STAGE_INSTALL_CONSENT")
                == "I_ACCEPT_DISPOSABLE_GITHUB_KVM_DVD_THEN_DISK_ONLY"):
            raise SystemExit("two-stage Windows lab installation requires "
                             "separate hosted KVM consent and no-prompt DVD")
    elif args.one_shot_install_only:
        if not (args.derived_no_prompt and not args.boot_probe_only
                and args.accel == "kvm" and
                os.environ.get("GASLUX_WINDOWS_ONE_SHOT_INSTALL_CONSENT")
                == "I_ACCEPT_DISPOSABLE_GITHUB_KVM_INITIAL_DVD_ONLY"):
            raise SystemExit("one-shot Windows lab installation requires explicit "
                             "hosted KVM consent, no-prompt media and one-time DVD boot")
    elif args.derived_no_prompt and not args.boot_probe_only:
        raise SystemExit("derived no-prompt DVD requires probe-only unless the "
                         "separate hosted VM one-shot installation gate is approved")
    catalog = load_catalog()
    profile = catalog["profiles"][args.profile]
    xml = generate_unattend(
        args.profile, profile["expectedWindowsBuildPrefix"],
        usb_answer=args.two_stage_install_only,
    )
    validate_oobe_answer_pass(xml)
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
            boot_iso = iso
            if args.derived_no_prompt:
                require(args.accel == "kvm",
                        "no-prompt derived ISO permitted only in isolated hosted KVM")
                derived = workspace / "derived-microsoft-noprompt-lab.iso"
                derived_sha256 = derive_no_prompt_uefi_lab_iso(
                    iso, derived, workspace
                )
                report["labDerivedIsoSha256"] = derived_sha256
                report["labDerivedIsoOnly"] = True
                report["officialIsoUnmodified"] = True
                boot_iso = derived
                print("GASLUX_MICROSOFT_VERIFIED_SOURCE_TO_LAB_NOPROMPT_DERIVATIVE=1",
                      flush=True)
            xmlfile = workspace / "Autounattend.xml"
            xmlfile.write_bytes(xml)
            guest_ps1 = workspace / "GASLUX.PS1"
            guest_ps1.write_text(
                witness_powershell(args.profile,
                                   profile["expectedWindowsBuildPrefix"]) + "\n",
                encoding="utf-8")
            report["firstLogonScriptSha256"] = hashlib.sha256(
                guest_ps1.read_bytes()).hexdigest()
            # CONTROLLED A/B TEST: retain the SAME known-working derived DVD,
            # guest PowerShell and boot sequence; vary ONLY the guest answer
            # medium from a file-backed FAT12 floppy to a read-only FAT32 USB.
            answer = workspace / "only-disposable-answer-usb.img"
            require(not answer.exists() and not answer.is_symlink(),
                    "refusing reused Windows Setup answer media")
            subprocess.run(["truncate", "-s", "64M", str(answer)], check=True)
            subprocess.run(["mkfs.vfat", "-F", "32", "-n", "GASLUXCI", str(answer)],
                           check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["mcopy", "-i", str(answer), str(xmlfile),
                            "::/Autounattend.xml"], check=True)
            subprocess.run(["mcopy", "-i", str(answer), str(guest_ps1),
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
                "-display", "none", "-vga", "std",
                "-monitor", f"unix:{monitor_path},server,nowait", "-net", "none",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={nvram}",
                # Explicit USB keyboard input is required in headless OVMF.
                # A QEMU HMP 'sendkey' command being accepted does NOT prove
                # that the guest firmware received the keystroke.
                "-device", "qemu-xhci,id=lab_usb",
                "-device", "usb-kbd,bus=lab_usb.0",
                "-device", "ich9-ahci,id=lab_sata",
                "-drive", f"if=none,id=verified_iso,media=cdrom,readonly=on,format=raw,file={boot_iso}",
                "-device", "ide-cd,drive=verified_iso,bus=lab_sata.1",
                "-serial", f"file:{serial}",
                # QEMU's documented 'once=d' gives DVD priority on initial
                # startup only. Subsequent reboots must use the owned QCOW2.
                "-boot", ("order=c,once=d" if args.one_shot_install_only
                          else "order=dc"),
            ]
            # The lab DVD probe MUST NOT expose a writable target disk,
            # unattend answer file, or any other guest storage. Its ONLY
            # attached medium is a read-only Microsoft-sourced DVD.
            if not args.boot_probe_only:
                base.extend([
                    "-drive", f"if=none,id=only_windows,format=qcow2,file={disk}",
                    "-device", "ide-hd,drive=only_windows,bus=lab_sata.0",
                    # Read-only file-backed FAT32 answer medium is exposed
                    # to both original and independent disk-only guest boots.
                    "-drive", f"if=none,id=lab_unattend,format=raw,readonly=on,file={answer}",
                    "-device", "usb-storage,drive=lab_unattend,bus=lab_usb.0",
                ])
            tpm = None
            if args.profile.startswith("win11"):
                require(shutil.which("swtpm") is not None, "Windows 11 requires TPM 2.0")
                state = workspace / "swtpm-state"
                state.mkdir(mode=0o700)
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
                if args.boot_probe_only:
                    ok, diagnostic = probe_no_prompt_uefi_dvd(base, serial)
                    report["labNoPromptDvdBootProbePassed"] = ok
                    report["windowsClientBootVerified"] = False
                elif args.two_stage_install_only:
                    def restart_guest_tpm() -> None:
                        nonlocal tpm
                        require(tpm is not None, "Windows 11 virtual TPM missing")
                        tpm = restart_owned_swtpm_for_second_guest(tpm, workspace)

                    ok, diagnostic = boot_two_stage_windows(
                        base, disk, serial, args.boot_timeout, args.profile,
                        restart_tpm=(restart_guest_tpm if args.profile.startswith("win11")
                                     else None),
                    )
                else:
                    ok, diagnostic = boot_vm(
                        base, serial, args.boot_timeout, args.profile,
                        monitor_socket=(None if args.one_shot_install_only
                                        else monitor_path),
                        reject_repeated_dvd_boot=args.one_shot_install_only,
                    )
                if not args.boot_probe_only:
                    report["windowsClientBootVerified"] = ok
                report["diagnostic"] = diagnostic
            finally:
                if args.two_stage_install_only:
                    # Preserve only bounded, VM-generated firmware serial and
                    # QEMU stderr evidence. Never archive ISO, Windows WIM,
                    # installed QCOW2, unattended media, TPM or private NVRAM.
                    for source_name, suffix, max_bytes in (
                        ("initial-dvd-guest-serial.log", "initial-dvd-serial", 2_000_000),
                        ("first-qemu-stderr.log", "initial-qemu-stderr", 256_000),
                        ("qemu-stderr.log", "second-qemu-stderr", 256_000),
                    ):
                        source = workspace / source_name
                        if (source.is_file() and not source.is_symlink()
                                and 0 < source.stat().st_size <= max_bytes):
                            dest = evidence / f"{args.profile}-{suffix}.log"
                            with source.open("rb") as stream, dest.open("xb") as output:
                                shutil.copyfileobj(stream, output, length=64 * 1024)
                            with dest.open("rb") as hashed:
                                digest = hashlib.file_digest(
                                    hashed, "sha256"
                                ).hexdigest()
                            (evidence / f"{args.profile}-{suffix}.sha256").write_text(
                                f"{digest}  {dest.name}\n", encoding="ascii",
                            )
                            if suffix == "initial-dvd-serial":
                                report["initialDvdGuestSerialSha256"] = digest
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
