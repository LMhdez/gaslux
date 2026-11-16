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
import json
import os
import platform
import re
import shutil
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
VM_SIZE = "80G"
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


def validate_environment(workspace: Path) -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_OS") == "Linux" and
            os.environ.get("GASLUX_WINDOWS_TCG_CONSENT") == CONSENT,
            "not the expressly authorized disposable GitHub Linux TCG laboratory")
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
  $ser.NewLine = "\n"
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
  if (-not (Test-Path 'C:\Windows\System32\winload.efi')) { throw 'Windows EFI loader missing' }
  $bcd = & bcdedit /enum '{bootmgr}' 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'BCD boot manager enumeration failed' }
  $winre = & reagentc /info 2>&1
  $winreOk = ($LASTEXITCODE -eq 0)
  $serialProof = @(
    'GASLUX_WINDOWS_X64_BOOT_BUILD=' + $os.BuildNumber,
    'GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1',
    'GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1',
    'GASLUX_WINDOWS_X64_BCD_ENUMERATED=1',
    'GASLUX_WINDOWS_X64_WINRE_COMMAND_SUCCEEDED=' + [int]$winreOk,
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
    for n, typ, size in ((1, "EFI", "260"), (2, "MSR", "16"),
                         (3, "Primary", None)):
        part = child(create, "CreatePartition", attrs={f"{{{wcm}}}action": "add"})
        child(part, "Order", str(n))
        child(part, "Type", typ)
        if size is not None:
            child(part, "Size", size)
        else:
            child(part, "Extend", "true")
    modify = child(disk, "ModifyPartitions")
    for n, fs, label in ((1, "FAT32", "GASLUXCIESP"),
                         (3, "NTFS", "GASLUXWIN")):
        part = child(modify, "ModifyPartition", attrs={f"{{{wcm}}}action": "add"})
        child(part, "Order", str(n))
        child(part, "PartitionID", str(n))
        child(part, "Format", fs)
        child(part, "Label", label)
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


def boot_vm(args: list[str], transcript: Path, limit: int,
            profile_key: str) -> tuple[bool, str]:
    started = time.monotonic()
    with (transcript.parent / "qemu-stderr.log").open("xb") as err:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
        try:
            while time.monotonic() - started < limit:
                if transcript.is_file():
                    with transcript.open("rb") as source:
                        source.seek(max(0, transcript.stat().st_size - 400_000))
                        data = source.read(400_000)
                    if FAILURE.encode() in data:
                        return False, "installed Windows reported failed boot audit"
                    required = (
                        f"{MARKER}={profile_key}".encode(),
                        b"GASLUX_WINDOWS_X64_BOOT_PRODUCTTYPE=1",
                        b"GASLUX_WINDOWS_X64_GPT_ESP_COUNT=1",
                        b"GASLUX_WINDOWS_X64_BCD_ENUMERATED=1",
                    )
                    if all(e in data for e in required):
                        return True, "real installed Windows x64 client serial audit observed"
                if proc.poll() is not None:
                    return False, "QEMU exited before installed Windows first-logon witness"
                time.sleep(10)
            return False, "timed out before a complete installed Windows x64 audit"
        finally:
            if proc.poll() is None:
                proc.kill()  # VM-only simulated power off, no host disk signals.
                proc.wait(timeout=30)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=sorted(EXPECTED), required=True)
    ap.add_argument("--fixture-only", action="store_true",
                    help="generate/validate ONLY XML, no download or VM")
    ap.add_argument("--boot-timeout", type=int, default=6300)
    args = ap.parse_args(argv)
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
        "profile": args.profile, "isoHashVerified": False,
        "windowsClientBootVerified": False, "dualBootVerified": False,
        "winReAndBcdRecovered": False, "stable": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="gaslux-win-x64-", dir=os.environ["RUNNER_TEMP"]) as tmp:
            workspace = Path(tmp)
            validate_environment(workspace)
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
            base = [
                "qemu-system-x86_64", "-machine", "q35,accel=tcg,smm=on",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-cpu", "max", "-smp", "2", "-m", "4096",
                "-display", "none", "-vga", "std",
                "-monitor", "none", "-net", "none",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={nvram}",
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
                ok, diagnostic = boot_vm(base, serial, args.boot_timeout, args.profile)
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
