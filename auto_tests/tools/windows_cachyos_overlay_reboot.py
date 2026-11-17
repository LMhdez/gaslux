"""Third Windows boot on an isolated fifth-GPT QCOW2 COW: VM ONLY, never production."""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from uuid import UUID
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, validate_workspace, sha256_file)
from windows_cachyos_qcow2_gpt_readonly import (
    WINDOW_BYTES, VIRTUAL_BYTES, qcow2_file_identity, require_unchanged_qcow2,
    bounded_qcow2_dd_command)
from windows_cachyos_overlay_gpt_stage import verify_linux_root_layout

CONSENT = "I_ACCEPT_WINDOWS_GUEST_REBOOT_ON_PRIVATE_GPT_OVERLAY_ONLY"
PROOF = (
    "GASLUX_COW_WIN10_REBOOT_LIVE=1",
    "GASLUX_COW_WIN10_REBOOT_BUILD=19045",
    "GASLUX_COW_WIN10_REBOOT_ESP=1",
    "GASLUX_COW_WIN10_REBOOT_BCD=1",
    "GASLUX_COW_WIN10_REBOOT_WINRE=1",
    "GASLUX_COW_WIN10_REBOOT_FIFTH_GPT=1",
)

class OverlayBootError(ValueError):
    pass

def require(ok: bool, message: str) -> None:
    if not ok: raise OverlayBootError(message)

def guest_reboot_script() -> str:
    """Executed by a task registered at the FIRST verified disposable Windows logon."""
    return r"""
$ErrorActionPreference = 'Stop'
$serial = $null
try {
  Start-Sleep -Seconds 8
  $serial = [System.IO.Ports.SerialPort]::new('COM1',115200,[System.IO.Ports.Parity]::None,8,[System.IO.Ports.StopBits]::One)
  $serial.NewLine = [Environment]::NewLine
  $serial.Open()
  $os = Get-CimInstance Win32_OperatingSystem
  if ($os.ProductType -ne 1 -or -not $os.BuildNumber.StartsWith('19045')) { throw 'unexpected Windows client build' }
  $disk = Get-Disk -Number 0
  $parts = @(Get-Partition -DiskNumber 0)
  if ($disk.PartitionStyle -ne 'GPT' -or $parts.Count -ne 5) { throw 'GPT partition count not five' }
  $esp = @($parts | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })
  $recovery = @($parts | Where-Object { $_.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' })
  $linux = @($parts | Where-Object { $_.GptType -eq '{0fc63daf-8483-4772-8e79-3d69d8477de4}' })
  if ($esp.Count -ne 1 -or $recovery.Count -ne 1 -or $linux.Count -ne 1) { throw 'ESP, Recovery or Linux root missing' }
  if ($linux[0].PartitionNumber -ne 5 -or $linux[0].Size -ne 24GB) { throw 'Linux root geometry not 24 GiB' }
  $windows = Get-Partition -DriveLetter C
  if ($windows.DiskNumber -ne 0 -or $windows.PartitionNumber -ne 3 -or
      $recovery[0].PartitionNumber -ne 4 -or
      $linux[0].Offset -lt ($recovery[0].Offset + $recovery[0].Size)) {
    throw 'Windows or Linux partition changed order'
  }
  if (-not (Test-Path 'C:\Windows\System32\winload.efi')) { throw 'Windows bootloader missing' }
  $bcd = & bcdedit.exe /enum '{bootmgr}' 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'Windows Boot Manager BCD invalid' }
  $re = & reagentc.exe /info 2>&1
  if ($LASTEXITCODE -ne 0 -or ($re -join [Environment]::NewLine) -notmatch 'Windows RE status:\s+Enabled') {
    throw 'WinRE is missing or disabled'
  }
  foreach ($m in @(
    'GASLUX_COW_WIN10_REBOOT_LIVE=1',
    'GASLUX_COW_WIN10_REBOOT_BUILD=19045',
    'GASLUX_COW_WIN10_REBOOT_ESP=1',
    'GASLUX_COW_WIN10_REBOOT_BCD=1',
    'GASLUX_COW_WIN10_REBOOT_WINRE=1',
    'GASLUX_COW_WIN10_REBOOT_FIFTH_GPT=1'
  )) { $serial.WriteLine($m); Start-Sleep -Milliseconds 150 }
} catch {
  if ($serial -and $serial.IsOpen) { $serial.WriteLine('GASLUX_COW_WIN10_REBOOT_FAIL=1') }
} finally {
  if ($serial) { $serial.Close(); $serial.Dispose() }
}
Start-Sleep -Seconds 2
& "$env:WINDIR\System32\shutdown.exe" /s /f /t 0
""".strip()


# An unattended third boot must not turn a later guest reboot into success.
# Validate the complete serial again only AFTER QEMU has exited.
BOOT_MANAGER = re.compile(
    rb'BdsDxe: starting Boot[0-9A-Fa-f]{4} "Windows Boot Manager"'
)
def audit_complete_third_serial(path: Path) -> str:
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_nlink == 1
            and 0 < path.stat().st_size <= 512_000,
            "missing, linked or oversized third Windows serial")
    data = path.read_bytes()
    require(len(data) <= 512_000, "third Windows COM1 grew beyond limit")
    # The third guest receives neither DVD nor a boot-key mechanism.
    require(len(BOOT_MANAGER.findall(data)) == 1
            and b'UEFI QEMU DVD-ROM' not in data,
            "third guest rebooted or tried DVD rather than single Windows boot")
    require(b'GASLUX_COW_WIN10_REBOOT_FAIL=1' not in data,
            "third guest audit failure takes precedence over positive markers")
    lines = data.splitlines()
    require(all(lines.count(line.encode("ascii")) == 1 for line in PROOF),
            "missing, duplicated or coalesced third Windows audit witnesses")
    return hashlib.sha256(data).hexdigest()

def first_logon_task(script_hash: str) -> str:
    require(len(script_hash) == 64 and all(c in '0123456789abcdef' for c in script_hash),
            'invalid guest reboot script sha256')
    return r"""
  $source = 'A:\GASLUXR.PS1'
  if (-not (Test-Path -LiteralPath $source)) { throw 'missing VM-only audit media' }
  if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne '__DIGEST__') {
    throw 'guest second boot script hash mismatch'
  }
  $folder = 'C:\ProgramData\GasluxDisposableCI'
  New-Item -ItemType Directory -Path $folder -Force | Out-Null
  $target = Join-Path $folder 'GASLUXR.PS1'
  Copy-Item -LiteralPath $source -Destination $target -Force
  if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne '__DIGEST__') {
    throw 'copied second boot audit hash mismatch'
  }
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $target + '"')
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName 'GasluxCIThirdBootAudit' -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
""".replace('__DIGEST__',script_hash).strip('\n')

def third_guest_args(original: list[str], base: Path, nvram: Path,
                     overlay: Path, trial_vars: Path, serial: Path) -> list[str]:
    require(overlay.parent == trial_vars.parent and
            base.parent == serial.parent and all(p.is_absolute() for p in
            (base,nvram,overlay,trial_vars,serial)), 'unsafe third guest arguments')
    from windows_x64_tcg_firstboot import build_two_stage_qemu_args
    _, cmd=build_two_stage_qemu_args(original,base.parent/'never-started-dvd-serial.log')
    def replace(flag: str, before: str, after: str) -> None:
        positions=[i+1 for i in range(len(cmd)-1) if cmd[i]==flag and cmd[i+1]==before]
        require(len(positions)==1,'missing or ambiguous third guest device argument')
        cmd[positions[0]]=after
    replace('-drive',f'if=none,id=only_windows,format=qcow2,file={base}',
            f'if=none,id=only_windows,format=qcow2,file={overlay}')
    replace('-drive',f'if=pflash,format=raw,file={nvram}',
            f'if=pflash,format=raw,file={trial_vars}')
    replace('-serial',f'file:{base.parent/"win-guest-serial.log"}',f'file:{serial}')
    require(cmd.count('-boot')==1 and cmd[cmd.index('-boot')+1]=='order=c'
            and cmd.count('-monitor')==1 and cmd[cmd.index('-monitor')+1]=='none'
            and all('verified_iso' not in x for x in cmd)
            and all(str(base) not in x and str(nvram) not in x for x in cmd),
            'third guest may not boot DVD or write Windows backing or original VARS')
    return cmd

def gpt_windows(image: Path, directory: Path) -> tuple[bytes,bytes]:
    result=[]
    for side in ('front','back'):
        out=directory/(side+'.raw')
        require(not out.exists() and not out.is_symlink(),'reused GPT scratch')
        subprocess.run(bounded_qcow2_dd_command(image,out,side),
                       check=True,capture_output=True,timeout=90)
        data=out.read_bytes()
        out.unlink()
        require(len(data)==WINDOW_BYTES,'truncated GPT evidence')
        result.append(data)
    return result[0],result[1]

def verify_third_windows_boot(original: list[str], base: Path, nvram: Path,
                              geometry: dict, cow: dict, stage: dict,
                              timeout: int=1200) -> dict:
    from windows_cachyos_overlay_gpt_stage import LAB_CONSENT
    require(os.environ.get('GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT')==CONSENT and
            os.environ.get('GASLUX_CACHYOS_OVERLAY_GPT_CONSENT')==LAB_CONSENT and
            os.environ.get('GITHUB_ACTIONS')=='true' and
            os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and
            os.environ.get('GITHUB_REPOSITORY')=='LMhdez/gaslux' and
            type(timeout) is int and 120<=timeout<=1800,
            'third Windows boot requires separate hosted-VM-only consent')
    require(stage.get('overlayGptLinuxRootEntryPrepared') is True and
            stage.get('bothGptMirrorsAfterStageVerified') is True and
            stage.get('windowsBackingQcow2Unchanged') is True and
            stage.get('linuxRootFilesystemFormatted') is False and
            stage.get('storageWritesAuthorized') is False and
            geometry.get('candidateWindowsGptPrimaryAndBackupConsistent') is True and
            cow.get('candidateWindowsCowCheckpointPrepared') is True,
            'failed Windows+fifth-GPT staging prerequisite')
    validate_workspace(base,nvram)
    folder=base.parent/CHECKPOINT_DIR
    require(folder.is_dir() and not folder.is_symlink() and
            stat.S_IMODE(folder.stat().st_mode)==0o700,'unsafe checkpoint directory')
    overlay=folder/OVERLAY_NAME
    trial=folder/'trial-ovmf-variables.fd'
    nvbase=folder/'windows-ovmf-baseline.fd'
    for p in (overlay,trial,nvbase): owned_regular(p,folder,p.name)
    require(stat.S_IMODE(base.stat().st_mode)==0o400 and
            stat.S_IMODE(overlay.stat().st_mode)==0o600 and
            stat.S_IMODE(nvbase.stat().st_mode)==0o400,
            'original Windows QCOW2/NVRAM checkpoint not read-only')
    info=json.loads(subprocess.run(
        ['qemu-img','info','-f','qcow2','--output=json',str(overlay)],
        check=True,capture_output=True,text=True,timeout=30).stdout)
    require(info.get('format')=='qcow2' and info.get('virtual-size')==VIRTUAL_BYTES and
            info.get('backing-filename')==str(base) and
            info.get('backing-filename-format')=='qcow2' and not info.get('encrypted',False),
            'overlay backing identity or size invalid')
    identity=qcow2_file_identity(base)
    nvhash=sha256_file(nvram)
    require(sha256_file(nvbase)==nvhash==cow['uefiVarsCopySha256'],
            'baseline Windows NVRAM changed')
    scratch=base.parent
    with tempfile.TemporaryDirectory(prefix='gaslux-gpt-thirdboot-',dir=scratch) as tmp:
        before=gpt_windows(base,Path(tmp))
        fifth=gpt_windows(overlay,Path(tmp))
        linux=stage['linuxRoot']
        require(linux['index']==5 and linux['lengthBytes']==24*1024**3 and
                linux['firstLba']>geometry['windowsPartitions'][-1]['lastLba'],
                'unexpected fifth Linux partition')
        verify_linux_root_layout(before[0],before[1],fifth[0],fifth[1],
                                 linux['firstLba'],linux['lastLba'],
                                 UUID(linux['uniqueGuid']))
    require_unchanged_qcow2(base,identity)
    serial=base.parent/'third-overlay-windows-serial.log'
    require(not serial.exists() and not serial.is_symlink(),'third serial path reused')
    args=third_guest_args(original,base,nvram,overlay,trial,serial)
    digest=None
    with (scratch/'third-overlay-qemu-stderr.log').open('xb') as stderr:
        proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=stderr)
        try:
            started=time.monotonic()
            while time.monotonic()-started<timeout:
                if serial.is_file():
                    require(not serial.is_symlink() and
                            serial.stat().st_size<=512_000,
                            'untrusted or oversized Windows COM1')
                    if b'GASLUX_COW_WIN10_REBOOT_FAIL=1' in serial.read_bytes():
                        raise OverlayBootError(
                            'installed Windows rejected BCD/WinRE/GPT')
                rc=proc.poll()
                if rc is not None:
                    require(rc==0,
                            'Windows third guest did not power off cleanly')
                    # Final evidence may be appended between serial.read_bytes
                    # and proc.poll(). Do not decide success on a stale read.
                    digest=audit_complete_third_serial(serial)
                    break
                time.sleep(3)
            else:
                raise OverlayBootError('Windows third-boot timeout')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
    with tempfile.TemporaryDirectory(prefix='gaslux-gpt-after-thirdboot-',dir=scratch) as tmp:
        after=gpt_windows(overlay,Path(tmp))
    require(after==fifth,'Windows third boot modified fifth GPT')
    require_unchanged_qcow2(base,identity)
    require(sha256_file(nvram)==nvhash and sha256_file(nvbase)==nvhash,
            'original Windows UEFI variables changed after overlay boot')
    require(digest is not None, 'third Windows COM1 not authenticated after exit')
    return {
        'windowsBootAfterOverlayMutationVerified':True,
        'guestBcdWinreEspAfterOverlayVerified':True,
        'windowsGuestShutdownAfterOverlayVerified':True,
        'fifthGptUnchangedAfterGuestBoot':True,
        'windowsBackingUnchangedAfterGuestBoot':True,
        'originalUefiVarsUnchangedAfterGuestBoot':True,
        'thirdBootGuestSerialSha256':digest,
        'cachyosInstalled':False,'cachyosFirstBootVerified':False,
        'windowsRecoveryAfterLinuxVerified':False,'rollbackProven':False,
        'sameDiskDualBootVerified':False,'storageWritesAuthorized':False,
        'releaseEligible':False,
    }
