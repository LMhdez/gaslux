#!/usr/bin/env python3
"""VM-only fourth Windows guest boot on fifth-ext4 COW. NO Linux install."""
from __future__ import annotations
import json, os, stat, subprocess, tempfile, time
from pathlib import Path
from uuid import UUID
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, sha256_file, validate_workspace)
from windows_cachyos_qcow2_gpt_readonly import (
    VIRTUAL_BYTES, qcow2_file_identity, require_unchanged_qcow2)
from windows_cachyos_overlay_reboot import (
    CONSENT as THIRD_BOOT_CONSENT, audit_complete_third_serial,
    gpt_windows, third_guest_args)
from windows_cachyos_overlay_ext4_only import CONSENT as EXT4_CONSENT

CONSENT="I_ACCEPT_WINDOWS_FOURTH_GUEST_ON_EXT4_ONLY_QCOW2_COW"
class FourthBootError(ValueError): pass
def require(ok, why):
    if not ok: raise FourthBootError(why)


def add_tpm_device(args: list[str], tpm_socket: Path) -> list[str]:
    require(tpm_socket.is_absolute() and tpm_socket.is_socket()
            and not tpm_socket.is_symlink()
            and tpm_socket.lstat().st_uid == os.getuid(),
            "independent TPM socket is missing or unowned")
    require(not any("chrtpm" in item for item in args)
            and "-tpmdev" not in args,
            "refusing duplicate TPM device in Windows QEMU arguments")
    return [*args,
            "-chardev", f"socket,id=chrtpm,path={tpm_socket}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis,tpmdev=tpm0"]


def add_qemu_trace(args: list[str], events_file: Path | None,
                   trace_file: Path | None) -> list[str]:
    require((events_file is None) == (trace_file is None),
            "QEMU trace events and output must be supplied together")
    if events_file is None or trace_file is None:
        return list(args)
    require(events_file.is_absolute() and events_file.is_file()
            and not events_file.is_symlink()
            and events_file.stat().st_size <= 16_384
            and trace_file.is_absolute()
            and trace_file.parent == events_file.parent
            and not trace_file.exists() and not trace_file.is_symlink(),
            "unsafe QEMU write-trace paths")
    return [*args, "-trace", f"events={events_file},file={trace_file}"]


def verify_windows_post_ext4(original: list[str], base: Path, nvram: Path,
                            geometry: dict, cow: dict, stage: dict,
                            third: dict, ext4: dict, timeout: int=1200,
                            evidence_stem: str="fourth-post-ext4",
                            overlay_override: Path | None=None,
                            trial_vars_override: Path | None=None,
                            tpm_socket: Path | None=None,
                            trace_events_file: Path | None=None,
                            trace_file: Path | None=None) -> dict:
    require(os.environ.get("GITHUB_ACTIONS")=="true"
            and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
            and os.environ.get("GITHUB_REPOSITORY")=="LMhdez/gaslux"
            and os.environ.get("GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT")==CONSENT
            and os.environ.get("GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT")==THIRD_BOOT_CONSENT
            and os.environ.get("GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT")==EXT4_CONSENT
            and type(timeout) is int and 120<=timeout<=1800
            and evidence_stem in ("fourth-post-ext4", "sixth-post-pacstrap",
                                  "bcd-control-windows-only"),
            "fourth Windows boot requires dedicated hosted KVM consent")
    require(all(type(x) is dict for x in (geometry,cow,stage,third,ext4))
            and geometry.get("candidateWindowsGptPrimaryAndBackupConsistent") is True
            and geometry.get("storageWritesAuthorized") is False
            and cow.get("candidateWindowsCowCheckpointPrepared") is True
            and stage.get("overlayGptLinuxRootEntryPrepared") is True
            and stage.get("linuxRootFilesystemFormatted") is False
            and third.get("windowsBootAfterOverlayMutationVerified") is True
            and third.get("guestBcdWinreEspAfterOverlayVerified") is True
            and third.get("windowsGuestShutdownAfterOverlayVerified") is True
            and ext4.get("onlyOwnedOverlayFifthPartitionFormatted") is True
            and ext4.get("linuxRootFilesystemFormatted") is True
            and ext4.get("windowsBackingQcow2UnchangedAfterExt4") is True
            and ext4.get("windowsOriginalUefiUnchangedAfterExt4") is True
            and ext4.get("windowsBootAfterExt4Verified") is False
            and ext4.get("cachyosInstalled") is False
            and ext4.get("sameDiskDualBootVerified") is False
            and ext4.get("storageWritesAuthorized") is False
            and ext4.get("releaseEligible") is False
            and ext4.get("linuxRoot")==stage.get("linuxRoot")
            and ext4.get("rootFilesystem",{}).get("filesystemType")=="ext4"
            and ext4.get("rootFilesystem",{}).get("allFourWindowsPartitionSha256Unchanged") is True,
            "fourth Windows boot lacks genuine Windows third-boot and ext4 proofs")
    try: root_uuid=UUID(ext4["rootFilesystem"]["filesystemUuid"])
    except (TypeError,ValueError,KeyError,AttributeError) as e:
        raise FourthBootError("invalid root filesystem UUID") from e
    require(root_uuid.int!=0,"zero root filesystem UUID")
    validate_workspace(base,nvram)
    folder=base.parent/CHECKPOINT_DIR
    require(folder.is_dir() and not folder.is_symlink()
            and folder.stat().st_uid==os.getuid()
            and stat.S_IMODE(folder.stat().st_mode)==0o700,
            "unowned post-ext4 workspace")
    overlay=overlay_override or (folder/OVERLAY_NAME)
    trial_vars=trial_vars_override or (folder/"trial-ovmf-variables.fd")
    require(overlay.parent==folder and trial_vars.parent==folder
            and (overlay_override is None
                 or overlay.name=="bcd-ab-control-windows-only.qcow2")
            and (trial_vars_override is None
                 or trial_vars.name=="bcd-ab-control-ovmf-variables.fd"),
            "foreign A/B control disk or OVMF variables path")
    nv_baseline=folder/"windows-ovmf-baseline.fd"
    for item in (overlay,nv_baseline,trial_vars):
        owned_regular(item,folder,item.name)
    require(stat.S_IMODE(base.stat().st_mode)==0o400
            and stat.S_IMODE(overlay.stat().st_mode)==0o600
            and stat.S_IMODE(nv_baseline.stat().st_mode)==0o400
            and stat.S_IMODE(trial_vars.stat().st_mode)==0o600,
            "unsafe protected Windows base or trial file permissions")
    nvhash=sha256_file(nvram)
    require(nvhash==cow.get("uefiVarsCopySha256")
            and sha256_file(nv_baseline)==nvhash,
            "original Windows UEFI state not preserved")
    info=json.loads(subprocess.run([
        "qemu-img","info","-f","qcow2","--output=json",str(overlay),
    ],check=True,capture_output=True,text=True,timeout=30).stdout)
    require(info.get("format")=="qcow2"
            and info.get("virtual-size")==VIRTUAL_BYTES
            and info.get("backing-filename")==str(base)
            and info.get("backing-filename-format")=="qcow2"
            and not info.get("encrypted",False),
            "post-ext4 disk is not exact Windows-backed private COW")
    identity=qcow2_file_identity(base)
    with tempfile.TemporaryDirectory(prefix="gaslux-fourth-before-",dir=base.parent) as tmp:
        before=gpt_windows(overlay,Path(tmp))
    serial=base.parent/(evidence_stem+"-windows-serial.log")
    require(not serial.exists() and not serial.is_symlink(),"reused fourth boot evidence")
    args=third_guest_args(original,base,nvram,overlay,trial_vars,serial)
    if tpm_socket is not None:
        args=add_tpm_device(args,tpm_socket)
    args=add_qemu_trace(args,trace_events_file,trace_file)
    require(all(str(base) not in a and str(nvram) not in a and "verified_iso" not in a
                for a in args)
            and args.count("-boot")==1 and args[args.index("-boot")+1]=="order=c",
            "fourth boot could access base Windows, original EFI or ISO")
    digest=None
    with (base.parent/(evidence_stem+"-qemu-stderr.log")).open("xb") as stderr:
        proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=stderr)
        try:
            start=time.monotonic()
            while time.monotonic()-start<timeout:
                if serial.is_file():
                    require(not serial.is_symlink()
                            and serial.stat().st_size<=512_000,
                            "untrusted or oversized fourth Windows COM1")
                    if b"GASLUX_COW_WIN10_REBOOT_FAIL=1" in serial.read_bytes():
                        raise FourthBootError("fourth guest rejected Windows BCD/WinRE")
                rc=proc.poll()
                if rc is not None:
                    require(rc==0,"fourth Windows guest did not power off cleanly")
                    # Always re-read all COM1 bytes AFTER QEMU has terminated.
                    digest=audit_complete_third_serial(serial)
                    break
                time.sleep(3)
            else:
                raise FourthBootError("fourth Windows guest timeout")
        finally:
            if proc.poll() is None:
                proc.kill();proc.wait(timeout=30)
    require(digest is not None,"missing fourth Windows boot evidence")
    with tempfile.TemporaryDirectory(prefix="gaslux-fourth-after-",dir=base.parent) as tmp:
        require(gpt_windows(overlay,Path(tmp))==before,
                "Windows fourth boot modified GPT geometry")
    require_unchanged_qcow2(base,identity)
    require(sha256_file(nvram)==nvhash and sha256_file(nv_baseline)==nvhash,
            "original Windows UEFI changed during fourth boot")
    import guestfs
    g=guestfs.GuestFS(python_return_dict=True)
    try:
        g.add_drive_opts(str(overlay),format="qcow2",readonly=1)
        g.launch()
        devices=g.list_devices()
        require(len(devices)==1 and g.blockdev_getsize64(devices[0])==VIRTUAL_BYTES,
                "wrong post-ext4 guestfs disk identity")
        dev=devices[0];suffix="p" if dev[-1].isdigit() else ""
        parts=[dev+suffix+str(i) for i in range(1,6)]
        require(g.list_partitions()==parts,"foreign or missing GPT partition")
        require(g.blockdev_getsize64(parts[4])==24*1024**3
                and g.vfs_type(parts[4])=="ext4"
                and g.vfs_uuid(parts[4])==str(root_uuid),
                "Windows boot changed fifth ext4 identity")
    finally:
        try:g.shutdown()
        finally:g.close()
    require_unchanged_qcow2(base,identity)
    require(sha256_file(nvram)==nvhash and sha256_file(nv_baseline)==nvhash,
            "Windows EFI baseline modified during postboot audit")
    result = {
        "windowsBootAfterExt4Verified":True,
        "windowsBcdWinreEspAfterExt4Verified":True,
        "fourthGuestCleanShutdownVerified":True,
        "fourthGuestSerialSha256":digest,
        "fifthExt4UuidSurvivedWindowsBoot":True,
        "windowsGptUnchangedAfterExt4Boot":True,
        "windowsBackingUnchangedAfterExt4Boot":True,
        "originalWindowsUefiUnchangedAfterExt4Boot":True,
        "cachyosInstalled":False,"cachyosFirstBootVerified":False,
        "windowsRecoveryAfterLinuxVerified":False,"rollbackProven":False,
        "sameDiskDualBootVerified":False,"storageWritesAuthorized":False,
        "releaseEligible":False,
    }
    if trace_file is not None:
        if trace_file.is_file() and not trace_file.is_symlink():
            trace_size = trace_file.stat().st_size
            if trace_size <= 10 * 1024 * 1024:
                result["qemuWriteTraceSha256"] = sha256_file(trace_file)
                result["qemuWriteTraceBytes"] = trace_size
                result["qemuWriteTraceStatus"] = "captured"
            else:
                st = trace_file.lstat()
                require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
                        and st.st_nlink == 1,
                        "refusing to remove oversized foreign QEMU trace")
                trace_file.unlink()
                result["qemuWriteTraceStatus"] = "omitted-oversized"
        else:
            result["qemuWriteTraceStatus"] = "no-trace-file-produced"
    return result

if __name__=="__main__":
    raise SystemExit("library only: no host devices or installer operations")
