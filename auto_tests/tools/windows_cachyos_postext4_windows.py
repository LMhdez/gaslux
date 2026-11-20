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

def verify_windows_post_ext4(original: list[str], base: Path, nvram: Path,
                            geometry: dict, cow: dict, stage: dict,
                            third: dict, ext4: dict, timeout: int=1200,
                            evidence_stem: str="fourth-post-ext4") -> dict:
    require(os.environ.get("GITHUB_ACTIONS")=="true"
            and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
            and os.environ.get("GITHUB_REPOSITORY")=="LMhdez/gaslux"
            and os.environ.get("GASLUX_WINDOWS_POST_EXT4_REBOOT_CONSENT")==CONSENT
            and os.environ.get("GASLUX_WINDOWS_OVERLAY_REBOOT_CONSENT")==THIRD_BOOT_CONSENT
            and os.environ.get("GASLUX_CACHYOS_OVERLAY_EXT4_CONSENT")==EXT4_CONSENT
            and type(timeout) is int and 120<=timeout<=1800
            and evidence_stem in ("fourth-post-ext4", "sixth-post-pacstrap"),
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
    overlay=folder/OVERLAY_NAME
    nv_baseline=folder/"windows-ovmf-baseline.fd"
    trial_vars=folder/"trial-ovmf-variables.fd"
    for item in (overlay,nv_baseline,trial_vars): owned_regular(item,folder,item.name)
    require(stat.S_IMODE(base.stat().st_mode)==0o400
            and stat.S_IMODE(overlay.stat().st_mode)==0o600
            and stat.S_IMODE(nv_baseline.stat().st_mode)==0o400,
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
    return {
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

if __name__=="__main__":
    raise SystemExit("library only: no host devices or installer operations")
