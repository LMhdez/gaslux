#!/usr/bin/env python3
"""VM-only fourth Windows guest boot on fifth-ext4 COW. NO Linux install."""
from __future__ import annotations
import hashlib, json, os, stat, subprocess, tempfile, time
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
BOOT_PHASES = {
    "fourth-post-ext4": "WINDOWS_FOURTH_POST_EXT4",
    "bcd-control-windows-only": "BCD_AB_CONTROL_WINDOWS_ONLY",
    "sixth-post-pacstrap": "POST_PACSTRAP_WINDOWS",
}
COM1_WITNESSES = (
    b"GASLUX_COW_WIN10_REBOOT_LIVE=1",
    b"GASLUX_COW_WIN10_REBOOT_BUILD=19045",
    b"GASLUX_COW_WIN10_REBOOT_ESP=1",
    b"GASLUX_COW_WIN10_REBOOT_BCD=1",
    b"GASLUX_COW_WIN10_REBOOT_WINRE=1",
    b"GASLUX_COW_WIN10_REBOOT_FIFTH_GPT=1",
)
class FourthBootError(ValueError): pass
def require(ok, why):
    if not ok: raise FourthBootError(why)


def boot_failure_code(evidence_stem: str, reason: str) -> str:
    require(evidence_stem in BOOT_PHASES
            and reason in ("TIMEOUT", "QEMU_EXIT_NONZERO",
                           "COM1_REJECTED", "COM1_INCOMPLETE"),
            "invalid Windows QEMU failure phase")
    return BOOT_PHASES[evidence_stem] + "_" + reason


def read_bounded_com1_witness(serial: Path) -> dict:
    """Only hashed COM1 metadata and a fixed allowlist of marker names."""
    if not serial.exists() and not serial.is_symlink():
        return {"exists": False, "sizeBytes": 0, "markerNames": [],
                "completeBootWitness": False}
    require(not serial.is_symlink() and serial.is_file()
            and serial.lstat().st_uid == os.getuid()
            and serial.stat().st_nlink == 1
            and serial.stat().st_size <= 512_000,
            "untrusted Windows COM1 observation")
    data = serial.read_bytes()
    observed = [tag.decode("ascii")
                for tag in COM1_WITNESSES
                if data.splitlines().count(tag) == 1]
    return {"exists": True, "sizeBytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "markerNames": observed,
            "completeBootWitness": len(observed) == len(COM1_WITNESSES)}


def observe_windows_qemu(
    proc: subprocess.Popen, serial: Path,
    evidence_stem: str, timeout: int,
) -> str:
    """Require both independent COM1 witness and real QEMU process shutdown."""
    require(evidence_stem in BOOT_PHASES and type(timeout) is int
            and 120 <= timeout <= 1800,
            "unrecognized Windows QEMU observation phase")
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if serial.is_file():
            require(not serial.is_symlink() and serial.stat().st_size <= 512_000,
                    "untrusted or oversized Windows COM1")
            if b"GASLUX_COW_WIN10_REBOOT_FAIL=1" in serial.read_bytes():
                raise FourthBootError(boot_failure_code(
                    evidence_stem, "COM1_REJECTED"))
        rc = proc.poll()
        if rc is not None:
            if rc != 0:
                raise FourthBootError(boot_failure_code(
                    evidence_stem, "QEMU_EXIT_NONZERO"))
            try:
                return audit_complete_third_serial(serial)
            except (OSError, ValueError) as error:
                raise FourthBootError(boot_failure_code(
                    evidence_stem, "COM1_INCOMPLETE")) from error
        time.sleep(3)
    raise FourthBootError(boot_failure_code(evidence_stem, "TIMEOUT"))


def record_windows_boot_failure(
    *, base: Path, evidence_stem: str, serial: Path,
    overlay: Path, trial_vars: Path, original_vars_sha256: str,
    original_overlay_sha256: str | None, base_identity: dict,
    qemu_args: list[str], elapsed_seconds: float, timeout_seconds: int,
    observed_exit_code: int | None, forced_termination: bool,
    trace_file: Path | None, reason: str,
) -> Path:
    """Persist bounded host diagnostics: never claim guest boot from host output."""
    require(evidence_stem in BOOT_PHASES
            and serial == base.parent / (evidence_stem + "-windows-serial.log")
            and overlay.parent == trial_vars.parent
            and trial_vars.parent == base.parent / CHECKPOINT_DIR,
            "refusing non-owned Windows QEMU diagnostic paths")
    path = base.parent / (evidence_stem + "-boot-diagnostic.json")
    require(not path.exists() and not path.is_symlink(),
            "refusing reused Windows QEMU diagnostic")
    marker_snapshot = read_bounded_com1_witness(serial)
    current_vars_hash = sha256_file(trial_vars)
    trace_status = "not-configured" if trace_file is None else "not-created"
    trace_bytes = None
    trace_digest = None
    if trace_file is not None:
        require(trace_file.parent == base.parent
                and not trace_file.is_symlink(),
                "foreign Windows QEMU trace")
        if trace_file.is_file():
            trace_bytes = trace_file.stat().st_size
            trace_status = "present-bounded" if trace_bytes <= 10_000_000 else "oversized"
            if trace_bytes <= 10_000_000:
                trace_digest = sha256_file(trace_file)
    disk_after_sha = sha256_file(overlay) if original_overlay_sha256 else None
    payload = {
        "phase": BOOT_PHASES[evidence_stem],
        "failureCode": boot_failure_code(evidence_stem, reason),
        "source": "HOST_OBSERVATION_ONLY",
        "guestWindowsBootVerified": False,
        "productionStorageWritesAuthorized": False,
        "sameDiskDualBootVerified": False,
        "rollbackProven": False,
        "releaseEligible": False,
        "qemuLaunchAttempted": True,
        "qemuProfileSha256": hashlib.sha256(json.dumps(
            qemu_args, separators=(",", ":")).encode("utf-8")).hexdigest(),
        "elapsedSeconds": max(0, round(elapsed_seconds, 3)),
        "configuredTimeoutSeconds": timeout_seconds,
        "observedProcessExitCodeBeforeTermination": observed_exit_code,
        "forcedTermination": forced_termination,
        "com1": marker_snapshot,
        "initialOvmfVarsSha256": original_vars_sha256,
        "finalOvmfVarsSha256": current_vars_hash,
        "ovmfVarsChanged": current_vars_hash != original_vars_sha256,
        "initialControlCloneSha256": original_overlay_sha256,
        "finalControlCloneSha256": disk_after_sha,
        "controlCloneChanged": (
            disk_after_sha != original_overlay_sha256
            if original_overlay_sha256 is not None else None
        ),
        "immutableBackingIdentityUnchanged": qcow2_file_identity(base) == base_identity,
        "qemuTraceStatus": trace_status,
        "qemuTraceBytes": trace_bytes,
        "qemuTraceSha256": trace_digest,
    }
    data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    require(len(data) <= 8192, "Windows QEMU diagnostic exceeded size cap")
    with path.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    return path


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
    initial_vars_sha = sha256_file(trial_vars)
    initial_overlay_sha = (sha256_file(overlay)
                           if evidence_stem=="bcd-control-windows-only" else None)
    start=time.monotonic()
    stderr_path = base.parent/(evidence_stem+"-qemu-stderr.log")
    with stderr_path.open("xb") as stderr:
        proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=stderr)
        failure_reason: str | None = None
        observed_exit: int | None = None
        forced = False
        try:
            digest=observe_windows_qemu(proc, serial, evidence_stem, timeout)
        except FourthBootError as error:
            for candidate in ("TIMEOUT", "QEMU_EXIT_NONZERO",
                              "COM1_REJECTED", "COM1_INCOMPLETE"):
                if str(error) == boot_failure_code(evidence_stem, candidate):
                    failure_reason = candidate
                    break
            raise
        finally:
            observed_exit = proc.poll()
            if observed_exit is None:
                forced = True
                proc.kill()
                proc.wait(timeout=30)
            if failure_reason is not None:
                record_windows_boot_failure(
                    base=base, evidence_stem=evidence_stem,
                    serial=serial, overlay=overlay, trial_vars=trial_vars,
                    original_vars_sha256=initial_vars_sha,
                    original_overlay_sha256=initial_overlay_sha,
                    base_identity=identity, qemu_args=args,
                    elapsed_seconds=time.monotonic()-start,
                    timeout_seconds=timeout,
                    observed_exit_code=observed_exit,
                    forced_termination=forced,
                    trace_file=trace_file, reason=failure_reason)
    require(digest is not None,
            boot_failure_code(evidence_stem, "COM1_INCOMPLETE"))
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
