#!/usr/bin/env python3
"""Matched Windows-only vs CachyOS-treatment BCD control on disposable QCOW2 clones.

Both arms fork the exact same post-fourth-Windows checkpoint. The control boots
Windows once without Archiso/pacstrap; the treatment later runs the existing
signed Archiso/pacstrap path and boots Windows once. Each arm owns independent
OVMF VARS and cloned TPM 2.0 state. No Windows ESP/BCD/NVRAM repair or writes
are authorized by this diagnostic.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Iterator

from cachyos_windows_archiso_signed_plan_lab import read_windows_file_hashes
from windows_cachyos_cow_checkpoint import (
    CHECKPOINT_DIR, OVERLAY_NAME, owned_regular, sha256_file, validate_workspace,
)
from windows_cachyos_overlay_reboot import gpt_windows, third_guest_args
from windows_cachyos_postext4_windows import verify_windows_post_ext4
from windows_cachyos_postpacstrap_windows import (
    _read_bcd_readonly, summarize_bcd_difference,
)
from windows_cachyos_qcow2_gpt_readonly import qcow2_file_identity

CONSENT = "I_ACCEPT_WINDOWS_ONLY_BCD_AB_CONTROL_ON_DISPOSABLE_COW"
WINDOWS_CONTROL_OVERLAY = "bcd-ab-control-windows-only.qcow2"
WINDOWS_CONTROL_VARS = "bcd-ab-control-ovmf-variables.fd"
TPM_TEMPLATE = "bcd-ab-tpm-template"
TPM_CONTROL = "bcd-ab-tpm-control"
TPM_TREATMENT = "bcd-ab-tpm-treatment"
MAX_TPM_FILES = 64
MAX_TPM_FILE_BYTES = 4 * 1024 * 1024


class BcdAbControlError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise BcdAbControlError(reason)


def _copy_owned(source: Path, target: Path, mode: int) -> None:
    require(source.is_file() and not source.is_symlink()
            and source.stat().st_uid == os.getuid(),
            "A/B clone source is not an owned regular file")
    require(not target.exists() and not target.is_symlink(),
            "refusing reused A/B clone target")
    with source.open("rb") as src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    target.chmod(mode)
    st = target.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
            and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == mode,
            "A/B clone is not an exclusive owned regular file")


def tpm_state_tree_sha256(root: Path) -> str:
    require(root.is_dir() and not root.is_symlink()
            and root.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.stat().st_mode) == 0o700,
            "TPM state directory is not private and owned")
    entries = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    files = [p for p in entries if p.is_file() and not p.is_symlink()]
    require(0 < len(files) <= MAX_TPM_FILES,
            "TPM state tree has no files or exceeds bounded file count")
    digest = hashlib.sha256()
    for path in entries:
        st = path.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid == os.getuid(),
                "TPM state tree contains a symlink or foreign owner")
        if path.is_dir():
            continue
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                and 0 < st.st_size <= MAX_TPM_FILE_BYTES,
                "TPM state contains an unsafe or oversized file")
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(rel + b"\0" + bytes.fromhex(sha256_file(path)) + b"\n")
    return digest.hexdigest()


def prepare_independent_tpm_clones(workspace: Path) -> tuple[Path, Path, str]:
    require(shutil.which("swtpm") is not None
            and shutil.which("swtpm_setup") is not None,
            "swtpm and swtpm_setup are required for independent TPM control arms")
    template = workspace / TPM_TEMPLATE
    control = workspace / TPM_CONTROL
    treatment = workspace / TPM_TREATMENT
    for path in (template, control, treatment):
        require(not path.exists() and not path.is_symlink(),
                "refusing reused A/B TPM state directory")
    template.mkdir(mode=0o700)
    setup = subprocess.run(
        ["swtpm_setup", "--tpm2", "--tpmstate", str(template), "--createek"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    require(setup.returncode == 0,
            "could not initialize disposable TPM 2.0 baseline")
    template_hash = tpm_state_tree_sha256(template)
    shutil.copytree(template, control, symlinks=False)
    shutil.copytree(template, treatment, symlinks=False)
    control.chmod(0o700)
    treatment.chmod(0o700)
    control_hash = tpm_state_tree_sha256(control)
    treatment_hash = tpm_state_tree_sha256(treatment)
    require(control_hash == template_hash == treatment_hash
            and control != treatment,
            "independent TPM state clones differ from common baseline")
    return control, treatment, template_hash


@contextmanager
def running_swtpm(state_dir: Path, workspace: Path, label: str) -> Iterator[Path]:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
            and workspace.is_absolute()
            and workspace.parent == Path("/home/runner/work/_temp")
            and workspace.name.startswith("gaslux-win-x64-")
            and workspace.is_dir() and not workspace.is_symlink()
            and workspace.stat().st_uid == os.getuid()
            and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
            "TPM process refused outside private hosted Windows VM workspace")
    require(state_dir.parent == workspace and state_dir.name in
            (TPM_CONTROL, TPM_TREATMENT),
            "TPM process refused foreign state directory")
    tpm_state_tree_sha256(state_dir)
    socket = workspace / (label + ".sock")
    log = workspace / (label + "-swtpm.log")
    require(not socket.exists() and not socket.is_symlink()
            and not log.exists() and not log.is_symlink(),
            "refusing reused TPM socket or log")
    proc: subprocess.Popen | None = None
    with log.open("xb") as stderr:
        try:
            proc = subprocess.Popen(
                ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state_dir}",
                 "--ctrl", f"type=unixio,path={socket}",
                 "--flags", "not-need-init"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
            for _ in range(100):
                if proc.poll() is not None:
                    raise BcdAbControlError("swtpm exited before its TPM socket became ready")
                if socket.is_socket() and not socket.is_symlink():
                    break
                time.sleep(0.1)
            require(socket.is_socket() and not socket.is_symlink()
                    and socket.lstat().st_uid == os.getuid(),
                    "owned TPM 2.0 Unix socket did not become ready")
            yield socket
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
            if socket.exists() or socket.is_symlink():
                st = socket.lstat()
                require(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid(),
                        "refusing to remove non-owned TPM socket")
                socket.unlink()


def block_write_event_names(trace_help_text: str) -> list[str]:
    names: set[str] = set()
    for line in trace_help_text.splitlines():
        token = line.strip().split(maxsplit=1)[0] if line.strip() else ""
        if (re.fullmatch(r"[A-Za-z0-9_]+", token)
                and re.search(r"(?:blk|bdrv|qcow2|virtio_blk)", token, re.I)
                and re.search(r"(?:write|pwrite)", token, re.I)):
            names.add(token)
    return sorted(names)


def prepare_qemu_write_trace(workspace: Path) -> tuple[Path | None, list[str], str]:
    """Enable bounded QEMU block-write trace only when this QEMU build supports it."""
    try:
        probe = subprocess.run(
            ["qemu-system-x86_64", "-trace", "help"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, [], "unavailable-qemu-trace-help-failed"
    events = block_write_event_names(probe.stdout + "\\n" + probe.stderr)
    if probe.returncode != 0 or not events:
        return None, events, "unavailable-no-block-write-events"
    events_file = workspace / "bcd-ab-qemu-write-events.txt"
    probe_trace = workspace / "bcd-ab-qemu-trace-probe.bin"
    require(not events_file.exists() and not events_file.is_symlink()
            and not probe_trace.exists() and not probe_trace.is_symlink(),
            "refusing reused QEMU trace probe files")
    with events_file.open("xb") as out:
        out.write(("".join(name + "\n" for name in events)).encode("ascii"))
        out.flush()
        os.fsync(out.fileno())
    args = [
        "qemu-system-x86_64", "-machine", "none", "-nodefaults",
        "-display", "none", "-S", "-monitor", "none", "-serial", "none",
        "-trace", f"events={events_file},file={probe_trace}",
    ]
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.75)
        supported = process.poll() is None
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    if probe_trace.exists() or probe_trace.is_symlink():
        st = probe_trace.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid(),
                "QEMU trace probe produced an unsafe file")
        probe_trace.unlink()
    if not supported:
        events_file.unlink()
        return None, events, "unavailable-qemu-trace-backend-probe-failed"
    return events_file, events, "available"


def _profile_args(
    original: list[str], base: Path, nvram: Path, overlay: Path,
    trial_vars: Path, serial: Path, tpm_socket: Path,
    trace_events_file: Path | None, trace_file: Path | None,
) -> list[str]:
    args = third_guest_args(original, base, nvram, overlay, trial_vars, serial)
    args.extend([
        "-chardev", f"socket,id=chrtpm,path={tpm_socket}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis,tpmdev=tpm0",
    ])
    if trace_events_file is not None and trace_file is not None:
        args.extend(["-trace", f"events={trace_events_file},file={trace_file}"])
    return args


def _normalized_profile_digest(
    args: list[str], replacements: list[tuple[str, str]],
) -> str:
    normalized = []
    for item in args:
        value = item
        for source, token in replacements:
            value = value.replace(source, token)
        normalized.append(value)
    raw = json.dumps(normalized, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def run_windows_only_bcd_control(
    *, original: list[str], base: Path, nvram: Path,
    geometry: dict[str, Any], checkpoint: dict[str, Any],
    staged: dict[str, Any], third: dict[str, Any], ext4: dict[str, Any],
    fourth: dict[str, Any], workspace: Path, timeout: int = 1500,
) -> tuple[dict[str, Any], Path, Path | None, Path | None]:
    """Run arm A from an exact copy before arm B receives Archiso/pacstrap."""
    require(os.environ.get("GASLUX_CACHYOS_BCD_AB_CONTROL_CONSENT") == CONSENT,
            "separate Windows-only BCD A/B control consent required")
    require(type(timeout) is int and 120 <= timeout <= 1800,
            "A/B Windows control timeout outside safe bounds")
    validate_workspace(base, nvram)
    folder = workspace / CHECKPOINT_DIR
    overlay_b = folder / OVERLAY_NAME
    vars_b = folder / "trial-ovmf-variables.fd"
    owned_regular(overlay_b, folder, OVERLAY_NAME)
    owned_regular(vars_b, folder, vars_b.name)
    require(stat.S_IMODE(overlay_b.stat().st_mode) == 0o600
            and stat.S_IMODE(vars_b.stat().st_mode) == 0o600
            and stat.S_IMODE(base.stat().st_mode) == 0o400,
            "A/B checkpoint permissions are unsafe")

    overlay_a = folder / WINDOWS_CONTROL_OVERLAY
    vars_a = folder / WINDOWS_CONTROL_VARS
    overlay_b_before = sha256_file(overlay_b)
    vars_b_before = sha256_file(vars_b)
    base_before = sha256_file(base)
    base_identity = qcow2_file_identity(base)
    nvram_before = sha256_file(nvram)
    _copy_owned(overlay_b, overlay_a, 0o600)
    _copy_owned(vars_b, vars_a, 0o600)
    require(sha256_file(overlay_a) == overlay_b_before
            and sha256_file(vars_a) == vars_b_before,
            "A/B COW or OVMF VARS clone differs byte-for-byte")
    compare = subprocess.run(
        ["qemu-img", "compare", "-f", "qcow2", "-F", "qcow2",
         str(overlay_b), str(overlay_a)],
        capture_output=True, text=True, timeout=180, check=False,
    )
    require(compare.returncode == 0,
            "A/B guest-visible disk images are not identical")
    info = subprocess.run(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", str(overlay_a)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    require(info.returncode == 0, "cannot inspect Windows-only control QCOW2")
    try:
        doc = json.loads(info.stdout)
    except ValueError as error:
        raise BcdAbControlError("invalid Windows-only control QCOW2 metadata") from error
    require(doc.get("format") == "qcow2"
            and doc.get("virtual-size") == 128 * 1024**3
            and doc.get("backing-filename") == str(base)
            and doc.get("backing-filename-format") == "qcow2",
            "Windows-only control clone does not share the exact immutable Windows backing")

    protected_before_b = read_windows_file_hashes(overlay_b)
    protected_before_a = read_windows_file_hashes(overlay_a)
    require(protected_before_a == protected_before_b,
            "A/B initial protected Windows hashes differ")
    bcd_before_a = _read_bcd_readonly(overlay_a)
    bcd_before_b = _read_bcd_readonly(overlay_b)
    require(hashlib.sha256(bcd_before_a).hexdigest()
            == hashlib.sha256(bcd_before_b).hexdigest()
            == protected_before_a["espBcdSha256"],
            "A/B initial BCD bytes do not match the protected manifest")
    with tempfile.TemporaryDirectory(prefix="gaslux-bcd-ab-gpt-",
                                                    dir=workspace) as scratch:
        gpt_before_a = gpt_windows(overlay_a, Path(scratch))
    with __import__("tempfile").TemporaryDirectory(prefix="gaslux-bcd-ab-gpt-b-",
                                                    dir=workspace) as scratch:
        gpt_before_b = gpt_windows(overlay_b, Path(scratch))
    require(gpt_before_a == gpt_before_b,
            "A/B initial primary/secondary GPT bytes differ")

    tpm_a, tpm_b, tpm_initial = prepare_independent_tpm_clones(workspace)
    trace_events_file, trace_events, trace_status = prepare_qemu_write_trace(workspace)
    trace_a = workspace / "bcd-control-windows-only-qemu-trace.bin"
    trace_b = workspace / "sixth-post-pacstrap-qemu-trace.bin"
    if trace_events_file is None:
        trace_a = None
        trace_b = None
    serial_a = workspace / "bcd-control-windows-only-windows-serial.log"
    serial_b = workspace / "sixth-post-pacstrap-windows-serial.log"
    socket_a = workspace / "bcd-ab-control-tpm.sock"
    socket_b = workspace / "bcd-ab-treatment-tpm.sock"
    args_a = _profile_args(
        original, base, nvram, overlay_a, vars_a, serial_a, socket_a,
        trace_events_file, trace_a,
    )
    args_b = _profile_args(
        original, base, nvram, overlay_b, vars_b, serial_b, socket_b,
        trace_events_file, trace_b,
    )
    replacements = [
        (str(overlay_a), "<WINDOWS_COW>"),
        (str(overlay_b), "<WINDOWS_COW>"),
        (str(vars_a), "<OVMF_VARS>"),
        (str(vars_b), "<OVMF_VARS>"),
        (str(serial_a), "<COM1>"),
        (str(serial_b), "<COM1>"),
        (str(socket_a), "<TPM_SOCKET>"),
        (str(socket_b), "<TPM_SOCKET>"),
        (str(trace_a), "<TRACE_FILE>") if trace_a else ("<NO_TRACE_A>", "<NO_TRACE_A>"),
        (str(trace_b), "<TRACE_FILE>") if trace_b else ("<NO_TRACE_B>", "<NO_TRACE_B>"),
    ]
    profile_a = _normalized_profile_digest(args_a, replacements)
    profile_b = _normalized_profile_digest(args_b, replacements)
    require(profile_a == profile_b,
            "A/B Windows QEMU argument profiles differ beyond isolated paths")

    with running_swtpm(tpm_a, workspace, "bcd-ab-control-tpm") as socket:
        boot = verify_windows_post_ext4(
            original, base, nvram, geometry, checkpoint, staged, third, ext4,
            timeout=timeout, evidence_stem="bcd-control-windows-only",
            overlay_override=overlay_a, trial_vars_override=vars_a,
            tpm_socket=socket, trace_events_file=trace_events_file,
            trace_file=trace_a,
        )

    bcd_after_a = _read_bcd_readonly(overlay_a)
    protected_after_a = read_windows_file_hashes(overlay_a)
    bcd_forensic = summarize_bcd_difference(bcd_before_a, bcd_after_a)
    require(hashlib.sha256(bcd_after_a).hexdigest()
            == protected_after_a["espBcdSha256"],
            "control BCD read-only bytes disagree with protected-file hash")
    protected_mismatches = [
        key for key in protected_before_a
        if protected_after_a.get(key) != protected_before_a[key]
    ]
    other_mismatches = [key for key in protected_mismatches if key != "espBcdSha256"]
    require(not other_mismatches,
            "Windows-only control changed protected non-BCD files: "
            + ",".join(other_mismatches))
    with __import__("tempfile").TemporaryDirectory(prefix="gaslux-bcd-ab-gpt-after-",
                                                    dir=workspace) as scratch:
        gpt_after_a = gpt_windows(overlay_a, Path(scratch))
    require(gpt_after_a == gpt_before_a,
            "Windows-only control changed primary or secondary GPT bytes")
    require(boot.get("windowsBootAfterExt4Verified") is True
            and boot.get("fifthExt4UuidSurvivedWindowsBoot") is True,
            "Windows-only control did not preserve the fifth ext4 identity")
    require(sha256_file(base) == base_before
            and qcow2_file_identity(base) == base_identity
            and sha256_file(nvram) == nvram_before,
            "Windows-only control changed immutable Windows backing or original NVRAM")
    require(sha256_file(overlay_b) == overlay_b_before
            and sha256_file(vars_b) == vars_b_before,
            "Windows-only control modified the independent treatment arm")
    require(tpm_state_tree_sha256(tpm_b) == tpm_initial,
            "Windows-only control modified the independent treatment TPM state")
    control_tpm_after = tpm_state_tree_sha256(tpm_a)
    vars_a_after = sha256_file(vars_a)
    require(vars_a_after != "" and vars_b_before == sha256_file(vars_b),
            "A/B OVMF variable copies were not independent")

    report: dict[str, Any] = {
        "controlArm": "Windows-only",
        "treatmentArm": "CachyOS Archiso/pacstrap then Windows",
        "controlWindowsBootVerified": True,
        "controlWindowsBootOrdinal": 5,
        "treatmentWindowsBootOrdinal": 5,
        "sameWindowsBootCountVerified": True,
        "sameCheckpointDiskCloneVerified": True,
        "sameCheckpointOverlayBytesSha256": overlay_b_before,
        "sameCheckpointGuestVisibleDiskVerified": True,
        "sameCheckpointPrimaryAndSecondaryGptVerified": True,
        "controlAndTreatmentInitialGptEqual": True,
        "controlAndTreatmentInitialProtectedHashesEqual": True,
        "controlAndTreatmentInitialBcdEqual": True,
        "controlBcdBeforeWindowsSha256": bcd_forensic["prebootBcdSha256"],
        "controlBcdAfterWindowsSha256": bcd_forensic["postbootBcdSha256"],
        "controlBcdForensic": bcd_forensic,
        "controlProtectedHashMismatchKeys": protected_mismatches,
        "controlOtherProtectedHashesUnchanged": True,
        "controlWindowsGptUnchanged": True,
        "controlFifthExt4IdentityPreserved": True,
        "controlWindowsBackingAndOriginalNVRAMUnchanged": True,
        "independentOvmfCopiesVerified": (
            vars_a != vars_b
            and vars_a.lstat().st_ino != vars_b.lstat().st_ino
            and vars_a.lstat().st_nlink == vars_b.lstat().st_nlink == 1
            and sha256_file(vars_a) == vars_b_before
            and sha256_file(vars_b) == vars_b_before
        ),
        "controlOvmfInitialSha256": vars_b_before,
        "treatmentOvmfInitialSha256": vars_b_before,
        "controlOvmfPostBootSha256": vars_a_after,
        "independentTpmStateClonesVerified": tpm_a != tpm_b
            and tpm_initial == tpm_state_tree_sha256(tpm_b),
        "tpmVersion": "2.0",
        "previousWindows10ProfileHadNoTpm": True,
        "matchedArmsUseSameFreshTpm2Baseline": True,
        "tpmInitialStateTreeSha256": tpm_initial,
        "controlTpmPostBootStateTreeSha256": control_tpm_after,
        "treatmentTpmInitialStateTreeSha256": tpm_initial,
        "sameQemuArgumentsExceptOwnedPathsVerified": True,
        "qemuArgumentsProfileSha256": profile_a,
        "qemuWriteTraceStatus": trace_status,
        "qemuWriteTraceEvents": trace_events,
        "controlQemuWriteTraceSha256": boot.get("qemuWriteTraceSha256"),
        "controlQemuWriteTraceBytes": boot.get("qemuWriteTraceBytes"),
        "productionStorageWritesAuthorized": False,
        "windowsEspWritesAllowed": False,
        "sameDiskDualBootVerified": False,
        "rollbackProven": False,
        "releaseEligible": False,
    }
    return report, tpm_b, trace_events_file, trace_b


def compare_bcd_ab(control: dict[str, Any], treatment: dict[str, Any]) -> dict[str, Any]:
    """Classify A/B outcomes without claiming process-level attribution."""
    require(type(control) is dict and type(treatment) is dict,
            "A/B BCD evidence must be JSON objects")
    required = ("prebootBcdSha256", "postbootBcdSha256", "changedByteCount",
                "firstChangedByteSpans")
    require(all(key in control for key in required)
            and all(key in treatment for key in required),
            "A/B BCD evidence is incomplete")
    initial_equal = control["prebootBcdSha256"] == treatment["prebootBcdSha256"]
    control_changed = control["changedByteCount"] > 0
    treatment_changed = treatment["changedByteCount"] > 0
    post_equal = control["postbootBcdSha256"] == treatment["postbootBcdSha256"]
    if not initial_equal:
        classification = "INVALID_INITIAL_BCD_MISMATCH"
    elif not control_changed and not treatment_changed:
        classification = "NO_BCD_MUTATION_IN_EITHER_ARM"
    elif control_changed and treatment_changed and post_equal:
        classification = (
            "WINDOWS_ONLY_CONTROL_REPRODUCED_IDENTICAL_BCD_MUTATION;"
            " NO_ADDITIONAL_CACHYOS_BCD_DELTA"
        )
    elif not control_changed and treatment_changed:
        classification = "TREATMENT_ASSOCIATED_BCD_MUTATION"
    elif control_changed and not treatment_changed:
        classification = "CONTROL_ONLY_BCD_MUTATION"
    else:
        classification = (
            "POSTBOOT_BCD_STATES_DIFFER;"
            " TREATMENT_ASSOCIATION_OR_WINDOWS_NONDETERMINISM"
        )
    control_spans = {(x["offset"], x["length"])
                     for x in control["firstChangedByteSpans"]}
    treatment_spans = {(x["offset"], x["length"])
                       for x in treatment["firstChangedByteSpans"]}
    return {
        "initialBcdEqual": initial_equal,
        "controlBcdChanged": control_changed,
        "treatmentBcdChanged": treatment_changed,
        "controlAndTreatmentPostBootBcdEqual": post_equal,
        "controlChangedByteCount": control["changedByteCount"],
        "treatmentChangedByteCount": treatment["changedByteCount"],
        "first24ChangedSpansEqual": control_spans == treatment_spans,
        "classification": classification,
        "processAttributionProven": False,
        "approvedMutation": False,
        "productionStorageWritesAuthorized": False,
        "releaseEligible": False,
    }


if __name__ == "__main__":
    raise SystemExit("Library only: requires matched disposable Windows A/B QCOW2 clones.")
