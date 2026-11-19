#!/usr/bin/env python3
"""Private disposable nested QCOW2 checkpoint for subsequent native Pop install.

The real Win10 backing disk and post-Windows-boot six-GPT staging COW are
read-only parents. A NEW child COW is the ONLY possible future guest writer.
Creating a child is NOT authorization to execute distinst; signed handoff,
recovery and boot evidence remain independent gates.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Iterator

from windows_x64_installed_gpt_ro_audit import DiskAuditError, require

LAB_CONSENT = "I_ACCEPT_DISPOSABLE_CHILD_ONLY_AFTER_POP_LIVE_GPT_GUEST"
VM_SIZE = 128 * 1024**3
CHILD_NAME = "gaslux-pop-native-install.qcow2"
STAGE_NAME = "gaslux-pop-stage.qcow2"
BASE_NAME = "only-disposable-windows-target.qcow2"


def validate_native_child_chain(
    base: Path, stage: Path, child: Path,
    stage_info: dict, child_info: dict,
) -> None:
    require(
        type(stage_info) is dict and type(child_info) is dict
        and child == base.parent / CHILD_NAME
        and stage == base.parent / STAGE_NAME
        and base.name == BASE_NAME
        and child.parent.name.startswith("gaslux-win-x64-")
        and child.parent.parent == Path("/home/runner/work/_temp"),
        "unknown real-Windows nested COW paths",
    )
    for data, backing in ((stage_info, base), (child_info, stage)):
        require(
            data.get("format") == "qcow2"
            and data.get("virtual-size") == VM_SIZE
            and data.get("backing-filename") == str(backing)
            and data.get("backing-filename-format") == "qcow2"
            and data.get("encrypted", False) is False,
            "native child QCOW2 chain can address unowned/backing disks",
        )


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _info(path: Path) -> dict:
    return json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", str(path)], timeout=30,
    ))


@contextmanager
def disposable_native_child(
    base: Path, stage: Path, *,
    live_guest_gpt_verified: bool,
) -> Iterator[tuple[Path, dict]]:
    """Create/checkpoint a private child; prove parents unchanged on exit.

    Only used after guest native Pop live GPT read-only test, and ONLY on
    GitHub-hosted KVM disposable filesystem. The native writer MUST have its
    own separately authenticated plan and opt-in; this context gives none.
    """
    require(
        os.environ.get("GASLUX_POP_NATIVE_CHILD_COW_CONSENT") == LAB_CONSENT
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and live_guest_gpt_verified is True
        and base.is_file() and stage.is_file()
        and not base.is_symlink() and not stage.is_symlink()
        and base.parent == stage.parent
        and base.parent.parent == Path("/home/runner/work/_temp")
        and base.parent.name.startswith("gaslux-win-x64-")
        and base.parent.resolve() == base.parent
        and base.parent.stat().st_uid == os.getuid()
        and stat.S_IMODE(base.parent.stat().st_mode) == 0o700
        and base.stat().st_nlink == stage.stat().st_nlink == 1
        and stat.S_ISREG(base.stat().st_mode)
        and stat.S_ISREG(stage.stat().st_mode),
        "refuse native writer child without verified real Windows private COW",
    )
    child = base.parent / CHILD_NAME
    require(not child.exists() and not child.is_symlink(),
            "refuse native overlay path reuse")
    original_hash = _sha256(base)
    stage_hash = _sha256(stage)
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
         "-b", str(stage), str(child)],
        check=True, timeout=30, stdout=subprocess.DEVNULL,
    )
    try:
        require(
            child.is_file() and not child.is_symlink()
            and child.stat().st_uid == os.getuid()
            and stat.S_ISREG(child.stat().st_mode)
            and child.stat().st_nlink == 1,
            "native guest child not a single owned private QCOW2 file",
        )
        os.chmod(child, 0o600)
        validate_native_child_chain(base, stage, child,
                                    _info(stage), _info(child))
        proof = {
            "schemaVersion": 1,
            "scenario": "genuine_win10_pop_owned_native_child_checkpoint",
            "snapshotOfGenuineWindowsParentSha256": original_hash,
            "snapshotOfSixGptWindowsStageSha256": stage_hash,
            "writerMayUseOnlyPrivateNativeChild": True,
            "authenticatedNativeInstallHandoffVerified": False,
            "distinstExecutionAuthorized": False,
            "popInstalled": False,
            "windowsAfterPopInstallBootVerified": False,
            "rollbackVerified": False,
            "productionInstallationAuthorized": False,
        }
        yield child, proof
        # This does NOT validate child-written data, only parent immutability.
        require(_sha256(base) == original_hash and _sha256(stage) == stage_hash,
                "native guest child modified Windows backing or checkpoint stage")
    finally:
        require(
            child.parent == base.parent and child.name == CHILD_NAME
            and not child.is_symlink()
            and (not child.exists() or (
                child.is_file() and child.stat().st_nlink == 1
                and child.stat().st_uid == os.getuid())),
            "refuse cleanup of foreign native child",
        )
        child.unlink(missing_ok=True)
