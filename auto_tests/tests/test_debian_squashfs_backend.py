from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "assets/live/libertix-distribution-common.sh"

UNSQUASHFS_STUB = """#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -ll)
    path="$3"
    case " ${MOCK_MISSING_PATHS:-} " in
      *" $path "*) exit 0 ;;
    esac
    printf 'squashfs-root/%s\\n' "$path"
    ;;
  -cat)
    [ "$3" = "etc/os-release" ]
    cat "$MOCK_OS_RELEASE"
    ;;
  *)
    echo "unexpected unsquashfs arguments: $*" >&2
    exit 2
    ;;
esac
"""


def _run_identity_check(
    tmp_path: Path,
    *,
    expected_id: str,
    os_release: str,
    missing_paths: tuple[str, ...] = (),
    rootfs_exists: bool = True,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "unsquashfs"
    stub.write_text(UNSQUASHFS_STUB, encoding="utf-8")
    stub.chmod(0o755)

    rootfs = tmp_path / "filesystem.squashfs"
    if rootfs_exists:
        rootfs.write_bytes(b"synthetic fixture; never mounted or written as a disk")

    release_file = tmp_path / "os-release"
    release_file.write_text(os_release, encoding="utf-8")

    env = os.environ.copy()
    env.update(
        PATH=f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
        MOCK_OS_RELEASE=str(release_file),
        MOCK_MISSING_PATHS=" ".join(missing_paths),
    )
    return subprocess.run(
        [
            "bash",
            "-e",
            "-c",
            'source "$1"; assert_distribution_rootfs_compatible_or_die "$2" "$3"',
            "bash",
            str(HELPER),
            str(rootfs),
            expected_id,
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("expected_id", "os_release"),
    [
        ("linuxmint", "ID=linuxmint\\nID_LIKE=ubuntu debian\\n"),
        ("zorin", 'ID=zorin\\nID_LIKE="ubuntu debian"\\n'),
    ],
)
def test_official_legacy_distributions_pass_exact_identity_and_family_gate(
    tmp_path: Path, expected_id: str, os_release: str
) -> None:
    result = _run_identity_check(
        tmp_path, expected_id=expected_id, os_release=os_release
    )
    assert result.returncode == 0, result.stderr
    assert f"ID={expected_id}" in result.stdout


def test_mint_payload_cannot_claim_zorin_identity(tmp_path: Path) -> None:
    result = _run_identity_check(
        tmp_path,
        expected_id="zorin",
        os_release="ID=linuxmint\\nID_LIKE=ubuntu debian\\n",
    )
    assert result.returncode != 0
    assert "Distribution identity mismatch" in result.stderr


def test_debian_family_payload_missing_required_initramfs_tool_is_rejected(
    tmp_path: Path,
) -> None:
    result = _run_identity_check(
        tmp_path,
        expected_id="linuxmint",
        os_release="ID=linuxmint\\nID_LIKE=ubuntu debian\\n",
        missing_paths=("usr/bin/lsinitramfs",),
    )
    assert result.returncode != 0
    assert "missing required capability: usr/bin/lsinitramfs" in result.stderr


def test_exact_identity_outside_debian_ubuntu_family_is_rejected(
    tmp_path: Path,
) -> None:
    result = _run_identity_check(
        tmp_path,
        expected_id="alpine",
        os_release="ID=alpine\\nID_LIKE=alpine\\n",
    )
    assert result.returncode != 0
    assert "not in the Debian/Ubuntu family" in result.stderr


def test_missing_squashfs_payload_is_rejected_before_inspection(tmp_path: Path) -> None:
    result = _run_identity_check(
        tmp_path,
        expected_id="linuxmint",
        os_release="ID=linuxmint\\nID_LIKE=ubuntu debian\\n",
        rootfs_exists=False,
    )
    assert result.returncode != 0
    assert "Distribution root filesystem is missing" in result.stderr
