"""Static and early-refusal tests for disposable Q4OS installed-root lab.

Never makes partitions, mounts an ISO, starts a VM or writes a target.
A pass does not prove a real installed Linux boot.
"""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "gaslux_q4os_installed_root_lab.sh"


def _run(args, *, lab=False):
    import os

    env = os.environ.copy()
    env.pop("GASLUX_Q4OS_ALLOW_DISPOSABLE_INSTALL", None)
    if lab:
        env["GASLUX_Q4OS_ALLOW_DISPOSABLE_INSTALL"] = "yes"
    return subprocess.run(
        ["bash", str(SCRIPT), *map(str, args)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_refuse_disk_write_without_explicit_guest_only_opt_in(tmp_path):
    iso = tmp_path / "real.iso"
    iso.write_bytes(b"synthetic data")
    r = _run([iso, "0" * 64, tmp_path])
    assert r.returncode != 0
    assert "explicit laboratory opt-in" in r.stderr


def test_refuse_symlink_source_even_when_lab_opted_in(tmp_path):
    iso = tmp_path / "real.iso"
    iso.write_bytes(b"synthetic data")
    link = tmp_path / "link.iso"
    link.symlink_to(iso)
    r = _run([link, "0" * 64, tmp_path], lab=True)
    assert r.returncode != 0
    assert "non-symlink regular file" in r.stderr


def test_refuse_without_pinned_iso_digest(tmp_path):
    iso = tmp_path / "real.iso"
    iso.write_bytes(b"synthetic data")
    r = _run([iso, "untrusted", tmp_path], lab=True)
    assert r.returncode != 0
    assert "No pinned official ISO digest" in r.stderr


def test_disposable_target_only_and_installed_boot_requires_guest_serial_proof():
    src = SCRIPT.read_text(encoding="utf-8")
    assert 'work="$(mktemp -d -t gaslux-q4os-installed-lab-XXXXXX)"' in src
    assert 'disk="$work/guest-q4os-gpt.raw"' in src
    assert 'sgdisk --verify "$disk"' in src
    assert '[[ "$actual" == "$disk" ]]' in src
    assert 'sudo mkfs.vfat -F 32 -n GASLUXEFI "$efi_dev"' in src
    assert 'sudo mkfs.ext4 -F -q -L GASLUXQ4OS "$root_dev"' in src
    assert "GASLUX_Q4OS_ISO_ATTACHED_TO_INSTALLED_BOOT=false" in src
    assert "GASLUX_Q4OS_INSTALLED_ROOT_PROOF=6.10-deb13u1" in src
    assert "No installed Q4OS root boot proof" in src
    assert "-net none" in src
    assert "-cdrom" not in src
    assert 'id=guesttarget,format=raw,file="$disk"' in src
    assert "guest-only" in src.lower() or "guest-only" in SCRIPT.read_text(encoding="utf-8")
