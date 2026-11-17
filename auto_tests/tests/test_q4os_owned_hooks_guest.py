"""Guest-only Q4OS process-hook replacement security regressions.

These unit tests execute no Calamares job, format no disk and create no users.
"""

import os
import subprocess
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
HOOK = TOOLS / "gaslux_q4os_owned_hooks_guest.sh"
HOST = TOOLS / "gaslux_q4os_installed_root_lab.sh"
BOOT = TOOLS / "gaslux_q4os_native_grub_guest.sh"


def test_safe_owned_hooks_never_guess_a_target_or_touch_windows():
    script = HOOK.read_text(encoding="utf-8")
    for evidence in (
        "GASLUX-Q4OS-ROOT",
        "GASLUX-Q4OS-ESP",
        "gaslux-q4os-lab-transaction.id",
        "gaslux-q4os-lab-root.uuid",
        "gaslux-q4os-lab-esp.uuid",
        "gaslux-q4os-lab-iso.sha256",
        "/dev/vda2",
        "/dev/vda1",
        "unexpected-additional-guest-disk",
        "Windows-ESP-resource-present",
        "symlink-into-unowned-ESP",
        "transaction-state-owned-by-other-install",
        "aptCleanup=blocked;profileInstaller=blocked;legacyEFI=blocked",
        "update-grub",
        "EFI-binary-changed-by-update-grub",
        "GASLUX_Q4OS_OWNED_HOOKS_VERIFIED",
    ):
        assert evidence in script
    assert "mount | grep proc | grep calamares" not in script
    assert "chroot $CHROOT" not in script
    assert "rm -rf $CHROOT" not in script
    assert "dpkg --purge --force-remove-essential" not in script
    assert "grub-install --force" not in script


def test_safe_hook_refuses_unknown_phase_without_writes():
    result = subprocess.run(
        ["bash", str(HOOK), "run-upstream-hooks"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "unknown-phase" in result.stderr


def test_safe_hook_refuses_running_on_host():
    result = subprocess.run(
        ["bash", str(HOOK), "hook2"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "GASLUX_Q4OS_OWNED_HOOK_REFUSED" in result.stderr


def test_lab_is_opt_in_and_guest_only(tmp_path):
    script = HOST.read_text(encoding="utf-8")
    assert 'owned_hooks="${GASLUX_Q4OS_OWNED_HOOK_LAB:-no}"' in script
    assert '[[ "$native_grub" == yes && "${GITHUB_ACTIONS:-}" == true ]]' in script
    assert "nativeHookCommandsExecuted" in script
    assert "hookExecutionAuthorized" in script
    assert "native-hook-source-audit.json" in script
    assert "gaslux_q4os_owned_hooks_guest.sh" in script
    assert "gaslux-q4os-lab-transaction.id" in script
    assert "GASLUX_Q4OS_OWNED_HOOK2=" in script
    assert "GASLUX_Q4OS_OWNED_HOOK3=" in script
    assert "GASLUX_Q4OS_OWNED_HOOK5=" in script
    assert "GASLUX_Q4OS_OWNED_HOOKS_VERIFIED=" in script
    assert "-net none" in script
    assert 'file="$disk"' in script

    iso = tmp_path / "not-real.iso"
    iso.write_bytes(b"fake")
    env = os.environ.copy()
    env["GASLUX_Q4OS_ALLOW_DISPOSABLE_INSTALL"] = "yes"
    env["GASLUX_Q4OS_NATIVE_GRUB_LAB"] = "yes"
    env["GASLUX_Q4OS_OWNED_HOOK_LAB"] = "yes"
    env.pop("GITHUB_ACTIONS", None)
    run = subprocess.run(
        ["bash", str(HOST), str(iso), "0" * 64, str(tmp_path)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert run.returncode != 0
    assert "require the native-GRUB disposable GitHub Actions guest" in run.stderr


def test_owned_adapters_surround_package_native_bootloader():
    source = BOOT.read_text(encoding="utf-8")
    assert source.index('"$owned_hook_tool" hook2') < source.index("grub-install --target")
    assert source.index("grub-install --target") < source.index('"$owned_hook_tool" hook3')
    assert source.index('"$owned_hook_tool" hook3') < source.index('"$owned_hook_tool" hook5')
    assert '"$owned_hook_tool" verify' in source
