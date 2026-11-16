"""Non-destructive legacy Ubuntu backend routing and order regression tests."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "assets/live/configure-target-main.sh"


def _validate_target(
    *, distro: str, os_id: str, backend: str | None, firmware: str = "uefi"
) -> subprocess.CompletedProcess:
    # Execute only function definitions and the pure routing guard; never main().
    # The installed-system /tmp helper is omitted because no real devices are used.
    source = TARGET.read_text(encoding="utf-8")
    helper = ". /tmp/libertix-storage-common.sh\n"
    invocation = 'main "$@"\n'
    assert source.count(helper) == 1
    assert source.endswith(invocation)
    script = source.replace(helper, "", 1).removesuffix(invocation)
    env = os.environ.copy()
    env.update(
        LIBERTIX_FIRMWARE_MODE=firmware,
        DISTRIBUTION_ID=distro,
        DISTRIBUTION_OS_RELEASE_ID=os_id,
    )
    if backend is None:
        env.pop("GASLUX_TARGET_BACKEND", None)
    else:
        env["GASLUX_TARGET_BACKEND"] = backend
    return subprocess.run(
        ["bash", "-c", script + "\nvalidate_legacy_target_backend_or_die\n"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("distro", "os_id", "backend"),
    [
        ("mint", "linuxmint", None),
        ("zorin", "zorin", None),
        ("mint", "linuxmint", "debian-squashfs"),
        ("zorin", "zorin", "debian-squashfs"),
    ],
)
@pytest.mark.parametrize("firmware", ["bios", "uefi"])
def test_original_mint_zorin_targets_remain_eligible(distro, os_id, backend, firmware):
    result = _validate_target(distro=distro, os_id=os_id, backend=backend, firmware=firmware)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("distro", "os_id", "backend"),
    [
        ("popos", "pop", None),
        ("popos", "pop", "system76"),
        ("pop", "pop", "debian-squashfs"),
        ("cachyos", "cachyos", None),
        ("bazzite", "fedora", None),
        ("mint", "pop", None),
        ("zorin", "ubuntu", None),
        ("mint", "linuxmint", "system76"),
        ("mint", "linuxmint", "unknown"),
    ],
)
def test_unknown_or_system76_backend_fails_closed(distro, os_id, backend):
    result = _validate_target(distro=distro, os_id=os_id, backend=backend)
    assert result.returncode == 2
    assert "legacy" in result.stderr.lower()


def _body(source: str, function: str) -> str:
    return source.split(function + "() {", 1)[1].split("\n}", 1)[0]


def test_target_legacy_order_preserved_and_gate_precedes_mutations():
    source = TARGET.read_text(encoding="utf-8")
    common = _body(source, "configure_common_ubuntu_target")
    legacy = _body(source, "configure_legacy_grub_target")
    main = source.split("main() {", 1)[1].split("\n}\n\nmain", 1)[0]
    common_ops = [
        "configure_user",
        "configure_windows_mount",
        "configure_windows_readonly_request",
        "configure_windows_preferences",
        "configure_locale",
        "configure_windows_profile_shortcuts",
        "configure_keyboard",
        "configure_timezone",
        "configure_development_access",
    ]
    legacy_ops = [
        "cleanup_live_boot_artifacts",
        "refresh_installed_initramfs",
        "configure_grub",
        "enable_first_boot_resize",
    ]
    assert common.split() == common_ops
    assert legacy.split() == legacy_ops
    assert main.split() == [
        "validate_legacy_target_backend_or_die",
        "assert_target_distribution_identity",
        "configure_common_ubuntu_target",
        "configure_target_backend",
    ]


def test_legacy_guard_is_not_a_popos_install_entrypoint():
    source = TARGET.read_text(encoding="utf-8")
    guard = _body(source, "validate_legacy_target_backend_or_die")
    assert "mint:linuxmint|zorin:zorin" in guard
    assert "system76)" not in guard
    assert "popos:pop)" not in guard


def test_unsupported_firmware_is_rejected_without_target_mutation():
    result = _validate_target(distro="mint", os_id="linuxmint", backend=None, firmware="invalid")
    assert result.returncode == 2
    assert "Unsupported firmware mode" in result.stderr
