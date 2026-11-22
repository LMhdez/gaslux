"""Non-destructive legacy Ubuntu backend routing and order regression tests."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "assets/live/configure-target-main.sh"


# Guard the actual squashfs capability scan used by the inherited Mint/Zorin
# backend. All unsquashfs output is synthetic; no ISO or disk is accessed.
SQUASHFS_HELPERS = ROOT / "assets/live/libertix-distribution-common.sh"


@pytest.mark.parametrize(
    ("listing", "tool_exit", "accepted"),
    [
        ("-rw-r--r-- root/root 100 2026-11-17 12:00 squashfs-root/etc/os-release", 0, True),
        (
            "lrwxrwxrwx root/root 1 2026-11-17 12:00 "
            "squashfs-root/etc/os-release -> ../usr/lib/os-release",
            0,
            True,
        ),
        ("-rw-r--r-- root/root 100 2026-11-17 12:00 squashfs-root/etc/os-release.old", 0, False),
        (
            "-rw-r--r-- root/root 100 2026-11-17 12:00 prefix/squashfs-root/etc/os-release",
            0,
            False,
        ),
        (
            "lrwxrwxrwx root/root 1 2026-11-17 12:00 "
            "squashfs-root/tmp/spoof -> squashfs-root/etc/os-release",
            0,
            False,
        ),
        ("unsquashfs: squashfs-root/etc/os-release", 0, False),
        ("", 0, False),
        ("-rw-r--r-- root/root 100 2026-11-17 12:00 squashfs-root/etc/os-release", 2, False),
    ],
)
def test_legacy_mint_zorin_squashfs_capabilities_require_exact_paths(
    listing: str, tool_exit: int, accepted: bool
):
    shell = (
        "set -euo pipefail\n"
        + SQUASHFS_HELPERS.read_text(encoding="utf-8")
        + r"""
unsquashfs() {
    printf '%s\n' "$MOCK_LISTING"
    return "$MOCK_EXIT"
}
distribution_squashfs_path_exists /fake/image.squashfs etc/os-release
"""
    )
    result = subprocess.run(
        ["bash", "-c", shell],
        env=dict(os.environ, MOCK_LISTING=listing, MOCK_EXIT=str(tool_exit)),
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted, result.stderr


@pytest.mark.parametrize(
    ("expected_id", "actual_id", "family", "broken_capability", "accepted"),
    [
        ("linuxmint", "linuxmint", "ubuntu", "", True),
        ("zorin", "zorin", "ubuntu debian", "", True),
        ("linuxmint", "zorin", "ubuntu", "", False),
        ("zorin", "zorin", "arch", "", False),
        ("linuxmint", "linuxmint", "ubuntu", "usr/sbin/update-grub", False),
    ],
)
def test_legacy_mint_zorin_payload_requires_real_capabilities_and_identity(
    tmp_path: Path,
    expected_id: str,
    actual_id: str,
    family: str,
    broken_capability: str,
    accepted: bool,
):
    rootfs = tmp_path / "filesystem.squashfs"
    rootfs.touch()
    shell = (
        "set -euo pipefail\n"
        + SQUASHFS_HELPERS.read_text(encoding="utf-8")
        + r"""
unsquashfs() {
    if [ "$1" = "-ll" ]; then
        path="$3"
        if [ "$path" = "$MOCK_BROKEN_CAPABILITY" ]; then
            path="$path.old"
        fi
        printf '%s\n' "-rw-r--r-- root/root 10 2026-11-17 12:00 squashfs-root/$path"
    elif [ "$1" = "-cat" ]; then
        printf 'ID=%s\nID_LIKE=%s\n' "$MOCK_ID" "$MOCK_FAMILY"
    else
        return 2
    fi
}
assert_distribution_rootfs_compatible_or_die "$MOCK_ROOTFS" "$MOCK_EXPECTED_ID"
"""
    )
    result = subprocess.run(
        ["bash", "-c", shell],
        env=dict(
            os.environ,
            MOCK_ROOTFS=str(rootfs),
            MOCK_EXPECTED_ID=expected_id,
            MOCK_ID=actual_id,
            MOCK_FAMILY=family,
            MOCK_BROKEN_CAPABILITY=broken_capability,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted, result.stderr


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


# These tests invoke the actual main() function but replace every operation that
# would read or write the installed target with an in-memory recorder. No
# filesystem, bootloader, account or partition command can be reached.
ORIGINAL_STEPS = [
    "assert_target_distribution_identity",
    "configure_user",
    "configure_windows_mount",
    "configure_windows_readonly_request",
    "configure_windows_preferences",
    "configure_locale",
    "configure_windows_profile_shortcuts",
    "configure_keyboard",
    "configure_timezone",
    "configure_development_access",
    "cleanup_live_boot_artifacts",
    "refresh_installed_initramfs",
    "configure_grub",
    "enable_first_boot_resize",
]


def _execute_mock_main(
    *, distro: str, os_id: str, backend: str | None, firmware: str
) -> subprocess.CompletedProcess:
    source = TARGET.read_text(encoding="utf-8")
    helper = ". /tmp/libertix-storage-common.sh\n"
    invocation = 'main "$@"\n'
    assert source.count(helper) == 1 and source.endswith(invocation)
    definitions = source.replace(helper, "", 1).removesuffix(invocation)
    stubs = "\n".join(f"{name}() {{ printf '%s\\n' '{name}'; }}" for name in ORIGINAL_STEPS)
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
        ["bash", "-c", definitions + "\n" + stubs + "\nmain\n"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("distro", "os_id"),
    [("mint", "linuxmint"), ("zorin", "zorin")],
)
@pytest.mark.parametrize("firmware", ["bios", "uefi"])
@pytest.mark.parametrize("backend", [None, "debian-squashfs"])
def test_mocked_legacy_main_preserves_every_original_action(distro, os_id, firmware, backend):
    result = _execute_mock_main(distro=distro, os_id=os_id, backend=backend, firmware=firmware)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ORIGINAL_STEPS


@pytest.mark.parametrize(
    ("distro", "os_id", "backend"),
    [
        ("popos", "pop", "system76"),
        ("cachyos", "cachyos", None),
        ("q4os", "q4os", None),
        ("bazzite", "bazzite", "fedora-atomic"),
        ("mint", "zorin", None),
        ("mint", "linuxmint", "system76"),
    ],
)
def test_mocked_unsupported_main_never_runs_any_target_action(distro, os_id, backend):
    result = _execute_mock_main(distro=distro, os_id=os_id, backend=backend, firmware="uefi")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "legacy" in result.stderr.lower()


# The ISO preflight is invoked with stubbed disk and mount commands. No real
# partition, loop device, ISO or filesystem is accessed by these regressions.
ISO_PREFLIGHT = ROOT / "assets/live/libertix-distribution-common.sh"
LIVE_INSTALLER = ROOT / "assets/live/libertix-install-main.sh"


@pytest.mark.parametrize(
    (
        "distro",
        "os_id",
        "hash_ok",
        "busy",
        "mount_ok",
        "rootfs_ok",
        "payload_ok",
        "umount_ok",
        "expected",
    ),
    [
        ("zorin", "zorin", 1, 0, 1, 1, 1, 1, ["HASH", "MOUNT", "PAYLOAD", "UNMOUNT"]),
        ("mint", "linuxmint", 1, 0, 1, 1, 1, 1, ["HASH", "MOUNT", "PAYLOAD", "UNMOUNT"]),
        ("zorin", "ubuntu", 1, 0, 1, 1, 1, 1, []),
        ("popos", "pop", 1, 0, 1, 1, 1, 1, []),
        ("zorin", "zorin", 0, 0, 1, 1, 1, 1, ["HASH"]),
        ("zorin", "zorin", 1, 1, 1, 1, 1, 1, ["HASH"]),
        ("zorin", "zorin", 1, 0, 0, 1, 1, 1, ["HASH", "MOUNT"]),
        ("zorin", "zorin", 1, 0, 1, 0, 1, 1, ["HASH", "MOUNT", "UNMOUNT"]),
        (
            "zorin",
            "zorin",
            1,
            0,
            1,
            1,
            0,
            1,
            ["HASH", "MOUNT", "PAYLOAD", "UNMOUNT"],
        ),
        (
            "zorin",
            "zorin",
            1,
            0,
            1,
            1,
            1,
            0,
            ["HASH", "MOUNT", "PAYLOAD", "UNMOUNT"],
        ),
    ],
)
def test_legacy_iso_preflight_fails_closed_and_releases_mounted_iso(
    distro, os_id, hash_ok, busy, mount_ok, rootfs_ok, payload_ok, umount_ok, expected
):
    shell = (
        ISO_PREFLIGHT.read_text(encoding="utf-8")
        + r"""
verify_file_sha256() { echo HASH; [ "$HASH_OK" = 1 ]; }
mkdir() { :; }
findmnt() { [ "$MOUNT_BUSY" = 1 ]; }
mount() { echo MOUNT; [ "$MOUNT_OK" = 1 ]; }
resolve_distribution_rootfs_or_die() {
    [ "$ROOTFS_OK" = 1 ] || return 1
    printf '%s\n' "/mnt/libertix-iso-preflight/casper/filesystem.squashfs"
}
assert_distribution_rootfs_compatible_or_die() {
    echo PAYLOAD
    [ "$PAYLOAD_OK" = 1 ]
}
umount() { echo UNMOUNT; [ "$UMOUNT_OK" = 1 ]; }
preflight_legacy_installer_iso_or_die /fake/zorin.iso hash "$DISTRO" "$OS_ID"
"""
    )
    env = dict(
        os.environ,
        DISTRO=distro,
        OS_ID=os_id,
        HASH_OK=str(hash_ok),
        MOUNT_BUSY=str(busy),
        MOUNT_OK=str(mount_ok),
        ROOTFS_OK=str(rootfs_ok),
        PAYLOAD_OK=str(payload_ok),
        UMOUNT_OK=str(umount_ok),
    )
    result = subprocess.run(
        ["bash", "-c", shell], env=env, capture_output=True, text=True, check=False
    )
    events = [
        line
        for line in result.stdout.splitlines()
        if line in {"HASH", "MOUNT", "PAYLOAD", "UNMOUNT"}
    ]
    assert events == expected
    expected_success = (distro, os_id) in {
        ("mint", "linuxmint"),
        ("zorin", "zorin"),
    } and all((hash_ok, not busy, mount_ok, rootfs_ok, payload_ok, umount_ok))
    assert (result.returncode == 0) == expected_success


def test_legacy_iso_guard_precedes_live_partition_writes_and_is_repeated():
    script = LIVE_INSTALLER.read_text(encoding="utf-8")
    first = script.index("preflight_legacy_installer_iso_or_die \\")
    unmount = script.index('mark "040-unmount-target-disk"')
    resize = script.index("prepare_offline_ntfs_resize_or_die", unmount)
    wipefs = script.index('mark "070-wipefs-live-part"')
    second_hash = script.index('verify_file_sha256 "$ISO_SOURCE" "$ISO_SHA256"', wipefs)
    second_payload = script.index("assert_distribution_rootfs_compatible_or_die", second_hash)
    assert first < unmount < resize < wipefs < second_hash < second_payload
