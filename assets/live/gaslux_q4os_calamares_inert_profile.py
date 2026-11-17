#!/usr/bin/env python3
"""Build a fail-closed, inert Q4OS Calamares lab overlay from verified ISO evidence.

Only creates data files *inside* the validated, private evidence directory.
It neither runs Calamares nor authorizes partition, EFI or package writes.
All three upstream native process jobs are replaced by /bin/false until a
separately validated live-guest transaction-bound executor exists.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import yaml

from gaslux_q4os_calamares_policy import CalamaresRefusal, _yaml
from gaslux_q4os_hook_policy import audit_q4os_native_hooks

OFFICIAL_ISO_SHA256 = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
JOBS = (
    "partition", "mount", "unpackfs", "luksbootkeyfile", "dpkg-unsafe-io",
    "sources-media", "machineid", "fstab", "locale", "keyboard",
    "localecfg", "users", "displaymanager", "networkcfg", "hwclock",
    "services-systemd", "q4oshook2", "bootloader-config", "grubcfg",
    "bootloader", "q4oshook3", "packages", "plymouthcfg", "initramfscfg",
    "initramfs", "q4oshook5", "dpkg-unsafe-io-undo",
    "sources-media-unmount", "umount",
)
NATIVE_HOOKS = ("q4oshook2", "q4oshook3", "q4oshook5")
EXPECTED_VIEWS = (
    ["welcome", "locale", "keyboard", "packagechooser",
     "partition", "users", "summary"],
    ["finished"],
)


def _dump_yaml(path: Path, data: dict) -> str:
    if path.exists() or path.is_symlink():
        raise CalamaresRefusal("Refusing to overwrite an existing overlay file")
    payload = yaml.safe_dump(data, allow_unicode=False, sort_keys=False).encode("utf-8")
    with path.open("xb") as handle:
        handle.write(payload)
    path.chmod(0o600)
    return hashlib.sha256(payload).hexdigest()


def create_inert_calamares_profile(evidence: Path) -> dict:
    """Create an *inactive* overlay anchored to an audited official Q4OS ISO.

    A machine must not activate this profile as an installer. /bin/false
    blockers intentionally prevent bootloader, firmware and hook commands.
    """
    if not isinstance(evidence, Path) or not evidence.is_absolute():
        raise CalamaresRefusal("Evidence must be an absolute directory")
    if evidence.is_symlink() or not evidence.is_dir():
        raise CalamaresRefusal("Evidence directory is absent or symlinked")
    provenance = audit_q4os_native_hooks(evidence)
    if provenance["version"] != "6.10-deb13u1":
        raise CalamaresRefusal("Unknown Q4OS installer version")
    if provenance["hookExecutionAuthorized"] or provenance["diskWrites"]:
        raise CalamaresRefusal("Input claims unsafe native hook authorization")
    original_settings = _yaml(evidence, "etc__calamares__settings.conf")
    sequence = original_settings["sequence"]
    if len(sequence) != 3:
        raise CalamaresRefusal("Unexpected full native sequence")
    if sequence[0] != {"show": EXPECTED_VIEWS[0]}:
        raise CalamaresRefusal("Unexpected native welcome/partition/users views")
    if sequence[1] != {"exec": list(JOBS)}:
        raise CalamaresRefusal("Unexpected official native job graph")
    if sequence[2] != {"show": EXPECTED_VIEWS[1]}:
        raise CalamaresRefusal("Unexpected installer final page")

    boot = _yaml(evidence, "etc__calamares__modules__bootloader.conf")
    if boot.get("installEFIFallback") is not True or boot.get("efiBootLoader") != "grub":
        raise CalamaresRefusal("Upstream boot semantics have changed")
    if boot.get("grubInstall") != "grub-install":
        raise CalamaresRefusal("Unrecognized upstream GRUB installer")
    pkg = _yaml(evidence, "etc__calamares__modules__packages.conf")
    if (
        pkg.get("backend") != "apt"
        or pkg.get("update_db") is not False
        or pkg.get("update_system") is not False
    ):
        raise CalamaresRefusal("Unrecognized upstream package policy")

    # Refuse any authorization: these names are data-only overlays and are
    # intentionally unusable for a real unattended installation at this stage.
    boot["installEFIFallback"] = False
    boot["efiBootloaderId"] = "GasluxQ4OSLab"
    for binary in ("grubInstall", "grubMkconfig", "efiBootMgr"):
        boot[binary] = "/bin/false"
    pkg["operations"] = []
    pkg["skip_if_no_internet"] = True

    folder = evidence / "calamares-inert-profile"
    if folder.exists() or folder.is_symlink():
        raise CalamaresRefusal("Refusing to replace a prior Calamares profile")
    # No path is supplied for an arbitrary target: only this owned subdir.
    folder.mkdir(mode=0o700)
    config = folder / "etc" / "calamares"
    (config / "modules").mkdir(parents=True, mode=0o700)
    native_modules = folder / "usr" / "lib" / "calamares" / "modules"
    native_modules.mkdir(parents=True, mode=0o700)
    hashes = {}
    hashes["etc/calamares/settings.conf"] = _dump_yaml(
        config / "settings.conf", original_settings
    )
    hashes["etc/calamares/modules/bootloader.conf"] = _dump_yaml(
        config / "modules" / "bootloader.conf", boot
    )
    hashes["etc/calamares/modules/packages.conf"] = _dump_yaml(
        config / "modules" / "packages.conf", pkg
    )
    for name in NATIVE_HOOKS:
        path = native_modules / name / "module.desc"
        path.parent.mkdir(mode=0o700)
        descriptor = {
            "type": "job",
            "name": name,
            "interface": "process",
            "command": "/bin/false",
            "timeout": {"q4oshook2": 3600, "q4oshook3": 18000, "q4oshook5": 600}[name],
        }
        hashes[f"usr/lib/calamares/modules/{name}/module.desc"] = _dump_yaml(
            path, descriptor
        )
    report = {
        "profile": "q4os-calamares-inert-v1",
        "officialIsoSha256Prerequisite": OFFICIAL_ISO_SHA256,
        "version": provenance["version"],
        "nativeShowCount": len(EXPECTED_VIEWS[0]) + len(EXPECTED_VIEWS[1]),
        "nativeExecJobsCount": len(JOBS),
        "nativeFullExecOrderVerified": True,
        "nativeHookProvenanceSha256": provenance["nativeHookSourceSha256"],
        "generatedFileSha256": hashes,
        "upstreamNativeHooksExecuted": False,
        "calamaresJobEngineExecuted": False,
        "calamaresCompleteInstallation": False,
        "installationAuthorized": False,
        "profileActivationAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "firmwareNvramWriteAuthorized": False,
        "originalEfiFallbackEnabled": True,
        "inertProfileEfiFallbackEnabled": False,
        "unsafePackagesRemovalDisabled": True,
        "grubAndNvramCommandsBlocked": True,
        "diskWrites": 0,
    }
    output = folder / "profile-audit.json"
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, sort_keys=True, indent=2)
        handle.write("\n")
    output.chmod(0o600)
    return report


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: gaslux_q4os_calamares_inert_profile.py EVIDENCE_DIR")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("REFUSED: inert profile may only be built on disposable Actions")
    result = create_inert_calamares_profile(Path(sys.argv[1]))
    if result["installationAuthorized"] or result["profileActivationAuthorized"]:
        raise SystemExit("REFUSED: profile is never authorization to install")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
