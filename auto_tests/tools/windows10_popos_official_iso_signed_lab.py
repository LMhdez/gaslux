#!/usr/bin/env python3
"""Fetch ONLY upstream GPG-authenticated Pop!_OS Intel ISO for hosted QEMU lab.

Never used by production distribution catalogue. The concrete per-build URL,
SHA-256 and byte count come from System76's API, and the manifest signature
MUST authenticate that exact filename/hash with a separately pinned key
fingerprint. Failure never grants a disk writer or distro support.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import urllib.request

from windows_x64_installed_gpt_ro_audit import require

OFFICIAL_KEY = "63C46DF0140D738961429F4E204DD8AEC33A7AFF"
OFFICIAL_URL = re.compile(
    r"https://iso[.]pop-os[.]org/24[.]04/amd64/intel/([0-9]{1,4})/"
    r"pop-os_24[.]04_amd64_intel_\1[.]iso\Z"
)
HASH = re.compile("[0-9a-f]{64}\\Z")
API = "https://api.pop-os.org/builds/24.04/intel"
LAB_CONSENT = "I_ACCEPT_VERIFIED_POP_ISO_IN_DISPOSABLE_WINDOWS_KVM_VM"


def validate_signed_release_identity(data: dict, manifest: bytes) -> tuple[str, str, int]:
    """Exactly one signed checksum entry for the API-selected Pop ISO."""
    require(type(data) is dict
            and data.get("version") == "24.04"
            and data.get("channel") == "intel"
            and type(data.get("url")) is str
            and OFFICIAL_URL.fullmatch(data["url"]) is not None
            and type(data.get("size")) is int
            and 2_000_000_000 <= data["size"] <= 6_000_000_000
            and type(data.get("sha_sum")) is str
            and HASH.fullmatch(data["sha_sum"]) is not None,
            "unsupported/unpinned official System76 ISO metadata",
    )
    filename = data["url"].rsplit("/", 1)[1]
    try:
        text = manifest.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("non-ASCII signed ISO checksum manifest") from None
    matches = []
    for line in text.splitlines():
        hit = re.fullmatch(r"([0-9a-f]{64})\s+\*?([^/\s]+)", line)
        if hit and hit[2] == filename:
            matches.append(hit[1])
    require(matches == [data["sha_sum"]],
            "signed ISO manifest does not pin exact API-selected filename")
    return data["url"], data["sha_sum"], data["size"]


def require_hosted_iso_lab(workspace: Path) -> None:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("GITHUB_REPOSITORY") == "LMhdez/gaslux"
        and os.environ.get("GASLUX_POP_WINDOWS_COW_LIVE_ISO_CONSENT") == LAB_CONSENT
        and workspace.is_absolute()
        and workspace.parent == Path("/home/runner/work/_temp")
        and workspace.name.startswith("gaslux-win-x64-")
        and workspace.is_dir() and not workspace.is_symlink()
        and workspace.stat().st_uid == os.getuid()
        and stat.S_IMODE(workspace.stat().st_mode) == 0o700,
        "official Pop ISO fetch refused outside explicitly opted-in hosted VM",
    )


def _command(*argv: str, env: dict | None = None, timeout: int = 180) -> None:
    subprocess.run(argv, env=env, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL)


def _sha256(file: Path) -> str:
    with file.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def get_official_pop_iso(workspace: Path) -> tuple[Path, dict]:
    require_hosted_iso_lab(workspace)
    for binary in ("gpg", "curl", "aria2c"):
        require(shutil.which(binary) is not None, "missing official ISO signature tool")
    directory = workspace / "verified-system76"
    directory.mkdir(mode=0o700, exist_ok=False)
    gnupg = directory / "gnupg"
    gnupg.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(gnupg))
    with urllib.request.urlopen(API, timeout=45) as response:
        require(response.status == 200, "System76 official API did not respond 200")
        release = json.load(response)
    url = release.get("url", "")
    require(type(url) is str and OFFICIAL_URL.fullmatch(url) is not None,
            "untrusted System76 ISO download origin")
    manifest = directory / "SHA256SUMS"
    signature = directory / "SHA256SUMS.gpg"
    base = url.rsplit("/", 1)[0]
    _command("curl", "--fail", "--location", "--silent", "--show-error",
             "--retry", "4", "--max-time", "120",
             "--output", str(manifest), base + "/SHA256SUMS", timeout=180)
    _command("curl", "--fail", "--location", "--silent", "--show-error",
             "--retry", "4", "--max-time", "120",
             "--output", str(signature), base + "/SHA256SUMS.gpg", timeout=180)
    require(manifest.is_file() and manifest.stat().st_size < 100_000
            and signature.is_file() and signature.stat().st_size < 30_000,
            "invalid System76 signature or checksum manifest size")
    _command("gpg", "--batch", "--keyserver", "hkps://keyserver.ubuntu.com",
             "--recv-keys", OFFICIAL_KEY[-16:], env=env, timeout=120)
    lines = subprocess.check_output(
        ["gpg", "--batch", "--with-colons", "--fingerprint", OFFICIAL_KEY[-16:]],
        env=env, timeout=25, text=True,
    ).splitlines()
    fingerprints = [x.split(":")[9] for x in lines if x.startswith("fpr:")]
    require(fingerprints and fingerprints[0] == OFFICIAL_KEY,
            "official System76 signer fingerprint mismatch")
    _command("gpg", "--batch", "--verify", str(signature), str(manifest),
             env=env, timeout=30)
    url, digest, size = validate_signed_release_identity(
        release, manifest.read_bytes(),
    )
    free = shutil.disk_usage(workspace).free
    require(free >= size + 1_500_000_000,
            "insufficient hosted workspace to retain Pop ISO and Windows QCOW2")
    iso = directory / "verified-pop-24.04-intel.iso"
    _command(
        "aria2c", "--allow-overwrite=false", "--auto-file-renaming=false",
        "--max-tries=6", "--retry-wait=8", "--timeout=60",
        "--connect-timeout=30", "--split=8", "--max-connection-per-server=8",
        f"--checksum=sha-256={digest}", "--dir", str(directory),
        "--out", iso.name, url, timeout=2200,
    )
    require(iso.is_file() and not iso.is_symlink()
            and iso.stat().st_size == size and _sha256(iso) == digest,
            "verified Pop ISO bytes disagree with GPG-signed metadata")
    return iso, {
        "upstreamId": "pop", "version": "24.04", "variant": "intel",
        "officialIsoSignedMetadataVerified": True, "officialSignerFpr": OFFICIAL_KEY,
        "url": url, "isoSha256": digest, "isoSizeBytes": size,
        "nativeSystem76InstallVerified": False,
        "productionInstallationAuthorized": False,
    }
