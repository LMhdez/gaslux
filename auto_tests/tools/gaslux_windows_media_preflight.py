#!/usr/bin/env python3
"""Private authorized-media transport preflight. No installation or writer."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import urllib.request
from urllib.parse import urlsplit

GIB = 1024**3
MINT_BYTES = 3091660800
MAX_MEDIA_BYTES = 16 * GIB
LAB_LIMIT = 85 * GIB
RESERVE = 8 * GIB
CHUNK = 1024**2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirect refused")


def validate_config(url, host, digest, raw_size, authorization):
    if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)+", host or ""):
        raise ValueError("Private media host not configured")
    if not url or any(ord(char) <= 32 or ord(char) >= 127 for char in url):
        raise ValueError("Missing or malformed media URL")
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname != host
            or parts.netloc not in (host, host + ":443")
            or parts.username is not None or parts.password is not None
            or parts.fragment or not parts.path.startswith("/")):
        raise ValueError("Unapproved media origin")
    if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        raise ValueError("Missing independently pinned SHA256")
    if not re.fullmatch(r"[1-9][0-9]{0,10}", raw_size or ""):
        raise ValueError("Missing exact media size")
    size = int(raw_size)
    if not 0 < size <= MAX_MEDIA_BYTES:
        raise ValueError("Media size outside supported bounds")
    if not authorization or not authorization.strip():
        raise ValueError("Custodian authorization reference absent")
    return size


def capacity(free, size):
    # Actual Windows + pinned Mint bytes, not the historical 4-GiB assumption.
    planned = 60 * GIB + 8 * GIB + RESERVE + MINT_BYTES + size
    return {"available_bytes": free, "planned_lab_bytes": planned,
            "planning_ceiling_bytes": LAB_LIMIT,
            "compact_lab_capacity_ready": free >= planned and planned <= LAB_LIMIT,
            "media_capacity_ready": free >= size + RESERVE}


def private_parent(value):
    parent = Path(value)
    if (not parent.is_absolute() or not parent.is_dir()
            or any(p.is_symlink() for p in (parent, *parent.parents))
            or parent == Path("/") or Path("/dev") in (parent, *parent.parents)):
        raise ValueError("Unsafe runner temporary root")
    return parent


def download_verified(url, digest, size, parent):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with tempfile.TemporaryDirectory(prefix="gaslux-private-media-", dir=parent) as work:
        target = Path(work) / "windows.iso"
        checksum = hashlib.sha256()
        count = 0
        with opener.open(request, timeout=60) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError("Unexpected response origin or status")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("Unexpected content encoding")
            length = response.headers.get("Content-Length")
            if length is not None and length != str(size):
                raise ValueError("Unexpected advertised length")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                while True:
                    chunk = response.read(min(CHUNK, size - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > size:
                        raise ValueError("Media exceeds pinned size")
                    checksum.update(chunk)
                    output.write(chunk)
        if count != size or not hmac.compare_digest(checksum.hexdigest(), digest):
            raise ValueError("Pinned media bytes do not match")
        # TemporaryDirectory removes the verified image on successful exit too.
        return count


def preflight(env):
    report = {"schema": "gaslux-private-windows-media-v1",
              "status": "blocked", "windows_media_authorization_declared": False,
              "windows_media_authorized": False, "windows_media_sha256_verified": False,
              "windows_guest_installed": False, "virtual_disk_writer_authorized": False,
              "dual_boot_verified": False, "release_eligible": False}
    try:
        url = env.get("GASLUX_WINDOWS_MEDIA_URL", "")
        digest = env.get("GASLUX_WINDOWS_MEDIA_SHA256", "")
        size = validate_config(url, env.get("GASLUX_WINDOWS_MEDIA_HOST", ""), digest,
                               env.get("GASLUX_WINDOWS_MEDIA_SIZE_BYTES", ""),
                               env.get("GASLUX_WINDOWS_MEDIA_AUTHORIZATION_REF", ""))
        report["windows_media_authorization_declared"] = True
        parent = private_parent(env.get("RUNNER_TEMP", ""))
        report.update(capacity(shutil.disk_usage(parent).free, size))
        if not report["media_capacity_ready"]:
            report["reason"] = "Insufficient private temporary storage"
            return report
        report["verified_media_bytes"] = download_verified(url, digest, size, parent)
        report["windows_media_sha256_verified"] = True
        report["status"] = "media_bytes_verified_only"
        report["reason"] = "Custodian declaration is not independent license or VM proof"
    except (OSError, RuntimeError, ValueError, TypeError):
        # Do not print exception text: HTTP errors may contain a signed URL.
        report["reason"] = "Media configuration, transport, digest or cleanup failed"
    return report


if __name__ == "__main__":
    print(json.dumps(preflight(os.environ), indent=2, sort_keys=True))
