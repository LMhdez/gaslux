#!/usr/bin/env python3
"""Read-only Microsoft evaluation ISO HTTP origin probe (never downloads media).

Checks HTTPS redirect chain and metadata on the actual GitHub Linux runner.
It cannot establish a Windows ISO's SHA-256, Windows boot, WinRE or dual boot.
Never print signed CDN URLs or query parameters in logs/reports.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from windows_x64_qemu_host_gate import EXPECTED, load_catalog
from windows_x64_tcg_firstboot import (
    EXPECTED_FINAL_HOSTS, MAX_ISO_SIZE, MIN_ISO_SIZE, LabError, MicrosoftOnlyRedirect
)

CONSENT = "I_ACCEPT_READ_ONLY_MICROSOFT_ORIGIN_PROBE"
PERMITTED_START = {"go.microsoft.com"}


def validate_origin(url: str, allowed_hosts: set[str]) -> str:
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts or
            parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443)):
        raise LabError("Windows evaluation ISO metadata URL is not allowlisted HTTPS")
    return parsed.hostname


def parse_iso_length(headers, code: int) -> int | None:
    size = headers.get("Content-Length")
    if code == 206:
        content_range = headers.get("Content-Range", "")
        # e.g. bytes 0-0/5515509760
        import re
        m = re.fullmatch(r"bytes 0-(?:0|4095)/([1-9][0-9]*)", content_range)
        size = m.group(1) if m else None
    if not size:
        return None
    if not size.isascii() or not size.isdecimal():
        raise LabError("invalid official Microsoft ISO content length")
    n = int(size)
    if not MIN_ISO_SIZE <= n <= MAX_ISO_SIZE:
        raise LabError("official Microsoft response size is outside ISO bounds")
    return n


def probe(key: str, profile: dict) -> dict:
    start = validate_origin(profile["downloadUrl"], PERMITTED_START)
    opener = urllib.request.build_opener(MicrosoftOnlyRedirect())
    outcome = {
        "profile": key,
        "startDomain": start,
        "isoDigestVerified": False,
        "windowsClientInstalled": False,
        "dualBootVerified": False,
        "winReRecovered": False,
        "productionStable": False,
    }
    base_headers = {
        "User-Agent": "Gaslux-Disposable-ISO-Evaluation-Lab/1",
        "Accept-Encoding": "identity",
    }
    # HEAD avoids fetching the ISO; try a one-byte Range only if origin
    # rejects HEAD. A non-compliant server may stream the whole ISO:
    # never read more than one byte, and close immediately.
    for method in ("HEAD", "GET"):
        h = dict(base_headers)
        if method == "GET":
            h["Range"] = "bytes=0-0"
        req = urllib.request.Request(profile["downloadUrl"],
                                     headers=h, method=method)
        try:
            with opener.open(req, timeout=20) as response:
                domain = validate_origin(response.geturl(), EXPECTED_FINAL_HOSTS)
                code = response.status
                if code not in (200, 206):
                    raise LabError("unexpected Microsoft ISO response HTTP status")
                size = parse_iso_length(response.headers, code)
                if method == "GET":
                    data = response.read(1)
                    if not data:
                        raise LabError("range probe yielded no response bytes")
                outcome.update({
                    "finalDomain": domain,
                    "probeMethod": method,
                    "httpStatus": code,
                    "reportedIsoBytes": size,
                    "httpOriginProbePassed": True,
                })
                return outcome
        except urllib.error.HTTPError as exc:
            if exc.code == 405 and method == "HEAD":
                continue
            # Never include exception's URL, signed token or query string.
            raise LabError(f"official Microsoft origin returned HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise LabError("official Microsoft ISO origin DNS/TLS/network failed") from None
    raise LabError("official Microsoft ISO server rejected HEAD and byte-range probing")


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--profile", choices=sorted(EXPECTED), required=True)
    cli.add_argument("--report-dir", type=Path, required=True)
    a = cli.parse_args()
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_OS") != "Linux" or
            os.environ.get("GITHUB_REPOSITORY") != "LMhdez/gaslux" or
            os.environ.get("GASLUX_ISO_PROBE_CONSENT") != CONSENT):
        print("authorized GitHub Actions Linux-only origin probe required",
              file=sys.stderr)
        return 2
    report_dir = a.report_dir
    if (not report_dir.is_absolute() or not report_dir.is_dir() or
            report_dir.is_symlink() or report_dir.resolve() != report_dir or
            report_dir.name != "windows-iso-origin-evidence"):
        print("invalid or non-owned CI evidence directory", file=sys.stderr)
        return 2
    try:
        profile = load_catalog()["profiles"][a.profile]
        report = probe(a.profile, profile)
        status = 0
    except (LabError, ValueError) as exc:
        # Report fixed descriptions only; errors must not leak signed CDN URLs.
        report = {"profile": a.profile, "httpOriginProbePassed": False,
                  "isoDigestVerified": False, "windowsClientInstalled": False,
                  "dualBootVerified": False, "winReRecovered": False,
                  "productionStable": False, "blocker": str(exc)}
        status = 1
    dest = report_dir / f"{a.profile}-origin.json"
    if dest.exists() or dest.is_symlink():
        print("refuse to replace previous origin evidence", file=sys.stderr)
        return 2
    serialized = json.dumps(report, indent=2, sort_keys=True)
    dest.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)
    return status


if __name__ == "__main__":
    sys.exit(main())
