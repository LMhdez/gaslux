#!/usr/bin/env python3
"""Anaconda live-guest D-Bus *read-only* inventory. Never produces install authority.

Run INSIDE an already authorized, isolated Bazzite live guest. This does not
start Anaconda, select storage, change partitioning, or dispatch installation.
The output is untrusted until independently bound to host QEMU/ISO/Safety proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

SERVICE = "org.fedoraproject.Anaconda.Modules.Storage"
BUS = "/usr/bin/busctl"
READS = (
    "GetActions",
    "GetDevices",
    "GetDisks",
    "GetMountPoints",
    "GetBootDevice",
)
DETAIL_READS = ("GetDeviceData", "GetFormatData")
DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OWNER = re.compile(r":1\.[0-9]+\Z")


class CaptureRefusal(ValueError):
    """Fail closed on missing, replaced or ambiguous live Anaconda evidence."""


def run(*command: str) -> str:
    """Execute only bounded busctl read-side calls, without a shell."""
    if (
        len(command) < 3
        or command[0:2] != (BUS, "--system")
        or command[2] not in ("list", "tree", "introspect", "call")
    ):
        raise CaptureRefusal("Only pre-approved system D-Bus introspection is permitted")
    result = subprocess.run(command, capture_output=True, text=True, timeout=12, check=True)
    if len(result.stdout.encode("utf-8")) > 1024 * 1024:
        raise CaptureRefusal("Unbounded Anaconda D-Bus response")
    return result.stdout


def installed_service(listing: str) -> bool:
    return any(line.split() and line.split()[0] == SERVICE for line in listing.splitlines())


def _reply(value: str, kind: str) -> str:
    fields = shlex.split(value)
    if len(fields) != 2 or fields[0] != kind:
        raise CaptureRefusal("Unexpected D-Bus ownership response")
    return fields[1]


def owner_and_pid(reader=run) -> tuple[str, int]:
    if not installed_service(reader(BUS, "--system", "list", "--no-legend", "--no-pager")):
        raise CaptureRefusal("Storage service is not currently running (no activation allowed)")
    owner = _reply(
        reader(BUS, "--system", "call", DBUS, DBUS_PATH, DBUS, "GetNameOwner", "s", SERVICE), "s"
    )
    if not OWNER.fullmatch(owner):
        raise CaptureRefusal("Invalid unique D-Bus owner")
    pid_text = _reply(
        reader(
            BUS, "--system", "call", DBUS, DBUS_PATH, DBUS, "GetConnectionUnixProcessID", "s", owner
        ),
        "u",
    )
    if not pid_text.isdecimal() or int(pid_text) <= 1:
        raise CaptureRefusal("Unexpected Anaconda service PID")
    return owner, int(pid_text)


def process_proof(pid: int) -> dict:
    if type(pid) is not int or pid <= 1:
        raise CaptureRefusal("Invalid process identity")
    proc = Path("/proc") / str(pid)
    cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", errors="strict")
    exe = (proc / "exe").resolve(strict=True)
    if "anaconda" not in cmdline.lower() or not exe.is_file():
        raise CaptureRefusal("D-Bus service PID is not an Anaconda process")
    digest = hashlib.sha256()
    with exe.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    binary_hashes = {}
    for binary in ("/usr/sbin/anaconda", "/usr/bin/anaconda", "/usr/bin/blivet-gui"):
        path = Path(binary)
        if path.is_file() and not path.is_symlink():
            hasher = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(chunk)
            binary_hashes[binary] = hasher.hexdigest()
    package_versions = {}
    for package in ("anaconda", "anaconda-core", "python3-blivet", "blivet-gui"):
        try:
            query = subprocess.run(
                ["/usr/bin/rpm", "-q", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}", package],
                capture_output=True, check=False, text=True, timeout=8,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if query.returncode == 0 and 0 < len(query.stdout) <= 256:
            package_versions[package] = query.stdout.strip()
    return {
        "pid": pid,
        "commandLine": cmdline[:4096],
        "executablePath": str(exe),
        "executableSha256": digest.hexdigest(),
        "installerBinaryHashes": binary_hashes,
        "reportedPackageVersions": package_versions,
        "packageAndBinaryAuthenticityVerified": False,
    }


def viewer_from_xml(xml: str) -> tuple[str, dict[str, str]]:
    """Require a single interface with GetActions and no writable calls."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise CaptureRefusal("Invalid D-Bus introspection XML") from exc
    matches = []
    for iface in root.findall("interface"):
        name = iface.get("name", "")
        if not name.startswith(SERVICE + "."):
            continue
        methods = {}
        for method in iface.findall("method"):
            method_name = method.get("name", "")
            arguments = method.findall("arg")
            signature = "".join(
                arg.get("type", "") for arg in arguments if arg.get("direction", "in") == "in"
            )
            methods[method_name] = signature
        if methods.get("GetActions") == "":
            matches.append((name, methods))
    if len(matches) != 1:
        raise CaptureRefusal("Missing or ambiguous read-only GetActions interface")
    return matches[0]


def parse_device_ids(raw: str) -> list[str]:
    values = shlex.split(raw)
    if len(values) < 2 or values[0] != "as" or not values[1].isdecimal():
        raise CaptureRefusal("Cannot decode GetDevices response")
    count = int(values[1])
    if count > 64 or len(values) != count + 2:
        raise CaptureRefusal("Unbounded or truncated GetDevices response")
    if any(not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", value) for value in values[2:]):
        raise CaptureRefusal("Unexpected device identifier")
    return values[2:]


def _paths(tree: str) -> list[str]:
    paths = set(re.findall(r"/org/fedoraproject/Anaconda/[A-Za-z0-9_/]+", tree))
    if len(paths) > 128:
        raise CaptureRefusal("Unbounded Anaconda object tree")
    return sorted(paths)


def capture(reader=run, verifier=process_proof) -> dict:
    """Read an existing Anaconda service using its unique owner, never activate it."""
    unique_owner, pid = owner_and_pid(reader)
    identity = verifier(pid)
    if (
        not isinstance(identity, dict)
        or identity.get("pid") != pid
        or not SHA256.fullmatch(str(identity.get("executableSha256", "")))
    ):
        raise CaptureRefusal("Executable identity evidence missing")
    tree = reader(BUS, "--system", "tree", unique_owner)
    candidates = []
    for path in _paths(tree):
        xml = reader(BUS, "--system", "introspect", "--xml-interface", unique_owner, path)
        try:
            interface, methods = viewer_from_xml(xml)
        except CaptureRefusal:
            continue
        candidates.append((path, interface, methods))
    if len(candidates) != 1:
        raise CaptureRefusal("No uniquely discovered Anaconda DeviceTreeViewer")
    path, interface, methods = candidates[0]
    responses = {}
    absent = []
    for name in READS:
        if name not in methods:
            absent.append(name)
            continue
        if methods[name] != "":
            raise CaptureRefusal(f"Unexpected parameters for read-only {name}")
        responses[name] = reader(BUS, "--system", "call", unique_owner, path, interface, name)
    if "GetActions" not in responses or "GetDevices" not in responses:
        raise CaptureRefusal("Missing actual Anaconda action/device observations")
    device_ids = parse_device_ids(responses["GetDevices"])
    if len(device_ids) != len(set(device_ids)):
        raise CaptureRefusal("Duplicate device identities")
    for method in DETAIL_READS:
        if method not in methods:
            absent.append(method)
            continue
        if methods[method] != "s":
            raise CaptureRefusal(f"Unexpected device detail signature: {method}")
        responses[method] = {
            dev: reader(BUS, "--system", "call", unique_owner, path, interface, method, "s", dev)
            for dev in device_ids
        }
    if owner_and_pid(reader) != (unique_owner, pid):
        raise CaptureRefusal("Anaconda D-Bus service replaced during observation")
    # Raw busctl replies are NOT converted to a Blivet write-set or authenticated.
    return {
        "schemaVersion": 1,
        "origin": "anaconda-dbus-readonly-untrusted",
        "service": SERVICE,
        "uniqueOwner": unique_owner,
        "process": identity,
        "viewerObjectPath": path,
        "viewerInterface": interface,
        "methodSignatures": methods,
        "rawResponses": responses,
        "unobservedMethods": absent,
        "deviceIds": device_ids,
        "hostIsoAndQemuBindingVerified": False,
        "gptPrimaryAndBackupWritesObserved": False,
        "efiWritesObserved": False,
        "nvramOperationsObserved": False,
        "atomicPayloadBoundToIso": False,
        "realActionGraphAuthenticated": False,
        "nativeInstallerWriteSetVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "gptMetadataWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nvramWriteAuthorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.is_symlink() or args.output.exists():
            raise CaptureRefusal("Evidence file must be new, not reused or linked")
        result = capture()
        encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(encoded) > 1024 * 1024:
            raise CaptureRefusal("Unbounded evidence record")
        with os.fdopen(
            os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except (CaptureRefusal, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print("Untrusted read-only Anaconda capture: installation remains refused")


if __name__ == "__main__":
    main()
