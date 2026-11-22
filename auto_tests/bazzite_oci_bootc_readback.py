#!/usr/bin/env python3
"""Inspect EXACT signed Bazzite OCI bytes on the host, never execute guest code.

Registry reads use an immutable digest. Every byte is bounded and hashed.
OCI layer tar members are parsed, never extracted or executed. A successful
binary observation still refuses installation, GPT, EFI, NVRAM and guest access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from bazzite_iso_public_readback import CONFIG_DIGEST, PAYLOAD_DIGEST, PAYLOAD_IMAGE

PINNED = PAYLOAD_IMAGE + "@" + PAYLOAD_DIGEST
MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
LAYER_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    }
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_MANIFEST = 2 * 1024 * 1024
MAX_CONFIG = 16 * 1024 * 1024
MAX_LAYER = 4 * 1024**3
MAX_TOTAL = 10 * 1024**3
MAX_EXPANDED = 32 * 1024**3
MAX_ENTRIES = 500_000
MAX_BOOTC = 128 * 1024 * 1024
CANDIDATES = frozenset({"usr/bin/bootc", "usr/libexec/bootc", "bin/bootc"})
NO_WRITE = (
    "installationAuthorized",
    "partitionWriteAuthorized",
    "gptMetadataWriteAuthorized",
    "windowsEspWriteAuthorized",
    "nvramWriteAuthorized",
    "secureBootEnrollmentAuthorized",
    "guestCommandChannelAuthorized",
)


class Refusal(ValueError):
    """Cannot establish complete, bounded, pinned OCI identity and content."""


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _obj(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise Refusal("Invalid " + label)
    return value


def _json(data: bytes, label: str) -> dict:
    try:
        return _obj(json.loads(data), label)
    except (ValueError, UnicodeError) as exc:
        raise Refusal("Malformed " + label) from exc


def validate_metadata(
    manifest_bytes: bytes,
    config_bytes: bytes,
    *,
    expected_manifest: str = PAYLOAD_DIGEST,
    expected_config: str = CONFIG_DIGEST,
) -> tuple[list[dict], dict]:
    """Check exact cryptographic descriptor chain; never resolve mutable tags."""
    if not DIGEST.fullmatch(expected_manifest) or not DIGEST.fullmatch(expected_config):
        raise Refusal("Invalid immutable OCI pins")
    if len(manifest_bytes) > MAX_MANIFEST or digest_bytes(manifest_bytes) != expected_manifest:
        raise Refusal("OCI manifest digest mismatch")
    if len(config_bytes) > MAX_CONFIG or digest_bytes(config_bytes) != expected_config:
        raise Refusal("OCI config digest mismatch")
    manifest = _json(manifest_bytes, "OCI manifest")
    config = _json(config_bytes, "OCI config")
    declared = _obj(manifest.get("config"), "OCI config descriptor")
    if manifest.get("schemaVersion") != 2:
        raise Refusal("Unsupported pinned OCI schemaVersion")
    # Docker schema2 manifests can omit the top-level mediaType. The exact
    # manifest bytes must still match the immutable signed SHA-256 above.
    if manifest.get("mediaType") is not None and manifest["mediaType"] not in MANIFEST_TYPES:
        raise Refusal(
            "Unsupported pinned manifest mediaType: " + str(manifest.get("mediaType"))[:128]
        )
    if declared.get("digest") != expected_config:
        raise Refusal("OCI manifest config descriptor digest mismatch")
    if type(declared.get("size")) is not int or declared["size"] != len(config_bytes):
        raise Refusal("OCI config descriptor size mismatch")
    if config.get("architecture") != "amd64":
        raise Refusal("Unexpected OCI architecture: " + str(config.get("architecture"))[:32])
    if config.get("os") != "linux":
        raise Refusal("Unexpected OCI operating system: " + str(config.get("os"))[:32])
    layers = manifest.get("layers")
    rootfs = _obj(config.get("rootfs"), "rootfs")
    diffids = rootfs.get("diff_ids")
    if (
        not isinstance(layers, list)
        or not 0 < len(layers) <= 256
        or not isinstance(diffids, list)
        or len(diffids) != len(layers)
    ):
        raise Refusal("Incomplete OCI filesystem layer chain")
    result = []
    total = 0
    for desc, diffid in zip(layers, diffids, strict=True):
        d = _obj(desc, "layer descriptor")
        size = d.get("size")
        sha = d.get("digest")
        if d.get("mediaType") not in LAYER_TYPES:
            raise Refusal("Unsupported OCI layer mediaType: " + str(d.get("mediaType"))[:100])
        if not isinstance(sha, str) or not DIGEST.fullmatch(sha):
            raise Refusal("Invalid compressed OCI layer digest")
        if not isinstance(diffid, str) or not DIGEST.fullmatch(diffid):
            raise Refusal("Invalid uncompressed OCI diff-id")
        if type(size) is not int or not 0 < size <= MAX_LAYER:
            raise Refusal("Unbounded OCI layer size: " + str(size)[:24])
        if "urls" in d:
            raise Refusal("Foreign external OCI layer URL")
        total += size
        if total > MAX_TOTAL:
            raise Refusal("Total compressed layers exceed inspection budget")
        result.append({"digest": sha, "size": size, "mediaType": d["mediaType"]})
    labels = _obj(_obj(config.get("config"), "runtime config").get("Labels") or {}, "labels")
    relevant = {}
    for k, v in labels.items():
        if (
            isinstance(k, str)
            and isinstance(v, str)
            and len(k) <= 128
            and len(v) <= 512
            and any(t in k.casefold() for t in ("bootc", "ostree", "version", "image", "source"))
        ):
            relevant[k] = v
    return result, {"architecture": "amd64", "os": "linux", "declaredLabels": relevant}


def _path(name: str) -> str:
    if not isinstance(name, str) or len(name) > 4096 or "\x00" in name or "\\" in name:
        raise Refusal("Invalid tar path")
    if name.startswith("/") or any(part == ".." for part in name.split("/")):
        raise Refusal("Tar path escapes OCI root")
    n = posixpath.normpath(name)
    if n in (".", "") or n.startswith("../"):
        raise Refusal("Ambiguous tar path")
    return n


def _link(path: str, target: str) -> str:
    if not isinstance(target, str) or not target or target.startswith("/"):
        raise Refusal("Absolute or missing image executable link")
    combined = posixpath.join(posixpath.dirname(path), target)
    normalized = posixpath.normpath(combined)
    if normalized in ("", ".") or normalized.startswith("../") or normalized == "..":
        raise Refusal("Image symlink escapes OCI root")
    return _path(normalized)


def scan_layer(file, descriptor: dict, entries: dict, budgets: dict) -> None:
    """Overlay only candidate bootc path metadata, never extract tar members."""
    file.seek(0)
    sha = hashlib.sha256()
    total = 0
    while True:
        part = file.read(1024 * 1024)
        if not part:
            break
        total += len(part)
        if total > MAX_LAYER:
            raise Refusal("Compressed OCI layer exceeds bound")
        sha.update(part)
    if total != descriptor["size"] or "sha256:" + sha.hexdigest() != descriptor["digest"]:
        raise Refusal("OCI layer digest or size mismatch")
    file.seek(0)
    try:
        with tarfile.open(fileobj=file, mode="r|gz") as archive:
            count = 0
            for member in archive:
                count += 1
                budgets["members"] += 1
                budgets["expanded"] += member.size
                if (
                    count > MAX_ENTRIES
                    or budgets["members"] > MAX_ENTRIES
                    or budgets["expanded"] > MAX_EXPANDED
                ):
                    raise Refusal("OCI tar expansion/member limit exceeded")
                name = _path(member.name)
                directory, basename = posixpath.split(name)
                if basename.startswith(".wh."):
                    victim = basename[4:]
                    if victim == ".wh..opq":
                        prefix = directory + "/" if directory else ""
                        for previous in list(entries):
                            if previous.startswith(prefix):
                                del entries[previous]
                    else:
                        path = posixpath.join(directory, victim)
                        for previous in list(entries):
                            if previous == path or previous.startswith(path + "/"):
                                del entries[previous]
                    continue
                if member.isdev() or member.isfifo():
                    raise Refusal("Device or FIFO in untrusted OCI layer")
                if name not in CANDIDATES and not name.endswith("/bootc"):
                    continue
                if member.isfile():
                    if member.size <= 0 or member.size > MAX_BOOTC:
                        raise Refusal("Suspicious bootc executable size")
                    src = archive.extractfile(member)
                    if src is None:
                        raise Refusal("Unreadable bootc file")
                    header = src.read(4)
                    rest = hashlib.sha256(header)
                    consumed = 4
                    while True:
                        block = src.read(1024 * 1024)
                        if not block:
                            break
                        consumed += len(block)
                        rest.update(block)
                    if consumed != member.size:
                        raise Refusal("Truncated executable in OCI tar")
                    entries[name] = {
                        "kind": "file",
                        "elf": header == b"\x7fELF",
                        "size": member.size,
                        "sha256": rest.hexdigest(),
                    }
                elif member.issym():
                    entries[name] = {"kind": "symlink", "target": _link(name, member.linkname)}
                elif member.islnk():
                    # Tar hardlink path is relative to the archive root.
                    target = _path(member.linkname)
                    entries[name] = {"kind": "hardlink", "target": target}
                else:
                    entries.pop(name, None)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise Refusal("Invalid or unsupported OCI layer tar") from exc


def _request(url: str, token: str | None = None):
    headers = {
        "Accept": ", ".join(sorted(MANIFEST_TYPES)),
        "User-Agent": "gaslux-oci-bootc-readback/1",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60)


def _bounded(response, cap: int) -> bytes:
    result = bytearray()
    while True:
        data = response.read(min(1024 * 1024, cap + 1 - len(result)))
        if not data:
            return bytes(result)
        result.extend(data)
        if len(result) > cap:
            raise Refusal("OCI network response exceeds byte bound")


def download_registry() -> dict:
    """Host-only authenticated-by-digest registry reads; never pull by tag."""
    with _request(
        "https://ghcr.io/token?scope=repository%3Aublue-os%2Fbazzite%3Apull&service=ghcr.io"
    ) as response:
        token = _json(_bounded(response, 64 * 1024), "GHCR bearer").get("token")
    if not isinstance(token, str) or not token:
        raise Refusal("Cannot obtain public GHCR bearer")
    base = "https://ghcr.io/v2/ublue-os/bazzite/"
    with _request(base + "manifests/" + PAYLOAD_DIGEST, token) as response:
        manifest = _bounded(response, MAX_MANIFEST)
    if digest_bytes(manifest) != PAYLOAD_DIGEST:
        raise Refusal("Foreign immutable manifest")
    with _request(base + "blobs/" + CONFIG_DIGEST, token) as response:
        config = _bounded(response, MAX_CONFIG)
    descriptors, _info = validate_metadata(manifest, config)
    with tempfile.TemporaryDirectory(prefix="gaslux-bazzite-oci-") as temp:
        directory = Path(temp)
        files = []
        # Each compressed layer stays under a hard quota and is immediately
        # deleted after scanning; no tar member is ever extracted.
        try:
            state = {}
            budget = {"members": 0, "expanded": 0}
            for index, desc in enumerate(descriptors):
                layer = directory / f"layer-{index}.tar.gz"
                with (
                    _request(base + "blobs/" + desc["digest"], token) as response,
                    layer.open("xb") as output,
                ):
                    measured = hashlib.sha256()
                    size = 0
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        size += len(block)
                        if size > desc["size"] or size > MAX_LAYER:
                            raise Refusal("Layer network transfer exceeded announced size")
                        measured.update(block)
                        output.write(block)
                if size != desc["size"] or "sha256:" + measured.hexdigest() != desc["digest"]:
                    raise Refusal("OCI layer substituted during registry transfer")
                with layer.open("rb") as source:
                    scan_layer(source, desc, state, budget)
                layer.unlink()
            # Evaluate the fully replayed overlay state without layer files.
            return finish(state, descriptors, budget, _info)
        finally:
            for path in files:
                path.unlink(missing_ok=True)


def finish(entries: dict, descriptors: list[dict], budgets: dict, info: dict) -> dict:
    """Decision only after scanning ALL signed, immutable OCI layers."""
    matched = []
    unresolved = []
    for path in sorted(CANDIDATES):
        item = entries.get(path)
        if item is None:
            continue
        visited = {path}
        for _ in range(8):
            if item["kind"] == "file":
                if item["elf"]:
                    matched.append({"path": path, "sha256": item["sha256"], "size": item["size"]})
                else:
                    unresolved.append(path)
                break
            target = item["target"]
            if target in visited:
                raise Refusal("Cyclic bootc path")
            visited.add(target)
            item = entries.get(target)
            if item is None:
                unresolved.append(path)
                break
        else:
            raise Refusal("Excessive bootc symbolic links")
    if unresolved and not matched:
        raise Refusal("Image bootc path exists but cannot be resolved safely")
    return {
        "status": (
            "BOOTC_PRESENT_ROUTE_UNVERIFIED" if matched else "BOOTC_UNAVAILABLE_IN_PINNED_IMAGE"
        ),
        "image": PINNED,
        "manifestDigest": PAYLOAD_DIGEST,
        "configDigest": CONFIG_DIGEST,
        "bootcFiles": matched,
        "bootcVersion": None,
        "bootcVersionVerified": False,
        "bootcToFilesystemAvailableInBinaryVerified": False,
        "nativeInstallationVerified": False,
        "arch": info["architecture"],
        "os": info["os"],
        "declaredLabels": info["declaredLabels"],
        "layersVerified": len(descriptors),
        "totalCompressedBytes": sum(d["size"] for d in descriptors),
        "expandedBytesDeclared": budgets["expanded"],
        "windowsEspPreservationVerified": False,
        "btrfsSubvolumesVerified": False,
        "bootloaderAndNVRAMWriteSetVerified": False,
        **{key: False for key in NO_WRITE},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = download_registry()
    except (Refusal, OSError, ValueError, urllib.error.URLError, tarfile.TarError) as exc:
        result = {
            "status": "REFUSED_UNAUTHENTICATED_OCI",
            "reason": str(exc)[:512],
            "requestedImage": PINNED,
            "bootcFileVerified": False,
            **{key: False for key in NO_WRITE},
        }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["status"] == "REFUSED_UNAUTHENTICATED_OCI":
        print("REFUSED_UNAUTHENTICATED_OCI:", result["reason"])
    else:
        print(result["status"])
    raise SystemExit(2 if result["status"] != "REFUSED_UNAUTHENTICATED_OCI" else 3)


if __name__ == "__main__":
    main()
