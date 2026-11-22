"""Bounded RPM/ELF metadata readback from signed OCI bytes, never execute them.

RPM database is an internal RPM format: unknown formats or missing file-digest
binding are INSUFFICIENT_EVIDENCE, not a version/installation authorization.
All inputs come from the already verified ordered OCI layer stream.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import struct

RPMDB_PATHS = frozenset(
    {
        "usr/share/rpm/rpmdb.sqlite",
        "usr/lib/sysimage/rpm/rpmdb.sqlite",
        "var/lib/rpm/rpmdb.sqlite",
    }
)
RPMDB_SIDECARS = frozenset(
    path + suffix for path in RPMDB_PATHS for suffix in ("-wal", "-shm", "-journal")
)
RPMDB_ALL = RPMDB_PATHS | RPMDB_SIDECARS
MAX_RPMDB = 192 * 1024 * 1024
MAX_RPM_HEADER = 16 * 1024 * 1024
MAX_PACKAGES = 25000
MAX_ARRAY = 200000
MAX_ELF_PREFIX = 2 * 1024 * 1024
RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9_.+~^:-]{1,128}\Z")

# RPM tag identifiers from rpm.org/manual/tags, not runner RPM package data.
NAME = 1000
VERSION = 1001
RELEASE = 1002
EPOCH = 1003
BUILDTIME = 1006
BUILDHOST = 1007
ARCH = 1022
FILEDIGESTS = 1035
SOURCERPM = 1044
DIRINDEXES = 1116
BASENAMES = 1117
DIRNAMES = 1118
FILEDIGESTALGO = 5011


class PackageUnproven(ValueError):
    """Package/ELF identity cannot be established from final signed bytes."""


def _read_tag(
    blob: bytes,
    wanted: dict[int, tuple[int, int, int, int]],
    tag: int,
    *,
    kind: int,
    optional: bool = False,
):
    entry = wanted.get(tag)
    if entry is None:
        if optional:
            return None
        raise PackageUnproven("RPM header required tag absent")
    typ, start, count, end = entry
    if typ != kind or count <= 0 or count > MAX_ARRAY:
        raise PackageUnproven("RPM header tag type or count invalid")
    segment = blob[start:end]
    if kind == 4:
        if count > len(segment) // 4:
            raise PackageUnproven("Truncated RPM integer array")
        return list(struct.unpack_from(f">{count}I", segment))
    if kind in (6, 8):
        values = []
        position = 0
        for _ in range(count):
            stop = segment.find(b"\x00", position)
            if stop < 0:
                raise PackageUnproven("Unterminated RPM string")
            raw = segment[position:stop]
            if len(raw) > 4096:
                raise PackageUnproven("Oversized RPM string")
            try:
                values.append(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise PackageUnproven("Malformed RPM UTF8 metadata") from exc
            position = stop + 1
        return values[0] if kind == 6 and count == 1 else values
    raise PackageUnproven("Unexpected RPM tag type")


def rpm_header(data: bytes) -> dict:
    """Read only required scalar and per-file tags from one bounded RPM header."""
    if not isinstance(data, bytes) or not 16 <= len(data) <= MAX_RPM_HEADER:
        raise PackageUnproven("Invalid RPM header size")
    if data[:8] != RPM_HEADER_MAGIC:
        raise PackageUnproven("Invalid RPM header magic")
    n, size = struct.unpack_from(">II", data, 8)
    if n == 0 or n > 100000 or size > MAX_RPM_HEADER - 16 or 16 + 16 * n + size != len(data):
        raise PackageUnproven("RPM header index/store lengths invalid")
    offset = 16 + 16 * n
    wanted = {}
    selected = {
        NAME,
        VERSION,
        RELEASE,
        EPOCH,
        BUILDTIME,
        BUILDHOST,
        ARCH,
        FILEDIGESTS,
        SOURCERPM,
        DIRINDEXES,
        BASENAMES,
        DIRNAMES,
        FILEDIGESTALGO,
    }
    for i in range(n):
        tag, typ, pos, count = struct.unpack_from(">IIII", data, 16 + 16 * i)
        if tag not in selected:
            continue
        if tag in wanted or pos >= size or count == 0 or count > MAX_ARRAY:
            raise PackageUnproven("Duplicated or malformed RPM tag")
        wanted[tag] = (typ, offset + pos, count, offset + size)
    name = _read_tag(data, wanted, NAME, kind=6)
    if name != "bootc":
        return {"name": name}
    version = _read_tag(data, wanted, VERSION, kind=6)
    release = _read_tag(data, wanted, RELEASE, kind=6)
    arch = _read_tag(data, wanted, ARCH, kind=6)
    epoch_values = _read_tag(data, wanted, EPOCH, kind=4, optional=True)
    epoch = epoch_values[0] if epoch_values is not None else 0
    if not all(isinstance(x, str) and SAFE_ID.fullmatch(x) for x in (version, release, arch)):
        raise PackageUnproven("Unsafe RPM NEVRA identity")
    if arch != "x86_64":
        raise PackageUnproven("RPM architecture not x86_64")
    base = _read_tag(data, wanted, BASENAMES, kind=8)
    dirs = _read_tag(data, wanted, DIRNAMES, kind=8)
    indices = _read_tag(data, wanted, DIRINDEXES, kind=4)
    digests = _read_tag(data, wanted, FILEDIGESTS, kind=8)
    digest_alg = _read_tag(data, wanted, FILEDIGESTALGO, kind=4, optional=True)
    if digest_alg != [8]:  # RPM_HASH_SHA256
        raise PackageUnproven("RPM file digest is not SHA-256")
    if not (len(base) == len(indices) == len(digests) and len(base) <= 200000):
        raise PackageUnproven("RPM file arrays inconsistent")
    matches = []
    for b, ix, digest in zip(base, indices, digests, strict=True):
        if ix >= len(dirs) or "/" in b or "\x00" in b:
            raise PackageUnproven("Invalid RPM file path")
        full = dirs[ix].rstrip("/") + "/" + b
        if full == "/usr/bin/bootc":
            if not SHA256_HEX.fullmatch(digest):
                raise PackageUnproven("Invalid RPM bootc SHA-256")
            matches.append(digest)
    if len(matches) != 1:
        raise PackageUnproven("RPM bootc executable owner ambiguous or missing")
    buildtime = _read_tag(data, wanted, BUILDTIME, kind=4, optional=True)
    source = _read_tag(data, wanted, SOURCERPM, kind=6, optional=True)
    buildhost = _read_tag(data, wanted, BUILDHOST, kind=6, optional=True)
    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "architecture": arch,
        "fileSha256": matches[0],
        "sourceRpm": source,
        "buildTimeUnix": buildtime[0] if buildtime else None,
        "toFilesystemManpageDeclared": any("bootc-install-to-filesystem." in b for b in base),
        "buildHost": buildhost,
        "rpmHeaderSha256": hashlib.sha256(data).hexdigest(),
    }


def elf_build_id(prefix: bytes) -> dict:
    """Extract x86_64 GNU NT_GNU_BUILD_ID from bounded ELF PT_NOTE, if present."""
    if len(prefix) < 64 or prefix[:4] != b"\x7fELF":
        raise PackageUnproven("Truncated or non-ELF bootc")
    if prefix[4:6] != b"\x02\x01":  # ELFCLASS64, little endian
        raise PackageUnproven("Unsupported ELF class or endianness")
    if struct.unpack_from("<H", prefix, 18)[0] != 62:
        raise PackageUnproven("Unexpected ELF architecture")
    phoff = struct.unpack_from("<Q", prefix, 32)[0]
    entsize, count = struct.unpack_from("<HH", prefix, 54)
    if count > 256 or entsize < 56 or phoff + entsize * count > len(prefix):
        raise PackageUnproven("ELF program headers outside bounded prefix")
    ids = set()
    for index in range(count):
        off = phoff + index * entsize
        typ = struct.unpack_from("<I", prefix, off)[0]
        if typ != 4:  # PT_NOTE
            continue
        noteoff = struct.unpack_from("<Q", prefix, off + 8)[0]
        notesize = struct.unpack_from("<Q", prefix, off + 32)[0]
        end = noteoff + notesize
        if notesize > MAX_ELF_PREFIX or end > len(prefix):
            raise PackageUnproven("ELF notes outside bounded prefix")
        at = noteoff
        while at + 12 <= end:
            namesz, descsz, kind = struct.unpack_from("<III", prefix, at)
            at += 12
            nend = at + (namesz + 3 & ~3)
            dend = nend + (descsz + 3 & ~3)
            if dend > end:
                raise PackageUnproven("Truncated ELF note")
            if kind == 3 and namesz == 4 and prefix[at : at + 4] == b"GNU\x00":
                if not 8 <= descsz <= 64:
                    raise PackageUnproven("Unexpected ELF build-id size")
                ids.add(prefix[nend : nend + descsz].hex())
            at = dend
    if len(ids) > 1:
        raise PackageUnproven("Inconsistent ELF build-ids")
    return {"elfArchitecture": "x86_64", "elfBuildId": next(iter(ids)) if ids else None}


def bind_rpm(overlay: dict, bootc_file: dict) -> dict:
    """Return package binding only if final RPM DB and ELF hashes agree."""
    unproven = {"status": "BOOTC_PACKAGE_BINDING_UNPROVEN"}
    files = []
    for path in sorted(RPMDB_PATHS):
        item = overlay.get(path)
        if item is not None:
            if item.get("kind") != "rpmdb" or not isinstance(item.get("content"), bytes):
                return {**unproven, "reason": "RPM DB path not a regular bounded file"}
            files.append((path, item["content"]))
    if any(path in overlay for path in RPMDB_SIDECARS):
        return {**unproven, "reason": "RPM DB requires sidecar recovery"}
    if not files:
        return {**unproven, "reason": "No supported SQLite RPM DB in final OCI"}
    hashes = {hashlib.sha256(raw).hexdigest() for _, raw in files}
    if len(hashes) != 1:
        return {**unproven, "reason": "Conflicting RPM DB snapshots"}
    path, raw = files[0]
    try:
        if not raw.startswith(b"SQLite format 3\x00") or len(raw) > MAX_RPMDB:
            raise PackageUnproven("Unsupported SQLite RPM DB")
        conn = sqlite3.connect(":memory:")
        try:
            conn.deserialize(raw)  # Host sqlite; no guest executable or shell.
            conn.execute("PRAGMA query_only=ON")
            if conn.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                raise PackageUnproven("RPM DB SQLite integrity check failed")
            count = conn.execute("SELECT count(*) FROM Packages").fetchone()[0]
            if type(count) is not int or not 0 < count <= MAX_PACKAGES:
                raise PackageUnproven("RPM DB package count out of bounds")
            records = []
            for (value,) in conn.execute("SELECT blob FROM Packages"):
                if not isinstance(value, bytes):
                    raise PackageUnproven("RPM package header is not bytes")
                package = rpm_header(value)
                if package.get("name") == "bootc":
                    records.append(package)
        finally:
            conn.close()
        if len(records) != 1:
            raise PackageUnproven("RPM bootc package missing or ambiguous")
        result = records[0]
        if result["fileSha256"] != bootc_file["sha256"]:
            raise PackageUnproven("RPM file digest does not match OCI bootc ELF")
        elf = elf_build_id(bootc_file["elfPrefix"])
        return {
            "status": "BOOTC_RPM_IDENTITY_VERIFIED",
            "rpmdbPath": path,
            "rpmdbSha256": hashlib.sha256(raw).hexdigest(),
            "rpmPackage": result,
            **elf,
            "bootcRuntimeToFilesystemVerified": False,
            "nativeInstallationVerified": False,
            "stable": False,
        }
    except (PackageUnproven, sqlite3.Error, OverflowError, ValueError, struct.error) as exc:
        return {**unproven, "reason": str(exc)[:160]}
