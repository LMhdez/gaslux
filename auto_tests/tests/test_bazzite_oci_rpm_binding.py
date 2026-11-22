"""Offline adversarial RPM DB ↔ signed bootc ELF byte binding tests."""

from __future__ import annotations

import gzip
import hashlib
import io
import sqlite3
import struct
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_oci_bootc_readback import (  # noqa: E402
    NO_WRITE,
    digest_bytes,
    finish,
    scan_layer,
)
from bazzite_oci_rpm_binding import (  # noqa: E402
    RPM_HEADER_MAGIC,
    RPMDB_PATHS,
    PackageUnproven,
    elf_build_id,
    rpm_header,
)


def rpm_pack_tag(tag: int, typ: int, data) -> tuple[int, int, bytes, int]:
    if typ == 4:
        values = data if isinstance(data, list) else [data]
        return tag, typ, struct.pack(">" + "I" * len(values), *values), len(values)
    if typ == 6:
        return tag, typ, data.encode() + b"\0", 1
    if typ == 8:
        return tag, typ, b"".join(value.encode() + b"\0" for value in data), len(data)
    raise ValueError("Unsupported fixture type")


def rpm_header_fixture(*, name="bootc", version="1.17.1", digest=None, arch="x86_64"):
    if digest is None:
        digest = "0" * 64
    tags = [
        rpm_pack_tag(1000, 6, name),
        rpm_pack_tag(1001, 6, version),
        rpm_pack_tag(1002, 6, "1.fc45"),
        rpm_pack_tag(1003, 4, 0),
        rpm_pack_tag(1006, 4, 1795000000),
        rpm_pack_tag(1007, 6, "build-host"),
        rpm_pack_tag(1022, 6, arch),
        rpm_pack_tag(1044, 6, "bootc-1.17.1-1.fc45.src.rpm"),
        rpm_pack_tag(1117, 8, ["bootc", "bootc-install-to-filesystem.8.gz"]),
        rpm_pack_tag(1118, 8, ["/usr/bin/", "/usr/share/man/man8/"]),
        rpm_pack_tag(1116, 4, [0, 1]),
        rpm_pack_tag(1035, 8, [digest, ""]),
        rpm_pack_tag(5011, 4, 8),
    ]
    tags.sort()
    store = bytearray()
    indices = bytearray()
    for tag, typ, content, count in tags:
        indices += struct.pack(">IIII", tag, typ, len(store), count)
        store += content
    return RPM_HEADER_MAGIC + struct.pack(">II", len(tags), len(store)) + indices + store


def sqlite_db(*headers: bytes) -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)")
        connection.executemany(
            "INSERT INTO Packages(blob) VALUES (?)",
            [(sqlite3.Binary(header),) for header in headers],
        )
        return connection.serialize()
    finally:
        connection.close()


def elf_fixture(buildid=b"\xa5" * 20) -> bytes:
    data = bytearray(256)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    note = struct.pack("<III", 4, len(buildid), 3) + b"GNU\x00" + buildid
    struct.pack_into("<IIQQQQQQ", data, 64, 4, 0, 128, 0, 0, len(note), len(note), 4)
    data[128 : 128 + len(note)] = note
    return bytes(data)


def layer(items):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as out:
        for path, payload in items.items():
            member = tarfile.TarInfo(path)
            if isinstance(payload, tuple):
                member.type = tarfile.SYMTYPE
                member.linkname = payload[1]
                out.addfile(member)
            else:
                member.size = len(payload)
                out.addfile(member, io.BytesIO(payload))
    return buf.getvalue()


def apply(archives):
    overlay, budget, descs = {}, {"members": 0, "expanded": 0}, []
    for archive in archives:
        desc = {
            "digest": digest_bytes(archive),
            "size": len(archive),
            "diffId": digest_bytes(gzip.decompress(archive)),
        }
        scan_layer(io.BytesIO(archive), desc, overlay, budget)
        descs.append(desc)
    return overlay, budget, descs


def prepared(*, digest=None, name="bootc", version="1.17.1", arch="x86_64"):
    elf = elf_fixture()
    if digest is None:
        digest = hashlib.sha256(elf).hexdigest()
    db = sqlite_db(rpm_header_fixture(name=name, version=version, digest=digest, arch=arch))
    raw = layer({"usr/bin/bootc": elf, "usr/share/rpm/rpmdb.sqlite": db})
    return apply([raw])


def result(overlay, budget, descs):
    return finish(
        overlay,
        descs,
        budget,
        {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
    )


def test_rpm_database_and_exact_elf_byte_binding_green():
    overlay, budgets, descs = prepared()
    output = result(overlay, budgets, descs)
    proof = output["bootcRpmIdentity"]
    assert proof["status"] == "BOOTC_RPM_IDENTITY_VERIFIED"
    assert proof["rpmPackage"]["name"] == "bootc"
    assert proof["rpmPackage"]["epoch"] == 0
    assert proof["rpmPackage"]["version"] == "1.17.1"
    assert proof["rpmPackage"]["release"] == "1.fc45"
    assert proof["rpmPackage"]["architecture"] == "x86_64"
    assert proof["rpmPackage"]["toFilesystemManpageDeclared"] is True
    assert proof["rpmPackage"]["fileSha256"] == hashlib.sha256(elf_fixture()).hexdigest()
    assert proof["elfBuildId"] == (b"\xa5" * 20).hex()
    assert output["bootcToFilesystemAvailableInBinaryVerified"] is False
    assert output["bootcToFilesystemDocumentedInRpm"] is True
    assert output["nativeInstallationVerified"] is False
    assert output["stable"] is False
    assert all(output[flag] is False for flag in NO_WRITE)


@pytest.mark.parametrize(
    "scenario", ["missing", "truncated", "foreign", "wrong-hash", "fake-version"]
)
def test_missing_forged_and_malformed_rpm_binding_refused(scenario):
    elf = elf_fixture()
    good_sha = hashlib.sha256(elf).hexdigest()
    if scenario == "missing":
        archives = [layer({"usr/bin/bootc": elf})]
    else:
        options = {
            "truncated": b"SQLite format 3\x00" + b"CORRUPTED",
            "foreign": sqlite_db(rpm_header_fixture(name="other", digest=good_sha)),
            "wrong-hash": sqlite_db(rpm_header_fixture(digest="0" * 64)),
            "fake-version": sqlite_db(
                rpm_header_fixture(digest=good_sha, version="../../fake-version")
            ),
        }
        archives = [
            layer(
                {
                    "usr/bin/bootc": elf,
                    "usr/share/rpm/rpmdb.sqlite": options[scenario],
                }
            )
        ]
    overlay, budget, descs = apply(archives)
    output = result(overlay, budget, descs)
    assert output["status"] == "BOOTC_PRESENT_ROUTE_UNVERIFIED"
    assert output["bootcRpmIdentity"]["status"] == "BOOTC_PACKAGE_BINDING_UNPROVEN"
    assert output["bootcVersionVerified"] is False
    assert output["bootcVersion"] is None
    assert all(output[f] is False for f in NO_WRITE)


def test_later_rpmdb_layer_replaces_previous_database_not_stale_package():
    elf = elf_fixture()
    digest = hashlib.sha256(elf).hexdigest()
    first = layer(
        {
            "usr/bin/bootc": elf,
            "usr/share/rpm/rpmdb.sqlite": sqlite_db(rpm_header_fixture(digest=digest)),
        }
    )
    second = layer(
        {
            "usr/share/rpm/rpmdb.sqlite": sqlite_db(
                rpm_header_fixture(version="2.0.0", digest="0" * 64)
            )
        }
    )
    overlay, budget, descs = apply([first, second])
    assert result(overlay, budget, descs)["bootcRpmIdentity"]["status"] == (
        "BOOTC_PACKAGE_BINDING_UNPROVEN"
    )


def test_rpmdb_whiteout_and_opaque_directory_cannot_preserve_stale_owner():
    elf = elf_fixture()
    db = sqlite_db(rpm_header_fixture(digest=hashlib.sha256(elf).hexdigest()))
    first = layer({"usr/bin/bootc": elf, "usr/share/rpm/rpmdb.sqlite": db})
    for victim in ("usr/share/rpm/.wh.rpmdb.sqlite", "usr/share/rpm/.wh..wh..opq"):
        state, budget, descs = apply([first, layer({victim: b""})])
        assert result(state, budget, descs)["bootcRpmIdentity"]["status"] == (
            "BOOTC_PACKAGE_BINDING_UNPROVEN"
        )


def test_duplicate_rpmdb_in_single_layer_fails_closed():
    elf = elf_fixture()
    db = sqlite_db(rpm_header_fixture(digest=hashlib.sha256(elf).hexdigest()))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for _ in range(2):
            name = "usr/share/rpm/rpmdb.sqlite"
            entry = tarfile.TarInfo(name)
            entry.size = len(db)
            archive.addfile(entry, io.BytesIO(db))
    with pytest.raises(Exception, match="Duplicate RPM DB path"):
        apply([buf.getvalue()])


def test_database_symlink_and_sqlite_wal_not_accepted():
    elf = elf_fixture()
    db = sqlite_db(rpm_header_fixture(digest=hashlib.sha256(elf).hexdigest()))
    for extra in (
        {"usr/share/rpm/rpmdb.sqlite": ("symlink", "../../etc/passwd")},
        {"usr/share/rpm/rpmdb.sqlite": db, "usr/share/rpm/rpmdb.sqlite-wal": b"header"},
    ):
        overlay, budget, descs = apply([layer({"usr/bin/bootc": elf, **extra})])
        assert result(overlay, budget, descs)["bootcRpmIdentity"]["status"] == (
            "BOOTC_PACKAGE_BINDING_UNPROVEN"
        )


def test_ambiguous_packages_not_accepted():
    elf = elf_fixture()
    digest = hashlib.sha256(elf).hexdigest()
    db = sqlite_db(rpm_header_fixture(digest=digest), rpm_header_fixture(digest=digest))
    overlay, budget, descs = apply(
        [
            layer(
                {
                    "usr/bin/bootc": elf,
                    "usr/share/rpm/rpmdb.sqlite": db,
                }
            )
        ]
    )
    assert result(overlay, budget, descs)["bootcRpmIdentity"]["status"] == (
        "BOOTC_PACKAGE_BINDING_UNPROVEN"
    )


def test_elf_wrong_machine_and_truncated_build_id_unproven():
    elf = bytearray(elf_fixture())
    elf[18:20] = b"\x28\x00"
    with pytest.raises(PackageUnproven, match="architecture"):
        elf_build_id(bytes(elf))
    elf = bytearray(elf_fixture())
    struct.pack_into("<Q", elf, 64 + 32, 65536)
    with pytest.raises(PackageUnproven, match="notes outside"):
        elf_build_id(bytes(elf))


def test_rpm_header_truncation_and_duplicate_tags_refused():
    good = rpm_header_fixture()
    for malformed in (good[:20], good[:-1], good[:8] + b"\xff" * 8 + good[16:]):
        with pytest.raises(PackageUnproven):
            rpm_header(malformed)


def test_other_package_cannot_claim_bootc_file():
    header = rpm_header_fixture(name="not-bootc", digest="0" * 64)
    parsed = rpm_header(header)
    assert parsed == {"name": "not-bootc"}
    assert "fileSha256" not in parsed


def test_bounded_db_paths_are_explicit_and_no_executable_import():
    assert "usr/share/rpm/rpmdb.sqlite" in RPMDB_PATHS
    assert "var/lib/rpm/rpmdb.sqlite" in RPMDB_PATHS
