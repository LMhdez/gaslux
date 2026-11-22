"""Adversarial tests for signed OCI host-only bootc readback; no image execution."""

from __future__ import annotations

import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest
import zstandard as zstd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))
from bazzite_oci_bootc_readback import (  # noqa: E402
    CANDIDATES,
    MAX_LAYER,
    NO_WRITE,
    ZSTD_LAYER,
    InsufficientEvidence,
    Refusal,
    digest_bytes,
    finish,
    scan_layer,
    validate_metadata,
)


def sample_metadata(*, arch="amd64", layer_count=1):
    desc = {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "size": 123,
        "digest": "sha256:" + "1" * 64,
    }
    config = {
        "architecture": arch,
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "2" * 64] * layer_count},
        "config": {"Labels": {"org.opencontainers.image.version": "45.20261117.1"}},
    }
    encoded_config = json.dumps(config, separators=(",", ":")).encode()
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(encoded_config),
            "digest": digest_bytes(encoded_config),
        },
        "layers": [desc.copy() for _ in range(layer_count)],
    }
    encoded_manifest = json.dumps(manifest, separators=(",", ":")).encode()
    return manifest, config, encoded_manifest, encoded_config


def verified_meta():
    _m, _c, a, b = sample_metadata()
    return validate_metadata(
        a, b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b)
    )


def tar_layer(entries: dict[str, bytes | tuple[str, str]]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                member.type = tarfile.SYMTYPE
                member.linkname = data[1]
            else:
                member.size = len(data)
            tar.addfile(member, io.BytesIO(data) if isinstance(data, bytes) else None)
    return out.getvalue()


def scan(data: bytes, state=None, budget=None):
    state = {} if state is None else state
    budget = {"members": 0, "expanded": 0} if budget is None else budget
    try:
        expanded = gzip.decompress(data)
    except (OSError, EOFError):
        expanded = b"invalid-layer"
    desc = {"digest": digest_bytes(data), "size": len(data), "diffId": digest_bytes(expanded)}
    scan_layer(io.BytesIO(data), desc, state, budget)
    return state, budget


def test_authenticated_format_without_top_level_media_type_supported():
    manifest, _config, _a, b = sample_metadata()
    del manifest["mediaType"]
    a = json.dumps(manifest).encode()
    descriptors, info = validate_metadata(
        a, b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b)
    )
    assert len(descriptors) == 1
    assert info["architecture"] == "amd64"


def test_unknown_top_level_media_type_remains_refused():
    manifest, _config, _a, b = sample_metadata()
    manifest["mediaType"] = "application/x-unsafe-container"
    a = json.dumps(manifest).encode()
    with pytest.raises(Refusal, match="manifest mediaType"):
        validate_metadata(a, b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b))


def test_synthetic_oci_manifest_and_config_chained():
    descriptors, info = verified_meta()
    assert len(descriptors) == 1
    assert info["architecture"] == "amd64"
    assert info["declaredLabels"]["org.opencontainers.image.version"] == "45.20261117.1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("architecture", "arm64"),
        ("os", "windows"),
    ],
)
def test_wrong_architecture_or_os_refused(field, value):
    manifest, config, _a, _b = sample_metadata()
    config[field] = value
    encoded = json.dumps(config).encode()
    manifest["config"]["digest"] = digest_bytes(encoded)
    manifest["config"]["size"] = len(encoded)
    encoded_manifest = json.dumps(manifest).encode()
    reason = "architecture" if field == "architecture" else "operating system"
    with pytest.raises(Refusal, match=reason):
        validate_metadata(
            encoded_manifest,
            encoded,
            expected_manifest=digest_bytes(encoded_manifest),
            expected_config=digest_bytes(encoded),
        )


def test_signed_manifest_or_config_substitution_refused():
    _m, _c, a, b = sample_metadata()
    with pytest.raises(Refusal, match="manifest digest"):
        validate_metadata(
            a + b"x", b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b)
        )
    with pytest.raises(Refusal, match="config digest"):
        validate_metadata(
            a, b + b"x", expected_manifest=digest_bytes(a), expected_config=digest_bytes(b)
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("size", True),
        ("size", 0),
        ("size", MAX_LAYER + 1),
        ("digest", "sha256:" + "x" * 64),
        ("mediaType", "application/vnd.oci.image.layer.v1.tar+lz4"),
        ("urls", ["https://attacker.example/layer"]),
    ],
)
def test_untrusted_layer_descriptor_refused(key, value):
    manifest, _config, _a, b = sample_metadata()
    manifest["layers"][0][key] = value
    a = json.dumps(manifest).encode()
    with pytest.raises(Refusal):
        validate_metadata(a, b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b))


def test_missing_or_extra_rootfs_layer_refused():
    _manifest, config, _a, b = sample_metadata()
    config["rootfs"]["diff_ids"] = []
    b = json.dumps(config).encode()
    _manifest["config"]["digest"] = digest_bytes(b)
    _manifest["config"]["size"] = len(b)
    a = json.dumps(_manifest).encode()
    with pytest.raises(Refusal, match="layer chain"):
        validate_metadata(a, b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b))


def test_real_elf_header_observed_but_never_authorizes_execution():
    data = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"\0" * 40})
    state, budget = scan(data)
    desc = [{"digest": digest_bytes(data), "size": len(data)}]
    decision = finish(
        state, desc, budget, {"architecture": "amd64", "os": "linux", "declaredLabels": {}}
    )
    assert decision["status"] == "BOOTC_PRESENT_ROUTE_UNVERIFIED"
    assert decision["bootcVersion"] is None
    assert decision["bootcToFilesystemAvailableInBinaryVerified"] is False
    assert decision["bootcFiles"][0]["path"] in CANDIDATES
    assert all(decision[field] is False for field in NO_WRITE)


def test_complete_no_binary_image_marked_unavailable_not_signed_runtime():
    data = tar_layer({"etc/os-release": b"ID=bazzite\n"})
    state, budget = scan(data)
    decision = finish(
        state,
        [{"digest": digest_bytes(data), "size": len(data)}],
        budget,
        {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
    )
    assert decision["status"] == "BOOTC_UNAVAILABLE_IN_PINNED_IMAGE"
    assert decision["bootcVersionVerified"] is False
    assert all(decision[k] is False for k in NO_WRITE)


def test_whiteout_removes_executable_and_prevents_false_presence():
    first = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"A" * 40})
    state, budget = scan(first)
    second = tar_layer({"usr/bin/.wh.bootc": b""})
    scan(second, state, budget)
    assert state == {}


@pytest.mark.parametrize(
    "name",
    [
        "../usr/bin/bootc",
        "/usr/bin/bootc",
        "usr/../../etc/passwd",
    ],
)
def test_hostile_tar_paths_refused(name):
    data = tar_layer({name: b"\x7fELF" + b"abc"})
    with pytest.raises(Refusal, match="path"):
        scan(data)


def test_backslash_in_posix_tar_name_is_not_a_directory_separator():
    archive = tar_layer({"usr\\bin\\bootc": b"\x7fELF" + b"not-the-real-path"})
    state, budget = scan(archive)
    assert "usr/bin/bootc" not in state
    result = finish(
        state,
        [{"digest": digest_bytes(archive), "size": len(archive)}],
        budget,
        {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
    )
    assert result["status"] == "BOOTC_UNAVAILABLE_IN_PINNED_IMAGE"
    assert all(result[field] is False for field in NO_WRITE)


@pytest.mark.parametrize("target", ["/etc/passwd", "../../../etc/shadow"])
def test_executable_symlink_escaping_image_refused(target):
    data = tar_layer({"usr/bin/bootc": ("symlink", target)})
    with pytest.raises(Refusal):
        scan(data)


def test_tampered_layer_gzip_digest_refused():
    data = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"A"})
    with pytest.raises(Refusal, match="digest or size"):
        scan_layer(
            io.BytesIO(data + b"forged"),
            {"size": len(data), "digest": digest_bytes(data), "diffId": digest_bytes(b"tar")},
            {},
            {"members": 0, "expanded": 0},
        )


def test_unbounded_binary_size_refused():
    info = tarfile.TarInfo("usr/bin/bootc")
    info.size = 128 * 1024 * 1024 + 1
    compressed = gzip.compress(info.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024)
    with pytest.raises(Refusal, match="Suspicious bootc executable size"):
        scan(compressed)


def test_valid_zstandard_layer_replays_exact_bootc_elf_without_executing():
    gz = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"bootc-example"})
    zbytes = zstd.ZstdCompressor(level=1).compress(gzip.decompress(gz))
    descriptor = {
        "digest": digest_bytes(zbytes),
        "size": len(zbytes),
        "mediaType": ZSTD_LAYER,
        "diffId": digest_bytes(gzip.decompress(gz)),
    }
    state = {}
    budget = {"members": 0, "expanded": 0}
    scan_layer(io.BytesIO(zbytes), descriptor, state, budget)
    result = finish(
        state,
        [descriptor],
        budget,
        {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
    )
    assert result["status"] == "BOOTC_PRESENT_ROUTE_UNVERIFIED"
    assert result["bootcToFilesystemAvailableInBinaryVerified"] is False
    assert all(result[k] is False for k in NO_WRITE)


def test_invalid_zstandard_payload_with_matching_fake_descriptor_refused():
    forged = b"not-zstandard-data"
    with pytest.raises(Refusal, match="OCI layer tar"):
        scan_layer(
            io.BytesIO(forged),
            {
                "digest": digest_bytes(forged),
                "size": len(forged),
                "mediaType": ZSTD_LAYER,
                "diffId": digest_bytes(b"tar"),
            },
            {},
            {"members": 0, "expanded": 0},
        )


def test_malformed_gzip_refused_after_matching_descriptor():
    data = b"not a tarball"
    with pytest.raises(Refusal, match="tar"):
        scan(data)


def test_json_has_no_authority_even_when_status_is_present():
    data = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"xyz"})
    state, budget = scan(data)
    d = finish(
        state,
        [{"size": len(data), "digest": digest_bytes(data)}],
        budget,
        {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
    )
    assert all(d[key] is False for key in NO_WRITE)


def test_oci_config_diffid_is_passed_to_every_layer_descriptor():
    _manifest, _config, a, b = sample_metadata()
    desc, _info = validate_metadata(
        a, b, expected_manifest=digest_bytes(a), expected_config=digest_bytes(b)
    )
    assert desc[0]["diffId"] == "sha256:" + "2" * 64


def test_matching_compressed_digest_with_forged_uncompressed_diffid_refused():
    layer = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"x" * 50})
    wrong = {
        "digest": digest_bytes(layer),
        "size": len(layer),
        "diffId": "sha256:" + "0" * 64,
    }
    with pytest.raises(Refusal, match="uncompressed diff-id mismatch"):
        scan_layer(
            io.BytesIO(layer),
            wrong,
            {},
            {"members": 0, "expanded": 0},
        )


def test_uncompressed_diffid_must_be_present_and_well_formed():
    layer = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"x" * 50})
    for invalid in (None, True, "sha256:000", "0" * 64):
        with pytest.raises(Refusal, match="Missing or malformed"):
            scan_layer(
                io.BytesIO(layer),
                {"digest": digest_bytes(layer), "size": len(layer), "diffId": invalid},
                {},
                {"members": 0, "expanded": 0},
            )


def test_valid_gzip_layer_hashes_full_uncompressed_tar_not_only_members():
    layer = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"x" * 50})
    state, budget = scan(layer)
    assert budget["diffIdsVerified"] == 1
    assert budget["expandedStreamBytes"] == len(gzip.decompress(layer))
    result = finish(
        state,
        [{"digest": digest_bytes(layer), "size": len(layer)}],
        budget,
        {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
    )
    assert result["allUncompressedLayerDigestsVerified"] is True
    assert result["expandedStreamBytesHashed"] == len(gzip.decompress(layer))
    assert all(result[key] is False for key in NO_WRITE)


def test_uncompressed_trailing_bytes_are_included_in_diffid():
    original = gzip.decompress(tar_layer({"usr/bin/bootc": b"\x7fELF" + b"x"}))
    altered = original + b"UNEXPECTED_AFTER_TAR_END"
    layer = gzip.compress(altered)
    desc = {"digest": digest_bytes(layer), "size": len(layer), "diffId": digest_bytes(original)}
    with pytest.raises(Refusal, match="uncompressed diff-id mismatch"):
        scan_layer(io.BytesIO(layer), desc, {}, {"members": 0, "expanded": 0})


def test_actual_decompressed_stream_limit_includes_padding(monkeypatch):
    import bazzite_oci_bootc_readback as module

    original = gzip.decompress(tar_layer({"usr/bin/bootc": b"\x7fELF" + b"x"}))
    layer = gzip.compress(original + b"\x00" * 8192)
    desc = {
        "digest": digest_bytes(layer),
        "size": len(layer),
        "diffId": digest_bytes(original + b"\x00" * 8192),
    }
    monkeypatch.setattr(module, "MAX_EXPANDED", 1024)
    with pytest.raises(Refusal, match="Actual decompressed OCI stream"):
        scan_layer(io.BytesIO(layer), desc, {}, {"members": 0, "expanded": 0})


def test_finish_refuses_unverified_diffids_even_with_forged_bootc_file():
    data = tar_layer({"usr/bin/bootc": b"\x7fELF" + b"payload"})
    state, budget = scan(data)
    budget["diffIdsVerified"] = 0
    with pytest.raises(Refusal, match="Not all OCI uncompressed diff-ids verified"):
        finish(
            state,
            [{"digest": digest_bytes(data), "size": len(data)}],
            budget,
            {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
        )


def test_duplicate_bootc_file_in_one_layer_is_ambiguous_and_refused():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for payload in (b"\x7fELFfirst", b"\x7fELFsecond"):
            entry = tarfile.TarInfo("usr/bin/bootc")
            entry.size = len(payload)
            tar.addfile(entry, io.BytesIO(payload))
    with pytest.raises(Refusal, match="Duplicate bootc path"):
        scan(out.getvalue())


def test_unresolved_bootc_path_is_insufficient_not_absent():
    layer = tar_layer({"usr/bin/bootc": ("symlink", "not-present")})
    state, budget = scan(layer)
    with pytest.raises(InsufficientEvidence, match="cannot be resolved safely"):
        finish(
            state,
            [{"digest": digest_bytes(layer), "size": len(layer)}],
            budget,
            {"architecture": "amd64", "os": "linux", "declaredLabels": {}},
        )


def test_cli_insufficient_evidence_fails_closed_without_writer(tmp_path, monkeypatch):
    import bazzite_oci_bootc_readback as module

    def cannot_resolve():
        raise module.InsufficientEvidence("Unresolved executable")

    monkeypatch.setattr(module, "download_registry", cannot_resolve)
    dest = tmp_path / "readback.json"
    monkeypatch.setattr(sys, "argv", ["inspector", "--output", str(dest)])
    with pytest.raises(SystemExit) as exited:
        module.main()
    assert exited.value.code == 3
    result = json.loads(dest.read_text())
    assert result["status"] == "INSUFFICIENT_EVIDENCE"
    assert result["bootcFileVerified"] is False
    assert all(result[flag] is False for flag in NO_WRITE)
