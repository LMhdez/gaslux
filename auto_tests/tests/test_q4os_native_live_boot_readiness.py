"""Q4OS native live boot readiness: strictly offline, never QEMU or Calamares."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import q4os_native_live_boot_readiness as readiness  # noqa: E402


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    target = directory / "fixture.iso"
    data = b"TEST_ONLY_NOT_A_Q4OS_ISO" * 400
    target.write_bytes(data)
    target.chmod(0o600)
    return target, data


def measurement(path: Path, digest: str, minimum: int = 1, maximum: int = 30000):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return readiness.measure_fd(fd, digest, minimum, maximum)
    finally:
        os.close(fd)


def test_readonly_fd_measurement_is_exact_and_not_a_qemu_binding(source):
    target, data = source
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.lseek(fd, 12, os.SEEK_SET)
        info = readiness.measure_fd(fd, hashlib.sha256(data).hexdigest(), 1, 30000)
        assert info["sha256"] == hashlib.sha256(data).hexdigest()
        assert info["sizeBytes"] == len(data)
        assert info["fdReadOnlyPinnedDuringMeasurement"] is True
        assert info["qemuFdBound"] is False
        assert os.lseek(fd, 0, os.SEEK_CUR) == 12
    finally:
        os.close(fd)


def test_digest_flip_denied_without_public_path(source):
    target, data = source
    with pytest.raises(readiness.MediaRefusal, match="ISO_DIGEST_MISMATCH"):
        measurement(target, hashlib.sha256(data + b"x").hexdigest())


@pytest.mark.parametrize("size_range", [(len(b"TEST_ONLY_NOT_A_Q4OS_ISO" * 400) + 1, 50000), (1, 3)])
def test_wrong_length_denied(source, size_range):
    target, data = source
    with pytest.raises(readiness.MediaRefusal, match="ISO_SIZE_OUT_OF_RANGE"):
        measurement(target, hashlib.sha256(data).hexdigest(), *size_range)


def test_symlink_opened_by_caller_must_be_no_follow(source):
    target, data = source
    symlink = target.parent / "link.iso"
    symlink.symlink_to(target)
    with pytest.raises(OSError):
        os.open(symlink, os.O_RDONLY | os.O_NOFOLLOW)


def test_hardlink_denied(source):
    target, data = source
    os.link(target, target.parent / "hardlink.iso")
    with pytest.raises(readiness.MediaRefusal, match="ISO_FD_LINKED"):
        measurement(target, hashlib.sha256(data).hexdigest())


def test_public_permissions_denied(source):
    target, data = source
    target.chmod(0o644)
    with pytest.raises(readiness.MediaRefusal, match="ISO_FD_PUBLIC_PERMISSIONS"):
        measurement(target, hashlib.sha256(data).hexdigest())


def test_writable_descriptor_is_not_a_readonly_witness(source):
    target, data = source
    fd = os.open(target, os.O_RDWR | os.O_NOFOLLOW)
    try:
        with pytest.raises(readiness.MediaRefusal, match="ISO_FD_NOT_READ_ONLY"):
            readiness.measure_fd(fd, hashlib.sha256(data).hexdigest(), 1, 30000)
    finally:
        os.close(fd)


def test_closed_or_non_regular_descriptor_denied(source):
    target, data = source
    fd = os.open(target, os.O_RDONLY)
    os.close(fd)
    with pytest.raises(readiness.MediaRefusal, match="ISO_READ_FAILURE"):
        readiness.measure_fd(fd, hashlib.sha256(data).hexdigest(), 1, 30000)
    other = os.open(os.devnull, os.O_RDONLY)
    try:
        with pytest.raises(readiness.MediaRefusal, match="ISO_FD_NOT_REGULAR"):
            readiness.measure_fd(other, hashlib.sha256(data).hexdigest(), 1, 30000)
    finally:
        os.close(other)


def test_replaced_path_after_pin_preserves_original_and_rejects_new(source):
    target, data = source
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    original = target.parent / "original.iso"
    target.rename(original)
    target.write_bytes(b"FOREIGN_SENTINEL")
    target.chmod(0o600)
    try:
        result = readiness.measure_fd(fd, hashlib.sha256(data).hexdigest(), 1, 30000)
        assert result["sha256"] == hashlib.sha256(original.read_bytes()).hexdigest()
        assert target.read_bytes() == b"FOREIGN_SENTINEL"
        with pytest.raises(readiness.MediaRefusal, match="ISO_DIGEST_MISMATCH"):
            measurement(target, hashlib.sha256(data).hexdigest())
    finally:
        os.close(fd)


def test_in_place_mutation_is_denied(source, monkeypatch):
    target, data = source
    original_pread = readiness.os.pread
    changed = []

    def mutating_pread(fd, count, offset):
        chunk = original_pread(fd, count, offset)
        if not changed:
            with target.open("r+b") as stream:
                stream.seek(0)
                stream.write(b"X")
                stream.flush()
                os.fsync(stream.fileno())
            changed.append(True)
        return chunk

    monkeypatch.setattr(readiness.os, "pread", mutating_pread)
    with pytest.raises(readiness.MediaRefusal, match="ISO_CHANGED_DURING_READ"):
        measurement(target, hashlib.sha256(data).hexdigest())
    assert changed


def test_official_wrapper_rejects_tiny_untrusted_iso_and_bad_directory(tmp_path):
    directory = tmp_path / "secure"
    directory.mkdir(mode=0o700)
    path = directory / readiness.ISO_NAME
    path.write_bytes(b"DELIBERATELY_INVALID_ISO")
    path.chmod(0o600)
    with pytest.raises(readiness.MediaRefusal, match="ISO_SIZE_OUT_OF_RANGE"):
        readiness.measure_official_iso(path)
    directory.chmod(0o755)
    with pytest.raises(readiness.MediaRefusal, match="ISO_SOURCE_DIRECTORY_UNTRUSTED"):
        readiness.measure_official_iso(path)


def test_official_wrapper_denies_symlink_and_bad_source_name(tmp_path):
    directory = tmp_path / "secure"
    directory.mkdir(mode=0o700)
    target = directory / "foreign"
    target.write_bytes(b"not an ISO")
    path = directory / readiness.ISO_NAME
    path.symlink_to(target)
    with pytest.raises(readiness.MediaRefusal, match="ISO_READ_FAILURE"):
        readiness.measure_official_iso(path)
    with pytest.raises(readiness.MediaRefusal, match="ISO_SOURCE_NAME_INVALID"):
        readiness.measure_official_iso(target)


def test_source_only_manifest_has_no_boot_or_provenance_authority():
    doc = readiness.readiness_manifest()
    assert doc["decision"] == "DENY"
    assert doc["evidenceLevel"] == "SOURCE_REFERENCE_ONLY"
    assert doc["iso"]["observed"] is None
    assert doc["source"]["signedGasluxCatalogVerified"] is False
    assert doc["source"]["exactCatalogSizeBytes"] is None
    assert doc["source"]["historicalNativeInstaller"] == "Calamares"
    assert doc["source"]["installerObservedInThisRun"] is False
    assert not any(doc["runtimeBindings"].values())
    assert not any(doc["guest"].values())
    assert all(val is False for key, val in doc["gates"].items() if key != "disposableVmStandingPolicy")
    assert doc["gates"]["disposableVmStandingPolicy"] is True
    assert "SIGNED_GASLUX_ISO_CATALOG_MISSING" in doc["blockers"]


def test_no_sensitive_path_in_cli_refusal(tmp_path, monkeypatch, capsys):
    sentinel = "SECRET_SENTINEL_PRIVATE_ISO_DIR"
    directory = tmp_path / sentinel
    directory.mkdir(mode=0o700)
    path = directory / readiness.ISO_NAME
    path.write_bytes(b"invalid")
    path.chmod(0o600)
    monkeypatch.setattr(sys, "argv", ["q4os-readiness", "--iso", str(path)])
    assert readiness.main() == 2
    output = capsys.readouterr()
    assert sentinel not in output.out + output.err
    assert output.err == ""
    assert json.loads(output.out)["decision"] == "DENY"


def test_official_sha_matches_existing_dev_workflow_and_not_stable_catalog():
    repo = Path(__file__).resolve().parents[2]
    workflow = (
        repo / ".github/workflows/gaslux-q4os-official-iso.yml"
    ).read_text(encoding="utf-8")
    catalog = json.loads((repo / "release-config.json").read_text(encoding="utf-8"))
    assert readiness.UPSTREAM_SHA256 in workflow
    assert readiness.ISO_NAME in workflow
    assert "q4os" not in {item["id"] for item in catalog["distributions"]}



def test_manifest_schema_rejects_false_guest_and_release_authority():
    import jsonschema

    repo = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (repo / "schemas/gaslux-q4os-native-live-readiness.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    doc = readiness.readiness_manifest()
    jsonschema.validate(doc, schema)
    assert doc["gates"]["liveBootAuthorized"] is False
    assert doc["gates"]["stable"] is False

    forged = json.loads(json.dumps(doc))
    forged["guest"]["kernelBooted"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)
    forged = json.loads(json.dumps(doc))
    forged["gates"]["QEMU_FD_BACKING_VERIFIED"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)
    forged = json.loads(json.dumps(doc))
    forged["source"]["signedGasluxCatalogVerified"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)
    forged = json.loads(json.dumps(doc))
    forged["decision"] = "ALLOW"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)


def test_schema_does_not_allow_self_referential_fake_media_observation():
    import jsonschema

    repo = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (repo / "schemas/gaslux-q4os-native-live-readiness.schema.json").read_text()
    )
    forged = readiness.readiness_manifest()
    forged["iso"]["sha256MatchedThisRun"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)
    forged = readiness.readiness_manifest()
    forged["evidenceLevel"] = "MEDIA_HASH_ONLY"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)


def test_private_source_directory_requires_owned_absolute_path(source):
    target, _data = source
    with pytest.raises(readiness.MediaRefusal, match="ISO_SOURCE_NAME_INVALID"):
        readiness.measure_official_iso(Path(readiness.ISO_NAME))
    with pytest.raises(readiness.MediaRefusal, match="ISO_SOURCE_NAME_INVALID"):
        readiness.measure_official_iso(target)


def test_untrusted_hash_format_never_bypasses_fd_validation(source):
    target, _data = source
    with pytest.raises(readiness.MediaRefusal, match="ISO_FD_INVALID"):
        measurement(target, "0" * 63)
    with pytest.raises(readiness.MediaRefusal, match="ISO_FD_INVALID"):
        measurement(target, "Z" * 64)
