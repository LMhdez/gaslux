"""Offline adversarial tests for the real Q4OS ISO provenance inspector.

Synthetic config text is deliberately not a claim of verified live media.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import q4os_native_live_boot_readiness as readiness  # noqa: E402
import q4os_official_iso_provenance as provenance  # noqa: E402

OS_RELEASE = 'ID=debian\nVERSION_ID="13"\n'
VERSION = "6.10-deb13u1"
SETTINGS = "sequence:\n  - show:\n      - welcome\n"
BOOTLOADER = "installEFIFallback: true\n"
KERNELS = ["vmlinuz-6.12.111+deb13-amd64"]
INITRDS = ["initrd.img-6.12.111+deb13-amd64"]


def inspect(**override):
    details = {
        "os_release": OS_RELEASE,
        "version": VERSION,
        "settings_yaml": SETTINGS,
        "bootloader_yaml": BOOTLOADER,
        "kernel_names": KERNELS,
        "initrd_names": INITRDS,
    }
    details.update(override)
    return provenance.validate_native_fields(**details)


def test_native_iso_identity_requires_q4os_marker_and_calamares():
    result = inspect()
    assert result["debianOsReleaseId"] == "debian"
    assert result["debianVersionId"] == "13"
    assert result["q4osVersion"] == VERSION
    assert result["nativeInstaller"] == "Calamares"
    assert result["calamaresSequenceVerified"] is True
    assert result["installEFIFallback"] is True


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"os_release": "ID=ubuntu\nVERSION_ID=24\n"}, "MEDIA_INSPECT_BAD_IDENTITY"),
        ({"os_release": "ID=debian\nVERSION_ID=12\n"}, "MEDIA_INSPECT_BAD_IDENTITY"),
        ({"version": "6.9-deb13u1"}, "MEDIA_INSPECT_BAD_IDENTITY"),
        ({"version": "7.0-deb13u1"}, "MEDIA_INSPECT_BAD_IDENTITY"),
        ({"version": "../6.10"}, "MEDIA_INSPECT_BAD_IDENTITY"),
        ({"kernel_names": []}, "MEDIA_INSPECT_BAD_KERNEL"),
        ({"initrd_names": []}, "MEDIA_INSPECT_BAD_KERNEL"),
        ({"kernel_names": ["../../secret"]}, "MEDIA_INSPECT_BAD_KERNEL"),
        ({"initrd_names": ["../foo"]}, "MEDIA_INSPECT_BAD_KERNEL"),
        ({"settings_yaml": "bootloader: grub\n"}, "MEDIA_INSPECT_BAD_INSTALLER"),
        ({"settings_yaml": "sequence: [1]\nsequence: [2]\n"}, "MEDIA_INSPECT_BAD_CONFIGURATION"),
        (
            {"bootloader_yaml": "installEFIFallback: true\ninstallEFIFallback: false\n"},
            "MEDIA_INSPECT_BAD_CONFIGURATION",
        ),
        ({"bootloader_yaml": "installEFIFallback: unknown\n"}, "MEDIA_INSPECT_BAD_CONFIGURATION"),
        (
            {"bootloader_yaml": "installEFIFallback: !!python/object/apply:os.system ['exit 1']"},
            "MEDIA_INSPECT_BAD_CONFIGURATION",
        ),
    ],
)
def test_reject_unverified_version_boot_paths_and_unsafe_installer(change, reason):
    with pytest.raises(provenance.InspectRefusal, match=reason):
        inspect(**change)


@pytest.mark.parametrize(
    "member",
    [
        "etc/../../../etc/shadow",
        "../etc/os-release",
        "etc/calamares/modules/partition.conf",
        "etc/calamares/modules/bootloader.conf/../shadow",
        "etc/os-release\0",
    ],
)
def test_reject_non_allowlisted_squashfs_member_before_subprocess(member, monkeypatch):
    called = []

    def forbidden(*_args, **_kwargs):
        called.append(True)
        raise AssertionError("unexpected unsquashfs launch")

    monkeypatch.setattr(provenance.subprocess, "run", forbidden)
    with pytest.raises(provenance.InspectRefusal, match="MEDIA_INSPECT_BAD_CONFIGURATION"):
        provenance._bounded_unsquashfs(Path("/not-used"), member)
    assert not called


def test_probe_refuses_non_mount_before_any_source_read(tmp_path, monkeypatch):
    called = []

    def forbidden(*_args, **_kwargs):
        called.append(True)
        raise AssertionError("unexpected mount inspection")

    monkeypatch.setattr(provenance.subprocess, "run", forbidden)
    with pytest.raises(provenance.InspectRefusal, match="MEDIA_INSPECT_EXTERNAL_FAILURE"):
        provenance.inspect_mounted_native_iso(tmp_path)
    assert not called


def test_forged_signing_can_never_be_inferred_from_public_checksum(tmp_path, monkeypatch):
    calls = []
    measured = {
        "sha256": readiness.UPSTREAM_SHA256,
        "sizeBytes": 1_910_000_000,
        "fdReadOnlyPinnedDuringMeasurement": True,
        "qemuFdBound": False,
    }

    def fixed_measurement(_iso):
        calls.append("measure")
        return dict(measured)

    def fixed_inspection(_root):
        calls.append("inspect")
        return inspect()

    monkeypatch.setattr(provenance.readiness, "measure_official_iso", fixed_measurement)
    monkeypatch.setattr(provenance, "inspect_mounted_native_iso", fixed_inspection)
    result = provenance.report_for_inspection(tmp_path / readiness.ISO_NAME, tmp_path)
    assert calls == ["measure", "inspect", "measure"]
    assert result["decision"] == "DENY"
    assert result["publisherSignatureVerified"] is False
    assert result["publisherSigningKeyTrusted"] is False
    assert result["gasluxCatalogSignatureVerified"] is False
    assert result["isoFdBoundToQemu"] is False
    assert result["guestBooted"] is False
    assert result["candidateCatalogFieldsUnsigned"]["signed"] is False
    assert result["candidateCatalogFieldsUnsigned"]["isoInstallerSizeBytes"] == 1_910_000_000
    assert result["candidateCatalogFieldsUnsigned"]["productionEligible"] is False


def test_inode_or_hash_measurement_changed_between_inspections_denied(tmp_path, monkeypatch):
    values = [
        {"sha256": readiness.UPSTREAM_SHA256, "sizeBytes": 1_900_000_000},
        {"sha256": readiness.UPSTREAM_SHA256, "sizeBytes": 1_900_000_001},
    ]

    def changing_measurement(_path):
        return values.pop(0)

    monkeypatch.setattr(provenance.readiness, "measure_official_iso", changing_measurement)
    monkeypatch.setattr(provenance, "inspect_mounted_native_iso", lambda _root: inspect())
    with pytest.raises(provenance.InspectRefusal, match="MEDIA_NOT_AUTHENTICATED"):
        provenance.report_for_inspection(tmp_path / readiness.ISO_NAME, tmp_path)


def test_candidate_matches_stable_catalog_field_names(tmp_path, monkeypatch):
    media = {"sha256": readiness.UPSTREAM_SHA256, "sizeBytes": 1234567890}
    monkeypatch.setattr(provenance.readiness, "measure_official_iso", lambda _p: dict(media))
    monkeypatch.setattr(provenance, "inspect_mounted_native_iso", lambda _p: inspect())
    result = provenance.report_for_inspection(tmp_path / readiness.ISO_NAME, tmp_path)
    candidate = result["candidateCatalogFieldsUnsigned"]
    repo = Path(__file__).resolve().parents[2]
    stable = json.loads((repo / "release-config.json").read_text(encoding="utf-8"))
    example = stable["distributions"][0]
    fields = (
        "id",
        "name",
        "isoInstaller",
        "isoInstallerFileName",
        "isoInstallerSha256",
        "isoInstallerSizeBytes",
    )
    for field in fields:
        assert field in example and field in candidate
    assert not any(item["id"] == "q4os" for item in stable["distributions"])
    assert candidate["experimental"] is True
    assert candidate["signed"] is False


def test_public_q4os_checksum_is_literal_pinned_and_not_publisher_signature():
    assert readiness.UPSTREAM_SHA256 == (
        "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
    )
    assert readiness.SIGNED_RELEASE_METADATA_VERIFIED is False
    assert not hasattr(provenance, "sign") and not hasattr(provenance, "authorize_live_boot")


def test_provenance_schema_rejects_forged_signatures_and_unsigned_catalog():
    import jsonschema

    repo = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (repo / "schemas/gaslux-q4os-iso-provenance-evidence.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    media = {
        "sha256": readiness.UPSTREAM_SHA256,
        "sizeBytes": 1_910_000_000,
        "fdReadOnlyPinnedDuringMeasurement": True,
        "qemuFdBound": False,
    }
    original_measure = provenance.readiness.measure_official_iso
    original_inspect = provenance.inspect_mounted_native_iso
    try:
        provenance.readiness.measure_official_iso = lambda _p: dict(media)
        provenance.inspect_mounted_native_iso = lambda _p: inspect()
        report = provenance.report_for_inspection(Path("/test.iso"), Path("/mount"))
    finally:
        provenance.readiness.measure_official_iso = original_measure
        provenance.inspect_mounted_native_iso = original_inspect
    jsonschema.validate(report, schema)
    for field in ("publisherSignatureVerified", "gasluxCatalogSignatureVerified", "guestBooted"):
        forged = json.loads(json.dumps(report))
        forged[field] = True
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(forged, schema)
    forged = json.loads(json.dumps(report))
    forged["candidateCatalogFieldsUnsigned"]["signed"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)
    forged = json.loads(json.dumps(report))
    forged["media"]["sizeBytes"] = -1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)


def test_invalid_squashfs_member_refusal_does_not_emit_private_path(capsys):
    private = Path("/private/SECRET_SENTINEL_ABC")
    with pytest.raises(provenance.InspectRefusal):
        provenance._bounded_unsquashfs(private, "../etc/shadow")
    assert "SECRET_SENTINEL_ABC" not in "".join(capsys.readouterr())


def test_experimental_iso_candidate_pins_measured_size_without_forging_signature():
    repo = Path(__file__).resolve().parents[2]
    candidate = json.loads(
        (repo / "auto_tests/fixtures/q4os_6_10_r2_unsigned_catalog_candidate.json").read_text(
            encoding="utf-8"
        )
    )
    assert candidate["artifactType"] == "UNSIGNED_EXPERIMENTAL_CATALOG_CANDIDATE"
    assert candidate["candidateOnly"] is True
    assert candidate["productionEligible"] is False
    assert candidate["signed"] is False
    assert candidate["stable"] is False
    assert candidate["iso"]["sha256"] == readiness.UPSTREAM_SHA256
    assert candidate["iso"]["sizeBytes"] == 1851392000
    assert candidate["iso"]["publisherSignatureValidated"] is False
    assert candidate["iso"]["publisherKeyFingerprint"] is None
    assert candidate["iso"]["detachedSignatureFile"] is None
    assert candidate["catalogCompatibleFields"]["isoInstallerSizeBytes"] == 1851392000
    assert candidate["catalogCompatibleFields"]["isoInstallerSha256"] == readiness.UPSTREAM_SHA256
    assert candidate["trust"]["catalogPromotionAllowed"] is False
    assert candidate["trust"]["publisherSignedRelease"] is False
    assert candidate["trust"]["authenticatedGasluxCatalog"] is False
    catalog = json.loads((repo / "release-config.json").read_text(encoding="utf-8"))
    assert "q4os" not in {item["id"] for item in catalog["distributions"]}
