from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def load_helper():
    path = ROOT / "assets/live/gaslux_distribution_capabilities.py"
    spec = importlib.util.spec_from_file_location("gaslux_capability_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capability(backend, source, secure_boot, bios, uefi, status, layouts):
    return {
        "version": 1,
        "backend": backend,
        "source": source,
        "firmwareLayouts": layouts,
        "secureBoot": secure_boot,
        "bootloader": {"bios": bios, "uefi": uefi},
        "status": status,
        "minimumRamMiB": 8192,
        "minimumDiskGiB": 64,
    }


def test_mint_zorin_v2_capability_is_released_and_schema_valid():
    module = load_helper()
    schema = json.loads(
        (ROOT / "schemas/distribution-capabilities.schema.json").read_text(encoding="utf-8")
    )
    for distribution_id, os_release_id in [("mint", "linuxmint"), ("zorin", "zorin")]:
        cap = capability(
            "debian-squashfs",
            "casper-squashfs",
            "ms-shim",
            "grub",
            "grub",
            "released",
            ["bios/mbr", "uefi/gpt"],
        )
        Draft202012Validator(schema).validate(cap)
        assert module.validate_capabilities(distribution_id, os_release_id, cap)


@pytest.mark.parametrize(
    ("distribution_id", "os_release_id", "backend", "source", "secure_boot", "bios", "uefi"),
    [
        ("cachyos", "cachyos", "archiso-cachyos", "archiso", "unsupported", "grub", "grub"),
        ("popos", "pop", "system76", "pop-live", "unsupported", "grub", "systemd-boot"),
        ("q4os", "q4os", "q4os-native", "q4os-native-iso", "unsupported", "grub", "grub"),
        (
            "bazzite",
            "bazzite",
            "fedora-atomic",
            "fedora-atomic-iso",
            "manual-enrollment",
            "none",
            "grub",
        ),
    ],
)
def test_candidate_validates_but_cannot_be_released(
    distribution_id, os_release_id, backend, source, secure_boot, bios, uefi
):
    module = load_helper()
    cap = capability(backend, source, secure_boot, bios, uefi, "lab-only", ["uefi/gpt"])
    assert not module.validate_capabilities(distribution_id, os_release_id, cap)
    cap["status"] = "released"
    with pytest.raises(module.CapabilityError, match="experimental"):
        module.validate_capabilities(distribution_id, os_release_id, cap)


def test_bazzite_rejects_bios_mbr_and_wrong_storage():
    module = load_helper()
    cap = capability(
        "fedora-atomic",
        "fedora-atomic-iso",
        "manual-enrollment",
        "none",
        "grub",
        "lab-only",
        ["uefi/gpt"],
    )
    cap["firmwareLayouts"] = ["bios/mbr", "uefi/gpt"]
    with pytest.raises(module.CapabilityError, match="firmware"):
        module.validate_capabilities("bazzite", "bazzite", cap)
    cap["firmwareLayouts"] = ["uefi/gpt"]
    cap["minimumDiskGiB"] = 20
    with pytest.raises(module.CapabilityError, match="50"):
        module.validate_capabilities("bazzite", "bazzite", cap)


def test_signed_v1_catalog_is_not_changed_by_new_schema():
    # The historical detached signature must continue to verify the exact
    # v1 byte sequence. The signing key must not be regenerated.
    catalog = json.loads((ROOT / "auto_tests/app/filepool/catalog.json").read_text())
    assert catalog["schemaVersion"] == 1
    assert all("capabilities" not in d for d in catalog["distributions"])


def test_v2_release_schema_requires_capabilities_and_rejects_forged_upgrades():
    schema = json.loads((ROOT / "schemas/release-config.schema.json").read_text())
    cfg = json.loads((ROOT / "release-config.json").read_text())
    validator = Draft202012Validator(schema)
    assert validator.is_valid(cfg)
    v2 = copy.deepcopy(cfg)
    v2["schemaVersion"] = 2
    assert not validator.is_valid(v2)
    for d in v2["distributions"]:
        d["capabilities"] = capability(
            "debian-squashfs",
            "casper-squashfs",
            "ms-shim",
            "grub",
            "grub",
            "released",
            ["bios/mbr", "uefi/gpt"],
        )
    assert validator.is_valid(v2)
    v2["distributions"][0]["capabilities"]["extra"] = "untrusted"
    assert not validator.is_valid(v2)


def test_generator_v2_rejects_wrong_backend_identity(tmp_path):
    path = ROOT / "iso-tools/generate-release-metadata.py"
    spec = importlib.util.spec_from_file_location("gen_v2_test", path)
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    cfg = json.loads((ROOT / "release-config.json").read_text())
    cfg["schemaVersion"] = 2
    for d in cfg["distributions"]:
        d["capabilities"] = capability(
            "debian-squashfs",
            "casper-squashfs",
            "ms-shim",
            "grub",
            "grub",
            "released",
            ["bios/mbr", "uefi/gpt"],
        )
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    assert gen.load_config(config_path)["schemaVersion"] == 2
    cfg["distributions"][1]["capabilities"]["backend"] = "system76"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    with pytest.raises(ValueError, match="backend"):
        gen.load_config(config_path)


def test_v2_generator_excludes_unreleased_entries_from_main(tmp_path):
    path = ROOT / "iso-tools/generate-release-metadata.py"
    spec = importlib.util.spec_from_file_location("gen_v2_filter_test", path)
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    cfg = json.loads((ROOT / "release-config.json").read_text())
    cfg["schemaVersion"] = 2
    for d in cfg["distributions"]:
        d["capabilities"] = capability(
            "debian-squashfs",
            "casper-squashfs",
            "ms-shim",
            "grub",
            "grub",
            "released",
            ["bios/mbr", "uefi/gpt"],
        )
    cfg["distributions"][0]["capabilities"]["status"] = "lab-only"
    cfg_file = tmp_path / "v2-config.json"
    cfg_file.write_text(json.dumps(cfg), encoding="utf-8")
    signed_config = gen.load_config(cfg_file)

    artifacts = {
        name: tmp_path / name
        for name in (
            "libertix-installer-bios.iso",
            "libertix-installer-uefi.iso",
            "aria2-64.zip",
            "ext4-win-driver.exe",
            "grldr",
            "grldr.mbr",
        )
    }
    for name, path in artifacts.items():
        path.write_bytes(name.encode("utf-8"))
    main_zip = tmp_path / f"Libertix-{cfg['mainRelease']['version']}.zip"
    dev_zip = tmp_path / "Libertix-abcdef0.zip"
    main_zip.write_bytes(b"main")
    dev_zip.write_bytes(b"dev")
    kwargs = {
        "bios_iso": artifacts["libertix-installer-bios.iso"],
        "uefi_iso": artifacts["libertix-installer-uefi.iso"],
        "aria2_archive": artifacts["aria2-64.zip"],
        "ext4_driver": artifacts["ext4-win-driver.exe"],
        "grub4dos_loader": artifacts["grldr"],
        "grub4dos_mbr": artifacts["grldr.mbr"],
        "published_at": "2026-11-16T17:00:00Z",
    }
    main, _ = gen.generate_metadata(
        signed_config,
        channel="main",
        tag=cfg["mainRelease"]["version"],
        commit="abcdef0" + "0" * 33,
        wpf_zip=main_zip,
        **kwargs,
    )
    dev, _ = gen.generate_metadata(
        signed_config,
        channel="dev",
        tag="abcdef0",
        commit="abcdef0" + "0" * 33,
        wpf_zip=dev_zip,
        **kwargs,
    )
    assert main["schemaVersion"] == dev["schemaVersion"] == 2
    assert [d["id"] for d in main["distributions"]] == ["zorin"]
    assert [d["id"] for d in dev["distributions"]] == ["mint", "zorin"]
    assert all(d["capabilities"]["status"] == "released" for d in main["distributions"])

# Cross-language JSON type boundary: bool is a subclass of int in Python.
# C# and PowerShell deserialize version as an integer; do not grant a
# capability when Python sees JSON true in place of protocol version 1.
@pytest.mark.parametrize(
    (
        "distribution_id",
        "os_release_id",
        "backend",
        "source",
        "secure_boot",
        "bios",
        "uefi",
        "layouts",
    ),
    [
        (
            "mint",
            "linuxmint",
            "debian-squashfs",
            "casper-squashfs",
            "ms-shim",
            "grub",
            "grub",
            ["bios/mbr", "uefi/gpt"],
        ),
        (
            "zorin",
            "zorin",
            "debian-squashfs",
            "casper-squashfs",
            "ms-shim",
            "grub",
            "grub",
            ["bios/mbr", "uefi/gpt"],
        ),
        (
            "cachyos",
            "cachyos",
            "archiso-cachyos",
            "archiso",
            "unsupported",
            "grub",
            "grub",
            ["uefi/gpt"],
        ),
        (
            "popos",
            "pop",
            "system76",
            "pop-live",
            "unsupported",
            "grub",
            "systemd-boot",
            ["uefi/gpt"],
        ),
        (
            "q4os",
            "q4os",
            "q4os-native",
            "q4os-native-iso",
            "unsupported",
            "grub",
            "grub",
            ["uefi/gpt"],
        ),
        (
            "bazzite",
            "bazzite",
            "fedora-atomic",
            "fedora-atomic-iso",
            "manual-enrollment",
            "none",
            "grub",
            ["uefi/gpt"],
        ),
    ],
)
@pytest.mark.parametrize("bad_version", [True, False, 1.0, "1", None])
def test_capability_version_is_exact_integer_across_live_and_release_generator(
    distribution_id, os_release_id, backend, source, secure_boot, bios, uefi, layouts, bad_version
):
    live = load_helper()
    path = ROOT / "iso-tools/generate-release-metadata.py"
    spec = importlib.util.spec_from_file_location("gaslux_generator_version_type_test", path)
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    schema = json.loads(
        (ROOT / "schemas/distribution-capabilities.schema.json").read_text(encoding="utf-8")
    )
    status = "released" if distribution_id in {"mint", "zorin"} else "lab-only"
    cap = capability(backend, source, secure_boot, bios, uefi, status, layouts)
    Draft202012Validator(schema).validate(cap)
    assert live.validate_capabilities(distribution_id, os_release_id, cap) == (status == "released")
    generator.validate_distribution_capability(distribution_id, os_release_id, cap)
    cap["version"] = bad_version
    if type(bad_version) is bool:
        assert not Draft202012Validator(schema).is_valid(cap)
    with pytest.raises(live.CapabilityError, match="shape"):
        live.validate_capabilities(distribution_id, os_release_id, cap)
    with pytest.raises(ValueError, match="shape/version"):
        generator.validate_distribution_capability(distribution_id, os_release_id, cap)
