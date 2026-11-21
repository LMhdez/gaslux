"""Synthetic GPT adversarial contracts for the real read-only producer.

These fixtures are generated regular files; they do not prove VM collection.
Actual QEMU/guestfs runs must remain separate and are labelled laboratory-only.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import os
import shutil
import struct
import sys
import uuid
import zlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from auto_tests.installer_observer.gpt_readonly_producer import (
    GptProducerRefused,
    GuestSliceProof,
    build_safety_v1,
    capture_gpt,
)

SAFETY = Path(__file__).resolve().parents[2] / "safety-pinned"
if (SAFETY / "assets/live/libertix_disk_identity_gate.py").is_file():
    sys.path.insert(0, str(SAFETY / "assets/live"))
    sys.path.insert(0, str(SAFETY / "auto_tests/tests"))
else:
    pytest.skip("Pinned Safety source checkout unavailable", allow_module_level=True)

disk = importlib.import_module("libertix_disk_identity_gate")
from test_disk_identity_gate import make_image  # noqa: E402

SCHEMA = SAFETY / "schemas/safety-gpt-provenance-v1.schema.json"


@pytest.fixture
def sample(tmp_path):
    tmp_path.chmod(0o700)
    raw = tmp_path / "test.raw"
    make_image(raw)
    return raw, tmp_path


def take(sample, source="host", *, guest=False, size=512):
    path, folder = sample
    proof = None
    if guest:
        # Synthetic test fixture only; not a claim of a real QEMU guest.
        data = path.read_bytes()
        path = folder / "guest-reconstructed.raw"
        path.write_bytes(data)
        proof = GuestSliceProof(
            data[: 34 * 512], data[-34 * 512 :], "gasluxabcdefabcdef", 1234, 5678
        )
    return capture_gpt(
        path,
        folder,
        source=source,
        guest_sample_origin=proof,
        logical_sector_size=size,
        safety_disk=disk,
    )


def refused(expected, fn):
    with pytest.raises((GptProducerRefused, disk.DiskIdentityError)) as caught:
        fn()
    if isinstance(caught.value, GptProducerRefused):
        assert caught.value.code == expected


def test_actual_sector_hashes_and_crc_are_not_fixture_claims(sample):
    measurement = take(sample)
    assert measurement.source == "host"
    assert measurement.gpt["partitionStyle"] == "GPT"
    assert measurement.gpt["partitions"][0]["partGuid"]
    assert measurement.trace["fileSizeBytes"] == sample[0].stat().st_size
    for name, record in measurement.trace["samples"].items():
        data = base64.b64decode(measurement.trace["sampleBytesBase64"][name], validate=True)
        assert len(data) == record["lengthBytes"]
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        with sample[0].open("rb") as handle:
            handle.seek(record["offsetBytes"])
            assert handle.read(record["lengthBytes"]) == data
    assert measurement.sectors["primaryArrayCrc32"] == measurement.sectors["backupArrayCrc32"]


@pytest.mark.parametrize("corrupt", ("primary", "secondary", "array"))
def test_real_crc_corruption_refused(sample, corrupt):
    path, _ = sample
    with path.open("r+b") as output:
        offset = {
            "primary": 512 + 56,
            "secondary": path.stat().st_size - 512 + 56,
            "array": 1024 + 32,
        }[corrupt]
        output.seek(offset)
        value = output.read(1)
        output.seek(offset)
        output.write(bytes([value[0] ^ 1]))
    refused("GPT_SECTOR_INVALID", lambda: take(sample))


def test_wrong_sector_size_fails(sample):
    refused("GPT_SECTOR_INVALID", lambda: take(sample, size=4096))


def test_guest_source_requires_real_sample_origin(sample):
    refused("GUEST_ORIGIN_MISSING", lambda: take(sample, source="guest"))


def test_false_guest_read_bytes_are_rejected(sample):
    path, folder = sample
    data = path.read_bytes()
    target = folder / "guest-reconstructed.raw"
    target.write_bytes(data)
    invalid = GuestSliceProof(bytes(34 * 512), data[-34 * 512 :], "gasluxabcdefabcdef", 1234, 5678)
    refused(
        "GUEST_SLICE_BYTES_MISMATCH",
        lambda: capture_gpt(
            target,
            folder,
            source="guest",
            logical_sector_size=512,
            safety_disk=disk,
            guest_sample_origin=invalid,
        ),
    )


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "replacement"))
def test_link_and_replacement_refused(sample, kind):
    path, folder = sample
    if kind == "symlink":
        other = folder / "original.raw"
        path.rename(other)
        path.symlink_to(other)
    elif kind == "hardlink":
        os.link(path, folder / "duplicate.raw")
    else:
        other = folder / "fresh.raw"
        make_image(other)
        path.unlink()
        path.symlink_to(other)
    refused("DISK_FILE_UNSAFE", lambda: take(sample))


def test_foreign_location_refused(sample, tmp_path_factory):
    path, _ = sample
    other = tmp_path_factory.mktemp("foreign")
    refused(
        "DISK_PATH_UNOWNED",
        lambda: capture_gpt(path, other, source="host", logical_sector_size=512, safety_disk=disk),
    )


def test_replaced_while_reading_refused(sample):
    path, folder = sample

    class TamperingParser:
        inspect_gpt_image = staticmethod(disk.inspect_gpt_image)
        read_header = staticmethod(disk.read_header)
        count = 0

        @staticmethod
        def exact_read(fd, offset, length):
            TamperingParser.count += 1
            if TamperingParser.count == 1:
                new = folder / "fresh.raw"
                make_image(new)
                path.unlink()
                new.rename(path)
            return disk.exact_read(fd, offset, length)

    refused(
        "DISK_CHANGED_DURING_READ",
        lambda: capture_gpt(
            path, folder, source="host", logical_sector_size=512, safety_disk=TamperingParser
        ),
    )


def test_host_guest_immediate_comparison_refuses_changed_identity(sample):
    host = take(sample)
    guest = take(sample, source="guest", guest=True)
    immediate = take(sample, source="immediate")
    pins = SimpleNamespace(
        virtual_size_bytes=host.gpt["sizeBytes"],
        disk_id=host.gpt["partitionTableId"],
        transaction_id="11111111-1111-4111-8111-111111111111",
        vm_uuid="22222222-2222-4222-8222-222222222222",
        request_id="33333333-3333-4333-8333-333333333333",
        nonce="A" * 43,
        sequence=1,
        qemu_pid=1234,
        qemu_start_ticks=5678,
        virtual_serial="lab-only-device",
        controller_id="lab-only-controller",
        collector_id="lab-only-collector",
        observer_key_id="lab-only-key",
        overlay_sha256="a" * 64,
        backing_sha256="b" * 64,
        backing_filename=str(sample[0]),
    )
    authority = SimpleNamespace(
        issuer_id="lab-only-issuer",
        observer_id="lab-only-observer",
        collector_id=pins.collector_id,
        controller_id=pins.controller_id,
        policy_id="lab-only-policy",
        policy_sha256="f" * 64,
        signing_key_id=pins.observer_key_id,
        administrative_domain="same-runner",
        qemu_executable_sha256="c" * 64,
        device_id="guestfs-label:lab-only-device",
        overlay_path=str(sample[0]),
        overlay_device_id="dev:1",
        overlay_inode=100,
        parent_device_id="dev:1",
        parent_inode=101,
    )
    args = dict(
        pins=pins,
        authority=authority,
        logical_sector_size=512,
        schema_path=SCHEMA,
        expected_observer_result_sha256="e" * 64,
    )
    record = build_safety_v1((host, guest, immediate), **args)
    assert record["classification"] == "NOT_INDEPENDENT"
    assert record["writeAuthorized"] is False
    assert record["measurements"][1]["readMethod"] == "guest-virtio-readonly-sector"
    assert record["measurements"][1]["originProof"]["evidenceSha256"] == guest.trace_sha256
    refused(
        "GPT_THREE_WAY_MISMATCH",
        lambda: build_safety_v1(
            (
                host,
                replace(guest, gpt={**guest.gpt, "partitionTableId": "gpt:" + "0" * 36}),
                immediate,
            ),
            **args,
        ),
    )
    refused(
        "GPT_THREE_WAY_MISMATCH",
        lambda: build_safety_v1(
            (host, replace(guest, sectors={**guest.sectors, "backupArrayCrc32": 1}), immediate),
            **args,
        ),
    )
    refused("GUEST_MEASUREMENT_MISSING", lambda: build_safety_v1((host, host, immediate), **args))
    refused(
        "OBSERVER_RESULT_NOT_VERIFIED",
        lambda: build_safety_v1(
            (host, guest, immediate),
            **{**args, "expected_observer_result_sha256": ""},
        ),
    )
    refused(
        "GPT_PIN_MISMATCH",
        lambda: build_safety_v1(
            (host, guest, immediate),
            **{**args, "pins": SimpleNamespace(**{**vars(pins), "disk_id": "gpt:" + "0" * 36})},
        ),
    )


def test_immediate_reexports_overlay_after_source_gpt_changes(sample):
    """Synthetic exporter checks fresh source selection, not QEMU execution."""
    from auto_tests.installer_observer.gpt_lab_provenance import capture_fresh_immediate

    path, folder = sample
    source = folder / "overlay.qcow2"
    base = folder / "base.raw"
    historical = folder / "host.raw"
    for destination in (source, base, historical):
        shutil.copyfile(path, destination)
    host = capture_gpt(
        historical, folder, source="host", logical_sector_size=512, safety_disk=disk
    )
    guest = take(sample, source="guest", guest=True)

    # Mutate the current source AFTER host capture. Keep primary/backup GPT
    # CRCs valid so failure is caused by freshness, not invalid GPT input.
    changed = bytearray(source.read_bytes())
    guid = uuid.UUID("81d479d3-148e-49b7-908a-19427a32c644")
    for sector in (1, len(changed) // 512 - 1):
        at = sector * 512
        changed[at + 56 : at + 72] = guid.bytes_le
        changed[at + 16 : at + 20] = b"\x00" * 4
        changed[at + 16 : at + 20] = struct.pack(
            "<I", zlib.crc32(changed[at : at + 92])
        )
    source.write_bytes(changed)

    class FakeConverter:
        tamper_during_export = False
        exported_from = None

        @staticmethod
        def own_regular(path, folder):
            assert path.parent == folder
            return path.stat()

        @staticmethod
        def verify_chain(overlay, base, folder):
            return {
                "overlaySha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
                "backingSha256": hashlib.sha256(base.read_bytes()).hexdigest(),
            }

        def host_snapshot(self, overlay, destination, folder):
            self.exported_from = overlay
            shutil.copyfile(overlay, destination)
            if self.tamper_during_export:
                with overlay.open("r+b") as handle:
                    handle.seek(1000000)
                    handle.write(b"\x01")

    fake = FakeConverter()
    immediate = capture_fresh_immediate(
        workspace=folder,
        overlay=source,
        base=base,
        lab=fake,
        safety_disk=disk,
        host=host,
    )
    assert fake.exported_from == source
    assert immediate.trace["imageFile"] == str(folder / "immediate.raw")
    assert immediate.trace["fileInode"] != host.trace["fileInode"]
    assert immediate.gpt["partitionTableId"] != host.gpt["partitionTableId"]
    assert historical.read_bytes() == path.read_bytes()
    refused(
        "GPT_THREE_WAY_MISMATCH",
        lambda: build_safety_v1(
            (host, guest, immediate),
            pins=None,
            authority=None,
            logical_sector_size=512,
            schema_path=SCHEMA,
            expected_observer_result_sha256="e" * 64,
        ),
    )

    # If the overlay changes *during* the fresh export, fail closed.
    (folder / "immediate.raw").unlink()
    fake.tamper_during_export = True
    refused(
        "OBSERVATION_INCOMPLETE",
        lambda: capture_fresh_immediate(
            workspace=folder,
            overlay=source,
            base=base,
            lab=fake,
            safety_disk=disk,
            host=host,
        ),
    )


def test_immediate_missing_export_is_observation_incomplete(sample):
    from auto_tests.installer_observer.gpt_lab_provenance import capture_fresh_immediate

    path, folder = sample
    source = folder / "overlay.qcow2"
    base = folder / "base.raw"
    historical = folder / "host.raw"
    for destination in (source, base, historical):
        shutil.copyfile(path, destination)
    host = capture_gpt(
        historical, folder, source="host", logical_sector_size=512, safety_disk=disk
    )

    class MissingExport:
        @staticmethod
        def own_regular(path, folder):
            return path.stat()

        @staticmethod
        def verify_chain(overlay, base, folder):
            return {
                "overlaySha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
                "backingSha256": hashlib.sha256(base.read_bytes()).hexdigest(),
            }

        @staticmethod
        def host_snapshot(overlay, destination, folder):
            return None

    refused(
        "OBSERVATION_INCOMPLETE",
        lambda: capture_fresh_immediate(
            workspace=folder,
            overlay=source,
            base=base,
            lab=MissingExport(),
            safety_disk=disk,
            host=host,
        ),
    )
