"""Bounded disposable QEMU COW write contract: negative tests and recovery gates."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets" / "live"))
sys.path.insert(0, str(ROOT / "auto_tests" / "tools"))

from gaslux_q4os_bounded_cow_write_lab import (  # noqa: E402
    EMPTY_SHA,
    MARKER_SHA,
    WRITE_BYTES,
    WRITE_OFFSET,
    BoundVmWriteRefusal,
    validate_overlay_allocation,
    validate_writable_preflight,
    validate_write_result,
)
from gaslux_q4os_guest_disk_probe import expected_virtio_serial  # noqa: E402

RUN = "q4os-actions-1234567890"
NONCE = "1" * 32


@pytest.fixture
def pair():
    plan = {
        "runId": RUN,
        "nonce": NONCE,
        "diskGuid": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
        "espGuid": "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
        "espStartLba": 2048,
        "espEndLba": 1050623,
        "espName": "GASLUX-LAB-ESP",
        "diskSizeBytes": 32 * 1024**3,
        "sectorBytes": 512,
    }
    serial = expected_virtio_serial(plan)
    esp = {
        "number": 1,
        "startLba": plan["espStartLba"],
        "endLba": plan["espEndLba"],
        "partGuid": plan["espGuid"],
        "typeGuid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "label": plan["espName"],
        "filesystem": "vfat",
    }
    preflight = {
        "schemaVersion": 1,
        "runId": RUN,
        "nonce": NONCE,
        "device": "/dev/vda",
        "serial": serial,
        "sizeBytes": plan["diskSizeBytes"],
        "logicalSectorBytes": 512,
        "physicalSectorBytes": 512,
        "diskGuid": plan["diskGuid"],
        "partitions": [esp],
        "blockDeviceReadOnly": False,
        "readOnlyProbe": True,
        "writeAttempted": False,
        "writeOffsetBytes": WRITE_OFFSET,
        "writeLengthBytes": WRITE_BYTES,
        "markerBeforeSha256": EMPTY_SHA,
    }
    outcome = {
        "schemaVersion": 1,
        "runId": RUN,
        "nonce": NONCE,
        "serial": serial,
        "diskGuid": plan["diskGuid"],
        "writeAttempted": True,
        "writeCompleted": True,
        "writeOffsetBytes": WRITE_OFFSET,
        "writeLengthBytes": WRITE_BYTES,
        "markerAfterSha256": MARKER_SHA,
        "gptUnchanged": True,
        "calamaresExecuted": False,
        "windowsEspTouched": False,
    }
    return plan, serial, preflight, outcome


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_guest_prewrite_identity_is_verified_before_any_write(pair):
    plan, serial, preflight, _ = pair
    result = validate_writable_preflight(encoded(preflight), plan=plan, serial=serial)
    assert result["gptVerified"] is True
    assert result["device"] == "/dev/vda"
    assert (plan["espEndLba"] + 1) * 512 < WRITE_OFFSET


@pytest.mark.parametrize(
    "field,value",
    [
        ("runId", "other-actions-123456"),
        ("nonce", "f" * 32),
        ("device", "/dev/sda"),
        ("serial", "OTHER-SERIAL"),
        ("diskGuid", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("blockDeviceReadOnly", True),
        ("readOnlyProbe", False),
        ("writeAttempted", True),
        ("writeOffsetBytes", 0),
        ("writeOffsetBytes", True),
        ("writeLengthBytes", 8192),
        ("markerBeforeSha256", "e" * 64),
        ("sizeBytes", 16 * 1024**3),
        ("logicalSectorBytes", 4096),
    ],
)
def test_prewrite_refuses_foreign_identity_or_unapproved_extent(pair, field, value):
    plan, serial, preflight, _ = pair
    with pytest.raises((BoundVmWriteRefusal, ValueError)):
        validate_writable_preflight(encoded({**preflight, field: value}), plan=plan, serial=serial)


def test_prewrite_rejects_extra_partitions_and_json_duplicate_keys(pair):
    plan, serial, preflight, _ = pair
    extra = dict(preflight)
    extra["partitions"] = preflight["partitions"] * 2
    with pytest.raises(ValueError):
        validate_writable_preflight(encoded(extra), plan=plan, serial=serial)
    duplicate = encoded(preflight)[:-1] + b',"nonce":"' + NONCE.encode() + b'"}'
    with pytest.raises(BoundVmWriteRefusal, match="Duplicate"):
        validate_writable_preflight(duplicate, plan=plan, serial=serial)


def test_result_proves_exact_one_write_and_immutable_gpt(pair):
    plan, serial, _, outcome = pair
    result = validate_write_result(encoded(outcome), plan=plan, serial=serial)
    assert result["writeLengthBytes"] == 4096
    assert result["writeCompleted"] is True
    assert hashlib.sha256(b"\xa5" * 4096).hexdigest() == MARKER_SHA


@pytest.mark.parametrize(
    "field,value",
    [
        ("runId", "replayed-run-12345"),
        ("nonce", "f" * 32),
        ("serial", "fake"),
        ("diskGuid", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("writeCompleted", False),
        ("writeOffsetBytes", WRITE_OFFSET + 512),
        ("writeLengthBytes", True),
        ("markerAfterSha256", "e" * 64),
        ("gptUnchanged", False),
        ("calamaresExecuted", True),
        ("windowsEspTouched", True),
    ],
)
def test_guest_postwrite_refuses_any_untrusted_semantics(pair, field, value):
    plan, serial, _, outcome = pair
    with pytest.raises(BoundVmWriteRefusal):
        validate_write_result(encoded({**outcome, field: value}), plan=plan, serial=serial)


def test_cow_map_must_show_real_allocation_only_inside_free_root():
    block = {"start": (WRITE_OFFSET // 65536) * 65536, "length": 65536, "depth": 0, "data": True}
    assert validate_overlay_allocation([block]) == [
        {"start": block["start"], "length": block["length"]}
    ]
    with pytest.raises(BoundVmWriteRefusal):
        validate_overlay_allocation([dict(block, start=0)])
    with pytest.raises(BoundVmWriteRefusal):
        validate_overlay_allocation([dict(block, start=67108800 * 512)])
    with pytest.raises(BoundVmWriteRefusal):
        validate_overlay_allocation([dict(block, depth=1)])
    with pytest.raises(BoundVmWriteRefusal):
        validate_overlay_allocation([dict(block, start=True)])


def test_guest_write_agent_never_formats_partitions_or_calls_calamares():
    guest = (ROOT / "auto_tests" / "tools" / "q4os_guest_bound_write_agent.py").read_text(
        encoding="utf-8"
    )
    assert "os.pwrite(handle, PATTERN, WRITE_OFFSET)" in guest
    assert "os.fsync(handle)" in guest
    assert "inspect_gpt_fd" in guest
    assert "Host did not authorize marker" in guest
    assert "Untrusted non-VirtIO device" in guest
    assert "qemu-img" not in guest
    assert "sgdisk" not in guest
    assert "calamares" not in guest.lower().split("def main()")[1]


def test_host_write_is_disabled_without_explicit_runner_opt_in(monkeypatch, tmp_path):
    from gaslux_q4os_bounded_cow_write_lab import run_lab

    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.delenv("GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY", raising=False)
    with pytest.raises(BoundVmWriteRefusal, match="opt-in"):
        run_lab(*(tmp_path / str(i) for i in range(6)))


def test_old_read_only_initramfs_is_never_modified():
    old = (ROOT / "auto_tests/tools/gaslux_q4os_identity_initramfs.sh").read_text()
    new = (ROOT / "auto_tests/tools/gaslux_q4os_bounded_write_initramfs.sh").read_text()
    assert "exec /usr/bin/python3 /guest_probe.py" in old
    assert "GASLUX_Q4OS_SYNTHETIC_WRITE_LAB_ONLY" in new
    assert "exec /usr/bin/python3 /guest_write.py" in new
    assert "Guest agent not found" in new


def test_restore_checkpoint_does_not_claim_full_windows_rollback():
    src = (ROOT / "auto_tests/tools/gaslux_q4os_bounded_cow_write_lab.py").read_text()
    assert '"rollbackVerified": False' in src
    assert '"windowsDiskAttached": False' in src
    assert '"calamaresExecuted": False' in src
    assert '"guestAttestation": False' in src
    assert "qemu-img" in src
    assert "qemu-io" in src
    assert "sgdisk" in src
    assert '"syntheticWriteRecoveredVerified"' in src


def test_sigkill_fault_injection_requires_separate_explicit_opt_in():
    import inspect

    from gaslux_q4os_bounded_cow_write_lab import _authenticate_guest_write, run_lab

    host = inspect.getsource(_authenticate_guest_write)
    assert "if simulate_power_cut:" in host
    assert "POWER_CUT_READY" in host
    assert "process.poll() is None" in host
    assert "process.kill()" in host
    assert "process.returncode == -signal.SIGKILL" in host
    assert host.index("verified = validate_write_result") < host.index("process.kill()")
    lab = inspect.getsource(run_lab)
    assert "GASLUX_Q4OS_POWER_CUT_LAB_ONLY" in lab
    assert '"rollbackVerified": False' in lab or '"rollbackVerified"' in lab


def test_normal_guest_shutdown_requires_authenticated_host_finish():
    import inspect

    from gaslux_q4os_bounded_cow_write_lab import _authenticate_guest_write
    from q4os_guest_bound_write_agent import run

    host = inspect.getsource(_authenticate_guest_write)
    guest = inspect.getsource(run)
    assert 'FINISH = b"GQ4OS-WRITE-FINISH-V1"' in host
    assert 'hmac.new(secret.encode("ascii"), AUTH_DOMAIN + FINISH' in host
    assert 'conn.sendall(FINISH + b":" + finish_mac' in host
    assert 'finish = _read_line(fd, 256).split(b":")' in guest
    assert "hmac.compare_digest(finish[1], finish_mac)" in guest


def test_sigkill_recovery_does_not_claim_host_power_loss_or_windows_rollback():
    import inspect

    from gaslux_q4os_bounded_cow_write_lab import run_lab

    source = inspect.getsource(run_lab)
    assert '"powerCutAfterFsync": simulate_power_cut' in source
    assert '"powerCutRecoveryInSyntheticLab": simulate_power_cut' in source
    assert '"rollbackVerified": False' in source
    assert '"windowsDiskAttached": False' in source
    assert '"calamaresExecuted": False' in source
    assert 'checkpoint_state["postPowerCutRecoveryVerified"] = simulate_power_cut' in source
