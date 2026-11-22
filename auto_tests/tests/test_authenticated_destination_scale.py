"""Bounded 128-GiB sparse host metadata inspection: explicitly DENY_NO_WRITER.

Only disposable private regular files are created. A 128-GiB RAW is sparse
(truncate, no bulk fill); no Windows, guest, boot, disk or full RAW hash.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from auto_tests.installer_observer import authenticated_destination as dest

GiB = 1024**3


@pytest.fixture
def sparse_128g(tmp_path):
    workspace = tmp_path.resolve(strict=True)
    workspace.chmod(0o700)
    raw = workspace / "backing.raw"
    qcow2 = workspace / "destination.qcow2"
    with raw.open("wb") as stream:
        stream.truncate(128 * GiB)  # Sparse inode; NOT 128 GiB allocated.
    assert shutil.which("qemu-img"), "real qemu-img required"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", str(raw), str(qcow2)],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert raw.stat().st_size == 128 * GiB
    assert qcow2.stat().st_size < dest.MAX_BYTES
    return workspace, qcow2, raw


@contextmanager
def pinned_pair(overlay: Path, backing: Path):
    with overlay.open("rb") as ov, backing.open("rb") as raw:
        yield ov.fileno(), raw.fileno()


def probe(sample):
    ws, overlay, raw = sample
    with pinned_pair(overlay, raw) as (qcow_fd, raw_fd):
        return dest.probe_destination_scale_metadata(
            qcow2_fd=qcow_fd,
            qcow2_path=overlay,
            backing_fd=raw_fd,
            backing_path=raw,
            workspace=ws,
        )


def test_a_posix_path_valid_only_for_metadata_probe(sparse_128g):
    result = probe(sparse_128g)
    assert type(sparse_128g[1]) is type(Path())
    assert result["virtualSizeBytes"] == 128 * GiB
    assert result["authorization"] == "DENY_NO_WRITER"


def test_b_foreign_overlay_fd_really_reaches_identity_gate(sparse_128g):
    ws, overlay, raw = sparse_128g
    foreign = ws / "foreign.qcow2"
    shutil.copyfile(overlay, foreign)
    with (
        pinned_pair(foreign, raw) as (ov, back),
        pytest.raises(dest.DestinationRefused, match="FD_ALIAS_OR_WRITABLE_FILE"),
    ):
        dest.probe_destination_scale_metadata(
            qcow2_fd=ov,
            qcow2_path=overlay,
            backing_fd=back,
            backing_path=raw,
            workspace=ws,
        )


def test_c_backing_fd_alias_really_reaches_identity_gate(sparse_128g):
    ws, overlay, raw = sparse_128g
    foreign = ws / "foreign.raw"
    with foreign.open("wb") as stream:
        stream.truncate(128 * GiB)
    with (
        pinned_pair(overlay, foreign) as (ov, back),
        pytest.raises(dest.DestinationRefused, match="FD_ALIAS_OR_WRITABLE_FILE"),
    ):
        dest.probe_destination_scale_metadata(
            qcow2_fd=ov,
            qcow2_path=overlay,
            backing_fd=back,
            backing_path=raw,
            workspace=ws,
        )


def test_e_large_virtual_size_stays_metadata_only_with_32_bytes_read(sparse_128g):
    result = probe(sparse_128g)
    assert result["virtualSizeBytes"] > dest.MAX_BYTES
    assert result["backingFileSizeBytes"] == 128 * GiB
    assert result["qcow2HeaderBytesRead"] == 32
    assert result["fullHashBytesRequired"] > 128 * GiB
    assert result["fullHashBudgetPerFileBytes"] == 512 * 1024**2
    assert result["fullSha256Performed"] is False
    assert result["qcow2BackingChainAuthenticated"] is False
    assert result["guestEffectiveGptProven"] is False


def test_f_sparse_allocation_distinct_from_logical_size(sparse_128g):
    result = probe(sparse_128g)
    assert result["backingIsSparse"] is True
    assert result["backingAllocatedBytes"] < result["backingFileSizeBytes"]
    assert result["qcow2AllocatedBytes"] <= dest.MAX_BYTES
    assert result["fullCheckpointReserveMinimumBytes"] == 128 * GiB
    assert result["checkpointReserveProven"] is False


def test_g_insufficient_resources_fail_closed_without_reservation(sparse_128g, monkeypatch):
    monkeypatch.setattr(
        dest.os,
        "statvfs",
        lambda path: SimpleNamespace(f_frsize=4096, f_bavail=0),
    )
    result = probe(sparse_128g)
    assert result["status"] == "READONLY_SCALE_CAPACITY_INSUFFICIENT"
    assert result["reasonCode"] == "INSUFFICIENT_CHECKPOINT_SPACE"
    assert result["checkpointCapacityEstimateSufficient"] is False
    assert result["checkpointReserveProven"] is False
    assert result["productionStorageWritesAuthorized"] is False


def test_g_physical_allocation_budget_blocks_before_header_read(sparse_128g, monkeypatch):
    monkeypatch.setattr(dest, "_allocated_bytes", lambda st: dest.MAX_BYTES)
    with pytest.raises(dest.DestinationRefused, match="SCALE_PHYSICAL_BUDGET_EXCEEDED"):
        probe(sparse_128g)


def test_h_short_digest_read_is_refused_even_when_nonempty(tmp_path, monkeypatch):
    path = tmp_path / "small.bin"
    path.write_bytes(b"A" * 256)
    monkeypatch.setattr(dest.os, "pread", lambda fd, size, offset: b"A")
    with (
        path.open("rb") as stream,
        pytest.raises(dest.DestinationRefused, match="FD_SHORT_READ"),
    ):
        dest._digest(stream.fileno(), hashlib.sha256(b"A" * 256).hexdigest())


def test_h_short_header_read_is_refused(sparse_128g, monkeypatch):
    original = dest.os.pread

    def short_header(fd, size, offset):
        payload = original(fd, size, offset)
        return payload[:-1] if size == dest.QCOW2_HEADER_READ_BYTES else payload

    monkeypatch.setattr(dest.os, "pread", short_header)
    with pytest.raises(dest.DestinationRefused, match="SCALE_HEADER_SHORT_READ"):
        probe(sparse_128g)


def test_i_backing_path_swap_is_refused(sparse_128g):
    ws, overlay, raw = sparse_128g
    with pinned_pair(overlay, raw) as (ov, back):
        parked = ws / "original.raw"
        replacement = ws / "replacement.raw"
        with replacement.open("wb") as stream:
            stream.truncate(128 * GiB)
        raw.rename(parked)
        replacement.rename(raw)
        with pytest.raises(dest.DestinationRefused, match="FD_ALIAS_OR_WRITABLE_FILE"):
            dest.probe_destination_scale_metadata(
                qcow2_fd=ov,
                qcow2_path=overlay,
                backing_fd=back,
                backing_path=raw,
                workspace=ws,
            )


def test_j_no_writer_even_with_capacity_available(sparse_128g, monkeypatch):
    monkeypatch.setattr(
        dest.os,
        "statvfs",
        lambda path: SimpleNamespace(f_frsize=4096, f_bavail=2**29),
    )
    result = probe(sparse_128g)
    assert result["status"] == "READONLY_SCALE_METADATA_ONLY"
    assert result["checkpointCapacityEstimateSufficient"] is True
    assert result["checkpointReserveProven"] is False
    for key in (
        "productionStorageWritesAuthorized",
        "guestCommandChannelAuthorized",
        "rollbackProven",
        "sameDiskDualBootVerified",
        "stable",
        "windowsRollbackProven",
    ):
        assert result[key] is False


def test_symlink_backing_and_writable_fd_refused(sparse_128g):
    ws, overlay, raw = sparse_128g
    alias = ws / "alias.raw"
    alias.symlink_to(raw)
    with (
        pinned_pair(overlay, raw) as (ov, back),
        pytest.raises(dest.DestinationRefused, match="UNOWNED_PATH"),
    ):
        dest.probe_destination_scale_metadata(
            qcow2_fd=ov,
            qcow2_path=overlay,
            backing_fd=back,
            backing_path=alias,
            workspace=ws,
        )
    with (
        overlay.open("rb") as ov, raw.open("r+b") as back,
        pytest.raises(dest.DestinationRefused, match="FD_ALIAS_OR_WRITABLE_FILE"),
    ):
        dest.probe_destination_scale_metadata(
            qcow2_fd=ov.fileno(),
            qcow2_path=overlay,
            backing_fd=back.fileno(),
            backing_path=raw,
            workspace=ws,
        )
