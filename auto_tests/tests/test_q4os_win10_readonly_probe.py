"""Synthetic adversarial tests for the read-only genuine-Windows QEMU probe.

No genuine Windows disk, firmware, installation or network is used here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SAFETY = os.environ.get("GASLUX_Q4OS_PINNED_SAFETY_SOURCE_DIR")
if SAFETY is None or not Path(SAFETY).is_dir():
    pytest.fail("Real pinned Safety #267 sources are required for probe contracts")
sys.path.insert(0, SAFETY)
sys.path.insert(0, str(ROOT / "assets/live"))
sys.path.insert(0, str(ROOT / "auto_tests/tests"))

from gaslux_q4os_win10_readonly_probe import (  # noqa: E402
    _private_regular,
    _read_only_appliance,
    _real_safety_denial,
    require,
    validate_qcow2_chain,
)
from libertix_disk_identity_gate import (  # noqa: E402
    DiskIdentityError,
    assert_snapshot_matches,
    inspect_gpt_image,
)
from test_q4os_windows_boundary import (  # noqa: E402
    PARTS,
    SECTORS,
    make_image,
)


def _read_from_genuine_shape(monkeypatch, synthetic_source, *, extra_disks=False):
    """Simulate transport only; exercises actual pinned Safety GPT reader."""
    import gaslux_q4os_win10_readonly_probe as probe

    monkeypatch.setattr(probe, "SIZE", SECTORS * 512)
    calls = []

    class FakeGuest:
        def __init__(self, **kw):
            assert kw["python_return_dict"] is True

        def add_drive_opts(self, path, **kw):
            calls.append((str(path), kw))
            assert kw == {"format": "qcow2", "readonly": 1}

        def launch(self):
            return None

        def list_devices(self):
            return ["/dev/diagnostic"] + (["/dev/foreign"] if extra_disks else [])

        def blockdev_getsize64(self, device):
            return SECTORS * 512

        def blockdev_getss(self, device):
            return 512

        def pread_device(self, device, count, offset):
            with synthetic_source.open("rb") as source:
                source.seek(offset)
                return source.read(count)

        def shutdown(self):
            return None

        def close(self):
            return None

    monkeypatch.setitem(sys.modules, "guestfs", SimpleNamespace(GuestFS=FakeGuest))
    return calls


def test_two_gpt_observations_reconcile_with_actual_safety_reader(tmp_path, monkeypatch):
    source = tmp_path / "synthetic.raw"
    make_image(source)
    calls = _read_from_genuine_shape(monkeypatch, source)
    observation = _read_only_appliance(source, tmp_path, 512)
    host = inspect_gpt_image(source, logical_sector_size=512)
    guest = {key: observation[key] for key in host}
    assert_snapshot_matches(host, guest)
    assert len(calls) == 1
    assert calls[0][1]["readonly"] == 1
    assert observation["transportAuthenticatedToWindowsHost"] is False


@pytest.mark.parametrize("tamper", ["disk-guid", "part-guid", "part-offset", "part-length"])
def test_actual_safety_refuses_equivalent_size_foreign_gpt(tmp_path, monkeypatch, tamper):
    source = tmp_path / "synthetic-host.raw"
    foreign = tmp_path / "synthetic-foreign.raw"
    make_image(source)
    parts = list(PARTS)
    if tamper == "disk-guid":
        # The synthetic guest itself changes the source disk GUID, not a real disk.
        make_image(foreign)
        with foreign.open("r+b") as writer:
            writer.seek(512 + 56)
            writer.write(b"DIFFERENT-GUID-12")
        # CRC rejection is also a valid refusal, before identity equality.
        from libertix_disk_identity_gate import inspect_gpt_image

        with pytest.raises(DiskIdentityError):
            inspect_gpt_image(foreign, logical_sector_size=512)
        return
    kind, guid, first, last, name = parts[0]
    if tamper == "part-guid":
        parts[0] = kind, "11111111-2222-3333-4444-555555555555", first, last, name
    elif tamper == "part-offset":
        parts[0] = kind, guid, first + 1, last, name
    else:
        parts[0] = kind, guid, first, last - 1, name
    make_image(foreign, parts)
    _read_from_genuine_shape(monkeypatch, foreign)
    observation = _read_only_appliance(foreign, tmp_path, 512)
    host = inspect_gpt_image(source, logical_sector_size=512)
    with pytest.raises(DiskIdentityError):
        assert_snapshot_matches(host, {key: observation[key] for key in host})


def test_guest_probe_requires_only_one_attached_disk(tmp_path, monkeypatch):
    source = tmp_path / "synthetic.raw"
    make_image(source)
    _read_from_genuine_shape(monkeypatch, source, extra_disks=True)
    with pytest.raises(ValueError, match="exactly one"):
        _read_only_appliance(source, tmp_path, 512)


def test_no_authenticated_safety_evidence_means_denied(tmp_path):
    source = tmp_path / "synthetic.raw"
    make_image(source)
    host = inspect_gpt_image(source, logical_sector_size=512)
    result = _real_safety_denial(host)
    assert result["decision"] == "DENY_UNAUTHENTICATED"
    assert result["hostGuestTransactionAuthenticated"] is False


def test_foreign_or_hardlinked_private_input_rejected(tmp_path):
    source = tmp_path / "synthetic.raw"
    make_image(source)
    link = tmp_path / "alias"
    os.link(source, link)
    with pytest.raises(ValueError, match="Nonexclusive|nonexclusive"):
        _private_regular(source)
    link.unlink()
    source.unlink()
    source.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="unsafe image"):
        _private_regular(source)


def test_unowned_extra_efi_write_cannot_be_accepted():
    with pytest.raises(ValueError, match="unowned"):
        require(False, "unowned GPT/ESP writer")


def test_no_secret_or_writer_exposed_in_safety_denial(tmp_path):
    source = tmp_path / "synthetic.raw"
    make_image(source)
    result = _real_safety_denial(inspect_gpt_image(source, logical_sector_size=512))
    assert set(result) == {"decision", "reason", "hostGuestTransactionAuthenticated"}
    assert "secret" not in str(result).lower()
    assert "ACCEPT_NO_WRITER" not in str(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("backing-filename", "foreign.qcow2"),
        ("full-backing-filename", "/foreign.qcow2"),
        ("data-file", "/foreign-data-file.raw"),
        ("virtual-size", 64 * 1024**3),
        ("encrypted", True),
        ("snapshots", [{"name": "unexpected"}]),
    ],
)
def test_qcow2_foreign_chain_or_geometry_refused(field, value):
    source = {"format": "qcow2", "virtual-size": 48 * 1024**3}
    validate_qcow2_chain(source)
    source[field] = value
    with pytest.raises(ValueError, match="unexpected QCOW2"):
        validate_qcow2_chain(source)
