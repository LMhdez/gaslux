"""Read-only Bazzite ISO signature contract: synthetic media, no installed guest."""

import hashlib
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "assets/live"))

from gaslux_bazzite_iso_signature import verify_bazzite_iso_blob  # noqa: E402
from gaslux_lab_media_probe import ProbeRefusal  # noqa: E402


@pytest.fixture
def sample(tmp_path):
    data = bytearray(40 * 2048)
    data[16 * 2048 : 16 * 2048 + 7] = b"\x01CD001\x01"
    data[17 * 2048 : 17 * 2048 + 7] = b"\xffCD001\x01"
    iso = tmp_path / "bazzite-stable-live-amd64.iso"
    iso.write_bytes(data)
    sig = tmp_path / (iso.name + ".sig")
    sig.write_text("synthetic-not-signed", encoding="ascii")
    key = tmp_path / "cosign.pub"
    key.write_text("synthetic-key", encoding="ascii")
    return {
        "iso_path": iso,
        "signature_path": sig,
        "public_key_path": key,
        "trusted_key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
        "expected_iso_sha256": hashlib.sha256(data).hexdigest(),
        "expected_iso_size": len(data),
        "firmware": "uefi",
        "partition_style": "gpt",
        "secure_boot_enabled": False,
        "cosign_binary": "/bin/true",
    }


def _fake_success():
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="Verified OK", stderr="")


def test_synthetic_positive_is_never_install_authorization(sample):
    with patch("gaslux_bazzite_iso_signature.subprocess.run", return_value=_fake_success()) as run:
        evidence = verify_bazzite_iso_blob(**sample)
    assert evidence["detachedSignatureVerified"] is True
    assert evidence["installationAuthorized"] is False
    assert evidence["nativeInstallationVerified"] is False
    assert evidence["installerIdentityVerified"] is False
    assert evidence["transparencyAttestationVerified"] is False
    command = run.call_args.args[0]
    assert command[:2] == ["/bin/true", "verify-blob"]
    assert str(sample["iso_path"]) == command[-1]


@pytest.mark.parametrize(
    "change",
    [
        {"firmware": "bios", "partition_style": "mbr"},
        {"firmware": "bios", "partition_style": "gpt"},
        {"firmware": "uefi", "partition_style": "mbr"},
        {"secure_boot_enabled": True},
        {"secure_boot_enabled": None},
        {"trusted_key_sha256": "0" * 64},
        {"expected_iso_sha256": "f" * 64},
        {"expected_iso_size": 0},
        {"cosign_binary": "/does/not/exist/cosign"},
    ],
)
def test_fail_closed_negative_cases(sample, change):
    sample.update(change)
    with patch("gaslux_bazzite_iso_signature.subprocess.run") as run:
        with pytest.raises(ProbeRefusal):
            verify_bazzite_iso_blob(**sample)
        run.assert_not_called()


def test_bios_rejected_even_without_media(sample):
    sample["firmware"] = "bios"
    sample["partition_style"] = "mbr"
    sample["iso_path"].unlink()
    sample["signature_path"].unlink()
    with pytest.raises(ProbeRefusal, match="UEFI/GPT"):
        verify_bazzite_iso_blob(**sample)


def test_unsigned_iso_refused(sample):
    sample["signature_path"].unlink()
    with pytest.raises(ProbeRefusal, match="Trust material"):
        verify_bazzite_iso_blob(**sample)


def test_signature_filename_must_bind_iso(sample):
    sample["signature_path"] = sample["public_key_path"]
    with pytest.raises(ProbeRefusal, match="Signature"):
        verify_bazzite_iso_blob(**sample)


def test_signature_symlink_refused(sample):
    original = sample["signature_path"]
    original.unlink()
    original.symlink_to(sample["public_key_path"])
    with pytest.raises(ProbeRefusal, match="Trust material"):
        verify_bazzite_iso_blob(**sample)


def test_cosign_failure_refused(sample):
    bad = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="bad signature")
    with patch("gaslux_bazzite_iso_signature.subprocess.run", return_value=bad):
        with pytest.raises(ProbeRefusal, match="signature is invalid"):
            verify_bazzite_iso_blob(**sample)


def test_cosign_timeout_refused(sample):
    with patch(
        "gaslux_bazzite_iso_signature.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="cosign", timeout=1),
    ):
        with pytest.raises(ProbeRefusal, match="could not complete"):
            verify_bazzite_iso_blob(**sample)


def test_iso_change_during_cosign_is_refused(sample):
    def replace_iso(*args, **kwargs):
        with sample["iso_path"].open("r+b") as stream:
            stream.seek(35 * 2048)
            stream.write(b"MODIFIED")
        return _fake_success()

    with patch("gaslux_bazzite_iso_signature.subprocess.run", side_effect=replace_iso):
        with pytest.raises(ProbeRefusal, match="SHA-256"):
            verify_bazzite_iso_blob(**sample)


def test_oci_registry_digest_not_an_iso_filename(sample):
    sample["iso_path"] = sample["iso_path"].with_name("ghcr.io_ublue-os_bazzite_stable.iso")
    with pytest.raises(ProbeRefusal, match="filename"):
        verify_bazzite_iso_blob(**sample)
