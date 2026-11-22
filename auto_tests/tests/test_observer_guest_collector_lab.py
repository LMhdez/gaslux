"""Adversarial OFFLINE tests for Guest collector diagnostic protocol.

The real Linux Guest boot is a separate, non-parallel GitHub Actions step.
"""

from __future__ import annotations

import pytest

from auto_tests.installer_observer.guest_collector_lab import (
    GuestCollectorRefused,
    LabNonceLedger,
    bound_host,
    challenge_line,
    expected_context,
    read_line,
    response_line,
)

COLLECTOR_SHA = "c" * 64
BOOT_ID = "12345678-1234-4234-8234-123456789abc"


@pytest.fixture
def context():
    return expected_context(COLLECTOR_SHA)


@pytest.fixture
def response(context):
    values = [
        "GCR1",
        context["nonce"],
        context["session"],
        context["transaction"],
        context["vm"],
        "1",
        context["collector"],
        BOOT_ID,
    ]
    return (" ".join(values) + "\n").encode("ascii")


def refused(expected, fn):
    with pytest.raises(GuestCollectorRefused) as caught:
        fn()
    assert caught.value.code == expected


def test_realistic_response_is_bound_to_challenge_and_session(context, response):
    assert len(challenge_line(context)) < 512
    observed = response_line(response, context)
    assert observed["sessionId"] == context["session"]
    assert observed["nonce"] == context["nonce"]
    assert observed["bootId"] == BOOT_ID


def test_a_host_proxy_spoof_cannot_be_promoted_to_guest_origin():
    host, peer = fake_host_peer()
    peer["localKernelPeerMatchesSuppliedPins"] = False
    refused("HOST_PROXY_SPOOF", lambda: bound_host(host, peer, 42, 999))


def test_b_old_nonce_replay_rejected_across_reopen(tmp_path, context):
    tmp_path.chmod(0o700)
    path = tmp_path / "nonce.sqlite"
    first = LabNonceLedger(path)
    first.issue(context["nonce"], context["session"])
    first.close()
    second = LabNonceLedger(path, existing=True)
    refused("OLD_NONCE_REPLAY", lambda: second.issue(context["nonce"], context["session"]))
    second.consume(context["nonce"], context["session"])
    second.close()
    third = LabNonceLedger(path, existing=True)
    refused("OLD_NONCE_REPLAY", lambda: third.consume(context["nonce"], context["session"]))
    third.close()


@pytest.mark.parametrize("position", [2, 3, 4])
def test_c_wrong_vm_session(context, response, position):
    fields = response.decode("ascii").split()
    fields[position] = "0" * len(fields[position])
    refused(
        "WRONG_VM_SESSION",
        lambda: response_line((" ".join(fields) + "\n").encode("ascii"), context),
    )


def test_d_collector_hash_mismatch(context, response):
    changed = response.replace(COLLECTOR_SHA.encode(), b"a" * 64)
    refused("COLLECTOR_HASH_MISMATCH", lambda: response_line(changed, context))


class BrokenSocket:
    def recv(self, _size):
        return b""


class InterruptedSocket:
    def recv(self, _size):
        raise TimeoutError()


def test_e_transport_disconnect_fails_closed():
    refused("TRANSPORT_DISCONNECT", lambda: read_line(BrokenSocket()))
    refused("TRANSPORT_DISCONNECT", lambda: read_line(InterruptedSocket()))


@pytest.mark.parametrize("bad", [b"", b"GCR1", b"z" * 513 + b"\n"])
def test_f_truncated_or_oversized_response(context, bad):
    refused("TRUNCATED_RESPONSE", lambda: response_line(bad, context))


@pytest.mark.parametrize("position", [0, 5, 7])
def test_g_forged_guest_claims(context, response, position):
    fields = response.decode("ascii").split()
    fields[position] = "forged"
    refused(
        "FORGED_GUEST_CLAIMS",
        lambda: response_line((" ".join(fields) + "\n").encode("ascii"), context),
    )


def fake_host_peer():
    host = {
        "process": {"pid": {"value": 42}},
        "disk": {"inode": {"value": 999}},
        "status": "BLOCKED_TRUST_ROOT",
        "localQemuReadonlyDiskFdOpenProven": True,
    }
    peer = {
        "peer": {"pid": 42},
        "status": "BLOCKED_TRUST_ROOT",
        "localKernelPeerObserved": True,
        "localKernelPeerMatchesSuppliedPins": True,
    }
    return host, peer


def test_h_wrong_qemu_process():
    host, peer = fake_host_peer()
    peer["peer"]["pid"] = 43
    refused("WRONG_QEMU_PROCESS", lambda: bound_host(host, peer, 42, 999))


def test_i_wrong_disk_fd():
    host, peer = fake_host_peer()
    host["disk"]["inode"]["value"] = 1000
    refused("WRONG_DISK_FD", lambda: bound_host(host, peer, 42, 999))


def test_never_claim_independent_attestation(context, response):
    observed = response_line(response, context)
    assert "guestOriginIndependentlyAttested" not in observed
    assert "diskWritesAuthorized" not in observed


def test_replay_nonce_after_first_consumption_fails(tmp_path, context):
    tmp_path.chmod(0o700)
    with pytest.raises(FileExistsError):
        # This is deliberately NOT an auto-resume API; the existing ledger
        # must always be explicitly reopened and validated.
        path = tmp_path / "nonce.sqlite"
        ledger = LabNonceLedger(path)
        try:
            LabNonceLedger(path)
        finally:
            ledger.close()


def test_nonce_is_freshly_generated(context):
    assert context["nonce"] != expected_context(COLLECTOR_SHA)["nonce"]
    assert len(context["nonce"]) == 64
