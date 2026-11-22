"""Actual paused-free Linux guest collector boot; HOST-only, never attestation.

One controlled QEMU boot per pytest module; all other adversarial mutation
tests reuse genuine bytes observed from the guest, not fabricated boot claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from auto_tests.installer_observer.guest_transport_peer_boundary import (
    LocalSessionPins,
    LocalTransportWitness,
    TransportBoundaryRefused,
)
from auto_tests.installer_observer.qemu_local_disk_witness import (
    QemuDiskRefused,
    QemuLocalDiskWitness,
)
from auto_tests.tests.test_observer_qemu_real_disk_readonly import (
    make_qcow,
    make_raw,
    pinned as _pinned,
    pins_for,
    shutdown,
    wait_qmp,
)
from auto_tests.tools.observer_guest_collector_lab import (
    CollectorLabDenied,
    LabLedger,
    await_boot,
    bounded_line,
    build_guest,
    validate,
)

# Real QEMU is launched by a Linux hosted runner. No guest network, QGA,
# SSH, serial commands from HOST, install media, partitioning or writable disk.
QEMU = "/usr/bin/qemu-system-x86_64"


def _qemu_with_guest(workspace: Path, overlay: Path, image: dict) -> subprocess.Popen:
    assert os.environ["GITHUB_ACTIONS"] == "true"
    assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
    assert os.environ["GASLUX_GUEST_COLLECTOR_LAB"] == "1"
    assert overlay.parent == workspace and overlay.is_file()
    assert overlay.stat().st_nlink == 1
    assert (workspace / "guest-peer.sock").exists() is False
    argv = [
        QEMU,
        "-machine", "q35,accel=tcg",
        "-m", "384",
        "-nodefaults",
        "-no-user-config",
        "-no-reboot",
        "-display", "none",
        "-monitor", "none",
        "-nic", "none",
        "-serial", f"file:{workspace / 'kernel-serial.log'}",
        "-kernel", str(image["kernel"]),
        "-initrd", str(image["initrd"]),
        "-append", "console=ttyS0,115200 loglevel=4 panic=1 rdinit=/init",
        "-qmp", f"unix:{workspace / 'monitor.sock'},server=on,wait=off",
        "-drive", f"file={overlay},format=qcow2,if=none,id=disk0,readonly=on",
        "-device", "virtio-blk-pci,drive=disk0",
        "-chardev",
        f"socket,id=gp0,path={workspace / 'guest-peer.sock'},server=on,wait=off",
        "-device", "virtio-serial-pci",
        "-device", "virtserialport,chardev=gp0,name=gaslux.observer",
    ]
    mask = os.umask(0o077)
    try:
        proc = subprocess.Popen(
            argv,
            cwd=workspace,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    finally:
        os.umask(mask)
    try:
        wait_qmp(workspace / "monitor.sock", proc)
        wait_qmp(workspace / "guest-peer.sock", proc)
        return proc
    except BaseException:
        shutdown(proc)
        raise


def _peer_pins(conn: socket.socket, process_pins, session, nonce, collector, media_hash):
    st = os.fstat(conn.fileno())
    return LocalSessionPins(
        process=process_pins.process,
        transport_dev=st.st_dev,
        transport_inode=st.st_ino,
        session_id=session,
        transaction_id=str(uuid.uuid4()),
        host_vm_id="guest-lab-source-not-attested",
        disk_identity_sha256=media_hash,
        collector_sha256=collector,
        challenge=nonce,
    )


def _claims(pins: LocalSessionPins) -> dict[str, str]:
    return {
        "sessionId": pins.session_id,
        "transactionId": pins.transaction_id,
        "hostVmId": pins.host_vm_id,
        "diskIdentitySha256": pins.disk_identity_sha256,
        "collectorSha256": pins.collector_sha256,
        "challenge": pins.challenge,
        "provenance": "CLAIMED",
    }


def _write_manifest(meta, qemu, peer, report, boot_log, ledger, lab):
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = root / "gaslux-guest-collector-origin"
    output.mkdir(mode=0o700, exist_ok=False)
    assert output.stat().st_uid == os.getuid()
    assert output.stat().st_mode & 0o077 == 0
    manifest = {
        "schema": "gaslux-guest-collector-origin-lab-v1",
        "status": "BLOCKED_TRUST_ROOT",
        "classification": "NOT_INDEPENDENT",
        "scope": "BOOTED_DISPOSABLE_LINUX_GUEST_WITH_UNATTESTED_COLLECTOR",
        "kernelPackage": str(meta["kernelPackage"]),
        "busyboxPackage": str(meta["busyboxPackage"]),
        "kernelVersion": str(meta["kernelVersion"]),
        "kernelSha256": str(meta["kernelSha256"]),
        "initrdSha256": str(meta["initrdSha256"]),
        "collectorSha256": str(meta["collectorSha256"]),
        "bootSerialSha256": hashlib.sha256(boot_log).hexdigest(),
        "guestBootIdClaimed": report["bootIdClaimed"],
        "sessionId": report["session"],
        "nonceSha256": hashlib.sha256(report["nonce"].encode()).hexdigest(),
        "collectorSequence": report["counter"],
        "hostQemuPid": qemu["process"]["pid"]["value"],
        "peerKernelPid": peer["peer"]["pid"],
        "diskDev": qemu["disk"]["dev"]["value"],
        "diskInode": qemu["disk"]["inode"]["value"],
        "diskReadOnlyFdObserved": qemu["localQemuReadonlyDiskFdOpenProven"],
        "localQemuPeerObserved": peer["localKernelPeerObserved"],
        "hostQemuPeerAuthenticated": True,
        "guestCollectorExecutedObserved": True,
        "guestMessageReceived": True,
        "labReplayConsumptionVerified": lab,
        "guestOriginIndependentlyAttested": False,
        "guestChannelAuthenticated": False,
        "productionInstallationAuthorized": False,
        "diskWriteAuthorized": False,
        "inputAuthorized": False,
        "rollbackProven": False,
        "stable": False,
        "replayProtectedAgainstCompromisedHost": False,
        "ledgerSha256": hashlib.sha256(ledger.read_bytes()).hexdigest(),
    }
    content = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert len(content) < 4096
    (output / "manifest.json").write_bytes(content)
    (output / "manifest.sha256").write_text(
        hashlib.sha256(content).hexdigest() + "  manifest.json\n", encoding="ascii"
    )
    print("GASLUX_BOOTED_GUEST_COLLECTOR_LAB " + content.decode().strip(), flush=True)


@pytest.fixture(scope="module")
def real_guest(tmp_path_factory, pinned):
    _, lab = pinned
    folder = tmp_path_factory.mktemp("guest-origin", numbered=True).resolve(strict=True)
    folder.chmod(0o700)
    raw = make_raw(folder, lab)
    overlay = make_qcow(folder, lab, raw)
    original_chain = lab.verify_chain(overlay, raw, folder)
    image = build_guest(folder)
    child = _qemu_with_guest(folder, overlay, image)
    ledger_file = folder / "consumed.sqlite3"
    try:
        pins = pins_for(child, folder, overlay, "qcow2")
        session = str(uuid.uuid4())
        nonce = os.urandom(32).hex()
        with QemuLocalDiskWitness(pins) as disk:
            qemu = disk.finish()
            assert qemu["localQemuReadonlyDiskFdOpenProven"] is True
            assert qemu["guestChannelAuthenticated"] is False
            # Wrong process/FD must be denied while the real QEMU is running.
            with pytest.raises(QemuDiskRefused):
                QemuLocalDiskWitness(replace(pins, media_inode=pins.media_inode + 1))
            with pytest.raises(QemuDiskRefused):
                QemuLocalDiskWitness(
                    replace(
                        pins,
                        process=replace(
                            pins.process, start_ticks=pins.process.start_ticks + 1
                        ),
                    )
                )
            serial = folder / "kernel-serial.log"
            bootlog = await_boot(serial, child, "GASLUX_COLLECTOR_READY_TEST")
            assert ("GASLUX_COLLECTOR_HASH=" + str(image["collectorSha256"])).encode() in bootlog
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(15)
                conn.connect(str(folder / "guest-peer.sock"))
                peer_pins = _peer_pins(
                    conn,
                    pins,
                    session,
                    nonce,
                    image["collectorSha256"],
                    original_chain["overlaySha256"],
                )
                peer = LocalTransportWitness(conn, peer_pins)
                # Genuine peer of QEMU is still a HOST process, not a guest PID.
                conn.sendall(f"GASLUX_CHAL_V1|{session}|{nonce}\n".encode("ascii"))
                message = bounded_line(conn)
                observed = validate(message, session, nonce, str(image["collectorSha256"]))
                local = peer.finish(_claims(peer_pins))
                assert local["peer"]["pid"] == child.pid
                assert local["guestChannelAuthenticated"] is False
                # Genuine fake host proxy cannot claim the pinned QEMU ProcessSeal.
                with socket.socketpair() as (fake, other):
                    forged = _peer_pins(
                        fake,
                        pins,
                        session,
                        nonce,
                        image["collectorSha256"],
                        original_chain["overlaySha256"],
                    )
                    with pytest.raises(TransportBoundaryRefused):
                        LocalTransportWitness(fake, forged)
            token = LabLedger(ledger_file)
            token.consume(session, nonce)
            token.close()
            token = LabLedger(ledger_file)
            with pytest.raises(CollectorLabDenied, match="OLD_NONCE_REPLAY"):
                token.consume(session, nonce)
            token.close()
            # A serial boot record and real transport are two local observations.
            assert b"GASLUX_GUEST_INIT_EXECUTED_TEST" in bootlog
            shutdown(child)
            end = disk.assert_stopped()
            assert end["qemuProcessReaped"] is True
            assert lab.verify_chain(overlay, raw, folder) == original_chain
            _write_manifest(image, qemu, local, observed, bootlog, ledger_file, True)
        yield {"message": message, "session": session, "nonce": nonce, "image": image}
    finally:
        shutdown(child)


def test_linux_guest_collector_executed_and_reported_without_attestation(real_guest):
    e = real_guest
    assert validate(e["message"], e["session"], e["nonce"], e["image"]["collectorSha256"])


def test_old_nonce_replay_is_rejected_by_host_session(real_guest):
    e = real_guest
    with pytest.raises(CollectorLabDenied, match="OLD_NONCE_REPLAY"):
        validate(e["message"], e["session"], "0" * 64, e["image"]["collectorSha256"])


def test_wrong_vm_session_rejected(real_guest):
    e = real_guest
    with pytest.raises(CollectorLabDenied, match="WRONG_VM_SESSION"):
        validate(e["message"], str(uuid.uuid4()), e["nonce"], e["image"]["collectorSha256"])


def test_collector_hash_mismatch_rejected(real_guest):
    e = real_guest
    with pytest.raises(CollectorLabDenied, match="COLLECTOR_HASH_MISMATCH"):
        validate(e["message"], e["session"], e["nonce"], "f" * 64)


def test_forged_guest_claims_and_extra_authority_rejected(real_guest):
    e = real_guest
    with pytest.raises(CollectorLabDenied, match="RESPONSE_SCHEMA"):
        validate(
            e["message"] + b"|guestChannelAuthenticated=true",
            e["session"],
            e["nonce"],
            e["image"]["collectorSha256"],
        )


def test_transport_disconnect_without_full_report_refused():
    with socket.socketpair() as (receiver, sender):
        sender.sendall(b"GASLUX_REPORT_V1|truncated")
        sender.shutdown(socket.SHUT_WR)
        with pytest.raises(CollectorLabDenied, match="TRANSPORT_DISCONNECT"):
            bounded_line(receiver, timeout=1)


def test_truncated_response_and_oversized_frame_rejected():
    with socket.socketpair() as (receiver, sender):
        sender.sendall(b"x" * 260)
        with pytest.raises(CollectorLabDenied, match="TRUNCATED_OR_OVERSIZED_RESPONSE"):
            bounded_line(receiver, timeout=1)


def test_guest_message_without_fixed_counter_denied(real_guest):
    e = real_guest
    forged = e["message"].rsplit(b"|", 1)[0] + b"|2"
    with pytest.raises(CollectorLabDenied, match="SESSION_COUNTER_INVALID"):
        validate(forged, e["session"], e["nonce"], e["image"]["collectorSha256"])
