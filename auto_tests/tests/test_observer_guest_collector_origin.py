"""Real QEMU Linux guest + read-only BusyBox collector laboratory.

The real guest is booted from an Ubuntu signed apt kernel package and an
owned, source-measured initramfs assembled in the disposable CI runner.
SO_PEERCRED still authenticates QEMU HOST, NOT guest origin. No installation,
guest shell interface or production writer is ever exposed.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from auto_tests.installer_observer.guest_collector_lab_protocol import (
    CollectorChallenge,
    GuestCollectorDenied,
    LabChallengeLedger,
    read_frame,
    response_bytes,
    validate_response,
)
from auto_tests.installer_observer.guest_transport_peer_boundary import (
    LocalSessionPins,
    LocalTransportWitness,
)
from auto_tests.installer_observer.qemu_local_disk_witness import QemuLocalDiskWitness
from auto_tests.tests.test_observer_qemu_real_disk_readonly import (
    make_qcow,
    make_raw,
    pins_for,
    shutdown,
    start_qemu,
)

pytest_plugins = ("auto_tests.tests.test_observer_qemu_real_disk_readonly",)

COLLECTOR_SOURCE = """#!/bin/busybox sh
export PATH=/bin
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
for module in /modules/*.ko; do
    if [ -f "$module" ]; then /bin/busybox insmod "$module" || true; fi
done
i=0
while [ ! -c /dev/vport0p1 ] && [ "$i" -lt 100 ]; do
    /bin/busybox sleep 0.1
    i=$((i + 1))
done
if [ ! -c /dev/vport0p1 ]; then
    echo GASLUX_GUEST_COLLECTOR_NO_PORT >/dev/console
    exec /bin/busybox sleep 60
fi
echo GASLUX_GUEST_COLLECTOR_EXECUTED >/dev/console
exec 3<>/dev/vport0p1
IFS= read -r challenge <&3
set -- $(echo "$challenge" | /bin/busybox tr '|' ' ')
if [ "$#" -ne 3 ] || [ "$1" != "GASLUX-COLLECTOR-LAB-1" ]; then
    echo GASLUX_GUEST_CHALLENGE_REFUSED >/dev/console
    exec /bin/busybox sleep 60
fi
bootid=$(/bin/busybox cat /proc/sys/kernel/random/boot_id)
echo "GASLUX-COLLECTOR-LAB-1|$2|$3|COLLECTOR_DIGEST|1|$bootid" >&3
echo GASLUX_GUEST_RESPONSE_EMITTED >/dev/console
exec /bin/busybox sleep 60
"""
# This script is lab-owned source; the digest is a HOST-measured reference and
# a claim in the guest response, NEVER a guest authenticity signature.
COLLECTOR_SHA = hashlib.sha256(COLLECTOR_SOURCE.encode("ascii")).hexdigest()
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _run(*args: str, **kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def _kernel_and_modules() -> tuple[Path, str, dict[str, str]]:
    kernels = sorted(Path("/boot").glob("vmlinuz-*-generic"), reverse=True)
    for kernel in kernels:
        release = kernel.name.removeprefix("vmlinuz-")
        if not (Path("/lib/modules") / release).is_dir():
            continue
        dpkg = _run("dpkg-query", "-S", str(kernel)).stdout.decode().strip()
        package = dpkg.split(":", 1)[0]
        version = _run("dpkg-query", "-W", "-f=${Version}", package).stdout.decode()
        if package and version:
            return (
                kernel,
                release,
                {
                    "package": package,
                    "packageVersion": version,
                    "kernelSha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
                },
            )
    raise RuntimeError("NO_DPKG_MANAGED_LINUX_KERNEL_WITH_MODULES")


def _modules(release: str, root: Path) -> list[str]:
    result = _run("modprobe", "-S", release, "--show-depends", "virtio_pci", "virtio_console")
    modules = []
    for line in result.stdout.decode().splitlines():
        if not line.startswith("insmod "):
            continue
        original = Path(line.removeprefix("insmod ").split()[0])
        if not original.is_file():
            raise RuntimeError("APT_KERNEL_MODULE_MISSING")
        output = root / "modules" / f"{len(modules):03}.ko"
        if original.name.endswith(".ko.zst"):
            decompressed = _run("zstd", "-d", "-c", str(original)).stdout
        elif original.name.endswith(".ko.xz"):
            decompressed = _run("xz", "-d", "-c", str(original)).stdout
        else:
            decompressed = original.read_bytes()
        output.write_bytes(decompressed)
        modules.append(hashlib.sha256(decompressed).hexdigest())
    if not modules:
        raise RuntimeError("VIRTIO_CONSOLE_MODULES_NOT_RESOLVED")
    return modules


def _initrd(folder: Path) -> tuple[Path, Path, dict[str, object]]:
    kernel, release, provenance = _kernel_and_modules()
    root = folder / "initrd-root"
    for sub in ("bin", "dev", "proc", "sys", "modules"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    busybox = Path("/bin/busybox")
    _run("file", str(busybox))
    details = _run("file", str(busybox)).stdout.decode().lower()
    if "statically linked" not in details and "static-pie" not in details:
        raise RuntimeError("BUSYBOX_BINARY_NOT_STATIC")
    shutil.copyfile(busybox, root / "bin" / "busybox")
    (root / "bin" / "busybox").chmod(0o755)
    collector = COLLECTOR_SOURCE.replace("COLLECTOR_DIGEST", COLLECTOR_SHA)
    (root / "init").write_text(collector, encoding="ascii")
    (root / "init").chmod(0o755)
    module_hashes = _modules(release, root)
    image = folder / "lab-initrd.cpio.gz"
    # CPIO has deterministic source bytes; archive timestamp may vary but the
    # exact resulting artifact SHA is observed and pinned per Action run.
    find = subprocess.Popen(
        ["find", ".", "-print0"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        assert find.stdout is not None
        archive = subprocess.run(
            ["cpio", "--null", "-o", "-H", "newc"],
            cwd=root,
            stdin=find.stdout,
            capture_output=True,
            check=True,
        ).stdout
    finally:
        assert find.wait(timeout=5) == 0
    image.write_bytes(gzip.compress(archive, compresslevel=3, mtime=0))
    return (
        kernel,
        image,
        {
            **provenance,
            "kernelRelease": release,
            "busyboxSha256": hashlib.sha256(busybox.read_bytes()).hexdigest(),
            "collectorSourceSha256": COLLECTOR_SHA,
            "collectorDeliveredSha256": hashlib.sha256(collector.encode("ascii")).hexdigest(),
            "moduleSha256": module_hashes,
            "initrdSha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        },
    )


def _local_host_peer(conn: socket.socket, qemu, challenge: CollectorChallenge) -> dict:
    st = os.fstat(conn.fileno())
    pins = LocalSessionPins(
        process=qemu.process,
        transport_dev=st.st_dev,
        transport_inode=st.st_ino,
        session_id=str(uuid.uuid4()),
        transaction_id=str(uuid.uuid4()),
        host_vm_id=qemu.vm_label,
        disk_identity_sha256="b" * 64,
        collector_sha256=challenge.collector_sha256,
        challenge=challenge.nonce,
    )
    claims = {
        "sessionId": pins.session_id,
        "transactionId": pins.transaction_id,
        "hostVmId": pins.host_vm_id,
        "diskIdentitySha256": pins.disk_identity_sha256,
        "collectorSha256": pins.collector_sha256,
        "challenge": pins.challenge,
        "provenance": "CLAIMED",
    }
    return LocalTransportWitness(conn, pins).finish(claims)


def _resume_for_lab(qmp: Path) -> None:
    # The TEST SUPERVISOR alone may continue the disposable paused test guest.
    # The production Observer has no QMP 'cont' capability or controller.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(qmp))

        def read() -> dict:
            buffer = bytearray()
            while len(buffer) < 16384:
                char = conn.recv(1)
                if not char:
                    raise RuntimeError("QMP_LOST")
                buffer.extend(char)
                if char == b"\n":
                    return json.loads(buffer)
            raise RuntimeError("QMP_TOO_LARGE")

        assert "QMP" in read()
        conn.sendall(b'{"execute":"qmp_capabilities"}\n')
        assert "return" in read()
        conn.sendall(b'{"execute":"cont"}\n')
        assert "return" in read()


def _wait_marker(log: Path, marker: bytes, child: subprocess.Popen, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("GUEST_QEMU_EXITED")
        if log.exists() and marker in log.read_bytes()[-64000:]:
            return
        time.sleep(0.1)
    raise RuntimeError("GUEST_COLLECTOR_BOOT_MARKER_MISSING")


@pytest.fixture
def ledger(tmp_path):
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    return LabChallengeLedger(root / "issued.sqlite")


def _challenge() -> CollectorChallenge:
    return CollectorChallenge(
        session="gaslux" + uuid.uuid4().hex,
        nonce=os.urandom(32).hex(),
        collector_sha256=COLLECTOR_SHA,
    )


def test_real_guest_boot_collector_challenge_via_virtio_serial(workspace, pinned, ledger):
    gate, lab = pinned
    raw = make_raw(workspace, lab)
    overlay = make_qcow(workspace, lab, raw)
    chain = lab.verify_chain(overlay, raw, workspace)
    assert gate.inspect_gpt_image(raw, logical_sector_size=512)["partitions"]
    kernel, initrd, provenance = _initrd(workspace)
    challenge = _challenge()
    ledger.issue(challenge)
    child = start_qemu(
        workspace,
        overlay,
        "qcow2",
        guest_peer_endpoint=True,
        guest_kernel=kernel,
        guest_initrd=initrd,
    )
    serial = workspace / "guest-console.log"
    report = None
    try:
        qemu = pins_for(child, workspace, overlay, "qcow2")
        with QemuLocalDiskWitness(qemu) as host:
            host_report = host.finish()
            assert host_report["localQemuReadonlyDiskFdOpenProven"] is True
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(30)
                conn.connect(str(workspace / "guest-peer.sock"))
                kernel_peer = _local_host_peer(conn, qemu, challenge)
                assert kernel_peer["peer"]["pid"] == child.pid
                assert kernel_peer["guestChannelAuthenticated"] is False
                _resume_for_lab(workspace / "monitor.sock")
                _wait_marker(serial, b"GASLUX_GUEST_COLLECTOR_EXECUTED", child)
                conn.sendall(challenge.wire())
                reply = read_frame(conn)
                report = ledger.consume(challenge, reply)
                assert report["guestMessageReceived"] is True
                assert report["guestOriginIndependentlyAttested"] is False
                assert report["guestChannelAuthenticated"] is False
                assert report["counter"] == 1
                _wait_marker(serial, b"GASLUX_GUEST_RESPONSE_EMITTED", child)
                with pytest.raises(GuestCollectorDenied, match="OLD_NONCE_REPLAY_OR_UNISSUED"):
                    ledger.consume(challenge, reply)
        shutdown(child)
        assert host.assert_stopped()["qemuProcessReaped"] is True
    finally:
        shutdown(child)
    assert report is not None and ledger.count_used() == 1
    data = {
        "status": "BLOCKED_TRUST_ROOT",
        "classification": "NOT_ATTESTED",
        "guestBootObserved": True,
        "guestCollectorExecutedObserved": True,
        "guestMessageReceived": True,
        "hostQemuPeerAuthenticated": True,
        "guestOriginIndependentlyAttested": False,
        "guestChannelAuthenticated": False,
        "labLedgerSingleUseVerified": True,
        "replayProtectedAgainstHostCompromise": False,
        "diskWriteAuthorized": False,
        "productionInstallationAuthorized": False,
        "rollbackProven": False,
        "stable": False,
        "hostQemuPid": qemu.process.pid,
        "guestBootIdClaimed": report["bootIdClaimed"],
        "hostDiskInode": qemu.media_inode,
        "backingSha256": chain["backingSha256"],
        "artifacts": provenance,
    }
    print("GASLUX_GUEST_COLLECTOR_LAB " + json.dumps(data, sort_keys=True), flush=True)
    evidence_root = Path(os.environ["RUNNER_TEMP"]) / "gaslux-observer-collector-lab"
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    payload = (json.dumps(data, sort_keys=True) + "\n").encode()
    (evidence_root / "manifest.json").write_bytes(payload)
    (evidence_root / "manifest.sha256").write_text(
        hashlib.sha256(payload).hexdigest() + "  manifest.json\n", encoding="ascii"
    )


@pytest.mark.parametrize(
    "name",
    [
        "OLD_NONCE_REPLAY",
        "WRONG_VM_SESSION",
        "COLLECTOR_HASH_MISMATCH",
        "TRUNCATED_RESPONSE",
        "FORGED_GUEST_CLAIMS",
        "UNISSUED_NONCE",
        "COUNTER_INVALID",
        "HOST_PROXY_SPOOF",
        "WRONG_DISK_FD",
    ],
)
def test_guest_origin_adversarial_protocol_denied(tmp_path, name):
    root = tmp_path / "ledger"
    root.mkdir(mode=0o700)
    state = LabChallengeLedger(root / "state.db")
    challenge = _challenge()
    state.issue(challenge)
    legitimate = response_bytes(challenge, boot_id="labboot01")
    assert validate_response(legitimate, challenge)["guestOriginIndependentlyAttested"] is False
    if name == "OLD_NONCE_REPLAY":
        state.consume(challenge, legitimate)
        # Reopen the persisted db to prove local session replay denial.
        state = LabChallengeLedger(root / "state.db")
        with pytest.raises(GuestCollectorDenied, match="OLD_NONCE_REPLAY_OR_UNISSUED"):
            state.consume(challenge, legitimate)
    elif name == "WRONG_VM_SESSION":
        with pytest.raises(GuestCollectorDenied, match="WRONG_VM_SESSION"):
            state.consume(
                challenge, legitimate.replace(challenge.session.encode(), b"other-session")
            )
    elif name == "COLLECTOR_HASH_MISMATCH":
        with pytest.raises(GuestCollectorDenied, match="COLLECTOR_HASH_MISMATCH"):
            state.consume(challenge, legitimate.replace(COLLECTOR_SHA.encode(), b"f" * 64))
    elif name == "TRUNCATED_RESPONSE":
        with pytest.raises(GuestCollectorDenied, match="TRUNCATED_OR_MULTIFRAME"):
            state.consume(challenge, legitimate[:-1])
    elif name == "FORGED_GUEST_CLAIMS":
        with pytest.raises(GuestCollectorDenied, match="RESPONSE_SCHEMA_INVALID"):
            state.consume(challenge, legitimate[:-1] + b"|diskWriteAuthorized=true\n")
    elif name == "UNISSUED_NONCE":
        other = _challenge()
        with pytest.raises(GuestCollectorDenied, match="OLD_NONCE_REPLAY_OR_UNISSUED"):
            state.consume(other, response_bytes(other, boot_id="labboot01"))
    elif name == "COUNTER_INVALID":
        with pytest.raises(GuestCollectorDenied, match="COUNTER_INVALID"):
            state.consume(challenge, legitimate.replace(b"|1|", b"|0|"))
    elif name in ("HOST_PROXY_SPOOF", "WRONG_DISK_FD"):
        # A host process can produce identical bytes. The parser MUST NOT
        # identify the guest, collector delivery or the disk by itself.
        witness = state.consume(challenge, legitimate)
        assert witness["guestOriginIndependentlyAttested"] is False
        assert witness["guestChannelAuthenticated"] is False
        assert witness["diskWriteAuthorized"] is False


def test_transport_disconnect_and_truncation_denied():
    left, right = socket.socketpair()
    try:
        left.settimeout(1)
        right.sendall(b"GASLUX-COLLECTOR-LAB-1|partial")
        right.close()
        with pytest.raises(GuestCollectorDenied, match="TRANSPORT_DISCONNECT_OR_TRUNCATION"):
            read_frame(left)
    finally:
        left.close()
        right.close()


def test_overlarge_frame_denied():
    left, right = socket.socketpair()
    try:
        left.settimeout(1)
        right.sendall(b"x" * 513 + b"\n")
        with pytest.raises(GuestCollectorDenied, match="FRAME_TOO_LARGE"):
            read_frame(left)
    finally:
        left.close()
        right.close()
