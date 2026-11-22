#!/usr/bin/env python3
"""Host-only QEMU/collector boundary: attest a paused guest and refuse execution.

This module does NOT transport data into a guest or invoke the collector. No
QEMU monitor, QGA, VNC, serial console or shell is used to execute commands.
A successful host audit is a deterministic refusal, never an install grant.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from bazzite_anaconda_write_set_gate import expected_actions
from bazzite_atomic_destination_plan import inspect
from bazzite_gpt_fixture import Refusal

COLLECTOR = Path(__file__).with_name("bazzite_anaconda_readonly_capture.py")
SERIAL = "GLXBAZRO001"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TRANSACTION = re.compile(r"[a-f0-9]{32}\Z")
ALLOWED_WITH_VALUE = frozenset(
    {"-machine", "-m", "-display", "-nic", "-monitor", "-drive", "-device", "-name"}
)
ALLOWED_FLAGS = frozenset({"-S", "-nodefaults", "-no-reboot"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_qemu_process(pid: int) -> dict:
    """Independent host /proc observation, NOT a guest attestation."""
    if type(pid) is not int or pid <= 1:
        raise Refusal("Unexpected QEMU PID")
    proc = Path("/proc") / str(pid)
    cmdline = (proc / "cmdline").read_bytes().split(b"\0")
    if cmdline and cmdline[-1] == b"":
        cmdline.pop()
    args = [value.decode("utf-8", errors="strict") for value in cmdline]
    executable = (proc / "exe").resolve(strict=True)
    metadata = (proc / "stat").read_text(encoding="utf-8")
    fields = metadata.rsplit(")", maxsplit=1)
    if len(fields) != 2:
        raise Refusal("Unrecognized QEMU process lifetime metadata")
    words = fields[1].strip().split()
    if len(words) < 20 or not words[19].isdecimal():
        raise Refusal("Missing QEMU start ticks")
    return {
        "pid": pid,
        "startTicks": int(words[19]),
        "executable": str(executable),
        "executableSha256": _sha256(executable),
        "argv": args,
    }


def _options(argv: object) -> dict[str, list[str]]:
    if not isinstance(argv, list) or len(argv) > 48 or not argv:
        raise Refusal("Missing or unbounded QEMU command line")
    if any(not isinstance(v, str) or len(v) > 2048 or "\0" in v for v in argv):
        raise Refusal("Non-canonical QEMU arguments")
    result: dict[str, list[str]] = {}
    offset = 1
    while offset < len(argv):
        option = argv[offset]
        if option in ALLOWED_FLAGS:
            result.setdefault(option, []).append("")
            offset += 1
        elif option in ALLOWED_WITH_VALUE and offset + 1 < len(argv):
            result.setdefault(option, []).append(argv[offset + 1])
            offset += 2
        else:
            raise Refusal("Unapproved QEMU option or potential guest execution channel")
    return result


def verify_paused_topology(
    process: dict,
    transaction: str,
    expected_overlay: Path,
    expected_vars: Path,
) -> dict:
    """Accept only the precise host-side nonbooting, noninteractive topology."""
    if not isinstance(transaction, str) or not TRANSACTION.fullmatch(transaction):
        raise Refusal("Invalid or absent transaction identity")
    if (
        not isinstance(process, dict)
        or type(process.get("pid")) is not int
        or type(process.get("startTicks")) is not int
        or process["startTicks"] <= 0
        or Path(str(process.get("executable", ""))).name != "qemu-system-x86_64"
        or not isinstance(process.get("executableSha256"), str)
        or not SHA256.fullmatch(process["executableSha256"])
    ):
        raise Refusal("Unexpected QEMU executable, PID or start time")
    options = _options(process.get("argv"))
    if (
        not isinstance(process["argv"][0], str)
        or Path(process["argv"][0]).name != "qemu-system-x86_64"
        or {key for key in options}
        != {
            "-S",
            "-nodefaults",
            "-machine",
            "-m",
            "-display",
            "-nic",
            "-monitor",
            "-drive",
            "-device",
            "-name",
        }
        or options["-S"] != [""]
        or options["-nodefaults"] != [""]
        or options["-machine"] != ["q35,accel=tcg"]
        or options["-m"] != ["512"]
        or options["-display"] != ["none"]
        or options["-nic"] != ["none"]
        or options["-monitor"] != ["none"]
        or options["-name"] != [f"gaslux-bazzite-{transaction}"]
        or options["-device"] != [f"virtio-blk-pci,drive=owned,serial={SERIAL}"]
        or len(options["-drive"]) != 3
    ):
        raise Refusal("QEMU not exclusively paused, headless and without command channels")
    drives = options["-drive"]
    ovmf_code = [
        d.removeprefix("if=pflash,format=raw,unit=0,readonly=on,file=")
        for d in drives
        if d.startswith("if=pflash,format=raw,unit=0,readonly=on,file=")
    ]
    approved_code = {
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    }
    if (
        len(ovmf_code) != 1
        or ovmf_code[0] not in approved_code
        or f"if=pflash,format=raw,unit=1,file={expected_vars}" not in drives
        or f"file={expected_overlay},format=qcow2,if=none,id=owned,readonly=on" not in drives
    ):
        raise Refusal("Foreign synthetic disk or firmware attachment")
    if len(set(drives)) != 3:
        raise Refusal("Duplicated or substituted QEMU drive")
    return {
        "ovmfCodeSource": ovmf_code[0],
        "qemuPid": process["pid"],
        "qemuStartTicks": process["startTicks"],
        "qemuExecutable": process["executable"],
        "qemuExecutableSha256": process["executableSha256"],
        "qemuCommandSha256": hashlib.sha256("\0".join(process["argv"]).encode("utf-8")).hexdigest(),
        "configuredGuestSerial": SERIAL,
        "qemuCpuStopped": True,
        "guestNetworkConfigured": False,
        "guestCommandChannelConfigured": False,
    }


def audit_once(
    *,
    qemu_pid: int,
    transaction: str,
    root: Path,
    runner_temp: Path,
    expected_collector_sha256: str,
    process_reader=read_qemu_process,
) -> dict:
    """Produce only host evidence; reject replays and unattested collector bytes."""
    if not isinstance(expected_collector_sha256, str) or not SHA256.fullmatch(
        expected_collector_sha256
    ):
        raise Refusal("Missing 64-digit collector SHA-256 pin")
    if COLLECTOR.is_symlink() or not COLLECTOR.is_file():
        raise Refusal("Collector missing or redirected")
    calculated = _sha256(COLLECTOR)
    if calculated != expected_collector_sha256:
        raise Refusal("Collector binary hash differs from approved host pin")
    root = root.resolve(strict=True)
    runner_temp = runner_temp.resolve(strict=True)
    if not root.is_relative_to(runner_temp):
        raise Refusal("Synthetic transaction outside isolated runner temp")
    proposal = inspect(root, runner_temp)
    expected_actions(proposal)  # Reuse the existing exact candidate contract.
    if proposal["diskGuid"] is None or proposal["installationAuthorized"] is not False:
        raise Refusal("Missing verified synthetic GPT or forbidden install authority")
    overlay = root / "gpt-layout-scratch.qcow2"
    if overlay.is_symlink() or not overlay.is_file():
        raise Refusal("Non-owned or missing QEMU overlay")
    vars_file = runner_temp / "bazzite-ovmf-vars-disposable.fd"
    if vars_file.is_symlink() or not vars_file.is_file():
        raise Refusal("Missing independently disposable OVMF variables")
    current = process_reader(qemu_pid)
    topology = verify_paused_topology(current, transaction, overlay, vars_file)
    if process_reader(qemu_pid) != current:
        raise Refusal("QEMU process replaced or changed during inventory")
    if not TRANSACTION.fullmatch(transaction):
        raise Refusal("Unexpected transaction replay token")
    marker = root / f"collector-channel-{transaction}.used"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError as exc:
        raise Refusal("Reused QEMU/collector transaction") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write("HOST-ONLY-NO-EXECUTION\n")
        output.flush()
        os.fsync(output.fileno())
    return {
        "schemaVersion": 1,
        "origin": "host-only-qemu-proc-and-synthetic-gpt",
        "transaction": transaction,
        "qemu": topology,
        "collectorSha256": calculated,
        "hostGptGuid": proposal["diskGuid"],
        "hostProtectedPartuuids": [
            entry["partuuid"] for entry in proposal["protectedExistingPartitions"]
        ],
        "hostBackingValidatedByExistingFixture": True,
        "hostGuestIdentityIndependentlyAuthenticated": False,
        "collectorInvoked": False,
        "isoBooted": False,
        "legacyIsoIndependentSignatureVerified": False,
        "collectorStdout": None,
        "collectorStderr": None,
        "collectorExitCode": None,
        "anacondaDbusServiceObserved": False,
        "getActionsObserved": False,
        "writeSetRealObserved": False,
        "atomicPayloadBoundToIso": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nvramWriteAuthorized": False,
        "status": "REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu-pid", type=int, required=True)
    parser.add_argument("--transaction", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    parser.add_argument("--collector-sha256", required=True)
    args = parser.parse_args()
    try:
        result = audit_once(
            qemu_pid=args.qemu_pid,
            transaction=args.transaction,
            root=args.root,
            runner_temp=args.runner_temp,
            expected_collector_sha256=args.collector_sha256,
        )
    except (Refusal, OSError, KeyError, TypeError, ValueError, UnicodeError) as exc:
        parser.exit(3, f"REFUSED_HOST_ATTESTATION: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(2)  # A fully matching host topology still cannot execute a guest collector.


if __name__ == "__main__":
    main()
