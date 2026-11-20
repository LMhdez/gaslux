"""Host-only Bazzite collector-channel boundary: refused execution by construction.

All mocked process identities exercise the verifier, not an authenticated
live-guest communication channel. QEMU itself is checked in the integration job.
"""

import hashlib
import sys
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

import bazzite_live_channel_boundary as boundary  # noqa: E402
from bazzite_gpt_fixture import Refusal  # noqa: E402


def synthetic_qemu_process(overlay: Path, vars_file: Path, token: str) -> dict:
    return {
        "pid": 7134,
        "startTicks": 241223,
        "executable": "/usr/bin/qemu-system-x86_64",
        "argv": [
            "/usr/bin/qemu-system-x86_64",
            "-machine",
            "q35,accel=tcg",
            "-m",
            "512",
            "-nodefaults",
            "-display",
            "none",
            "-S",
            "-nic",
            "none",
            "-monitor",
            "none",
            "-drive",
            "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive",
            f"if=pflash,format=raw,unit=1,file={vars_file}",
            "-drive",
            f"file={overlay},format=qcow2,if=none,id=owned,readonly=on",
            "-device",
            "virtio-blk-pci,drive=owned,serial=GLXBAZRO001",
            "-name",
            f"gaslux-bazzite-{token}",
        ],
    }


def synthetic_context(tmp_path, monkeypatch):
    root = tmp_path / "owned"
    root.mkdir()
    overlay = root / "gpt-layout-scratch.qcow2"
    overlay.write_bytes(b"synthetic-cow-not-real-qcow2")
    vars_file = tmp_path / "bazzite-ovmf-vars-disposable.fd"
    vars_file.write_bytes(b"dummy-test-only")
    collector = tmp_path / "bazzite_anaconda_readonly_capture.py"
    collector.write_text("# test content\n")
    monkeypatch.setattr(boundary, "COLLECTOR", collector)
    monkeypatch.setattr(
        boundary,
        "inspect",
        lambda _root, _runner_temp: {
            "diskGuid": "11111111-2222-4333-8444-555555555555",
            "installationAuthorized": False,
            "protectedExistingPartitions": [
                {"partuuid": f"0000000{i}-2222-4333-8444-555555555555"} for i in range(1, 4)
            ],
        },
    )
    monkeypatch.setattr(boundary, "expected_actions", lambda proposal: None)
    token = "1234567890abcdef1234567890abcdef"
    process = synthetic_qemu_process(overlay, vars_file, token)
    return {
        "qemu_pid": 7134,
        "transaction": token,
        "root": root,
        "runner_temp": tmp_path,
        "expected_collector_sha256": hashlib.sha256(collector.read_bytes()).hexdigest(),
        "process_reader": lambda pid: deepcopy(process),
    }, process, collector


def test_host_observation_never_enables_collector_execution(tmp_path, monkeypatch):
    params, _, _ = synthetic_context(tmp_path, monkeypatch)
    result = boundary.audit_once(**params)
    assert result["status"] == "REFUSED_NO_AUTHENTICATED_GUEST_COLLECTOR_CHANNEL"
    assert result["qemu"]["qemuCpuStopped"] is True
    assert result["qemu"]["guestCommandChannelConfigured"] is False
    assert result["collectorInvoked"] is False
    assert result["collectorStdout"] is None
    assert result["collectorStderr"] is None
    assert result["collectorExitCode"] is None
    assert result["hostGuestIdentityIndependentlyAuthenticated"] is False
    assert result["getActionsObserved"] is False
    assert result["isoBooted"] is False
    assert result["legacyIsoIndependentSignatureVerified"] is False
    for key in (
        "installationAuthorized",
        "partitionWriteAuthorized",
        "windowsEspWriteAuthorized",
        "nvramWriteAuthorized",
    ):
        assert result[key] is False


def test_reused_transaction_refused_without_invoking_collector(tmp_path, monkeypatch):
    params, _, _ = synthetic_context(tmp_path, monkeypatch)
    boundary.audit_once(**params)
    with pytest.raises(Refusal, match="Reused"):
        boundary.audit_once(**params)


def test_collector_hash_changed_or_unpinned_refused(tmp_path, monkeypatch):
    params, _, collector = synthetic_context(tmp_path, monkeypatch)
    with pytest.raises(Refusal, match="pin"):
        boundary.audit_once(**{**params, "expected_collector_sha256": "invalid"})
    collector.write_text("# changed collector\n")
    with pytest.raises(Refusal, match="hash differs"):
        boundary.audit_once(**params)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("-nic", "user"),
        ("-monitor", "stdio"),
        ("-S", None),
        ("-device", "virtio-serial-pci"),
        ("-chardev", "socket,path=/tmp/guest-agent,server=on"),
        ("-qmp", "unix:/tmp/qmp,server=on,wait=off"),
        ("-vnc", "127.0.0.1:1"),
        ("-serial", "stdio"),
        ("-kernel", "/tmp/instrumented-vmlinuz"),
    ],
)
def test_unapproved_guest_control_topology_refused(tmp_path, monkeypatch, option, value):
    params, process, _ = synthetic_context(tmp_path, monkeypatch)
    argv = process["argv"]
    if option == "-S":
        argv.remove(option)
    elif option in argv:
        argv[argv.index(option) + 1] = value
    else:
        argv.extend((option, value))
    params["process_reader"] = lambda pid: deepcopy(process)
    with pytest.raises(Refusal):
        boundary.audit_once(**params)


@pytest.mark.parametrize("tamper", ("overlay", "serial", "vars", "firmware", "name"))
def test_foreign_disk_or_transaction_refused(tmp_path, monkeypatch, tamper):
    params, process, _ = synthetic_context(tmp_path, monkeypatch)
    argv = process["argv"]
    substitutions = {
        "overlay": ("gpt-layout-scratch.qcow2", "foreign.qcow2"),
        "serial": ("GLXBAZRO001", "FOREIGN"),
        "vars": ("bazzite-ovmf-vars-disposable.fd", "foreign-vars.fd"),
        "firmware": ("OVMF_CODE_4M.fd", "unverified-code.fd"),
        "name": ("gaslux-bazzite-", "untrusted-"),
    }
    before, after = substitutions[tamper]
    process["argv"] = [arg.replace(before, after) for arg in argv]
    params["process_reader"] = lambda pid: deepcopy(process)
    with pytest.raises(Refusal):
        boundary.audit_once(**params)


@pytest.mark.parametrize("tamper", ("pid", "startTicks", "executable", "argv"))
def test_substituted_qemu_process_refused(tmp_path, monkeypatch, tamper):
    params, process, _ = synthetic_context(tmp_path, monkeypatch)
    if tamper == "pid":
        process["pid"] = 9999
    elif tamper == "startTicks":
        process["startTicks"] = 0
    elif tamper == "executable":
        process["executable"] = "/usr/bin/python3"
    else:
        process["argv"][0] = "/bin/sh"
    params["process_reader"] = lambda pid: deepcopy(process)
    if tamper == "pid":
        # A real /proc reader would return a different process or raise ESRCH.
        params["process_reader"] = lambda pid: (
            process if pid == 9999 else {"pid": pid, "startTicks": 0}
        )
    with pytest.raises(Refusal):
        boundary.audit_once(**params)


def test_process_changed_between_independent_probes_refused(tmp_path, monkeypatch):
    params, process, _ = synthetic_context(tmp_path, monkeypatch)
    counts = [0]

    def changed(pid):
        counts[0] += 1
        evidence = deepcopy(process)
        if counts[0] == 2:
            evidence["startTicks"] += 1
        return evidence

    params["process_reader"] = changed
    with pytest.raises(Refusal, match="replaced"):
        boundary.audit_once(**params)


def test_no_executable_channel_even_when_host_geometry_matches(tmp_path, monkeypatch):
    params, _, _ = synthetic_context(tmp_path, monkeypatch)
    result = boundary.audit_once(**params)
    assert "rawResponses" not in result
    assert "atomicDeploymentVerified" not in result
    assert "GetActions" not in result
    assert not result["installationAuthorized"]
