#!/usr/bin/env python3
"""Independent parent-boundary admission; fixed synthetic client, not OpenCode."""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

import gaslux_opencode_iterative as iterative
import gaslux_opencode_workspace as broker

BWRAP = Path("/usr/bin/bwrap")
TIMEOUT = 60
NAMESPACES = ("user", "mnt", "pid", "net", "ipc", "uts")
ACTIONS = ["inspect_task", "read_candidate", "run_tests", "replace_candidate", "run_tests"]

# Fixed test client, not generated code. No host credential, repository or
# broker-state mount; the socket is the only capability deliberately shared.
CLIENT = r'''
import errno
import json
import os
from pathlib import Path
import socket
import sys

host = json.loads(sys.argv[1])
for name, expected in host["namespaces"].items():
    if os.readlink("/proc/self/ns/" + name) == expected:
        raise RuntimeError("host namespace visible")

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
    conn.settimeout(20)
    conn.connect("/ipc/broker.sock")
    stream = conn.makefile("rwb")
    seq = 0

    def rpc(method, params):
        global seq
        seq += 1
        stream.write(json.dumps({"jsonrpc": "2.0", "id": seq, "method": method,
                                 "params": params}).encode() + b"\n")
        stream.flush()
        line = stream.readline(65537)
        if not 0 < len(line) <= 65536:
            raise RuntimeError("bad broker response")
        row = json.loads(line)
        if row.get("id") != seq or "error" in row:
            raise RuntimeError("RPC response mismatch")
        return row["result"]

    def tool(name, args=None, denied=False):
        row = rpc("tools/call", {"name": name, "arguments": args or {}})
        if row.get("isError") is not denied:
            raise RuntimeError("unexpected broker outcome")
        return None if denied else json.loads(row["content"][0]["text"])

    rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "fixed-parent-probe", "version": "1"}})
    listed = rpc("tools/list", {})
    if {row["name"] for row in listed["tools"]} != {
            "inspect_task", "read_candidate", "replace_candidate", "run_tests"}:
        raise RuntimeError("tool allowlist mismatch")
    task = tool("inspect_task")
    seed = tool("read_candidate")
    if tool("run_tests")["status"] != "RED":
        raise RuntimeError("missing RED")

    # Real broker journal/seed files now exist on the host. Neither ordinary
    # paths nor /proc/1/root may expose them inside this PID/mount namespace.
    for path in host["protected_paths"]:
        for candidate in (path, "/proc/1/root" + path):
            for flags in (os.O_RDONLY, os.O_WRONLY):
                try:
                    fd = os.open(candidate, flags | os.O_NOFOLLOW)
                except OSError as error:
                    if error.errno not in (errno.ENOENT, errno.EACCES, errno.EPERM):
                        raise
                else:
                    os.close(fd)
                    raise RuntimeError("host file exposed")
    try:
        fd = os.open(host["forged_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno not in (errno.ENOENT, errno.EACCES, errno.EPERM):
            raise
    else:
        os.close(fd)
        raise RuntimeError("journal creation exposed")

    try:
        peer = socket.create_connection(("127.0.0.1", host["tcp_port"]), timeout=1)
    except OSError as error:
        if error.errno not in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH,
                               errno.EACCES, errno.EPERM):
            raise
    else:
        peer.close()
        raise RuntimeError("host TCP listener exposed")

    marker = Path("/scratch/positive")
    marker.write_bytes(b"ok")
    if marker.read_bytes() != b"ok":
        raise RuntimeError("scratch write failed")
    tool("bash", {"command": "true"}, denied=True)
    tool("read_candidate", {"path": host["protected_paths"][0]}, denied=True)

    role = task["role"]
    source = (f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
              "    gates = " + repr(tuple(task["gates"])) + "\n"
              "    missing = sorted([name for name in gates if evidence.get(name) is not True])\n"
              f"    return {{'backend': {role!r}, 'missingGates': missing, "
              "'installationAuthorized': False, 'releaseEligible': False}\n")
    tool("replace_candidate", {"expected_sha256": "0"*64, "source": source}, denied=True)
    tool("replace_candidate", {"expected_sha256": seed["sha256"], "source": source})
    final = tool("run_tests")
    if final["status"] != "PASS" or final["cases"] != 259:
        raise RuntimeError("missing GREEN")
    stream.close()
print("PARENT_BOUNDARY_PROBE_PASS")
'''


def sandbox_base():
    # No host root, checkout, home, /run, /sys, control or state mount.
    # Explicit namespace flags, not best-effort isolation. Never relax
    # AppArmor/userns settings or fall back to a non-isolated process.
    if not BWRAP.is_file() or BWRAP.is_symlink():
        raise ValueError("BWRAP_UNAVAILABLE")
    args = [str(BWRAP), "--unshare-user", "--disable-userns", "--unshare-pid",
            "--unshare-net", "--unshare-ipc", "--unshare-uts", "--die-with-parent",
            "--new-session", "--cap-drop", "ALL", "--clearenv"]
    for location in ("/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"):
        if Path(location).exists():
            args.extend(("--ro-bind", location, location))
    return args + ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]


class BoundaryFailure(ValueError):
    """Fixed diagnostic, never disclose raw stderr or host paths."""


def classify_failure(stderr):
    raw = stderr.lower()
    if b"bwrap:" in raw:
        if any(x in raw for x in (b"permission denied", b"operation not permitted",
                                  b"no permissions", b"new namespace")):
            return "BWRAP_NAMESPACE_DENIED"
        if b"unknown option" in raw:
            return "BWRAP_OPTION_UNSUPPORTED"
        return "BWRAP_SETUP_FAILED"
    if b"host namespace visible" in raw:
        return "HOST_NAMESPACE_EXPOSED"
    if b"host file exposed" in raw or b"journal creation exposed" in raw:
        return "HOST_FILE_EXPOSED"
    if b"host tcp listener exposed" in raw:
        return "HOST_TCP_EXPOSED"
    if b"missing red" in raw or b"missing green" in raw:
        return "BROKER_RED_GREEN_FAILED"
    if b"rpc response mismatch" in raw or b"bad broker response" in raw:
        return "BROKER_PROTOCOL_FAILED"
    return "PARENT_CLIENT_FAILED"


def namespace_preflight():
    # Fail before starting the external broker or waiting on accept().
    result = subprocess.run(sandbox_base() + ["/usr/bin/true"],
                            env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=15, check=False)
    if result.returncode != 0 or result.stdout:
        raise BoundaryFailure(classify_failure(result.stderr))


def sandbox_argv(scratch, endpoint, data):
    return sandbox_base() + ["--dir", "/ipc", "--bind", str(scratch), "/scratch",
                   "--ro-bind", str(endpoint), "/ipc/broker.sock",
                   "--setenv", "HOME", "/scratch", "--setenv", "PATH", "/usr/bin:/bin",
                   "--chdir", "/scratch", "/usr/bin/python3", "-I", "-B", "-c",
                   CLIENT, json.dumps(data, sort_keys=True)]


def run():
    if os.geteuid() == 0:
        raise ValueError("UNPRIVILEGED_RUNNER_REQUIRED")
    namespace_preflight()
    with tempfile.TemporaryDirectory(prefix="gaslux-parent-") as tmp:
        root = Path(tmp)
        state, control, scratch = (root / n for n in ("state", "control", "scratch"))
        for directory in (state, control, scratch):
            directory.mkdir(mode=0o700)
        outside = root / "outside-sentinel"
        broker.write_new(outside, iterative.SENTINEL)
        task = control / "task.json"
        task_data = json.dumps(iterative.task_for("mint"), sort_keys=True).encode()
        broker.write_new(task, task_data)
        endpoint = root / "broker.sock"
        outcome = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            server.bind(str(endpoint))
            endpoint.chmod(0o600)
            server.listen(1)
            server.settimeout(25)
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(1)
            tcp.setblocking(False)

            def serve():
                try:
                    with server.accept()[0] as conn:
                        # External broker is the controller's child, never a child
                        # of the untrusted namespace. It inherits no agent FDs.
                        with subprocess.Popen(
                            ["/usr/bin/python3", "-I", "-B", str(Path(broker.__file__).resolve()),
                             "--work", str(state), "--task", str(task), "--outside", str(outside)],
                            stdin=conn, stdout=conn, stderr=subprocess.DEVNULL,
                            env={"PATH": "/usr/bin:/bin", "HOME": str(control)},
                            close_fds=True, cwd=control,
                        ) as process:
                            try:
                                outcome.append(process.wait(timeout=TIMEOUT) == 0)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait()
                                outcome.append(False)
                except (OSError, ValueError):
                    outcome.append(False)

            data = {"namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in NAMESPACES},
                    "protected_paths": [str(x) for x in (outside, task, state / "event-00.json",
                                                         state / "candidate-0.py")],
                    "forged_path": str(state / "forged"),
                    "tcp_port": tcp.getsockname()[1]}
            argv = sandbox_argv(scratch, endpoint, data)
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                result = subprocess.run(argv, env={"PATH": "/usr/bin:/bin"},
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=TIMEOUT, check=False)
            finally:
                worker.join(timeout=TIMEOUT + 26)
            if result.returncode != 0:
                raise BoundaryFailure(classify_failure(result.stderr))
            if worker.is_alive() or outcome != [True]:
                raise BoundaryFailure("EXTERNAL_BROKER_EXIT_FAILED")
            if result.stdout != b"PARENT_BOUNDARY_PROBE_PASS\n":
                raise BoundaryFailure("PARENT_CLIENT_WITNESS_MISSING")
            try:
                peer, _ = tcp.accept()
            except BlockingIOError:
                pass
            else:
                peer.close()
                raise ValueError("HOST_TCP_REACHED")
        if (broker.read_bounded(outside, 64) != iterative.SENTINEL
                or broker.read_bounded(task, 32768) != task_data
                or (state / "forged").exists()):
            raise ValueError("HOST_STATE_CHANGED")
        proof = iterative.verify_journal(state, ACTIONS, "mint")
        return {"synthetic_parent_boundary_verified": True, "namespace_count": len(NAMESPACES),
                "host_files_hidden": True, "host_tcp_denied": True,
                "external_broker_verified": True, "functional_cases": proof["functional_cases"],
                "candidate_sha256": proof["candidate_sha256"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"kind": "synthetic_parent_namespace_admission", "accepted": False,
              "opencode_os_sandbox_verified": False, "synthetic_parent_boundary_verified": False,
              "model_inference_executed": False, "merge_authorized": False,
              "writer_authorized": False, "release_eligible": False}
    try:
        report.update(run())
        report["accepted"] = True
    except BoundaryFailure as error:
        report["failure"] = str(error)
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["failure"] = type(error).__name__
    broker.write_new(args.report, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
