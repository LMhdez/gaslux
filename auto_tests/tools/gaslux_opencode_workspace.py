#!/usr/bin/env python3
"""Pathless, bounded local MCP workspace; never writes a product checkout."""
from __future__ import annotations

import argparse
import ctypes
import errno
import itertools
import json
import os
from pathlib import Path
import platform
import resource
import select
import signal
import socket
import stat
import sys

# -I -B ignores environment and cwd. Import the copied trusted validator only.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gaslux_agent_feature_factory as factory

MAX_LINE = 65536
MAX_SOURCE = 5500
MAX_CALLS = 16
MAX_EDITS = 3
MAX_JOURNAL = 32768
TOOLS = ("inspect_task", "read_candidate", "replace_candidate", "run_tests")
# Linux x86_64 syscall ABI; fail closed on any unsupported runner/kernel.
LANDLOCK_CREATE, LANDLOCK_ADD, LANDLOCK_RESTRICT = 444, 445, 446
FS_ALL = (1 << 15) - 1  # ABI 3: execute, read/write, create/remove, refer, truncate
FS_READ_WRITE = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 8)  # write, read, read_dir, make_reg
NET_ALL = 3  # ABI 4: bind/connect TCP
PR_SET_NO_NEW_PRIVS = 38
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
LIBC.prctl.restype = ctypes.c_int


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def syscall(number, *args):
    result = LIBC.syscall(ctypes.c_long(number), *args)
    if result < 0:
        raise OSError(ctypes.get_errno(), "Landlock syscall failed")
    return result


def restrict(work=None):
    """Deny all handled FS/TCP access except explicitly allowed workspace."""
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("Unsupported sandbox architecture")
    abi = syscall(LANDLOCK_CREATE, ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint(1))
    if abi < 4:
        raise RuntimeError("Landlock ABI 4 required")
    rules = Ruleset(FS_ALL, NET_ALL)
    fd = syscall(LANDLOCK_CREATE, ctypes.byref(rules), ctypes.c_size_t(ctypes.sizeof(rules)),
                 ctypes.c_uint(0))
    try:
        if work is not None:
            directory = os.open(work, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                rule = PathRule(FS_READ_WRITE, directory)
                syscall(LANDLOCK_ADD, ctypes.c_int(fd), ctypes.c_int(1), ctypes.byref(rule),
                        ctypes.c_uint(0))
            finally:
                os.close(directory)
        if LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "no_new_privs failed")
        syscall(LANDLOCK_RESTRICT, ctypes.c_int(fd), ctypes.c_uint(0))
    finally:
        os.close(fd)
    return abi


def expect_denied(action):
    try:
        action()
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            return
        raise
    raise RuntimeError("Sandbox negative probe unexpectedly succeeded")


def probe(work, outside):
    # The parent creates the outside sentinel and verifies it is unchanged.
    def read_outside():
        fd = os.open(outside, os.O_RDONLY | os.O_NOFOLLOW)
        os.close(fd)

    def write_outside():
        fd = os.open(outside, os.O_WRONLY | os.O_NOFOLLOW)
        os.close(fd)

    def tcp():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.settimeout(1)
            conn.connect(("127.0.0.1", 11434))

    expect_denied(read_outside)
    expect_denied(write_outside)
    expect_denied(tcp)
    marker = work / "sandbox-positive"
    with marker.open("xb") as out:
        out.write(b"ok")
    if marker.read_bytes() != b"ok":
        raise RuntimeError("Workspace positive probe failed")
    return {"outside_read_denied": True, "outside_write_denied": True,
            "tcp_connect_denied": True, "workspace_read_write": True}


def seed_source(role):
    # Deliberately defective test fixture, never a product change.
    return (f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
            f"    return {{'backend': {role!r}, 'missingGates': [], "
            "'installationAuthorized': False, 'releaseEligible': False}\n")


def validate_source(role, source):
    if type(source) is not str or len(source.encode("utf-8")) > MAX_SOURCE:
        raise ValueError("SOURCE_SIZE")
    factory.validate_addition(role, source, execute=False)


def exhaustive(role, source):
    factory.validate_addition(role, source, execute=True)
    env = {"__builtins__": factory.SAFE_BUILTINS}
    namespace = {}
    exec(compile(source, "<isolated-iteration>", "exec"), env, namespace)
    fn = namespace[f"assess_{role}_lifecycle"]
    # Every combination of the eight gates, plus absent and truthy non-booleans.
    fixtures = ({g: v for g, v in zip(factory.GATES, bits)}
                for bits in itertools.product((False, True), repeat=len(factory.GATES)))
    cases = 0
    for evidence in itertools.chain(fixtures, ({}, dict.fromkeys(factory.GATES, 1),
                                               dict.fromkeys(factory.GATES, "true"))):
        before = dict(evidence)
        result = fn(evidence)
        expected = {"backend": role,
                    "missingGates": sorted(g for g in factory.GATES if before.get(g) is not True),
                    "installationAuthorized": False, "releaseEligible": False}
        if (type(result) is not dict or set(result) != set(expected) or result != expected
                or result["installationAuthorized"] is not False
                or result["releaseEligible"] is not False or evidence != before
                or type(result["missingGates"]) is not list):
            raise ValueError("DIFFERENTIAL_REJECTED")
        cases += 1
    return cases


def isolated_test(role, source, timeout=5):
    """Separate fork: no FS/TCP access, bounded CPU/memory/time; fixed status only."""
    validate_source(role, source)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        result = b"WORKER_FAILURE"
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
            restrict()  # no allowed paths or TCP ports
            try:
                cases = exhaustive(role, source)
                result = b"PASS_259" if cases == 259 else b"WORKER_FAILURE"
            except (ValueError, TypeError, KeyError, SyntaxError, NameError, ArithmeticError):
                result = b"REJECTED"
        except BaseException:
            pass
        try:
            os.write(write_fd, result)
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], timeout)
        if not ready:
            return "TIMEOUT"
        result = os.read(read_fd, 64)
        return {b"PASS_259": "PASS", b"REJECTED": "RED",
                b"WORKER_FAILURE": "WORKER_FAILURE"}.get(result, "WORKER_FAILURE")
    finally:
        os.close(read_fd)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)


SCHEMAS = {
    "inspect_task": ("Read the reviewed task, bounded history references and acceptance contract.",
                     {"type": "object", "properties": {}, "additionalProperties": False}),
    "read_candidate": ("Read current candidate function and exact SHA-256.",
                       {"type": "object", "properties": {}, "additionalProperties": False}),
    "replace_candidate": ("Replace only the candidate function; provide current SHA and complete source.",
                          {"type": "object", "properties": {
                              "expected_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                              "source": {"type": "string", "maxLength": MAX_SOURCE}},
                           "required": ["expected_sha256", "source"], "additionalProperties": False}),
    "run_tests": ("Run the fixed independent AST/functional suite on the current candidate.",
                  {"type": "object", "properties": {}, "additionalProperties": False}),
}


def write_new(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(payload)
        out.flush()
        os.fsync(out.fileno())


def read_bounded(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as inp:
        st = os.fstat(inp.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > maximum:
            raise ValueError("Unsafe input")
        result = inp.read(maximum + 1)
    if len(result) > maximum:
        raise ValueError("Oversized input")
    return result


class Workspace:
    def __init__(self, work, task, *, sandbox=None, tester=isolated_test):
        self.work, self.task, self.role = work, task, task["role"]
        if self.role not in factory.TASKS:
            raise ValueError("Unknown role")
        self.tester = tester
        self.source = seed_source(self.role)
        self.sha = factory.sha256(self.source.encode())
        self.calls = self.edits = 0
        self.inspected = self.read = self.red = False
        self.tested_sha = None
        self.journal = [{"event": "sandbox", "proof": sandbox or {}},
                        {"event": "seed", "sha256": self.sha}]
        write_new(work / "candidate-0.py", self.source.encode())
        self.log(self.journal[0])
        self.log(self.journal[1])

    def log(self, row):
        # Each event is a new exclusive file, fixed names, bounded metadata.
        number = len(list(self.work.glob("event-*.json")))
        raw = json.dumps(row, sort_keys=True).encode()
        if number >= MAX_CALLS + 3 or len(raw) > 2048:
            raise ValueError("Journal limit")
        write_new(self.work / f"event-{number:02}.json", raw)

    def call(self, name, args):
        self.calls += 1
        if self.calls > MAX_CALLS:
            raise ValueError("CALL_LIMIT")
        if name not in TOOLS or type(args) is not dict:
            raise ValueError("UNKNOWN_TOOL")
        if name == "replace_candidate":
            if set(args) != {"expected_sha256", "source"}:
                raise ValueError("ARGUMENTS")
        elif args:
            raise ValueError("ARGUMENTS")
        if name == "inspect_task":
            self.inspected = True
            self.log({"event": name})
            return self.task
        if not self.inspected:
            raise ValueError("INSPECT_FIRST")
        if name == "read_candidate":
            self.read = True
            self.log({"event": name, "sha256": self.sha})
            return {"source": self.source, "sha256": self.sha}
        if not self.read:
            raise ValueError("READ_FIRST")
        if name == "run_tests":
            outcome = self.tester(self.role, self.source)
            if outcome == "RED" and self.edits == 0:
                self.red = True
            self.tested_sha = self.sha
            self.log({"event": name, "sha256": self.sha, "status": outcome})
            return {"status": outcome, "sha256": self.sha,
                    "cases": 259 if outcome == "PASS" else 0,
                    "diagnosis": "Every absent, false or non-boolean gate must be missing; protected flags false."}
        if not self.red or self.tested_sha != self.sha:
            raise ValueError("TEST_CURRENT_REVISION_FIRST")
        if self.edits >= MAX_EDITS or args["expected_sha256"] != self.sha:
            raise ValueError("EDIT_LIMIT_OR_STALE_SHA")
        source = args["source"]
        validate_source(self.role, source)
        new_sha = factory.sha256(source.encode())
        if new_sha == self.sha:
            raise ValueError("UNCHANGED_CANDIDATE")
        write_new(self.work / f"candidate-{self.edits + 1}.py", source.encode())
        before = self.sha
        self.edits += 1
        self.source, self.sha = source, new_sha
        self.tested_sha = None
        self.log({"event": name, "before": before, "sha256": new_sha})
        return {"status": "EDITED", "sha256": new_sha}


def rpc(workspace, msg):
    if type(msg) is not dict or msg.get("jsonrpc") != "2.0":
        raise ValueError("RPC_SHAPE")
    method = msg.get("method")
    params = msg.get("params", {})
    if type(params) is not dict:
        raise ValueError("RPC_PARAMS")
    if "id" not in msg:
        return None
    ident = msg["id"]
    if type(ident) not in (int, str) or (type(ident) is str and len(ident) > 128):
        raise ValueError("RPC_ID")
    response = {"jsonrpc": "2.0", "id": ident}
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in ("2024-11-05", "2025-03-26", "2025-06-18",
                                             "2025-11-25") else "2025-03-26"
        result = {"protocolVersion": version, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "gaslux-workspace", "version": "1.0.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{"name": n, "description": d, "inputSchema": schema}
                            for n, (d, schema) in SCHEMAS.items()]}
    elif method == "tools/call":
        try:
            if set(params) - {"name", "arguments", "_meta"}:
                raise ValueError("RPC_TOOL_PARAMS")
            value = workspace.call(params.get("name"), params.get("arguments", {}))
            result = {"content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}],
                      "isError": False}
        except (ValueError, TypeError, SyntaxError, KeyError, OSError):
            # Never return untrusted exception text or filesystem paths.
            result = {"content": [{"type": "text", "text": "Rejected by bounded workspace contract."}],
                      "isError": True}
    else:
        response["error"] = {"code": -32601, "message": "Unsupported method"}
        return response
    response["result"] = result
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--task", required=True, type=Path)
    parser.add_argument("--outside", required=True, type=Path)
    args = parser.parse_args()
    task = json.loads(read_bounded(args.task, 32768))
    work = args.work.resolve(strict=True)
    if not work.is_dir() or work.is_symlink() or any(work.iterdir()):
        raise SystemExit("Workspace must be fresh")
    os.chdir(work)
    abi = restrict(work)
    proof = probe(work, args.outside)
    proof["landlock_abi"] = abi
    workspace = Workspace(work, task, sandbox=proof)
    for _ in range(64):
        line = sys.stdin.buffer.readline(MAX_LINE + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE:
            return 1
        try:
            msg = json.loads(line)
            response = rpc(workspace, msg)
        except (ValueError, TypeError, KeyError):
            return 1
        if response is not None:
            print(json.dumps(response, separators=(",", ":")), flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
