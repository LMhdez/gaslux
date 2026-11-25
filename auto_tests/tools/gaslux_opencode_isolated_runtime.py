#!/usr/bin/env python3
"""Run the pinned real OpenCode behind mandatory Bubblewrap and two fixed sockets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time

# Inside the namespace this file is a read-only stdlib-only relay/launcher.
# Controller-only modules are imported lazily and never mounted.
BROKER_SOCKET = "/ipc/broker.sock"
MODEL_SOCKET = "/ipc/model.sock"
MODEL_PORT = 11435
MAX_RELAY = 8 * 1024 * 1024
TIMEOUT = 1200
SKILL_NAME = "gaslux-history-reuse"
SKILL_DIR = "/scratch/.opencode/skills/" + SKILL_NAME
SKILL_PATH = SKILL_DIR + "/SKILL.md"
SKILL_PREFLIGHT_LIMIT = 128 * 1024
SKILL_PREFLIGHT_TIMEOUT = 45


def relay(source, sink, peer, *, timeout=TIMEOUT):
    """Bound bytes in both directions; no target selection or command execution."""
    deadline = time.monotonic() + timeout
    peer.settimeout(300)
    count = [0, 0]
    with selectors.DefaultSelector() as sel:
        sel.register(source, selectors.EVENT_READ, 0)
        sel.register(peer, selectors.EVENT_READ, 1)
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("RELAY_TIMEOUT")
            for key, _ in sel.select(min(remaining, 1)):
                data = os.read(key.fd, 65536)
                direction = key.data
                if not data:
                    sel.unregister(key.fileobj)
                    if direction == 0:
                        peer.shutdown(socket.SHUT_WR)
                    else:
                        # Server EOF terminates the session; never hang on stdin.
                        return
                    continue
                count[direction] += len(data)
                if count[direction] > MAX_RELAY:
                    raise ValueError("RELAY_LIMIT")
                if direction == 0:
                    peer.sendall(data)
                else:
                    view = memoryview(data)
                    while view:
                        written = os.write(sink, view)
                        if written <= 0:
                            raise OSError("RELAY_WRITE")
                        view = view[written:]


def mcp_relay():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.connect(BROKER_SOCKET)
        relay(0, 1, peer)


class ModelBridge(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.connect(MODEL_SOCKET)
            self.request.settimeout(300)
            relay(self.request.fileno(), self.request.fileno(), peer, timeout=310)


class BridgeServer(socketserver.TCPServer):
    allow_reuse_address = False
    def handle_error(self, *_):
        # A bridge transport failure cannot be considered a completed response.
        self.failed += 1


def preflight_command(argv, *, cwd="/scratch"):
    # Fixed debug invocations, not agent commands. Disable MCP for these
    # processes only so discovery cannot consume the real broker session.
    env = dict(os.environ)
    env["OPENCODE_CONFIG_CONTENT"] = json.dumps({
        "mcp": {"gaslux_workspace": {"type": "local",
            "command": ["/usr/bin/python3", "-I", "-B", "/opt/relay.py", "mcp"],
            "enabled": False}},
    })
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=SKILL_PREFLIGHT_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("SKILL_PREFLIGHT_PROCESS_FAILED") from None
    if (result.returncode != 0 or len(result.stdout) > SKILL_PREFLIGHT_LIMIT
            or len(result.stderr) > SKILL_PREFLIGHT_LIMIT):
        raise RuntimeError("SKILL_PREFLIGHT_PROCESS_FAILED")
    return result.stdout


def skill_preflight():
    # OpenCode v1.19.6 SkillTool.execute calls Ripgrep.find. Without rg it
    # attempts a network download. Require the existing read-only /usr mount.
    binary = Path("/usr/bin/rg")
    if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
        raise RuntimeError("SKILL_RIPGREP_MISSING")
    version = preflight_command([str(binary), "--version"])
    if not version.startswith(b"ripgrep "):
        raise RuntimeError("SKILL_RIPGREP_INVALID")
    path = Path(SKILL_PATH)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16384:
        raise RuntimeError("SKILL_LOCAL_FILE_INVALID")
    try:
        body = path.read_text(encoding="utf-8").split("---", 2)[2].strip()
        rows = json.loads(preflight_command(["/opt/opencode", "debug", "skill"]))
    except (ValueError, TypeError, IndexError, OSError):
        raise RuntimeError("SKILL_DISCOVERY_INVALID") from None
    if type(rows) is not list or len(rows) > 8 or any(type(row) is not dict for row in rows):
        raise RuntimeError("SKILL_DISCOVERY_INVALID")
    matches = [row for row in rows if row.get("name") == SKILL_NAME]
    if (len(matches) != 1 or matches[0].get("location") != SKILL_PATH
            or type(matches[0].get("content")) is not str
            or matches[0]["content"].strip() != body
            or any(row.get("name") not in (SKILL_NAME, "customize-opencode") for row in rows)):
        raise RuntimeError("SKILL_DISCOVERY_INVALID")
    # Exercise the pinned CLI's native Ripgrep service in the exact directory.
    listing = preflight_command(
        ["/opt/opencode", "debug", "rg", "files", "--glob", "SKILL.md", "--limit", "10"],
        cwd=SKILL_DIR)
    if listing.strip() != b"SKILL.md":
        raise RuntimeError("SKILL_NATIVE_RIPGREP_INVALID")
    return True


def namespace_launch(data, prompt):
    # Trusted read-only launcher runs in precisely the namespace used by OpenCode.
    for name, host in data["namespaces"].items():
        if os.readlink("/proc/self/ns/" + name) == host:
            raise RuntimeError("NAMESPACE_NOT_ISOLATED")
    for path in data["protected_paths"]:
        for candidate in (path, "/proc/1/root" + path):
            if os.path.exists(candidate):
                raise RuntimeError("HOST_PATH_VISIBLE")
    try:
        conn = socket.create_connection(("127.0.0.1", 11434), timeout=1)
    except OSError:
        pass
    else:
        conn.close()
        raise RuntimeError("HOST_OLLAMA_VISIBLE")
    skill_preflight()
    print("GASLUX_NATIVE_SKILL_PREFLIGHT_PASS", file=sys.stderr, flush=True)
    with BridgeServer(("127.0.0.1", MODEL_PORT), ModelBridge) as server:
        server.failed = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print("GASLUX_REAL_NAMESPACE_ADMITTED", file=sys.stderr, flush=True)
        try:
            result = subprocess.run(
                ["/opt/opencode", "run", "--format", "json", "--agent", "gaslux-lab",
                 "--model", "ollama/qwen3.5:9b", prompt],
                stdin=subprocess.DEVNULL, check=False)
        finally:
            server.shutdown()
            thread.join(5)
        if server.failed or thread.is_alive():
            return 1
        return result.returncode


def isolated_config(work, context):
    import gaslux_opencode_trial as trial
    import gaslux_opencode_iterative as iterative
    config = trial.prepare(work, context=context)
    # Only the authorized skill is needed in this bounded agent. Other
    # portable skills remain available in the separate historical trial.
    for folder in (work / ".opencode" / "skills").iterdir():
        if folder.name != trial.SKILL:
            shutil.rmtree(folder)
    permissions = {"*": "deny", "skill": {"*": "deny", trial.SKILL: "allow"}}
    permissions.update({tool: "allow" for tool in iterative.REQUIRED})
    config["permission"] = permissions
    config["agent"]["gaslux-lab"].update({
        "steps": 12, "permission": permissions,
        "prompt": (
            "You are a bounded Gaslux lifecycle test agent. Use only the five "
            "authorized tools, one call at a time. Load gaslux-history-reuse "
            "first; its repository research steps are already supplied as data "
            "in inspect_task. Then inspect, read, test RED, edit with current SHA, "
            "test PASS. Do not run shell or access other paths. Stop after PASS."
        ),
    })
    config["provider"]["ollama"]["models"]["qwen3.5:9b"]["options"] = {
        "reasoningEffort": "none",
    }
    config["skills"] = {"paths": ["/scratch/.opencode/skills"], "urls": []}
    config["provider"]["ollama"]["options"]["baseURL"] = "http://127.0.0.1:11435/v1"
    config["mcp"] = {"gaslux_workspace": {
        "type": "local", "enabled": True, "timeout": 20000,
        "command": ["/usr/bin/python3", "-I", "-B", "/opt/relay.py", "mcp"]}}
    (work / "opencode.json").write_text(json.dumps(config), encoding="utf-8")
    return config


def proxy_complete(stats):
    return (type(stats) is dict and
            all(type(stats.get(k)) is int for k in ("calls", "forwarded", "completed", "denied"))
            and stats["denied"] == 0 and 0 < stats["calls"] == stats["forwarded"] == stats["completed"])


def run(binary, root, role, context, prompt, report, *, product=None, timeout=TIMEOUT):
    import gaslux_opencode_iterative as iterative
    import gaslux_opencode_model_proxy as proxy
    import gaslux_opencode_parent_boundary as boundary
    import gaslux_opencode_trial as trial
    import gaslux_opencode_workspace as broker

    if type(timeout) is not int or not 1 <= timeout <= TIMEOUT:
        raise ValueError("BOUNDARY_TIMEOUT_SCOPE")
    if os.geteuid() == 0:
        raise ValueError("UNPRIVILEGED_RUNNER_REQUIRED")
    boundary.namespace_preflight()
    state, control, scratch = (root / name for name in ("state", "control", "scratch"))
    for path in (state, control, scratch):
        path.mkdir(mode=0o700)
    outside = root / "outside-sentinel"
    broker.write_new(outside, iterative.SENTINEL)
    task = control / "task.json"
    task_data = json.dumps(iterative.task_for(role, product), sort_keys=True).encode()
    if len(task_data) > 32768:
        raise ValueError("TASK_CONTEXT_LIMIT")
    broker.write_new(task, task_data)
    isolated_config(scratch, context)
    (scratch / "home").mkdir(mode=0o700)
    broker_endpoint, model_endpoint = root / "broker.sock", root / "model.sock"
    stop = threading.Event()
    outcome = []
    broker_process = []
    report["failure_stage"] = "namespace_launch"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(broker_endpoint))
        broker_endpoint.chmod(0o600)
        listener.listen(1)
        listener.settimeout(1)
        with proxy.ModelServer(model_endpoint, proxy.Handler, compact_tools=True) as model:
            model_endpoint.chmod(0o600)
            model.timeout = 0.25
            model.deadline = time.monotonic() + timeout

            def serve_broker():
                try:
                    while not stop.is_set():
                        try:
                            conn, _ = listener.accept()
                        except socket.timeout:
                            continue
                        with conn:
                            with subprocess.Popen(
                                ["/usr/bin/python3", "-I", "-B", str(Path(broker.__file__).resolve()),
                                 "--work", str(state), "--task", str(task), "--outside", str(outside)],
                                stdin=conn, stdout=conn, stderr=subprocess.DEVNULL,
                                env={"PATH": "/usr/bin:/bin", "HOME": str(control)},
                                cwd=control, close_fds=True, start_new_session=True,
                            ) as child:
                                broker_process.append(child)
                                outcome.append(child.wait(timeout=timeout) == 0)
                        return
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    outcome.append(False)
                    if broker_process and broker_process[-1].poll() is None:
                        broker_process[-1].kill()
                        broker_process[-1].wait()

            def serve_model():
                while not stop.is_set():
                    model.handle_request()

            threads = [threading.Thread(target=target, daemon=True)
                       for target in (serve_broker, serve_model)]
            data = {"namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in boundary.NAMESPACES},
                    "protected_paths": [str(x) for x in (outside, task, state, control)]}
            argv = boundary.sandbox_base() + [
                "--dir", "/ipc", "--dir", "/opt",
                "--bind", str(scratch), "/scratch",
                "--ro-bind", str(broker_endpoint), BROKER_SOCKET,
                "--ro-bind", str(model_endpoint), MODEL_SOCKET,
                "--ro-bind", str(binary), "/opt/opencode",
                "--ro-bind", str(Path(__file__).resolve()), "/opt/relay.py",
                "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/scratch/home",
                "--setenv", "XDG_CONFIG_HOME", "/scratch/home/config",
                "--setenv", "XDG_CACHE_HOME", "/scratch/home/cache",
                "--setenv", "XDG_DATA_HOME", "/scratch/home/data",
                "--setenv", "XDG_STATE_HOME", "/scratch/home/state",
                "--setenv", "OPENCODE_CONFIG", "/scratch/opencode.json",
                "--setenv", "OPENCODE_DISABLE_AUTOUPDATE", "true",
                "--setenv", "OPENCODE_DISABLE_DEFAULT_PLUGINS", "true",
                "--setenv", "OPENCODE_DISABLE_CLAUDE_CODE", "true",
                "--setenv", "OPENCODE_DISABLE_EXTERNAL_SKILLS", "true",
                "--setenv", "CI", "true", "--setenv", "TERM", "dumb",
                "--chdir", "/scratch", "/usr/bin/python3", "-I", "-B", "/opt/relay.py",
                "launch", json.dumps(data, sort_keys=True), prompt]
            for thread in threads:
                thread.start()
            result = None
            try:
                result = trial.bounded_process(argv, scratch, {"PATH": "/usr/bin:/bin"}, timeout=timeout)
            finally:
                stop.set()
                threads[0].join(5)
                if threads[0].is_alive() and broker_process and broker_process[-1].poll() is None:
                    broker_process[-1].kill()
                threads[0].join(5)
                threads[1].join(proxy.TIMEOUT + 5)
                report["proxy"] = {k: getattr(model, k) for k in ("calls", "forwarded", "completed", "denied")}
                report["proxy_diagnostics"] = {"denial_categories": dict(model.denial_categories),
                                               "inference_seconds": list(model.inference_seconds),
                                               "profile": "compact-sequential-tools-v1"}
                report["broker_exit_clean"] = outcome == [True]
                report["broker_journal_files"] = min(len(list(state.glob("event-*.json"))), broker.MAX_CALLS + 3)
                if any(thread.is_alive() for thread in threads):
                    raise ValueError("BOUNDARY_CLEANUP_FAILED")
            code, raw, stderr = result
            report["namespace_launcher_admitted"] = b"GASLUX_REAL_NAMESPACE_ADMITTED\n" in stderr.splitlines(keepends=True)
            report["native_skill_preflight"] = b"GASLUX_NATIVE_SKILL_PREFLIGHT_PASS\n" in stderr.splitlines(keepends=True)
            report["failure_stage"] = "native_events"
            # Even on nonzero exit, retain only partial validated event metadata.
            report["cli_exit_code"] = code
            if code:
                try:
                    iterative.native_events(raw, report)
                except (ValueError, TypeError, KeyError) as error:
                    report["native_event_failure"] = iterative.fixed_failure(error)
                raise trial.TrialFailure("CLI_NONZERO", detail=boundary.classify_failure(stderr))
            events, skills = iterative.native_events(raw, report)
            if not report["namespace_launcher_admitted"]:
                raise ValueError("NAMESPACE_WITNESS_MISSING")
            if not report["native_skill_preflight"]:
                raise ValueError("SKILL_PREFLIGHT_WITNESS_MISSING")
            if not proxy_complete(report["proxy"]):
                raise ValueError("PROXY_COMPLETION_REQUIRED")
            if outcome != [True]:
                raise ValueError("EXTERNAL_BROKER_EXIT_FAILED")
            if (broker.read_bounded(outside, 64) != iterative.SENTINEL
                    or broker.read_bounded(task, 32768) != task_data):
                raise ValueError("OUTSIDE_MUTATED")
            return state, events, skills


if __name__ == "__main__":
    # Invoked only through a fixed read-only mount within the namespace.
    if len(sys.argv) == 2 and sys.argv[1] == "mcp":
        mcp_relay()
    elif len(sys.argv) == 4 and sys.argv[1] == "launch":
        raise SystemExit(namespace_launch(json.loads(sys.argv[2]), sys.argv[3]))
    else:
        raise SystemExit(2)
