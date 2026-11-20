"""Host-side *connect-only* probe of a dedicated Unix-UID QEMU laboratory.

No event encoder, proxy or QMP command forwarding. The original runner UID
can invoke sudo on GitHub-hosted runners: this is an operational DAC test,
NOT a security boundary against an attacker controlling sudo or CI source.
"""

from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .evidence import Refusal, canonical


def _connect_as_runner(path: str) -> int:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(path)
    except PermissionError:
        return 13
    except OSError:
        return 14
    return 0


def _connect_as_nobody(path: str) -> int:
    code = (
        "import socket,sys;"
        "s=socket.socket(socket.AF_UNIX);p=sys.argv[1];"
        "result=0;"
        "exec('try:\\n s.connect(p)\\nexcept PermissionError:\\n result=13"
        "\\nexcept OSError:\\n result=14');"
        "s.close();sys.exit(result)"
    )
    proc = subprocess.run(
        ["sudo", "-n", "-u", "nobody", "/usr/bin/python3", "-c", code, path],
        capture_output=True,
        timeout=8,
        check=False,
    )
    return proc.returncode


def run(private_root: Path, service_user: str, public_evidence: Path) -> None:
    if os.geteuid() == 0 or not private_root.is_absolute():
        raise Refusal("Unprivileged runner and absolute private root required")
    if service_user != "gaslux_observer_ci":
        raise Refusal("Unexpected isolated service account")
    if private_root.is_symlink() or not private_root.name.startswith("gaslux-obs-"):
        raise Refusal("Unexpected private scratch root")
    if public_evidence.exists():
        raise Refusal("Evidence destination already exists")
    import pwd

    dedicated_uid = pwd.getpwnam(service_user).pw_uid
    if dedicated_uid == os.geteuid() or dedicated_uid == 0:
        raise Refusal("Dedicated UID must differ from original runner and root")
    # The root folder is 0700 owned by dedicated_uid. These are supplementary
    # barriers, not a defense against privileged original-runner escalation.
    info = private_root.stat()
    if info.st_uid != dedicated_uid or info.st_mode & 0o077:
        raise Refusal("Dedicated lab scratch root is not private")
    python = sys.executable
    cmd = [
        "sudo",
        "-n",
        "-H",
        "-u",
        service_user,
        "env",
        "GASLUX_ISOLATED_WORKER=1",
        f"RUNNER_TEMP={private_root}",
        f"PYTHONPATH={private_root}",
        python,
        "-u",
        "-m",
        "auto_tests.installer_observer.lab_probe",
    ]
    evidence = []
    seen = set()
    endpoint_paths = []
    worker_errors = []
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        close_fds=True,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdin is not None
        until = time.monotonic() + 170
        while time.monotonic() < until:
            if not select.select([proc.stdout], [], [], min(3, until - time.monotonic()))[0]:
                if proc.poll() is not None:
                    break
                continue
            line = proc.stdout.readline()
            if not line:
                break
            if not line.startswith("EXTERNAL_PROBE "):
                # Preserve sanitized status without exposing runner secrets.
                if line.startswith("QEMU stage:") or line.startswith("QEMU laboratory refused:"):
                    print(line.strip(), flush=True)
                elif line.startswith(
                    (
                        "ModuleNotFoundError:",
                        "PermissionError:",
                        "ImportError:",
                        "sudo:",
                        "OSError:",
                    )
                ):
                    worker_errors.append(line.strip()[:200])
                elif len(worker_errors) < 12:
                    # Only the dedicated, synthetic lab worker writes here.
                    # Retain bounded diagnostic output; no host environment dump.
                    worker_errors.append(line.strip()[:200])
                continue
            try:
                packet = json.loads(line.removeprefix("EXTERNAL_PROBE "))
                run_id = str(uuid.UUID(packet["run_id"]))
                qmp, rfb = packet["qmp"], packet["rfb"]
            except (KeyError, ValueError, TypeError) as exc:
                raise Refusal("Invalid isolated worker probe request") from exc
            if run_id in seen or len(seen) >= 2:
                raise Refusal("Isolated VM session identifier reused")
            seen.add(run_id)
            for path, leaf in ((qmp, "qmp.sock"), (rfb, "rfb.sock")):
                if not isinstance(path, str) or Path(path).name != leaf:
                    raise Refusal("Unapproved endpoint request")
                # String/path validation only; the host cannot resolve the
                # 0700 directory without privilege.
                if not path.startswith("/tmp/observer-qemu-"):
                    raise Refusal("Unexpected isolated endpoint root")
            endpoint_paths.extend((qmp, rfb))
            # Privileged original runner can impersonate the dedicated UID.
            # Connect-only: no QMP commands, RFB handshake or input messages.
            impersonation = {}
            for name, endpoint in (("qmp", qmp), ("rfb", rfb)):
                command = [
                    "sudo", "-n", "-u", service_user, "/usr/bin/python3", "-c",
                    (
                        "import socket,sys;"
                        "s=socket.socket(socket.AF_UNIX);s.settimeout(2);"
                        "s.connect(sys.argv[1]);s.close()"
                    ),
                    endpoint,
                ]
                result = subprocess.run(command, check=False, capture_output=True, timeout=8)
                impersonation[name] = result.returncode
                if result.returncode != 0:
                    raise Refusal("Privileged UID impersonation experiment was inconclusive")
            # Only test write access; do not alter the staged executable.
            code_path = private_root / "auto_tests/installer_observer/lab_probe.py"
            writable = subprocess.run(
                ["sudo", "-n", "-u", service_user, "test", "-w", str(code_path)],
                check=False, capture_output=True, timeout=8,
            ).returncode == 0
            if not writable:
                raise Refusal("Privileged staged-source write-capability test inconclusive")
            tests = {
                "original_runner_uid": os.geteuid(),
                "isolated_uid": dedicated_uid,
                "run_id": run_id,
                "runner_connect_qmp": _connect_as_runner(qmp),
                "runner_connect_rfb": _connect_as_runner(rfb),
                "nobody_connect_qmp": _connect_as_nobody(qmp),
                "nobody_connect_rfb": _connect_as_nobody(rfb),
                "no_input_events": True,
                "sudo_impersonated_qmp_connect": impersonation["qmp"] == 0,
                "sudo_impersonated_rfb_connect": impersonation["rfb"] == 0,
                "sudo_impersonated_uid_can_write_staged_source": writable,
            }
            if any(
                tests[key] != 13
                for key in (
                    "runner_connect_qmp",
                    "runner_connect_rfb",
                    "nobody_connect_qmp",
                    "nobody_connect_rfb",
                )
            ):
                raise Refusal("External UID was admitted to dedicated QEMU endpoints")
            evidence.append(tests)
            proc.stdin.write("PROBE_DONE " + run_id + "\n")
            proc.stdin.flush()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise Refusal("Dedicated worker did not exit") from exc
        if proc.returncode != 0 or len(evidence) != 2:
            raise Refusal(
                "Isolated laboratory failed or did not expose two VMs; "
                + ("; ".join(worker_errors[-3:]) if worker_errors else f"exit={proc.returncode}")
            )
        # Trusted post-exit inspection: stale names must be absent, including
        # broken symlinks. The original UID alone cannot traverse this tree.
        for stale in endpoint_paths:
            for test_flag in ("-e", "-L"):
                result = subprocess.run(
                    ["sudo", "-n", "test", "!", test_flag, stale],
                    check=False,
                    timeout=8,
                    capture_output=True,
                )
                if result.returncode != 0:
                    raise Refusal("Stale or replaced QEMU endpoint survived shutdown")
        # Evidence is copied by sudo only AFTER the dedicated worker exited.
        # Never return the private socket directory as an input-capable proxy.
        source = private_root / "observer-qemu-lab"
        subprocess.run(
            ["sudo", "-n", "cp", "-a", "--", str(source), str(public_evidence)],
            check=True,
            timeout=15,
        )
        subprocess.run(
            ["sudo", "-n", "chown", "-R", f"{os.geteuid()}:{os.getegid()}", str(public_evidence)],
            check=True,
            timeout=15,
        )
        public_evidence.joinpath("external_uid_probes.json").write_bytes(
            canonical(
                {
                    "mode": "dedicated-uid-read-only-qemu",
                    "runs": evidence,
                    "original_uid_has_sudo": True,
                    "privileged_original_uid_out_of_scope": True,
                    "dedicated_uid_external_clients_not_excluded": True,
                    "guest_input_count": 0,
                    "stale_endpoints_absent_after_worker_exit": True,
                }
            )
        )
        print(
            json.dumps(
                {"dedicated_uid_runs": 2, "external_connect_eacces": 8, "guest_input_count": 0}
            )
        )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Expected private-root, dedicated-user and evidence-root")
    run(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
