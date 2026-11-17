"""Isolated Windows 11 VM TPM reconnect regression and hosted swtpm smoke.

No Windows ISO, TPM secrets, physical disk, or Windows guest is accessed.
The optional hosted smoke exercises two real swtpm listener lifetimes, with the
same private temporary TPM state directory that the real QEMU lab uses.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "gaslux_windows_swtpm_restart", TOOLS / "windows_x64_tcg_firstboot.py"
)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)


class NeverTouchedProcess:
    def poll(self):
        raise AssertionError("untrusted TPM process was contacted")
    def wait(self, timeout=None):
        raise AssertionError("untrusted TPM process was contacted")
    def terminate(self):
        raise AssertionError("untrusted TPM process was terminated")


class SwtpmRestartContracts(unittest.TestCase):
    def test_unowned_workspace_refused_before_touching_process(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
        }):
            root = pathlib.Path(temp)
            (root / "swtpm-state").mkdir(mode=0o700)
            with self.assertRaisesRegex(VM.LabError, "private owned"):
                VM.restart_owned_swtpm_for_second_guest(
                    NeverTouchedProcess(), root
                )

    def test_windows11_second_boot_requires_tpm_restart_contract(self):
        code = (TOOLS / "windows_x64_tcg_firstboot.py").read_text()
        self.assertIn(
            'profile_key != "win11_26h2_en_us_x64" or restart_tpm is not None',
            code,
        )
        self.assertIn("restart_owned_swtpm_for_second_guest(tpm, workspace)", code)
        self.assertIn('f"dir={state_dir}"', code)
        self.assertIn('second = subprocess.Popen(', code)

    @unittest.skipUnless(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_TEMP") == "/home/runner/work/_temp"
        and shutil.which("swtpm") is not None,
        "real swtpm socket-reconnect smoke requires hosted Actions + swtpm",
    )
    def test_real_swtpm_reconnect_after_first_guest_shutdown(self):
        with tempfile.TemporaryDirectory(
            prefix="gaslux-win-x64-", dir=os.environ["RUNNER_TEMP"]
        ) as temp:
            work = pathlib.Path(temp)
            state = work / "swtpm-state"
            state.mkdir(mode=0o700)
            state_inode = state.stat().st_ino
            endpoint = work / "swtpm.sock"
            with (work / "swtpm-stderr.log").open("xb") as err:
                first = subprocess.Popen([
                    "swtpm", "socket", "--tpm2",
                    "--tpmstate", f"dir={state}",
                    "--ctrl", f"type=unixio,path={endpoint}",
                    "--flags", "not-need-init",
                ], stderr=err, stdout=subprocess.DEVNULL)
            second = None
            try:
                for _ in range(100):
                    if endpoint.is_socket() or first.poll() is not None:
                        break
                    time.sleep(0.1)
                self.assertTrue(endpoint.is_socket(), "first swtpm did not bind")
                first_pid = first.pid
                second = VM.restart_owned_swtpm_for_second_guest(first, work)
                self.assertNotEqual(first_pid, second.pid)
                self.assertIsNone(second.poll())
                self.assertTrue(endpoint.is_socket())
                self.assertEqual(state.stat().st_ino, state_inode,
                                 "TPM NV state directory was replaced")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.settimeout(5)
                    conn.connect(str(endpoint))
                print("GASLUX_VM_REAL_SWTPM_SECOND_LISTENER_CONNECTED=1",
                      flush=True)
            finally:
                for proc in (second, first):
                    if proc is not None:
                        if proc.poll() is None:
                            proc.terminate()
                        proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
