"""Bounded workspace protocol, state transitions and negative sandbox probes."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_opencode_workspace as b
import gaslux_opencode_iterative as i
import gaslux_opencode_parent_boundary as parent
import gaslux_opencode_model_proxy as proxy


def correct(role="mint"):
    return (f"def assess_{role}_lifecycle(evidence: dict) -> dict:\n"
            "    gates = " + repr(b.factory.GATES) + "\n"
            "    missing = sorted([name for name in gates if evidence.get(name) is not True])\n"
            f"    return {{'backend': {role!r}, 'missingGates': missing, "
            "'installationAuthorized': False, 'releaseEligible': False}\n")


class WorkspaceTests(unittest.TestCase):
    def workspace(self, path):
        return b.Workspace(path, {"role": "mint"}, tester=lambda role, src:
                           "RED" if src == b.seed_source(role) else "PASS")

    def test_required_red_edit_pass_and_sha_cas(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = self.workspace(Path(tmp))
            with self.assertRaises(ValueError):
                w.call("replace_candidate", {"expected_sha256": w.sha, "source": correct()})
            w.call("inspect_task", {})
            w.call("read_candidate", {})
            self.assertEqual(w.call("run_tests", {})["status"], "RED")
            before = w.sha
            with self.assertRaises(ValueError):
                w.call("replace_candidate", {"expected_sha256": "0"*64, "source": correct()})
            edited = w.call("replace_candidate", {"expected_sha256": before, "source": correct()})
            self.assertEqual(edited["status"], "EDITED")
            self.assertNotEqual(w.sha, before)
            self.assertEqual(w.call("run_tests", {})["status"], "PASS")
            self.assertEqual((Path(tmp) / "candidate-1.py").read_text(), correct())

    def test_no_paths_shell_or_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = self.workspace(Path(tmp))
            w.call("inspect_task", {})
            w.call("read_candidate", {})
            w.call("run_tests", {})
            for name, args in (("bash", {"command": "true"}),
                               ("read_candidate", {"path": "/etc/passwd"}),
                               ("replace_candidate", {"expected_sha256": w.sha,
                                "source": "def assess_mint_lifecycle(evidence: dict) -> dict:\n"
                                          "    import os\n    return {}"})):
                with self.assertRaises((ValueError, TypeError)):
                    w.call(name, args)
            self.assertEqual(w.edits, 0)

    def test_protocol_tools_are_exactly_pathless(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = self.workspace(Path(tmp))
            response = b.rpc(w, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertEqual([t["name"] for t in response["result"]["tools"]], list(b.TOOLS))
            denied = b.rpc(w, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "unknown", "arguments": {}}})
            self.assertTrue(denied["result"]["isError"])

    def test_exhaustive_suite_catches_mixed_and_truthy_inputs(self):
        self.assertEqual(b.exhaustive("mint", correct()), 259)
        with self.assertRaises(ValueError):
            b.exhaustive("mint", b.seed_source("mint"))
        with self.assertRaises(ValueError):
            b.exhaustive("mint", correct().replace(" is not True", " == False"))

    def test_sandbox_worker_real_red_and_green(self):
        if sys.platform != "linux":
            self.skipTest("Linux-only lab")
        # In the hosted lab this is mandatory. No fallback to unrestricted execution.
        self.assertEqual(b.isolated_test("mint", b.seed_source("mint")), "RED")
        self.assertEqual(b.isolated_test("mint", correct()), "PASS")

    def test_landlock_read_write_network_negative_probes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir()
            outside = root / "outside"
            outside.write_bytes(b"unchanged")
            rd, wr = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(rd)
                result = b"FAIL"
                try:
                    b.restrict(state)
                    b.probe(state, outside)
                    result = b"PASS"
                except BaseException:
                    pass
                os.write(wr, result)
                os._exit(0)
            os.close(wr)
            try:
                self.assertEqual(os.read(rd, 16), b"PASS")
            finally:
                os.close(rd)
                os.waitpid(pid, 0)
            self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_native_event_parser_rejects_shell_and_fake_skill(self):
        skill = {"type": "tool_use", "part": {"tool": "skill", "state": {
            "status": "completed", "input": {"name": i.trial.SKILL},
            "output": '<skill_content name="' + i.trial.SKILL + '">'}}}
        tool = {"type": "tool_use", "part": {"tool": i.PREFIX + "inspect_task",
                                             "state": {"status": "completed"}}}
        raw = lambda rows: "\n".join(json.dumps(row) for row in rows).encode()
        self.assertEqual(i.native_events(raw([skill, tool]))[0], ["inspect_task"])
        tool["part"]["tool"] = "bash"
        with self.assertRaises(ValueError):
            i.native_events(raw([skill, tool]))
        with self.assertRaises(ValueError):
            i.native_events(raw([{"type": "text", "part": {"text": "skill loaded"}}]))

    def test_safety1_419_01_iterative_native_event_audit(self):
        skill = {"type": "tool_use", "part": {"type": "tool", "tool": "skill",
            "state": {"status": "completed", "input": {"name": i.trial.SKILL},
            "output": '<skill_content name="' + i.trial.SKILL + '">'}}}
        tool = {"type": "tool_use", "part": {"type": "tool",
            "tool": i.PREFIX + "inspect_task", "state": {"status": "completed"}}}
        raw = lambda rows: "\n".join(json.dumps(row) for row in rows).encode()
        good = raw([skill, tool])
        malformed = [
            {"type": "unknown", "part": {"tool": "bash"}},
            {"type": "unknown", "part": {}},
            {"type": "tool_result", "part": {"tool": "bash"}},
            {"type": "reasoning", "part": {"text": "", "state": {"status": "completed"}}},
            {"type": "text", "part": {"text": "", "callID": "forbidden"}},
            {"type": "step_start", "part": None},
            {"type": "reasoning", "part": {"type": "reasoning", "text": []}},
            {"part": {"tool": "bash"}},
            {"type": None, "part": {}},
            {"type": [], "part": {}},
            {"type": "reasoning", "part": {"tool": "bash"}},
            {"type": "step_start", "part": {"type": "tool", "tool": "bash"}},
            {"type": "step_finish", "part": {"type": "tool"}},
            {"type": "text", "part": {"type": "tool", "text": "", "tool": "bash"}},
            {"type": "text", "tool": "bash", "part": {"text": ""}},
            {"type": "tool_use", "part": {**tool["part"], "type": "text"}},
        ]
        for event in malformed:
            with self.subTest(event=event):
                with self.assertRaises(ValueError):
                    i.native_events(raw([skill, tool, event]))
        for line in (
            b'{"type":"unknown","type":"reasoning","part":{}}',
            b'{"type":"reasoning","part":{"tool":"bash","tool":"skill"}}',
            b'{"type":"step_finish","part":{"tokens":{"input":NaN}}}',
            b'{"type":"step_finish","part":{"type":"step-finish","type":"tool"}}',
        ):
            with self.assertRaises(ValueError):
                i.native_events(good + b"\n" + line)
        self.assertEqual(i.native_events(raw([
            {"type": "step_start", "part": {"type": "step-start"}}, skill,
            {"type": "reasoning", "part": {"type": "reasoning",
                "text": "bash is not an invocation"}}, tool,
            {"type": "text", "part": {"type": "text", "text": "done"}},
            {"type": "step_finish", "part": {"type": "step-finish"}},
        ])), (["inspect_task"], [i.trial.SKILL]))

    def test_model_proxy_request_scope(self):
        valid = {"model": proxy.MODEL, "messages": [{"role": "user", "content": "synthetic"}],
                 "stream": True}
        def raw(row):
            return json.dumps(row).encode()
        self.assertEqual(json.loads(proxy.validate_request(raw(valid)))["max_tokens"],
                         proxy.MAX_OUTPUT)
        for changed in (
            {**valid, "model": "other"},
            {**valid, "options": {"num_ctx": 999999}},
            {**valid, "max_tokens": proxy.MAX_OUTPUT + 1},
            {**valid, "max_tokens": True},
            {**valid, "stream": "true"},
            {**valid, "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "file:///etc/passwd"}}]}]},
            {**valid, "messages": [{"role": "user", "content": "x", "attachments": []}]},
            {**valid, "tools": [{"type": "web_search"}]},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    proxy.validate_request(raw(changed))
        for invalid in (b'{"model":"other","model":"qwen3.5:9b"}',
                        b'{"model":"qwen3.5:9b","messages":[],"temperature":NaN}',
                        b"x" * (proxy.MAX_REQUEST + 1)):
            with self.assertRaises(ValueError):
                proxy.validate_request(invalid)

    def test_model_proxy_unix_endpoint_denies_non_model_routes(self):
        import socket
        import threading
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            endpoint = Path(tmp) / "model.sock"
            with proxy.ModelServer(endpoint, proxy.Handler) as server:
                server.timeout = 2
                requests = [
                    b"GET /api/tags HTTP/1.0\r\n\r\n",
                    b"POST /api/pull HTTP/1.0\r\nContent-Length: 0\r\n\r\n",
                    b"CONNECT 127.0.0.1:22 HTTP/1.0\r\n\r\n",
                    b"POST http://127.0.0.1:11434/v1/chat/completions HTTP/1.0\r\n\r\n",
                    b"POST /v1/chat/completions HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
                    b"POST /v1/chat/completions HTTP/1.0\r\nContent-Length: 1\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\nx",
                ]
                with patch.object(proxy.http.client, "HTTPConnection") as upstream:
                    for request in requests:
                        thread = threading.Thread(target=server.handle_request)
                        thread.start()
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                            client.settimeout(3)
                            client.connect(str(endpoint))
                            client.sendall(request)
                            client.shutdown(socket.SHUT_WR)
                            response = client.makefile("rb").read()
                        thread.join(3)
                        self.assertFalse(thread.is_alive())
                        self.assertIn(response.split(b" ")[1], (b"400", b"403"))
                    upstream.assert_not_called()
                self.assertEqual(server.forwarded, 0)

    def test_fixed_runtime_failure_categories(self):
        self.assertEqual(i.fixed_failure(ValueError("MCP_RED_EDIT_PASS_INCOMPLETE")),
                         "MCP_RED_EDIT_PASS_INCOMPLETE")
        self.assertEqual(i.fixed_failure(ValueError("MODEL_CONTEXT_NOT_APPLIED")),
                         "MODEL_CONTEXT_NOT_APPLIED")
        self.assertEqual(i.fixed_failure(ValueError("SECRET_SENTINEL")), "ValueError")
        self.assertEqual(parent.classify_failure(b"bwrap: setting up uid map: Permission denied"),
                         "BWRAP_NAMESPACE_DENIED")
        self.assertEqual(parent.classify_failure(b"bwrap: Unknown option --disable-userns"),
                         "BWRAP_OPTION_UNSUPPORTED")
        self.assertEqual(parent.classify_failure(b"RuntimeError: host file exposed"),
                         "HOST_FILE_EXPOSED")
        self.assertEqual(parent.classify_failure(b"SECRET_SENTINEL"), "PARENT_CLIENT_FAILED")

    def test_verified_journal_and_independent_final_recheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            proof = {key: True for key in i.PROOF_KEYS}
            proof["landlock_abi"] = 4
            w = b.Workspace(state, {"role": "mint"}, sandbox=proof, tester=b.isolated_test)
            events = ["inspect_task", "read_candidate", "run_tests", "replace_candidate", "run_tests"]
            for name in events:
                w.call(name, {"expected_sha256": w.sha, "source": correct()} if
                       name == "replace_candidate" else {})
            result = i.verify_journal(state, events, "mint")
            self.assertEqual(result["functional_cases"], 259)
            with self.assertRaises(ValueError):
                i.verify_journal(state, events[:-1], "mint")


if __name__ == "__main__":
    unittest.main()
