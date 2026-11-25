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
            {**valid, "tools": [{"type": "function", "function": {"name": "bash"}}]},
            {**valid, "tools": [{"type": "function", "function": {"name": []}}]},
            {**valid, "tool_choice": {"type": "function", "function": {"name": "bash"}}},
            {**valid, "tool_choice": "bash"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    proxy.validate_request(raw(changed))
        allowed = {**valid, "tools": [{"type": "function", "function": {"name": name}}
                                    for name in sorted(proxy.ALLOWED_TOOLS)],
                   "tool_choice": {"type": "function", "function": {"name": "skill"}}}
        self.assertEqual(json.loads(proxy.validate_request(raw(allowed)))["tools"], allowed["tools"])
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


    def test_model_proxy_actual_unix_forwarding_and_truncation(self):
        import socket
        import threading
        from unittest.mock import MagicMock, patch
        body = json.dumps({"model": proxy.MODEL,
                           "messages": [{"role": "user", "content": "fixture"}]}).encode()
        data = b'{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}'
        chunk = b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}\n\n'
        finish = b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
        done = b'data: [DONE]\n\n'
        cases = (
            ("application/json", data, str(len(data)), True),
            ("application/json", data, None, True),
            ("application/json", data, str(len(data) + 1), False),
            ("application/json", data[:-1], None, False),
            ("application/json", b'{}', None, False),
            ("application/json", data.replace(b'"stop"', b'null'), None, False),
            ("application/json", data + b'{}', None, False),
            ("application/json", data.replace(b'"index":0', b'"index":0,"index":1'), None, False),
            ("text/event-stream", chunk + finish + done, None, True),
            ("text/event-stream", (chunk + finish + done).replace(b'\n', b'\r\n'), None, True),
            ("text/event-stream", chunk + finish, None, False),
            ("text/event-stream", chunk + finish, str(len(chunk + finish)), False),
            ("text/event-stream", chunk + finish + done[:-1], None, False),
            ("text/event-stream", chunk + done, None, False),
            ("text/event-stream", done, None, False),
            ("text/event-stream", chunk + finish + done + chunk, None, False),
            ("text/event-stream", chunk + finish + done + done, None, False),
            ("text/event-stream", b'data: {"choices":\n\n' + finish + done, None, False),
            ("text/event-stream", chunk + finish + b'data: {"choices":[],"usage":{}}\n\n' + done,
             None, True),
        )
        with tempfile.TemporaryDirectory() as tmp:
            endpoint = Path(tmp) / "model.sock"
            with proxy.ModelServer(endpoint, proxy.Handler) as server:
                server.timeout = 2
                # Use a test-only call budget to exercise all fixtures over
                # the real Unix transport; production MAX_CALLS is unchanged.
                with patch.object(proxy, "MAX_CALLS", len(cases)):
                    for content_type, payload, declared, valid in cases:
                        with self.subTest(content_type=content_type, declared=declared, valid=valid):
                            before = server.completed
                            with patch.object(proxy.http.client, "HTTPConnection") as upstream:
                                response = MagicMock()
                                response.status = 200
                                response.headers.get_content_type.return_value = content_type
                                response.getheader.return_value = declared
                                # Force boundaries inside JSON and SSE frames.
                                response.read1.side_effect = [
                                    payload[pos:pos + 7] for pos in range(0, len(payload), 7)
                                ] + [b""]
                                upstream.return_value.getresponse.return_value.__enter__.return_value = response
                                thread = threading.Thread(target=server.handle_request)
                                thread.start()
                                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                                    client.settimeout(3)
                                    client.connect(str(endpoint))
                                    request = (b"POST /v1/chat/completions HTTP/1.0\r\n"
                                               b"Content-Type: application/json\r\n"
                                               b"Authorization: MUST-NOT-FORWARD\r\n"
                                               + b"Content-Length: " + str(len(body)).encode()
                                               + b"\r\n\r\n" + body)
                                    client.sendall(request)
                                    client.shutdown(socket.SHUT_WR)
                                    received = client.makefile("rb").read()
                                thread.join(3)
                                self.assertFalse(thread.is_alive())
                                headers, returned = received.split(b"\r\n\r\n", 1)
                                self.assertIn(b"200" if valid else b"502", headers.split(b"\r\n", 1)[0])
                                self.assertEqual(returned, payload if valid else b"")
                                upstream.assert_called_once_with("127.0.0.1", 11434, timeout=proxy.TIMEOUT)
                                args, kwargs = upstream.return_value.request.call_args
                                self.assertEqual(args, ("POST", proxy.PATH))
                                self.assertNotIn("Authorization", kwargs["headers"])
                                self.assertEqual(json.loads(kwargs["body"])["model"], proxy.MODEL)
                                self.assertEqual(server.completed, before + int(valid))
                self.assertEqual(server.forwarded, len(cases))
                self.assertEqual(server.completed, sum(case[3] for case in cases))
                self.assertEqual(server.denied, sum(not case[3] for case in cases))

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

    def test_real_parent_config_has_only_five_named_tools_and_two_fixed_destinations(self):
        import gaslux_opencode_isolated_runtime as runtime
        with tempfile.TemporaryDirectory() as tmp:
            config = runtime.isolated_config(Path(tmp), i.trial.COMPACT_CONTEXT)
            self.assertEqual(config["permission"]["*"], "deny")
            self.assertEqual(set(config["permission"]) - {"*", "skill"}, set(i.REQUIRED))
            self.assertEqual(config["mcp"]["gaslux_workspace"]["command"],
                             ["/usr/bin/python3", "-I", "-B", "/opt/relay.py", "mcp"])
            self.assertEqual(config["provider"]["ollama"]["options"]["baseURL"],
                             "http://127.0.0.1:11435/v1")
            self.assertEqual(config["skills"]["paths"], ["/scratch/.opencode/skills"])

    def test_real_proxy_completion_fails_closed(self):
        import gaslux_opencode_isolated_runtime as runtime
        valid = {"calls": 5, "forwarded": 5, "completed": 5, "denied": 0}
        self.assertTrue(runtime.proxy_complete(valid))
        for change in ({"denied": 1}, {"completed": 4}, {"forwarded": 4},
                       {"calls": 0, "forwarded": 0, "completed": 0}, {"calls": True}):
            self.assertFalse(runtime.proxy_complete({**valid, **change}))

    def test_native_failure_retains_only_validated_partial_operations(self):
        skill = {"type": "tool_use", "part": {"tool": "skill", "state": {
            "status": "completed", "input": {"name": i.trial.SKILL},
            "output": '<skill_content name="' + i.trial.SKILL + '">'}}}
        tool = {"type": "tool_use", "part": {"tool": i.PREFIX + "inspect_task",
                                             "state": {"status": "completed"}}}
        report = {}
        raw = "\n".join(json.dumps(x) for x in (skill, tool,
                  {"type": "tool_use", "part": {"tool": "UNTRUSTED_SENTINEL",
                                               "state": {"status": "completed"}}})).encode()
        with self.assertRaises(ValueError):
            i.native_events(raw, report)
        self.assertEqual(report["native_operations"], ["inspect_task"])
        self.assertEqual(report["native_skills"], [i.trial.SKILL])
        self.assertNotIn("UNTRUSTED_SENTINEL", json.dumps(report))

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
