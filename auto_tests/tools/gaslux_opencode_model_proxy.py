#!/usr/bin/env python3
"""Experimental model-only UNIX-socket HTTP boundary; no arbitrary forwarding.

No host network access is given to the client. A future admitted namespace
client may reach this single socket. Never expose this endpoint publicly.
"""
from __future__ import annotations

import argparse
import http.client
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socketserver
import stat
import time

MODEL = "qwen3.5:9b"
MAX_REQUEST = 512 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
MAX_CALLS = 16
MAX_OUTPUT = 2048
TIMEOUT = 300
PATH = "/v1/chat/completions"
ALLOWED_TOOLS = frozenset({"skill", "gaslux_workspace_inspect_task",
                           "gaslux_workspace_read_candidate", "gaslux_workspace_replace_candidate",
                           "gaslux_workspace_run_tests"})
ALLOWED_KEYS = frozenset({
    "model", "messages", "stream", "stream_options", "tools", "tool_choice",
    "temperature", "top_p", "max_tokens", "max_completion_tokens", "stop",
    "frequency_penalty", "presence_penalty", "seed", "parallel_tool_calls",
    "reasoning_effort",
})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("NON_JSON_CONSTANT")


def validate_request(raw):
    if not 0 < len(raw) <= MAX_REQUEST:
        raise ValueError("REQUEST_SIZE")
    row = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    if type(row) is not dict or set(row) - ALLOWED_KEYS or row.get("model") != MODEL:
        raise ValueError("REQUEST_SCOPE")
    messages = row.get("messages")
    if type(messages) is not list or not 1 <= len(messages) <= 128:
        raise ValueError("MESSAGE_COUNT")
    for msg in messages:
        if (type(msg) is not dict or msg.get("role") not in
                ("system", "developer", "user", "assistant", "tool")):
            raise ValueError("MESSAGE_ROLE")
        # No image/file/audio URLs or multimodal resource resolution.
        if set(msg) - {"role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content"}:
            raise ValueError("MESSAGE_SCOPE")
        content = msg.get("content")
        if content is not None and type(content) is not str:
            if type(content) is not list or not all(
                type(part) is dict and set(part) == {"type", "text"}
                and part["type"] == "text" and type(part["text"]) is str
                for part in content
            ):
                raise ValueError("MESSAGE_CONTENT")
    for key in ("max_tokens", "max_completion_tokens"):
        if key in row and (type(row[key]) is not int or not 1 <= row[key] <= MAX_OUTPUT):
            raise ValueError("OUTPUT_LIMIT")
    if "max_tokens" not in row and "max_completion_tokens" not in row:
        row["max_tokens"] = MAX_OUTPUT
    if "stream" in row and type(row["stream"]) is not bool:
        raise ValueError("STREAM_TYPE")
    if "tools" in row:
        tools = row["tools"]
        if type(tools) is not list or len(tools) > 16 or any(
            type(tool) is not dict or set(tool) != {"type", "function"}
            or tool["type"] != "function" or type(tool["function"]) is not dict
            or type(tool["function"].get("name")) is not str
            or tool["function"]["name"] not in ALLOWED_TOOLS
            for tool in tools
        ):
            raise ValueError("TOOLS_SCOPE")
    choice = row.get("tool_choice")
    if choice is not None:
        if type(choice) is str:
            if choice not in ("auto", "none", "required"):
                raise ValueError("TOOL_CHOICE_SCOPE")
        elif (type(choice) is not dict or set(choice) != {"type", "function"}
              or choice["type"] != "function" or type(choice["function"]) is not dict
              or set(choice["function"]) != {"name"}
              or type(choice["function"]["name"]) is not str
              or choice["function"]["name"] not in ALLOWED_TOOLS):
            raise ValueError("TOOL_CHOICE_SCOPE")
    return json.dumps(row, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()



# OpenAI-compatible completion is more than EOF or Content-Length. Never
# release a successful HTTP response until the bounded protocol body is valid.
FINISH_REASONS = frozenset({"stop", "length", "tool_calls", "content_filter", "function_call"})


def response_object(raw):
    row = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                     parse_constant=reject_constant)
    if type(row) is not dict or "error" in row:
        raise ValueError("RESPONSE_OBJECT")
    return row


def response_choice(row, *, stream):
    choices = row.get("choices")
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise ValueError("RESPONSE_CHOICES")
    choice = choices[0]
    if type(choice.get("index")) is not int or choice["index"] != 0:
        raise ValueError("RESPONSE_CHOICE_INDEX")
    part = choice.get("delta" if stream else "message")
    if type(part) is not dict:
        raise ValueError("RESPONSE_CHOICE_PART")
    finish = choice.get("finish_reason")
    if finish is not None and (type(finish) is not str or finish not in FINISH_REASONS):
        raise ValueError("RESPONSE_FINISH_REASON")
    return finish


def validate_response(content_type, raw):
    if not 0 < len(raw) <= MAX_RESPONSE:
        raise ValueError("RESPONSE_SIZE")
    if content_type == "application/json":
        if response_choice(response_object(raw), stream=False) is None:
            raise ValueError("RESPONSE_NOT_FINISHED")
        return
    if content_type != "text/event-stream":
        raise ValueError("RESPONSE_CONTENT_TYPE")
    # SSE line endings may be LF, CRLF, or CR. Require a complete blank-line
    # event boundary, not an unterminated data line at EOF.
    text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n\n"):
        raise ValueError("SSE_INCOMPLETE_EVENT")
    finished = done = False
    chunks = 0
    for event in text.split("\n\n"):
        if not event:
            continue
        if done:
            raise ValueError("SSE_AFTER_DONE")
        fields = []
        for line in event.split("\n"):
            if line.startswith(":"):
                continue
            if not line.startswith("data:"):
                raise ValueError("SSE_FIELD")
            value = line[5:]
            fields.append(value[1:] if value.startswith(" ") else value)
        if not fields:
            continue
        payload = "\n".join(fields)
        if payload == "[DONE]":
            if not finished or chunks == 0:
                raise ValueError("SSE_PREMATURE_DONE")
            done = True
            continue
        row = response_object(payload.encode("utf-8"))
        # OpenAI stream_options.include_usage permits a final usage-only chunk.
        if row.get("choices") == [] and finished and type(row.get("usage")) is dict:
            continue
        if finished:
            raise ValueError("SSE_AFTER_FINISH")
        finish = response_choice(row, stream=True)
        chunks += 1
        if finish is not None:
            finished = True
    if not done:
        raise ValueError("SSE_MISSING_DONE")


class ModelServer(socketserver.UnixStreamServer):
    # A serial server deliberately prevents parallel inference through this
    # capability. Requests and responses are never logged or retained.
    def __init__(self, path, handler):
        self.calls = 0
        self.forwarded = 0
        self.completed = 0
        self.denied = 0
        self.deadline = time.monotonic() + 1200
        super().__init__(str(path), handler)

    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(TIMEOUT)
        return conn, addr

    def handle_error(self, request, client_address):
        # Do not emit request text, model output or host paths.
        self.denied += 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "GasluxModelBoundary"
    sys_version = ""

    def log_message(self, *_):
        pass

    def deny(self, status=400):
        self.server.denied += 1
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.deny(403)

    do_HEAD = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET
    do_CONNECT = do_GET
    do_OPTIONS = do_GET

    def do_POST(self):
        self.server.calls += 1
        if self.server.calls > MAX_CALLS or time.monotonic() >= self.server.deadline:
            self.deny(429)
            return
        if self.path != PATH:
            self.deny(403)
            return
        if (self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect")
                or self.headers.get_all("Content-Encoding")
                or len(self.headers.get_all("Content-Length", [])) != 1
                or len(self.headers.get_all("Content-Type", [])) != 1
                or self.headers.get_content_type() != "application/json"):
            self.deny()
            return
        length = self.headers["Content-Length"]
        if not length.isascii() or not length.isdecimal() or len(length) > 7:
            self.deny()
            return
        size = int(length)
        if not 0 < size <= MAX_REQUEST:
            self.deny(413)
            return
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("INCOMPLETE_REQUEST")
            body = validate_request(raw)
        except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
            self.deny()
            return
        # Fixed destination, fixed path, no incoming headers/URLs/credentials.
        upstream = http.client.HTTPConnection("127.0.0.1", 11434, timeout=TIMEOUT)
        started = False
        try:
            upstream.request("POST", PATH, body=body, headers={
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                "Connection": "close",
            })
            self.server.forwarded += 1
            with upstream.getresponse() as response:
                if response.status != 200:
                    self.deny(502)
                    return
                content_type = response.headers.get_content_type()
                if content_type not in ("application/json", "text/event-stream"):
                    self.deny(502)
                    return
                declared = response.getheader("Content-Length")
                if declared is not None and (not declared.isascii() or not declared.isdecimal()
                                             or len(declared) > 7
                                             or not 0 < int(declared) <= MAX_RESPONSE):
                    self.deny(502)
                    return
                # Buffer at most MAX_RESPONSE bytes. A partial protocol body
                # must never be delivered as HTTP 200 or counted as completed.
                payload = bytearray()
                deadline = min(self.server.deadline, time.monotonic() + TIMEOUT)
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("RESPONSE_DEADLINE")
                    data = response.read1(min(65536, MAX_RESPONSE + 1 - len(payload)))
                    if not data:
                        break
                    payload.extend(data)
                    if len(payload) > MAX_RESPONSE:
                        raise ValueError("RESPONSE_LIMIT")
                if declared is not None and len(payload) != int(declared):
                    raise ValueError("RESPONSE_TRUNCATED")
                validate_response(content_type, bytes(payload))
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                started = True
                self.wfile.write(payload)
                self.wfile.flush()
                self.server.completed += 1
        except (OSError, ValueError, UnicodeError, RecursionError, http.client.HTTPException):
            if not started:
                self.deny(502)
            else:
                # A truncated stream is a failed request, never synthetic success.
                self.server.denied += 1
        finally:
            upstream.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    args = parser.parse_args()
    path = args.socket
    parent = path.parent
    mode = parent.lstat()
    if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid()
            or mode.st_mode & 0o077 or path.exists() or path.is_symlink()
            or not path.is_absolute()):
        raise ValueError("UNSAFE_SOCKET_DIRECTORY")
    # Private parent, exclusive socket bind, no replacement/unlink of an
    # existing object. Socket removal is owned by the disposable controller.
    old = os.umask(0o077)
    try:
        with ModelServer(path, Handler) as server:
            server.timeout = 1
            while time.monotonic() < server.deadline and server.calls < MAX_CALLS:
                server.handle_request()
            print(json.dumps({"calls": server.calls, "forwarded": server.forwarded,
                              "completed": server.completed, "denied": server.denied,
                              "operational_authorized": False}))
    finally:
        os.umask(old)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
