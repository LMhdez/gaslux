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
            for tool in tools
        ):
            raise ValueError("TOOLS_SCOPE")
    return json.dumps(row, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


class ModelServer(socketserver.UnixStreamServer):
    # A serial server deliberately prevents parallel inference through this
    # capability. Requests and responses are never logged or retained.
    def __init__(self, path, handler):
        self.calls = 0
        self.forwarded = 0
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
                if declared is not None and (not declared.isdecimal() or
                                             int(declared) > MAX_RESPONSE):
                    self.deny(502)
                    return
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Connection", "close")
                self.end_headers()
                started = True
                total = 0
                deadline = min(self.server.deadline, time.monotonic() + TIMEOUT)
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("RESPONSE_DEADLINE")
                    data = response.read1(min(65536, MAX_RESPONSE + 1 - total))
                    if not data:
                        break
                    total += len(data)
                    if total > MAX_RESPONSE:
                        raise ValueError("RESPONSE_LIMIT")
                    self.wfile.write(data)
                    self.wfile.flush()
        except (OSError, ValueError, http.client.HTTPException):
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
                              "denied": server.denied, "operational_authorized": False}))
    finally:
        os.umask(old)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
