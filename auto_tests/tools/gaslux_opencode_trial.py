#!/usr/bin/env python3
"""Isolated OpenCode/Qwen proof of native skill use; never a publishing path."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time

import gaslux_agent_feature_factory as factory
from gaslux_agent_history import SKILLS

ROOT = Path(__file__).resolve().parents[2]
SKILL = "gaslux-history-reuse"
MODEL = "ollama/" + factory.MODEL
VERSION = "1.19.6"
MAX_EVENTS = 2 * 1024 * 1024
MAX_INTERNAL_FILE = 512 * 1024 * 1024
MAX_SCRATCH = 2 * 1024**3
MIN_FREE = 4 * 1024**3
MAX_ENTRIES = 100_000
PROMPT = (
    "Return exactly one JSON object with key addition, no Markdown. "
    "Its value is a Python function with signature "
    "def assess_mint_lifecycle(evidence: dict) -> dict:. "
    "Inside define a tuple gates with these eight exact keys: "
    + repr(factory.GATES)
    + ". Compute missing = sorted([name for name in gates if evidence.get(name) is not True]). "
    "Return exactly backend='mint', missingGates=missing, installationAuthorized=False, "
    "releaseEligible=False. No imports, other functions, loops, shell or I/O. "
    "Use a tuple, comprehension, and literal False flags."
)


def prepare(work: Path, source: Path = ROOT):
    for name in SKILLS:
        actual = "gaslux-" + name
        target = work / ".opencode" / "skills" / actual / "SKILL.md"
        origin = source / "docs/agent-skills" / name / "SKILL.md"
        if origin.is_symlink() or not origin.is_file() or origin.stat().st_size > 16384:
            raise ValueError("Missing or unsafe portable skill")
        text = origin.read_text(encoding="utf-8")
        if not text.startswith("---\nname: " + actual + "\n"):
            raise ValueError("Skill name mismatch")
        target.parent.mkdir(parents=True, exist_ok=False)
        target.write_text(text, encoding="utf-8")
    permission = {"*": "deny", "skill": {"*": "deny", "gaslux-*": "allow"}}
    config = {
        "model": MODEL, "enabled_providers": ["ollama"],
        "autoupdate": False, "share": "disabled",
        "plugin": [], "mcp": {},
        "skills": {"paths": [str(work / ".opencode" / "skills")], "urls": []},
        "permission": permission,
        "agent": {"gaslux-lab": {"mode": "primary", "steps": 4, "permission": permission}},
        "provider": {"ollama": {"npm": "@ai-sdk/openai-compatible",
                                "name": "Ollama", "options": {"baseURL": "http://127.0.0.1:11434/v1"},
                                "models": {factory.MODEL: {"name": factory.MODEL,
                                    "limit": {"context": 65536, "output": 1000}}}}},
    }
    (work / "opencode.json").write_text(json.dumps(config), encoding="utf-8")
    return config


class TrialFailure(ValueError):
    """Fixed diagnostic category; never publish arbitrary exception strings."""

    def __init__(self, category, *, skills=(), counts=None, detail=None):
        super().__init__(category)
        self.category = category
        self.skills = sorted(set(skills))
        self.counts = counts or {}
        self.detail = detail


def parse_events(raw: bytes):
    if len(raw) > MAX_EVENTS:
        raise TrialFailure("EVENT_STREAM_OVERSIZE")
    texts, skills = [], []
    counts = {}

    def fail(category, detail=None):
        raise TrialFailure(category, skills=skills, counts=counts, detail=detail)

    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (ValueError, UnicodeError):
            fail("EVENT_JSON_INVALID")
        if type(row) is not dict:
            fail("EVENT_SHAPE_INVALID")
        kind = row.get("type")
        known = ("text", "tool_use", "error", "step_start", "step_finish", "reasoning")
        key = kind if kind in known else "other"
        counts[key] = counts.get(key, 0) + 1
        if kind == "error":
            error = row.get("error")
            name = error.get("name") if type(error) is dict else None
            allowed = ("APIError", "ProviderAuthError", "UnknownError",
                       "MessageAbortedError", "ContextOverflowError",
                       "OutputLengthError", "StructuredOutputError")
            fail("OPENCODE_ERROR_EVENT", name if name in allowed else "OTHER")
        if kind not in ("text", "tool_use"):
            continue
        part = row.get("part")
        if type(part) is not dict:
            fail("EVENT_PART_INVALID")
        if kind == "text":
            if type(part.get("text")) is not str:
                fail("TEXT_EVENT_INVALID")
            texts.append(part["text"])
        else:
            state = part.get("state")
            if part.get("tool") != "skill":
                fail("UNEXPECTED_TOOL")
            if type(state) is not dict:
                fail("SKILL_STATE_INVALID")
            if state.get("status") != "completed":
                # Match only fixed known signatures; never retain the error text.
                err = state.get("error")
                detail = "OTHER"
                if isinstance(err, str):
                    if "not found" in err.lower():
                        detail = "NOT_FOUND"
                    elif "permission" in err.lower() or "denied" in err.lower():
                        detail = "PERMISSION_DENIED"
                fail("SKILL_TOOL_FAILED", detail)
            if type(state.get("input")) is not dict:
                fail("SKILL_INPUT_INVALID")
            name = state["input"].get("name")
            if type(name) is not str or name not in ["gaslux-" + n for n in SKILLS]:
                fail("SKILL_NAME_UNEXPECTED")
            if (type(state.get("output")) is not str
                    or '<skill_content name="' + name + '">' not in state["output"]):
                fail("SKILL_OUTPUT_MISSING")
            skills.append(name)
    if SKILL not in skills:
        fail("NO_NATIVE_SKILL_EVENT" if not counts.get("tool_use") else "REQUIRED_SKILL_NOT_LOADED")
    if not texts:
        fail("NO_FINAL_TEXT")
    try:
        result = json.loads("".join(texts).strip())
    except (ValueError, UnicodeError):
        fail("CANDIDATE_JSON_INVALID")
    if type(result) is not dict or set(result) != {"addition"} or type(result["addition"]) is not str:
        fail("CANDIDATE_SCHEMA_INVALID")
    return result["addition"], sorted(set(skills))


def cli_failure(returncode, raw, stderr):
    # A structured error may exist despite a nonzero CLI exit. Preserve only
    # fixed categories, event counters and known skill names.
    try:
        parse_events(raw)
    except TrialFailure as error:
        if error.category == "OPENCODE_ERROR_EVENT":
            return error
    signatures = (
        (b"invalid configuration", "CONFIG_INVALID"),
        (b"configinvaliderror", "CONFIG_INVALID"),
        (b"provider", "PROVIDER_ERROR"),
        (b"file size limit", "FILE_SIZE_LIMIT"),
        (b"enospc", "DISK_SPACE"),
        (b"permission denied", "PERMISSION_DENIED"),
        (b"not found", "NOT_FOUND"),
    )
    lower = stderr.lower()
    detail = next((label for needle, label in signatures if needle in lower), "OTHER")
    if returncode == -25:
        detail = "FILE_SIZE_LIMIT"
    return TrialFailure("CLI_NONZERO", detail=detail)


def check_scratch(work: Path):
    total, entries = 0, 0
    for directory, dirs, files in os.walk(work, followlinks=False):
        for name in dirs + files:
            entries += 1
            if entries > MAX_ENTRIES:
                raise TrialFailure("SCRATCH_ENTRY_LIMIT")
            try:
                st = (Path(directory) / name).lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(st.st_mode):
                total += max(st.st_size, st.st_blocks * 512)
                if total > MAX_SCRATCH:
                    raise TrialFailure("SCRATCH_SIZE_LIMIT")
    if shutil.disk_usage(work).free < MIN_FREE:
        raise TrialFailure("DISK_RESERVE_LIMIT")
    return total


def bounded_process(argv, work, env, timeout=900):
    # Per-file ceiling for SQLite/cache/provider binaries is distinct from the
    # strict stdout/stderr caps. Periodic scratch accounting is not a hard quota.
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_INTERNAL_FILE, MAX_INTERNAL_FILE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    check_scratch(work)
    deadline = time.monotonic() + timeout
    next_check = time.monotonic() + 1
    with subprocess.Popen(
        argv, cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=limit, start_new_session=True,
    ) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                buffers = {}
                for stream in (proc.stdout, proc.stderr):
                    buffers[stream] = bytearray()
                    sel.register(stream, selectors.EVENT_READ)
                while sel.get_map():
                    now = time.monotonic()
                    if now >= deadline:
                        raise TrialFailure("CLI_TIMEOUT")
                    if now >= next_check:
                        check_scratch(work)
                        next_check = now + 1
                    for key, _ in sel.select(timeout=min(0.25, deadline - now)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            sel.unregister(key.fileobj)
                            continue
                        buf = buffers[key.fileobj]
                        if len(buf) + len(chunk) > MAX_EVENTS:
                            raise TrialFailure("EVENT_STREAM_OVERSIZE" if key.fileobj is proc.stdout
                                               else "STDERR_STREAM_OVERSIZE")
                        buf.extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TrialFailure("CLI_TIMEOUT")
                try:
                    code = proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    raise TrialFailure("CLI_TIMEOUT") from None
                check_scratch(work)
                return code, bytes(buffers[proc.stdout]), bytes(buffers[proc.stderr])
        finally:
            # Kill remaining group members on success as well as failure.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()


def run_cli(binary: Path, work: Path):
    # No GITHUB_TOKEN, credentials, checkout, user config, or job command files
    # in the process environment. This is an experimental permission boundary,
    # not an OS-level sandbox. Third-party provider dependency fetches may occur.
    home = work / "home"
    home.mkdir(mode=0o700)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
           "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
           "XDG_DATA_HOME": str(home / "data"), "XDG_STATE_HOME": str(home / "state"),
           "OPENCODE_DISABLE_AUTOUPDATE": "true", "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
           "OPENCODE_DISABLE_CLAUDE_CODE": "true",
           "OPENCODE_DISABLE_EXTERNAL_SKILLS": "true",
           "OPENCODE_CONFIG": str(work / "opencode.json"), "CI": "true", "TERM": "dumb"}
    code, raw, stderr = bounded_process(
        [str(binary), "run", "--format", "json", "--agent", "gaslux-lab",
         "--model", MODEL, "First load the native skill gaslux-history-reuse using the skill tool. "
         "This is a synthetic read-only coding trial, not repository work. Then " + PROMPT],
        work, env)
    if code:
        raise cli_failure(code, raw, stderr)
    return parse_events(raw)


def assess(method):
    start = time.monotonic()
    report = {"accepted": False, "native_skills": [], "failure": None,
              "failure_stage": None, "failure_detail": None, "event_counts": {}}
    stage = "inference"
    try:
        addition, skills = method()
        report["native_skills"] = skills
        stage = "ast_functional_guard"
        factory.validate_addition("mint", addition, execute=True)
        report["accepted"] = True
        report["candidate_sha256"] = factory.sha256(addition.encode())
    except TrialFailure as error:
        report.update({"failure": error.category, "failure_stage": "opencode_events",
                       "failure_detail": error.detail, "event_counts": error.counts,
                       "native_skills": error.skills})
    except (ValueError, TypeError, KeyError, SyntaxError, OSError,
            subprocess.SubprocessError) as error:
        # Never publish raw model output or exception content.
        report["failure"] = type(error).__name__
        report["failure_stage"] = stage
    report["elapsed_seconds"] = round(time.monotonic() - start, 2)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    # The exact release archive is verified by the existing job before this CLI.
    with tempfile.TemporaryDirectory(prefix="gaslux-opencode-scratch-") as temp:
        work = Path(temp)
        prepare(work)
        direct = assess(lambda: (factory.call_model(PROMPT), []))
        agent = assess(lambda: run_cli(binary, work))
    report = {"experiment": "opencode-native-skill-synthetic-v3", "version": VERSION,
              "model": factory.MODEL, "model_digest": factory.MODEL_DIGEST,
              "direct_num_ctx": 5800, "opencode_configured_context": 65536,
              "stream_limit_bytes": MAX_EVENTS, "internal_file_limit_bytes": MAX_INTERNAL_FILE,
              "scratch_monitor_limit_bytes": MAX_SCRATCH, "scratch_hard_quota": False,
              "direct": direct, "opencode": agent,
              "native_skill_use_observed": SKILL in agent["native_skills"],
              "product_regressions_run": False, "production_authorized": False,
              "code_authorized": False, "merge_authorized": False,
              "writer_authorized": False, "release_eligible": False}
    with args.report.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps(report, sort_keys=True))
    # Negative comparison remains informative but never reports a green pilot.
    return 0 if agent["accepted"] and report["native_skill_use_observed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
