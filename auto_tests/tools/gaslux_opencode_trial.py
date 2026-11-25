#!/usr/bin/env python3
"""Isolated OpenCode/Qwen proof of native skill use; never a publishing path."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import urllib.request

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
# CLI --format json structures the event envelope, not the model's answer.
# The native agent returns source inside the text event, without nested JSON.
AGENT_PROMPT = PROMPT.replace(
    "Return exactly one JSON object with key addition, no Markdown. "
    "Its value is a Python function with signature ",
    "Return only the Python function source, no explanation and no JSON encoding. "
    "A single complete Python code block is permitted. Use signature ",
)
SIGNATURE = "def assess_mint_lifecycle(evidence: dict) -> dict:"
MAX_ADDITION_BYTES = 16384
COMPACT_CONTEXT = 16384
BASELINE_CONTEXT = 65536
MAX_ATTEMPTS = 2
RETRYABLE = frozenset({"CANDIDATE_FORMAT_INVALID", "CANDIDATE_FENCE_INVALID",
                       "CANDIDATE_JSON_INVALID", "CANDIDATE_SCHEMA_INVALID"})



def prepare(work: Path, source: Path = ROOT, *, context=BASELINE_CONTEXT):
    if context not in (BASELINE_CONTEXT, COMPACT_CONTEXT):
        raise ValueError("Unreviewed context profile")
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
        "agent": {"gaslux-lab": {"mode": "primary", "steps": 4, "temperature": 0, "permission": permission}},
        "provider": {"ollama": {"npm": "@ai-sdk/openai-compatible",
                                "name": "Ollama", "options": {"baseURL": "http://127.0.0.1:11434/v1"},
                                "models": {factory.MODEL: {"name": factory.MODEL,
                                    "limit": {"context": context, "output": 1000},
                                    **({"options": {"reasoningEffort": "low"}}
                                       if context == COMPACT_CONTEXT else {})}}}},
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


def decode_candidate(text):
    """Extract exactly one complete answer; never search prose for executable code."""
    text = text.strip()
    if not text or len(text.encode("utf-8")) > MAX_ADDITION_BYTES:
        raise TrialFailure("CANDIDATE_SIZE_INVALID")
    if text.startswith("```"):
        match = re.fullmatch(r"```(python|py|json)?[ \t]*\r?\n(.*?)\r?\n```", text, re.DOTALL)
        if not match or "```" in match.group(2):
            raise TrialFailure("CANDIDATE_FENCE_INVALID")
        language, text = match.group(1), match.group(2).strip()
        if language == "json" and not text.startswith("{"):
            raise TrialFailure("CANDIDATE_JSON_INVALID", detail="JSON_FENCE")
        if language in ("python", "py") and not text.startswith(SIGNATURE):
            raise TrialFailure("CANDIDATE_FORMAT_INVALID", detail="PYTHON_FENCE")
    if text.startswith(SIGNATURE):
        # No repair, code substitution or arbitrary execution. The unchanged
        # factory.validate_addition() checks every AST node and fixtures next.
        return text
    if not text.startswith("{"):
        raise TrialFailure("CANDIDATE_FORMAT_INVALID", detail="NON_SOURCE_TEXT")

    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError):
        raise TrialFailure("CANDIDATE_JSON_INVALID", detail="JSON_OBJECT") from None
    if type(result) is not dict or set(result) != {"addition"} or type(result["addition"]) is not str:
        raise TrialFailure("CANDIDATE_SCHEMA_INVALID")
    addition = result["addition"]
    if not addition or len(addition.encode("utf-8")) > MAX_ADDITION_BYTES:
        raise TrialFailure("CANDIDATE_SIZE_INVALID")
    return addition



# OpenCode 1.19.6 JSON stream: recognize only reviewed event envelopes.
# Keep one validator for both experimental clients. An unknown event is not
# telemetry: it could conceal an unreviewed tool invocation.
EVENT_PART_TYPES = {"text": "text", "tool_use": "tool", "step_start": "step-start",
                    "step_finish": "step-finish", "reasoning": "reasoning"}
EVENT_TOOL_FIELDS = frozenset({"tool", "state", "callID", "callId", "toolName",
                               "toolCallId", "tool_call_id", "tool_calls"})


def decode_event(line):
    def unique_keys(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate event key")
            obj[key] = value
        return obj

    def reject_constant(_):
        raise ValueError("non-JSON constant")

    try:
        row = json.loads(line, object_pairs_hook=unique_keys, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise TrialFailure("EVENT_JSON_INVALID") from None
    if type(row) is not dict:
        raise TrialFailure("EVENT_SHAPE_INVALID")
    kind = row.get("type")
    if type(kind) is not str or kind not in (*EVENT_PART_TYPES, "error"):
        raise TrialFailure("EVENT_TYPE_UNEXPECTED")
    if EVENT_TOOL_FIELDS.intersection(row):
        raise TrialFailure("EVENT_ENVELOPE_INVALID")
    if kind == "error":
        # An error always terminates the stream in either client.
        return row
    part = row.get("part")
    if type(part) is not dict:
        raise TrialFailure("EVENT_PART_INVALID")
    # Older synthetic fixtures omit the inner type. If supplied, it must
    # agree with the outer event. Never reinterpret one part as another.
    if "type" in part and part["type"] != EVENT_PART_TYPES[kind]:
        raise TrialFailure("EVENT_PART_TYPE_MISMATCH")
    if kind != "tool_use" and EVENT_TOOL_FIELDS.intersection(part):
        raise TrialFailure("UNEXPECTED_TOOL")
    if kind in ("text", "reasoning") and type(part.get("text")) is not str:
        raise TrialFailure("TEXT_EVENT_INVALID")
    return row


def parse_events(raw: bytes, observations=None):
    if len(raw) > MAX_EVENTS:
        raise TrialFailure("EVENT_STREAM_OVERSIZE")
    texts, skills = [], []
    counts = {}
    token_totals = {"input": 0, "output": 0, "reasoning": 0, "cache_read": 0, "cache_write": 0}
    token_steps = 0

    def record():
        if observations is not None:
            observations.update({"event_counts": dict(counts), "reported_tokens": dict(token_totals),
                                 "token_steps": token_steps})

    def fail(category, detail=None):
        record()
        raise TrialFailure(category, skills=skills, counts=counts, detail=detail)

    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = decode_event(line)
        except TrialFailure as error:
            fail(error.category, error.detail)
        kind = row["type"]
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "error":
            error = row.get("error")
            name = error.get("name") if type(error) is dict else None
            allowed = ("APIError", "ProviderAuthError", "UnknownError",
                       "MessageAbortedError", "ContextOverflowError",
                       "OutputLengthError", "StructuredOutputError")
            fail("OPENCODE_ERROR_EVENT", name if name in allowed else "OTHER")
        if kind == "step_finish":
            part = row.get("part")
            tokens = part.get("tokens") if type(part) is dict else None
            if type(tokens) is dict:
                cache = tokens.get("cache")
                for key in ("input", "output", "reasoning", "cache_read", "cache_write"):
                    value = (cache.get(key.removeprefix("cache_")) if
                             key.startswith("cache_") and type(cache) is dict else tokens.get(key))
                    if type(value) is int and 0 <= value <= 1_000_000:
                        token_totals[key] += value
                token_steps += 1
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
        addition = decode_candidate("".join(texts))
    except TrialFailure as error:
        fail(error.category, error.detail)
    record()
    return addition, sorted(set(skills))


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


def run_cli(binary: Path, work: Path, observations=None, correction=None):
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
    if correction is not None and correction not in RETRYABLE | {"AST_FUNCTIONAL_REJECTED"}:
        raise ValueError("Unreviewed repair reason")
    prompt = AGENT_PROMPT
    if correction:
        prompt += "\nPrevious attempt rejected: " + correction + ". Re-read the skill and return corrected source only."
    code, raw, stderr = bounded_process(
        [str(binary), "run", "--format", "json", "--agent", "gaslux-lab",
         "--model", MODEL, "First load the native skill gaslux-history-reuse using the skill tool. "
         "This is a synthetic read-only coding trial, not repository work. Then " + prompt],
        work, env, timeout=480 if correction else 900)
    if code:
        raise cli_failure(code, raw, stderr)
    return parse_events(raw, observations)


def model_snapshot():
    # Ollama /api/ps reports model allocation, not whole-run peak RSS.
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/ps", timeout=5) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            return None
        data = json.loads(raw)
        for row in data.get("models", []):
            if row.get("digest") != factory.MODEL_DIGEST:
                continue
            result = {}
            for key in ("size", "size_vram", "context_length"):
                value = row.get(key)
                if type(value) is int and 0 <= value <= 2**50:
                    result[key] = value
            return result
    except (ValueError, TypeError, AttributeError, OSError):
        pass
    return None


def attempt_candidate(binary, work, context, correction=None):
    prepare(work, context=context)
    observations = {}
    row = assess(lambda: run_cli(binary, work, observations, correction), workspace=work)
    row.update(observations)
    row["ollama_loaded_model"] = model_snapshot()
    return row


def bounded_repair(attempt):
    rows = [attempt(None)]
    first = rows[0]
    if not first["accepted"] and SKILL in first["native_skills"]:
        reason = first["failure"]
        if first["failure_stage"] == "ast_functional_guard":
            reason = "AST_FUNCTIONAL_REJECTED"
        if reason in RETRYABLE | {"AST_FUNCTIONAL_REJECTED"}:
            rows.append(attempt(reason))
    return rows[-1], rows


def assess(method, workspace=None):
    start = time.monotonic()
    report = {"accepted": False, "native_skills": [], "failure": None,
              "failure_stage": None, "failure_detail": None, "event_counts": {}}
    stage = "inference"
    try:
        addition, skills = method()
        report["native_skills"] = skills
        stage = "ast_functional_guard"
        if workspace is not None:
            # The model has no edit tool. The trusted harness materializes only
            # a statically admitted function in a fresh private scratch file.
            factory.validate_addition("mint", addition, execute=False)
            path = workspace / "candidate.py"
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(addition)
            if path.read_bytes() != addition.encode():
                raise ValueError("Candidate readback mismatch")
            addition = path.read_text(encoding="utf-8")
            report["scratch_candidate_materialized"] = True
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
    parser.add_argument("--context", type=int, choices=(BASELINE_CONTEXT, COMPACT_CONTEXT),
                        default=BASELINE_CONTEXT)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    # The exact release archive is verified by the existing job before this CLI.
    with tempfile.TemporaryDirectory(prefix="gaslux-opencode-scratch-") as temp:
        work = Path(temp)
        direct = assess(lambda: (factory.call_model(PROMPT), []))
        direct["ollama_loaded_model"] = model_snapshot()
        def attempt(correction):
            with tempfile.TemporaryDirectory(prefix="attempt-", dir=work) as attempt_dir:
                return attempt_candidate(binary, Path(attempt_dir), args.context, correction)
        agent, attempts = bounded_repair(attempt)
    report = {"experiment": "opencode-native-skill-synthetic-v5", "version": VERSION,
              "model": factory.MODEL, "model_digest": factory.MODEL_DIGEST,
              "direct_num_ctx": 5800, "opencode_configured_context": args.context,
              "opencode_requested_reasoning_effort": "low" if args.context == COMPACT_CONTEXT else None,
              "opencode_attempts": attempts, "max_attempts": MAX_ATTEMPTS,
              "native_edit_or_shell_enabled": False, "os_sandbox_verified": False,
              "direct_response_contract": "structured_json",
              "opencode_response_contract": "one_source_function_or_exact_json_envelope",
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
