#!/usr/bin/env python3
"""Isolated OpenCode/Qwen proof of native skill use; never a publishing path."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import resource
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
        "permission": permission,
        "agent": {"gaslux-lab": {"mode": "primary", "steps": 4, "permission": permission}},
        "provider": {"ollama": {"npm": "@ai-sdk/openai-compatible",
                                "name": "Ollama", "options": {"baseURL": "http://127.0.0.1:11434/v1"},
                                "models": {factory.MODEL: {"name": factory.MODEL,
                                    "limit": {"context": 65536, "output": 1000}}}}},
    }
    (work / "opencode.json").write_text(json.dumps(config), encoding="utf-8")
    return config


def parse_events(raw: bytes):
    if len(raw) > MAX_EVENTS:
        raise ValueError("Oversized CLI event stream")
    texts, skills = [], []
    for line in raw.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if type(row) is not dict:
            raise ValueError("Invalid event")
        if row.get("type") == "error":
            raise ValueError("OpenCode error event")
        if row.get("type") not in ("text", "tool_use"):
            continue
        part = row.get("part")
        if type(part) is not dict:
            raise ValueError("Invalid event part")
        if row["type"] == "text":
            if type(part.get("text")) is not str:
                raise ValueError("Invalid text event")
            texts.append(part["text"])
        else:
            state = part.get("state")
            if (part.get("tool") != "skill" or type(state) is not dict
                    or state.get("status") != "completed" or type(state.get("input")) is not dict):
                raise ValueError("Unexpected or failed tool use")
            name = state["input"].get("name")
            if (name not in ["gaslux-" + n for n in SKILLS]
                    or type(state.get("output")) is not str
                    or '<skill_content name="' + name + '">' not in state["output"]):
                raise ValueError("Native skill output missing")
            skills.append(name)
    if SKILL not in skills:
        raise ValueError("Required native skill not loaded")
    result = json.loads("".join(texts).strip())
    if type(result) is not dict or set(result) != {"addition"} or type(result["addition"]) is not str:
        raise ValueError("Invalid candidate schema")
    return result["addition"], sorted(set(skills))


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
           "OPENCODE_DISABLE_CLAUDE_CODE": "true", "CI": "true", "TERM": "dumb"}
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_EVENTS, MAX_EVENTS))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        run = subprocess.run(
            [str(binary), "run", "--format", "json", "--agent", "gaslux-lab",
             "--model", MODEL, "First load the native skill gaslux-history-reuse using the skill tool. "
             "This is a synthetic read-only coding trial, not repository work. Then " + PROMPT],
            cwd=work, env=env, stdout=output, stderr=errors, timeout=900,
            preexec_fn=limit, check=False, start_new_session=True)
        if run.returncode:
            raise ValueError("OpenCode nonzero exit")
        output.seek(0)
        return parse_events(output.read(MAX_EVENTS + 1))


def assess(method):
    start = time.monotonic()
    report = {"accepted": False, "native_skills": [], "failure": None}
    try:
        addition, skills = method()
        report["native_skills"] = skills
        factory.validate_addition("mint", addition, execute=True)
        report["accepted"] = True
        report["candidate_sha256"] = factory.sha256(addition.encode())
    except (ValueError, TypeError, KeyError, SyntaxError, OSError,
            subprocess.SubprocessError) as error:
        # Never publish raw model output or exception content.
        report["failure"] = type(error).__name__
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
    report = {"experiment": "opencode-native-skill-synthetic-v1", "version": VERSION,
              "model": factory.MODEL, "model_digest": factory.MODEL_DIGEST,
              "direct_num_ctx": 5800, "opencode_configured_context": 65536,
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
