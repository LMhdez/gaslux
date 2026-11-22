#!/usr/bin/env python3
"""Zero-API-credit, unprivileged Gaslux specialist developer (curated pilot).

The model supplies a single missing product code line. Independent validation
requires exact task identity, exact source and line, safe C# syntax, and a
real outstanding feature, not an intentionally introduced regression.

All model inference and candidate tests run without GitHub write credentials.
The privileged publisher (on trusted main) separately validates every byte.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request


MISSION_PATH = Path("docs/autonomy/agent_missions.json")
OUT = Path("evidence/autonomous-agent")
EXPECTED_MODEL = "qwen3.5:9b"
EXPECTED_DIGEST = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
SOURCE = Path("Installation/WindowsKeyboardLayout.cs")
ALLOWED_IDS = {"00000816": "pt", "00000416": "br"}
LINE = re.compile(r'^\s*\{\s*"([0-9A-Fa-f]{8})",\s*Mapping\("([a-z]{2})"\)\s*\},\s*$')


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def tasks() -> list[dict]:
    data = json.loads(MISSION_PATH.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unexpected mission schema")
    result = data["tasks"]
    if len(result) != 2 or {x["keyboard_identifier"] for x in result} != set(ALLOWED_IDS):
        raise ValueError("Mission changes require trusted publisher review")
    for x in result:
        if x["source"] != str(SOURCE) or ALLOWED_IDS.get(x["keyboard_identifier"]) != x["xkb_layout"]:
            raise ValueError("Task outside approved product scope")
    return result


def plan(role: str = "") -> dict:
    raw = SOURCE.read_bytes()
    text = raw.decode("utf-8")
    for task in tasks():
        if role and task["role"] != role:
            continue
        key = task["keyboard_identifier"]
        if re.search(r'\{\s*"' + key + r'"\s*,', text):
            continue
        anchor = re.search(r'^\s*\{\s*"' + task["anchor_identifier"] + r'"\s*,.+$', text, re.M)
        if not anchor or text.count('"' + task["anchor_identifier"] + '"') != 1:
            raise ValueError("Unique mapping insertion anchor missing")
        return {
            "role": task["role"], "task": task, "source_sha256": digest(raw),
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "status": "pending",
        }
    return {"status": "idle", "role": "", "task": None}


def propose(source: str, task: dict, suggestion: str) -> str:
    matched = LINE.fullmatch(suggestion)
    if not matched:
        raise ValueError("Model produced unauthorized statement")
    if (matched.group(1).upper(), matched.group(2)) != (
        task["keyboard_identifier"], task["xkb_layout"]
    ):
        raise ValueError("Model candidate does not implement selected feature")
    if len(suggestion) > 95 or ";" in suggestion or "#" in suggestion:
        raise ValueError("Unexpected syntax")
    anchor = re.compile(r'^(\s*\{\s*"' + task["anchor_identifier"] + r'"\s*,.+\n)', re.M)
    matches = list(anchor.finditer(source))
    if len(matches) != 1 or task["keyboard_identifier"] in source:
        raise ValueError("Baseline changed while task executed")
    indentation = re.match(r"^\s*", matches[0].group(1)).group(0)
    new_line = indentation + suggestion.strip() + "\n"
    candidate = source[:matches[0].end()] + new_line + source[matches[0].end():]
    if candidate != anchor.sub(lambda m: m.group(1) + new_line, source, count=1):
        raise ValueError("Unexpected unrelated code mutation")
    return candidate


def acceptance(original: str, candidate: str, task: dict) -> None:
    if len(candidate.splitlines()) != len(original.splitlines()) + 1:
        raise ValueError("Exactly one line must be added")
    key = task["keyboard_identifier"]
    layout = task["xkb_layout"]
    entries = re.findall(r'\{\s*"([0-9A-Fa-f]{8})",\s*Mapping\("([a-z-]+)"(?:,\s*"[^"]+")?\)\s*\}', candidate)
    if (key, layout) not in entries or sum(i == key for i, _ in entries) != 1:
        raise ValueError("Real keyboard mapping feature acceptance failed")
    if not re.search(r'^\s*\{\s*"' + key + r'",\s*Mapping\("' + layout + r'"\)\s*\},$', candidate, re.M):
        raise ValueError("Expected exact mapping entry absent")
    expected = propose(original, task, next(
        s for s in candidate.splitlines() if '"' + key + '"' in s
    ))
    if candidate != expected:
        raise ValueError("Unrelated source changes")


def call_model(prompt: str) -> tuple[str, str]:
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps({
            "model": EXPECTED_MODEL, "stream": False,
            "prompt": prompt, "think": False,
            "format": {"type": "object", "properties": {"line": {"type": "string"}},
                       "required": ["line"], "additionalProperties": False},
            "options": {"temperature": 0, "num_ctx": 3000, "num_predict": 120},
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=270) as response:
        data = json.load(response)
    return json.loads(data["response"])["line"], str(data.get("total_duration", ""))


def run(role: str) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    selected = plan(role)
    report: dict = {
        "model": EXPECTED_MODEL, "model_digest": EXPECTED_DIGEST,
        "role": role, "status": selected["status"], "candidate_valid": False,
    }
    if selected["status"] == "idle":
        (OUT / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return 0
    task = selected["task"]
    report.update({
        "task_id": task["id"], "target": task["source"],
        "base_commit": selected["source_commit"],
        "source_sha256": selected["source_sha256"],
        "task_identifier": task["keyboard_identifier"],
        "expected_layout": task["xkb_layout"],
    })
    original = SOURCE.read_bytes()
    source = original.decode("utf-8")
    prompt = (
        "You are implementing a missing feature in the actual Gaslux Windows-to-Linux "
        "installer, NOT correcting a synthetic seeded bug. The shared installer "
        "translates Windows keyboard IDs into XKB layouts. Insert ONE safe mapping "
        "dictionary entry after the existing anchor. Return JSON only: {\"line\": "
        "\"...\"}. No explanation, no full file, no side effects, no method call "
        "except Mapping, no semicolon. Keep indentation out of response.\n"
        f"MISSION: {task['description']}\n"
        f"Windows keyboard identifier: {task['keyboard_identifier']}\n"
        f"Linux XKB layout: {task['xkb_layout']}\n"
        f"Existing map anchor: {next(s.strip() for s in source.splitlines() if '\"' + task['anchor_identifier'] + '\"' in s)}\n"
        "Example C# dictionary entry syntax: { \"00000409\", Mapping(\"us\") },\n"
    )
    report["attempts"] = []
    for attempt in range(1, 3):
        row: dict = {"attempt": attempt}
        report["attempts"].append(row)
        try:
            line, duration = call_model(prompt)
            row["model_duration_ns"] = duration
            row["proposed_line"] = line[:150]
            updated = propose(source, task, line)
            acceptance(source, updated, task)
            if SOURCE.read_bytes() != original:
                raise RuntimeError("Unprivileged runner source unexpectedly changed")
            (OUT / "candidate.cs").write_bytes(updated.encode())
            report["candidate_sha256"] = digest(updated.encode())
            report["candidate_valid"] = True
            report["status"] = "candidate_green"
            row["passed"] = True
            break
        except Exception as error:
            row["passed"] = False
            row["error"] = f"{type(error).__name__}: {str(error)[:180]}"
            prompt += "\nRejected candidate. Fix syntax and return exactly one mapping line as JSON.\n"
    (OUT / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["candidate_valid"] else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["plan", "run"])
    parser.add_argument("--role", choices=["", "mint", "zorin"], default="")
    args = parser.parse_args()
    if args.action == "plan":
        print(json.dumps(plan(args.role), sort_keys=True))
        return 0
    return run(args.role)


if __name__ == "__main__":
    sys.exit(main())
