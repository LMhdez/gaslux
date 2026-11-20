#!/usr/bin/env python3
"""Independently verify two original Q4OS UI artifacts; never touch VM/disks/network."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
from pathlib import Path

ISO_SHA = "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d"
LAB_COMMIT = "6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb"
_HASH_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)\Z")


class PairProofError(ValueError):
    """Refuse evidence that is absent, wrong, cross-run or not reproducible."""


def read_regular(directory: Path, name: str, *, limit: int = 8 * 1024 * 1024) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise PairProofError("Unsafe evidence file name")
    path = directory / name
    if directory.is_symlink() or not directory.is_dir():
        raise PairProofError("Unsafe evidence directory")
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise PairProofError("Missing, linked or oversized file: " + name)
        return path.read_bytes()
    except OSError as exc:
        raise PairProofError("Unreadable original evidence: " + name) from exc


def verify_manifest(directory: Path) -> dict[str, str]:
    manifest_bytes = read_regular(directory, "evidence.sha256", limit=1024 * 1024)
    rows = manifest_bytes.decode("ascii").splitlines()
    entries = {}
    for line in rows:
        hit = _HASH_LINE.fullmatch(line)
        if not hit or hit[2] == "evidence.sha256" or hit[2] in entries:
            raise PairProofError("Invalid, duplicate or self-referential SHA manifest line")
        entries[hit[2]] = hit[1]
    if list(entries) != sorted(entries):
        raise PairProofError("Unsorted SHA evidence manifest")
    actual = {path.name for path in directory.iterdir() if path.name != "evidence.sha256"}
    if set(entries) != actual:
        raise PairProofError("Missing/unlisted evidence files")
    for name, expected in entries.items():
        raw = read_regular(directory, name)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise PairProofError("Original evidence bytes changed: " + name)
    return entries


def load_gate(path: Path):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PairProofError("Invalid pinned visual gate script")
    spec = importlib.util.spec_from_file_location("gaslux_q4os_gate_pair", path)
    if spec is None or spec.loader is None:
        raise PairProofError("Cannot load visual gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit_replica(artifact: Path, mapping: dict, gate) -> dict:
    directory = artifact / "evidence"
    entries = verify_manifest(directory)
    report = json.loads(read_regular(directory, "ui-screenshots-report.json"))
    if (
        report.get("kind") != "q4os-genuine-visual-experiment"
        or report.get("isoSha256") != ISO_SHA
        or report.get("labSourceCommit") != LAB_COMMIT
        or report.get("installationAuthorized") is not False
        or report.get("windowsDiskAttached") is not False
        or report.get("nativeCalamaresInstallExecuted") is not False
        or report.get("summaryVisited") is not False
    ):
        raise PairProofError("Experiment authority or media identity mismatch")
    if len(report.get("states", [])) != len(mapping["states"]):
        raise PairProofError("State count did not match pinned UI map")
    for expected, actual in zip(mapping["states"], report["states"], strict=True):
        if (
            actual.get("state") != expected["id"]
            or actual.get("png") != expected["screenshot"]
            or actual.get("visualGate") != expected["visualGate"]
            or actual.get("visualGateVerified") is not True
            or actual.get("resolution") != [1280, 800]
        ):
            raise PairProofError("Original screenshot/UI state contract mismatch")
        name = expected["screenshot"]
        if actual.get("sha256") != entries.get(name):
            raise PairProofError("Screenshot SHA does not match retained file")
        guard = getattr(gate, expected["visualGate"], None)
        if not callable(guard) or not guard((directory / name).resolve(strict=True)):
            raise PairProofError("Independent visual RGB guard refused screenshot: " + name)
    for expected, actual in zip(mapping["transitions"], report.get("transitions", []), strict=True):
        if (
            actual.get("from") != expected["from"]
            or actual.get("to") != expected["to"]
            or actual.get("centralPixelTransition") is not True
        ):
            raise PairProofError("Transition not positively observed")
        before_name = next(
            state["screenshot"] for state in mapping["states"] if state["id"] == expected["from"]
        )
        before = directory / before_name
        after = directory / next(
            s["screenshot"] for s in mapping["states"] if s["id"] == expected["to"]
        )
        if not gate.verified_centre_changed(before.resolve(), after.resolve()):
            raise PairProofError("No independent central ROI transition detected")
        before_matches = actual["beforeSha256"] == entries.get(before.name)
        after_matches = actual["afterSha256"] == entries.get(after.name)
        if not (before_matches and after_matches):
            raise PairProofError("State-to-transition PNG linkage mismatch")
    if len(report["transitions"]) != len(mapping["transitions"]):
        raise PairProofError("Unexpected transition count")
    serial = read_regular(directory, "serial.log", limit=8 * 1024 * 1024)
    gpt = read_regular(directory, "gpt-audit.txt")
    if not serial or b"GASLUX_Q4OS_VM_GPT_AUDIT=PASS" not in gpt:
        raise PairProofError("Missing independent guest serial/GPT proof")
    policy = json.loads(read_regular(artifact / "calamares-inspect", "native-calamares-audit.json"))
    if (
        policy.get("nativeCalamaresConfigVerified") is not True
        or policy.get("upstreamInstallsEfiFallback") is not True
        or policy.get("windowsEspFallbackWriteAuthorized") is not False
        or policy.get("installationAuthorized") is not False
        or policy.get("version") != "6.10-deb13u1"
    ):
        raise PairProofError("Calamares ISO policy was not independently audited")
    package = read_regular(artifact / "calamares-inspect", "calamares-package-version.txt")
    if b"Version:" not in package or b"Package: calamares" not in package:
        raise PairProofError("Exact ISO Calamares binary package version not determined")
    return {
        "replica": report["replica"],
        "runId": report["runId"],
        "attempt": report["attempt"],
        "isoSizeBytes": report["isoSizeBytes"],
        "screenshots": {s["state"]: s["sha256"] for s in report["states"]},
        "visualTransitionsRechecked": len(report["transitions"]),
        "calamaresPackage": package.decode("utf-8").strip().splitlines()[:3],
    }


def verify_pair(artifacts: list[Path], map_path: Path, gate_path: Path) -> dict:
    if len(artifacts) != 2:
        raise PairProofError("Exactly two independent artifact directories required")
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    # This verifier covers the original blank-Users experiment only.
    for key, count in (("states", 9), ("transitions", 8)):
        mapping[key] = [
            row
            for row in mapping[key]
            if any(proof["runId"] == "44641233701" for proof in row["proofs"])
        ]
        if len(mapping[key]) != count:
            raise PairProofError("Incomplete historical Users experiment")
    gate = load_gate(gate_path)
    reports = [audit_replica(artifact, mapping, gate) for artifact in artifacts]
    if (
        {r["replica"] for r in reports} != {1, 2}
        or len({r["runId"] for r in reports}) != 1
        or len({r["attempt"] for r in reports}) != 1
        or len({str(p.resolve()) for p in artifacts}) != 2
        or len({r["isoSizeBytes"] for r in reports}) != 1
    ):
        raise PairProofError("Not two independent, matching-ISO guest replicas")
    return {
        "distribution": "q4os",
        "isoSha256": ISO_SHA,
        "runId": reports[0]["runId"],
        "attempt": reports[0]["attempt"],
        "stateCountVerifiedInTwoGuests": 9,
        "transitionCountVerifiedInTwoGuests": 8,
        "replicas": sorted(reports, key=lambda r: r["replica"]),
        "nativeCalamaresInstallExecuted": False,
        "windowsDiskAttached": False,
        "summaryVisited": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("map", type=Path)
    parser.add_argument("gate", type=Path)
    parser.add_argument("replica1", type=Path)
    parser.add_argument("replica2", type=Path)
    args = parser.parse_args()
    result = verify_pair(
        [args.replica1, args.replica2],
        args.map,
        args.gate,
    )
    print("Q4OS_TWO_VM_PROOF=" + json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
