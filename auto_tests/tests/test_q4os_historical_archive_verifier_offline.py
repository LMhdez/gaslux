"""Adversarial offline Q4OS archive tests; no guest, network or disk writers."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from auto_tests.installer_observer.evidence import Refusal, canonical, digest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "q4os_archive_verifier_offline",
    ROOT / "auto_tests/tools/verify_q4os_action_archives_offline.py",
)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def png():
    def chunk(kind, payload):
        return (
            len(payload).to_bytes(4, "big")
            + kind
            + payload
            + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    return (
        verifier.PNG_SIGNATURE
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1280, 800, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00" * 32))
        + chunk(b"IEND", b"")
    )


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
    return buf.getvalue()


def fixture(tmp_path, monkeypatch):
    zips, meta = tmp_path / "zips", tmp_path / "metadata"
    zips.mkdir()
    meta.mkdir()
    p = png()
    runs = []
    archives = []
    for i, aid in enumerate(verifier.ARTIFACTS):
        count = 9 if i < 2 else 11
        report = b'{"report":true}'
        paths = [f"screen-{j}.png" for j in range(count)]
        members = {"evidence/ui-screenshots-report.json": report}
        members.update({f"evidence/{name}": p for name in paths})
        binary = archive(members.items())
        (zips / f"{aid}.zip").write_bytes(binary)
        run_id = verifier.RUNS[i]
        runs.append(
            {
                "artifactId": aid,
                "runId": str(run_id),
                "screenshots": [{"path": x, "sha256": digest(p)} for x in paths],
                "transitions": [{} for _ in range(count - 1)],
            }
        )
        item = {
            "artifactId": aid,
            "name": f"pinned-{aid}",
            "archiveSha256": digest(binary),
            "workflowCommit": "a" * 40,
            "reports": {"ui-screenshots-report.json": digest(report)},
        }
        archives.append(item)
        (meta / f"{aid}.json").write_text(
            json.dumps(
                {
                    "id": aid,
                    "name": item["name"],
                    "expired": False,
                    "digest": "sha256:" + item["archiveSha256"],
                    "workflow_run": {"id": run_id, "head_sha": item["workflowCommit"]},
                }
            )
        )
    manifest = {
        "distribution": "q4os",
        "schemaVersion": 1,
        "runs": runs[:2],
        "summaryRuns": runs[2:],
        "archives": archives,
    }
    target = tmp_path / "manifest.json"
    target.write_bytes(canonical(manifest))
    monkeypatch.setattr(verifier, "MANIFEST_SHA", digest(canonical(manifest)))
    return target, zips, meta, manifest


def test_four_synthetic_archives_pass_without_claiming_external_provenance(tmp_path, monkeypatch):
    args = fixture(tmp_path, monkeypatch)
    result = verifier.validate_archives(*args[:3])
    assert result["decision"] == "HISTORICAL_ARTIFACT_MATCHED"
    assert (result["screenshots"], result["transitions"]) == (40, 36)
    assert result["externalProvenance"] == "EXTERNAL_PROVENANCE_UNPROVEN"
    assert not any(
        result[k]
        for k in (
            "inputAuthorized",
            "diskWritesAuthorized",
            "trustBoundaryIndependent",
            "productionInstallationAuthorized",
            "releaseEligible",
        )
    )


@pytest.mark.parametrize(
    "kind",
    [
        "hash",
        "truncated",
        "extra",
        "traversal",
        "symlink",
        "duplicate",
        "run",
        "workflow",
        "report",
        "png",
        "manifest",
        "missing",
        "bomb",
        "wrong_name",
        "metadata",
        "swapped",
        "hardlink",
    ],
)
def test_adversarial_mutations_refused(tmp_path, monkeypatch, kind):
    manifest_path, zip_dir, metadata_dir, manifest = fixture(tmp_path, monkeypatch)
    aid = verifier.ARTIFACTS[0]
    zip_path = zip_dir / f"{aid}.zip"
    metadata_path = metadata_dir / f"{aid}.json"
    item = manifest["archives"][0]
    raw = zip_path.read_bytes()
    changed = False
    if kind in {"hash", "truncated"}:
        zip_path.write_bytes(raw + b"x" if kind == "hash" else raw[:-5])
        changed = True
    elif kind in {
        "extra",
        "traversal",
        "symlink",
        "duplicate",
        "report",
        "png",
        "bomb",
        "wrong_name",
        "swapped",
    }:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members = [(i.filename, z.read(i)) for i in z.infolist()]
        if kind == "extra":
            members.append(("outside/bad.txt", b"bad"))
        elif kind == "traversal":
            members.append(("evidence/../bad", b"bad"))
        elif kind == "duplicate":
            members.append(members[0])
        elif kind == "report":
            members[0] = (members[0][0], b"tampered")
        elif kind == "png":
            members[1] = (members[1][0], b"badpng")
        elif kind == "bomb":
            members.append(("calamares-inspect/bomb.bin", b"0" * 2_000_000))
        elif kind == "wrong_name":
            members.append(("evidence/unexpected.png", b"bad"))
        elif kind == "swapped":
            members[1] = (members[1][0], members[0][1])
        elif kind == "symlink":
            pass
        if kind == "symlink":
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w") as z:
                for name, data in members:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (0o120777 if name == members[0][0] else 0o100644) << 16
                    z.writestr(info, data)
            raw = out.getvalue()
        else:
            raw = archive(members)
        zip_path.write_bytes(raw)
        # Update all untrusted metadata and manifest digest to simulate forged consistency.
        item["archiveSha256"] = digest(raw)
        changed = True
    elif kind in {"run", "workflow", "metadata"}:
        doc = json.loads(metadata_path.read_text())
        if kind == "run":
            doc["workflow_run"]["id"] += 1
        elif kind == "workflow":
            doc["workflow_run"]["head_sha"] = "b" * 40
        else:
            doc["name"] = "forged-name"
        metadata_path.write_text(json.dumps(doc))
    elif kind == "manifest":
        manifest["distribution"] = "other"
        manifest_path.write_bytes(canonical(manifest))
    elif kind == "missing":
        metadata_path.unlink()
    elif kind == "hardlink":
        link = zip_dir / "duplicate.zip"
        os.link(zip_path, link)
    if changed:
        doc = json.loads(metadata_path.read_text())
        doc["digest"] = "sha256:" + item["archiveSha256"]
        metadata_path.write_text(json.dumps(doc))
        manifest_path.write_bytes(canonical(manifest))
        monkeypatch.setattr(verifier, "MANIFEST_SHA", digest(canonical(manifest)))
    # A wrong ZIP digest, even if its metadata is internally coherent, is no proof
    # of historical provenance; core pinned member checks still refuse mutations.
    with pytest.raises(Refusal):
        verifier.validate_archives(manifest_path, zip_dir, metadata_dir)


def test_pathname_swap_after_read_cannot_change_authenticated_bytes(tmp_path, monkeypatch):
    manifest_path, zip_dir, meta_dir, _ = fixture(tmp_path, monkeypatch)
    original_read = verifier.read
    first = verifier.ARTIFACTS[0]
    target = zip_dir / f"{first}.zip"

    def swap_after_read(path, limit=1024 * 1024):
        raw = original_read(path, limit)
        if path == target:
            substitute = target.with_suffix(".new")
            substitute.write_bytes(b"attacker")
            substitute.replace(target)
        return raw

    monkeypatch.setattr(verifier, "read", swap_after_read)
    result = verifier.validate_archives(manifest_path, zip_dir, meta_dir)
    assert result["decision"] == "HISTORICAL_ARTIFACT_MATCHED"


def test_archive_module_has_no_controller_or_network_imports():
    import ast

    source = (ROOT / "auto_tests/tools/verify_q4os_action_archives_offline.py").read_text()
    nodes = ast.walk(ast.parse(source))
    banned = {"q4os", "replay", "locators", "socket", "subprocess", "requests", "paramiko"}
    for node in nodes:
        if isinstance(node, ast.Import):
            assert all(x.name.split(".")[0] not in banned for x in node.names)
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[-1] not in banned
    assert "send_key" not in source
