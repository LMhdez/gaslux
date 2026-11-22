"""Negative tests for the original Q4OS evidence, offline and no guest input.

The pinned upstream map, manifest and binary fixture blobs are immutable inputs.
Any mutated copy is placed in pytest temporary directories only.
"""

from __future__ import annotations

import io
import json
import shutil
from dataclasses import replace

import pytest
from PIL import Image

from auto_tests.installer_observer import q4os
from auto_tests.installer_observer.evidence import Refusal, digest, read
from auto_tests.installer_observer.replay import replay
from auto_tests.installer_observer.schema import load_map, validate
from auto_tests.tools.gaslux_q4os_summary_visual_gate import ScreenRefusal


@pytest.fixture(scope="module")
def mapping():
    return load_map(q4os.MAP, q4os.PROFILE)


@pytest.fixture(scope="module")
def originals(mapping):
    return tuple(q4os.recordings(mapping, q4os.MANIFEST, q4os.ORIGINALS))


@pytest.fixture
def local_recording(tmp_path, originals):
    record = originals[0]
    directory = tmp_path / str(record.artifact_id)
    directory.mkdir()
    for row in record.states:
        shutil.copyfile(record.directory / row.filename, directory / row.filename)
    return replace(record, directory=directory)


def run_record(mapping, recording, recognize=q4os.recognize, edge_check=q4os.validate_edge):
    return replay(mapping, recording, recognize, edge_check, q4os.REGION)


def test_four_original_sessions_are_distinct_and_read_only(mapping, originals):
    report = q4os.replay_q4os()
    assert len(originals) == 4
    assert tuple(x.artifact_id for x in originals) == (
        14587306682,
        14586773677,
        14590616864,
        14589299655,
    )
    assert tuple(x.run_id for x in originals) == (
        "44641233701",
        "44641233701",
        "44648406729",
        "44648406729",
    )
    assert tuple(x.replica for x in originals) == (1, 2, 1, 2)
    assert tuple(len(x.states) for x in originals) == (9, 9, 11, 11)
    assert tuple(len(x.edges) for x in originals) == (8, 8, 10, 10)
    assert sum(len(x.states) for x in originals) == 40
    assert sum(len(x.edges) for x in originals) == 36
    sessions = report["manifest"]["sessions"]
    assert tuple(x["artifact_id"] for x in sessions) == tuple(x.artifact_id for x in originals)
    assert sum(len(x["frames"]) for x in sessions) == 40
    assert sum(len(x["steps"]) for x in sessions) == 36
    assert sessions[-1]["final_state"] == "calamares-summary"
    assert sessions[-2]["final_state"] == "calamares-summary"
    assert mapping.terminal == "calamares-summary"
    assert report["manifest"]["live_input_count"] == 0
    assert all(
        step["authorized_action"] is None for session in sessions for step in session["steps"]
    )


@pytest.mark.parametrize("field", ("runId", "artifactId", "replica", "attempt"))
def test_manifest_identity_tamper_refused(tmp_path, mapping, field):
    manifest = json.loads(read(q4os.MANIFEST))
    first = manifest["runs"][0]
    first[field] = first[field] + 1 if isinstance(first[field], int) else "bogus-run"
    altered = tmp_path / "manifest.json"
    altered.write_text(json.dumps(manifest))
    with pytest.raises(Refusal):
        tuple(q4os.recordings(mapping, altered, q4os.ORIGINALS))


def test_workflow_commit_tamper_refused(tmp_path, mapping):
    manifest = json.loads(read(q4os.MANIFEST))
    manifest["archives"][0]["workflowCommit"] = "0" * 40
    altered = tmp_path / "manifest.json"
    altered.write_text(json.dumps(manifest))
    with pytest.raises(Refusal):
        tuple(q4os.recordings(mapping, altered, q4os.ORIGINALS))


def test_missing_or_reordered_manifest_transition_refused(tmp_path, mapping):
    manifest = json.loads(read(q4os.MANIFEST))
    edges = manifest["runs"][0]["transitions"]
    edges[0], edges[1] = edges[1], edges[0]
    altered = tmp_path / "manifest.json"
    altered.write_text(json.dumps(manifest))
    with pytest.raises(Refusal):
        tuple(q4os.recordings(mapping, altered, q4os.ORIGINALS))


def test_original_report_sha_mutation_refused(tmp_path, originals):
    from auto_tests.installer_observer.evidence import parse

    original = originals[0]
    manifest = parse(read(q4os.MANIFEST))
    archive = next(a for a in manifest["archives"] if a["artifactId"] == original.artifact_id)
    report = read(original.directory / "ui-screenshots-report.json")
    altered_dir = tmp_path / "report-tamper"
    altered_dir.mkdir()
    (altered_dir / "ui-screenshots-report.json").write_bytes(report + b" ")
    with pytest.raises(Refusal, match="report SHA-256"):
        q4os._report(altered_dir, archive, "ui-screenshots-report.json")


def test_original_png_missing_refused(mapping, local_recording):
    (local_recording.directory / local_recording.states[1].filename).unlink()
    with pytest.raises(Refusal):
        run_record(mapping, local_recording)


def test_original_png_tampering_refused(mapping, local_recording):
    first = local_recording.states[0]
    (local_recording.directory / first.filename).write_bytes(b"forged PNG")
    with pytest.raises(Refusal):
        run_record(mapping, local_recording)


def test_original_cross_replica_png_substitution_refused(mapping, local_recording, originals):
    first = local_recording.states[0]
    donor = originals[1].directory / first.filename
    assert digest(read(donor, 2 * 1024 * 1024)) != first.sha256
    shutil.copyfile(donor, local_recording.directory / first.filename)
    with pytest.raises(Refusal):
        run_record(mapping, local_recording)


def test_original_png_wrong_dimensions_refused(mapping, local_recording):
    second = local_recording.states[1]
    buffer = io.BytesIO()
    Image.new("RGB", (100, 100), "white").save(buffer, "PNG")
    forged = buffer.getvalue()
    (local_recording.directory / second.filename).write_bytes(forged)
    rows = list(local_recording.states)
    rows[1] = replace(second, sha256=digest(forged))
    with pytest.raises(Refusal):
        run_record(mapping, replace(local_recording, states=tuple(rows)))


@pytest.mark.parametrize("alias", ("symlink", "hardlink"))
def test_original_png_alias_refused(mapping, local_recording, alias):
    first = local_recording.states[0]
    path = local_recording.directory / first.filename
    target = local_recording.directory / "other.png"
    path.rename(target)
    if alias == "symlink":
        path.symlink_to(target)
    else:
        path.hardlink_to(target)
    with pytest.raises(Refusal):
        run_record(mapping, local_recording)


def test_path_escape_refused(mapping, local_recording):
    rows = list(local_recording.states)
    rows[0] = replace(rows[0], filename="../outside.png")
    with pytest.raises(Refusal):
        run_record(mapping, replace(local_recording, states=tuple(rows)))


def test_undeclared_and_unverified_edges_refused(mapping, local_recording):
    first = local_recording.states[0].id
    missing_edge = replace(
        mapping, transitions=tuple(t for t in mapping.transitions if t.source != first)
    )
    with pytest.raises(Refusal):
        run_record(missing_edge, local_recording)
    broken = replace(
        mapping,
        transitions=tuple(
            replace(t, verified=False) if t.source == local_recording.states[0].id else t
            for t in mapping.transitions
        ),
    )
    with pytest.raises(Refusal):
        run_record(broken, local_recording)


def test_reordered_or_concatenated_sessions_refused(mapping, local_recording, originals):
    rows = list(local_recording.states)
    rows[0], rows[1] = rows[1], rows[0]
    with pytest.raises(Refusal):
        run_record(mapping, replace(local_recording, states=tuple(rows)))
    merged = replace(local_recording, states=local_recording.states + originals[2].states)
    with pytest.raises(Refusal):
        run_record(mapping, merged)


def test_summary_fabrication_refused(tmp_path, mapping, originals):
    summary = originals[2]
    directory = tmp_path / "summary"
    directory.mkdir()
    for row in summary.states:
        shutil.copyfile(summary.directory / row.filename, directory / row.filename)
    last = summary.states[-1]
    output = io.BytesIO()
    Image.new("RGB", mapping.resolution, "white").save(output, "PNG")
    altered = output.getvalue()
    (directory / last.filename).write_bytes(altered)
    rows = list(summary.states)
    rows[-1] = replace(last, sha256=digest(altered))
    with pytest.raises(Refusal):
        run_record(mapping, replace(summary, directory=directory, states=tuple(rows)))


def test_original_map_tamper_refused(tmp_path):
    data = json.loads(read(q4os.MAP))
    data["stopBoundary"]["lastObservedState"] = "calamares-install"
    fake = tmp_path / "map.json"
    fake.write_text(json.dumps(data))
    with pytest.raises(Refusal):
        load_map(fake, q4os.PROFILE)


def test_schema_tamper_refused(tmp_path):
    fake = tmp_path / "schema.json"
    fake.write_text('{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array"}')
    document = json.loads(read(q4os.MANIFEST))
    with pytest.raises(Refusal):
        validate(document, fake)


def test_fail_closed_on_unchanged_review_roi(mapping, local_recording):
    first = local_recording.states[0]
    second = local_recording.states[1]
    (local_recording.directory / second.filename).write_bytes(
        (local_recording.directory / first.filename).read_bytes()
    )
    rows = list(local_recording.states)
    rows[1] = replace(second, sha256=first.sha256)
    seen = iter((row.id,) for row in rows)
    with pytest.raises(Refusal):
        run_record(
            mapping,
            replace(local_recording, states=tuple(rows)),
            recognize=lambda _frame: next(seen),
        )


def test_ocr_and_pixel_gate_failure_propagate(monkeypatch, mapping, originals):
    def failed_ocr(*_args, **_kwargs):
        raise OSError("Tesseract unavailable")

    monkeypatch.setattr(q4os.summary.subprocess, "run", failed_ocr)
    with pytest.raises((Refusal, ScreenRefusal)):
        run_record(mapping, originals[2])


def test_original_replay_never_opens_transport(monkeypatch):
    import socket

    def forbidden_socket(*_args, **_kwargs):
        pytest.fail("Historical replay must remain offline")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    replayed = q4os.replay_q4os()
    assert replayed["manifest"]["live_input_count"] == 0


def test_cli_has_no_input_subcommand():
    from auto_tests.installer_observer.cli import main

    with pytest.raises(SystemExit):
        main(["click"])
    with pytest.raises(SystemExit):
        main(["install"])


# N-04: All archive parsing must consume the exact bytes authenticated by SHA-256.
# These ZIPs are synthetic contract fixtures, not copies of the original evidence.


@pytest.fixture
def synthetic_q4os_archives(tmp_path, monkeypatch):
    import zipfile

    from auto_tests.installer_observer.evidence import canonical

    manifest = json.loads(read(q4os.MANIFEST))
    zip_dir = tmp_path / "synthetic-zips"
    metadata_dir = tmp_path / "synthetic-metadata"
    originals_dir = tmp_path / "synthetic-frames"
    zip_dir.mkdir()
    metadata_dir.mkdir()
    originals_dir.mkdir()

    for run in manifest["runs"] + manifest["summaryRuns"]:
        aid = run["artifactId"]
        item = next(a for a in manifest["archives"] if a["artifactId"] == aid)
        directory = originals_dir / str(aid)
        directory.mkdir()
        zip_path = zip_dir / f"{aid}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for index, screen in enumerate(run["screenshots"]):
                image = Image.new("RGB", (1280, 800), (index * 17 % 255, aid % 251, 67))
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                data = buffer.getvalue()
                screen["sha256"] = digest(data)
                (directory / screen["path"]).write_bytes(data)
                archive.writestr("evidence/" + screen["path"], data)
            for name in item["reports"]:
                content = json.dumps({"synthetic": True, "artifact_id": aid, "name": name}).encode()
                item["reports"][name] = digest(content)
                (directory / name).write_bytes(content)
                archive.writestr("evidence/" + name, content)
            archive.writestr("calamares-inspect/synthetic-audit.txt", b"synthetic only")
        item["archiveSha256"] = digest(read(zip_path, 16 * 1024 * 1024))
        metadata = {
            "id": aid,
            "name": item["name"],
            "expired": False,
            "digest": "sha256:" + item["archiveSha256"],
            "workflow_run": {
                "id": int(run["runId"]),
                "head_sha": item["workflowCommit"],
            },
        }
        (metadata_dir / f"{aid}.json").write_text(json.dumps(metadata))

    manifest_path = tmp_path / "synthetic-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(q4os, "MANIFEST", manifest_path)
    monkeypatch.setattr(q4os, "MANIFEST_SHA", digest(canonical(manifest)))
    return zip_dir, metadata_dir, originals_dir, manifest, manifest_path


def _validate_synthetic_archives(lab):
    from auto_tests.tools import verify_q4os_action_archives as verifier

    return verifier.validate_archives(*lab[:3])


def test_n04_four_valid_synthetic_archives_with_extra_inspection_member(synthetic_q4os_archives):
    result = _validate_synthetic_archives(synthetic_q4os_archives)
    assert result["screenshots"] == 40
    assert result["historical_edges"] == 36
    assert result["guest_input_events"] == 0
    assert len(result["verified_artifacts"]) == 4


@pytest.mark.parametrize("substitute", ("extra-member", "truncated"))
def test_n04_atomic_zip_path_swap_cannot_change_authenticated_bytes(
    synthetic_q4os_archives, monkeypatch, substitute
):
    import os
    import zipfile

    from auto_tests.tools import verify_q4os_action_archives as verifier

    zip_dir, metadata_dir, originals_dir, _, _ = synthetic_q4os_archives
    target = zip_dir / "14587306682.zip"
    originally_authenticated = read(target, verifier.MAX_ARCHIVE)
    replacement = zip_dir / "replacement.zip"
    if substitute == "extra-member":
        shutil.copyfile(target, replacement)
        with zipfile.ZipFile(replacement, "a") as altered:
            altered.writestr("calamares-inspect/substituted-marker.txt", b"wrong ZIP")
    else:
        replacement.write_bytes(b"not a ZIP")

    real_read = verifier.read
    original_zip_opener = zipfile.ZipFile
    inspected = []
    reads = []
    changed = []

    def read_and_swap(path, limit=1024 * 1024):
        data = real_read(path, limit)
        if path == target and limit == verifier.MAX_ARCHIVE:
            reads.append(data)
            if not changed:
                os.replace(replacement, target)
                changed.append(True)
        return data

    def inspect_opened_zip(source, *args, **kwargs):
        archive = original_zip_opener(source, *args, **kwargs)
        inspected.append((isinstance(source, io.BytesIO), set(archive.namelist())))
        return archive

    monkeypatch.setattr(verifier, "read", read_and_swap)
    monkeypatch.setattr(verifier.zipfile, "ZipFile", inspect_opened_zip)
    result = verifier.validate_archives(zip_dir, metadata_dir, originals_dir)

    assert changed == [True]
    assert reads == [originally_authenticated]
    assert len(inspected) == 4
    assert all(from_bytes for from_bytes, _names in inspected)
    assert all(
        "calamares-inspect/substituted-marker.txt" not in names for _from_bytes, names in inspected
    )
    assert result["screenshots"] == 40


def test_n04_invalid_initial_hash_still_refused(synthetic_q4os_archives):
    from auto_tests.tools import verify_q4os_action_archives as verifier

    zip_dir, metadata_dir, originals_dir, _, _ = synthetic_q4os_archives
    target = zip_dir / "14587306682.zip"
    target.write_bytes(read(target, verifier.MAX_ARCHIVE) + b"tampered")
    with pytest.raises(Refusal, match="ZIP SHA-256 mismatch"):
        verifier.validate_archives(zip_dir, metadata_dir, originals_dir)


def test_n04_truncated_zip_with_pinned_hash_is_refused(synthetic_q4os_archives, monkeypatch):
    from auto_tests.installer_observer.evidence import canonical
    from auto_tests.tools import verify_q4os_action_archives as verifier

    zip_dir, metadata_dir, originals_dir, manifest, manifest_path = synthetic_q4os_archives
    item = next(a for a in manifest["archives"] if a["artifactId"] == 14587306682)
    target = zip_dir / "14587306682.zip"
    target.write_bytes(read(target, verifier.MAX_ARCHIVE)[:-24])
    item["archiveSha256"] = digest(read(target, verifier.MAX_ARCHIVE))
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(q4os, "MANIFEST_SHA", digest(canonical(manifest)))

    metadata_path = metadata_dir / "14587306682.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["digest"] = "sha256:" + item["archiveSha256"]
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(Refusal, match="Historical ZIP invalid"):
        verifier.validate_archives(zip_dir, metadata_dir, originals_dir)


def test_n04_missing_archive_is_refused(synthetic_q4os_archives):
    zip_dir, _, _, _, _ = synthetic_q4os_archives
    (zip_dir / "14587306682.zip").unlink()
    with pytest.raises(Refusal):
        _validate_synthetic_archives(synthetic_q4os_archives)
