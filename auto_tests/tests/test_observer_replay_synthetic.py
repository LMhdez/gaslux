"""Synthetic, offline-only replay regressions; NOT original Q4OS evidence.

All frames are created inside pytest temporary directories. The test suite never
starts QEMU, opens RFB/QMP, clicks a guest or modifies installation disks.
"""

from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path

import pytest
from PIL import Image

from auto_tests.installer_observer.evidence import Refusal, digest
from auto_tests.installer_observer.models import (
    Action,
    DistributionIdentity,
    InstallerIdentity,
    InterfaceMap,
    Locator,
    Postconditions,
    Preconditions,
    ScreenState,
    Transition,
)
from auto_tests.installer_observer.replay import RecordedState, Recording, replay
from auto_tests.installer_observer.screenshot import Screenshot

REGION = (2, 2, 12, 12)


def frame(color: tuple[int, int, int], size: tuple[int, int] = (16, 16)) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", size, color).save(output, format="PNG")
    return output.getvalue()


def example(tmp_path: Path, replica: int = 1):
    directory = tmp_path / f"replica-{replica}"
    directory.mkdir()
    image_colors = ((20, 40, 60), (80, 90, 100), (130, 160, 190))
    rows = []
    for state, rgb in zip(("first", "second", "third"), image_colors, strict=True):
        binary = frame(rgb)
        filename = state + ".png"
        (directory / filename).write_bytes(binary)
        rows.append(RecordedState(state, filename, digest(binary)))
    identity = DistributionIdentity("synthetic", "test-only", "a" * 64, 10)
    states = tuple(ScreenState(r.id, r.filename, "synthetic-only", ()) for r in rows)
    transitions = tuple(
        Transition(
            f"{source}-to-{target}",
            source,
            target,
            Action.NEXT,
            Locator("none", None, None),
            Preconditions(()),
            Postconditions(()),
            5,
            True,
        )
        for source, target in (("first", "second"), ("second", "third"))
    )
    mapping = InterfaceMap(
        identity,
        InstallerIdentity("synthetic-installer", "test"),
        states,
        transitions,
        "third",
        (16, 16),
        None,
        "synthetic-source",
        b'{"synthetic":true}',
    )
    recording = Recording(
        f"synthetic-run-{replica}",
        replica,
        10000 + replica,
        directory,
        tuple(rows),
        (("first", "second"), ("second", "third")),
        (17, 19),
        "synthetic-source",
    )

    def recognize(image: Screenshot):
        for row in rows:
            if image.sha256 == row.sha256:
                return (row.id,)
        return ()

    def validate_edge(_edge: Transition, _before: Screenshot, _after: Screenshot):
        return None

    return mapping, recording, recognize, validate_edge


def run_case(mapping, recording, recognize, validate_edge):
    return replay(mapping, recording, recognize, validate_edge, REGION)


def test_valid_synthetic_replay_is_observation_only(tmp_path):
    m, r, recognize, check = example(tmp_path)
    report = run_case(m, r, recognize, check)
    assert report["run_id"] == r.run_id
    assert report["replica"] == 1
    assert report["artifact_id"] == r.artifact_id
    assert report["workflow_commit"] == "synthetic-source"
    assert report["final_state"] == "third"
    assert len(report["frames"]) == 3
    assert len(report["steps"]) == 2
    assert all(row["mode"] == "historical-replay" for row in report["steps"])
    assert all(row["authorized_action"] is None for row in report["steps"])


def test_bad_frame_sha_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    rows = list(r.states)
    rows[1] = replace(rows[1], sha256="0" * 64)
    with pytest.raises(Refusal):
        run_case(m, replace(r, states=tuple(rows)), recognize, check)


def test_missing_frame_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    (r.directory / "second.png").unlink()
    with pytest.raises(Refusal):
        run_case(m, r, recognize, check)


def test_evidence_symlink_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    original = r.directory / "second.png"
    target = r.directory / "original.png"
    original.rename(target)
    original.symlink_to(target)
    with pytest.raises(Refusal):
        run_case(m, r, recognize, check)


def test_unknown_state_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    rows = list(r.states)
    rows[1] = replace(rows[1], id="unreviewed")
    with pytest.raises(Refusal):
        run_case(m, replace(r, states=tuple(rows)), recognize, check)


def test_unlisted_transition_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    m = replace(m, transitions=m.transitions[1:])
    with pytest.raises(Refusal):
        run_case(m, r, recognize, check)


def test_unverified_transition_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    m = replace(m, transitions=(replace(m.transitions[0], verified=False), m.transitions[1]))
    with pytest.raises(Refusal):
        run_case(m, r, recognize, check)


def test_reordered_frames_are_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    rows = list(r.states)
    rows[0], rows[1] = rows[1], rows[0]
    with pytest.raises(Refusal):
        run_case(m, replace(r, states=tuple(rows)), recognize, check)


def test_fabricated_or_skipped_edge_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    recording = replace(r, edges=(("first", "third"), ("second", "third")))
    with pytest.raises(Refusal):
        run_case(m, recording, recognize, check)


def test_inter_replica_frame_substitution_is_refused(tmp_path):
    m, a, recognize, check = example(tmp_path, replica=1)
    _other_map, b, _, _ = example(tmp_path, replica=2)
    (b.directory / "second.png").write_bytes(frame((222, 1, 2)))
    with pytest.raises(Refusal):
        run_case(m, replace(a, directory=b.directory), recognize, check)


def test_session_identity_cannot_be_spliced_via_edge_list(tmp_path):
    m, a, recognize, check = example(tmp_path, replica=1)
    _other_map, b, _, _ = example(tmp_path, replica=2)
    # Combining edges from distinct sessions without their full three-state
    # recorded sequence is incomplete and must not be accepted.
    spliced = replace(a, edges=a.edges + b.edges)
    with pytest.raises(Refusal):
        run_case(m, spliced, recognize, check)


def test_truncated_png_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    original = (r.directory / "second.png").read_bytes()
    (r.directory / "second.png").write_bytes(original[:-9])
    with pytest.raises(Refusal):
        run_case(m, r, recognize, check)


def test_wrong_png_dimensions_are_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    altered = frame((80, 90, 100), (17, 16))
    (r.directory / "second.png").write_bytes(altered)
    rows = list(r.states)
    rows[1] = replace(rows[1], sha256=digest(altered))
    with pytest.raises(Refusal):
        run_case(m, replace(r, states=tuple(rows)), recognize, check)


def test_unchanged_region_is_refused_even_if_full_png_differs(tmp_path):
    m, r, recognize, check = example(tmp_path)
    binary = frame((20, 40, 60))
    image = Image.open(io.BytesIO(binary)).convert("RGB")
    image.putpixel((0, 0), (0, 0, 0))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    changed = buffer.getvalue()
    (r.directory / "second.png").write_bytes(changed)
    rows = list(r.states)
    rows[1] = replace(rows[1], sha256=digest(changed))

    def recognize_modified(img: Screenshot):
        return (next(row.id for row in rows if row.sha256 == img.sha256),)

    with pytest.raises(Refusal):
        run_case(m, replace(r, states=tuple(rows)), recognize_modified, check)


def test_unreviewed_visual_identity_is_refused(tmp_path):
    m, r, _, check = example(tmp_path)
    with pytest.raises(Refusal):
        run_case(m, r, lambda _frame: ("first", "second"), check)


def test_edge_validator_refusal_propagates(tmp_path):
    m, r, recognize, _check = example(tmp_path)

    def refuse(_edge, _before, _after):
        raise Refusal("Synthetic visual gate failed")

    with pytest.raises(Refusal, match="Synthetic visual gate failed"):
        run_case(m, r, recognize, refuse)


def test_missing_or_extra_timing_is_refused(tmp_path):
    m, r, recognize, check = example(tmp_path)
    with pytest.raises(Refusal):
        run_case(m, replace(r, elapsed_ms=(17,)), recognize, check)
    with pytest.raises(Refusal):
        run_case(m, replace(r, elapsed_ms=(17, 19, 22)), recognize, check)


def test_no_network_or_input_transport_is_needed(tmp_path, monkeypatch):
    m, r, recognize, check = example(tmp_path)
    import socket

    def refuse_socket(*_args, **_kwargs):
        pytest.fail("Offline replay attempted network access")

    monkeypatch.setattr(socket, "socket", refuse_socket)
    result = run_case(m, r, recognize, check)
    assert len(result["steps"]) == 2


def test_no_replay_of_unknown_transition_order(tmp_path):
    m, r, recognize, check = example(tmp_path)
    swapped = replace(r, edges=(r.edges[1], r.edges[0]))
    with pytest.raises(Refusal):
        run_case(m, swapped, recognize, check)
