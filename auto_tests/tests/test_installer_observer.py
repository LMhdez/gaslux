"""Adversarial observer contracts: every pre-click refusal leaves transport input empty."""

from __future__ import annotations

import io
import json
import os
import struct
from dataclasses import replace

import pytest
from PIL import Image

from auto_tests.installer_observer import q4os
from auto_tests.installer_observer.evidence import Refusal, basename, canonical, digest, parse, read
from auto_tests.installer_observer.locators import Candidate, Method, Surface, Target
from auto_tests.installer_observer.models import Action, DistributionIdentity
from auto_tests.installer_observer.schema import load_map, validate
from auto_tests.installer_observer.screenshot import Screenshot
from auto_tests.installer_observer.state_machine import (
    Frame,
    Grant,
    LabAuthority,
    SafetyPolicy,
    StateMachine,
)
from auto_tests.installer_observer.transport_vnc import ReadOnlyVncTransport, RfbReader

RUN = "14587306682"


@pytest.fixture(scope="module")
def mapping():
    return load_map(q4os.MAP, q4os.PROFILE)


@pytest.fixture(scope="module")
def pictures():
    directory = q4os.ORIGINALS / RUN
    return (
        read(directory / "vnc-after-installer-icon.png", 2 * 1024 * 1024),
        read(directory / "vnc-location-page.png", 2 * 1024 * 1024),
    )


class FakeTransport:
    def __init__(self, before: Frame, after: Frame, *, fail_at: str | None = None):
        self.frames = [before, after]
        self.fail_at = fail_at
        self.inputs: list[tuple[str, str, tuple[int, int]]] = []
        self.captures = 0

    def capture(self, deadline: float) -> Frame:
        self.captures += 1
        if self.fail_at == "before" and self.captures == 1:
            raise Refusal("before capture failed")
        if self.fail_at == "after" and self.captures > 1:
            raise Refusal("after capture failed")
        return self.frames[min(self.captures - 1, len(self.frames) - 1)]

    def click_if_current(
        self, run_id: str, png_sha256: str, point: tuple[int, int], deadline: float
    ) -> None:
        if self.fail_at == "click":
            raise Refusal("atomic check refused click")
        self.inputs.append((run_id, png_sha256, point))


def session(mapping, pictures, *, authority=None, scale=1.0, initial=None):
    source, target = pictures
    edge = next(e for e in mapping.transitions if e.source == "calamares-welcome")
    source_shot = Screenshot.decode(source, mapping.resolution)
    target_box = edge.locator.box
    assert target_box is not None and edge.locator.point is not None
    locator_target = Target(
        "Next", "button", target_box, source_shot.roi(target_box), edge.locator.point
    )
    a = authority or LabAuthority(
        "run-1", mapping.identity, mapping.lab_commit, "snapshot-1", True, False
    )
    surface = Surface(supported=frozenset({Method.POINT}))
    first = Frame(source, scale, a, surface, frozenset(edge.before.requirements))
    second = Frame(target, scale, a, surface, frozenset(edge.after.requirements))
    transport = FakeTransport(first, second)
    policy = SafetyPolicy(
        digest(mapping.document),
        a,
        (Grant(edge.source, edge.target, locator_target),),
        q4os.REGION,
        (Method.POINT,),
    )
    machine = StateMachine(
        replace(mapping, scale=1.0),
        policy,
        transport,
        q4os.recognize,
        initial or edge.source,
    )
    return edge, machine, transport


def test_original_map_schema_and_distribution_identity(mapping):
    assert len(mapping.states) == 11
    assert len(mapping.transitions) == 10
    assert mapping.terminal == "calamares-summary"
    assert mapping.scale is None
    assert mapping.identity == q4os.PROFILE.identity
    assert mapping.installer == q4os.PROFILE.installer
    assert digest(mapping.document) == q4os.PROFILE.map_digest


def test_iso_hash_and_size_are_both_required(tmp_path):
    iso = tmp_path / "synthetic.iso"
    iso.write_bytes(b"fake test image")
    identity = DistributionIdentity("test-only", "0", digest(iso.read_bytes()), iso.stat().st_size)
    identity.verify_iso(iso)
    iso.write_bytes(b"fake test imagX")
    with pytest.raises(Refusal):
        identity.verify_iso(iso)
    iso.write_bytes(b"fake")
    with pytest.raises(Refusal):
        identity.verify_iso(iso)


def test_json_duplicate_keys_and_commands_refused(tmp_path):
    with pytest.raises(Refusal, match="Duplicate"):
        parse(b'{"action":"next","action":"install"}')
    doc = json.loads(q4os.MAP.read_text())
    doc["transitions"][1]["shell"] = "rm -rf /"
    with pytest.raises(Refusal):
        validate(doc, q4os.PROFILE.schema)
    doc["transitions"][1].pop("shell")
    doc["transitions"][1]["action"] = "os.system('whoami')"
    candidate = tmp_path / "map.json"
    candidate.write_bytes(canonical(doc))
    with pytest.raises(Refusal):
        load_map(candidate, q4os.PROFILE)


@pytest.mark.parametrize("bad", ["../secret", "/tmp/no", "sub/file", "CON", "a\\b"])
def test_traversal_and_device_names_refused(bad):
    with pytest.raises(Refusal):
        basename(bad)


def test_map_mutation_refused_even_when_schema_valid(tmp_path):
    data = json.loads(q4os.MAP.read_text())
    data["states"][0]["visibleTextObserved"] = "modified"
    file = tmp_path / "map.json"
    file.write_bytes(canonical(data))
    with pytest.raises(Refusal, match="reviewed"):
        load_map(file, q4os.PROFILE)


def test_duplicate_controls_and_unbound_locator_never_click(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    states = list(machine.mapping.states)
    idx = next(i for i, state in enumerate(states) if state.id == edge.source)
    controls = states[idx].controls
    states[idx] = replace(states[idx], controls=controls + (controls[0],))
    machine.mapping = replace(machine.mapping, states=tuple(states))
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_original_q4os_live_scale_unproven_prevents_input(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    machine.mapping = mapping
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_successful_double_only_simulates_one_forward_input(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    result = machine.step(edge.id)
    assert result.passed, result.errors
    assert len(fake.inputs) == 1
    assert result.final_state == edge.target
    assert not machine.step(edge.id).passed
    assert len(fake.inputs) == 1


@pytest.mark.parametrize("tamper", ["snapshot", "vm", "disk", "media", "commit", "scale"])
def test_session_identity_divergence_never_clicks(mapping, pictures, tamper):
    edge, machine, fake = session(mapping, pictures)
    a = machine.policy.authority
    if tamper == "snapshot":
        changed = replace(a, snapshot_id="different")
    elif tamper == "vm":
        changed = replace(a, run_id="different")
    elif tamper == "disk":
        changed = replace(a, physical_disk_attached=True)
    elif tamper == "media":
        changed = replace(a, media=replace(a.media, version="incompatible"))
    elif tamper == "commit":
        changed = replace(a, source_commit="unknown")
    else:
        fake.frames[0] = replace(fake.frames[0], scale=2.0)
        changed = a
    if tamper != "scale":
        fake.frames[0] = replace(fake.frames[0], authority=changed)
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


@pytest.mark.parametrize("attempt", [Action.PREVIEW, "Install", "os.system('rm -rf /')"])
def test_install_and_non_next_action_never_click(mapping, pictures, attempt):
    edge, machine, fake = session(mapping, pictures)
    edges = tuple(
        replace(t, action=attempt) if t.id == edge.id else t for t in machine.mapping.transitions
    )
    machine.mapping = replace(machine.mapping, transitions=edges)
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_out_of_region_target_never_clicks(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    grant = machine.policy.grants[0]
    bad = replace(grant.target, point=(0, 0))
    machine.policy = replace(machine.policy, grants=(replace(grant, target=bad),))
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_ambiguous_locator_never_clicks(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    target = machine.policy.grants[0].target
    first = fake.frames[0]
    duplicate = Candidate("Next", "button", target.box)
    fake.frames[0] = replace(
        first, surface=Surface(controls=(duplicate, duplicate), supported=frozenset({Method.TEXT}))
    )
    machine.policy = replace(machine.policy, methods=(Method.TEXT,))
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_precondition_failure_and_unexpected_state_never_click(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    fake.frames[0] = replace(fake.frames[0], passed_checks=frozenset())
    assert not machine.step(edge.id).passed
    assert fake.inputs == []
    edge, machine, fake = session(mapping, pictures)
    machine.recognize = lambda _frame: ("calamares-summary",)
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_invalid_png_and_modified_pixels_never_click(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    fake.frames[0] = replace(fake.frames[0], png=pictures[0][:-10])
    assert not machine.step(edge.id).passed
    assert fake.inputs == []
    edge, machine, fake = session(mapping, pictures)
    png = io.BytesIO()
    with Image.open(io.BytesIO(pictures[0])) as image:
        image.putpixel((1000, 640), (255, 0, 0))
        image.save(png, "PNG")
    fake.frames[0] = replace(fake.frames[0], png=png.getvalue())
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


@pytest.mark.parametrize("failure,inputs", [("before", 0), ("click", 0), ("after", 1)])
def test_failures_are_terminal_and_never_retry(mapping, pictures, failure, inputs):
    edge, machine, fake = session(mapping, pictures)
    fake.fail_at = failure
    assert not machine.step(edge.id).passed
    assert len(fake.inputs) == inputs
    assert not machine.step(edge.id).passed
    assert len(fake.inputs) == inputs


def test_postcondition_failure_stops_after_single_input(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    fake.frames[1] = replace(fake.frames[1], passed_checks=frozenset())
    assert not machine.step(edge.id).passed
    assert machine.halted
    assert len(fake.inputs) == 1


def test_deadline_before_locator_prevents_input(mapping, pictures):
    edge, machine, fake = session(mapping, pictures)
    times = iter((0.0, 100.0, 100.0))
    machine.clock = lambda: next(times, 100.0)
    assert not machine.step(edge.id).passed
    assert fake.inputs == []


def test_duplicate_json_properties_and_missing_manifest_envelope(tmp_path):
    with pytest.raises(Refusal):
        parse(b'{"sha256":"a","sha256":"b"}')
    from auto_tests.installer_observer.evidence import unseal

    with pytest.raises(Refusal):
        unseal({"manifest": {}})
    path = tmp_path / "empty.json"
    path.write_bytes(b"")
    with pytest.raises(Refusal):
        read(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink and hardlink contract")
def test_symlink_parent_symlink_leaf_and_hardlink_rejected(tmp_path):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"safe":true}')
    alias = tmp_path / "alias.json"
    alias.symlink_to(source)
    with pytest.raises(Refusal):
        read(alias)
    folder = tmp_path / "dir"
    folder.mkdir()
    child = folder / "proof.json"
    child.write_bytes(b'{"safe":true}')
    shortcut = tmp_path / "shortcut"
    shortcut.symlink_to(folder, target_is_directory=True)
    with pytest.raises(Refusal):
        read(shortcut / "proof.json")
    link = tmp_path / "hardlink.json"
    os.link(source, link)
    with pytest.raises(Refusal):
        read(source)


def test_manifest_tampering_and_missing_frame_refused(mapping, tmp_path):
    manifest = json.loads(q4os.MANIFEST.read_text())
    manifest["summaryRuns"][0]["replica"] = 99
    file = tmp_path / "manifest.json"
    file.write_bytes(canonical(manifest))
    with pytest.raises(Refusal):
        list(q4os.recordings(mapping, file, q4os.ORIGINALS))
    from auto_tests.installer_observer.replay import RecordedState, Recording, replay

    first = RecordedState("calamares-welcome", "missing.png", "0" * 64)
    incomplete = Recording("x", 1, 1, tmp_path, (first,), (), (), "sha")
    with pytest.raises(Refusal):
        replay(mapping, incomplete, q4os.recognize, q4os.validate_edge, q4os.REGION)


def test_original_replay_four_replicas_and_summary_timing():
    report = q4os.replay_q4os()
    sessions = report["manifest"]["sessions"]
    assert len(sessions) == 4
    assert [len(session["frames"]) for session in sessions].count(11) == 2
    assert [len(session["frames"]) for session in sessions].count(9) == 2
    times = sorted(
        step["elapsed_ms"]
        for session in sessions
        for step in session["steps"]
        if step["final_state"] == "calamares-summary"
    )
    assert times == [3279, 3328]
    assert report["manifest"]["live_input_count"] == 0


class FakeRfbSocket:
    def __init__(self, payload):
        self.payload = bytearray(payload)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def settimeout(self, _seconds):
        pass

    def recv(self, amount):
        data = bytes(self.payload[:amount])
        del self.payload[:amount]
        return data

    def sendall(self, data):
        self.sent.append(data)


def test_raw_rfb_reader_emits_only_observation_messages():
    pixel = b"\x00\x00\xff\x00" * 2
    init = struct.pack(">HH", 2, 1) + b"\x00" * 16 + struct.pack(">I", 1) + b"Q"
    update = b"\x00\x00" + struct.pack(">H", 1) + struct.pack(">HHHHi", 0, 0, 2, 1, 0)
    payload = b"RFB 003.008\n" + b"\x01\x01" + b"\x00" * 4 + init + update + pixel
    sock = FakeRfbSocket(payload)
    reader = RfbReader(dial=lambda *_args, **_kwargs: sock, clock=lambda: 0.0)
    shot = Screenshot.decode(reader.read_png(10.0, (2, 1)), (2, 1))
    assert shot.image.getpixel((1, 0)) == (255, 0, 0)
    assert len(sock.sent) == 6
    assert sock.sent[-1][0] == 3  # request complete framebuffer, never input
    assert all(message[0] != 5 for message in sock.sent)


def test_remote_vnc_endpoint_never_dialed():
    reader = RfbReader(host="1.2.3.4", dial=lambda *_args, **_kw: pytest.fail("dialled"))
    with pytest.raises(Refusal):
        reader.read_png(99999999999.0, (2, 2))


def test_observation_only_transport_refuses_any_click_and_checks_attestor(pictures, mapping):
    identity = LabAuthority("run", mapping.identity, mapping.lab_commit, "snap", True, False)
    events = []

    class Reader:
        def read_png(self, _deadline, _size):
            return pictures[0]

    class Attestor:
        def verify(self, _deadline):
            return identity

    transport = ReadOnlyVncTransport(
        Reader(),
        Attestor(),
        identity,
        mapping.resolution,
        events.append,
    )
    frame = transport.capture(99999999999.0)
    assert frame.scale is None
    assert frame.passed_checks == frozenset()
    with pytest.raises(Refusal, match="atomically"):
        transport.click_if_current(identity.run_id, digest(frame.png), (1000, 640), 99999999999.0)
    assert events[-1] == "vnc-input-refused"


def test_transport_snapshot_swap_never_returns_frame(pictures, mapping):
    identity = LabAuthority("run", mapping.identity, mapping.lab_commit, "snap", True, False)

    class Reader:
        def read_png(self, _deadline, _size):
            return pictures[0]

    class Attestor:
        count = 0

        def verify(self, _deadline):
            self.count += 1
            return identity if self.count == 1 else replace(identity, snapshot_id="swap")

    transport = ReadOnlyVncTransport(Reader(), Attestor(), identity, mapping.resolution)
    with pytest.raises(Refusal):
        transport.capture(99999999999.0)
