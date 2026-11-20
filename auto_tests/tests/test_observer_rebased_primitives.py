"""Non-destructive direct contracts for imported Observer primitives."""

from __future__ import annotations

import io

import pytest
from PIL import Image

from auto_tests.installer_observer.evidence import Refusal, basename, digest, parse, read
from auto_tests.installer_observer.locators import Method, Surface, Target, resolve
from auto_tests.installer_observer.models import (
    DistributionIdentity,
    InstallerIdentity,
    InterfaceMap,
    ScreenState,
)
from auto_tests.installer_observer.screenshot import Screenshot
from auto_tests.installer_observer.state_machine import LabAuthority, SafetyPolicy, StateMachine


def png_frame() -> Screenshot:
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), (100, 100, 100)).save(buffer, format="PNG")
    return Screenshot.decode(buffer.getvalue(), (16, 16))


def test_evidence_rejects_duplicate_json_and_unsafe_paths(tmp_path):
    with pytest.raises(Refusal):
        parse(b'{"action":"next","action":"install"}')
    with pytest.raises(Refusal):
        basename("../outside")
    target = tmp_path / "original"
    target.write_bytes(b"test")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(Refusal):
        read(alias)


def test_screenshot_bounds_hashes_and_truncated_png():
    frame = png_frame()
    assert frame.roi((0, 0, 5, 5)) == digest(frame.image.crop((0, 0, 5, 5)).tobytes())
    with pytest.raises(Refusal):
        frame.roi((0, 0, 17, 17))
    with pytest.raises(Refusal):
        Screenshot.decode(frame.png[:-5], (16, 16))
    with pytest.raises(Refusal):
        Screenshot.decode(frame.png, (16, 16), "0" * 64)


def test_locator_requires_proven_capture_and_target_pixels():
    frame = png_frame()
    target = Target("Next", "button", (2, 2, 8, 8), frame.roi((2, 2, 8, 8)), (4, 4))
    supported = Surface(supported=frozenset({Method.POINT}))
    assert resolve(frame, supported, target, (Method.POINT,), 0.1) == (Method.POINT, (4, 4))
    with pytest.raises(Refusal):
        resolve(
            frame,
            Surface(unproven=frozenset({Method.POINT})),
            target,
            (Method.POINT,),
            0.1,
        )
    with pytest.raises(Refusal):
        resolve(
            frame,
            supported,
            Target("Next", "button", (2, 2, 8, 8), "0" * 64, (4, 4)),
            (Method.POINT,),
            0.1,
        )


def test_distribution_identity_checks_size_and_digest(tmp_path):
    source = tmp_path / "test.iso"
    source.write_bytes(b"not-an-ISO--synthetic")
    identity = DistributionIdentity(
        "fixture", "0", digest(source.read_bytes()), source.stat().st_size
    )
    identity.verify_iso(source)
    source.write_bytes(b"not-an-ISO--synthEtic")
    with pytest.raises(Refusal):
        identity.verify_iso(source)


def test_unknown_state_machine_edge_never_captures_or_clicks():
    identity = DistributionIdentity("fixture", "0", "a" * 64, 20)
    mapping = InterfaceMap(
        identity,
        InstallerIdentity("test", "0"),
        (ScreenState("welcome", "fake.png", "", ()),),
        (),
        "summary",
        (16, 16),
        None,
        "source",
        b"{}",
    )
    authority = LabAuthority("run", identity, "source", "snap", True, False)
    policy = SafetyPolicy(digest(mapping.document), authority, (), (0, 0, 16, 16))

    class NoInput:
        def capture(self, _deadline):
            pytest.fail("Unexpected guest capture")

        def click_if_current(self, *_args):
            pytest.fail("Unexpected guest click")

    machine = StateMachine(mapping, policy, NoInput(), lambda _s: (), "welcome")
    result = machine.step("untrusted")
    assert not result.passed
    assert machine.halted
