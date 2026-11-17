"""Negative-only tests for read-only Windows Panther answer-cache evidence.

No Microsoft ISO, virtual or host disk is opened. The guestfish response is
mocked; the optional hosted CI smoke separately tests the guestfish CLI.
"""
from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent / "tools"
SPEC = importlib.util.spec_from_file_location(
    "gaslux_panther_probe", TOOLS / "windows_x64_offline_panther_probe.py"
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

DUMMY_DISK = pathlib.Path(
    "/home/runner/work/_temp/gaslux-win-x64-unit/"
    "only-disposable-windows-target.qcow2"
)
XML = (b'<?xml version="1.0" encoding="utf-8"?>'
       b'<unattend xmlns="urn:schemas-microsoft-com:unattend">'
       b'<settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup">'
       b'<Password>CI_SECRET_NEVER_LOGGED</Password></component></settings></unattend>')


def result(argv, code, data=b""):
    return subprocess.CompletedProcess(argv, code, stdout=data, stderr=b"")


class FakeGuestfish:
    def __init__(self, *, cached=True, filesystems=None):
        self.calls = []
        self.cached = cached
        self.filesystems = (filesystems if filesystems is not None
                            else b"/dev/sda1: vfat\n/dev/sda3: ntfs\n"
                                 b"/dev/sda4: ntfs\n")

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False
        assert kwargs["timeout"] == 95
        assert command[:5] == [
            "/usr/bin/guestfish", "--ro", "--format=qcow2", "-a",
            str(DUMMY_DISK)
        ]
        if command[-1] == "list-filesystems":
            return result(command, 0, self.filesystems)
        if self.cached and command[-2:] == [
            "filesize", "/Windows/Panther/Unattend.xml"
        ]:
            return result(command, 0, str(len(XML)).encode() + b"\n")
        if self.cached and command[-2:] == [
            "cat", "/Windows/Panther/Unattend.xml"
        ]:
            return result(command, 0, XML)
        return result(command, 1)


class PantherProbeContracts(unittest.TestCase):
    def invoke(self, fake):
        output = io.StringIO()
        with patch.object(probe, "validate_owned_disk") as owner, patch.object(
            pathlib.Path, "is_file", return_value=True
        ), redirect_stdout(output):
            status = probe.inspect_cached_oobe_answer(DUMMY_DISK, runner=fake)
        owner.assert_called_once_with(DUMMY_DISK)
        return status, output.getvalue()

    def test_cached_answer_is_observed_without_exposing_password(self):
        fake = FakeGuestfish()
        status, printed = self.invoke(fake)
        self.assertTrue(status["cachedWindowsAnswerObserved"])
        self.assertTrue(status["cachedAnswerOobePassPresent"])
        self.assertFalse(status["windowsClientBootVerified"])
        self.assertEqual(len(status["cachedAnswerSha256"]), 64)
        self.assertNotIn("CI_SECRET_NEVER_LOGGED", printed)
        self.assertNotIn("CI_SECRET_NEVER_LOGGED", repr(status))
        self.assertIn("GASLUX_WINDOWS_STAGE1_PANTHER_CACHED_OOBE_FOUND=1",
                      printed)
        self.assertTrue(all("--ro" in c for c in fake.calls))
        self.assertTrue(all("cat" not in c or "-m" in c for c in fake.calls))
        size_seen = False
        for command in fake.calls:
            if command[-2:] == ["filesize", "/Windows/Panther/Unattend.xml"]:
                size_seen = True
            if command[-2:] == ["cat", "/Windows/Panther/Unattend.xml"]:
                self.assertTrue(size_seen,
                                "no credential content before bounded file size")

    def test_guestfish_cat_one_extra_cli_lf_is_not_part_of_xml(self):
        original = FakeGuestfish()

        def guestfish_appends_lf(command, **kwargs):
            res = original(command, **kwargs)
            if command[-2:] == [
                "cat", "/Windows/Panther/Unattend.xml"
            ] and res.returncode == 0:
                return result(command, 0, res.stdout + b"\n")
            return res

        state, stdout = self.invoke(guestfish_appends_lf)
        self.assertTrue(state["cachedWindowsAnswerObserved"])
        self.assertTrue(state["cachedAnswerOobePassPresent"])
        self.assertFalse(state["windowsClientBootVerified"])
        self.assertEqual(
            state["cachedAnswerSha256"],
            probe.hashlib.sha256(XML).hexdigest(),
            "CLI-generated LF must never change cached file identity",
        )
        self.assertNotIn("CI_SECRET_NEVER_LOGGED", stdout)

    def test_guestfish_cat_arbitrary_extra_bytes_fail_closed(self):
        for junk in (b"X", b"\n\n", b"\x00"):
            with self.subTest(extra=junk):
                fake = FakeGuestfish()

                def tampered_output(command, **kwargs):
                    res = fake(command, **kwargs)
                    if command[-2:] == [
                        "cat", "/Windows/Panther/Unattend.xml"
                    ] and res.returncode == 0:
                        return result(command, 0, res.stdout + junk)
                    return res

                state, printed = self.invoke(tampered_output)
                self.assertFalse(state["cachedWindowsAnswerObserved"])
                self.assertFalse(state["windowsClientBootVerified"])
                self.assertNotIn("CI_SECRET_NEVER_LOGGED", printed)

    def test_missing_cached_answer_fails_proof_closed(self):
        status, printed = self.invoke(FakeGuestfish(cached=False))
        self.assertFalse(status["cachedWindowsAnswerObserved"])
        self.assertFalse(status["windowsClientBootVerified"])
        self.assertNotIn("cachedAnswerSha256", status)
        self.assertIn("GASLUX_WINDOWS_STAGE1_PANTHER_CACHED_OOBE_FOUND=0",
                      printed)

    def test_ambiguous_windows_partition_list_rejected(self):
        fake = FakeGuestfish(filesystems=(
            b"/dev/sda1: ntfs\n/dev/sda2: ntfs\n/dev/sda3: ntfs\n"
            b"/dev/sda4: ntfs\n/dev/sda5: ntfs\n"
        ))
        with self.assertRaisesRegex(probe.PantherProbeError, "ambiguous"):
            self.invoke(fake)
        self.assertEqual(len(fake.calls), 1)

    def test_unowned_disk_rejected_before_any_guestfish_invocation(self):
        called = FakeGuestfish()
        with patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "GITHUB_REPOSITORY": "LMhdez/gaslux",
        }):
            with self.assertRaisesRegex(probe.PantherProbeError,
                                        "unowned or physical disk"):
                probe.inspect_cached_oobe_answer(
                    pathlib.Path("/dev/sda"), runner=called
                )
        self.assertEqual(called.calls, [])

    def test_invalid_guest_firmware_marker_does_not_fake_oobe(self):
        fake = FakeGuestfish(cached=True)
        status, printed = self.invoke(fake)
        self.assertFalse(status["windowsClientBootVerified"])
        self.assertNotIn("Windows RE", printed)

    def test_oversized_panther_answer_rejected_before_read(self):
        fake = FakeGuestfish(cached=True)
        observed = []
        def oversized(command, **kwargs):
            observed.append(command)
            if command[-2:] == ["filesize", "/Windows/Panther/Unattend.xml"]:
                return result(command, 0, b"3000000\n")
            if command[-2:] == ["cat", "/Windows/Panther/Unattend.xml"]:
                raise AssertionError("oversized guest XML must never be read")
            return fake(command, **kwargs)

        status, printed = self.invoke(oversized)
        self.assertFalse(status["cachedWindowsAnswerObserved"])
        self.assertFalse(status["windowsClientBootVerified"])
        self.assertNotIn("CI_SECRET_NEVER_LOGGED", printed)

    def test_bad_xml_is_never_accepted_as_cached_answer(self):
        fake = FakeGuestfish(cached=True)

        def broken(cmd, **kwargs):
            value = fake(cmd, **kwargs)
            if cmd[-1] == "/Windows/Panther/Unattend.xml":
                return result(cmd, 0, b"<not-xml")
            return value

        status, _ = self.invoke(broken)
        self.assertFalse(status["cachedWindowsAnswerObserved"])


if __name__ == "__main__":
    unittest.main()
