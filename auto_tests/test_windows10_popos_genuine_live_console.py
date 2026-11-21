"""Live Pop serial refusal diagnostics: never truncate an error at TCP chunk boundary."""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent / "tools"))

from windows10_popos_genuine_live_console import REFUSED, RESULT


class PopLiveConsoleRefusalContracts(unittest.TestCase):
    def test_partial_serial_chunks_are_not_complete_evidence(self):
        for chunk in (
            b"GASLUX_POP_LIVE_WINDOWS_GPT_REFUSED=o",
            b"GASLUX_POP_LIVE_WINDOWS_GPT_REFUSED=owned ESP/root already",
            b"GASLUX_POP_LIVE_GENUINE_WIN10_COW_GPT_VERIFIED=1",
        ):
            with self.subTest(chunk=chunk):
                self.assertIsNone(RESULT.search(chunk))
        self.assertIsNone(REFUSED.search(b"GASLUX_POP_LIVE_WINDOWS_GPT_REFUSED=o"))

    def test_complete_refusal_preserves_specific_blocker(self):
        msg = (
            b"GASLUX_POP_LIVE_WINDOWS_GPT_REFUSED="
            b"owned Pop partition 5 signature probe refused: blkid exit=0 "
            b"type='vfat' stderr=''\r\n"
        )
        match = REFUSED.search(msg)
        self.assertIsNotNone(match)
        self.assertIn(b"blkid exit=0", match.group(1))
        self.assertIsNotNone(RESULT.search(msg))

    def test_completed_success_marker_still_accepted(self):
        self.assertIsNotNone(RESULT.search(
            b"GASLUX_POP_LIVE_GENUINE_WIN10_COW_GPT_VERIFIED=1\r\n"
        ))


if __name__ == "__main__":
    unittest.main()
