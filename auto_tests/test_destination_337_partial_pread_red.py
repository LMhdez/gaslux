"""Independent RED regression on the real #337 FD hashing helper.

No guest, QEMU process or disk image; private tempfile regular file only.
The mock simulates a POSIX-legal positive but incomplete pread response.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from auto_tests.installer_observer.authenticated_destination import (
    DestinationRefused,
    _digest,
)


class PartialPreadMustNotAuthenticate(unittest.TestCase):
    def test_positive_complete_read_is_valid(self):
        payload = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory(prefix="gaslux-337-pread-") as root:
            file = Path(root) / "owned.bin"
            file.write_bytes(payload)
            fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                actual = _digest(fd, hashlib.sha256(payload).hexdigest())
                self.assertEqual(actual, hashlib.sha256(payload).hexdigest())
            finally:
                os.close(fd)

    def test_short_positive_pread_must_deny_even_if_caller_claim_matches_short_bytes(self):
        payload = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory(prefix="gaslux-337-pread-") as root:
            file = Path(root) / "owned.bin"
            file.write_bytes(payload)
            fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
            real_pread = os.pread
            observed = []

            def partial_read(seen_fd, requested, offset):
                result = real_pread(seen_fd, requested, offset)
                if seen_fd == fd and requested == len(payload) and offset == 0:
                    part = result[: len(result) // 2]
                    observed.append((requested, len(part)))
                    return part
                return result

            try:
                # These bytes are NOT the actual complete file, so accepting
                # this claimed SHA makes "verified FD hash" factually false.
                false_digest = hashlib.sha256(payload[: len(payload) // 2]).hexdigest()
                with patch(
                    "auto_tests.installer_observer.authenticated_destination.os.pread",
                    side_effect=partial_read,
                ):
                    with self.assertRaises(DestinationRefused):
                        _digest(fd, false_digest)
            finally:
                os.close(fd)
            self.assertEqual(observed, [(len(payload), len(payload) // 2)])


if __name__ == "__main__":
    unittest.main()
