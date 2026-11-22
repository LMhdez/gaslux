"""D-337-01: test the real pinned-FD digest with adversarial POSIX pread.

Read-only test file descriptors and private temporary regular files only.
No QEMU, guest, block device, Windows partition, or writer authority.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auto_tests.installer_observer.authenticated_destination import (
    DestinationRefused,
    _digest,
)


class FullFdDigestContracts(unittest.TestCase):
    @staticmethod
    def _sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _assert_denied(
        self,
        *,
        content: bytes,
        expected: str,
        read_override,
        reason: str,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="gaslux-337-fd-digest-") as root:
            path = Path(root) / "private.bin"
            path.write_bytes(content)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            real_read = os.pread
            try:
                with patch(
                    "auto_tests.installer_observer.authenticated_destination.os.pread",
                    side_effect=lambda f, n, off: read_override(
                        path, fd, real_read, f, n, off
                    ),
                ):
                    with self.assertRaisesRegex(DestinationRefused, reason):
                        _digest(fd, expected)
            finally:
                os.close(fd)

    def test_a_intact_file_full_sha_across_chunk_boundary(self):
        content = bytes(range(256)) * 4096 + b"end-of-authenticated-file"
        with tempfile.TemporaryDirectory(prefix="gaslux-337-digest-intact-") as root:
            path = Path(root) / "private.bin"
            path.write_bytes(content)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                self.assertEqual(_digest(fd, self._sha(content)), self._sha(content))
            finally:
                os.close(fd)

    def test_b_positive_short_read_denied_before_offset_advance(self):
        payload = bytes(range(256)) * 4
        offsets = []

        def half(_path, _fd, read, f, n, offset):
            offsets.append(offset)
            return read(f, n, offset)[: n // 2]

        self._assert_denied(
            content=payload, expected=self._sha(payload),
            read_override=half, reason="FD_SHORT_READ",
        )
        self.assertEqual(offsets, [0])

    def test_c_hash_matching_only_prefix_is_never_accepted(self):
        payload = bytes(range(256)) * 4

        def prefix(_path, _fd, read, f, n, offset):
            return read(f, n, offset)[:512]

        self._assert_denied(
            content=payload, expected=self._sha(payload[:512]),
            read_override=prefix, reason="FD_SHORT_READ",
        )

    def test_d_premature_eof_denied(self):
        self._assert_denied(
            content=b"private owned file",
            expected=self._sha(b"private owned file"),
            read_override=lambda _path, _fd, _read, _f, _n, _off: b"",
            reason="FD_SHORT_READ",
        )

    def test_e_multiple_short_read_attempts_each_refuse(self):
        """Fail immediately on first short read; never try a second fragment."""
        payload = b"Q" * 2048
        seen = []

        def one_byte(_path, _fd, read, f, n, off):
            seen.append((n, off))
            return read(f, n, off)[:1]

        for _ in range(2):
            self._assert_denied(
                content=payload, expected=self._sha(payload),
                read_override=one_byte, reason="FD_SHORT_READ",
            )
        self.assertEqual(seen, [(len(payload), 0), (len(payload), 0)])

    def test_f_mutation_during_read_refused_even_if_digest_would_match(self):
        payload = b"A" * (1024 * 1024 + 17)
        touched = []

        def mutate(path, _fd, read, f, n, off):
            data = read(f, n, off)
            if off == 0:
                with path.open("r+b") as out:
                    out.seek(0)
                    out.write(b"Z")
                before = path.stat()
                os.utime(
                    path,
                    ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000),
                )
                touched.append(True)
            return data

        self._assert_denied(
            content=payload, expected=self._sha(payload),
            read_override=mutate, reason="FD_MUTATED_DURING_HASH",
        )
        self.assertEqual(touched, [True])

    def test_g_size_change_during_read_refused(self):
        payload = b"C" * 1024

        def expand(path, _fd, read, f, n, off):
            data = read(f, n, off)
            if off == 0:
                with path.open("ab") as out:
                    out.write(b"growth")
            return data

        self._assert_denied(
            content=payload, expected=self._sha(payload),
            read_override=expand, reason="FD_MUTATED_DURING_HASH",
        )

    def test_h_eio_is_refusal_not_authenticated_data(self):
        def fail(_path, _fd, _read, _f, _n, _off):
            raise OSError(errno.EIO, "injected I/O failure")

        self._assert_denied(
            content=b"private FD bytes", expected=self._sha(b"private FD bytes"),
            read_override=fail, reason="FD_READ_FAILED",
        )


if __name__ == "__main__":
    unittest.main()
