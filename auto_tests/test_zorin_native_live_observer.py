"""Negative tests for diskless Zorin 18.1 UEFI live-ISO observation."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import zorin_native_live_observer as live


class ZorinLiveObserverContracts(unittest.TestCase):
    def test_without_explicit_hosted_consent_refused(self):
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(live.ObservationError, "requires opted-in"):
                live.check_host(Path(td) / "z.iso", Path(td))

    def test_no_physical_disk_commands_or_installer_invocation(self):
        source = Path(live.__file__).read_text(encoding="utf-8")
        for required in ('"-nodefaults"', '"-no-user-config"', '"-net"', '"none"',
                         '"readonly=on,file=" + str(code)',
                         '"readonly=on,format=raw,file=" + str(iso)'):
            self.assertIn(required, source)
        for forbidden in ("grub-install", "mkfs.ext4", "wipefs ",
                          "efibootmgr --create", "sudo ubiquity", "sudo calamares"):
            self.assertNotIn(forbidden, source)

    def test_invalid_qmp_ack_is_rejected(self):
        first, second = socket.socketpair()
        try:
            with second.makefile("wb") as output:
                output.write(b'{"id":"query-status","error":{"class":"GenericError"}}\n')
                output.flush()
            with first.makefile("rb") as response:
                with self.assertRaisesRegex(live.ObservationError, "not acknowledged"):
                    live.qmp(first, response, "query-status")
        finally:
            first.close()
            second.close()

    def test_unrelated_qmp_event_cannot_replace_corresponding_reply(self):
        first, second = socket.socketpair()
        try:
            with second.makefile("wb") as output:
                output.write(b'{"event":"POWERDOWN"}\n')
                output.write(b'{"id":"query-status","return":{"status":"running"}}\n')
                output.flush()
            with first.makefile("rb") as response:
                value = live.qmp(first, response, "query-status")
                self.assertEqual(value["status"], "running")
        finally:
            first.close()
            second.close()

    def test_readonly_state_is_only_observation_not_proof_of_boot(self):
        source = Path(live.__file__).read_text(encoding="utf-8")
        for field in ("liveIsoBootVerified", "nativeInstallationVerified",
                      "hostGuestIdentityIndependentlyAuthenticated",
                      "guestShutdownVerified", "qmpQuitIsCleanupOnly"):
            self.assertIn(field, source)


if __name__ == "__main__":
    unittest.main()
