"""Regression contract for the read-only official CachyOS serial witness."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/cachyos-official-iso.yml"
SMOKE = ROOT / "auto_tests/tools/cachyos_real_live_kernel_smoke.sh"


class CachyosSerialEvidenceContract(unittest.TestCase):
    def test_official_iso_job_uploads_serial_evidence_even_on_failure(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("GASLUX_BOOT_EVIDENCE_DIR: 'gaslux-boot-evidence'", workflow)
        self.assertIn("name: Preserve virtual CachyOS serial boot evidence", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", workflow)
        self.assertIn("path: gaslux-boot-evidence/", workflow)
        self.assertIn("retention-days: 14", workflow)

    def test_witness_is_hashed_before_boot_assertions(self):
        smoke = SMOKE.read_text(encoding="utf-8")
        self.assertIn('install -m 0600 -- "$w/serial.log"', smoke)
        self.assertIn("sha256sum cachyos-live-serial.log > cachyos-live-serial.sha256", smoke)
        self.assertLess(smoke.index("sha256sum cachyos-live-serial.log"), smoke.index("if ! grep -Eq 'Linux version"))
        self.assertIn('[[ -n "${GASLUX_BOOT_EVIDENCE_DIR:-}" && -f "$w/serial.log" ]]', smoke)


if __name__ == "__main__":
    unittest.main()
