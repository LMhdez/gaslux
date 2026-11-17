"""CachyOS native Plasma Wayland QEMU proof and fail-closed framebuffer tests."""
from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "auto_tests/tools/cachyos_qemu_graphics_evidence.py"
INSTALL = ROOT / "auto_tests/tools/cachyos_guest_vm_only_install.sh"
RUNNER = ROOT / "auto_tests/tools/cachyos_real_live_kernel_smoke.sh"
SERIAL = ROOT / "auto_tests/tools/cachyos_live_guest_serial.py"
WORKFLOW = ROOT / ".github/workflows/cachyos-official-iso.yml"

spec = importlib.util.spec_from_file_location("gaslux_qemu_graphics", PROOF)
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class CachyosQemuPlasmaProof(unittest.TestCase):
    def test_real_signed_x11_desktop_packages_and_session_guard(self):
        script = INSTALL.read_text()
        for piece in (
            "GASLUX_LAB_GRAPHICAL", "plasma-meta", "plasma-workspace",
            "kwin", "qt6-wayland", "sddm", "mesa",
            "pacstrap -K", "arch-chroot",
            "usr/share/wayland-sessions/plasma.desktop",
            "User=gasluxtest", "Session=plasma.desktop",
            "systemctl enable sddm.service", "graphical.target",
            "pgrep -u gasluxtest -x plasmashell",
            "pgrep -u gasluxtest -x kwin_wayland",
            "GASLUX_VM_CACHYOS_PLASMA_WAYLAND_SESSION_PASS=1",
        ):
            self.assertIn(piece, script)
        self.assertNotIn("cp -a /run/archiso", script)
        self.assertNotIn("--skippgpcheck", script)

    def test_runner_requires_native_processes_and_real_fb(self):
        script = RUNNER.read_text()
        self.assertIn("--run-lab-graphical", script)
        self.assertIn("GASLUX_VM_CACHYOS_PLASMA_WAYLAND_SESSION_PASS=1", script)
        self.assertIn("cachyos_qemu_graphics_evidence.py", script)
        self.assertIn("cachyos-installed-plasma-session.ppm", script)
        # A separate target disk, no ISO/FAT, remains mandatory on second boot.
        second = script.split("GASLUX_LAB_STAGE_COMPLETE:", 1)[1]
        self.assertIn('file="$w/target.qcow2"', second)
        self.assertNotIn("id=bootimg", second.split("for _ in $(seq 1 112)", 1)[0])

    def test_host_separates_graphical_from_headless_lab(self):
        text = SERIAL.read_text()
        self.assertIn("run_lab_graphical: bool = False", text)
        self.assertIn("graphical VM stage requires the real signed installer", text)
        self.assertIn('b"export GASLUX_LAB_GRAPHICAL=1 && "', text)
        workflow = WORKFLOW.read_text()
        self.assertIn("feature/cachyos-qemu-plasma-graphical-session", workflow)
        self.assertIn("GASLUX_LAB_GRAPHICAL:", workflow)

    def test_valid_graphical_ppm_with_diverse_pixels(self):
        with tempfile.TemporaryDirectory() as d:
            ppm = Path(d) / "picture.ppm"
            width, height = 640, 480
            pixels = bytearray()
            for i in range(width * height):
                pixels.extend((i % 251, (i // 13) % 253, (i // 101) % 255))
            ppm.write_bytes(f"P6\n{width} {height}\n255\n".encode() + pixels)
            w, h, colors = audit.verify_ppm(ppm)
            self.assertEqual((w, h), (width, height))
            self.assertGreaterEqual(colors, 32)

    def test_blank_console_or_truncated_fb_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "blank.ppm"
            p.write_bytes(b"P6\n640 480\n255\n" + b"\x00" * (640 * 480 * 3))
            with self.assertRaisesRegex(audit.GraphicsEvidenceError, "pixel diversity"):
                audit.verify_ppm(p)
            p.write_bytes(b"P6\n640 480\n255\n" + b"\x80" * 700)
            with self.assertRaisesRegex(audit.GraphicsEvidenceError, "pixels truncated"):
                audit.verify_ppm(p)

    def test_image_output_must_be_new_vm_only_path(self):
        with tempfile.TemporaryDirectory() as folder:
            arbitrary = Path(folder) / "untrusted.ppm"
            with self.assertRaisesRegex(audit.GraphicsEvidenceError, "lab-only"):
                audit.run(Path(folder) / "monitor.sock", arbitrary)

    def test_serial_login_prompt_interleaving_must_match_exact_guest_marker(self):
        script = RUNNER.read_text()
        self.assertIn('installed_marker_present()', script)
        self.assertIn('"gaslux-cachyos-ci login: " marker', script)
        self.assertIn('$0 == marker || $0 ==', script)
        self.assertNotIn('index($0, marker)', script)
        self.assertIn('cachyos_qemu_graphics_evidence.py', script)

    def test_bash_stage_and_qemu_runner_syntax(self):
        for script in (INSTALL, RUNNER):
            proc = subprocess.run(["bash", "-n", str(script)],
                                  capture_output=True, text=True, timeout=8)
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
