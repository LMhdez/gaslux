"""VM-only CachyOS update/recovery safety contracts and negative guards."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUEST = ROOT / "auto_tests/tools/cachyos_vm_update_recovery_guest.sh"
HOST = ROOT / "auto_tests/tools/cachyos_qemu_update_rollback.sh"
STAGE = ROOT / "auto_tests/tools/cachyos_guest_vm_only_install.sh"
RUNNER = ROOT / "auto_tests/tools/cachyos_real_live_kernel_smoke.sh"
WORKFLOW = ROOT / ".github/workflows/cachyos-official-iso.yml"


class CachyosQemuUpdateRecoveryContract(unittest.TestCase):
    def setUp(self):
        self.guest = GUEST.read_text()
        self.host = HOST.read_text()
        self.stage = STAGE.read_text()
        self.runner = RUNNER.read_text()

    def test_no_host_disk_mutator_or_signature_bypass(self):
        for content in (self.host, self.guest):
            for forbidden in (
                "/dev/sda", "/dev/nvme", "mkfs.ext4", "sgdisk --clear",
                "bcdedit", "Set-Partition", "efibootmgr -c",
                "--skippgpcheck", "TrustAll --", "SigLevel = Never",
                "pacman -Sy --noconfirm", "pacman -Syu --overwrite",
            ):
                self.assertNotIn(forbidden, content)
        self.assertIn("pacman -Syu --noconfirm linux-cachyos-lts grub",
                      self.guest)
        self.assertIn("--no-nvram --removable --recheck", self.guest)

    def test_host_rejects_non_vm_paths_without_any_mutation(self):
        env = os.environ.copy()
        env.update({
            "GASLUX_LAB_FIRSTBOOT": "1",
            "GASLUX_LAB_UPDATE_ROLLBACK": "1",
            "GASLUX_SIGNED_EVIDENCE_DIR": "synthetic-signed-identity",
        })
        for invalid in ("/dev/sda", "/dev/null",
                        "/tmp/wrong-target.qcow2", "/etc/hosts"):
            p = subprocess.run(
                ["bash", str(HOST), invalid, "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                 "/usr/share/OVMF/OVMF_VARS_4M.fd", "/tmp"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(p.returncode, 0, invalid)
            self.assertIn("GASLUX_UPDATE_ROLLBACK_FAILED", p.stderr)

    def test_host_requires_opt_in_and_pinned_signed_iso(self):
        p = subprocess.run(
            ["bash", str(HOST), "/tmp/cachyos-real-boot-fake/target.qcow2",
             "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
             "/usr/share/OVMF/OVMF_VARS_4M.fd", "/tmp"],
            env={**os.environ, "GASLUX_LAB_UPDATE_ROLLBACK": "0",
                 "GASLUX_LAB_FIRSTBOOT": "0"},
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("explicit signed-ISO disposable VM mode absent", p.stderr)

    def test_host_rejects_symlink_even_for_approved_pattern(self):
        env = os.environ.copy()
        env.update(GASLUX_LAB_FIRSTBOOT="1", GASLUX_LAB_UPDATE_ROLLBACK="1",
                   GASLUX_SIGNED_EVIDENCE_DIR="signed-lab")
        with tempfile.TemporaryDirectory(prefix="cachyos-real-boot-") as folder:
            base = Path(folder) / "target.qcow2"
            base.symlink_to("/dev/null")
            p = subprocess.run(
                ["bash", str(HOST), str(base),
                 "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                 "/usr/share/OVMF/OVMF_VARS_4M.fd", folder],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("missing unsafe or linked QCOW2", p.stderr)

    def test_raw_qemu_powercut_and_byte_identity_proven(self):
        for requirement in (
            "qemu-img create -f qcow2 -F qcow2 -b",
            "GASLUX_CI_POWERCUT", "kill -KILL",
            "GASLUX_VM_UPDATE_POWERCUT_ARMED=1",
            "GASLUX_QCOW2_POWERCUT_SNAPSHOT_PRESERVED=1",
            "GASLUX_QCOW2_BASELINE_RECOVERY_BOOT_VERIFIED=1",
            "assert_base_unchanged",
            'rm -- "$cut"', 'rm -- "$update"',
            "GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1",
        ):
            self.assertIn(requirement, self.host)

    def test_vm_explicit_failure_aborts_marker_wait_before_success(self):
        # Fail closed if an installed service reports a concrete problem,
        # even if an unrelated marker exists or QEMU remains running.
        body = self.host.split('require_marker() {', 1)[1].split('\n}\n', 1)[0]
        failure = body.index("GASLUX_VM_UPDATE_FAILURE:")
        success = body.index("awk -v marker=")
        self.assertLess(failure, success)
        self.assertIn("GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_FAIL:", body)
        self.assertIn('guest explicitly rejected VM phase before $marker', body)
        self.assertIn("tail -c 10000", body)

    def test_updated_disk_must_power_off_cleanly_before_new_boot(self):
        # Do not SIGKILL immediately after native pacman/GRUB writes: that
        # would inject an unintended crash unrelated to the power-cut case.
        self.assertIn("GASLUX_VM_UPDATE_CLEAN_SHUTDOWN_REQUESTED=1", self.guest)
        self.assertIn("systemctl --no-block poweroff", self.guest)
        self.assertNotIn("systemctl --no-block reboot", self.guest)
        start = self.host.index("require_marker \"$w/update-transaction-serial.log\" 'GASLUX_VM_UPDATE_APPLIED=1'")
        end = self.host.index("GASLUX_QCOW2_SIGNED_PACMAN_UPDATE_APPLIED=1", start)
        update_phase = self.host[start:end]
        self.assertIn("GASLUX_VM_UPDATE_CLEAN_SHUTDOWN_REQUESTED=1", update_phase)
        self.assertIn("await_clean_shutdown 160", update_phase)
        self.assertNotIn("stop_vm", update_phase)
        self.assertLess(update_phase.index("await_clean_shutdown 160"),
                        update_phase.index("assert_base_unchanged"))
        self.assertIn("wait \"$vm_pid\" || status=$?", self.host)
        self.assertIn("(( status == 0 ))", self.host)
        self.assertIn("GASLUX_QCOW2_UPDATE_CLEAN_SHUTDOWN_VERIFIED=1", self.host)
        powercut = self.host.split("# Inject a real VM loss of power", 1)[1]
        self.assertIn("stop_vm # SIGKILL is a hard VM cut", powercut)

    def test_recovery_never_boots_writable_baseline_qcow2(self):
        # A guest can update journal/filesystem state merely by booting.
        # Recovery proof must use a disposable COW overlay and then prove
        # that the baseline remained byte-identical after that boot.
        self.assertNotIn('launch "$base" BASELINE', self.host)
        region = self.host.split('recovered="$w/recovered-overlay.qcow2"', 1)[1]
        steps = (
            'make_overlay "$recovered"',
            'launch "$recovered" BASELINE',
            "require_marker \"$w/recovered-baseline-serial.log\" 'GASLUX_INSTALLED_CACHYOS_FIRSTBOOT_PASS=1'",
            'stop_vm',
            'assert_base_unchanged',
            'rm -- "$recovered"',
            'assert_base_unchanged',
            "GASLUX_QCOW2_BASELINE_RECOVERY_BOOT_VERIFIED=1",
        )
        prev = -1
        for step in steps:
            with self.subTest(step=step):
                at = region.find(step, prev + 1)
                self.assertGreaterEqual(at, 0)
                prev = at

    def test_update_requires_installed_kernel_root_and_trusted_packages(self):
        for requirement in (
            "GASLUX_CI_UPDATE", "opt/gaslux/ci-mode/raw",
            "ID=cachyos", "ID_LIKE=arch",
            "lab-real-iso-signed-20261116",
            "01234567-89ab-cdef-0123-456789abcdef",
            "pacman-conf --repo", "TrustedOnly", "PackageRequired",
            "pacman -Syu --noconfirm linux-cachyos-lts grub",
            "mkinitcpio -P", "grub-script-check",
            "GASLUX_VM_UPDATE_APPLIED=1",
            "GASLUX_VM_UPDATED_REBOOT_VERIFIED=1",
        ):
            self.assertIn(requirement, self.guest)

    def test_native_repo_set_provisioned_without_weak_live_config(self):
        # The pinned ISO's live pacman.conf is NOT sufficient for signed-only
        # pacstrap. Reuse the tested PR34 builder and effective trust guard.
        strict = (ROOT / "assets/live/cachyos-strict-pacman.py").read_text()
        trust = (ROOT / "assets/live/cachyos-pacman-trust.py").read_text()
        for required in (
            'sha256sum --check --status "$guard.sha256"',
            'strict-pacman.py --root / --run-id "$TX" --prepare-vm',
            'pacman-trust.py --config "$strict_dir/pacman-install.conf"',
            'pacstrap -K -C "$strict_dir/pacman-install.conf" "$TARGET"',
            'LocalFileSigLevel = Required TrustedOnly',
            'RemoteFileSigLevel = Required TrustedOnly',
            'install -m 0644 "$strict_dir/pacman-target.conf"',
            'cmp -s "$strict_dir/pacman-target.conf"',
            'GASLUX_LAB_SIGNED_INSTALLED_REPOS_CONFIGURED=1',
        ):
            self.assertIn(required, self.stage)
        self.assertIn("Required DatabaseOptional TrustedOnly", strict)
        self.assertIn("PackageTrustedOnly", trust)
        self.assertNotIn('pacstrap -K "$TARGET"', self.stage)
        self.assertNotIn('cp /etc/pacman.conf', self.stage)
        self.assertIn("GASLUX_VM_UPDATE_TRUST_POLICY_VERIFIED=1", self.guest)

    def test_effective_pacman_policy_accepts_only_trusted_required_packages(self):
        # Execute exactly the offline Python policy check embedded in the lab
        # installer, not a weaker duplicate implementation.
        anchor = '  python3 - "$repo" "$level" <<\'PY\' || die'
        self.assertIn(anchor, self.stage)
        code = self.stage.split(anchor, 1)[1].split("\nPY\n", 1)[0].split("\n", 1)[1]
        accepted = (
            'Required DatabaseOptional TrustedOnly',
            'PackageRequired DatabaseOptional TrustedOnly',
            'DatabaseOptional PackageRequired PackageTrustedOnly',
        )
        rejected = (
            '', 'DatabaseRequired TrustedOnly', 'Required Optional TrustedOnly',
            'Required DatabaseOptional TrustAll',
            'Required DatabaseOptional PackageTrustAll',
            'PackageOptional DatabaseRequired TrustedOnly',
            'Required Required TrustedOnly',
            'Required DatabaseNever TrustedOnly',
            'Required DatabaseOptional Unknown',
        )
        for siglevel in accepted + rejected:
            with self.subTest(siglevel=siglevel):
                result = subprocess.run(
                    ['python3', '-c', code, 'cachyos', siglevel],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode == 0, siglevel in accepted,
                                 result.stdout + result.stderr)
        self.assertIn('pacstrap -K -C "$strict_dir/pacman-install.conf"', self.stage)

    def test_update_rejects_untrusted_and_foreign_repo_configuration(self):
        self.assertIn('unexpected enabled repository count', self.guest)
        self.assertIn('unapproved installed repository', self.guest)
        self.assertIn('count == 1', self.guest)
        start = self.guest.index('import sys\nrepo, raw = sys.argv[1:]')
        code = self.guest[start:].split("\nPY\n", 1)[0]
        cases = {
            'Required DatabaseOptional TrustedOnly': True,
            'PackageRequired DatabaseOptional PackageTrustedOnly': True,
            'DatabaseRequired TrustedOnly': False,
            'Required DatabaseOptional': False,
            'Required Optional TrustedOnly': False,
            'Required DatabaseOptional TrustAll': False,
            'Required PackageOptional TrustedOnly': False,
            'Required Required TrustedOnly': False,
            'Required DatabaseOptional Unknown': False,
        }
        for level, expected in cases.items():
            with self.subTest(level=level):
                result = subprocess.run(
                    ['python3', '-c', code, 'cachyos', level],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode == 0, expected,
                                 result.stdout + result.stderr)

    def test_signed_only_tools_are_hashed_on_disposable_boot_volume(self):
        for required in (
            'assets/live/cachyos-strict-pacman.py',
            'assets/live/cachyos-pacman-trust.py',
            'mcopy -i "$fat" "$src"',
            'mcopy -i "$fat" "$w/$guard.sha256"',
        ):
            self.assertIn(required, self.runner)
        self.assertIn('missing trusted VM-only $guard tool', self.stage)
        self.assertLess(
            self.stage.index('sha256sum --check --status "$guard.sha256"'),
            self.stage.index('sgdisk --clear'),
        )
        self.assertLess(
            self.stage.index('GASLUX_LAB_STRICT_SIGNED_ONLY_POLICY_PASS=1'),
            self.stage.index('pacstrap -K -C "$strict_dir/pacman-install.conf"'),
        )

    def test_bounded_guest_script_is_hashed_in_signed_boot_fat(self):
        self.assertIn('sha256sum "$updater"', self.runner)
        self.assertIn('mcopy -i "$fat" "$updater" ::/update.sh', self.runner)
        self.assertIn('sha256sum --check update.sha256', self.stage)
        self.assertIn("ExecStart=/usr/local/sbin/gaslux-ci-vm-update",
                      self.stage)
        self.assertIn("After=gaslux-ci-firstboot.service", self.stage)
        self.assertIn('GASLUX_LAB_UPDATE_ROLLBACK', self.runner)
        self.assertIn("auto_tests/tools/cachyos_qemu_update_rollback.sh",
                      self.runner)

    def test_real_official_iso_ci_only_on_explicit_branch(self):
        config = WORKFLOW.read_text()
        self.assertIn("feature/cachyos-qemu-updates-snapshot-recovery", config)
        self.assertIn("GASLUX_LAB_UPDATE_ROLLBACK:", config)
        self.assertIn("cachyos_qemu_update_rollback.sh", config)
        self.assertIn("cachyos_vm_update_recovery_guest.sh", config)
        self.assertIn("No Windows rollback", config)


if __name__ == "__main__":
    unittest.main()
