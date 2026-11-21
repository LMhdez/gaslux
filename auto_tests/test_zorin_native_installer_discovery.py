"""Adversarial read-only Zorin ISO discovery and bound-target tests."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "tools"))
import zorin_native_installer_discovery as discover
import zorin_native_target_guard as target


class NativeInstallerDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.status = (b"Package: ubiquity\nVersion: 25.0\n"
                       b"Architecture: all\nStatus: install ok installed\n\n")
        self.sources = {
            "var/lib/dpkg/status": self.status,
            "var/lib/dpkg/info/ubiquity.list": b"/usr/bin/ubiquity\n",
            "usr/bin/ubiquity": b"#!/usr/bin/python3\nfrom ubiquity import main\n",
        }
        self.baseline = {
            "isoSha256": "44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5",
            "isoSizeBytes": 3909091328,
            "squashfsPath": "casper/filesystem.squashfs",
            "installerCandidateLaunchers": [
                {"path": "usr/share/applications/ubiquity.desktop",
                 "exec": "sudo sh -c 'ubiquity gtk_ui'", "sha256": "a" * 64}],
            "installerCandidateSnaps": [],
        }

    def member(self, root, name, limit, optional=False):
        return self.sources.get(name)

    def report(self, manifest=b"ubiquity 25.0\n"):
        return discover.inspect(Path("/not-a-disk"), self.baseline, manifest, self.member)

    def test_static_candidate_is_never_an_installer_proof(self):
        doc = self.report()
        self.assertEqual(doc["staticInstallerCandidate"], "ubiquity")
        self.assertEqual(doc["discoveryStatus"], "IDENTIFIED_STATICALLY")
        self.assertFalse(doc["nativeInstallerInvoked"])
        self.assertFalse(doc["writeSetAuthenticated"])
        self.assertEqual(doc["authorization"], "DENY_NO_WRITER")
        self.assertEqual(doc["capabilities"]["grubInstall"], "UNOBSERVED")
        self.assertTrue(doc["executables"][0]["ownerVerified"])

    def test_missing_executable_fails_closed(self):
        del self.sources["usr/bin/ubiquity"]
        self.assertIsNone(self.report()["staticInstallerCandidate"])

    def test_wrong_executable_owner_fails_closed(self):
        self.sources["var/lib/dpkg/info/ubiquity.list"] = b"/usr/bin/other\n"
        self.assertIsNone(self.report()["staticInstallerCandidate"])

    def test_manifest_version_mismatch_fails_closed(self):
        self.assertIsNone(self.report(b"ubiquity 24.0\n")["staticInstallerCandidate"])

    def test_launcher_mismatch_fails_closed(self):
        self.baseline["installerCandidateLaunchers"] = []
        self.assertIsNone(self.report()["staticInstallerCandidate"])

    def test_duplicated_dpkg_identity_rejected(self):
        with self.assertRaisesRegex(discover.NativeDiscoveryError, "duplicate"):
            discover.installed_packages(self.status + self.status)

    def test_installed_package_requires_version(self):
        raw = b"Package: ubiquity\nArchitecture: all\nStatus: install ok installed\n"
        with self.assertRaisesRegex(discover.NativeDiscoveryError, "version"):
            discover.installed_packages(raw)

    def test_squashfs_path_traversal_rejected_without_subprocess(self):
        with patch.object(discover.subprocess, "run") as runner:
            for path in ("../../etc/shadow", "/dev/sda", "a/../b", "a//b", "a/./b"):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(discover.NativeDiscoveryError, "unsafe"):
                        discover.read_member(Path("/mock"), path, 4096)
            runner.assert_not_called()

    def test_no_disk_writer_code_in_discovery(self):
        code = Path(discover.__file__).read_text(encoding="utf-8")
        for forbidden in ("grub-install", "mkfs.ext4", "efibootmgr --create",
                          "sudo ubiquity", "sudo calamares"):
            self.assertNotIn(forbidden, code)

    def test_schema_requires_denial(self):
        import jsonschema
        folder = Path(__file__).parents[1] / "schemas"
        schema = json.loads((folder / "zorin-native-installer-discovery.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        report = self.report()
        jsonschema.validate(report, schema)
        report["authorization"] = "ACCEPT"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(report, schema)

    def test_target_plan_is_readonly_and_identical_to_historical_root(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/zorin-native-observed-linux-target.json").read_text())
        schema = json.loads((Path(__file__).parents[1] / "schemas/zorin-native-target-plan.schema.json").read_text())
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
        read_only = target.proposed_readonly_target(target.ObservedLinuxTarget(**fixture))
        jsonschema.validate(read_only, schema)
        self.assertEqual(read_only["writeOperations"], [])
        self.assertEqual(read_only["authorization"], "DENY_NO_WRITER")
        self.assertEqual(read_only["target"]["gpt_label"], "GASLUX-CACHYOS-ROOT")
        read_only["transactionOwned"] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(read_only, schema)

    def test_mutated_target_identity_refused(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/zorin-native-observed-linux-target.json").read_text())
        for field, value in (("first_lba", 154707969),
                             ("last_lba", 205039614),
                             ("partuuid", "00000000-0000-0000-0000-000000000001"),
                             ("ext4_uuid", "00000000-0000-0000-0000-000000000001"),
                             ("gpt_label", "GASLUX-ZORIN-ROOT"),
                             ("logical_sector_bytes", 4096)):
            modified = deepcopy(fixture)
            modified[field] = value
            with self.subTest(field=field), self.assertRaises(target.TargetIdentityError):
                target.proposed_readonly_target(target.ObservedLinuxTarget(**modified))

    def test_missing_or_extra_identity_rejected_by_cli_contract(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/zorin-native-observed-linux-target.json").read_text())
        self.assertEqual(len(fixture), len(target.ObservedLinuxTarget.__dataclass_fields__))
        fixture["writeAuthorized"] = True
        self.assertNotEqual(set(fixture), set(target.ObservedLinuxTarget.__dataclass_fields__))


if __name__ == "__main__":
    unittest.main()
