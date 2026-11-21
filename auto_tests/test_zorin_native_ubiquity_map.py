"""Adversarial source-map checks: no installer execution and no writer grant."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import zorin_native_ubiquity_map as mapping


class ZorinNativeUbiquityMapTests(unittest.TestCase):
    def setUp(self):
        self.entry = b"#!/usr/bin/python3\nfrom ubiquity import main\nmain()\n"
        self.plugin = (
            b"class Page:\n"
            b"    def set_partitions(self):\n"
            b"        self.partman.commit()\n"
            b"        self.efi_partition = '/boot/efi'\n"
            b"    def save_user(self):\n"
            b"        username = self.username\n"
            b"        timezone = self.timezone\n"
            b"        self.preseed_config()\n"
        )
        self.status = (
            b"Package: ubiquity\nStatus: install ok installed\n"
            b"Version: 24.04.5+zorin2\nArchitecture: amd64\n\n"
            b"Package: partman-base\nStatus: install ok installed\n"
            b"Version: 1.0\nArchitecture: all\n\n"
        )
        self.manifest = b"ubiquity 24.04.5+zorin2\npartman-base 1.0\n"
        self.members = {
            "var/lib/dpkg/status": self.status,
            "var/lib/dpkg/info/ubiquity.list":
                (b"/usr/bin/ubiquity\n"
                 b"/usr/lib/ubiquity/components/ubi-partman.py\n"),
            "var/lib/dpkg/info/partman-base.list": b"/usr/share/doc/partman-base/README\n",
            "usr/bin/ubiquity": self.entry,
            "usr/lib/ubiquity/components/ubi-partman.py": self.plugin,
        }
        self.prior = {
            "authorization": "DENY_NO_WRITER",
            "staticInstallerCandidate": "ubiquity",
            "iso": {"sha256": mapping.ISO_SHA},
            "packages": {"ubiquity": {"version": mapping.UBIQUITY_VERSION}},
            "executables": [{"path": "usr/bin/ubiquity",
                             "sha256": mapping.digest(self.entry),
                             "ownerVerified": True}],
        }

    def read(self, _rootfs, name, _size, optional=False):
        return self.members.get(name)

    def build(self):
        with patch.object(mapping, "STATUS_SHA", mapping.digest(self.status)), \
             patch.object(mapping, "UBIQUITY_EXEC_SHA", mapping.digest(self.entry)):
            report = mapping.build_map(Path("/unmounted"), self.prior,
                                       self.manifest, self.read)
            mapping.validate_consistency(report)
            return report

    def test_exact_owned_source_witness_and_ungranted_writer(self):
        report = self.build()
        self.assertEqual(report["authorization"], "DENY_NO_WRITER")
        self.assertFalse(report["partitionLockdownVerified"])
        self.assertFalse(report["outsideLinuxTargetWriteSetAuthenticated"])
        self.assertFalse(report["nativeInstallerExecuted"])
        self.assertEqual(report["capabilities"]["gptModification"]["status"],
                         "SUPPORTED_STATICALLY")
        evidence = report["capabilities"]["gptModification"]["evidence"][0]
        self.assertEqual(evidence["function"], "set_partitions")
        self.assertEqual(evidence["sourceSha256"], mapping.digest(self.plugin))
        self.assertGreater(evidence["line"], 1)
        self.assertEqual(report["potentialWriteSurfaces"]
                         ["gptAndPartitionMetadata"]["observedWrites"], False)

    def test_only_code_references_cannot_claim_write_confinement(self):
        report = self.build()
        report["potentialWriteSurfaces"]["gptAndPartitionMetadata"][
            "writeSetLimitedToOwnedLinuxRoot"] = True
        with patch.object(mapping, "UBIQUITY_EXEC_SHA", mapping.digest(self.entry)):
            with self.assertRaisesRegex(mapping.NativeDiscoveryError, "overclaims"):
                mapping.validate_consistency(report)

    def test_hash_mismatch_in_capability_witness_rejected(self):
        report = self.build()
        report["capabilities"]["gptModification"]["evidence"][0][
            "sourceSha256"] = "0" * 64
        with patch.object(mapping, "UBIQUITY_EXEC_SHA", mapping.digest(self.entry)):
            with self.assertRaisesRegex(mapping.NativeDiscoveryError, "not bound"):
                mapping.validate_consistency(report)

    def test_missing_module_keeps_capability_unobserved(self):
        del self.members["usr/lib/ubiquity/components/ubi-partman.py"]
        report = self.build()
        self.assertEqual(report["capabilities"]["gptModification"]["status"],
                         "UNOBSERVED")
        self.assertIn("usr/lib/ubiquity/components/ubi-partman.py",
                      report["unreadablePaths"])
        self.assertEqual(report["potentialWriteSurfaces"]
                         ["gptAndPartitionMetadata"]["classification"], "UNKNOWN")

    def test_missing_pinned_entrypoint_rejected(self):
        del self.members["usr/bin/ubiquity"]
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "missing"):
            self.build()

    def test_untrusted_version_rejected(self):
        self.prior["packages"]["ubiquity"]["version"] = "24.04.5+zorin3"
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "mismatch"):
            self.build()

    def test_untrusted_installer_executable_sha_rejected(self):
        self.prior["executables"][0]["sha256"] = "1" * 64
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "mismatch"):
            self.build()

    def test_status_hash_mismatch_rejected(self):
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "status changed"):
            mapping.build_map(Path("/unmounted"), self.prior,
                              self.manifest, self.read)

    def test_double_package_rejected(self):
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "duplicate"):
            mapping.package_status(self.status + self.status)

    def test_missing_package_version_rejected(self):
        broken = self.status.replace(b"Version: 24.04.5+zorin2\n", b"")
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "missing"):
            mapping.package_status(broken)

    def test_duplicate_casper_identity_rejected(self):
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "duplicate"):
            mapping.casper_versions(self.manifest + b"ubiquity 2.0\n")

    def test_path_traversal_in_owned_file_list_rejected(self):
        for path in (b"/usr/lib/ubiquity/../etc/secret.py\n",
                     b"/usr/lib/ubiquity//hidden.py\n",
                     b"/usr/lib/ubiquity/../../dev/sda.py\n"):
            with self.subTest(path=path), self.assertRaisesRegex(
                    mapping.NativeDiscoveryError, "traversal"):
                mapping.owned_sources("ubiquity", path)

    def test_reused_owner_for_same_source_rejected(self):
        self.members["var/lib/dpkg/info/partman-base.list"] = (
            b"/usr/lib/ubiquity/components/ubi-partman.py\n")
        with self.assertRaisesRegex(mapping.NativeDiscoveryError, "multiple"):
            self.build()

    def test_truncation_must_remain_visible(self):
        with patch.object(mapping, "FILE_LIMIT", 1):
            report = self.build()
        self.assertTrue(report["sourceEnumerationTruncated"])
        self.assertEqual(report["selectedSourceCount"], 1)
        self.assertEqual(report["capabilities"]["gptModification"]["status"],
                         "UNOBSERVED")
        self.assertFalse(report["partitionLockdownVerified"])

    def test_false_supported_without_evidence_rejected(self):
        report = self.build()
        report["capabilities"]["nvram"]["status"] = "SUPPORTED_STATICALLY"
        with patch.object(mapping, "UBIQUITY_EXEC_SHA", mapping.digest(self.entry)):
            with self.assertRaisesRegex(mapping.NativeDiscoveryError, "classification"):
                mapping.validate_consistency(report)

    def test_readonly_schema_refuses_accept_and_overstated_risks(self):
        import jsonschema
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / \
            "zorin-native-ubiquity-capabilities.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        report = self.build()
        # Synthetic source fixture, not a claim that the real ISO has these
        # hashes. Align pinned top-level proof fields ONLY for schema tests.
        report["installer"]["sha256"] = mapping.UBIQUITY_EXEC_SHA
        report["casperManifestSha256"] = (
            "cc206a10d7de5cd8d373634f1b91ac35e030f5d4075acda7edcbb2b0318ee948")
        report["dpkgStatusSha256"] = mapping.STATUS_SHA
        jsonschema.validate(report, schema)
        for key, bad in (
            ("authorization", "ACCEPT_NO_WRITER"),
            ("nativeInstallerExecuted", True),
            ("partitionLockdownVerified", True),
            ("efiAndNvramPreservationVerified", True),
        ):
            fake = deepcopy(report)
            fake[key] = bad
            with self.subTest(key=key), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(fake, schema)

    def test_no_writers_executed_by_source_mapper(self):
        source = Path(mapping.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess.run([\"grub-install\"",
                          "subprocess.run([\"parted\"",
                          "subprocess.run([\"efibootmgr\"",
                          "subprocess.run([\"mkfs\""):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
