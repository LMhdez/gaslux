"""Offline contracts for the read-only AST inventory."""
import base64
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gaslux_history_ast as audit


class AstHistoryTests(unittest.TestCase):
    def test_exact_blob(self):
        raw = b"def f():\n    return 1\n"
        sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        row = {"sha": sha, "size": len(raw), "encoding": "base64",
               "content": base64.b64encode(raw).decode()}
        self.assertEqual(audit.blob_bytes(sha, row), raw)
        for patch in ({"sha": "a" * 40}, {"size": True}, {"content": "AAAA"}, {"encoding": "utf-8"}):
            with self.assertRaises(ValueError):
                audit.blob_bytes(sha, {**row, **patch})

    def test_ast_normalizes_formatting_not_constants(self):
        a = audit.declarations(b"def f(x):\n    return x+1\n")[0]
        b = audit.declarations(b"# comment\ndef f(x):\n  return x + 1\n")[0]
        c = audit.declarations(b"def f(x):\n    return x+2\n")[0]
        self.assertEqual(a["ast_sha256"], b["ast_sha256"])
        self.assertNotEqual(a["ast_sha256"], c["ast_sha256"])

    def test_source_is_not_imported(self):
        nodes = audit.declarations(b"raise RuntimeError('never execute')\nclass C:\n def f(self): pass\n")
        self.assertEqual([n["qualified"] for n in nodes], ["C", "C.f"])

    def test_reviewed_witness_differential(self):
        a = audit.WITNESS_TEMPLATE.replace("ARG", "serial_bytes")
        b = audit.WITNESS_TEMPLATE.replace("ARG", "serial_log")
        report = audit.differential(a, b)
        self.assertEqual(report["passed"], 16)
        self.assertFalse(report["general_equivalence_verified"])

    def test_reject_changed_witness(self):
        a = audit.WITNESS_TEMPLATE.replace("ARG", "serial_bytes")
        for altered in (a.replace("return any", "return all"),
                        a.replace("    witnesses =", "    print('untrusted')\n    witnesses ="),
                        a + "\n" + a):
            with self.assertRaises(ValueError):
                audit.approved_witness(altered, "serial_bytes")

    def test_memory_hash_differential(self):
        raw = audit.HASH_TEMPLATE.encode()
        result = audit.hash_differential([raw, raw, raw])
        self.assertEqual(result["passed"], 9)
        self.assertEqual(result["function_evaluations"], 27)
        self.assertFalse(result["filesystem_access"])
        self.assertFalse(result["general_equivalence_verified"])

    def test_reject_changed_hash(self):
        raw = audit.HASH_TEMPLATE
        for changed in (raw.replace('"rb"', '"wb"'),
                        raw.replace('"sha256"', '"sha1"'),
                        raw.replace("return hashlib", "print('untrusted')\n        return hashlib"),
                        raw + "\n" + raw):
            with self.assertRaises(ValueError):
                audit.approved_hash(changed.encode())

    def test_fixed_manifest(self):
        rows = audit.manifest()
        self.assertEqual(sum(x["group"] == "dev" for x in rows), 202)
        self.assertTrue(all(x["path"].endswith(".py") for x in rows))


if __name__ == "__main__":
    unittest.main()
