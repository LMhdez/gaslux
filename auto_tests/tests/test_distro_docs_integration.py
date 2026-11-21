"""Static regression checks for extracted documentation; no installer execution."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "distro-backends"
BACKENDS = ("MINT", "ZORIN", "CACHYOS", "POPOS", "BAZZITE", "Q4OS")
FILES = ("README.md", "SHARED_CONTRACTS.md") + tuple(
    f"{name}.md" for name in BACKENDS
)
SOURCE_SHA = "9b434a6a2b96b7a02fded73eb2ef66753bddde5d"


def markdown_targets(content: str) -> list[str]:
    return re.findall(r"\]\(([^)]+)\)", content)


class DistroDossiersIntegrationTests(unittest.TestCase):
    def test_dossiers_and_provenance_exist(self):
        for name in FILES + ("INTEGRATION_PROVENANCE.md",):
            with self.subTest(name=name):
                self.assertTrue((DOCS / name).is_file())

    def test_markdown_parser_detects_broken_target(self):
        self.assertEqual(markdown_targets("[missing](nonexistent.md)"), ["nonexistent.md"])

    def test_relative_markdown_links_resolve(self):
        for name in FILES:
            document = DOCS / name
            content = document.read_text(encoding="utf-8")
            links = markdown_targets(content)
            self.assertTrue(links, f"Link coverage missing: {name}")
            for link in links:
                path = link.split("#", 1)[0]
                if not path or path.startswith(("https://", "http://", "mailto:")):
                    continue
                with self.subTest(document=name, link=link):
                    self.assertTrue((document.parent / path).is_file())

    def test_documented_only_never_writer_authority(self):
        for name in BACKENDS:
            with self.subTest(backend=name):
                content = (DOCS / f"{name}.md").read_text(encoding="utf-8")
                self.assertIn("Não usar este documento como autorização de escrita.", content)
        readme = (DOCS / "README.md").read_text(encoding="utf-8")
        self.assertIn("Nenhuma linha desta matriz autoriza escrita real.", readme)

    def test_q4os_external_evidence_uses_immutable_origin(self):
        content = (DOCS / "Q4OS.md").read_text(encoding="utf-8")
        self.assertIn(f"/blob/{SOURCE_SHA}/docs/distro-backends/boot-maps/q4os.md", content)
        self.assertIn(f"/blob/{SOURCE_SHA}/schemas/distro-ui-map.schema.json", content)
        self.assertIn("Não fazem parte desta extração documental", content)


if __name__ == "__main__":
    unittest.main()
