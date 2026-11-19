"""Fail-closed contracts for archive-only Git history preservation.

These tests never contact GitHub, alter refs or modify disks.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

PATH = Path(__file__).resolve().parent / "tools/gaslux_branch_prune.py"
spec = importlib.util.spec_from_file_location("gaslux_branch_maintenance", PATH)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ArchiveSafetyTests(TestCase):
    def setUp(self):
        self.refs = {
            "main": "a" * 40, "dev": "b" * 40,
            mod.CONTROL: "c" * 40, mod.ARCHIVE: "d" * 40,
            "feature/old-independent": "e" * 40,
            "test/recent": "f" * 40,
            "fix/protected": "1" * 40,
        }
        self.protect = {"main", "dev", mod.CONTROL, mod.ARCHIVE,
                        "fix/protected"}
        self.keep = {"main", "dev", mod.ARCHIVE}

    def _git(self, *args, **kwargs):
        if args[0] == "show" and ":docs/" in args[1]:
            return SimpleNamespace(returncode=0,
                                   stdout="não integra código no instalador")
        if args[:3] == ("show", "-s", "--format=%ct"):
            return SimpleNamespace(returncode=0,
                                   stdout="190000" if args[-1] == "f" * 40
                                   else "100")
        raise AssertionError("unexpected external operation")

    def test_old_own_history_only_and_active_or_recent_excluded(self):
        with patch.object(mod, "git", side_effect=self._git), \
             patch.object(mod, "is_ancestor", return_value=False), \
             patch.object(mod.time, "time", return_value=200000):
            selected = mod.archive_candidates(self.refs, self.protect, self.keep)
        self.assertEqual([x["branch"] for x in selected],
                         ["feature/old-independent"])

    def test_kept_history_not_rearchived(self):
        with patch.object(mod, "git", side_effect=self._git), \
             patch.object(mod, "is_ancestor", return_value=True), \
             patch.object(mod.time, "time", return_value=200000):
            self.assertEqual(mod.archive_candidates(
                self.refs, self.protect, self.keep), [])

    def test_marker_required_before_archive(self):
        def bad_marker(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="wrong archive")
        with patch.object(mod, "git", side_effect=bad_marker):
            with self.assertRaisesRegex(RuntimeError, "archive marker"):
                mod.archive_candidates(self.refs, self.protect, self.keep)

    def test_never_authorize_unreviewed_archive_mutation(self):
        with patch.dict(mod.os.environ, {"GASLUX_ARCHIVE_APPROVED": "NO"}):
            with self.assertRaisesRegex(RuntimeError, "authorization"):
                mod.archive_history_and_delete({}, [], self.refs)

    def test_main_dev_and_control_cannot_be_archive_candidates(self):
        refs = dict(self.refs)
        refs["feature/new-non-pr"] = "2" * 40
        with patch.object(mod, "git", side_effect=self._git), \
             patch.object(mod, "is_ancestor", return_value=False), \
             patch.object(mod.time, "time", return_value=200000):
            selected = mod.archive_candidates(refs, self.protect, self.keep)
        self.assertNotIn("main", {x["branch"] for x in selected})
        self.assertNotIn("dev", {x["branch"] for x in selected})
        self.assertNotIn(mod.CONTROL, {x["branch"] for x in selected})
        self.assertNotIn(mod.ARCHIVE, {x["branch"] for x in selected})


if __name__ == "__main__":
    main()
