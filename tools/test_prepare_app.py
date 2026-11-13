import hashlib
import tempfile
from pathlib import Path
import unittest

from prepare_app import apply_edits, apply_recipe, checked_path


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


class RecipeTests(unittest.TestCase):
    def test_reverse_edits_and_wrong_input(self):
        record = {"path": "x", "before_sha256": digest("a\nb\nc\n"),
                  "after_sha256": digest("a\nB\nc\nd\n"),
                  "edits": [[3, 0, "d\n"], [1, 1, "B\n"]]}
        self.assertEqual(apply_edits("a\nb\nc\n", record), "a\nB\nc\nd\n")
        with self.assertRaisesRegex(ValueError, "Source mismatch"):
            apply_edits("wrong", record)
        record["after_sha256"] = digest("wrong result")
        with self.assertRaisesRegex(ValueError, "Result mismatch"):
            apply_edits("a\nb\nc\n", record)

    def test_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("../secret", "/secret", "C:/secret", "a\\..\\secret"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    checked_path(root, name)

    def test_relocation_pruning_and_additions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "app"
            root.mkdir()
            (root / "old").write_text("source\n")
            additions = Path(temporary) / "additions"
            additions.mkdir()
            (additions / "new").write_bytes(b"new\n")
            record = {"path": "moved", "source": "old", "before_sha256": digest("source\n"),
                      "after_sha256": digest("changed\n"), "edits": [[0, 1, "changed\n"]]}
            apply_recipe(root, {"keep": [], "changes": [record],
                                "additions": {"new": digest("new\n")}}, additions)
            self.assertFalse((root / "old").exists())
            self.assertEqual((root / "moved").read_bytes(), b"changed\n")
            self.assertEqual((root / "new").read_bytes(), b"new\n")


if __name__ == "__main__":
    unittest.main()
