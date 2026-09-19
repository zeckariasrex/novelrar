#!/usr/bin/env python3
"""Security-focused tests for the extraction CLI."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import novelrar_cli  # noqa: E402


class SafeMemberPathTests(unittest.TestCase):

    def test_accepts_normal_relative_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            self.assertEqual(
                novelrar_cli._safe_member_path(dest, "chapter/one.txt"),
                dest / "chapter" / "one.txt",
            )

    def test_rejects_parent_and_absolute_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            self.assertIsNone(novelrar_cli._safe_member_path(dest, "../escape"))
            self.assertIsNone(novelrar_cli._safe_member_path(dest, "/escape"))
            self.assertIsNone(novelrar_cli._safe_member_path(dest, ""))

    def test_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dest = base / "out"
            outside = base / "outside"
            dest.mkdir()
            outside.mkdir()
            try:
                (dest / "link").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            self.assertIsNone(
                novelrar_cli._safe_member_path(dest, "link/escaped.txt")
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
