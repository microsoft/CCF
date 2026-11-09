# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Regression checks for selective cache fetching and shared Lean dependencies."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class LeanSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = self.root / "scripts" / "lean-setup.sh"
        self.script.parent.mkdir()
        shutil.copyfile(
            Path(__file__).resolve().parents[1] / "scripts" / "lean-setup.sh",
            self.script,
        )
        self.packages = [
            "common",
            "kv",
            "consistency",
            "disaster-recovery",
            "consensus",
        ]
        for package in self.packages:
            (self.root / "lean" / package).mkdir(parents=True)
        self.common = self.root / "lean" / "common" / "CCF.lean"
        self.common.write_text("public import Mathlib.Data.Seq.Basic\n")
        self.capture = self.root / "capture"
        binary = self.root / "bin" / "lake"
        binary.parent.mkdir()
        binary.write_text(
            '#!/bin/bash\nset -euo pipefail\npwd > "$CAPTURE"\n'
            'printf "%s\\n" "$@" >> "$CAPTURE"\n'
            'exit "${FAKE_LAKE_STATUS:-0}"\n'
        )
        binary.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(binary.parent) + os.pathsep + os.environ["PATH"],
            "CAPTURE": str(self.capture),
        }

    def run_setup(self, *args, cwd=None, status=0):
        return subprocess.run(
            ["bash", str(self.script), *args],
            cwd=cwd or self.root,
            env={**self.env, "FAKE_LAKE_STATUS": str(status)},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_extracts_private_and_import_all_and_ignores_build_directories(self):
        directory = self.root / "lean" / "consensus"
        source = directory / "Proofs" / "Safety.lean"
        source.parent.mkdir()
        source.write_text(
            "import all Mathlib.Data.List.Sort\n"
            "private meta import Mathlib.Order.Basic -- support\n"
            "import Mathlib.Data.Seq.Basic\n"
            "import Std\n"
        )
        ignored = directory / ".lake" / "Ignored.lean"
        ignored.parent.mkdir()
        ignored.write_text("import Mathlib.NotNeeded\n")
        result = self.run_setup("consensus")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.capture.read_text().splitlines(),
            [
                str(directory),
                "exe",
                "cache",
                "get",
                "Mathlib.Data.List.Sort",
                "Mathlib.Data.Seq.Basic",
                "Mathlib.Order.Basic",
            ],
        )

    def test_all_packages_share_dependencies_and_setup_is_repeatable(self):
        for package in self.packages:
            with self.subTest(package=package):
                directory = self.root / "lean" / package
                for _ in range(2):
                    result = self.run_setup(cwd=directory)
                    self.assertEqual(result.returncode, 0, result.stderr)
                link = directory / ".lake" / "packages"
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.resolve(), self.root / "lean/.lake/packages")
                modules = self.capture.read_text().splitlines()[4:]
                expected = ["Mathlib.Data.Seq.Basic"]
                if package in {"kv", "disaster-recovery"}:
                    expected = [
                        "Batteries.Data.Array.Basic",
                        "Batteries.Tactic.Lint",
                        *expected,
                    ]
                self.assertEqual(modules, expected)

    def test_print_imports_does_not_fetch_or_create_directories(self):
        result = self.run_setup("--print-imports", "common")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Mathlib.Data.Seq.Basic\n")
        self.assertFalse(self.capture.exists())
        self.assertFalse((self.root / "lean/.lake").exists())
        self.assertFalse((self.root / "lean/common/.lake").exists())

    def test_print_imports_ignores_non_import_changes(self):
        before = self.run_setup("--print-imports", "common")
        self.common.write_text(
            "public import Mathlib.Data.Seq.Basic\n"
            "theorem example_claim : True := by trivial\n"
        )
        after = self.run_setup("--print-imports", "common")
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(before.stdout, after.stdout)

    def test_print_imports_changes_when_required_modules_change(self):
        before = self.run_setup("--print-imports", "common")
        self.common.write_text(
            "public import Mathlib.Data.Seq.Basic\n"
            "private import Mathlib.Tactic.SplitIfs\n"
        )
        after = self.run_setup("--print-imports", "common")
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertNotEqual(before.stdout, after.stdout)
        self.assertEqual(
            after.stdout.splitlines(),
            ["Mathlib.Data.Seq.Basic", "Mathlib.Tactic.SplitIfs"],
        )

    def test_preserves_existing_directory(self):
        directory = self.root / "lean" / "common" / ".lake" / "packages"
        directory.mkdir(parents=True)
        marker = directory / "keep"
        marker.write_text("existing dependency")
        result = self.run_setup("common")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Move the existing dependency directory aside", result.stderr)
        self.assertEqual(marker.read_text(), "existing dependency")
        self.assertFalse(directory.is_symlink())
        self.assertFalse(self.capture.exists())

    def test_rejects_symlink_to_another_directory(self):
        link = self.root / "lean" / "common" / ".lake" / "packages"
        link.parent.mkdir()
        link.symlink_to(self.root / "other")
        result = self.run_setup("common")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Dependency symlink points elsewhere", result.stderr)
        self.assertEqual(link.readlink(), self.root / "other")
        self.assertFalse(self.capture.exists())

    def test_rejects_empty_import_set_without_fetching_all_mathlib(self):
        self.common.write_text("import Std\n")
        result = self.run_setup("common")
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing a full cache fetch", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_rejects_invalid_package_and_extra_arguments(self):
        for args in [("unknown",), ("common", "extra")]:
            with self.subTest(args=args):
                result = self.run_setup(*args)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(result.stderr)
                self.assertFalse(self.capture.exists())

    def test_propagates_lake_failure(self):
        result = self.run_setup("common", status=7)
        self.assertEqual(result.returncode, 7)


if __name__ == "__main__":
    unittest.main()
