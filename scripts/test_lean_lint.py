# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Regression tests for repository-wide Lean source discovery and coverage."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lean_lint


class LeanLintTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ccf-lean-lint-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.lean = self.root / "lean"
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("lean/.gitignore", ".lake/\n")
        self.write("lean/lakefile.toml", 'name = "lint"\n')
        self.write("lean/lean-toolchain", "leanprover/lean4:v4.34.0\n")

    def write(self, path, content=""):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
        return file

    def test_discovers_tracked_and_new_packages_but_not_dependencies(self):
        tracked = self.write("lean/First/Main.lean")
        subprocess.run(["git", "-C", str(self.root), "add", str(tracked)], check=True)
        new = self.write("lean/NewPackage/Unimported.lean")
        nested = self.write("lean/First/replayer/Main.lean")
        self.write("lean/First/.lake/packages/dependency/Unrelated.lean")
        self.write("outside.lean")
        self.assertEqual(
            lean_lint.source_files(self.root), sorted([tracked, new, nested])
        )

    def test_empty_source_set_fails(self):
        with self.assertRaisesRegex(RuntimeError, "No Lean sources"):
            lean_lint.source_files(self.root)

    def test_external_source_symlink_fails(self):
        outside = self.root.parent / f"{self.root.name}-outside.lean"
        outside.write_text("")
        self.addCleanup(outside.unlink)
        (self.lean / "External.lean").symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "outside the repository"):
            lean_lint.source_files(self.root)

    def test_resolves_each_nearest_package(self):
        self.write("lean/First/lakefile.toml")
        self.write("lean/First/replayer/lakefile.lean")
        files = {
            "lean/SourceLint.lean": "lean",
            "lean/First/Library/Nested.lean": "lean/First",
            "lean/First/replayer/Main.lean": "lean/First/replayer",
        }
        for file, package in files.items():
            with self.subTest(file=file):
                self.assertEqual(
                    lean_lint.package_for(self.write(file), self.lean),
                    self.root / package,
                )

    def test_rejects_sources_outside_lean(self):
        with self.assertRaisesRegex(RuntimeError, "No Lake package"):
            lean_lint.package_for(self.write("Outside.lean"), self.lean)

    def test_inherits_toolchain_and_detects_overrides(self):
        package = self.lean / "First" / "replayer"
        self.assertEqual(
            lean_lint.toolchain_for(package, self.lean), "leanprover/lean4:v4.34.0"
        )
        self.write("lean/First/lean-toolchain", "leanprover/lean4:v4.33.0\n")
        self.assertEqual(
            lean_lint.toolchain_for(package, self.lean), "leanprover/lean4:v4.33.0"
        )

    def test_toolchain_mismatch_fails_before_building(self):
        self.write("lean/NewPackage/lakefile.toml")
        self.write("lean/NewPackage/lean-toolchain", "leanprover/lean4:v4.33.0\n")
        file = self.write("lean/NewPackage/Main.lean")
        with (
            patch.object(lean_lint, "ROOT", self.root),
            patch.object(lean_lint, "LEAN_ROOT", self.lean),
            patch.object(lean_lint, "source_files", return_value=[file]),
            patch.object(lean_lint.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                lean_lint.main()
            run.assert_not_called()

    def test_lints_every_source_even_after_a_failure(self):
        files = [
            self.write("lean/First/Main.lean"),
            self.write("lean/Second/Unimported.lean"),
        ]
        self.write("lean/First/lakefile.toml")
        self.write("lean/Second/lakefile.toml")
        linted = []
        setups = []

        def run(command, **kwargs):
            if command[1] == "setup-file":
                setups.append((Path(command[2]), kwargs["cwd"]))
            elif command[:2] == ["lean", "--run"]:
                linted.append(Path(command[3]))
                return SimpleNamespace(returncode=int(len(linted) == 1))
            return SimpleNamespace(returncode=0)

        with (
            patch.object(lean_lint, "ROOT", self.root),
            patch.object(lean_lint, "LEAN_ROOT", self.lean),
            patch.object(lean_lint, "source_files", return_value=files),
            patch.object(lean_lint.subprocess, "run", side_effect=run),
        ):
            with self.assertRaisesRegex(RuntimeError, "failed for 1 of 2 files"):
                lean_lint.main()
        self.assertEqual(linted, files)
        self.assertEqual(setups, [(file, file.parent) for file in files])

    def test_driver_crash_is_not_reported_as_a_style_finding(self):
        file = self.write("lean/Main.lean")

        def run(command, **kwargs):
            if command[:2] == ["lean", "--run"]:
                return SimpleNamespace(returncode=-11)
            return SimpleNamespace(returncode=0)

        with (
            patch.object(lean_lint, "ROOT", self.root),
            patch.object(lean_lint, "LEAN_ROOT", self.lean),
            patch.object(lean_lint, "source_files", return_value=[file]),
            patch.object(lean_lint.subprocess, "run", side_effect=run),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "driver failed with exit code -11"
            ):
                lean_lint.main()


class LeanSourceLintTests(unittest.TestCase):
    """Exercise the pinned linters on files outside a package's default targets."""

    def test_source_checks_in_an_unimported_dependency_free_module(self):
        driver = lean_lint.LEAN_ROOT / "SourceLint.lean"
        env = os.environ.copy()
        env["ELAN_TOOLCHAIN"] = (
            (lean_lint.LEAN_ROOT / "lean-toolchain").read_text().strip()
        )
        env["LEAN_PATH"] = subprocess.check_output(
            ["lake", "env", "printenv", "LEAN_PATH"],
            cwd=lean_lint.LEAN_ROOT,
            text=True,
        ).strip()
        cases = {
            "valid": ("example : True := by\n  trivial\n", 0, ""),
            "empty-line": (
                "example : True := by\n\n  trivial\n",
                1,
                "linter.style.emptyLine",
            ),
            "lambda": (
                "def identity : Nat -> Nat := \u03bb n => n\n",
                1,
                "linter.style.lambdaSyntax",
            ),
            "flexible": (
                "example (n : Nat) (h : n + 0 = 1) : n = 1 := by\n"
                "  simp at h\n  exact h\n",
                1,
                "linter.flexible",
            ),
        }
        valid_body = "example : True := by\n  trivial\n"
        cases["standalone"] = (valid_body, 0, "")
        for width, code in ((100, 0), (101, 1)):
            cases[f"{width}-columns"] = (
                "-- " + "x" * (width - 3) + "\n" + valid_body,
                code,
                "linter.style.longLine" if code else "",
            )
        # Upstream counts the trailing empty line and rejects an EOF at line 1500.
        for length, code in ((1499, 0), (1500, 1), (1501, 1)):
            cases[f"{length}-lines"] = (
                "-- Padding.\n" * (length - 7) + valid_body,
                code,
                "linter.style.longFile" if code else "",
            )
        with tempfile.TemporaryDirectory(prefix="ccf-lean-compiler-test-") as temporary:
            directory = Path(temporary)
            (directory / "lakefile.toml").write_text(
                'name = "lint_probe"\n'
                'defaultTargets = ["NewPackage"]\n'
                '[[lean_lib]]\nname = "NewPackage"\n'
            )
            (directory / "NewPackage.lean").write_text("import Std\n")
            (directory / "NewPackage").mkdir()
            setup_path = directory / "setup.json"
            for name, (body, exit_code, diagnostic) in cases.items():
                with self.subTest(name=name):
                    if name == "standalone":
                        (directory / "lakefile.toml").write_text(
                            'name = "lint_probe"\n'
                        )
                        subprocess.run(
                            ["lake", "--allow-empty", "build", "--wfail"],
                            cwd=directory,
                            env=env,
                            check=True,
                        )
                    source = (
                        directory / "Standalone.lean"
                        if name == "standalone"
                        else directory / "NewPackage" / "Unimported.lean"
                    )
                    content = (
                        "import Std\n\n/-! Source linter regression fixture. -/\n\n"
                        + body
                    )
                    if name.endswith("-lines"):
                        self.assertEqual(
                            len(content.split("\n")), int(name.split("-")[0])
                        )
                    source.write_text(content)
                    setup_path.write_bytes(
                        subprocess.check_output(
                            ["lake", "setup-file", str(source)], cwd=directory, env=env
                        )
                    )
                    subprocess.run(
                        ["lean", "--run", str(driver), str(source), str(setup_path)],
                        cwd=directory,
                        env=env,
                        check=True,
                    )
                    setup = json.loads(setup_path.read_text())
                    self.assertEqual(
                        setup["name"],
                        (
                            "Standalone"
                            if name == "standalone"
                            else "NewPackage.Unimported"
                        ),
                    )
                    self.assertTrue(
                        any(
                            item["module"] == "Mathlib.Init"
                            for item in setup["imports"]
                        )
                    )
                    result = subprocess.run(
                        ["lean", f"--setup={setup_path}", str(source)],
                        cwd=directory,
                        env=env,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, exit_code, result.stdout + result.stderr
                    )
                    self.assertIn(diagnostic, result.stdout)
                    self.assertEqual(source.read_text(), content)
                    self.assertFalse(list(directory.rglob("*.olean")))


if __name__ == "__main__":
    unittest.main(buffer=True)
