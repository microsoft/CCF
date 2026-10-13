#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import contextlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "clang-tidier.py"
SPEC = importlib.util.spec_from_file_location("clang_tidier", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
TIDIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TIDIER)


class ClangTidierRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sources = [self.root / f"source_{index}.cpp" for index in range(6)]

    def invoke(
        self,
        arguments: list[str],
        check_source: Callable[[str, Path, Path], subprocess.CompletedProcess[str]],
    ) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(TIDIER, "ROOT_DIR", self.root),
            mock.patch.object(TIDIER, "compilation_sources", return_value=self.sources),
            mock.patch.object(TIDIER, "find_clang_query", return_value="clang-query"),
            mock.patch.object(TIDIER, "check_source", side_effect=check_source),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = TIDIER.main(["--all", *arguments])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_limits_concurrent_invocations_and_groups_output(self) -> None:
        lock = threading.Lock()
        barrier = threading.Barrier(2)
        active = 0
        maximum = 0
        started = []

        def check_source(executable, build_dir, source):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
                started.append(source)
            try:
                barrier.wait(timeout=5)
                return subprocess.CompletedProcess(
                    [executable],
                    0,
                    f"{source.name}: begin\n{source.name}: end\n0 matches.\n",
                )
            finally:
                with lock:
                    active -= 1

        status, stdout, stderr = self.invoke(["-j", "2"], check_source)
        self.assertEqual(status, 0, stderr)
        self.assertEqual(maximum, 2)
        self.assertCountEqual(started, self.sources)
        for source in self.sources:
            self.assertIn(f"{source.name}: begin\n{source.name}: end\n", stdout)
        self.assertIn("Case scopes checked in 6 C++ translation unit(s).", stdout)

    def test_one_job_preserves_serial_source_order(self) -> None:
        started = []

        def check_source(executable, build_dir, source):
            started.append(source)
            return subprocess.CompletedProcess([executable], 0, "0 matches.\n")

        status, _, stderr = self.invoke(["-j", "1"], check_source)
        self.assertEqual(status, 0, stderr)
        self.assertEqual(started, self.sources)

    def test_defaults_to_at_most_four_available_cpus(self) -> None:
        for cpus, expected in ((None, 1), (2, 2), (32, 4)):
            with (
                self.subTest(cpus=cpus),
                mock.patch.object(TIDIER.os, "cpu_count", return_value=cpus),
                mock.patch.object(
                    TIDIER, "ThreadPoolExecutor", wraps=ThreadPoolExecutor
                ) as executor,
            ):
                status, _, stderr = self.invoke(
                    [],
                    lambda executable, build_dir, source: subprocess.CompletedProcess(
                        [executable], 0, "0 matches.\n"
                    ),
                )
                self.assertEqual(status, 0, stderr)
                executor.assert_called_once_with(max_workers=expected)

    def test_stops_scheduling_after_a_failed_invocation(self) -> None:
        started = []
        barrier = threading.Barrier(2)

        def check_source(executable, build_dir, source):
            started.append(source)
            barrier.wait(timeout=5)
            return subprocess.CompletedProcess([executable], 1, "compiler failure\n")

        status, _, stderr = self.invoke(["-j", "2"], check_source)
        self.assertEqual(status, 1)
        self.assertIn("clang-query failed", stderr)
        self.assertEqual(len(started), 2)

    def test_sums_matches_from_all_workers(self) -> None:
        def check_source(executable, build_dir, source):
            count = self.sources.index(source)
            return subprocess.CompletedProcess([executable], 0, f"{count} matches.\n")

        status, stdout, stderr = self.invoke(["-j", "3"], check_source)
        self.assertEqual(status, 1)
        self.assertIn("15 non-empty case/default body match(es)", stderr)
        self.assertNotIn("Case scopes checked", stdout)

    def test_reports_nonzero_exit_and_keeps_diagnostics(self) -> None:
        def check_source(executable, build_dir, source):
            return subprocess.CompletedProcess(
                [executable], 7, "compiler failure details\n"
            )

        status, stdout, stderr = self.invoke(["-j", "2"], check_source)
        self.assertEqual(status, 1)
        self.assertIn("compiler failure details", stdout)
        self.assertIn("clang-query failed for", stderr)
        self.assertIn("(exit 7)", stderr)
        self.assertNotIn("Case scopes checked", stdout)

    def test_rejects_recovered_parse_errors_and_bad_summaries(self) -> None:
        for output, error in [
            (
                "source.cpp:1:1: error: invalid syntax\n0 matches.\n",
                "compilation errors",
            ),
            ("fatal error: invalid syntax\n0 matches.\n", "compilation errors"),
            ("no summary\n", "exactly one"),
            ("0 matches.\n0 matches.\n", "exactly one"),
        ]:
            with self.subTest(output=output):
                status, stdout, stderr = self.invoke(
                    ["-j", "2"],
                    lambda executable, build_dir, source: subprocess.CompletedProcess(
                        [executable], 0, output
                    ),
                )
                self.assertEqual(status, 1)
                self.assertIn(output, stdout)
                self.assertIn(error, stderr)
                self.assertNotIn("Case scopes checked", stdout)

    def test_reports_worker_os_errors(self) -> None:
        def check_source(executable, build_dir, source):
            raise OSError("could not start clang-query")

        status, stdout, stderr = self.invoke(["-j", "2"], check_source)
        self.assertEqual(status, 1)
        self.assertIn("could not start clang-query", stderr)
        self.assertNotIn("Case scopes checked", stdout)

    def test_rejects_nonpositive_worker_counts(self) -> None:
        for value in ("0", "-1"):
            with self.subTest(value=value):
                stderr = io.StringIO()
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as error,
                ):
                    TIDIER.main(["-j", value])
                self.assertEqual(error.exception.code, 2)
                self.assertIn("--jobs must be positive", stderr.getvalue())


class ClangTidierSelectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sources = [self.root / f"source_{index}.cpp" for index in range(3)]
        for source in self.sources:
            source.write_text("void source() {}\n")
        (self.root / "shared.h").write_text("#pragma once\n")
        (self.root / ".gitignore").write_text("build/\n")
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Test baseline")
        self.write_database()

    def git(self, *arguments: str) -> None:
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=Clang tidier tests",
                "-c",
                "user.email=clang-tidier@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *arguments,
            ],
            check=True,
            capture_output=True,
        )

    def write_database(self, variants: tuple[int, ...] = (0,)) -> None:
        self.build_dir = self.root / "build"
        self.build_dir.mkdir(exist_ok=True)
        (self.build_dir / "compile_commands.json").write_text(
            json.dumps(
                [
                    {
                        "directory": str(self.root),
                        "file": str(source),
                        "arguments": [
                            "clang++",
                            f"-DCASE_VARIANT={variant}",
                            "-c",
                            str(source),
                        ],
                    }
                    for source in self.sources
                    for variant in variants
                ]
            )
        )

    def invoke(
        self, arguments: list[str] | None = None
    ) -> tuple[int, str, str, list[Path]]:
        started = []

        def check_source(executable, build_dir, source):
            started.append(source)
            self.assertEqual(build_dir, self.build_dir)
            return subprocess.CompletedProcess([executable], 0, "0 matches.\n")

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(TIDIER, "ROOT_DIR", self.root),
            mock.patch.object(TIDIER, "find_clang_query", return_value="clang-query"),
            mock.patch.object(TIDIER, "check_source", side_effect=check_source),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = TIDIER.main(
                ["-p", str(self.build_dir), "-j", "2", *(arguments or [])]
            )
        return status, stdout.getvalue(), stderr.getvalue(), started

    def test_selects_staged_unstaged_and_untracked_sources(self) -> None:
        for source in self.sources[:2]:
            source.write_text("void changed() {}\n")
        self.git("add", str(self.sources[0]))
        new = self.root / "new source_\u00e9\n.cpp"
        new.write_text("void added() {}\n")
        self.sources.append(new)
        self.write_database()

        status, _, stderr, started = self.invoke()
        self.assertEqual(status, 0, stderr)
        self.assertCountEqual(started, [*self.sources[:2], new])

    def test_clean_or_documentation_only_changes_are_explicit_noops(self) -> None:
        for documentation in (False, True):
            with self.subTest(documentation=documentation):
                if documentation:
                    (self.root / "README.md").write_text("Documentation change.\n")
                status, stdout, stderr, started = self.invoke()
                self.assertEqual(status, 0, stderr)
                self.assertEqual(started, [])
                self.assertIn("No modified first-party C++ sources", stdout)
                self.assertIn("Use --all", stdout)
                self.assertNotIn("Case scopes checked", stdout)

    def test_shared_inputs_and_configuration_trigger_full_scans(self) -> None:
        for filename in (
            "new.h",
            "new.hpp",
            "new.h.in",
            "helper.c",
            "src/no_get_ledger_sign_mode.cpp",
            "CMakeLists.txt",
            "CMakePresets.json",
            "cmake/options.cmake",
            "scripts/clang-tidier.py",
            "scripts/case-scopes.query",
            "3rdparty/vendor/definitions.txt",
        ):
            with self.subTest(filename=filename):
                path = self.root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Changed shared input.\n")
                try:
                    status, stdout, stderr, started = self.invoke()
                    self.assertEqual(status, 0, stderr)
                    self.assertCountEqual(started, self.sources)
                    self.assertIn("checking all sources", stdout)
                finally:
                    path.unlink()

    def test_staged_header_deletions_trigger_full_scans(self) -> None:
        self.git("rm", "shared.h")
        status, stdout, stderr, started = self.invoke()
        self.assertEqual(status, 0, stderr)
        self.assertCountEqual(started, self.sources)
        self.assertIn("checking all sources", stdout)

    def test_explicit_sources_and_all_bypass_git_selection(self) -> None:
        for arguments, expected in (
            (["--all"], self.sources),
            ([str(self.sources[1])], [self.sources[1]]),
        ):
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(
                    TIDIER, "modified_sources", side_effect=AssertionError("Used Git")
                ),
            ):
                status, _, stderr, started = self.invoke(arguments)
                self.assertEqual(status, 0, stderr)
                self.assertCountEqual(started, expected)

    def test_missing_git_falls_back_to_full_scan(self) -> None:
        with mock.patch.object(TIDIER.shutil, "which", return_value=None):
            status, stdout, stderr, started = self.invoke()
        self.assertEqual(status, 0, stderr)
        self.assertCountEqual(started, self.sources)
        self.assertIn("Git worktree unavailable", stdout)

    def test_export_without_git_metadata_falls_back_to_full_scan(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            sources = TIDIER.modified_sources(self.root / "export", self.sources)
        self.assertEqual(sources, self.sources)
        self.assertIn("Git worktree unavailable", stdout.getvalue())

    def test_git_errors_fail_instead_of_skipping_checks(self) -> None:
        for successful_commands in (0, 1):
            with (
                self.subTest(successful_commands=successful_commands),
                mock.patch.object(
                    TIDIER.subprocess,
                    "run",
                    side_effect=[
                        *[
                            subprocess.CompletedProcess(["git"], 0, b"", b"")
                            for _ in range(successful_commands)
                        ],
                        subprocess.CompletedProcess(
                            ["git"], 128, b"", b"fatal: Git failed\n"
                        ),
                    ],
                ),
            ):
                status, stdout, stderr, started = self.invoke()
                self.assertEqual(status, 1)
                self.assertEqual(started, [])
                self.assertIn("Cannot list modified files with Git (exit 128)", stderr)
                self.assertIn("fatal: Git failed", stderr)
                self.assertNotIn("No modified", stdout)

    def test_linked_git_worktrees_select_modified_sources(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.git("worktree", "add", "--quiet", "--detach", str(root))
        self.sources = [root / source.relative_to(self.root) for source in self.sources]
        self.root = root
        self.assertTrue((self.root / ".git").is_file())
        self.write_database()
        self.sources[0].write_text("void changed() {}\n")

        status, _, stderr, started = self.invoke()
        self.assertEqual(status, 0, stderr)
        self.assertEqual(started, [self.sources[0]])

    def test_incremental_scan_checks_variants_and_all_bypasses_filter(self) -> None:
        self.sources[1].write_text(
            "void existing(int value) { switch (value) { case 0: return; } }\n"
        )
        self.git("add", str(self.sources[1]))
        self.git("commit", "--quiet", "-m", "Existing violation fixture")
        self.sources[0].write_text("""
void modified(int value)
{
  switch (value)
  {
    case 0:
#if CASE_VARIANT
      return;
#else
      { return; }
#endif
    default: { return; }
  }
}
""")
        self.write_database(variants=(0, 1))
        for arguments, matches, checked_sources in (([], 1, 1), (["--all"], 3, 3)):
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(TIDIER, "ROOT_DIR", self.root),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                status = TIDIER.main(["-p", str(self.build_dir), *arguments])
                self.assertEqual(status, 1)
                self.assertIn(
                    f"{matches} non-empty case/default body match(es)",
                    stderr.getvalue(),
                )
                self.assertEqual(
                    len(re.findall(r"(?m)^\[\d+/\d+\] ", stdout.getvalue())),
                    checked_sources,
                )

    def test_empty_database_still_fails_on_a_clean_worktree(self) -> None:
        (self.build_dir / "compile_commands.json").write_text("[]")
        status, stdout, stderr, started = self.invoke()
        self.assertEqual(status, 1)
        self.assertEqual(started, [])
        self.assertIn("No first-party C++ translation units", stderr)
        self.assertNotIn("No modified", stdout)

    def test_rejects_all_with_explicit_sources(self) -> None:
        with self.assertRaises(SystemExit) as error:
            self.invoke(["--all", str(self.sources[0])])
        self.assertEqual(error.exception.code, 2)


class ClangTidierQueryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.executable = TIDIER.find_clang_query(os.environ.get("CLANG_QUERY"))

    def query(
        self, sources: dict[str, str], variants: tuple[int, ...] = (0,)
    ) -> tuple[int, str]:
        entries = []
        paths = []
        for filename, content in sources.items():
            path = self.root / filename
            path.write_text(content)
            paths.append(str(path))
            for variant in variants:
                entries.append(
                    {
                        "directory": str(self.root),
                        "file": str(path),
                        "arguments": [
                            "clang++",
                            "-std=c++23",
                            f"-DCASE_VARIANT={variant}",
                            "-isystem",
                            str(self.root / "system"),
                            "-c",
                            str(path),
                        ],
                    }
                )
        (self.root / "compile_commands.json").write_text(json.dumps(entries))
        result = subprocess.run(
            [
                self.executable,
                "--use-color=false",
                "-p",
                str(self.root),
                "-f",
                str(TIDIER.QUERY_FILE),
                *paths,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotRegex(result.stderr, r"(?:fatal )?error:")
        counts = re.findall(r"(?m)^(\d+) match(?:es)?\.$", result.stdout)
        self.assertEqual(len(counts), 1, result.stdout)
        return int(counts[0]), result.stdout

    def test_accepts_braced_stacked_labelled_and_attributed_bodies(self) -> None:
        count, output = self.query({"valid.cpp": """
#define CASE_BLOCK { return; }
void valid(int value)
{
  switch (value)
  {
    case 0:
    case 1: { return; }
    case 2: label: { return; }
    case 3: [[likely]] { return; }
    case 4: another_label: [[likely]] { return; }
    case 5: CASE_BLOCK
    default: { return; }
  }
}
void stacked_default(int value)
{
  switch (value) { default: case 0: { return; } }
}
"""})
        self.assertEqual(count, 0, output)

    def test_rejects_every_nonempty_unbraced_body(self) -> None:
        bodies = [
            "return;",
            "break;",
            "int local = value; (void)local; break;",
            "auto [first, second] = items; (void)first; (void)second; break;",
            "++value; break;",
            "if (value) { return; } break;",
            "for (int index = 0; index < value; ++index) { } break;",
            "while (value) { --value; } break;",
            "do { --value; } while (value); break;",
            "for (int item : items) { (void)item; } break;",
            "[] { }(); break;",
            "switch (value) { default: { break; } } break;",
            "try { ++value; } catch (...) { --value; } break;",
            "label: return;",
            "[[likely]] if (value) { return; } break;",
            ";",
            "case 1: return;",
        ]
        functions = [f"""
void invalid_{index}(int value)
{{
  int items[2] = {{}};
  switch (value) {{ default: {{ break; }} case 0: {body} }}
}}
""" for index, body in enumerate(bodies)]
        count, output = self.query({"invalid.cpp": "\n".join(functions)})
        self.assertEqual(count, len(bodies), output)

    def test_checks_all_compile_variants(self) -> None:
        count, output = self.query(
            {"variants.cpp": """
void variant(int value)
{
  switch (value)
  {
    case 0:
#if CASE_VARIANT
      return;
#else
      { return; }
#endif
    default: { return; }
  }
}
"""},
            variants=(0, 1),
        )
        self.assertEqual(count, 1, output)

    def test_excludes_vendored_and_system_headers_but_checks_shared_headers(
        self,
    ) -> None:
        for directory in ("3rdparty", "system", "shared"):
            path = self.root / directory
            path.mkdir()
            (path / "cases.h").write_text(
                f"inline void excluded_{directory}_case(int value) "
                "{ switch (value) { case 0: return; default: { return; } } }\n"
            )
        count, output = self.query(
            {
                "headers.cpp": (
                    '#include "3rdparty/cases.h"\n'
                    '#include "shared/cases.h"\n'
                    "#include <cases.h>\n"
                )
            }
        )
        self.assertEqual(count, 1, output)
        self.assertIn("shared/cases.h", output)

    def test_multiple_files_have_one_combined_summary(self) -> None:
        count, output = self.query(
            {
                "first.cpp": "void first(int v) { switch (v) { case 0: return; } }",
                "second.cpp": "void second(int v) { switch (v) { case 0: break; } }",
            }
        )
        self.assertEqual(count, 2, output)


if __name__ == "__main__":
    unittest.main()
