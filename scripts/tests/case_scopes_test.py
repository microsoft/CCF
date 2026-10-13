#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "check-case-scopes.py"
SPEC = importlib.util.spec_from_file_location("check_case_scopes", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CaseScopesFixture(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="case scopes ")
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "checkout"
        self.build = self.root / "build"
        self.build.mkdir(parents=True)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def entry(self, name, *flags):
        return {
            "directory": str(self.root),
            "file": name,
            "arguments": ["clang++", "-std=c++20", *flags, "-c", name],
        }

    def database(self, entries):
        self.write("build/compile_commands.json", json.dumps(entries))

    def run_main(self, *args):
        output = io.StringIO()
        with mock.patch.object(
            CHECKER, "ROOT_DIR", self.root
        ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = CHECKER.main(["-p", str(self.build), *args])
        return status, output.getvalue()


class CaseScopesTest(CaseScopesFixture):
    def test_source_selection(self):
        names = [
            "src/one.cpp",
            "samples/two.cc",
            "src/three.C",
            "src/c_file.c",
            "3rdparty/vendor.cpp",
            "build/generated.cpp",
            "../outside.cpp",
        ]
        for name in names:
            self.write(name, "")
        entries = [self.entry(name) for name in names]
        entries.append(self.entry("src/one.cpp", "-DVARIANT"))
        entries.append(self.entry(str(self.root / "src/one.cpp")))
        self.database(entries)
        self.assertEqual(
            CHECKER.compilation_sources(self.build, self.root),
            sorted(self.root / name for name in names[:3]),
        )

    def test_invalid_or_empty_databases_fail(self):
        for contents in ["invalid JSON", "{}", "[]", "[{}]", '[{"file": 3}]']:
            with self.subTest(contents=contents):
                self.write("build/compile_commands.json", contents)
                status, output = self.run_main()
                self.assertEqual(status, 1)
                self.assertIn("Case scope check failed:", output)

    def test_missing_database_and_source_fail(self):
        status, output = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("compile_commands.json", output)
        self.database([self.entry("src/missing.cpp")])
        status, output = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("source is missing", output)

    def test_bad_explicit_source_or_tool_fails(self):
        source = self.write("src/example.cpp", "")
        self.database([self.entry("src/example.cpp")])
        status, output = self.run_main(str(self.root / "unknown.cpp"))
        self.assertEqual(status, 1)
        self.assertIn("Not first-party C++", output)
        status, output = self.run_main(
            "--clang-query", str(self.root / "missing-tool"), str(source)
        )
        self.assertEqual(status, 1)
        self.assertIn("Cannot find", output)

    def test_wrapper_fails_closed(self):
        source = self.write("src/example.cpp", "")
        self.database([self.entry("src/example.cpp")])
        for text, code, expected in [
            ("0 matches.\n", 0, 0),
            ("1 match.\n", 0, 1),
            ("2 matches.\n", 0, 1),
            ("", 0, 1),
            ("0 matches.\n0 matches.\n", 0, 1),
            ("parse error\n0 matches.\n", 1, 1),
            ("source.cpp:1:1: error: invalid source\n0 matches.\n", 0, 1),
            ("source.cpp:1:1: fatal error: missing header\n0 matches.\n", 0, 1),
            ("error: unknown argument\n0 matches.\n", 0, 1),
        ]:
            with self.subTest(text=text, code=code), mock.patch.object(
                CHECKER, "find_clang_query", return_value="clang-query"
            ), mock.patch.object(
                CHECKER.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], code, text),
            ) as run:
                status, output = self.run_main(str(source))
                self.assertEqual(status, expected, output)
                self.assertIn(str(source), run.call_args.args[0])
                self.assertIn(text, output)
        with mock.patch.object(
            CHECKER, "find_clang_query", return_value="clang-query"
        ), mock.patch.object(
            CHECKER.subprocess, "run", side_effect=OSError("cannot start")
        ):
            status, output = self.run_main()
            self.assertEqual(status, 1)
            self.assertIn("cannot start", output)


class ClangQueryCaseScopesTest(CaseScopesFixture):
    @classmethod
    def setUpClass(cls):
        # Missing tools are failures, not skipped enforcement coverage.
        cls.executable = CHECKER.find_clang_query(os.environ.get("CLANG_QUERY"))

    def check_body(self, body, expected):
        source = self.write(
            "src/example.cpp",
            "void consume(int);\n"
            "int acquire();\n"
            "struct Pair { int a; int b; };\n"
            "#define DECLARE_VALUE int value = 1\n"
            "void example(int n) {\n" + body + "\n}\n",
        )
        self.database([self.entry("src/example.cpp")])
        status, output = self.run_main("--clang-query", self.executable)
        self.assertEqual(status, int(expected != 0), output)
        self.assertEqual(
            len(re.findall(r'"case_variable" binds here', output)), expected, output
        )
        self.assertIn(f"{expected} match", output)
        return source

    def test_unscoped_declarations(self):
        bodies = {
            "direct": "case 0: int value = 1; consume(value);",
            "later": "case 0: consume(n); int value = 1; consume(value);",
            "stacked": "case 0: case 1: int value = 1; consume(value);",
            "default": "case 0: break; default: int value = 1; consume(value);",
            "named labels": "case 0: first: second: int value = 1; consume(value);",
            "after block": "case 0: { consume(n); } int value = 1; consume(value);",
            "multiple": "case 0: int a = 1, b = 2; consume(a + b);",
            "structured binding": "case 0: auto [a, b] = Pair{1, 2}; consume(a + b);",
            "reference": "case 0: int& value = n; consume(value);",
            "static": "case 0: static int value = 1; consume(value);",
            "uninitialized": "case 0: int value; value = 1; consume(value); break; case 1: break;",
            "macro": "case 0: DECLARE_VALUE; consume(value);",
            "nested switch": "case 0: { switch (n) { case 0: int value = 1; consume(value); } }",
        }
        for name, body in bodies.items():
            with self.subTest(name=name):
                self.check_body("switch (n) { " + body + " }", 1)
        for wrapper in ["body:", "[[likely]]"]:
            with self.subTest(wrapper=wrapper):
                self.check_body(
                    f"switch (n) {wrapper} {{ "
                    "case 0: consume(n); int value = 1; consume(value); }",
                    1,
                )

    def test_nested_scopes_are_allowed(self):
        bodies = [
            "case 0: { int value = 1; consume(value); }",
            "case 0: case 1: { int value = 1; consume(value); }",
            "default: { int value = 1; consume(value); }",
            "case 0: if (n == 0) { int value = 1; consume(value); }",
            "case 0: if (int value = acquire(); value > 0) { consume(value); }",
            "case 0: for (int value = 0; value < n; ++value) { consume(value); }",
            "case 0: while (int value = acquire()) { consume(value); }",
            "case 0: consume([] { int value = 1; return value; }());",
            "case 0: { label: int value = 1; consume(value); }",
            "case 0: int provided(int); consume(provided(n));",
            "case 0: using Value = int; typedef int Other;",
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.check_body("switch (n) { " + body + " }", 0)
        self.check_body(
            "switch ([] { int value = 0; return value; }()) { case 0: break; }", 0
        )
        self.check_body(
            "int values[] = {1, 2}; "
            "switch (n) { case 0: for (int value : values) { consume(value); } }",
            0,
        )
        self.check_body(
            "switch (int value = n; value) { case 0: consume(value); break; }", 0
        )

    def test_headers_and_expansion_locations(self):
        header = "inline void example(int n) { switch(n) { case 0: int value = n; } }\n"
        for path, flags, expected in [
            ("include/example.h", [], 1),
            ("include/3rdparty/example.h", [], 0),
            ("system/example.h", ["-isystem", str(self.root / "system")], 0),
        ]:
            with self.subTest(path=path):
                self.write(path, header)
                self.write("src/example.cpp", f'#include "{Path(path).name}"\n')
                self.database(
                    [
                        self.entry(
                            "src/example.cpp",
                            *flags,
                            "-I",
                            str((self.root / path).parent),
                        )
                    ]
                )
                status, output = self.run_main("--clang-query", self.executable)
                self.assertEqual(status, int(expected != 0), output)
                self.assertIn(f"{expected} match", output)
        self.write("3rdparty/macro.h", "#define DECLARE_VALUE int value = 1\n")
        self.write(
            "src/example.cpp",
            '#include "../3rdparty/macro.h"\n'
            "void example(int n) { switch(n) { case 0: DECLARE_VALUE; } }\n",
        )
        self.database([self.entry("src/example.cpp")])
        status, output = self.run_main("--clang-query", self.executable)
        self.assertEqual(status, 1, output)
        self.assertIn("1 match.", output)

    def test_all_compile_variants_are_checked(self):
        self.write(
            "src/example.cpp",
            "void example(int n) { switch(n) { case 0:\n"
            "#ifdef VARIANT\n"
            "int value = 1;\n"
            "#else\n"
            "int other = 2;\n"
            "#endif\n"
            "} }\n",
        )
        self.database(
            [self.entry("src/example.cpp"), self.entry("src/example.cpp", "-DVARIANT")]
        )
        status, output = self.run_main("--clang-query", self.executable)
        self.assertEqual(status, 1, output)
        self.assertIn("2 matches.", output)
        self.assertIn("[1/1]", output)

    def test_real_parse_and_query_errors_fail(self):
        source = self.write("src/example.cpp", "not valid C++")
        self.database([self.entry("src/example.cpp")])
        status, output = self.run_main("--clang-query", self.executable)
        self.assertEqual(status, 1)
        self.assertIn("compilation errors", output)
        source.write_text("void example() {}", encoding="utf-8")
        query = self.write("invalid.query", "match noSuchMatcher()\n")
        with mock.patch.object(CHECKER, "QUERY_FILE", query):
            status, output = self.run_main("--clang-query", self.executable)
        self.assertEqual(status, 1)
        self.assertIn("clang-query failed", output)


if __name__ == "__main__":
    unittest.main()
