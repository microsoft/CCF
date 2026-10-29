#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "vendor-glaze.py"
SPEC = importlib.util.spec_from_file_location("vendor_glaze", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
VENDOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VENDOR)


class VendorGlazeTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ccf-vendor-glaze-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source" / "include"
        self.output = self.root / "exported" / "glaze"
        for entry in VENDOR.ENTRY_POINTS:
            self.write_source(entry, b"#pragma once\n")

    def write_source(self, relative: str, content: bytes) -> None:
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def snapshot(self) -> dict[str, tuple[bytes, int]]:
        return {
            path.relative_to(self.output).as_posix(): (
                path.read_bytes(),
                path.stat().st_mtime_ns,
            )
            for path in self.output.rglob("*")
            if path.is_file()
        }

    def vendor(self, check: bool = False) -> int:
        with redirect_stdout(io.StringIO()):
            return VENDOR.vendor(self.source, self.output, check)

    def test_transitive_closure_is_sorted_and_byte_identical(self) -> None:
        self.write_source(
            "glaze/json/read.hpp",
            b'#include "glaze/core/a.hpp"\r\n#include <vector>\r\n',
        )
        self.write_source("glaze/core/a.hpp", b"#include <glaze/core/b.hpp>\n")
        self.write_source("glaze/core/b.hpp", b'#include "glaze/core/a.hpp"\n')
        self.write_source("glaze/unused.hpp", b"not reachable\n")
        expected = {
            Path(entry).relative_to("glaze") for entry in VENDOR.ENTRY_POINTS
        } | {Path("core/a.hpp"), Path("core/b.hpp")}
        headers = VENDOR.collect_headers(self.source)
        self.assertEqual(list(headers), sorted(expected))
        self.assertEqual(self.vendor(), 0)
        self.assertEqual(set(self.snapshot()), {path.as_posix() for path in expected})
        for relative in expected:
            self.assertEqual(
                (self.output / relative).read_bytes(),
                (self.source / "glaze" / relative).read_bytes(),
            )
        self.assertEqual(self.vendor(check=True), 0)

    def test_relative_includes_and_all_conditional_branches(self) -> None:
        self.write_source(
            "glaze/json/read.hpp",
            b"""
#if 0
#include "../core/inactive.hpp"
#else
#include "active.hpp"
#endif
#ifdef ANOTHER_PLATFORM
#include <glaze/core/platform.hpp>
#endif
""",
        )
        self.write_source("glaze/core/inactive.hpp", b'#include "../json/active.hpp"\n')
        self.write_source("glaze/json/active.hpp", b"#pragma once\n")
        self.write_source("glaze/core/platform.hpp", b"#include <windows.h>\n")
        headers = VENDOR.collect_headers(self.source)
        self.assertEqual(len(headers), 6)
        for relative in ("core/inactive.hpp", "json/active.hpp", "core/platform.hpp"):
            self.assertIn(Path(relative), headers)

    def test_comments_continuations_and_raw_strings(self) -> None:
        self.write_source(
            "glaze/json/read.hpp",
            b"""
/* #include MACRO
#include "glaze/nonexistent.hpp"
*/
// #include "glaze/nonexistent.hpp"
const char* text = R"raw(
#include NOT_A_DIRECTIVE
)raw";
# /* between tokens */ include \\
  "glaze/core/active.hpp" /* trailing */
#include <vector> // normal system include
""",
        )
        self.write_source("glaze/core/active.hpp", b"// preserved exactly\n")
        self.assertEqual(len(VENDOR.collect_headers(self.source)), 4)

    def test_source_mutation_changes_transitive_closure(self) -> None:
        self.assertEqual(self.vendor(), 0)
        before = self.snapshot()
        self.write_source("glaze/json/read.hpp", b'#include "glaze/core/new.hpp"\n')
        self.write_source("glaze/core/new.hpp", b"// new header\n")
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(VENDOR.vendor(self.source, self.output, True), 1)
        self.assertEqual(
            output.getvalue().splitlines(),
            ["Missing: core/new.hpp", "Changed: json/read.hpp"],
        )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.vendor(), 0)
        self.assertEqual(self.vendor(check=True), 0)
        self.write_source("glaze/json/read.hpp", b"#pragma once\n")
        self.assertEqual(self.vendor(), 0)
        self.assertFalse((self.output / "core/new.hpp").exists())

    def test_check_reports_missing_changed_surplus_without_writes(self) -> None:
        self.assertEqual(self.vendor(), 0)
        (self.output / "json/read.hpp").unlink()
        (self.output / "json/write.hpp").write_bytes(b"changed\n")
        (self.output / "unused.hpp").write_bytes(b"stale\n")
        before = self.snapshot()
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(VENDOR.vendor(self.source, self.output, True), 1)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "Missing: json/read.hpp",
                "Changed: json/write.hpp",
                "Surplus: unused.hpp",
            ],
        )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.vendor(), 0)
        self.assertEqual(self.vendor(check=True), 0)
        self.assertFalse((self.output / "unused.hpp").exists())

    def test_check_does_not_create_output_directory(self) -> None:
        self.assertEqual(self.vendor(check=True), 1)
        self.assertFalse(self.output.parent.exists())
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--source",
                str(self.source),
                "--output",
                str(self.output),
                "--check",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Missing: json/read.hpp", result.stdout)
        self.assertFalse(self.output.parent.exists())

    def test_check_leaves_matching_output_untouched(self) -> None:
        self.assertEqual(self.vendor(), 0)
        before = self.snapshot()
        self.assertEqual(self.vendor(check=True), 0)
        self.assertEqual(self.snapshot(), before)

    def test_rejects_macro_and_unsupported_directives_before_any_writes(self) -> None:
        self.assertEqual(self.vendor(), 0)
        before = self.snapshot()
        for directive in (
            b"#include HEADER\n",
            b"#if 0\n#include MAKE_HEADER(json)\n#endif\n",
            b"\f#\vinclude UNKNOWN_HEADER\n",
            b'#include "glaze/a.hpp" EXTRA\n',
            b"#include_next <vector>\n",
        ):
            with self.subTest(directive=directive):
                self.write_source("glaze/json/read.hpp", directive)
                with self.assertRaisesRegex(VENDOR.VendorError, "unsupported include"):
                    self.vendor()
                self.assertEqual(self.snapshot(), before)

    def test_rejects_missing_internal_headers_before_any_writes(self) -> None:
        self.assertEqual(self.vendor(), 0)
        before = self.snapshot()
        for directive in (
            b'#include "glaze/missing.hpp"\n',
            b"#include <glaze/missing.hpp>\n",
            b'#include "../core/missing.hpp"\n',
        ):
            with self.subTest(directive=directive):
                self.write_source("glaze/json/read.hpp", directive)
                with self.assertRaisesRegex(VENDOR.VendorError, "Missing Glaze header"):
                    self.vendor()
                self.assertEqual(self.snapshot(), before)

    def test_entry_points_define_the_selected_formats(self) -> None:
        self.write_source("glaze/csv/read.hpp", b'#include "../core/extra.hpp"\n')
        self.write_source("glaze/core/extra.hpp", b"#pragma once\n")
        self.write_source("glaze/beve/write.hpp", b"#pragma once\n")
        with mock.patch.object(
            VENDOR, "ENTRY_POINTS", ("glaze/csv/read.hpp", "glaze/beve/write.hpp")
        ):
            self.assertEqual(self.vendor(), 0)
            self.assertEqual(self.vendor(check=True), 0)
        self.assertEqual(
            set(self.snapshot()),
            {"csv/read.hpp", "beve/write.hpp", "core/extra.hpp"},
        )

    def test_rejects_overlapping_or_broad_output(self) -> None:
        for output in (
            self.source,
            self.source / "glaze",
            self.source / "glaze" / "nested" / "glaze",
            self.root,
            Path.cwd(),
            Path.home(),
            Path("/"),
        ):
            with self.subTest(output=output), self.assertRaises(VENDOR.VendorError):
                VENDOR.vendor(self.source, output, False)
        ancestor_output = self.root / "glaze"
        with self.assertRaisesRegex(VENDOR.VendorError, "must not overlap"):
            VENDOR.vendor(ancestor_output / "include", ancestor_output, False)
        aliased_source = self.root / "aliased-source"
        aliased_source.mkdir()
        (aliased_source / "glaze").symlink_to(
            self.source / "glaze", target_is_directory=True
        )
        with self.assertRaisesRegex(VENDOR.VendorError, "must not overlap"):
            VENDOR.vendor(aliased_source, self.source / "glaze", False)

    def test_rejects_escaping_includes(self) -> None:
        self.write_source("glaze/json/read.hpp", b'#include "../../outside.hpp"\n')
        with self.assertRaisesRegex(VENDOR.VendorError, "escapes"):
            self.vendor()

    def test_rejects_symlinked_output_and_contents(self) -> None:
        self.assertEqual(self.vendor(), 0)
        before = self.snapshot()
        link = self.root / "glaze"
        link.symlink_to(self.output, target_is_directory=True)
        with self.assertRaisesRegex(VENDOR.VendorError, "must not be a symlink"):
            VENDOR.vendor(self.source, link, False)
        stale = self.output / "stale.hpp"
        stale.symlink_to(self.source / "glaze/json/read.hpp")
        with self.assertRaisesRegex(VENDOR.VendorError, "must not contain symlinks"):
            self.vendor()
        stale.unlink()
        self.assertEqual(self.snapshot(), before)

    def test_stages_source_before_writing_and_deletes_only_surplus_files(self) -> None:
        self.assertEqual(self.vendor(), 0)
        (self.output / "stale.hpp").write_bytes(b"stale\n")
        outside = self.output.parent / "keep.hpp"
        outside.write_bytes(b"keep\n")
        self.write_source("glaze/json/read.hpp", b"// updated\n")
        original_read = Path.read_bytes

        def read_bytes(path: Path) -> bytes:
            if path == self.source / "glaze/json/read.hpp":
                raise OSError("source read failed")
            return original_read(path)

        before = self.snapshot()
        with mock.patch.object(Path, "read_bytes", read_bytes), self.assertRaisesRegex(
            OSError, "source read failed"
        ):
            self.vendor()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.vendor(), 0)
        self.assertFalse((self.output / "stale.hpp").exists())
        self.assertEqual(outside.read_bytes(), b"keep\n")

    def test_output_conflicts_do_not_delete_surplus(self) -> None:
        self.assertEqual(self.vendor(), 0)
        (self.output / "stale.hpp").write_bytes(b"stale\n")
        (self.output / "core").write_bytes(b"blocking file\n")
        self.write_source("glaze/json/read.hpp", b'#include "glaze/core/needed.hpp"\n')
        self.write_source("glaze/core/needed.hpp", b"#pragma once\n")
        before = self.snapshot()
        with self.assertRaisesRegex(VENDOR.VendorError, "conflicts"):
            self.vendor()
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
