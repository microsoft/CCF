#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
import coverage_summary
import lean_coverage_report


class LeanCoverageReportTest(unittest.TestCase):
    def test_parse_coverage_mapping(self) -> None:
        doc = """
# Title

## Alpha (`lean/alpha`)

### Core implementation files

- [`src/a/one.h`](../src/a/one.h): core file mentioning `src/ignored/in_prose.h`.
- [`src/a/two.cpp`](../src/a/two.cpp) and [`include/ccf/a.h`](../include/ccf/a.h): paired files.

### Questionable or partial inclusions

- **Partial coverage within [`src/a/one.h`](../src/a/one.h)**: commentary only.
- [`src/a/extra.h`](../src/a/extra.h): optional wrapper.
- **Explicitly excluded files**:
  - [`src/a/excluded.h`](../src/a/excluded.h).
"""
        mappings = lean_coverage_report.parse_coverage_mapping(doc)
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].name, "alpha")
        self.assertEqual(
            mappings[0].core_files,
            ["src/a/one.h", "src/a/two.cpp", "include/ccf/a.h"],
        )
        self.assertEqual(mappings[0].questionable_files, ["src/a/extra.h"])

    def test_count_cpp_loc(self) -> None:
        code = """
// line comment
/* single line block */
int x = 1; // trailing comment
/* multi-line
   comment */ int y = 2;
const char* s = "// not a comment";
const char* r = R"raw(
// still inside raw string
)raw";

"""
        # Lines: int x, int y, const char* s, const char* r, // still..., )raw";
        self.assertEqual(lean_coverage_report.count_cpp_loc(code), 6)

    def test_count_lean_loc_nested_comments_and_chars(self) -> None:
        code = """
-- line comment
/- outer
   /- nested -/
   still comment -/
def f (x' : Char) : Bool :=
  x' == '"' -- char literal quote does not open string
/-- doc comment -/
def g : Nat := 1
"""
        self.assertEqual(lean_coverage_report.count_lean_loc(code), 3)

    def test_compute_metrics_deduplicates_totals_and_tracks_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/a").mkdir(parents=True)
            (root / "src/a/core.h").write_text("int a();\nint b();\n", encoding="utf-8")
            (root / "src/a/types.h").write_text("struct T {};\n", encoding="utf-8")
            (root / "lean/alpha/Alpha/Model").mkdir(parents=True)
            (root / "lean/alpha/Alpha/Proofs").mkdir(parents=True)
            (root / "lean/alpha/Alpha/Model.lean").write_text(
                "def s := 1\n", encoding="utf-8"
            )
            (root / "lean/alpha/Alpha/Model/Sub.lean").write_text(
                "def t := 2\n", encoding="utf-8"
            )
            (root / "lean/alpha/Alpha/Proofs/P.lean").write_text(
                "theorem p : True := trivial\n", encoding="utf-8"
            )
            (root / "lean/beta/Beta").mkdir(parents=True)
            (root / "lean/beta/Beta/Properties.lean").write_text(
                "theorem q : True := trivial\n", encoding="utf-8"
            )

            mappings = [
                lean_coverage_report.SpecMapping(
                    name="alpha",
                    core_files=["src/a/core.h", "src/a/types.h"],
                    questionable_files=[],
                ),
                lean_coverage_report.SpecMapping(
                    name="beta",
                    core_files=["src/a/core.h"],
                    questionable_files=[],
                ),
            ]
            cov_files = [
                coverage_summary.FileCoverage(
                    path="src/a/core.h",
                    lines=10,
                    missed_lines=2,
                    branches=4,
                    missed_branches=1,
                )
            ]

            per_spec, total, _ = lean_coverage_report.compute_metrics(
                root, mappings, cov_files
            )
            self.assertEqual(per_spec[0].code_loc, 3)
            self.assertEqual(per_spec[0].spec_loc, 2)
            self.assertEqual(per_spec[0].total_lean_loc, 3)
            self.assertEqual(per_spec[0].missing_from_report, ["src/a/types.h"])
            # Total deduplicates src/a/core.h across alpha and beta.
            self.assertEqual(total.code_loc, 3)
            self.assertEqual(total.lines, 10)
            self.assertEqual(total.missed_lines, 2)
            self.assertEqual(total.branches, 4)
            self.assertEqual(total.missed_branches, 1)
            self.assertEqual(total.spec_loc, 3)
            self.assertEqual(total.total_lean_loc, 4)


if __name__ == "__main__":
    unittest.main()
