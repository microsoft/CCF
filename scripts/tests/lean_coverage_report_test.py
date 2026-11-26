#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import gzip
import json
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

    def test_count_cpp_loc_with_mask_preserves_block_comment_state(self) -> None:
        code = (
            "int keep_1 = 1;\n"
            "/* comment starts in excluded range\n"
            "   still commented inside included range */\n"
            "int keep_2 = 2;\n"
            "int drop_me = 3;\n"
        )
        # Include lines 1, 3, 4; exclude lines 2 and 5.
        # Line 3 is still inside the block comment opened on excluded line 2.
        self.assertEqual(lean_coverage_report.count_cpp_loc(code, {1, 3, 4}), 2)

    def test_load_spec_mask_and_anchor_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/kv").mkdir(parents=True)
            (root / "lean/kv").mkdir(parents=True)
            (root / "src/kv/a.h").write_text(
                "int keep();\nvoid skip_me()\n{\n}\nint also_keep();\n",
                encoding="utf-8",
            )
            mask = {
                "spec": "kv",
                "files": {
                    "src/kv/a.h": {
                        "exclude": [
                            {
                                "start": 2,
                                "end": 4,
                                "start_anchor": "void skip_me()",
                                "end_anchor": "}",
                                "reason": "unmodeled",
                            }
                        ]
                    }
                },
            }
            mask_path = root / "lean/kv/coverage_mask.json"
            mask_path.write_text(json.dumps(mask), encoding="utf-8")

            loaded = lean_coverage_report.load_spec_mask(root, "kv", ["src/kv/a.h"])
            self.assertEqual(loaded, {"src/kv/a.h": {1, 5}})

            # Anchor drift must raise ValueError.
            mask["files"]["src/kv/a.h"]["exclude"][0]["start_anchor"] = "wrong()"
            mask_path.write_text(json.dumps(mask), encoding="utf-8")
            with self.assertRaises(ValueError):
                lean_coverage_report.load_spec_mask(root, "kv", ["src/kv/a.h"])

    def test_parse_html_ignores_nested_expansion_tables(self) -> None:
        html = (
            "<table>"
            "<tr><td class='line-number'><a name='L1'><pre>1</pre></a></td>"
            "<td class='covered-line'><pre>1.2k</pre></td>"
            "<td class='code'><pre>int x;</pre></td></tr>"
            "<tr><td class='line-number'><a name='L2'><pre>2</pre></a></td>"
            "<td class='uncovered-line'><pre>0</pre></td>"
            "<td class='code'><pre><table>"
            "<tr><td class='line-number'><a name='L1'><pre>1</pre></a></td>"
            "<td class='uncovered-line'><pre>0</pre></td>"
            "<td class='code'><pre>nested</pre></td></tr>"
            "</table></pre></td></tr>"
            "</table>"
        )
        parsed = lean_coverage_report.parse_html_file_coverage(html)
        self.assertEqual(parsed, {1: 1200, 2: 0})

    def test_load_export_json_gz_and_masked_branches(self) -> None:
        payload = {
            "data": [
                {
                    "files": [
                        {
                            "filename": "/__w/CCF/src/kv/a.h",
                            "segments": [
                                [1, 1, 5, True, True, False],
                                [3, 1, 0, False, False, False],
                                [4, 1, 0, True, True, False],
                                [5, 1, 0, False, False, False],
                            ],
                            "branches": [
                                [1, 5, 1, 10, 4, 1, 0, 0, 4],
                                # Duplicate instantiation of same branch location:
                                [1, 5, 1, 10, 0, 2, 0, 0, 4],
                                # Branch on excluded line 4:
                                [4, 5, 4, 10, 0, 0, 0, 0, 4],
                            ],
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/kv").mkdir(parents=True)
            (root / "lean/kv/Kv").mkdir(parents=True)
            (root / "src/kv/a.h").write_text(
                "if (a) {}\nint b = 1;\n\nif (c) {}\n", encoding="utf-8"
            )
            (root / "lean/kv/Kv/Model.lean").write_text(
                "def x := 1\n", encoding="utf-8"
            )

            gz_path = root / "coverage.json.gz"
            with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
                json.dump(payload, fh)

            details = lean_coverage_report.load_export_json(gz_path)
            mappings = [
                lean_coverage_report.SpecMapping(
                    name="kv", core_files=["src/kv/a.h"], questionable_files=[]
                )
            ]
            # Mask includes lines 1-3, excludes line 4.
            per_spec, total, _ = lean_coverage_report.compute_metrics(
                repo_root=root,
                mappings=mappings,
                coverage_files=[],
                spec_masks={"kv": {"src/kv/a.h": {1, 2, 3}}},
                detailed_coverage=details,
            )
            kv = per_spec[0]
            self.assertTrue(kv.masked)
            self.assertTrue(kv.branches_available)
            self.assertEqual(kv.code_loc, 2)
            # Lines 1 and 2 are covered (count 5); line 3 ends region at col 1; line 4 excluded.
            self.assertEqual((kv.lines, kv.missed_lines), (2, 0))
            # Only the deduplicated branch on line 1 is included: both true (4) and false (2) hit.
            self.assertEqual((kv.branches, kv.missed_branches), (2, 0))
            self.assertEqual((total.lines, total.branches), (2, 2))

    def test_repo_kv_coverage_mask_is_valid(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        mappings = lean_coverage_report.parse_coverage_mapping(
            (repo_root / "lean/COVERAGE_MAPPING.md").read_text(encoding="utf-8")
        )
        kv_mapping = next(m for m in mappings if m.name == "kv")
        loaded = lean_coverage_report.load_spec_mask(
            repo_root, "kv", kv_mapping.core_files
        )
        self.assertEqual(
            set(loaded.keys()),
            {
                "src/kv/store.h",
                "src/kv/untyped_map.h",
                "src/kv/untyped_change_set.h",
                "src/kv/apply_changes.h",
                "include/ccf/kv/tx.h",
                "src/kv/committable_tx.h",
            },
        )


if __name__ == "__main__":
    unittest.main()
