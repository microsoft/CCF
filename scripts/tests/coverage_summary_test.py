#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "coverage_summary.py"
SPEC = importlib.util.spec_from_file_location("coverage_summary", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)

# A cut-down llvm-cov report as it appears in a GitHub Actions job log: each
# line is prefixed with a timestamp, and some lines carry ANSI colour codes.
REPORT = """
2026-09-22T18:00:00.000Z Filename  Regions  Missed Regions  Cover  Functions  Missed Functions  Executed  Lines  Missed Lines  Cover  Branches  Missed Branches  Cover
2026-09-22T18:00:00.000Z ------------------------------------------------------------------------
2026-09-22T18:00:00.000Z \x1b[0;31msrc/kv/store.h\x1b[0m  100  20  80.00%  10  1  90.00%  200  50  75.00%  40  10  75.00%
2026-09-22T18:00:00.000Z src/kv/untyped_map.h  50  0  100.00%  5  0  100.00%  100  0  100.00%  0  0  -
2026-09-22T18:00:00.000Z src/node/rpc/frontend.h  300  100  66.67%  30  10  66.67%  600  300  50.00%  100  60  40.00%
2026-09-22T18:00:00.000Z src/node/node_state.h  400  100  75.00%  40  5  87.50%  800  100  87.50%  200  50  75.00%
2026-09-22T18:00:00.000Z include/ccf/ds/json.h  10  0  100.00%  1  0  100.00%  20  0  100.00%  4  0  100.00%
2026-09-22T18:00:00.000Z ------------------------------------------------------------------------
2026-09-22T18:00:00.000Z TOTAL  860  220  74.42%  86  16  81.40%  1720  450  73.84%  344  120  65.12%
"""

PREVIOUS_REPORT = """
src/kv/store.h  100  30  70.00%  10  1  90.00%  200  60  70.00%  40  12  70.00%
src/node/rpc/frontend.h  300  100  66.67%  30  10  66.67%  600  300  50.00%  100  60  40.00%
TOTAL  400  130  67.50%  40  11  72.50%  800  360  55.00%  140  72  48.57%
"""


class ExtractFileCoverageTest(unittest.TestCase):
    def test_parses_rows_and_skips_headers_and_total(self):
        files = SUMMARY.extract_file_coverage(REPORT)
        self.assertEqual(
            [entry.path for entry in files],
            [
                "src/kv/store.h",
                "src/kv/untyped_map.h",
                "src/node/rpc/frontend.h",
                "src/node/node_state.h",
                "include/ccf/ds/json.h",
            ],
        )
        store = files[0]
        self.assertEqual((store.lines, store.missed_lines), (200, 50))
        self.assertEqual((store.branches, store.missed_branches), (40, 10))

    def test_accepts_dash_percentage_for_empty_branch_column(self):
        files = SUMMARY.extract_file_coverage(REPORT)
        untyped_map = files[1]
        self.assertEqual((untyped_map.branches, untyped_map.missed_branches), (0, 0))

    def test_accepts_rows_without_branch_columns(self):
        files = SUMMARY.extract_file_coverage(
            "src/a/b.h  10  1  90.00%  2  0  100.00%  30  3  90.00%"
        )
        self.assertEqual(len(files), 1)
        self.assertEqual((files[0].lines, files[0].missed_lines), (30, 3))
        self.assertEqual((files[0].branches, files[0].missed_branches), (0, 0))

    def test_ignores_unrelated_log_lines(self):
        self.assertEqual(
            SUMMARY.extract_file_coverage("+ ninja\nFound 785 .profraw file(s)\n"),
            [],
        )


class AggregateByAreaTest(unittest.TestCase):
    def test_groups_by_leading_directories_and_sorts_by_missed_lines(self):
        areas = SUMMARY.aggregate_by_area(SUMMARY.extract_file_coverage(REPORT))
        self.assertEqual(
            [area.area for area in areas],
            ["src/node/rpc", "src/node", "src/kv", "include/ccf/ds"],
        )
        kv = next(area for area in areas if area.area == "src/kv")
        self.assertEqual((kv.lines, kv.missed_lines), (300, 50))
        self.assertEqual((kv.branches, kv.missed_branches), (40, 10))
        self.assertAlmostEqual(kv.line_coverage, 100.0 * 250 / 300)

    def test_area_of_uses_directory_components_only(self):
        self.assertEqual(SUMMARY.area_of("src/node/rpc/test/x.cpp"), "src/node/rpc")
        self.assertEqual(SUMMARY.area_of("src/kv/store.h"), "src/kv")
        self.assertEqual(SUMMARY.area_of("store.h"), ".")

    def test_coverage_is_none_without_lines_or_branches(self):
        area = SUMMARY.AreaCoverage("x", 0, 0, 0, 0)
        self.assertIsNone(area.line_coverage)
        self.assertIsNone(area.branch_coverage)


class RenderTest(unittest.TestCase):
    def test_render_areas_includes_deltas_against_previous_run(self):
        current = SUMMARY.aggregate_by_area(SUMMARY.extract_file_coverage(REPORT))
        previous = SUMMARY.aggregate_by_area(
            SUMMARY.extract_file_coverage(PREVIOUS_REPORT)
        )
        rendered = SUMMARY.render_areas(current, previous)
        self.assertIn("## Coverage by area", rendered)
        # src/kv went from 70.00% to 83.33% line coverage (+13.33 points), and
        # from 70.00% to 75.00% branch coverage.
        self.assertIn(
            "| `src/kv` | 300 | 50 | 83.33% | +13.33 | 40 | 10 | 75.00% | +5.00 |",
            rendered,
        )
        # Unchanged area.
        self.assertIn("| `src/node/rpc` | 600 | 300 | 50.00% | +0.00 |", rendered)
        # Area absent from the previous run has no delta.
        self.assertIn("| `src/node` | 800 | 100 | 87.50% | - |", rendered)

    def test_render_areas_without_previous_run(self):
        current = SUMMARY.aggregate_by_area(SUMMARY.extract_file_coverage(REPORT))
        rendered = SUMMARY.render_areas(current, None)
        for row in rendered.splitlines():
            if row.startswith("| `"):
                self.assertEqual(row.count(" - |"), 2, row)

    def test_render_top_files_orders_by_missed_lines(self):
        files = SUMMARY.extract_file_coverage(REPORT)
        rendered = SUMMARY.render_top_files(files)
        rows = [row for row in rendered.splitlines() if row.startswith("| `")]
        self.assertEqual(rows[0].split("|")[1].strip(), "`src/node/rpc/frontend.h`")
        self.assertEqual(rows[1].split("|")[1].strip(), "`src/node/node_state.h`")
        self.assertIn("| `src/kv/untyped_map.h` | 100 | 0 | 100.00% | - |", rendered)

    def test_render_top_files_is_limited(self):
        files = [
            SUMMARY.FileCoverage(f"src/f{i}.h", 10, i, 0, 0)
            for i in range(SUMMARY._TOP_FILES + 5)
        ]
        rendered = SUMMARY.render_top_files(files)
        rows = [row for row in rendered.splitlines() if row.startswith("| `")]
        self.assertEqual(len(rows), SUMMARY._TOP_FILES)
        self.assertIn(f"(top {SUMMARY._TOP_FILES})", rendered)


class HistoryTest(unittest.TestCase):
    def test_latest_history_path_picks_highest_run_id(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ["100-1.log", "300-3.log", "200-2.log", "notes.txt"]:
                Path(directory, name).write_text("TOTAL 1 0 100.00%\n")
            self.assertEqual(
                SUMMARY.latest_history_path(directory),
                os.path.join(directory, "300-3.log"),
            )

    def test_latest_history_path_without_directory(self):
        self.assertIsNone(SUMMARY.latest_history_path("/nonexistent/path"))


class MainTest(unittest.TestCase):
    def test_main_renders_trend_area_and_file_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "coverage_report.txt")
            report.write_text(REPORT)
            history = Path(directory, "coverage_history")
            history.mkdir()
            Path(history, "1-1.log").write_text(PREVIOUS_REPORT)

            argv = ["coverage_summary.py", str(report), str(history)]
            env = {"GITHUB_RUN_ID": "2", "GITHUB_RUN_NUMBER": "2"}
            with mock.patch.object(sys, "argv", argv), mock.patch.dict(
                os.environ, env
            ), mock.patch("sys.stdout") as stdout:
                self.assertEqual(SUMMARY.main(), 0)
            output = "".join(call.args[0] for call in stdout.write.call_args_list)

        self.assertIn("## Line coverage trend", output)
        self.assertIn("## Coverage by area", output)
        self.assertIn("## Files with most uncovered lines", output)
        self.assertIn("| `src/kv` | 300 | 50 | 83.33% | +13.33 |", output)

    def test_main_without_file_rows_only_renders_trend(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "coverage_report.txt")
            report.write_text("TOTAL  1  0  100.00%  1  0  100.00%  1  0  100.00%\n")
            argv = ["coverage_summary.py", str(report), str(Path(directory, "none"))]
            with mock.patch.object(sys, "argv", argv), mock.patch(
                "sys.stdout"
            ) as stdout:
                self.assertEqual(SUMMARY.main(), 0)
            output = "".join(call.args[0] for call in stdout.write.call_args_list)
        self.assertIn("## Line coverage trend", output)
        self.assertNotIn("## Coverage by area", output)


if __name__ == "__main__":
    unittest.main()
