#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import json
import os
import subprocess
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


class CoverageSummaryTest(unittest.TestCase):
    def test_combines_series_on_one_scale(self) -> None:
        points = [
            SUMMARY.CoveragePoint(100, "10", 83.20, 63.49),
            SUMMARY.CoveragePoint(101, "11", 84.30, 64.50),
        ]

        rendered = SUMMARY.render_trend(points)

        self.assertEqual(rendered.count("```mermaid"), 1)
        self.assertEqual(rendered.count("    line ["), 2)
        self.assertIn('x-axis "Run" ["10", "11"]', rendered)
        self.assertIn('y-axis "Coverage (%)" 60 --> 90', rendered)
        self.assertIn('line [83.20, 84.30 "Line"]', rendered)
        self.assertIn('line [63.49, 64.50 "Branch"]', rendered)
        self.assertEqual(rendered.count(' "Line"'), 1)
        self.assertEqual(rendered.count(' "Branch"'), 1)
        self.assertIn("**84.30% line coverage**", rendered)
        self.assertIn("**64.50% branch coverage**", rendered)
        self.assertNotIn('    title "', rendered)
        self.assertNotIn('    line "Line"', rendered)
        self.assertNotIn('    line "Branch"', rendered)
        self.assertNotIn('" "]', rendered)

    def test_uses_supported_white_background_styling(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 83.20, 63.49),
                SUMMARY.CoveragePoint(101, "11", 84.30, 64.50),
            ]
        )
        directive = next(
            line for line in rendered.splitlines() if line.startswith("%%{init: ")
        )
        config = json.loads(directive[len("%%{init: ") : -len("}%%")])

        self.assertEqual(config["theme"], "base")
        self.assertEqual(
            config["themeCSS"],
            ".main .plot, .main .bottom-axis, .main .left-axis "
            "{ transform: translate(10px, 20px) scale(0.93); } "
            ".plot .line-plot-1 .labels text "
            "{ text-anchor: end; translate: -20px 20px; }",
        )
        self.assertEqual(config["xyChart"]["width"], 700)
        self.assertEqual(config["xyChart"]["height"], 300)
        self.assertFalse(config["xyChart"]["showTitle"])
        for axis in ("xAxis", "yAxis"):
            self.assertFalse(config["xyChart"][axis]["showAxisLine"])
            self.assertFalse(config["xyChart"][axis]["showTick"])
            self.assertEqual(config["xyChart"][axis]["labelFontSize"], 12)
            self.assertEqual(config["xyChart"][axis]["titleFontSize"], 14)
        theme = config["themeVariables"]["xyChart"]
        self.assertEqual(theme["backgroundColor"], "#ffffff")
        self.assertEqual(theme["plotColorPalette"], "#333333, #4c78a8")
        self.assertIn("accTitle: Coverage trend", rendered)
        self.assertIn("accDescr: Line coverage is charcoal", rendered)

    def test_missing_branch_values_do_not_shift_either_series(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 83.20, 63.49),
                SUMMARY.CoveragePoint(101, "11", 87.60, None),
                SUMMARY.CoveragePoint(102, "12", 84.30, 64.50),
            ]
        )

        self.assertIn('x-axis "Run" ["10", "12"]', rendered)
        self.assertIn('line [83.20, 84.30 "Line"]', rendered)
        self.assertIn('line [63.49, 64.50 "Branch"]', rendered)
        self.assertIn("omits 1 run without branch coverage", rendered)
        self.assertIn("all runs remain in the table", rendered)
        self.assertIn("87.60% | - |", rendered)
        self.assertNotIn("87.60,", rendered)

    def test_line_only_history_still_has_a_trend(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 83.20, None),
                SUMMARY.CoveragePoint(101, "11", 84.30, None),
            ]
        )

        self.assertEqual(rendered.count("    line ["), 1)
        self.assertIn('x-axis "Run" ["10", "11"]', rendered)
        self.assertIn('line [83.20, 84.30 "Line"]', rendered)
        self.assertNotIn(' "Branch"', rendered)
        self.assertIn("Branch coverage was not reported", rendered)
        self.assertNotIn("omits", rendered)

    def test_latest_run_without_branches_is_not_substituted(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 83.20, 63.49),
                SUMMARY.CoveragePoint(101, "11", 84.30, 64.50),
                SUMMARY.CoveragePoint(102, "12", 85.40, None),
            ]
        )

        self.assertIn("Latest run: **85.40% line coverage**", rendered)
        self.assertIn("Branch coverage was not reported", rendered)
        self.assertIn('x-axis "Run" ["10", "11"]', rendered)
        self.assertIn("85.40% | - |", rendered)

    def test_multiple_omissions_are_explicit(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 80.00, None),
                SUMMARY.CoveragePoint(101, "11", 81.00, 60.00),
                SUMMARY.CoveragePoint(102, "12", 82.00, None),
                SUMMARY.CoveragePoint(103, "13", 83.00, 61.00),
            ]
        )

        self.assertIn("omits 2 runs without branch coverage", rendered)
        self.assertIn('x-axis "Run" ["11", "13"]', rendered)
        self.assertIn('line [81.00, 83.00 "Line"]', rendered)
        self.assertIn('line [60.00, 61.00 "Branch"]', rendered)

    def test_zero_branch_coverage_is_still_labelled(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 100.0, 0.0),
                SUMMARY.CoveragePoint(101, "11", 100.0, 0.0),
            ]
        )

        self.assertIn('line [100.00, 100.00 "Line"]', rendered)
        self.assertIn('line [0.00, 0.00 "Branch"]', rendered)
        self.assertIn('y-axis "Coverage (%)" 0 --> 100', rendered)
        self.assertNotIn("omits", rendered)

    def test_single_run_shows_values_without_an_invisible_line(self) -> None:
        for branch in (63.49, None):
            with self.subTest(branch=branch):
                rendered = SUMMARY.render_trend(
                    [SUMMARY.CoveragePoint(100, "10", 83.20, branch)]
                )
                self.assertNotIn("```mermaid", rendered)
                self.assertIn("At least two comparable runs", rendered)
                self.assertIn("**83.20% line coverage**", rendered)
                self.assertIn("| 83.20% |", rendered)

    def test_single_paired_run_preserves_all_table_rows(self) -> None:
        rendered = SUMMARY.render_trend(
            [
                SUMMARY.CoveragePoint(100, "10", 80.00, None),
                SUMMARY.CoveragePoint(101, "11", 83.20, 63.49),
            ]
        )

        self.assertNotIn("```mermaid", rendered)
        self.assertIn("At least two comparable runs", rendered)
        self.assertIn("omits 1 run without branch coverage", rendered)
        self.assertIn("80.00% | - |", rendered)
        self.assertIn("83.20% | 63.49% |", rendered)

    def test_empty_history_has_no_trend(self) -> None:
        self.assertEqual(SUMMARY.render_trend([]), "")

    def test_table_is_newest_first_and_uses_run_links(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_SERVER_URL": "https://github.example.com/",
                "GITHUB_REPOSITORY": "owner/repository",
            },
        ):
            rendered = SUMMARY.render_trend(
                [
                    SUMMARY.CoveragePoint(100, "10", 83.20, 63.49),
                    SUMMARY.CoveragePoint(101, "11", 84.30, 64.50),
                ]
            )

        newest = (
            "| [11](https://github.example.com/owner/repository/actions/runs/101) "
            "| 84.30% | 64.50% |"
        )
        oldest = (
            "| [10](https://github.example.com/owner/repository/actions/runs/100) "
            "| 83.20% | 63.49% |"
        )
        self.assertLess(rendered.index(newest), rendered.index(oldest))
        self.assertIn("| --- | ---: | ---: |", rendered)

    def test_axis_bounds_include_both_series_without_leaving_percentage_range(
        self,
    ) -> None:
        for values, expected in (
            ([83.20, 63.49], (60, 85)),
            ([0.0, 0.0], (0, 5)),
            ([100.0, 100.0], (95, 100)),
            ([0.0, 100.0], (0, 100)),
            ([50.0, 50.0], (45, 55)),
        ):
            with self.subTest(values=values):
                bounds = SUMMARY._axis_bounds(values)
                self.assertEqual(bounds, expected)
                self.assertLess(bounds[0], bounds[1])
                self.assertLessEqual(bounds[0], min(values))
                self.assertGreaterEqual(bounds[1], max(values))

    def test_rejects_misaligned_series(self) -> None:
        for labels, lines, branches in (
            (["10", "11"], [83.20], []),
            (["10", "11"], [83.20, 84.30], [63.49]),
        ):
            with self.subTest(labels=labels, lines=lines, branches=branches):
                with self.assertRaisesRegex(ValueError, "one value per run label"):
                    SUMMARY._render_chart(labels, lines, branches)

    def test_cli_preserves_area_and_file_summaries(self) -> None:
        report = (
            "src/kv/store.h 40 10 75.00% 4 1 75.00% "
            "40 4 90.00% 20 5 75.00%\n"
            "TOTAL 40 10 75.00% 4 1 75.00% 40 4 90.00% 20 5 75.00%\n"
        )
        previous = (
            "2026-10-01T08:00:00Z \x1b[32m"
            "src/kv/store.h 40 10 75.00% 4 1 75.00% "
            "40 8 80.00% 20 8 60.00%\x1b[0m\n"
            "2026-10-01T08:00:00Z "
            "TOTAL 40 10 75.00% 4 1 75.00% 40 8 80.00% 20 8 60.00%\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "coverage_report.txt"
            report_path.write_text(report, encoding="utf-8")
            history = root / "history"
            history.mkdir()
            (history / "100-10.log").write_text(previous, encoding="utf-8")
            env = os.environ.copy()
            env.update({"GITHUB_RUN_ID": "101", "GITHUB_RUN_NUMBER": "11"})
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(report_path), str(history)],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.stdout.count("```mermaid"), 1)
        self.assertIn('line [80.00, 90.00 "Line"]', result.stdout)
        self.assertIn('line [60.00, 75.00 "Branch"]', result.stdout)
        self.assertIn("## Coverage by area", result.stdout)
        self.assertIn(
            "| `src/kv` | 40 | 4 | 90.00% | +10.00 | 20 | 5 | 75.00% | +15.00 |",
            result.stdout,
        )
        self.assertIn("## Files with most uncovered lines (top 1)", result.stdout)
        self.assertIn("| `src/kv/store.h` | 40 | 4 | 90.00% | 75.00% |", result.stdout)


if __name__ == "__main__":
    unittest.main()
