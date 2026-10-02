# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
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
sys.modules[SPEC.name] = SUMMARY
SPEC.loader.exec_module(SUMMARY)

REPORT = (
    "src/kv/store.h 10 1 90.00% 10 1 90.00% 10 1 90.00% 5 1 80.00%\n"
    "TOTAL 10 1 90.00% 10 1 90.00% 10 1 90.00% 5 1 80.00%\n"
)


class CoverageSummaryTest(unittest.TestCase):
    def test_loads_artifact_reports_and_skips_incomplete_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory)
            (history / "100-5.txt").write_text(REPORT, encoding="utf-8")
            (history / "200-6.txt").write_text(REPORT, encoding="utf-8")
            (history / "300-7.txt").write_text("incomplete", encoding="utf-8")
            (history / "400-8.log").write_text(REPORT, encoding="utf-8")

            points = SUMMARY.load_history(directory)
            self.assertEqual(sorted(point.run_id for point in points), [100, 200])
            self.assertEqual(SUMMARY.previous_file_coverage(directory)[0].path, "src/kv/store.h")

    def test_limits_trend_to_30_runs_including_current(self) -> None:
        history = [SUMMARY.CoveragePoint(i, str(i), 90.0, 80.0) for i in range(1, 36)]
        current = SUMMARY.CoveragePoint(36, "36", 91.0, 81.0)

        with mock.patch.object(SUMMARY, "HISTORY_POINTS", 30):
            points = SUMMARY.build_points(history, current)
            self.assertEqual([point.run_id for point in points], list(range(7, 37)))
            self.assertEqual(len(SUMMARY.build_points([], current)), 1)
            self.assertEqual(
                [point.run_id for point in SUMMARY.build_points(history, None)],
                list(range(6, 36)),
            )
            self.assertEqual(
                [point.run_id for point in SUMMARY.build_points(history, history[-1])],
                list(range(6, 36)),
            )


if __name__ == "__main__":
    unittest.main()
