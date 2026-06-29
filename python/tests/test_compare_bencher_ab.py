# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "compare_bencher_ab.py"
SCRIPTS_DIR = str(MODULE_PATH.parent)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
SPEC = importlib.util.spec_from_file_location("compare_bencher_ab", MODULE_PATH)
compare_bencher_ab = importlib.util.module_from_spec(SPEC)
if SPEC.loader is None:
    raise RuntimeError(f"Could not load module from {MODULE_PATH}")
SPEC.loader.exec_module(compare_bencher_ab)


class CompareBencherABTests(unittest.TestCase):
    def test_create_side_by_side_plot_renders_summary(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            main_file = tmp_path / "main.json"
            pr_file = tmp_path / "pr.json"

            main_file.write_text(
                json.dumps(
                    {
                        "benchmark_a": {
                            "latency": {"value": 10.0},
                            "throughput": {"value": 100.0},
                        }
                    }
                ),
                encoding="utf-8",
            )
            pr_file.write_text(
                json.dumps(
                    {
                        "benchmark_a": {
                            "latency": {"value": 8.0},
                            "throughput": {"value": 110.0},
                        }
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                compare_bencher_ab.create_side_by_side_plot(
                    str(main_file), str(pr_file), "main", "PR"
                )

        output = stdout.getvalue()
        self.assertIn("BENCHMARK COMPARISON: main vs PR", output)
        self.assertIn("Summary:", output)
        self.assertIn("Improvements: 2", output)
        self.assertIn("Regressions: 0", output)

    def test_directory_input_renders_history_comparison(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            perf_dir = tmp_path / "perf"
            perf_dir.mkdir()
            (perf_dir / "100-1-1.json").write_text(
                json.dumps({"benchmark_a": {"throughput": {"value": 100.0}}}),
                encoding="utf-8",
            )
            pr_file = tmp_path / "pr.json"
            pr_file.write_text(
                json.dumps({"benchmark_a": {"throughput": {"value": 110.0}}}),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                compare_bencher_ab.create_side_by_side_plot(
                    str(perf_dir), str(pr_file), label2="PR"
                )

        output = stdout.getvalue()
        self.assertIn("# Performance summary", output)
        self.assertIn("### Runs", output)
        self.assertIn("| PR |  |  |", output)
        self.assertIn("## Throughput (tx/s)", output)

    def test_load_bencher_file_reports_directory_input(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            nested_dir = Path(tmp_dir) / "nested"
            nested_dir.mkdir()

            stdout = io.StringIO()
            with self.assertRaises(SystemExit) as exc:
                with redirect_stdout(stdout):
                    compare_bencher_ab.load_bencher_file(str(nested_dir))

        self.assertEqual(exc.exception.code, 1)
        self.assertEqual(
            stdout.getvalue().strip(),
            f"Error: {nested_dir} is a directory, expected a bencher.json file",
        )


if __name__ == "__main__":
    unittest.main()
