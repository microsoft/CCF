# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import json
from pathlib import Path
import sys

import pytest

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "compare_bencher_ab.py"
SCRIPTS_DIR = str(MODULE_PATH.parent)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
SPEC = importlib.util.spec_from_file_location("compare_bencher_ab", MODULE_PATH)
compare_bencher_ab = importlib.util.module_from_spec(SPEC)
if SPEC.loader is None:
    raise RuntimeError(f"Could not load module from {MODULE_PATH}")
SPEC.loader.exec_module(compare_bencher_ab)


def test_create_side_by_side_plot_renders_summary(tmp_path, capsys):
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

    compare_bencher_ab.create_side_by_side_plot(str(main_file), str(pr_file), "main", "PR")

    output = capsys.readouterr().out
    assert "BENCHMARK COMPARISON: main vs PR" in output
    assert "Summary:" in output
    assert "Improvements: 2" in output
    assert "Regressions: 0" in output


def test_directory_input_renders_history_comparison(tmp_path, capsys):
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

    compare_bencher_ab.create_side_by_side_plot(str(perf_dir), str(pr_file), label2="PR")

    output = capsys.readouterr().out
    assert "# Performance summary" in output
    assert "### Runs" in output
    assert "| PR |  |  |" in output
    assert "## Throughput (tx/s)" in output


def test_load_bencher_file_reports_directory_input(tmp_path, capsys):
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()

    with pytest.raises(SystemExit) as exc:
        compare_bencher_ab.load_bencher_file(str(nested_dir))

    assert exc.value.code == 1
    assert capsys.readouterr().err.strip() == (
        f"Error: {nested_dir} is a directory, expected a bencher.json file"
    )
