# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import sys
import argparse
from typing import Dict, List, Tuple


def load_bencher_file(filepath: str) -> Dict:
    """Load a bencher.json file"""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File {filepath} not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {filepath}")
        sys.exit(1)


def extract_metrics(data: Dict) -> Dict[str, float]:
    """Extract metrics from bencher data into a flat dictionary"""
    metrics = {}
    for test_name, test_data in data.items():
        for metric_type, metric_data in test_data.items():
            key = f"{test_name} - {metric_type}"
            if isinstance(metric_data, dict) and "value" in metric_data:
                metrics[key] = metric_data["value"]
            else:
                metrics[key] = metric_data
    return metrics


def normalize_value_independent(val1: float, val2: float, width: int) -> tuple:
    """Normalize two values independently to show relative comparison within each metric"""
    if val1 is None and val2 is None:
        return 0, 0
    if val1 is None:
        return 0, width
    if val2 is None:
        return width, 0

    # For a single metric comparison, normalize against the larger of the two values
    max_val = max(val1, val2)
    if max_val == 0:
        return width // 2, width // 2

    bar1_len = int((val1 / max_val) * width)
    bar2_len = int((val2 / max_val) * width)

    return bar1_len, bar2_len


def create_ascii_bar(
    value: float, min_val: float, max_val: float, width: int = 40, char: str = "█"
) -> str:
    """Create an ASCII bar representation of a value"""
    if value is None:
        return " " * width + " N/A"

    bar_length = normalize_value(value, min_val, max_val, width)
    bar = char * bar_length + " " * (width - bar_length)
    return f"{bar} {value:.2f}"


def format_metric_name(name: str, max_length: int = 40) -> str:
    """Format metric name to fit within specified length"""
    if len(name) <= max_length:
        return name.ljust(max_length)
    else:
        # Truncate and add ellipsis
        return name[: max_length - 3] + "..."


def calculate_percentage_change(val1: float, val2: float) -> str:
    """Calculate percentage change from val1 to val2"""
    if val1 is None or val2 is None:
        return "N/A"
    if val1 == 0:
        return "∞" if val2 != 0 else "0%"

    change = ((val2 - val1) / val1) * 100
    sign = "+" if change > 0 else ""
    return f"{sign}{change:.1f}%"


def create_side_by_side_plot(
    file1: str, file2: str, label1: str = None, label2: str = None
):
    """Create ASCII side-by-side comparison plot"""

    # Default labels
    if not label1:
        label1 = file1.replace(".json", "")
    if not label2:
        label2 = file2.replace(".json", "")

    # Load data
    data1 = load_bencher_file(file1)
    data2 = load_bencher_file(file2)

    # Extract metrics
    metrics1 = extract_metrics(data1)
    metrics2 = extract_metrics(data2)

    # Get all unique metric keys
    all_keys = set(metrics1.keys()) | set(metrics2.keys())
    all_keys = sorted(all_keys)

    if not all_keys:
        print("No metrics found in the files")
        return

    # We don't need global min/max anymore since we normalize each metric independently

    # Print header
    print("=" * 120)
    print(f"BENCHMARK COMPARISON: {label1} vs {label2}")
    print("=" * 120)
    print()

    # Column widths
    metric_width = 40
    value_width = 15
    bar_width = 20
    change_width = 12

    # Print column headers
    print(
        f"{'Metric':<{metric_width}} {'Value 1':<{value_width}} {'Bar 1':<{bar_width}} {'Value 2':<{value_width}} {'Bar 2':<{bar_width}} {'Change':<{change_width}}"
    )
    print(
        f"{label1:<{metric_width}} {'':<{value_width}} {'':<{bar_width}} {label2:<{value_width}} {'':<{bar_width}} {'':<{change_width}}"
    )
    print("-" * 120)

    # Process each metric
    for key in all_keys:
        val1 = metrics1.get(key)
        val2 = metrics2.get(key)

        # Format metric name
        metric_name = key[: metric_width - 1] if len(key) >= metric_width else key

        # Format values
        val1_str = f"{val1:.2f}" if val1 is not None else "N/A"
        val2_str = f"{val2:.2f}" if val2 is not None else "N/A"

        # Create bars (normalized independently for each metric)
        bar1_len, bar2_len = normalize_value_independent(val1, val2, bar_width)
        bar1 = "█" * bar1_len + " " * (bar_width - bar1_len)
        bar2 = "▓" * bar2_len + " " * (bar_width - bar2_len)

        # Calculate change
        change = calculate_percentage_change(val1, val2)
        if change != "N/A" and change != "∞":
            change_val = float(change.replace("%", "").replace("+", ""))
            if abs(change_val) < 2:
                change_indicator = "≈"
            elif change_val > 0:
                change_indicator = "↑"
            else:
                change_indicator = "↓"
        else:
            change_indicator = "?"

        # Print row
        print(
            f"{metric_name:<{metric_width}} {val1_str:<{value_width}} {bar1} {val2_str:<{value_width}} {bar2} {change_indicator} {change}"
        )

    print()
    print("Legend:")
    print("  █ = " + label1)
    print("  ▓ = " + label2)
    print("  ↑ = Regression (worse performance)")
    print("  ↓ = Improvement (better performance)")
    print("  ≈ = No significant change (<2%)")
    print("  ? = Unable to calculate change")
    print("  Note: Each metric's bars are normalized independently for A/B comparison")

    # Summary statistics
    print()
    print("Summary:")
    improvements = 0
    regressions = 0
    no_change = 0

    for key in all_keys:
        val1 = metrics1.get(key)
        val2 = metrics2.get(key)
        if val1 is not None and val2 is not None and val1 != 0:
            change_val = ((val2 - val1) / val1) * 100
            if abs(change_val) < 2:
                no_change += 1
            elif change_val > 0:
                regressions += 1
            else:
                improvements += 1

    total_compared = improvements + regressions + no_change
    print(f"  Total metrics compared: {total_compared}")
    print(f"  Improvements: {improvements}")
    print(f"  Regressions: {regressions}")
    print(f"  No significant change: {no_change}")


def main():
    parser = argparse.ArgumentParser(
        description="Create ASCII side-by-side comparison of bencher.json files"
    )
    parser.add_argument("file1", help="First bencher.json file")
    parser.add_argument("file2", help="Second bencher.json file")
    parser.add_argument("--label1", help="Label for first file (default: filename)")
    parser.add_argument("--label2", help="Label for second file (default: filename)")

    args = parser.parse_args()

    create_side_by_side_plot(args.file1, args.file2, args.label1, args.label2)


if __name__ == "__main__":
    main()
