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


def normalize_value(value: float, min_val: float, max_val: float, width: int) -> int:
    """Normalize a value to fit within the given width"""
    if max_val == min_val:
        return width // 2
    return int((value - min_val) / (max_val - min_val) * (width - 1))


def create_ascii_bar(
    value: float, min_val: float, max_val: float, width: int = 40, char: str = "█"
) -> str:
    """Create an ASCII bar representation of a value"""
    if value is None:
        return " " * width + " N/A"

    bar_length = normalize_value(value, min_val, max_val, width)
    bar = char * bar_length + " " * (width - bar_length)
    return f"{bar} {value:.2f}"


def format_metric_name(name: str, max_length: int = 35) -> str:
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

    # Calculate min/max for normalization
    all_values = []
    for key in all_keys:
        if key in metrics1 and metrics1[key] is not None:
            all_values.append(metrics1[key])
        if key in metrics2 and metrics2[key] is not None:
            all_values.append(metrics2[key])

    if not all_values:
        print("No valid numeric values found")
        return

    min_val = min(all_values)
    max_val = max(all_values)

    # Print header
    print("=" * 120)
    print(f"BENCHMARK COMPARISON: {label1} vs {label2}")
    print("=" * 120)
    print()

    # Column headers
    metric_col_width = 35
    bar_width = 25
    value_width = 12
    change_width = 10

    header = (
        f"{'Metric':<{metric_col_width}} "
        f"{'<-- ' + label1[:bar_width-4] + ' -->':<{bar_width + value_width}} "
        f"{'<-- ' + label2[:bar_width-4] + ' -->':<{bar_width + value_width}} "
        f"{'Change':<{change_width}}"
    )
    print(header)
    print("-" * len(header))

    # Process each metric
    for key in all_keys:
        val1 = metrics1.get(key)
        val2 = metrics2.get(key)

        # Format metric name
        formatted_key = format_metric_name(key, metric_col_width)

        # Create bars
        bar1 = create_ascii_bar(val1, min_val, max_val, bar_width, "█")
        bar2 = create_ascii_bar(val2, min_val, max_val, bar_width, "▓")

        # Calculate change
        change = calculate_percentage_change(val1, val2)

        # Color coding for change (using unicode symbols)
        if change != "N/A" and change != "∞":
            change_val = float(change.replace("%", "").replace("+", ""))
            if abs(change_val) < 2:
                change_indicator = "≈"  # roughly equal
            elif change_val > 0:
                change_indicator = "↑"  # regression
            else:
                change_indicator = "↓"  # improvement
        else:
            change_indicator = "?"

        # Print row
        row = (
            f"{formatted_key} "
            f"{bar1:<{bar_width + value_width}} "
            f"{bar2:<{bar_width + value_width}} "
            f"{change_indicator} {change:<{change_width-2}}"
        )
        print(row)

    print()
    print("Legend:")
    print("  █ = " + label1)
    print("  ▓ = " + label2)
    print("  ↑ = Regression (worse performance)")
    print("  ↓ = Improvement (better performance)")
    print("  ≈ = No significant change (<2%)")
    print("  ? = Unable to calculate change")

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
