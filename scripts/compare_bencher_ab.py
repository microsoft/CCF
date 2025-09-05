# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import sys
import argparse
from typing import Dict


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


def is_higher_better(metric_name: str) -> bool:
    """Determine if higher values are better for this metric"""
    metric_lower = metric_name.lower()

    # Higher is better for these metrics
    if any(keyword in metric_lower for keyword in ["throughput", "rate", "queries"]):
        return True

    # Lower is better for these metrics
    if any(keyword in metric_lower for keyword in ["latency", "memory"]):
        return False

    # Default assumption: higher is better (for most performance metrics)
    return True


def create_diverging_bar(
    change_percent: float, metric_name: str, width: int = 40
) -> str:
    """Create a diverging bar chart centered at 0 using block characters"""
    if change_percent == "N/A" or change_percent == "∞":
        return " " * (width // 2) + "|" + " " * (width // 2) + " N/A"

    try:
        # Parse the percentage
        if isinstance(change_percent, str):
            change_val = float(change_percent.replace("%", "").replace("+", ""))
        else:
            change_val = change_percent
    except (ValueError, AttributeError):
        return " " * (width // 2) + "|" + " " * (width // 2) + " N/A"

    # Center position
    center = width // 2

    # Scale the change to fit the bar width (max ±50% uses full width)
    max_change = 50.0  # Cap at ±50% for reasonable scaling
    clamped_change = max(-max_change, min(max_change, change_val))

    # Calculate bar length (half width = max extent)
    bar_length = int(abs(clamped_change) / max_change * center)

    # Determine if this change is actually good or bad
    higher_is_better = is_higher_better(metric_name)
    is_improvement = (change_val > 0 and higher_is_better) or (
        change_val < 0 and not higher_is_better
    )

    if abs(change_val) < 2:  # No significant change
        bar = " " * center + "|" + " " * center
        return bar + f" {change_val:+.1f}%"
    elif is_improvement:  # This is actually an improvement
        if change_val > 0:  # Positive change that's good (e.g., higher throughput)
            bar = " " * center + "|" + "▓" * bar_length + " " * (center - bar_length)
        else:  # Negative change that's good (e.g., lower latency)
            left_start = center - bar_length
            bar = " " * left_start + "▓" * bar_length + "|" + " " * center
        return bar + f" {change_val:+.1f}%"
    else:  # This is a regression
        if change_val > 0:  # Positive change that's bad (e.g., higher latency)
            bar = " " * center + "|" + "█" * bar_length + " " * (center - bar_length)
        else:  # Negative change that's bad (e.g., lower throughput)
            left_start = center - bar_length
            bar = " " * left_start + "█" * bar_length + "|" + " " * center
        return bar + f" {change_val:+.1f}%"


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
    total_width = 120
    print("=" * total_width)
    title = f"BENCHMARK COMPARISON: {label1} vs {label2}"
    print(f"{title:^{total_width}}")
    print("=" * total_width)
    print()

    # Column widths
    metric_width = 40
    bar_width = 50  # Width for the diverging bar chart
    values_width = 30

    # Print column headers
    print(
        f"{'Metric':<{metric_width}} {'Performance Change':^{bar_width}} {'Values':^{values_width}}"
    )
    print(
        f"{'':<{metric_width}} {'':<{bar_width}} {label1 + ' → ' + label2:^{values_width}}"
    )
    print("-" * total_width)

    # Process each metric
    for key in all_keys:
        val1 = metrics1.get(key)
        val2 = metrics2.get(key)

        # Format metric name
        metric_name = key[: metric_width - 1] if len(key) >= metric_width else key

        # Calculate change
        change = calculate_percentage_change(val1, val2)

        # Create diverging bar chart with context-aware direction
        bar_display = create_diverging_bar(change, key, 40)

        # Format values
        val1_str = f"{val1:.2f}" if val1 is not None else "N/A"
        val2_str = f"{val2:.2f}" if val2 is not None else "N/A"
        values_display = f"{val1_str} → {val2_str}"

        # Print row
        print(
            f"{metric_name:<{metric_width}} {bar_display:<{bar_width}} {values_display:<{values_width}}"
        )

    print()
    print("Legend:")
    print("  ▓▓▓|         = Improvement (left side, better performance)")
    print("      |███     = Regression (right side, worse performance)")
    print("      |         = No significant change (<2%)")
    print("  ▓ = Better performance (lighter blocks)")
    print("  █ = Worse performance (darker blocks)")
    print("  Scale: ±50% change uses full bar width")
    print(
        "  Note: For performance metrics, lower latency = better, higher throughput = better"
    )

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
            else:
                # Use is_higher_better() to determine if this is actually an improvement or regression
                higher_is_better = is_higher_better(key)
                is_improvement = (change_val > 0 and higher_is_better) or (
                    change_val < 0 and not higher_is_better
                )
                if is_improvement:
                    improvements += 1
                else:
                    regressions += 1

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
