# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import os
import json
import subprocess
import statistics
from loguru import logger as LOG
import infra.bencher


def run_performance_tests(iterations: int):
    """Run performance tests N times and save individual results"""
    LOG.info(f"Running performance tests {iterations} times...")

    for i in range(1, iterations + 1):
        LOG.debug(f"Running iteration {i} of {iterations}")

        # Remove existing bencher.json
        if os.path.exists("bencher.json"):
            os.remove("bencher.json")

        # Run the performance tests
        try:
            subprocess.run(["./tests.sh", "-C", "perf", "-L", "perf"], check=True)

            if os.path.exists("bencher.json"):
                # Copy to bencherN.json
                subprocess.run(["cp", "bencher.json", f"bencher{i}.json"], check=True)
                LOG.trace(f"Saved results to bencher{i}.json")
            else:
                LOG.warning(f"bencher.json not found after iteration {i}")
        except subprocess.CalledProcessError as e:
            LOG.error(f"Error running tests in iteration {i}: {e}")

        LOG.debug(f"Completed iteration {i}")


def aggregate_results(iterations: int):
    """Aggregate all bencherN.json files into a single bencher.json with avg/min/max"""
    LOG.info("Aggregating results...")

    # Collect all test data
    all_data = {}

    for i in range(1, iterations + 1):
        filename = f"bencher{i}.json"
        if not os.path.exists(filename):
            continue

        LOG.trace(f"Processing {filename}")
        with open(filename, "r") as f:
            data = json.load(f)

        for test_name, metrics in data.items():
            if test_name not in all_data:
                all_data[test_name] = {}

            for metric_name, metric_data in metrics.items():
                if metric_name not in all_data[test_name]:
                    all_data[test_name][metric_name] = {
                        "values": [],
                        "low_values": [],
                        "high_values": [],
                    }

                if isinstance(metric_data, dict):
                    # Collect value field
                    if "value" in metric_data:
                        all_data[test_name][metric_name]["values"].append(
                            metric_data["value"]
                        )
                    # Collect low_value field
                    if (
                        "low_value" in metric_data
                        and metric_data["low_value"] is not None
                    ):
                        all_data[test_name][metric_name]["low_values"].append(
                            metric_data["low_value"]
                        )
                    # Collect high_value field
                    if (
                        "high_value" in metric_data
                        and metric_data["high_value"] is not None
                    ):
                        all_data[test_name][metric_name]["high_values"].append(
                            metric_data["high_value"]
                        )

    # Create aggregated bencher.json using Bencher class
    bf = infra.bencher.Bencher()

    for test_name, metrics in all_data.items():
        LOG.debug(f"Processing: {test_name}")

        for metric_name, metric_collections in metrics.items():
            values = metric_collections["values"]
            low_values = metric_collections["low_values"]
            high_values = metric_collections["high_values"]

            assert values and len(values) > 2
            sorted_values = sorted(values)
            trimmed_values = sorted_values[1:-1]  # Remove first (min) and last (max)
            avg_val = statistics.mean(trimmed_values)
            LOG.trace(
                f"  {metric_name}: trimmed mean from {len(values)} values (excluded min={sorted_values[0]:.1f}, max={sorted_values[-1]:.1f})"
            )

            # Calculate aggregated low_value (minimum of all 'low_value' fields)
            aggregated_low = min(low_values) if low_values else None

            # Calculate aggregated high_value (maximum of all 'high_value' fields)
            aggregated_high = max(high_values) if high_values else None

            LOG.trace(
                f"  {metric_name}: avg={avg_val:.1f}, low={aggregated_low}, high={aggregated_high}"
            )

            # Create appropriate metric object based on metric name
            if metric_name == "throughput":
                metric = infra.bencher.Throughput(
                    avg_val, aggregated_high, aggregated_low
                )
            elif metric_name == "memory":
                metric = infra.bencher.Memory(avg_val, aggregated_high, aggregated_low)
            elif metric_name == "latency":
                metric = infra.bencher.Latency(avg_val, aggregated_high, aggregated_low)
            elif metric_name == "rate":
                metric = infra.bencher.Rate(avg_val, aggregated_high, aggregated_low)
            else:
                assert False, "unknown metrics"

            bf.set(test_name, metric)

    LOG.info(
        "Aggregated bencher.json created with averages, mins, and maxs from all runs"
    )


if __name__ == "__main__":
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    assert iterations >= 3  # Best/worst get thrown away.

    # Run performance tests
    run_performance_tests(iterations)

    # Aggregate results
    aggregate_results(iterations)

    LOG.info(f"All {iterations} iterations completed and aggregated")
