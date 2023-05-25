# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import throughput
from loguru import logger as LOG
from pathlib import Path
import os


def get_throughputs(analyzers):
    throughputs = []
    for piccolo_analyzers in analyzers:
        throughputs.append(sum([analysis.throughput for analysis in piccolo_analyzers]))
    return throughputs


def analyze_results(experiment_dir: Path):
    # TODO: remove hack
    sys.path.insert(0, "/home/azureuser/CCF/tests/perf-system/analyzer")
    import analyzer

    LOG.info(f"Analyzing results in {experiment_dir}")
    analyzers = []
    results_dirs = [
        filename
        for filename in os.listdir(experiment_dir)
        if filename.startswith("writes")
    ]
    write_percentages = [
        int(filename.split("writes")[1].split("%")[0]) for filename in results_dirs
    ]
    write_percentages.sort(reverse=True)

    for write_percentage in write_percentages:
        piccolo_dirs = [
            filename
            for filename in os.listdir(experiment_dir / f"writes{write_percentage}%")
            if filename.startswith("piccolo")
        ]
        piccolo_numbers = [
            int(filename.split("piccolo")[1]) for filename in piccolo_dirs
        ]
        piccolo_analyzers = []
        for piccolo_number in piccolo_numbers:
            analyze = analyzer.default_analysis_with_default_filenames(
                experiment_dir
                / f"writes{write_percentage}%"
                / f"piccolo{piccolo_number}",
                error_on_failure=True,
            )
            piccolo_analyzers.append(analyze)
        analyzers.append(piccolo_analyzers)

    read_labels = [f"{100 - w}%" for w in write_percentages]
    throughput.plot_throughput_comparision(
        get_throughputs(analyzers),
        read_labels,
        experiment_dir,
    )
    return analyzers
