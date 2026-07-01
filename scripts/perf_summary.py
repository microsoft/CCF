# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import sys

from perf_report import CHART_MAX_POINTS, list_perf_files, load_perf_data
from perf_report import render_perf_summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarise perf data files as markdown for a job summary."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="perf",
        help="Directory containing the perf data files (default: perf)",
    )
    args = parser.parse_args()

    files = list_perf_files(args.directory)
    recent = files[-CHART_MAX_POINTS:]
    loaded = load_perf_data(args.directory, recent)
    print(render_perf_summary(loaded))


if __name__ == "__main__":
    sys.exit(main())
