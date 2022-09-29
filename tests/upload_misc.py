# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import cimetrics.upload
import sys
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sum and upload values to cimetrics",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("name", help="Metric name", type=str)
    args = parser.parse_args(sys.argv[1:])

    with cimetrics.upload.metrics(complete=False) as metrics:
        acc = 0.0
        for line in sys.stdin:
            contents = line.strip()
            if contents:
                acc += float(contents)
        metrics.put(args.name, acc)
