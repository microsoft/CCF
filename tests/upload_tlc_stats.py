# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import argparse
import cimetrics.upload


def run(test_label, filename):
    if os.path.exists(filename):
        with open(filename) as f:
            data = json.load(f)
            duration_sec = data["duration"]
            dstates = data["distinct"]
            traces = data.get("traces", 0)
            levelmean = data.get("levelmean", 0)
            print(f"Uploading metrics for {test_label}: {data}")
            # https://github.com/microsoft/CCF/issues/6126
            # if dstates == -1:
            #     # Simulation
            #     with cimetrics.upload.metrics(complete=False) as metrics:
            #         metrics.put(f"tlc_{test_label}_traces", traces)
            #         metrics.put(f"tlc_{test_label}_levelmean", levelmean)
            # else:
            #     # Model checking
            #     with cimetrics.upload.metrics(complete=False) as metrics:
            #         metrics.put(f"tlc_{test_label}_duration_s", duration_sec)
            #         metrics.put(f"tlc_{test_label}_states", dstates)

    else:
        print(f"Could not find file {filename}: skipping metrics upload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Upload TLC stats to cimetrics.")

    parser.add_argument(
        "test_label",
        help="test name to upload metrics under",
    )

    parser.add_argument(
        "filename",
        help="TLC stats JSON file to upload",
    )

    args = parser.parse_args()
    run(args.test_label, args.filename)
