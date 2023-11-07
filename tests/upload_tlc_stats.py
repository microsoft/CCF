# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import argparse
import cimetrics.upload

from loguru import logger as LOG


def run(test_label, filename):
    if os.path.exists(filename):
        with open(filename) as f:
            data = json.load(f)
            duration_sec = data["duration"]
            dstates = data["distinct"]
            LOG.info(
                "Uploading metrics for {} - duration: {}, distinct states: {}",
                test_label,
                duration_sec,
                dstates,
            )
            with cimetrics.upload.metrics(complete=False) as metrics:
                metrics.put(f"tlc_{test_label}_duration_s", duration_sec)
                metrics.put(f"tlc_{test_label}_states", dstates)

    else:
        LOG.warning(f"Could not find file {filename}: skipping metrics upload")


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
