# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import argparse
import cimetrics.upload

from loguru import logger as LOG


def run(filename):
    if os.path.exists(filename):
        with open(filename) as f:
            data = json.load(f)
            duration_sec = data["duration"]
            dstates = data["distinct"]
            LOG.info(
                "Uploading metrics - duration: {}, distinct states: {}",
                duration_sec,
                dstates,
            )
            with cimetrics.upload.metrics(complete=False) as metrics:
                metrics.put("TLC Duration (s)", duration_sec)
                metrics.put("TLC Distinct States", dstates)

    else:
        LOG.warning(f"Could not find file {filename}: skipping metrics upload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Upload TLC stats to cimetrics.")

    parser.add_argument(
        "filename",
        help="TLC stats JSON file to upload",
    )

    args = parser.parse_args()
    run(args.filename)
