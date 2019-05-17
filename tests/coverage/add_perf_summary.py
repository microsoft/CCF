# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import time
import json

with open("coverage.json", "r") as file:
    timestamp = str(int(time.time()))
    data = json.load(file)["data"][0]
    lines_covered = str(data["totals"]["lines"]["covered"])
    lines_valid = str(data["totals"]["lines"]["count"])

with open("perf_summary.csv", "a") as f:
    f.write(
        timestamp
        + ","
        + lines_valid
        + ",Unit_Test_Coverage,0,0,0,"
        + lines_covered
        + ",0,0,0,0"
    )
