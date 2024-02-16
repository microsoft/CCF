#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Extract a summary of the last line in a trace, useful when finding out where a scenario has mismatched

if [ -e "$1" ]; then
    cat "$1" | jq '.action | last | .[2][1]._logline | "Last matched [" + .h_ts + "] " + .msg.function + " (" + .cmd + ")"' | xargs
    exit 1
fi
exit 0