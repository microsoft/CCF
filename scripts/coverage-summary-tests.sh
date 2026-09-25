#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Runs the unit tests for scripts/coverage_summary.py, which renders the
# coverage job summary. Accepts -f for interface compatibility with the other
# checks; there is nothing to fix automatically.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

python3 "$SCRIPT_DIR/tests/coverage_summary_test.py"
