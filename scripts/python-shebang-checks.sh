#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks that tracked Python scripts keep shebang lines and executable bits in sync.
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

"$SCRIPT_DIR"/python-shebang-check.py
