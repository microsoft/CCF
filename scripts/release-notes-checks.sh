#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Validates release notes formatting.
# Pass -f to auto-fix formatting issues.

set -uo pipefail

if [ "${1:-}" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/extract-release-notes.py -f
else
  "$SCRIPT_DIR"/extract-release-notes.py
fi
