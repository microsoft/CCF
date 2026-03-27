#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) Python formatting via black.
# Pass -f to auto-fix formatting issues.

set -euo pipefail

if [ "${1:-}" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

if [ ! -x "$(command -v uv)" ]; then
  echo "uv is required but not installed. See https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

if [ $FIX -ne 0 ]; then
  git ls-files tests/ python/ scripts/ tla/ .cmake-format.py | grep -e '\.py$' | xargs uvx black
else
  git ls-files tests/ python/ scripts/ tla/ .cmake-format.py | grep -e '\.py$' | xargs uvx black --check
fi
