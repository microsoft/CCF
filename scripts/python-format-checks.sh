#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) Python formatting via black.
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

# Ensure venv exists and activate (uses a dedicated venv to allow concurrent runs)
if [ ! -f "scripts/env-format/bin/activate" ]; then
  python3 -m venv scripts/env-format
fi
source scripts/env-format/bin/activate

pip install -U pip > /dev/null || exit 1
pip install -U wheel black 1>/dev/null || exit 1

if [ $FIX -ne 0 ]; then
  git ls-files tests/ python/ scripts/ tla/ .cmake-format.py | grep -e '\.py$' | xargs black
else
  git ls-files tests/ python/ scripts/ tla/ .cmake-format.py | grep -e '\.py$' | xargs black --check
fi
