#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) Python linting via ruff.
# Pass -f to auto-fix lint issues.

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
if [ ! -f "scripts/env-lint/bin/activate" ]; then
  python3 -m venv scripts/env-lint
fi
source scripts/env-lint/bin/activate

pip install -U pip > /dev/null || exit 1
pip install -U wheel ruff 1>/dev/null || exit 1
pip install -U -r tests/requirements.txt 1>/dev/null || exit 1
pip install -U -e python 1>/dev/null || exit 1

if [ $FIX -ne 0 ]; then
  ruff check --fix python/ tests/
else
  ruff check python/ tests/
fi
