#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks Python type annotations via mypy.
# Accepts -f for interface consistency, but no auto-fix is available.

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR" || exit 1

# Ensure venv exists and activate (uses a dedicated venv to allow concurrent runs)
if [ ! -f "scripts/env-types/bin/activate" ]; then
  python3 -m venv scripts/env-types
fi
source scripts/env-types/bin/activate

pip install -U pip > /dev/null || exit 1
pip install -U wheel pytest-mypy mypy 1>/dev/null || exit 1
pip install -U -e python 1>/dev/null || exit 1

git ls-files python/ | grep -e '\.py$' | xargs mypy
