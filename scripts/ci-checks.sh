#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$1" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Shell scripts"
find . -type f -regex ".*\.sh$" | grep -E -v "^./(3rdparty|build)" | xargs shellcheck -s bash -e SC2044,SC2002,SC1091,SC2181

echo "TODOs"
"$SCRIPT_DIR"/check-todo.sh src

echo "C/C++ format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-format.sh -f src samples
else
  "$SCRIPT_DIR"/check-format.sh src samples
fi

echo "Copyright notice headers"
python3.8 "$SCRIPT_DIR"/notice-check.py

echo "CMake format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-cmake-format.sh -f cmake samples src tests CMakeLists.txt
else
  "$SCRIPT_DIR"/check-cmake-format.sh cmake samples src tests CMakeLists.txt
fi

# Virtual Environment w/ dependencies for Python steps
if [ ! -f "scripts/env/bin/activate" ]
    then
        python3.8 -m venv scripts/env
fi

source scripts/env/bin/activate
pip --disable-pip-version-check install -U black pylint mypy 1>/dev/null

echo "Python format"
if [ $FIX -ne 0 ]; then
  black python/ tests/ scripts/*.py .cmake-format.py
else
  black --check python/ tests/ scripts/*.py .cmake-format.py
fi

# Install test dependencies before linting
pip --disable-pip-version-check install -U -r tests/requirements.txt 1>/dev/null
pip --disable-pip-version-check install -U -r python/requirements.txt 1>/dev/null

echo "Python lint"
find tests/ python/ -type f -name "*.py" -exec python -m pylint {} +

echo "Python types"
mypy python/