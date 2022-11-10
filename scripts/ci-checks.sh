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

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null

CHECK_DELIMITER="---------------------------"

echo "$CHECK_DELIMITER"
echo "-- Shell scripts"
git ls-files | grep -e '\.sh$' | grep -E -v "^3rdparty" | xargs shellcheck -s bash -e SC2044,SC2002,SC1091,SC2181

echo "$CHECK_DELIMITER"
echo "-- TODOs"
"$SCRIPT_DIR"/check-todo.sh include src

echo "$CHECK_DELIMITER"
echo "-- Public includes"
# Enforce that no private headers are included from public header files
violations=$(find "$ROOT_DIR/include/ccf" -type f -print0 | xargs --null grep -e "#include \"" | grep -v "#include \"ccf" | sort)
if [[ -n "$violations" ]]; then
  echo "Public headers include private implementation files:"
  echo "$violations"
  exit 1
else
  echo "No public header violations"
fi

echo "$CHECK_DELIMITER"
echo "-- Release notes"
if [ $FIX -ne 0 ]; then
  python3 "$SCRIPT_DIR"/extract-release-notes.py -f
else
  python3 "$SCRIPT_DIR"/extract-release-notes.py
fi

echo "$CHECK_DELIMITER"
echo "-- C/C++ format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-format.sh -f include src samples
else
  "$SCRIPT_DIR"/check-format.sh include src samples
fi

echo "$CHECK_DELIMITER"
echo "-- TypeScript, JavaScript, Markdown, YAML and JSON format"
npm install --loglevel=error --no-save prettier 1>/dev/null
if [ $FIX -ne 0 ]; then
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | xargs npx prettier --write
else
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | xargs npx prettier --check
fi

echo "$CHECK_DELIMITER"
echo "-- OpenAPI"
npm install --loglevel=error --no-save @apidevtools/swagger-cli 1>/dev/null
find doc/schemas/*.json -exec npx swagger-cli validate {} \;

echo "$CHECK_DELIMITER"
echo "-- Copyright notice headers"
python3.8 "$SCRIPT_DIR"/notice-check.py

echo "$CHECK_DELIMITER"
echo "-- CMake format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-cmake-format.sh -f cmake samples src tests CMakeLists.txt
else
  "$SCRIPT_DIR"/check-cmake-format.sh cmake samples src tests CMakeLists.txt
fi

echo "$CHECK_DELIMITER"
echo "-- Python dependencies"
# Virtual Environment w/ dependencies for Python steps
if [ ! -f "scripts/env/bin/activate" ]
    then
        python3.8 -m venv scripts/env
fi

source scripts/env/bin/activate
pip install -U pip
pip install -U wheel black pylint mypy 1>/dev/null

echo "$CHECK_DELIMITER"
echo "-- Python format"
if [ $FIX -ne 0 ]; then
  git ls-files tests/ python/ scripts/ .cmake-format.py | grep -e '\.py$' | xargs black
else
  git ls-files tests/ python/ scripts/ .cmake-format.py | grep -e '\.py$' | xargs black --check
fi

# Install test dependencies before linting
pip install -U -r tests/requirements.txt 1>/dev/null
pip install -U -r python/requirements.txt 1>/dev/null

echo "$CHECK_DELIMITER"
echo "-- Python lint"
git ls-files tests/ python/ | grep -e '\.py$' | xargs python -m pylint

echo "$CHECK_DELIMITER"
echo "-- Python types"
git ls-files python/ | grep -e '\.py$' | xargs mypy --implicit-optional
