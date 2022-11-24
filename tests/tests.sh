#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3.8 -m venv env
fi

source env/bin/activate
pip install -U -q pip
pip install -q -U -e ../python/
pip install -q -U -r ../tests/requirements.txt
pip install -q -U -r ../tests/perf-system/requirements.txt
echo "Python environment successfully setup"

# Export where the VENV has been set, so tests running
# a sandbox.sh can inherit it rather create a new one
VENV_DIR=$(realpath env)
export VENV_DIR="$VENV_DIR"

# Enable https://github.com/Qix-/better-exceptions
export BETTER_EXCEPTIONS=1

ctest "$@"
