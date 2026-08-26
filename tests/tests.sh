#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3 -m venv --without-pip env
fi

bash ../scripts/install_uv.sh env/bin
source env/bin/activate
if [ -n "${PIP_INDEX_URL:-}" ] && [ -z "${UV_INDEX_URL:-}" ]; then
    export UV_INDEX_URL="$PIP_INDEX_URL"
fi
uv pip install -q -e ../python/
uv pip install -q -r ../tests/requirements.txt
echo "Python environment successfully setup"

# Export where the VENV has been set, so tests running
# a sandbox.sh can inherit it rather create a new one
VENV_DIR=$(realpath env)
export VENV_DIR="$VENV_DIR"

# Enable https://github.com/Qix-/better-exceptions
export BETTER_EXCEPTIONS=1

ctest "$@"
