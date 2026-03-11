#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

echo "Setting up Python environment..."
uv sync --project ../tests
source ../tests/.venv/bin/activate
echo "Python environment successfully setup"

# Export where the VENV has been set, so tests running
# a sandbox.sh can inherit it rather create a new one
VENV_DIR=$(realpath ../tests/.venv)
export VENV_DIR="$VENV_DIR"

# Enable https://github.com/Qix-/better-exceptions
export BETTER_EXCEPTIONS=1

ctest "$@"
