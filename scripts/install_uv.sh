#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

UV_VERSION=0.11.19
install_dir=${1:-/usr/local/bin}

if [[ -x "$install_dir/uv" && -x "$install_dir/uvx" ]] &&
    [[ "$("$install_dir/uv" --version)" == "uv ${UV_VERSION}"* ]]; then
    exit 0
fi

if command -v uv >/dev/null 2>&1 &&
    command -v uvx >/dev/null 2>&1 &&
    [[ "$(uv --version)" == "uv ${UV_VERSION}"* ]]; then
    exit 0
fi

mkdir -p "$install_dir"

curl --proto "=https" --tlsv1.2 -LsSf \
    "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-installer.sh" |
    env UV_INSTALL_DIR="$install_dir" UV_NO_MODIFY_PATH=1 sh

"$install_dir/uv" --version
