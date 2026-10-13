#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
MODEL_DIR=$( dirname "$SCRIPT_DIR" )
CHECK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ccf-replayer-kernels.XXXXXX")
trap 'rm -rf -- "$CHECK_DIR"' EXIT

# The sandbox masks parent sources outside the package. Stage identical sources
# inside it, changing only the library's relative source directory.
cp "$SCRIPT_DIR/lakefile.toml" "$SCRIPT_DIR/lake-manifest.json" \
  "$SCRIPT_DIR/Main.lean" "$MODEL_DIR/lean-toolchain" "$CHECK_DIR/"
cp -R "$MODEL_DIR/DisasterRecovery" "$CHECK_DIR/"
sed -i 's/^srcDir = "\.\."$/srcDir = "."/' "$CHECK_DIR/lakefile.toml"

cd "$CHECK_DIR"
lake check --paranoid
