#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) all tracked Lean files via leanfmt.
# Pass -f to auto-fix formatting issues.

set -euo pipefail

FORMAT_ARGS=(--check)
if [ "${1:-}" == "-f" ]; then
  FORMAT_ARGS=()
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
cd "$ROOT_DIR/lean/disaster-recovery"

if ! command -v lake >/dev/null 2>&1; then
  echo "lake is required. Install Lean via elan: https://lean-lang.org/install/" >&2
  exit 1
fi

# leanfmt loads imported modules to parse project-specific syntax.
lake build DisasterRecovery

git -C "$ROOT_DIR" ls-files -z -- '*.lean' |
  while IFS= read -r -d '' file; do
    printf '%s\0' "$ROOT_DIR/$file"
  done |
  xargs -0 -r lake exe fmt --jobs "$(( ($(nproc) + 1) >> 1 ))" "${FORMAT_ARGS[@]}"
