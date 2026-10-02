#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) the tracked Lean files of each Lean package via
# the package's pinned leanfmt. Pass -f to auto-fix formatting issues. Pass
# package directories to check only those packages; by default all are checked.

set -euo pipefail

FORMAT_ARGS=(--check)
if [ "${1:-}" == "-f" ]; then
  FORMAT_ARGS=()
  shift
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )

if ! command -v lake >/dev/null 2>&1; then
  echo "lake is required. Install Lean via elan: https://lean-lang.org/install/" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- lean/disaster-recovery lean/kv
fi

for PACKAGE in "$@"; do
  cd "$ROOT_DIR/$PACKAGE"
  # leanfmt loads imported modules to parse project-specific syntax.
  lake build
  git ls-files -z -- '*.lean' |
    xargs -0 -r lake exe fmt --jobs "$(( ($(nproc) + 1) >> 1 ))" "${FORMAT_ARGS[@]}"
done
