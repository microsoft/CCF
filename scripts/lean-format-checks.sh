#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) all tracked Lean files via leanfmt.
# Pass -f to auto-fix formatting issues. Pass Lean package directories to check
# only the files those packages format; by default all are checked.
#
# Each file is formatted by the pinned leanfmt of the package containing it,
# because leanfmt loads the file's imported modules to parse project-specific
# syntax. Files outside a listed package, including the shared lean/common
# modules that disaster recovery depends on, are formatted by the first package.

set -euo pipefail

FORMAT_ARGS=(--check)
if [ "${1:-}" == "-f" ]; then
  FORMAT_ARGS=()
  shift
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )

PACKAGES=(lean/disaster-recovery lean/kv)

if ! command -v lake >/dev/null 2>&1; then
  echo "lake is required. Install Lean via elan: https://lean-lang.org/install/" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- "${PACKAGES[@]}"
fi

for PACKAGE in "$@"; do
  PACKAGE="${PACKAGE%/}"
  PATHSPECS=("$PACKAGE/*.lean")
  if [ "$PACKAGE" == "${PACKAGES[0]}" ]; then
    PATHSPECS=('*.lean')
    for OTHER in "${PACKAGES[@]:1}"; do
      PATHSPECS+=(":(exclude)$OTHER/*")
    done
  fi
  cd "$ROOT_DIR/$PACKAGE"
  # leanfmt loads imported modules to parse project-specific syntax.
  lake build
  git -C "$ROOT_DIR" ls-files -z -- "${PATHSPECS[@]}" |
    while IFS= read -r -d '' file; do
      printf '%s\0' "$ROOT_DIR/$file"
    done |
    xargs -0 -r lake exe fmt --jobs "$(( ($(nproc) + 1) >> 1 ))" "${FORMAT_ARGS[@]}"
done
