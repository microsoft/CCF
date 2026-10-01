#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks (and optionally fixes) all tracked Lean files via leanfmt.
# Pass -f to auto-fix formatting issues. Pass package names under lean/ to
# check only those packages; the default checks every package.

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

declare -A LIBRARIES=([disaster-recovery]=DisasterRecovery [ccf-raft]=CCFRaft)
PACKAGES=("$@")
if [ ${#PACKAGES[@]} -eq 0 ]; then
  PACKAGES=(disaster-recovery ccf-raft)
fi

for package in "${PACKAGES[@]}"; do
  library="${LIBRARIES[$package]:-}"
  if [ -z "$library" ]; then
    echo "Unknown Lean package: $package" >&2
    exit 1
  fi
  # The disaster recovery package also checks Lean files outside lean/.
  if [ "$package" == "disaster-recovery" ]; then
    PATHSPEC=("*.lean" ":(exclude)lean/ccf-raft/*")
  else
    PATHSPEC=("lean/$package/*.lean")
  fi
  (
    cd "$ROOT_DIR/lean/$package"
    # leanfmt loads imported modules to parse project-specific syntax.
    lake build "$library"
    git -C "$ROOT_DIR" ls-files -z -- "${PATHSPEC[@]}" |
      while IFS= read -r -d '' file; do
        printf '%s\0' "$ROOT_DIR/$file"
      done |
      xargs -0 -r lake exe fmt --jobs "$(( ($(nproc) + 1) >> 1 ))" "${FORMAT_ARGS[@]}"
  )
done
