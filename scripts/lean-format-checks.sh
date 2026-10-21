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

declare -A LIBRARIES=([disaster-recovery]=DisasterRecovery [ccf-raft]=CCFRaft [shamir]=Shamir)
PACKAGES=("$@")
if [ ${#PACKAGES[@]} -eq 0 ]; then
  PACKAGES=(disaster-recovery ccf-raft shamir)
fi

for package in "${PACKAGES[@]}"; do
  library="${LIBRARIES[$package]:-}"
  if [ -z "$library" ]; then
    echo "Unknown Lean package: $package" >&2
    exit 1
  fi
  # The disaster recovery package also checks Lean files outside lean/.
  if [ "$package" == "disaster-recovery" ]; then
    PATHSPEC=("*.lean" ":(exclude)lean/ccf-raft/*" ":(exclude)lean/shamir/*")
  elif [ "$package" == "shamir" ]; then
    # Preserve the extractor's exact output for reproducibility checks.
    PATHSPEC=("lean/shamir/*.lean" ":(exclude)lean/shamir/Generated/*" ":(exclude)lean/shamir/Generated.lean")
  else
    PATHSPEC=("lean/$package/*.lean")
  fi
  (
    cd "$ROOT_DIR/lean/$package"
    jobs="$(( ($(nproc) + 1) >> 1 ))"
    # leanfmt loads imported modules to parse project-specific syntax.
    if [ "$package" == "shamir" ]; then
      export LEAN_NUM_THREADS=1
      jobs=1
      # ListDeclarations.lean imports the Generated root as well as Shamir.
      lake build Generated "$library"
    else
      lake build "$library"
    fi
    git -C "$ROOT_DIR" ls-files -z -- "${PATHSPEC[@]}" |
      while IFS= read -r -d '' file; do
        printf '%s\0' "$ROOT_DIR/$file"
      done |
      xargs -0 -r lake exe fmt --jobs "$jobs" "${FORMAT_ARGS[@]}"
  )
done
