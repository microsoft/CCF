#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PRINT_IMPORTS=false
if [ "${1:-}" = "--print-imports" ]; then
  PRINT_IMPORTS=true
  shift
fi
PACKAGE="${1:-$(basename "$PWD")}"

if [ "$#" -gt 1 ]; then
  echo "Usage: bash scripts/lean-setup.sh [--print-imports] [package]" >&2
  exit 1
fi

case "$PACKAGE" in
  common|kv|consistency|disaster-recovery|consensus) ;;
  *)
    echo "Unsupported Lean package: $PACKAGE" >&2
    exit 1
    ;;
esac

PACKAGE_DIR="$ROOT_DIR/lean/$PACKAGE"
imports="$(find "$PACKAGE_DIR" "$ROOT_DIR/lean/common" \
  -type d -name .lake -prune -o \
  -type f -name '*.lean' -exec sed -nE \
  "s/^[[:space:]]*((public|private|meta)[[:space:]]+)*import[[:space:]]+(all[[:space:]]+)?((Mathlib|Batteries)\.[[:alnum:]_'.]+)[[:space:]]*(--.*)?$/\4/p" \
  {} +)"

if [ -z "$imports" ]; then
  echo "No Mathlib or Batteries imports found for $PACKAGE; refusing a full cache fetch." >&2
  exit 1
fi

case "$PACKAGE" in
  kv|disaster-recovery)
    # Dependencies of Batteries' runLinter executable.
    imports+=$'\nBatteries.Data.Array.Basic\nBatteries.Tactic.Lint'
    ;;
esac
imports="$(printf '%s\n' "$imports" | sort -u)"
mapfile -t modules <<< "$imports"

if [ "$PRINT_IMPORTS" = true ]; then
  printf '%s\n' "${modules[@]}"
  exit 0
fi

shared="$ROOT_DIR/lean/.lake/packages"
link="$PACKAGE_DIR/.lake/packages"
mkdir -p "$shared" "$PACKAGE_DIR/.lake"

# Mathlib redirects its own cache, but other archives use .lake/packages.
if [ -L "$link" ]; then
  if [ "$(readlink -f "$link")" != "$shared" ]; then
    echo "Dependency symlink points elsewhere: $link" >&2
    exit 1
  fi
elif [ -e "$link" ]; then
  echo "Move the existing dependency directory aside before setup: $link" >&2
  exit 1
else
  ln -s ../../.lake/packages "$link"
fi

cd "$PACKAGE_DIR"
lake exe cache get "${modules[@]}"
