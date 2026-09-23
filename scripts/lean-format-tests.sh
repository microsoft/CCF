#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
TEST_ROOT=$(mktemp -d "$ROOT_DIR/.lean-format-tests.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT

unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_CONFIG_COUNT
export GIT_INDEX_FILE="$TEST_ROOT/index"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
cd "$ROOT_DIR"
git read-tree --empty

# Use an isolated index so these fixtures are the only tracked Lean files.
mkdir -p "$TEST_ROOT/outside lean"
fixture="$TEST_ROOT/outside lean/file with spaces.lean"
hidden="$TEST_ROOT/.hidden.lean"
printf 'def fixtureValue   : Nat:=1\n' > "$fixture"
printf 'def hiddenValue   : Nat:=2\n' > "$hidden"
printf 'def invalid :=\n' > "$TEST_ROOT/untracked.lean"
git add -f -- "$fixture" "$hidden"
cp "$fixture" "$TEST_ROOT/before"
cp "$hidden" "$TEST_ROOT/hidden-before"

check() {
  local expected=$1
  local description=$2
  shift 2
  local actual=0
  local output
  output=$("$SCRIPT_DIR/lean-format-checks.sh" "$@" 2>&1) || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    printf '%s: expected exit %s, got %s\n%s\n' "$description" "$expected" "$actual" "$output" >&2
    exit 1
  fi
}

# Exercise invocation from outside the repository root.
cd "$TEST_ROOT"
check 123 "Reject formatting drift outside lean/, including paths with spaces"
cmp "$fixture" "$TEST_ROOT/before"
cmp "$hidden" "$TEST_ROOT/hidden-before"

check 0 "Fix tracked files, ignoring malformed untracked files" -f
if cmp -s "$fixture" "$TEST_ROOT/before" || cmp -s "$hidden" "$TEST_ROOT/hidden-before"; then
  echo "Fix mode did not format every tracked fixture" >&2
  exit 1
fi
cp "$fixture" "$TEST_ROOT/formatted"
cp "$hidden" "$TEST_ROOT/hidden-formatted"
check 0 "Accept formatted files"
check 0 "Fix mode is idempotent" -f
cmp "$fixture" "$TEST_ROOT/formatted"
cmp "$hidden" "$TEST_ROOT/hidden-formatted"

printf 'def invalid :=\n' > "$fixture"
check 123 "Reject malformed tracked files"
check 123 "Do not hide formatter errors in fix mode" -f

cd "$ROOT_DIR"
git read-tree --empty
check 0 "Accept an empty tracked Lean file list"
printf 'invalid git index\n' > "$GIT_INDEX_FILE"
check 128 "Propagate Git discovery errors"

echo "Lean formatting regression tests passed"
