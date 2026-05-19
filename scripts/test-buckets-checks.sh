#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Verifies that the e2e tests in each ctest CI runner bucket (bucket_a,
# bucket_b, bucket_c) match the frozen snapshot at tests/ci-buckets.txt.
# Unit tests are excluded (runner A selects them with `ctest -L unit`).

set -uo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
SNAPSHOT="$ROOT_DIR/tests/ci-buckets.txt"

cd "$ROOT_DIR" || exit 1

# Always configure a fresh build dir with default flags. If the defaults
# change in a way that shifts test inventory, the snapshot diff will catch it.
BUILD_DIR=$(mktemp -d) || { echo "mktemp failed" >&2; exit 1; }
ACTUAL=$(mktemp) || { echo "mktemp failed" >&2; rm -rf "$BUILD_DIR"; exit 1; }
trap 'rm -rf "$BUILD_DIR"; rm -f "$ACTUAL"' EXIT

echo "Configuring build dir for bucket check: $BUILD_DIR"
if ! cmake -GNinja -S "$ROOT_DIR" -B "$BUILD_DIR" \
      >"$BUILD_DIR/configure.log" 2>&1; then
  cat "$BUILD_DIR/configure.log" >&2
  echo "cmake configure failed; cannot run test bucket check" >&2
  exit 1
fi

ctest_names() {
  # ctest -N lines look like "  Test  #12: foo_test"; take the last field.
  (cd "$BUILD_DIR" && ctest -N "$@" 2>/dev/null) \
    | grep -E "^[[:space:]]*Test +#" \
    | awk '{print $NF}'
}

emit_bucket() {
  local bucket="$1"
  echo "${bucket}:"
  ctest_names -L "^${bucket}\$" | sed 's/^/  /'
  echo
}

# Tests not labeled `unit` and not in any bucket_*. A new e2e test added
# without BUCKET lands here, making the regression obvious in the diff.
emit_no_bucket() {
  echo "no_bucket:"
  awk 'NR==FNR{seen[$0]=1; next} !seen[$0]' \
    <(ctest_names -L 'bucket_'; ctest_names -L 'unit') \
    <(ctest_names) \
    | sed 's/^/  /'
  echo
}

{
  emit_bucket bucket_a
  emit_bucket bucket_b
  emit_bucket bucket_c
  emit_no_bucket
} > "$ACTUAL"

if [ ! -f "$SNAPSHOT" ]; then
  echo "Snapshot file missing: $SNAPSHOT" >&2
  exit 1
fi

if ! diff -q "$SNAPSHOT" "$ACTUAL" >/dev/null; then
  {
    echo
    echo "ERROR: CI test bucket inventory diverged from $SNAPSHOT."
    echo
    echo "=== Current snapshot ($SNAPSHOT) ==="
    cat "$SNAPSHOT"
    echo "=== Actual ==="
    cat "$ACTUAL"
    echo
    echo "If the change is intentional, replace $SNAPSHOT with the Actual block above."
  } >&2
  exit 1
fi

echo "Test buckets match snapshot ✓"
