#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Verifies that the e2e tests in each ctest CI runner bucket (bucket_a,
# bucket_b, bucket_c) match the frozen snapshot at tests/ci-buckets.txt.
#
# Catches:
#   * an e2e test silently dropped from a bucket (regression of CI coverage),
#   * an e2e test silently moved between buckets (load imbalance),
#   * a new e2e test added without a BUCKET argument — it appears in the
#     `no_bucket:` section instead of bucket_a/b/c.
#
# Unit tests are intentionally NOT bucketed: runner A selects them with
# `ctest -L unit`, so a new unit test can't be missed accidentally. Anything
# matching `-L unit` is excluded from the `no_bucket:` listing.
#
# Buckets are assigned via the BUCKET argument of add_e2e_test (see
# cmake/common.cmake) plus explicit set_property calls in CMakeLists.txt,
# and consumed by .github/workflows/ci.yml as `-L bucket_X`.
#
# The snapshot is captured for the default CMake configuration (no LONG_TESTS,
# no SAN, no COVERAGE, no CLIENT_PROTOCOLS_TEST) which is what the PR CI
# runners use.
#
# Usage:
#   scripts/test-buckets-checks.sh        # verify; fail with diff on mismatch
#   scripts/test-buckets-checks.sh -f     # regenerate the snapshot
#
# If a build/ directory is already configured with default flags, it is
# reused for speed; otherwise a fresh build directory is configured in
# $TMPDIR (which requires the project build dependencies to be installed).

set -uo pipefail

if [ "${1:-}" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
SNAPSHOT="$ROOT_DIR/tests/ci-buckets.txt"

cd "$ROOT_DIR" || exit 1

# Detect whether an existing build/ is usable. It must have the default flags
# (no LONG_TESTS, no SAN, no COVERAGE, no CLIENT_PROTOCOLS_TEST) so the
# inventory matches what PR CI sees.
build_dir_matches_defaults() {
  local cache="$1/CMakeCache.txt"
  [ -f "$cache" ] || return 1
  grep -q "^LONG_TESTS:BOOL=OFF" "$cache" || return 1
  grep -q "^SAN:BOOL=OFF" "$cache" || return 1
  grep -q "^COVERAGE:BOOL=OFF" "$cache" || return 1
  grep -q "^CLIENT_PROTOCOLS_TEST:BOOL=OFF" "$cache" || return 1
}

CLEANUP_BUILD=""
if build_dir_matches_defaults "$ROOT_DIR/build"; then
  BUILD_DIR="$ROOT_DIR/build"
  echo "Using existing build dir: $BUILD_DIR"
else
  BUILD_DIR=$(mktemp -d) || { echo "mktemp failed" >&2; exit 1; }
  CLEANUP_BUILD="$BUILD_DIR"
  echo "Configuring fresh build dir for bucket check: $BUILD_DIR"
  if ! cmake -GNinja -S "$ROOT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug \
        >"$BUILD_DIR/configure.log" 2>&1; then
    cat "$BUILD_DIR/configure.log" >&2
    echo "cmake configure failed; cannot run test bucket check" >&2
    rm -rf "$CLEANUP_BUILD"
    exit 1
  fi
fi

ACTUAL=$(mktemp) || { echo "mktemp failed" >&2; [ -n "$CLEANUP_BUILD" ] && rm -rf "$CLEANUP_BUILD"; exit 1; }
trap '[ -n "$CLEANUP_BUILD" ] && rm -rf "$CLEANUP_BUILD"; rm -f "$ACTUAL"' EXIT

ctest_names() {
  # Extract test names from `ctest -N` output. ctest -N lines look like
  #   "  Test  #12: foo_test", so we take the last whitespace-separated field.
  (cd "$BUILD_DIR" && ctest -N "$@" 2>/dev/null) \
    | grep -E "^[[:space:]]*Test +#" \
    | awk '{print $NF}' \
    | sort -u
}

emit_bucket() {
  local bucket="$1"
  echo "${bucket}:"
  ctest_names -L "^${bucket}\$" | sed 's/^/  /'
  echo
}

# Tests that are neither labeled `unit` (handled by runner A's `-L unit`) nor
# placed in any bucket_* (handled by runners A/B/C's `-L bucket_X`). A new e2e
# test added without BUCKET will land here, making the regression obvious in
# the diff. Known-intentional residents are benchmarks (run in bencher
# workflows) and *_suite tests (run in long-test workflow).
emit_no_bucket() {
  local all bucketed unit_tests
  all=$(ctest_names)
  bucketed=$(ctest_names -L 'bucket_')
  unit_tests=$(ctest_names -L 'unit')
  echo "no_bucket:"
  comm -23 <(echo "$all") <(printf '%s\n%s\n' "$bucketed" "$unit_tests" | sort -u) \
    | sed 's/^/  /'
  echo
}

{
  cat <<'EOF'
# Frozen snapshot of CI e2e test bucket membership. Edited by
# scripts/test-buckets-checks.sh; do not hand-edit.
#
# Unit tests are not listed: they are selected with `ctest -L unit` and
# don't need explicit bucketing. Anything labeled `unit` is excluded from
# the no_bucket: section below.
#
# Buckets are assigned via add_e2e_test BUCKET (cmake/common.cmake) and
# consumed by .github/workflows/ci.yml as -L bucket_a/b/c.
#
# Snapshot is for the default CMake config (no LONG_TESTS, SAN, COVERAGE,
# CLIENT_PROTOCOLS_TEST). Tests gated by those flags do not appear here.
#
# To regenerate after an intentional change:
#   ./scripts/test-buckets-checks.sh -f

EOF
  emit_bucket bucket_a
  emit_bucket bucket_b
  emit_bucket bucket_c
  emit_no_bucket
} > "$ACTUAL"

if [ "$FIX" -eq 1 ]; then
  mv "$ACTUAL" "$SNAPSHOT"
  # Recreate the trap target so EXIT cleanup doesn't fail on the moved file.
  ACTUAL=""
  trap '[ -n "$CLEANUP_BUILD" ] && rm -rf "$CLEANUP_BUILD"' EXIT
  echo "Updated snapshot: $SNAPSHOT"
  exit 0
fi

if [ ! -f "$SNAPSHOT" ]; then
  echo "Snapshot file missing: $SNAPSHOT" >&2
  echo "Create one with: $0 -f" >&2
  exit 1
fi

if ! diff -u "$SNAPSHOT" "$ACTUAL"; then
  cat <<EOF >&2

ERROR: CI test bucket inventory diverged from $SNAPSHOT.

Lines marked '-' are missing from (or moved out of) the current build;
lines marked '+' are new (or moved in).

If the change is intentional, regenerate the snapshot:
  $0 -f

Common pitfall: a new add_e2e_test() call without a BUCKET argument will
appear under 'no_bucket:' instead of one of the e2e buckets. Add
'BUCKET bucket_a' (or bucket_b / bucket_c) to the call.
EOF
  exit 1
fi

echo "Test buckets match snapshot ✓"
