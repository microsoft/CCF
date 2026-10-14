#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if [ "${1:-}" == "-f" ]; then
  FIX_ARG="-f"
else
  FIX_ARG=""
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null || exit 1

# GitHub actions workflow commands: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
function group(){
    if [[ ${CI:-} ]]; then
      echo "::group::$1"
    else
      echo "-=[ $1 ]=-"
    fi
}
function endgroup() {
    if [[ ${CI:-} ]]; then
      echo "::endgroup::"
    fi
}

# --- Concurrent execution of all checks ---
# Each check runs as a background job with output captured to a temp file.
# After all jobs complete, outputs are printed in order with CI group annotations.

TMPDIR_CHECKS=$(mktemp -d) || { echo "Failed to create temporary directory for ci-checks" >&2; exit 1; }
trap 'rm -rf "$TMPDIR_CHECKS"' EXIT

# Declare the checks: "group_name:script_name"
CHECKS=(
  "Shell scripts:shellcheck-checks.sh"
  "TODOs:todo-checks.sh"
  "Includes:includes-checks.sh"
  "Release notes:release-notes-checks.sh"
  "Non-ASCII characters:ascii-checks.sh"
  "ASCII policy regression tests:ascii-policy-tests.sh"
  "Devcontainer startup regression test:devcontainer_startup_test.py"
  "C/C++ format:cpp-format-checks.sh"
  "TypeScript, JavaScript, Markdown, TypeSpec, YAML and JSON format:prettier-checks.sh"
  "Documentation newlines:doc-newline-checks.sh"
  "OpenAPI:openapi-checks.sh"
  "Copyright notice headers:copyright-checks.sh"
  "CMake format:cmake-format-checks.sh"
  "Python format:python-format-checks.sh"
  "Python lint:python-lint-checks.sh"
  "Python types:python-types-checks.sh"
  "CI test buckets:test-buckets-checks.sh"
)

SERIAL_FIX_SCRIPTS=(
  "release-notes-checks.sh"
  "prettier-checks.sh"
  "doc-newline-checks.sh"
)

function is_serial_fix_script() {
  local candidate=$1
  local script
  for script in "${SERIAL_FIX_SCRIPTS[@]}"; do
    if [[ "$candidate" == "$script" ]]; then
      return 0
    fi
  done
  return 1
}

function record_failure() {
  local name=$1
  if [[ -z "$FAIL" ]]; then
    FAIL="$name"
  else
    FAIL="$FAIL;$name"
  fi
}

declare -A PID_TO_IDX
for i in "${!CHECKS[@]}"; do
  IFS=: read -r _name script <<< "${CHECKS[$i]}"
  if [[ -n "$FIX_ARG" ]] && is_serial_fix_script "$script"; then
    continue
  fi
  (
    start=$SECONDS
    # shellcheck disable=SC2086
    "$SCRIPT_DIR"/$script $FIX_ARG
    echo $? > "$TMPDIR_CHECKS/$i.rc"
    echo $((SECONDS - start)) > "$TMPDIR_CHECKS/$i.time"
  ) > "$TMPDIR_CHECKS/$i.out" 2>&1 &
  PID_TO_IDX[$!]=$i
done

# Print output from each check as it finishes (no interleaving)
FAIL=""
REMAINING=${#PID_TO_IDX[@]}
while [ "$REMAINING" -gt 0 ]; do
  DONE_PID=""
  wait -n -p DONE_PID "${!PID_TO_IDX[@]}" 2>/dev/null || true
  if [[ -z "$DONE_PID" ]]; then
    break
  fi
  i=${PID_TO_IDX[$DONE_PID]}
  IFS=: read -r name _script <<< "${CHECKS[$i]}"
  rc=$(cat "$TMPDIR_CHECKS/$i.rc")

  group "$name"
  cat "$TMPDIR_CHECKS/$i.out"
  if [ "$rc" != "0" ]; then
    record_failure "$name"
  fi
  endgroup
  unset "PID_TO_IDX[$DONE_PID]"
  REMAINING=$((REMAINING - 1))
done

# Fix scripts that rewrite the same Markdown files must run serially.
if [[ -n "$FIX_ARG" ]]; then
  group "Serial Markdown fixes"
  for i in "${!CHECKS[@]}"; do
    IFS=: read -r name script <<< "${CHECKS[$i]}"
    if ! is_serial_fix_script "$script"; then
      continue
    fi

    echo "- $name"
    start=$SECONDS
    "$SCRIPT_DIR"/"$script" -f > "$TMPDIR_CHECKS/$i.out" 2>&1
    rc=$?
    echo "$rc" > "$TMPDIR_CHECKS/$i.rc"
    echo $((SECONDS - start)) > "$TMPDIR_CHECKS/$i.time"
    cat "$TMPDIR_CHECKS/$i.out"
    if [[ "$rc" != "0" ]]; then
      record_failure "$name"
    fi
  done
  endgroup
fi

group "Timing"
printf "%-70s %6s  %s\n" "Check" "Time" "Status"
printf "%-70s %6s  %s\n" "-----" "----" "------"
for i in "${!CHECKS[@]}"; do
  IFS=: read -r name _script <<< "${CHECKS[$i]}"
  rc=$(cat "$TMPDIR_CHECKS/$i.rc")
  elapsed=$(cat "$TMPDIR_CHECKS/$i.time")
  if [ "$rc" = "0" ]; then
    status="OK"
  else
    status="FAIL"
  fi
  printf "%-70s %5ds  %s\n" "$name" "$elapsed" "$status"
done
endgroup

group "Summary"
if [[ -n "$FAIL" ]]; then
  echo "The following checks failed: ${FAIL//;/, }"
  endgroup
  exit 1
else
  echo "All checks passed"
  endgroup
  exit 0
fi