#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if [ "${1:-}" == "-f" ]; then
  FIX_ARG="-f"
else
  FIX_ARG=""
fi

# List of failed groups
FAIL=""

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null || exit 1

# GitHub actions workflow commands: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
function group(){
    # Track current group name
    CURRENT_GROUP="$1"
    # Only do this in GitHub actions, where CI is defined according to
    # https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
    if [[ ${CI} ]]; then
      echo "::group::$1"
    else
      echo "-=[ $1 ]=-"
    fi
}
function endgroup() {
    if [[ ${CI} ]]; then
      echo "::endgroup::"
    fi
}

# Helper to record a failing group
function fail() {
  if [[ -z "$FAIL" ]]; then
    FAIL="$CURRENT_GROUP"
  else
    FAIL="$FAIL;$CURRENT_GROUP"
  fi
  return 0
}

group "Shell scripts"
"$SCRIPT_DIR"/shellcheck-checks.sh $FIX_ARG || fail
endgroup

group "TODOs"
"$SCRIPT_DIR"/todo-checks.sh $FIX_ARG || fail
endgroup

group "Includes"
"$SCRIPT_DIR"/includes-checks.sh $FIX_ARG || fail
endgroup

group "Release notes"
"$SCRIPT_DIR"/release-notes-checks.sh $FIX_ARG || fail
endgroup

group "C/C++ format"
"$SCRIPT_DIR"/cpp-format-checks.sh $FIX_ARG || fail
endgroup

group "TypeScript, JavaScript, Markdown, TypeSpec, YAML and JSON format"
"$SCRIPT_DIR"/prettier-checks.sh $FIX_ARG || fail
endgroup

group "OpenAPI"
"$SCRIPT_DIR"/openapi-checks.sh $FIX_ARG || fail
endgroup

group "Copyright notice headers"
"$SCRIPT_DIR"/copyright-checks.sh $FIX_ARG || fail
endgroup

group "CMake format"
"$SCRIPT_DIR"/cmake-format-checks.sh $FIX_ARG || fail
endgroup

group "Python format"
"$SCRIPT_DIR"/python-format-checks.sh $FIX_ARG || fail
endgroup

group "Python lint"
"$SCRIPT_DIR"/python-lint-checks.sh $FIX_ARG || fail
endgroup

group "Python types"
"$SCRIPT_DIR"/python-types-checks.sh $FIX_ARG || fail
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