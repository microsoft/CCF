#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "No args given - specify dir(s) to be formatted"
  exit 1
fi

fix=false
while getopts ":f:" opt; do
  case $opt in
    f)
      fix=true
      shift
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
      exit
    ;;
  esac
done

if $fix ; then
  echo "Formatting files in" "$@"
else
  echo "Checking file format in" "$@"
fi

if [ ! -x "$(command -v uv)" ]; then
  echo "uv is required but not installed. See https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

GERSEMI="uvx gersemi@0.27.0 --warnings-as-errors"

FILES=$(git ls-files "$@" | grep -e '\.cmake$' -e 'CMakeLists\.txt$')

if $fix ; then
  # shellcheck disable=SC2086
  if ! $GERSEMI -i $FILES; then
    echo "Formatting failed (unknown commands or other warnings treated as errors)"
    exit 1
  fi
  echo "All files formatted!"
else
  # shellcheck disable=SC2086
  if $GERSEMI --check $FILES; then
    echo "All files formatted correctly!"
  else
    echo "Fix formatting by running: scripts/cmake-format-checks.sh -f"
    exit 1
  fi
fi