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

CMAKE_FORMAT="uvx --from cmake-format==0.6.11 cmake-format"

# Collect the file list once
mapfile -t files < <(git ls-files "$@" | grep -e '\.cmake$' -e 'CMakeLists\.txt$')

if [ "${#files[@]}" -eq 0 ]; then
  echo "All files formatted correctly!"
  exit 0
fi

# Check formatting in a single invocation (stderr has "Check failed: <file>")
unformatted_files=$($CMAKE_FORMAT --check "${files[@]}" 2>&1 1>/dev/null | \
  sed -n 's/.*Check failed: //p' | sort) || true

if $fix && [ "$unformatted_files" != "" ]; then
  # shellcheck disable=SC2086
  $CMAKE_FORMAT -i $unformatted_files
fi

if [ "$unformatted_files" != "" ]; then
  if $fix ; then
    echo "Formatted files:"
  else
    echo "Fix formatting:"
  fi

  echo "$unformatted_files"
  exit 1
else
  echo "All files formatted correctly!"
fi