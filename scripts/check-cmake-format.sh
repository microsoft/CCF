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

if [ ! -f "scripts/env/bin/activate" ]
    then
        python3 -m venv scripts/env
fi

source scripts/env/bin/activate
pip install -U pip
pip install 'gersemi==0.17.0' 1>/dev/null

FILES=$(git ls-files "$@" | grep -e '\.cmake$' -e 'CMakeLists\.txt$')

if $fix ; then
  # shellcheck disable=SC2086
  gersemi -i $FILES
  echo "All files formatted!"
else
  # shellcheck disable=SC2086
  if gersemi --check $FILES; then
    echo "All files formatted correctly!"
  else
    echo "Fix formatting by running: scripts/cmake-format-checks.sh -f"
    exit 1
  fi
fi