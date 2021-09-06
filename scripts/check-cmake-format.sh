#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -u

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
        python3.8 -m venv scripts/env
fi

source scripts/env/bin/activate
pip install -U pip
pip install cmake_format==0.6.11 1>/dev/null

unformatted_files=""
for file in $(git ls-files "$@" | grep -e '\.cmake$' -e 'CMakeLists\.txt$'); do
  cmake-format --check "$file" > /dev/null
  d=$?
  if $fix ; then
    cmake-format -i "$file"
  fi
  if [ $d -ne 0 ]; then
    if [ "$unformatted_files" != "" ]; then
      unformatted_files+=$'\n'
    fi
    unformatted_files+="$file"
  fi
done

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