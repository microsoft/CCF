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

echo "Checking file format in" "$@"

unformatted_files=""
for file in $(find "$@" -name "*.h" -or -name "*.hpp" -or -name "*.cpp" -or -name "*.c"); do
  # Workaround for https://bugs.llvm.org/show_bug.cgi?id=39216
  d=$(cat "$file" | clang-format-7 -style=file --assume-filename "${file%.*}".cpp | diff "$file" -)
  if $fix ; then
    cat "$file" | clang-format-7 -style=file --assume-filename "${file%.*}".cpp > "$file".tmp
    mv "$file".tmp "$file"
  fi
  if [ "$d" != "" ]; then
    if [ "$unformatted_files" != "" ]; then
      unformatted_files+=$'\n'
    fi
    unformatted_files+="$file"
  fi
done

if [ "$unformatted_files" != "" ]; then
  echo "$unformatted_files"
  exit 1
else
  echo "All files formatted correctly"
fi
