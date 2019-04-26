#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -u

unformatted_files=""
for f in $(find src -name "*.h" -o -name "*.hpp" -o -name "*.cpp" -name "*.c"); do
  # Workaround for https://bugs.llvm.org/show_bug.cgi?id=39216
  d=$(cat "$f" | clang-format-7 -style=file --assume-filename "$f".cpp | diff "$f" -)
  if [ "$d" != "" ]; then
    if [ "$unformatted_files" != "" ]; then
      unformatted_files+=$'\n'
    fi
    unformatted_files+="$f"
  fi
done

if [ "$unformatted_files" != "" ]; then
  echo "$unformatted_files"
  exit 1
fi
