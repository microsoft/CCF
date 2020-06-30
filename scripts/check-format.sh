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

file_name_regex="^[[:lower:]0-9_]+$"
unformatted_files=""
badly_named_files=""
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
  file_base_name=$(basename "${file%.*}")
  if ! [[ $file_base_name =~ $file_name_regex ]]; then
    if [ "$badly_named_files" != "" ]; then
      badly_named_files+=$'\n'
    fi
    badly_named_files+="$file"
  fi
done

if [ "$unformatted_files" != "" ]; then
  echo "Fix formatting:"
  echo "$unformatted_files"
  exit 1
else
  echo "All files formatted correctly!"
fi

if [ "$badly_named_files" != "" ]; then
  echo "Fix file name:"
  echo "$badly_named_files"
  exit 2
else
  echo "All files named correctly!"
fi
