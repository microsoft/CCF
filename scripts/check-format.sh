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

CLANG_FORMAT=clang-format
if [ -x "$(command -v clang-format-10)" ]; then
    CLANG_FORMAT=clang-format-10
fi
if [ -x "$(command -v clang-format-12)" ]; then
    CLANG_FORMAT=clang-format-12
fi

file_name_regex="^[[:lower:]0-9_]+$"
unformatted_files=""
badly_named_files=""
for file in $(git ls-files "$@" | grep -e '\.h$' -e '\.hpp$' -e '\.cpp$' -e '\.c$' -e '\.proto$'); do
  if ! $CLANG_FORMAT -n -Werror -style=file "$file"; then
    if $fix ; then
      $CLANG_FORMAT -style=file -i "$file"
    fi
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
  if $fix ; then
    echo "Fixed formatting:"
  else
    echo "Fix formatting:"
  fi
  echo "$unformatted_files"
  if ! $fix ; then
    exit 1
  fi
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
