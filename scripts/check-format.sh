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

CLANG_FORMAT=clang-format
if [ -x "$(command -v clang-format-18)" ]; then
    CLANG_FORMAT=clang-format-18
fi

echo "Using $(${CLANG_FORMAT} --version)"

NPROC=$(nproc 2>/dev/null || echo 4)

# Collect the file list once
mapfile -t files < <(git ls-files "$@" | grep -e '\.h$' -e '\.hpp$' -e '\.cpp$' -e '\.c$')

# --- Format check (parallel) ---
if $fix ; then
  # In fix mode, format first then check what changed
  printf '%s\n' "${files[@]}" | xargs -P "$NPROC" -n 50 "$CLANG_FORMAT" -style=file -i

  # Re-check to report which files were fixed
  unformatted_files=$(git diff --name-only -- "${files[@]}") || true
else
  # Check mode: collect filenames from clang-format warnings (parallel)
  unformatted_files=$(printf '%s\n' "${files[@]}" | \
    xargs -P "$NPROC" -n 50 "$CLANG_FORMAT" -n -Werror -style=file 2>&1 | \
    sed -n 's/^\(.*\):[0-9]*:[0-9]*:.*/\1/p' | sort -u) || true
fi

# --- File name check ---
file_name_regex="^[[:lower:]0-9_]+$"
badly_named_files=""
for file in "${files[@]}"; do
  file_base_name=$(basename "${file%.*}")
  if ! [[ $file_base_name =~ $file_name_regex ]]; then
    if [ "$badly_named_files" != "" ]; then
      badly_named_files+=$'\n'
    fi
    badly_named_files+="$file"
  fi
done

# --- Report results ---
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
