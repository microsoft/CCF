#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# This script is used to wrap Clang to enable the use of
# Clang 10 in the V8 build which assumes Clang 14.
# All this script does is filter out unsupported flags.
# Note that it takes the path to Clang as first argument.

compiler=$1
shift

out=()
while (( "$#" )); do
    arg="$1"
    shift
    case "$arg" in
      # Unsupported by Clang 10
      -ffile-compilation-dir=*) ;;
      -fuse-ctor-homing) ;;
      -Wno-psabi) ;;
      -Wno-unused-but-set-parameter) ;;
      -Wno-unused-but-set-variable) ;;
      -Wmax-tokens) ;;
      # Prevents -stdlib=libc++ from working
      -no-canonical-prefixes) ;;
      # Avoid debugging issues by making source paths absolute
      ../../*.cc)
        abs_path=$(realpath -s "$arg")
        out+=("$abs_path")
        ;;
      # Pass-through everything else
      *) out+=("$arg") ;;
    esac
done

echo "$compiler" "${out[@]}"
$compiler "${out[@]}"
