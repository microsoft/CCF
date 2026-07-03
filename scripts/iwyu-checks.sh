#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Checks C/C++ include hygiene with include-what-you-use.
# Pass -f for interface consistency, but no auto-fix is available.

set -e
set -u
set -o pipefail

FIX=0
if [ "${1:-}" = "-f" ]; then
  FIX=1
  shift
fi

if [ "$#" -ne 0 ]; then
  echo "Usage: $0 [-f]"
  exit 1
fi

if [ "$FIX" -ne 0 ]; then
  echo "include-what-you-use checks do not support auto-fix; running checks only"
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
BUILD_DIR=${CCF_IWYU_BUILD_DIR:-"$ROOT_DIR/build-iwyu"}
NPROC=$(nproc 2>/dev/null || echo 4)

cmake \
  -S "$ROOT_DIR" \
  -B "$BUILD_DIR" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_END_TO_END_TESTS=OFF \
  -DCOMPILE_TARGET=virtual \
  -DINCLUDE_WHAT_YOU_USE=ON

cmake --build "$BUILD_DIR" --parallel "$NPROC"
echo "include-what-you-use checks passed"
