#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

mkdir -p build_against_install
cd build_against_install

CC=$(which clang || true)
CXX=$(which clang++ || true)

if [ "$CC" = "" ] || [ "$CXX" = "" ]; then
    CC=$(command -v clang-15 || true)
    CXX=$(command -v clang++-15 || true)
fi

CC=$CC CXX=$CXX cmake -GNinja "$@" ../samples/apps/logging/

ninja