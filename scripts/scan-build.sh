#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

CLANG_VERSION=10

export CCC_CC="clang-$CLANG_VERSION"
export CCC_CXX="clang++-$CLANG_VERSION"

SCAN="scan-build-$CLANG_VERSION --exclude 3rdparty --exclude test"

$SCAN cmake -GNinja -DCOMPILE_TARGET=virtual -DCMAKE_BUILD_TYPE=Debug ..
$SCAN ninja