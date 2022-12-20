#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

CLANG_VERSION=10

export CCC_CC="clang-$CLANG_VERSION"
export CCC_CXX="clang++-$CLANG_VERSION"

SCAN="scan-build-$CLANG_VERSION --exclude 3rdparty --exclude test"

# VERBOSE_LOGGING=ON is important, without it scan-build will report values as unused
# everywhere we compile out the logging statements that would otherwise read them
$SCAN cmake -GNinja -DCOMPILE_TARGET=virtual -DVERBOSE_LOGGING=ON -DCMAKE_BUILD_TYPE=Debug ..
# Fails on the current build of clang, because of false positives in doctest, WIP
$SCAN ninja || true