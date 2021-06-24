#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

export CCC_CC=clang-10
export CCC_CXX=clang++-10

SCAN="scan-build-10 --exclude 3rdparty --exclude test"

$SCAN cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..
$SCAN ninja