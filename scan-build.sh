#!/bin/bash

export CCC_CC=clang-8
export CCC_CXX=clang++-8

SCAN="scan-build-8 --exclude 3rdparty --exclude test"

$SCAN cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..
$SCAN ninja