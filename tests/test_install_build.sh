#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

mkdir build_against_install
cd build_against_install
CC=$(command -v clang-8) CXX=$(command -v clang++-8) cmake -GNinja ../samples/apps/logging/
ninja