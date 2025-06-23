#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

pushd ..
mkdir -p build
pushd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DVERBOSE_LOGGING=ON -DCCF_RAFT_TRACING=ON ..
ninja raft_driver
./tests.sh -VV -R scenario
popd
popd