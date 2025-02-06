#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Source control
tdnf -y install  \
    git  \
    ca-certificates

# To build CCF
tdnf -y install  \
    build-essential  \
    clang  \
    cmake  \
    ninja-build  \
    which  \
    openssl-devel  \
    libuv-devel  \
    nghttp2-devel  \
    curl-devel  \
    libarrow-devel  \
    parquet-libs-devel

# To run standard tests
tdnf -y install  \
    lldb  \
    expect  \
    npm  \
    jq

# Extra-dependency for CDDL schema checker
tdnf -y install rubygems
gem install cddl
