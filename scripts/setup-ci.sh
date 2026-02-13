#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

H2SPEC_VERSION="v2.6.0"

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}
echo "Using SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

# Source control
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install  \
    git  \
    ca-certificates

# To build CCF
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install  \
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
    parquet-libs-devel  \
    doxygen  \
    clang-tools-extra-devel

# To run standard tests
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install  \
    lldb  \
    expect  \
    npm  \
    jq

# Extra-dependency for CDDL schema checker
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install rubygems
gem install cddl

# Release (extended) tests
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install procps

# protocoltest
tdnf --snapshottime=$SOURCE_DATE_EPOCH install -y bind-utils
curl -L --output h2spec_linux_amd64.tar.gz https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz
tar -xvf h2spec_linux_amd64.tar.gz
mkdir /opt/h2spec
mv h2spec /opt/h2spec/h2spec
rm h2spec_linux_amd64.tar.gz

# partitions test
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install iptables
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install strace

# For packaging
tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install rpm-build

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component rustfmt
export PATH="$HOME/.cargo/bin:$PATH"
