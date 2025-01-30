#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
tdnf -y update

# Source control
tdnf -y install ca-certificates git

# Build tools
tdnf -y install build-essential clang cmake ninja-build which

# libc++
tdnf -y install libcxx-devel llvm-libunwind-devel llvm-libunwind-static

# Dependencies
tdnf -y install openssl-devel libuv-devel nghttp2-devel curl-devel

# Test dependencies
tdnf -y install libarrow-devel parquet-libs-devel lldb npm jq expect procps

# Install CDDL via rubygems
tdnf -y install rubygems
gem install cddl
