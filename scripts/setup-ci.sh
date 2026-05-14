#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

H2SPEC_VERSION="v2.6.0"

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}
echo "Using SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

retry() {
    local description=$1
    shift

    if [[ -z ${CI+x} ]]; then
        "$@"
        return
    fi

    local attempt=1
    local delay
    while true; do
        if "$@"; then
            return
        fi

        if (( attempt == 3 )); then
            echo "'$description' failed after 3 attempts"
            return 1
        fi

        if (( attempt == 1 )); then
            delay=5
        else
            delay=30
        fi

        echo "'$description' failed on attempt $attempt. Retrying in ${delay}s..."
        sleep "$delay"
        attempt=$(( attempt + 1 ))
    done
}

install_source_control() {
    # Source control
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install  \
        git  \
        ca-certificates
}

install_build_dependencies() {
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
}

install_test_dependencies() {
    # To run standard tests
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install  \
        lldb  \
        expect  \
        npm  \
        jq &&

    # Extra-dependency for CDDL schema checker
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install rubygems &&
    gem install cddl &&

    # Release (extended) tests
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install procps &&

    # protocoltest
    tdnf --snapshottime=$SOURCE_DATE_EPOCH install -y bind-utils &&

    # partitions test
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install iptables &&
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install strace
}

install_h2spec() {
    if ! curl -L --output h2spec_linux_amd64.tar.gz https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz; then
        echo "Failed to download h2spec"
        return 1
    fi

    tar -xvf h2spec_linux_amd64.tar.gz &&
    mkdir -p /opt/h2spec &&
    mv h2spec /opt/h2spec/h2spec &&
    rm h2spec_linux_amd64.tar.gz
}

install_packaging_and_python() {
    # For packaging
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install rpm-build &&

    # For end to end tests and scripts
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install python3-pip &&
    pip install uv==0.10.8
}

install_rust() {
    # Rust
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install rust
}

retry "Source control dependencies" install_source_control
retry "Build dependencies" install_build_dependencies
retry "Test dependencies" install_test_dependencies
retry "h2spec installation" install_h2spec
retry "Packaging and Python dependencies" install_packaging_and_python
retry "Rust dependencies" install_rust
