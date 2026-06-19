#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

H2SPEC_VERSION="v2.6.0"
NODE_VERSION="v24.17.0"
# SHA256 checksum of node-${NODE_VERSION}-linux-x64.tar.gz from
# https://nodejs.org/dist/${NODE_VERSION}/SHASUMS256.txt
NODE_SHA256="e0472427aa791ad80bdc426ff7cc73cdd28ed0f616d1ff9689a23a7f47f1265f"

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
        clang-tools-extra-devel  \
        rust
}

install_test_dependencies() {
    local packages=(
        # To run standard tests
        lldb
        expect
        jq
        # Extra-dependency for CDDL schema checker
        rubygems
        # Release (extended) tests
        procps
        # protocoltest
        bind-utils
        # partitions test
        iptables
        strace
    )
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install "${packages[@]}" &&
    gem install cddl
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

install_node() {
    local node_dist="node-${NODE_VERSION}-linux-x64"
    local archive="${node_dist}.tar.gz"
    if ! curl -fL --output "$archive" "https://nodejs.org/dist/${NODE_VERSION}/${archive}"; then
        echo "Failed to download Node.js"
        return 1
    fi

    if ! echo "${NODE_SHA256}  ${archive}" | sha256sum --check --status; then
        echo "Node.js checksum verification failed"
        rm -f "$archive"
        return 1
    fi

    rm -rf /opt/node &&
    mkdir -p /opt/node &&
    tar -xzf "$archive" -C /opt/node --strip-components=1 &&
    ln -sf /opt/node/bin/node /usr/local/bin/node &&
    ln -sf /opt/node/bin/npm /usr/local/bin/npm &&
    ln -sf /opt/node/bin/npx /usr/local/bin/npx &&
    rm -f "$archive"
}

install_packaging_and_python() {
    local packages=(
        # For packaging
        rpm-build
        # For end to end tests and scripts
        python3-pip
    )
    tdnf --snapshottime=$SOURCE_DATE_EPOCH -y install "${packages[@]}" &&
    pip install uv==0.11.19
}

retry "Source control dependencies" install_source_control
retry "Build dependencies" install_build_dependencies
retry "Test dependencies" install_test_dependencies
retry "Node.js installation" install_node
retry "h2spec installation" install_h2spec
retry "Packaging and Python dependencies" install_packaging_and_python
