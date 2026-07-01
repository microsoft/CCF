#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

H2SPEC_VERSION="v2.6.0"

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
    # Source control and tools used by this script.
    tdnf -y install  \
        git  \
        ca-certificates  \
        curl  \
        tar  \
        gzip
}

install_build_dependencies() {
    # To build CCF. Azure Linux 4 uses more explicit package names than Azure
    # Linux 3: build-essential is not present, and the curl/nghttp2 development
    # packages are named libcurl-devel and libnghttp2-devel.
    tdnf -y install  \
        gcc  \
        gcc-c++  \
        make  \
        binutils  \
        clang  \
        cmake  \
        ninja-build  \
        which  \
        openssl  \
        openssl-devel  \
        libuv-devel  \
        libnghttp2-devel  \
        libcurl-devel  \
        libarrow-devel  \
        parquet-libs-devel  \
        doxygen  \
        clang-tools-extra-devel  \
        rust  \
        cargo  \
        libstdc++-devel
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
        procps-ng
        # protocoltest
        bind-utils
        strace
    )
    tdnf -y install "${packages[@]}" &&
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
    # The Azure Linux 4 package repositories currently provide Node.js 22. The
    # JS packages in this repository require Node.js >= 20.
    tdnf -y install  \
        nodejs  \
        nodejs-npm

    local node_major
    node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
    if (( node_major < 20 )); then
        echo "Unsupported Node.js version $(node --version); expected >= 20" >&2
        return 1
    fi
}

install_packaging_and_python() {
    local packages=(
        # For packaging
        rpm-build
        # For end to end tests and scripts
        python3-pip
        python3-devel
    )
    tdnf -y install "${packages[@]}"

    if ! python3 -m pip install uv==0.11.19 --break-system-packages; then
        python3 -m pip install uv==0.11.19
    fi
}

retry "Source control dependencies" install_source_control
retry "Build dependencies" install_build_dependencies
retry "Test dependencies" install_test_dependencies
retry "Node.js installation" install_node
retry "h2spec installation" install_h2spec
retry "Packaging and Python dependencies" install_packaging_and_python
