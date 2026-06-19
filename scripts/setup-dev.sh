#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

NODE_VERSION="v24.17.0"
# SHA256 checksum of node-${NODE_VERSION}-linux-x64.tar.gz from
# https://nodejs.org/dist/${NODE_VERSION}/SHASUMS256.txt
NODE_SHA256="e0472427aa791ad80bdc426ff7cc73cdd28ed0f616d1ff9689a23a7f47f1265f"

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

install_dev_dependencies() {
    tdnf -y install  \
        clang-tools-extra  \
        python-pip \
        jq \
        tar \
        build-essential
}

install_lts_test_dependencies() {
    # For LTS test to extract binaries from rpms
    tdnf -y install cpio
}

install_python_tools() {
    pip install gersemi
}

install_node() {
    local node_dist="node-${NODE_VERSION}-linux-x64"
    local archive="${node_dist}.tar.gz"
    if ! curl -L --output "$archive" "https://nodejs.org/dist/${NODE_VERSION}/${archive}"; then
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

retry "Development dependencies" install_dev_dependencies
retry "LTS test dependencies" install_lts_test_dependencies
retry "Python tools" install_python_tools
retry "Node.js installation" install_node
