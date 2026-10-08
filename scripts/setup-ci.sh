#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

TDNF_OPTIONS=(-y)
if [[ -n ${SOURCE_DATE_EPOCH:-} ]]; then
    echo "Using SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
    TDNF_OPTIONS+=("--snapshottime=$SOURCE_DATE_EPOCH")
fi

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

install_dependencies() {
    # Resolve and install all RPM dependencies in one transaction.
    local packages=(
        # Source control
        git
        ca-certificates
        # To build CCF
        build-essential
        clang
        cmake
        ninja-build
        patch
        which
        openssl-devel
        libuv-devel
        curl-devel
        doxygen
        clang-tools-extra-devel
        rust
        libbacktrace-static
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
        # Node.js and npm from the same Azure Linux package repository
        "nodejs >= 24"
        nodejs-npm
        # Packaging and Python
        rpm-build
        python3
    )
    tdnf "${TDNF_OPTIONS[@]}" install "${packages[@]}"
}

install_cddl() {
    gem install cddl
}

install_uv() {
    bash "$SCRIPT_DIR/install_uv.sh" /usr/local/bin
}

retry "CI RPM dependencies" install_dependencies
retry "CDDL installation" install_cddl
retry "uv installation" install_uv
