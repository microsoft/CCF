#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

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
        npm \
        build-essential
}

install_lts_test_dependencies() {
    # For LTS test to extract binaries from rpms
    tdnf -y install cpio
}

install_python_tools() {
    pip install gersemi
}

install_shellcheck() {
    # For shellcheck
    curl -L https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.linux.x86_64.tar.xz  \
        --output shellcheck.tar.gz &&
    mkdir -p shellcheck-dir &&
    tar -xvf shellcheck.tar.gz -C shellcheck-dir &&
    mv shellcheck-dir/shellcheck-stable/shellcheck /usr/local/bin/shellcheck &&
    rm -rf shellcheck-dir shellcheck.tar.gz
}

retry "Development dependencies" install_dev_dependencies
retry "LTS test dependencies" install_lts_test_dependencies
retry "Python tools" install_python_tools
retry "shellcheck installation" install_shellcheck
