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
    # The compiler toolchain (Azure Linux 4 has no build-essential meta-package)
    # is installed by setup-ci-al4.sh; here we add the developer-only tools.
    dnf -y install  \
        clang-tools-extra  \
        python3-pip  \
        jq  \
        tar
}

install_lts_test_dependencies() {
    # For LTS test to extract binaries from rpms
    dnf -y install cpio
}

install_python_tools() {
    if ! python3 -m pip install gersemi --break-system-packages; then
        python3 -m pip install gersemi
    fi
}

retry "Development dependencies" install_dev_dependencies
retry "LTS test dependencies" install_lts_test_dependencies
retry "Python tools" install_python_tools
