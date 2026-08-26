#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -exo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

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
        kernel-tools  \
        jq  \
        tar
}

install_lts_test_dependencies() {
    # For LTS test to extract binaries from rpms
    dnf -y install cpio
}

install_python_tools() {
    # Match the clang-format version used by the existing formatting checks.
    bash "$SCRIPT_DIR/install_uv.sh" /usr/local/bin || return 1
    uv pip install \
        --system \
        --break-system-packages \
        gersemi \
        clang-format==18.1.8

    local clang_format
    clang_format=$(PATH="/usr/local/bin:$PATH" command -v clang-format)
    # The PyPI package provides an unversioned executable, so add the expected name.
    ln -sf "$clang_format" /usr/local/bin/clang-format-18
}

retry "Development dependencies" install_dev_dependencies
retry "LTS test dependencies" install_lts_test_dependencies
retry "Python tools" install_python_tools
