#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

tdnf -y install  \
    vim  \
    clang-tools-extra  \
    python-pip \
    jq

# For LTS test to extract binaries from rpms
tdnf -y install cpio

pip install cmakelang

# For shellcheck
curl -L https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.linux.x86_64.tar.xz  \
    --output shellcheck.tar.gz
mkdir -p shellcheck-dir
tar -xvf shellcheck.tar.gz -C shellcheck-dir
mv shellcheck-dir/shellcheck-stable/shellcheck /usr/local/bin/shellcheck
rm -rf shellcheck-dir shellcheck.tar.gz
