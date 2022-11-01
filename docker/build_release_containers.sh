#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Builds all release containers, for all target platforms

set -ex

ACR_REGISTRY="${1}"
VERSION=${2:-"latest"}
platforms="sgx snp virtual"

for platform in $platforms; do

    echo "** Building release containers for ${platform} platform"

    # Dev
    docker build -f docker/app_dev . --build-arg="platform=${platform}" --build-arg="ansible_vars=ccf_ver=${VERSION}" -t "$ACR_REGISTRY/public/ccf/app/dev:${VERSION}-${platform}"

    # Run
    docker build -f docker/app_run . --build-arg="platform=${platform}" --build-arg="ansible_vars=ccf_ver=${VERSION}" -t "$ACR_REGISTRY/public/ccf/app/run:${VERSION}-${platform}"

    # Run-JS
    docker build -f docker/app_run . --build-arg="platform=sgx" --build-arg="ansible_vars=ccf_ver=${VERSION}  run_js=true" -t "$ACR_REGISTRY/public/ccf/app/run-js:${VERSION}-${platform}"

done



