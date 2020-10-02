#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

PATH_HERE=$(dirname "$(realpath -s "$0")")
VERSION_FILE="${PATH_HERE}"/../share/VERSION
GOV_SCRIPT="${PATH_HERE}"/sandbox_gov.lua

echo "Setting up Python environment..."

if [ ! -f "sandbox_env/bin/activate" ]; then
    python3.8 -m venv sandbox_env
fi
source sandbox_env/bin/activate

if [ -f "${VERSION_FILE}" ]; then
    # install tree
    START_NETWORK_SCRIPT="${PATH_HERE}"/start_network.py
    VERSION=$(<"${VERSION_FILE}")
    pip install -q -U ccf=="$VERSION"
    pip install -q -U -r "${PATH_HERE}"/requirements.txt
else
    # source tree
    START_NETWORK_SCRIPT="${PATH_HERE}"/../start_network.py
    pip install -q -U -e "${PATH_HERE}"/../../python/
    pip install -q -U -r "${PATH_HERE}"/../requirements.txt
fi

echo "Python environment successfully setup"

CURL_CLIENT=ON \
    python "${START_NETWORK_SCRIPT}" \
    --enclave-type virtual \
    --initial-member-count 1 \
    --initial-user-count 1 \
    --gov-script "${GOV_SCRIPT}" \
    --ledger-chunk-bytes 5MB \
    --label sandbox \
    "$@"