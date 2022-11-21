#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

VENV_DIR=${VENV_DIR:-.venv_ccf_sandbox}

PATH_HERE=$(dirname "$(realpath -s "$0")")
VERSION_FILE="${PATH_HERE}"/../share/VERSION_LONG

is_package_specified=false
is_js_bundle_specified=false

PLATFORM_FILE="${PATH_HERE}"/../share/PLATFORM
platform="virtual"
enclave_type="virtual"

extra_args=("$@")
while [ "$1" != "" ]; do
    case $1 in
        -p|--package)
            is_package_specified=true
            shift
            ;;
        -p=*|--package=*)
            is_package_specified=true
            ;;
        --js-app-bundle)
            is_js_bundle_specified=true
            shift
            ;;
        --js-app-bundle=*)
            is_js_bundle_specified=true
            ;;
        *)
            ;;
    esac
    shift
done

echo "Setting up Python environment..."

if [ ! -f "${VENV_DIR}/bin/activate" ]; then
    python3.8 -m venv "${VENV_DIR}"
fi
# shellcheck source=/dev/null
source "${VENV_DIR}"/bin/activate
pip install -U -q pip

if [ -f "${VERSION_FILE}" ]; then
    # install tree
    BINARY_DIR=${PATH_HERE}
    START_NETWORK_SCRIPT="${PATH_HERE}"/start_network.py
    VERSION=$(<"${VERSION_FILE}")
    VERSION=${VERSION#"ccf-"}
    platform=$(<"${PLATFORM_FILE}")
    if [ "${platform}" == "sgx" ]; then
        enclave_type="release"
    else
        enclave_type="virtual"
    fi
    if [ ${is_package_specified} == false ] && [ ${is_js_bundle_specified} == false ]; then
        # Only on install tree, default to installed js logging app
        echo "No package/app specified. Defaulting to installed JS logging app"
        extra_args+=(--package "${PATH_HERE}/../lib/libjs_generic")
        extra_args+=(--js-app-bundle "${PATH_HERE}/../samples/logging/js")
    fi
    if [ -n "${PYTHON_PACKAGE_PATH}" ]; then
        # With an install tree, the python package can be specified, e.g. when testing
        # an install just before it is released
        echo "Using python package: ${PYTHON_PACKAGE_PATH}"
        pip install -q -U -e "${PYTHON_PACKAGE_PATH}"
    else
        # Note: Strip unsafe suffix if it exists
        sanitised_version=${VERSION%"+unsafe"}
        pip install -q -U ccf=="${sanitised_version}"
    fi
    pip install -q -U -r "${PATH_HERE}"/requirements.txt
else
    # source tree
    BINARY_DIR=.
    START_NETWORK_SCRIPT="${PATH_HERE}"/../start_network.py
    pip install -q -U -e "${PATH_HERE}"/../../python/
    pip install -q -U -r "${PATH_HERE}"/../requirements.txt
fi

echo "Python environment successfully setup"

export CURL_CLIENT=ON
export CURL_CLIENT_USE_COSE=ON
exec python "${START_NETWORK_SCRIPT}" \
    --binary-dir "${BINARY_DIR}" \
    --enclave-type "${enclave_type}" \
    --enclave-platform "${platform}" \
    --initial-member-count 1 \
    --constitution "${PATH_HERE}"/actions.js \
    --constitution "${PATH_HERE}"/validate.js \
    --constitution "${PATH_HERE}"/resolve.js \
    --constitution "${PATH_HERE}"/apply.js \
    --ledger-chunk-bytes 5000000 \
    --snapshot-tx-interval 10000 \
    --initial-node-cert-validity-days 90 \
    --initial-service-cert-validity-days 90 \
    --label sandbox \
    "${extra_args[@]}"
