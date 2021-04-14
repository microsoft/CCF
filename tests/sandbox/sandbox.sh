#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

VENV_DIR=${VENV_DIR:-.venv_ccf_sandbox}

PATH_HERE=$(dirname "$(realpath -s "$0")")
VERSION_FILE="${PATH_HERE}"/../share/VERSION

is_package_specified=false
is_js_bundle_specified=false

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

if [ -f "${VERSION_FILE}" ]; then
    # install tree
    BINARY_DIR=${PATH_HERE}
    START_NETWORK_SCRIPT="${PATH_HERE}"/start_network.py
    VERSION=$(<"${VERSION_FILE}")
    if [ ${is_package_specified} == false ] && [ ${is_js_bundle_specified} == false ]; then
        # Only on install tree, default to installed js logging app
        echo "No package/app specified. Defaulting to installed JS logging app"
        extra_args+=(--package "${PATH_HERE}/../lib/libjs_generic")
        extra_args+=(--js-app-bundle "${PATH_HERE}/../samples/logging/js")
    fi
    if [ ! -z "${PYTHON_PACKAGE_PATH}" ]; then
        # With an install tree, the python package can be specified, e.g. when testing
        # an install just before it is released
        echo "Using python package: ${PYTHON_PACKAGE_PATH}"
        pip install --disable-pip-version-check -q -U -e "${PYTHON_PACKAGE_PATH}"
    else
        pip install --disable-pip-version-check -q -U ccf=="$VERSION"
    fi
    pip install --disable-pip-version-check -q -U -r "${PATH_HERE}"/requirements.txt
else
    # source tree
    BINARY_DIR=.
    START_NETWORK_SCRIPT="${PATH_HERE}"/../start_network.py
    pip install --disable-pip-version-check -q -U -e "${PATH_HERE}"/../../python/
    pip install --disable-pip-version-check -q -U -r "${PATH_HERE}"/../requirements.txt
fi

echo "Python environment successfully setup"

export CURL_CLIENT=ON
exec python "${START_NETWORK_SCRIPT}" \
    --binary-dir "${BINARY_DIR}" \
    --enclave-type virtual \
    --initial-member-count 1 \
    --constitution "${PATH_HERE}"/actions.js \
    --constitution "${PATH_HERE}"/validate.js \
    --constitution "${PATH_HERE}"/resolve.js \
    --constitution "${PATH_HERE}"/apply.js \
    --ledger-chunk-bytes 5MB \
    --snapshot-tx-interval 10000 \
    --label sandbox \
    "${extra_args[@]}"
