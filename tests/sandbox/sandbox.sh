#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

VENV_DIR=${VENV_DIR:-.venv_ccf_sandbox}

PATH_HERE=$(dirname "$(realpath -s "$0")")
CONSTITUTION_DIR="${PATH_HERE}"
VERSION_FILE="${PATH_HERE}"/../share/VERSION_LONG

is_package_specified=false
is_js_bundle_specified=false

extra_args=()
while [ "$1" != "" ]; do
    case $1 in
        -p|--package)
            is_package_specified=true
            extra_args+=("$1" "$2")
            shift
            ;;
        -p=*|--package=*)
            is_package_specified=true
            extra_args+=("$1")
            ;;
        --js-app-bundle)
            is_js_bundle_specified=true
            extra_args+=("$1" "$2")
            shift
            ;;
        --js-app-bundle=*)
            is_js_bundle_specified=true
            extra_args+=("$1")
            ;;
        -c|--constitution-dir)
            CONSTITUTION_DIR=$2
            # We don't copy this argument to extra_args
            shift
            ;;
        *)
            extra_args+=("$1")
            ;;
    esac
    shift
done

if [ -f "${VERSION_FILE}" ]; then
    # install tree
    BINARY_DIR=${PATH_HERE}
    START_NETWORK_SCRIPT="${PATH_HERE}"/start_network.py
    if [ ${is_package_specified} == false ] && [ ${is_js_bundle_specified} == false ]; then
        # Only on install tree, default to installed js logging app
        echo "No package/app specified. Defaulting to installed JS logging app"
        extra_args+=(--package "${PATH_HERE}/../bin/js_generic")
        extra_args+=(--js-app-bundle "${PATH_HERE}/../samples/logging/js")
    fi
else
    # source tree
    BINARY_DIR=.
    START_NETWORK_SCRIPT="${PATH_HERE}"/../start_network.py
fi

if [ ! -f "${VENV_DIR}/bin/activate" ]; then
    echo "Setting up Python environment..."
    python3 -m venv "${VENV_DIR}"

    # shellcheck source=/dev/null
    source "${VENV_DIR}"/bin/activate
    echo "Installing pip..."
    pip install -U -q pip

    if [ -f "${VERSION_FILE}" ]; then
        VERSION=$(<"${VERSION_FILE}")
        VERSION=${VERSION#"ccf-"}
        if [ -n "${PYTHON_PACKAGE_PATH}" ]; then
            # With an install tree, the python package can be specified, e.g. when testing
            # an install just before it is released
            echo "Using python package: ${PYTHON_PACKAGE_PATH}"
            echo "Installing ccf package from ${PYTHON_PACKAGE_PATH}..."
            pip install -q -U -e "${PYTHON_PACKAGE_PATH}"
        else
            # Note: Strip unsafe suffix if it exists
            sanitised_version=${VERSION%"+unsafe"}
            echo "Installing ccf package (${sanitised_version})..."
            pip install -q -U ccf=="${sanitised_version}"
        fi
        echo "Installing test dependencies..."
        pip install -q -U -r "${PATH_HERE}"/requirements.txt
    else
        echo "Installing ccf package from source tree..."
        pip install -q -U -e "${PATH_HERE}"/../../python/
        echo "Installing test dependencies..."
        pip install -q -U -r "${PATH_HERE}"/../requirements.txt
    fi

    echo "Python environment successfully setup"
else
    # shellcheck disable=SC1090
    source "${VENV_DIR}/bin/activate"
    echo "Python environment already setup under ${VENV_DIR}"
fi

export CURL_CLIENT=ON
export INITIAL_MEMBER_COUNT=1
exec python "${START_NETWORK_SCRIPT}" \
    --binary-dir "${BINARY_DIR}" \
    --constitution "${CONSTITUTION_DIR}"/actions.js \
    --constitution "${CONSTITUTION_DIR}"/validate.js \
    --constitution "${CONSTITUTION_DIR}"/resolve.js \
    --constitution "${CONSTITUTION_DIR}"/apply.js \
    --ledger-chunk-bytes 5000000 \
    --snapshot-tx-interval 10000 \
    --initial-node-cert-validity-days 90 \
    --initial-service-cert-validity-days 90 \
    --label sandbox \
    "${extra_args[@]}"
