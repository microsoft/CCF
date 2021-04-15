#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -e

function service_http_status()
{
    curl -o /dev/null -s https://127.0.0.1:8000/app/commit -w "%{http_code}" --key ./workspace/sandbox_common/user0_privk.pem --cert ./workspace/sandbox_common/user0_cert.pem --cacert ./workspace/sandbox_common/networkcert.pem
}

function poll_for_service_open()
{
    network_live_time=$1
    polls=0
    while [ ! "$(service_http_status)" == "200" ] && [ "${polls}" -lt "${network_live_time}" ]; do
        echo "Waiting for service to open..."
        polls=$((polls+1))
        sleep 1
    done

    if [ "$(service_http_status)" == "200" ]; then
        return 1
    fi

    return 0
}

if [ "$#" -lt 1 ]; then
    echo "Install prefix should be passed as first argument to $0"
    exit 1
fi

# If "release" is passed as second argument to the script, run additional
# tests at the end of this script
is_release=false
if [ "${2}" == "release" ]; then
    echo "Testing release"
    is_release=true
fi

# Setup env
INSTALL_PREFIX="$1"
if [ ! -z "$PYTHON_PACKAGE_PATH" ]; then
    PYTHON_PACKAGE_PATH=$(realpath -s "${PYTHON_PACKAGE_PATH}")
fi
working_dir="nested/run"
rm -rf "$working_dir"
mkdir -p "$working_dir"
cd "$working_dir"

# Start ephemeral network in the background
network_live_time=60
timeout --signal=SIGINT --kill-after=${network_live_time}s --preserve-status ${network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh -e release --verbose &

if poll_for_service_open ${network_live_time}; then
    echo "Error: Timeout waiting for service to open"
    kill "$(jobs -p)"
    exit 1
fi

# Issue tutorial transactions to ephemeral network
python3.8 -m venv env
# shellcheck source=/dev/null
source env/bin/activate
python -m pip install ../../../python
python ../../../python/tutorial.py ./workspace/sandbox_common/

# Test Python package CLI
../../../tests/test_python_cli.sh > test_python_cli.out

# Poll until service has died
while [ "$(service_http_status)" == "200" ]; do
    echo "Waiting for service to close..."
    sleep 1
done

# Now that the service has been stopped, run ledger tutorial
python ../../../python/ledger_tutorial.py ./workspace/sandbox_0/0.ledger

# Recover network
cp -r ./workspace/sandbox_0/0.ledger .

recovered_network_live_time=30
timeout --signal=SIGINT --kill-after=${recovered_network_live_time}s --preserve-status ${recovered_network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh --verbose \
    -e release \
    --recover \
    --ledger-dir 0.ledger \
    --common-dir ./workspace/sandbox_common/

# If the install is a release, run additional tests. Otherwise, exit successfully.
if [ "$is_release" == false ]; then
    exit 0
fi

# In release, running a BFT service should not be possible
network_live_time=30
timeout --signal=SIGINT --kill-after=${network_live_time}s --preserve-status ${network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh -e release --consensus=bft --verbose &

if ! poll_for_service_open ${network_live_time}; then
    echo "Error: Experimental BFT consensus should not be allowed in release install"
    kill "$(jobs -p)"
    exit 1
fi
