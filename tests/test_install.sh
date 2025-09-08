#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -e

function service_http_status()
{
    curl -o /dev/null -s https://127.0.0.1:8000/commit -w "%{http_code}" --cacert ./workspace/sandbox_common/service_cert.pem
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

# Setup env
INSTALL_PREFIX="$1"
if [ -n "$PYTHON_PACKAGE_PATH" ]; then
    PYTHON_PACKAGE_PATH=$(realpath -s "${PYTHON_PACKAGE_PATH}")
fi
working_dir="nested/run"
rm -rf "$working_dir"
mkdir -p "$working_dir"
cd "$working_dir"

export BETTER_EXCEPTIONS=1

# Start ephemeral network in the background
network_live_time=60
"$INSTALL_PREFIX"/bin/sandbox.sh --auto-shutdown --auto-shutdown-delay-s ${network_live_time} --verbose &

if poll_for_service_open ${network_live_time}; then
    echo "Error: Timeout waiting for service to open"
    kill "$(jobs -p)"
    exit 1
fi

python3 -m venv env
# shellcheck source=/dev/null
source env/bin/activate
python -m pip install -U pip
python -m pip install -U -e ../../../python

# Poll until service has died
while [ "$(service_http_status)" == "200" ]; do
    echo "Waiting for service to close..."
    sleep 1
done

# Now that the service has been stopped, run ledger tutorial
python ../../../python/ledger_tutorial.py ./workspace/sandbox_0/0.ledger

# Recover network
cp -r ./workspace/sandbox_0/0.ledger .

recovered_network_live_time=10
"$INSTALL_PREFIX"/bin/sandbox.sh --auto-shutdown --auto-shutdown-delay-s ${recovered_network_live_time} --verbose  \
    --recover \
    --ledger-dir 0.ledger \
    --common-dir ./workspace/sandbox_common/
