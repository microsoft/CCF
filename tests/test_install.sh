#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

if [ "$#" -ne 1 ]; then
    echo "Install prefix should be passed as first argument to $0"
    exit 1
fi

echo "Install prefix is ${1}"

# Setup env
INSTALL_PREFIX="$1"
working_dir="nested/run"
rm -rf "$working_dir"
mkdir -p "$working_dir"
cd "$working_dir"

# Start ephemeral network in the background
network_live_time=60
timeout --signal=SIGINT --kill-after=${network_live_time}s --preserve-status ${network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh --verbose &

# Wait for service to be open
sleep 45

# # Issue tutorial transactions to ephemeral network
python3.8 -m venv env
source env/bin/activate
# python -m pip install -U -r "$INSTALL_PREFIX"/bin/requirements.txt
python -m pip install ../../../python
python ../../../python/tutorial.py ./workspace/sandbox_0/0.ledger/ ./workspace/sandbox_common/

# Test Python package CLI
../../../tests//test_python_cli.sh > test_python_cli.out

# Wait until original network has died
sleep 20

# Recover network
cp -r ./workspace/sandbox_0/0.ledger .

recovered_network_live_time=30
timeout --signal=SIGINT --kill-after=${recovered_network_live_time}s --preserve-status ${recovered_network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh --verbose \
    --recover \
    --ledger-dir 0.ledger \
    --common-dir ./workspace/sandbox_common/