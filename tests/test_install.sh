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

python3.8 -m venv env
source env/bin/activate
python -m pip install -U -r "$INSTALL_PREFIX"/bin/requirements.txt
python -m pip install ../../../python

# Test Python package CLI
../../test_python_cli.sh > test_python_cli.out

# Start ephemeral network in the background
network_info_file="network_info.txt"

network_live_time=30
timeout --signal=SIGINT --kill-after=${network_live_time}s --preserve-status ${network_live_time}s \
python "$INSTALL_PREFIX"/bin/start_network.py \
    -p liblogging \
    -b "$INSTALL_PREFIX"/bin \
    --library-dir ../../../build \
    -g "$(pwd)"/../../../src/runtime_config/gov.lua \
    --network-info-file "$network_info_file" \
    -v &

# Wait for network to be open and accessible
while [ ! -f "$network_info_file" ]; do
    sleep 1
done

# Issue tutorial transactions to ephemeral network
python ../../../python/tutorial.py "$network_info_file"

# Wait until original network has died
sleep ${network_live_time}

# ...and a tad longer to be sure
sleep 5

# Recover network
cp -r ./workspace/start_network_0/0.ledger .

timeout --signal=SIGINT --kill-after=${network_live_time}s --preserve-status ${network_live_time}s \
python "$INSTALL_PREFIX"/bin/start_network.py \
    -p liblogging \
    -b "$INSTALL_PREFIX"/bin \
    --library-dir ../../../build \
    -v \
    --recover \
    --ledger-dir 0.ledger \
    --common-dir ./workspace/start_network_common/