#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# The purpose of this script is to wrap the launch of a CCF node
# when the IP address of the node isn't known in advance
# (e.g. dynamically launched container).
# This sets the --node-address and --public-rpc-address arguments
# based on the IP address of the container (it assumes that the container
# is connected to service-specific network)

# Note: This should become less hacky once https://github.com/microsoft/CCF/issues/2612 is implemented

set -ex

cmd=$*
container_ip=$(hostname -i | cut -d " " -f 2) # Network container IP address
addresses="--node-address=${container_ip}:0 --public-rpc-address=${container_ip}:0"

# TODO: Fix:
# 1. For 1.x nodes leave as it is (for LTS compatibility)
# 2. For 2.x nodes, modify configuration JSON file
# - Extract config path from `--config argument`
# - Using jq, modify RPC address in place

echo "lala"

# Required for 1.x releases TODO: Still required?
addresses="${addresses} --san=iPAddress:${container_ip}"

startup_cmd=""
for c in " start " " join" " recover "; do
    if [[ $cmd == *"${c}"* ]]; then
        startup_cmd=${c}
    fi
done

if [ -z "${startup_cmd}" ]; then
    echo "Command does not contain valid cchost startup command"
    exit 1
fi

# Insert node and public RPC address in command line (yikes!)
cmd="${cmd%%${startup_cmd}*} ${addresses} ${startup_cmd} ${cmd##*${startup_cmd}}"
eval "${cmd}"