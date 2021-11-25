#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# The purpose of this script is to wrap the launch of a CCF node
# when the IP address of the node isn't known in advance
# (e.g. dynamically launched container).
# This sets the --node-address and --public-rpc-address arguments
# based on the IP address of the container (it assumes that the container
# is connected to service-specific network)

set -e

cmd=$*
container_ip=$(hostname -i | cut -d " " -f 2) # Network container IP address

if echo "${cmd}" | grep -- '--config'; then
    # Node makes use of configuration file (2.x nodes)
    container_ip_replace_str="CONTAINER_IP"
    config_file_path="$(echo "${cmd}" | grep -o -P "(?<=--config).*" | cut -d " " -f 2)"
    sed --follow-symlinks -i -e "s/${container_ip_replace_str}/${container_ip}/g" "${config_file_path}"
else
    # Legacy node that uses CLI paramters (1.x)
    addresses="--node-address=${container_ip}:0 --public-rpc-address=${container_ip}:0"

    # Required for 1.x releases
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
fi

eval "${cmd}"