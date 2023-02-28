#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# The purpose of this script is to wrap the launch of a CCF node
# when the IP address of the node isn't known in advance
# (e.g. dynamically launched container).
# This sets the node address and published RPC address configuration entries
# based on the IP address of the container (it assumes that the container
# is connected to service-specific network)

set -e

cmd=$*
container_ip=$(hostname -i | cut -d " " -f 2) # Network container IP address

# Node makes use of configuration file (2.x nodes)
container_ip_replace_str="CONTAINER_IP"
config_file_path="$(echo "${cmd}" | grep -o -P "(?<=--config).*" | cut -d " " -f 2)"
sed --follow-symlinks -i -e "s/${container_ip_replace_str}/${container_ip}/g" "${config_file_path}"

eval "${cmd}"