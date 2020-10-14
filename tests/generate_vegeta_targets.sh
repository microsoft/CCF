#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -e

# This script takes the information written to the infra's --network-info-file 
# and produces a stream of JSON-format vegeta targets for the logging app. For
# now this is very barebones, but could be extended to support more nodes,
# different request distributions, different request URLs, etc.

if [ "$#" -ne 1 ]; then
    echo "Network info file should be passed as first argument to $0"
    exit 1
fi

NETWORK_INFO="$1"

if [[ ! -f "$NETWORK_INFO" ]]; then
    echo "File '$NETWORK_INFO' does not exist. Running ls."
    ls
    exit 1
fi

NODE_URL=$(jq -r '[.host, .port | tostring] | join(":")' < "$NETWORK_INFO")
NODE_URL="https://${NODE_URL}"

# POST 10 private log messages
URL="$NODE_URL/app/log/private" jq -ncM '0 | while (.<10; .+1) | {"method": "POST", "url": env.URL, "body": {"id": ., "msg": ["A private vegeta message", . | tostring] | join(": ")} | @base64, "header": {"Content-type": ["application/json"]}}'

# GET 10 private log messages
URL="$NODE_URL/app/log/private" jq -ncM '0 | while (.<10; .+1) | {"method": "GET", "url": (env.URL + "?id=" + (. | tostring)), "header": {"Content-type": ["application/json"]}}'

# POST 10 public log messages
URL="$NODE_URL/app/log/public" jq -ncM '0 | while (.<10; .+1) | {"method": "POST", "url": env.URL, "body": {"id": ., "msg": ["A public vegeta message", . | tostring] | join(": ")} | @base64, "header": {"Content-type": ["application/json"]}}'

# GET 10 public log messages
URL="$NODE_URL/app/log/public" jq -ncM '0 | while (.<10; .+1) | {"method": "GET", "url": (env.URL + "?id=" + (. | tostring)), "header": {"Content-type": ["application/json"]}}'
