#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

function usage()
{
    echo "Usage:"""
    echo "  TODO: $0 https://<node-address> [CURL_OPTIONS]"
    echo "Verify node's remote attestation quote"
}

if [[ "$1" =~ ^(-h|-\?|--help)$ ]]; then
    usage
    exit 0
fi

if [ -z "$1" ]; then
    echo "Error: First argument should be CCF node address, e.g.: https://127.0.0.1:8000"
    exit 1
fi

node_rpc_address=$1
shift

# Temporary directory for raw quote
tmp_dir=$(mktemp -d)
function cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

curl -sS --fail -X GET "${node_rpc_address}"/node/quote "${@}" | jq .raw | xxd -r -p > "${tmp_dir}/quote"

if [ ! -s "${tmp_dir}/quote" ]; then
    echo "Node quote is empty. Virtual mode does not support verification."
    exit 1
fi

echo "Node quote successfully retrieved."

# Strip "https://" prefix
stripped_node_rpc_address=${node_rpc_address#"https://"}
pubk_node_hash=$(echo | openssl s_client -showcerts -connect ${stripped_node_rpc_address} 2>/dev/null | openssl x509 -pubkey -noout | openssl dgst -sha256)

echo $pubk_node_hash

# TODO:
# 1. Displays MRENCLAVE from quote
# 2.




