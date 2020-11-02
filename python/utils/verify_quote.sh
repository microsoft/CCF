#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

quote_file_name="quote.bin"
open_enclave_bin_path="/opt/openenclave/bin"
quote_format="LEGACY_REPORT_REMOTE"

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

curl -sS --fail -X GET "${node_rpc_address}"/node/quote "${@}" | jq .raw | xxd -r -p > "${tmp_dir}/${quote_file_name}"

if [ ! -s "${tmp_dir}/${quote_file_name}" ]; then
    echo "Node quote is empty. Virtual mode does not support verification."
    exit 1
fi

echo "Node quote successfully retrieved."

# Remove protocol
stripped_node_rpc_address=${node_rpc_address#*//}

node_pubk_hash=$(echo | openssl s_client -showcerts -connect ${stripped_node_rpc_address} 2>/dev/null | openssl x509 -pubkey -noout | sha256sum | awk '{ print $1 }')

oeverify_quote_data=$(${open_enclave_bin_path}/oeverify -r ${tmp_dir}/${quote_file_name} -f ${quote_format} | grep "sgx_report_data" | cut -d ":" -f 2)

# Extract hex sha-256 (64 char) from report data (128 char)
filter=$(echo ${oeverify_quote_data#*0x} | head -c 64)

echo ${filter}
echo ${node_pubk_hash}

if [ ${filter} = ${node_pubk_hash} ]; then
    echo "Quote matches"
    exit 0
else
    echo "Quote doesn't match"
    exit 1
fi




