#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

open_enclave_path=${OPEN_ENCLAVE_PATH:-"/opt/openenclave"}
default_port=443

function usage() {
    echo "Usage:"
    echo "  $0 https://<node-address> [--mrenclave <mrenclave_hex>] [CURL_OPTIONS]"
    echo "Verify target node's remote attestation quote."
    echo "Verification involves confirming that the public key (DER encoded) of the node certificate matches the SGX report data and that the MRENCLAVE included in the quote is trusted."
    echo "A specific trusted mrenclave can be specified with --mrenclave. If specified, the quoted mrenclave must match this exactly. If unspecified, the service's currently accepted code versions will be retrieved from the target node, and verification will succeed only if the quoted mrenclave is present in this list."
}

if [[ "$1" =~ ^(-h|-\?|--help)$ ]]; then
    usage
    exit 0
fi

if [ -z "$1" ]; then
    echo "Error: First argument should be CCF node address, e.g.: https://127.0.0.1:8000"
    exit 1
fi

node_address=$1
shift

# Add default port number if not included (required by openssl s_client)
if ! [[ $node_address =~ .*:[0-9]+$ ]]; then
    node_address="${node_address}:${default_port}"
fi

while [ "$1" != "" ]; do
    case $1 in
    -h | -\? | --help)
        usage
        exit 0
        ;;
    --mrenclave)
        trusted_mrenclaves=("$2")
        ;;
    *)
        break
        ;;
    esac
    shift
    shift
done

if [ ${#trusted_mrenclaves[@]} -eq 0 ]; then
    for pair in $(curl -sS --fail -X GET "${node_address}"/gov/kv/nodes/code_ids "${@}" | jq -c 'to_entries[]'); do
        code_status=$(echo "${pair}" | jq -r .'value')
        if [ "${code_status}" = "AllowedToJoin" ]; then
            trusted_mrenclaves+=("$(echo "${pair}" | jq -r .'key')")
        fi
    done
    echo "Retrieved ${#trusted_mrenclaves[@]} accepted code versions from CCF service."
fi

# Temporary directory for storing retrieved quote
tmp_dir=$(mktemp -d)
function cleanup() {
    rm -rf "${tmp_dir}"
}
trap cleanup EXIT

curl_output=$(curl -sS --fail -X GET "${node_address}"/node/quotes "${@}")

# Query quotes for ALL nodes to support talking to load-balancer with no session tracking, resulting into talking to different nodes during script execution.
# Save quotes in format
# tmp_dir/node_1_id.endorsements
# tmp_dir/node_1_id.quote
# ...
# tmp_dir/node_N_id.endorsements
# tmp_dir/node_N_id.quote
echo "${curl_output}" | jq -r '.quotes[] | .node_id as $id | .endorsements as $endorsements | .raw as $quote | "\($id).endorsements \($endorsements)\n\($id).quote \($quote)"' | while read -r line; do
    filename=$(echo "${line}" | awk '{print $1}')
    content=$(echo "${line}" | awk '{for (i=2; i<=NF; i++) printf $i;}')
    echo "${content}" | base64 --decode >"${tmp_dir}/${filename}"
done

echo "${curl_output}" >out.txt

# At least one quote has to be there.
quotes_count=$(find "${tmp_dir}" -maxdepth 1 -type f -name "*.quote" | wc -l)
if [ "$quotes_count" -eq 0 ]; then
    echo "Error: No quotes find"
    exit 1
fi

# All quotes must be non-empty.
empty_quotes=$(find "${tmp_dir}" -maxdepth 1 -type f -name "*.quote" -empty)
if [ -n "$empty_quotes" ]; then
    echo "Error: Empty quote found. Virtual mode does not support SGX quotes."
    exit 1
fi

echo "Nodes quotes successfully retrieved."

nodes=()
for file in "${tmp_dir}"/*.quote; do
    base_name=$(basename "$file" .quote)
    nodes+=("$base_name")
done

for node in "${nodes[@]}"; do
    quote_file_name="${node}.quote"
    endorsements_file_name="${node}.endorsements"

    oeverify_output=$("${open_enclave_path}"/bin/oeverify -r "${tmp_dir}"/"${quote_file_name}" -e "${tmp_dir}"/"${endorsements_file_name}")

    # Extract SGX report data
    oeverify_report_data=$(echo "${oeverify_output}" | grep "sgx_report_data" | cut -d ":" -f 2)
    # Extract hex sha-256 (64 char) from report data (128 char)
    extracted_report_data=$(echo "${oeverify_report_data#*0x}" | head -c 64)

    # Remove protocol and compute hash of target node's public key (DER)
    stripped_node_address=${node_address#*//}
    node_pubk_hash=$(echo | openssl s_client -showcerts -connect "${stripped_node_address}" 2>/dev/null | openssl x509 -pubkey -noout | openssl ec -pubin -outform der 2>/dev/null | sha256sum | awk '{ print $1 }')

    # Extract mrenclave
    is_mrenclave_valid=false
    oeverify_mrenclave=$(echo "${oeverify_output}" | grep "unique_id" | cut -d ":" -f 2)
    extracted_mrenclave="${oeverify_mrenclave#*0x}"
    for mrenclave in "${trusted_mrenclaves[@]}"; do
        if [ "${mrenclave}" == "${extracted_mrenclave}" ]; then
            is_mrenclave_valid=true
        fi
    done

    if [ "${extracted_report_data}" == "${node_pubk_hash}" ] && [ "${is_mrenclave_valid}" == true ]; then
        echo "mrenclave: \"${extracted_mrenclave}\""
        echo "Quote verification successful."
        exit 0
    fi

done

echo "Error: quote verification failed. No attested node found"
exit 1
