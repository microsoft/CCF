#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_MEMBER="member0"
DEFAULT_ADDRESS="https://127.0.0.1:443"

member=$DEFAULT_MEMBER
node_rpc_address=${CCF_NODE:-$DEFAULT_ADDRESS}

function usage()
{
    echo "Usage:"
    echo "  $0 [--node $DEFAULT_ADDRESS] [--member $DEFAULT_MEMBER]"
    echo "Submit an ACK to activate a CCF member"
    echo "Can also set node address with the CCF_NODE env var."
}

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        -n|--node)
            node_rpc_address="$2"
            shift
            ;;
        -m|--member)
            member="$2"
            shift
            ;;
        *)
            break
    esac
    shift
done

member_cert="${member}_cert.pem"
member_privk="${member}_privk.pem"

# Calculate member ID
member_id=$(openssl x509 -in "$member_cert" -noout -fingerprint -sha256 | cut -d "=" -f 2 | sed 's/://g' | awk '{print tolower($0)}')

function get_member_status()
{
  curl -k "${node_rpc_address}/gov/service/members/${member_id}?api-version=2024-07-01" --silent | jq .status
}

original_status=$(get_member_status)

echo "Getting state-digest for $member"
touch empty_file

ccf_cose_sign1 \
  --signing-key "$member_privk" \
  --signing-cert "$member_cert" \
  --ccf-gov-msg-type state_digest \
  --ccf-gov-msg-created_at "$(date -Is)" \
  --content empty_file \
  | curl -k \
    "${node_rpc_address}/gov/members/state-digests/${member_id}:update?api-version=2024-07-01" \
    -X POST \
    -H "Content-type: application/cose" \
    --data-binary @- --silent \
  | jq > ./digest.json

echo Signing and submitting state-digest
ccf_cose_sign1 \
  --signing-key "$member_privk" \
  --signing-cert "$member_cert"  \
  --ccf-gov-msg-type ack \
  --ccf-gov-msg-created_at "$(date -Is)" \
  --content ./digest.json \
  | curl -k \
    "${node_rpc_address}/gov/members/state-digests/${member_id}:ack?api-version=2024-07-01" \
    -H "Content-type: application/cose" \
    --data-binary @- --silent

final_status=$(get_member_status)

echo "Member status: ${original_status} => ${final_status}"
echo Done