#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_MEMBER="member0"
DEFAULT_ADDRESS="127.0.0.1:443"

member=$DEFAULT_MEMBER
node_rpc_address=${CCF_NODE:-$DEFAULT_ADDRESS}
proposal=""

function usage()
{
    echo "Usage:"
    echo "  $0 --proposal <proposal.json> [--node $DEFAULT_ADDRESS] [--member $DEFAULT_MEMBER]"
    echo "Submit a proposal to a CCF service."
    echo "Can also set node address with the CCF_NODE env var."
}

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        -p|--proposal)
            proposal="$2"
            shift
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

if [ -z "${proposal}" ]; then
    echo "Error: No proposal in arguments (--proposal)"
    exit 1
fi

member_cert="${member}_cert.pem"
member_privk="${member}_privk.pem"

ccf_cose_sign1 \
  --signing-key $member_privk \
  --signing-cert $member_cert \
  --ccf-gov-msg-type proposal \
  --ccf-gov-msg-created_at $(date -Is) \
  --content ${proposal} \
  | curl -k \
    "${node_rpc_address}/gov/members/proposals:create?api-version=2024-07-01" \
    -H "Content-type: application/cose" \
    --data-binary @- --silent \
  | jq .
