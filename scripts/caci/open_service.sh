#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_MEMBER="member0"
DEFAULT_ADDRESS="127.0.0.1:443"

member=$DEFAULT_MEMBER
node_rpc_address=${CCF_NODE:-$DEFAULT_ADDRESS}

function usage()
{
    echo "Usage:"
    echo "  $0 [--node $DEFAULT_ADDRESS] [--member $DEFAULT_MEMBER]"
    echo "Open a CCF service, by creating and submitting a proposal."
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

function get_service_status()
{
  curl -k "${node_rpc_address}/node/network" --silent | jq .service_status
}

original_status=$(get_service_status)
service_cert=$(curl -k "${node_rpc_address}/node/network" --silent | jq '.service_certificate')

echo "{
  \"actions\": [
    {
      \"name\": \"transition_service_to_open\",
      \"args\": {
        \"next_service_identity\": ${service_cert}
      }
    }
  ]
}
" > "./transition_service_to_open.json"

./member_propose.sh \
  --node "${node_rpc_address}" \
  --member "${member}" \
  --proposal "./transition_service_to_open.json"

final_status=$(get_service_status)

echo "Service status: ${original_status} => ${final_status}"
echo "Done"