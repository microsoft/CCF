#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_MEMBER="member0"

member=$DEFAULT_MEMBER
node_rpc_address=""

function usage()
{
    echo "Usage:"
    echo "  $0 --node <node_rpc_ip_or_fqdn:port> [--member $DEFAULT_MEMBER]"
    echo "Remove a given node from the service."
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

if [ -z "${node_rpc_address}" ]; then
    echo "Error: No node in arguments (--node)"
    exit 1
fi

node_id=$(curl -k --silent "${node_rpc_address}/node/network/nodes/self" | jq -r '.node_id')

filename="./remove_${node_id}.json"

echo "Writing proposal to ${filename}"
echo "{
  \"actions\": [
    {
      \"name\": \"remove_node\",
      \"args\": {
        \"node_id\": \"${node_id}\"
      }
    }
  ]
}
" > "$filename"

PATH_HERE=$(dirname "$(realpath -s "$0")")
echo "Submitting proposal"
"${PATH_HERE}/member_propose.sh" \
  --node "${node_rpc_address}" \
  --member "${member}" \
  --proposal "$filename"

echo "Done"