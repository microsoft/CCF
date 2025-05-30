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
    echo "Trust all pending nodes on this service."
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

function get_node_statuses()
{
  curl -k "${node_rpc_address}/node/network/nodes" --silent \
   | jq '.nodes | map({(.node_id): .status}) | reduce .[] as $e ({}; . + $e)'
}

echo "Fetching nodes"
initial_nodes=$(get_node_statuses)

mapfile -t pending_node_ids < <(jq -r 'to_entries.[] | select(.value == "Pending").key' <<< "${initial_nodes}")

PATH_HERE=$(dirname "$(realpath -s "$0")")

for node in "${pending_node_ids[@]}"; do
    echo "Creating proposal to trust ${node}"
    filename="./trust_${node}.json"
    jq -n \
      '{actions: [{name: "transition_node_to_trusted", args: {node_id: $node, valid_from: $datetime}}]}' \
      --arg node "$node" \
      --arg datetime "$(date -Is)" \
    > "$filename"

    echo "Submitting proposal $filename"
    "${PATH_HERE}/member_propose.sh" \
      --node "${node_rpc_address}" \
      --member "${member}" \
      --proposal "$filename"
done

final_nodes=$(get_node_statuses)

echo "Initial nodes: ${initial_nodes}"
echo "Resulting nodes: ${final_nodes}"

echo "Done"