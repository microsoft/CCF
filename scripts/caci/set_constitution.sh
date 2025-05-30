#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e


DEFAULT_MEMBER="member0"
DEFAULT_ADDRESS="127.0.0.1:443"

member=$DEFAULT_MEMBER
node_rpc_address=${CCF_NODE:-$DEFAULT_ADDRESS}
constitution_dir=""
auto_accept=false

function usage()
{
    echo "Usage:"
    echo "  $0 --path </path/to/constitution/dir> [--auto-accept] [--node $DEFAULT_ADDRESS] [--member $DEFAULT_MEMBER]"
    echo "Set the JS file in a given folder to be the constitution of a CCF service."
    echo "--auto-accept will use an auto-accepting resolve function, rather than the one given."
    echo "Can also set node address with the CCF_NODE env var."
}

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        -p|--path)
            constitution_dir="$2"
            shift
            ;;
        -a|--auto-accept)
            auto_accept=true
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

if [ -z "${constitution_dir}" ]; then
    echo "Error: No path in arguments (--path)"
    exit 1
fi

jq_args=()

validate_path="${constitution_dir}/validate.js"
if [ ! -f "$validate_path" ]; then
    echo "Error: File not found at: $validate_path"
    exit 1
else
    jq_args+=("--rawfile" "validate" "$validate_path")
fi

apply_path="${constitution_dir}/apply.js"
if [ ! -f "$apply_path" ]; then
    echo "Error: File not found at: $apply_path"
    exit 1
else
    jq_args+=("--rawfile" "apply" "$apply_path")
fi

if "$auto_accept"; then
    resolve=$'export function resolve() { return "Accepted"; }\n'
    jq_args+=("--arg" "resolve" "$resolve")
else
    resolve_path="${constitution_dir}/resolve.js"
    if [ ! -f "$resolve_path" ]; then
        echo "Error: File not found at: $resolve_path"
        exit 1
    else
        jq_args+=("--rawfile" "resolve" "$resolve_path")
    fi
fi

actions_path="${constitution_dir}/actions.js"
if [ ! -f "$actions_path" ]; then
    echo "Error: File not found at: $actions_path"
    exit 1
else
    jq_args+=("--rawfile" "actions" "$actions_path")
fi

proposal="./set_constitution.json"
echo "Writing proposal to $proposal"
jq -n \
  '{actions: [{name: "set_constitution", args: {constitution: ($validate + $apply + $resolve + $actions)}}]}' \
  "${jq_args[@]}" \
  > $proposal

PATH_HERE=$(dirname "$(realpath -s "$0")")
echo "Submitting proposal"
"${PATH_HERE}/member_propose.sh" \
  --node "${node_rpc_address}" \
  --member "${member}" \
  --proposal $proposal

echo "Done"
