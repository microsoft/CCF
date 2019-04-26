# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
from enum import Enum
import json
import sys
import infra.path
import infra.remote

#
# Usage examples:
#   (With a quote file - e.g. ACC machine)
#   $  python ../tests/infra/gennodes.py --output-file=nodes.json --expect-quote \
#       --node 10.0.1.10 13.80.134.85 41094 41229 0.pem quote0.bin \
#       --node 127.218.194.179 127.218.194.179 51388 35702 1.pem quote1.bin
#
#   (Without a quote)
#    $  python ../tests/infra/gennodes.py --output-file=nodes.json \
#        --node 10.0.1.10 13.80.134.85 41094 41229 0.pem \
#        --node 127.218.194.179 127.218.194.179 51388 35702 1.pem
#

DEFAULT_OUTPUT_FILE_NAME = "nodes.json"


class NodeInfo(Enum):
    host = 1
    pubhost = 2
    raftport = 3
    tlsport = 4
    cert = 5
    status = 6
    quote = 7
    pastsecret = 8


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Creates the nodes json file necessary for the genesigenerator utility to create the genesis transaction tx0."
    )
    parser.add_argument(
        "-n",
        "--node",
        nargs="*",
        help='Pass as many "--node" as there are nodes in the network.',
        action="append",
    )
    parser.add_argument(
        "-q",
        "--expect-quote",
        help="Expect quote from starting node (ACC only).",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-o",
        "--output-file",
        help="Output file. Default is {}.".format(DEFAULT_OUTPUT_FILE_NAME),
        default=DEFAULT_OUTPUT_FILE_NAME,
    )
    args = parser.parse_args()

    print("Generating {} file...".format(args.output_file))

    for node in args.node:
        if args.expect_quote and len(node) < NodeInfo.quote.value:
            sys.stderr.write(
                "ERROR: gennodes.py requires {} arguments, including quote file!\n".format(
                    NodeInfo.quote.value
                )
            )
            sys.exit(1)

    nodes_output = []

    for node in args.node:
        node_output = {}
        arg_index = 0
        for nodeinfo_ in NodeInfo:
            if arg_index < len(node):
                if nodeinfo_ == NodeInfo.cert:
                    node_output[nodeinfo_.name] = infra.path.cert_bytes(node[arg_index])
                elif nodeinfo_ == NodeInfo.quote:
                    node_output[nodeinfo_.name] = infra.path.quote_bytes(
                        node[arg_index]
                    )
                else:
                    node_output[nodeinfo_.name] = node[arg_index]
            else:
                node_output[nodeinfo_.name] = []
            # add node with status TRUSTED
            node_output["status"] = 0
            arg_index += 1
        nodes_output.append(node_output)

    with open(args.output_file, "w") as nodes_:
        json.dump(nodes_output, nodes_, indent=4)

    print("Done.")
