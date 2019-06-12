# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import json

import logging
import time

from loguru import logger as LOG


def create_and_add_node(
    network, lib_name, args, node_id, member_host, member_port, should_succeed=True
):
    forwarded_args = {
        arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
    }
    node_status = args.node_status or "pending"
    new_node = network.create_node(node_id, "localhost")
    new_node.start(
        lib_name=lib_name,
        node_status=node_status,
        workspace=args.workspace,
        label=args.label,
        **forwarded_args
    )
    new_node_info = new_node.remote.info()

    new_node_json_path = "{}/node_{}.json".format(new_node.remote.remote.root, node_id)
    with open(new_node_json_path, "w") as node_file:
        json.dump([new_node_info], node_file, indent=4)

    result = infra.proc.ccall(
        "./memberclient",
        "add_node",
        "--host={}".format(member_host),
        "--port={}".format(member_port),
        "--ca=networkcert.pem",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        "--nodes_to_add={}".format(new_node_json_path),
        "--sign",
    )

    j_result = json.loads(result.stdout)
    if not should_succeed:
        return (False, j_result["error"]["code"])

    return (True, j_result["result"])


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        # add a valid node
        assert create_and_add_node(
            network, "libloggingenc", args, 2, primary.host, primary.tls_port
        ) == (True, 2)
        # add an invalid node
        assert create_and_add_node(
            network, "libluagenericenc", args, 3, primary.host, primary.tls_port, False
        ) == (False, infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
