# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import json

import logging
import time

from loguru import logger as LOG

def create_and_add_node(network, args, node_id, member_host, member_port, should_succeed=True):
    dict_args = vars(args)
    forwarded_args = {
        arg: dict_args[arg] for arg in infra.ccf.Network.node_args_to_forward
    }
    node_status = args.node_status or "pending"
    new_node = network.create_node(node_id, "localhost")
    new_node.start(lib_name="libloggingenc", node_status=node_status, **forwarded_args)
    new_node_info = new_node.remote.info()
    new_cert_path = "{}/{}".format(new_node.remote.remote.root, getattr(new_node.remote, "pem"))

    if should_succeed:
        new_quote_path = "{}/{}".format(new_node.remote.remote.root, getattr(new_node.remote, "quote"))
    else:
        invalid_node = network.create_node(node_id + 1, "localhost")
        invalid_node.start(lib_name="libluagenericenc", node_status=node_status, **forwarded_args)
        new_quote_path = "{}/{}".format(invalid_node.remote.remote.root, getattr(invalid_node.remote, "quote"))
        invalid_node.stop()

    result = infra.proc.ccall(
        "./memberclient",
        "add_node",
        "--host={}".format(member_host),
        "--port={}".format(member_port),
        "--ca=networkcert.pem",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        "--new_node_host={}".format(new_node_info["host"]),
        "--new_node_pub_host={}".format(new_node_info["host"]),
        "--new_node_raft_port={}".format(new_node_info["raftport"]),
        "--new_node_tls_port={}".format(new_node_info["tlsport"]),
        "--new_node_cert={}".format(new_cert_path),
        "--new_node_quote={}".format(new_quote_path),
        "--sign",
    )
    
    j_result = json.loads(result.stdout)
    if should_succeed:
        # When successfully adding a new node, a proposal to accept 
        # the new node is automatically generated. The id of that 
        # proposal is the result value
        assert j_result["result"]
    else:
        assert j_result["error"]["code"]

    return new_node_info

def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        infra.proc.ccall(
            "./logging_client",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--ca=networkcert.pem",
            "--cert=user1_cert.pem",
            "--privk=user1_privk.pem",
        )

        # add a valid node
        new_node_info = create_and_add_node(network, args, 2, primary.host, primary.tls_port)
        # add an invalid node
        new_node_info = create_and_add_node(network, args, 3, primary.host, primary.tls_port, False)
        

if __name__ == "__main__":
    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            required=True,
        )
    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc" or "libunsignedenc"
    run(args)
