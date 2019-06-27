# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import json
import logging
import os
import subprocess
import time
from infra.ccf import NodeNetworkState
from loguru import logger as LOG


def get_code_id(lib_path):
    oed = subprocess.run(
        [args.oesign, "dump", "-e", lib_path], capture_output=True, check=True
    )
    lines = [
        line
        for line in oed.stdout.decode().split(os.linesep)
        if line.startswith("mrenclave=")
    ]

    return lines[0].split("=")[1]


def vote_to_accept(primary, proposal_id):
    # vote to accept the new code id
    result = infra.proc.ccall(
        "./memberclient",
        "vote",
        "--accept",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        f"--host={primary.host}",
        f"--port={primary.tls_port}",
        f"--id={proposal_id}",
        "--ca=networkcert.pem",
        "--sign",
    )
    j_result = json.loads(result.stdout)
    assert not j_result["result"]

    result = infra.proc.ccall(
        "./memberclient",
        "vote",
        "--accept",
        "--cert=member2_cert.pem",
        "--privk=member2_privk.pem",
        f"--host={primary.host}",
        f"--port={primary.tls_port}",
        f"--id={proposal_id}",
        "--ca=networkcert.pem",
        "--sign",
    )
    j_result = json.loads(result.stdout)
    assert j_result["result"]


def add_new_code(primary, new_code_id):
    LOG.debug(f"New code id: {new_code_id}")

    # first propose adding the new code id
    result = infra.proc.ccall(
        "./memberclient",
        "add_code",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        f"--host={primary.host}",
        f"--port={primary.tls_port}",
        "--ca=networkcert.pem",
        f"--new_code_id={new_code_id}",
    )

    vote_to_accept(primary, 0)


def create_node_using_new_code(network, args):
    # add a node using unsupported code
    assert network.create_and_add_node(args.patched_file_name, args, False) == (
        False,
        infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND,
    )


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        forwarded_args = {
            arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
        }

        res, new_node, new_node_id = network.create_and_add_node(
            args.package, args, True
        )
        new_node.join_network()

        new_code_id = get_code_id(f"{args.patched_file_name}.so.signed")

        # try to add a node using unsupported code
        assert network.create_and_add_node(args.patched_file_name, args, False) == (
            False,
            infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND,
        )

        add_new_code(primary, new_code_id)

        with open("networkcert.pem", mode="rb") as file:
            net_cert = list(file.read())

        new_nodes = set()
        old_nodes_count = len(network.nodes)
        # add nodes using the same code id that failed earlier
        for i in range(0, old_nodes_count + 1):
            LOG.debug(f"Adding node using new code")
            res, new_node, new_node_id = network.create_and_add_node(
                args.patched_file_name, args
            )
            assert res
            new_node.join_network()
            new_nodes.add(new_node)

        network.wait_for_node_commit_sync()

        for node in new_nodes:
            new_primary = node
            break

        old_nodes = set(network.nodes).difference(new_nodes)
        for node in old_nodes:
            LOG.debug(f"Stopping node {node.node_id}")
            node.stop()

        # wait for a new leader to be elected
        time.sleep(args.election_timeout * 6 / 1000)

        new_leader = network.find_leader()[0]
        LOG.debug(f"Waiting, new_leader is {new_leader.node_id}")
        res, new_node, new_node_id = network.create_and_add_node(
            args.patched_file_name, args
        )
        new_node.join_network_custom(new_leader.host, new_leader.tls_port, net_cert)
        network.wait_for_node_commit_sync()


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="libloggingenc",
        )
        parser.add_argument(
            "--oesign", help="Path to oesign binary", type=str, required=True
        )
        parser.add_argument(
            "--oeconfpath",
            help="Path to oe configuration file",
            type=str,
            required=True,
        )
        parser.add_argument(
            "--oesignkeypath", help="Path to oesign key", type=str, required=True
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    args.patched_file_name = "{}.patched".format(args.package)
    run(args)
