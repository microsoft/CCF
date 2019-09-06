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


def add_new_code(network, new_code_id):
    LOG.debug(f"Adding new code id: {new_code_id}")

    primary, _ = network.find_primary()
    result = network.propose(1, primary, "add_code", f"--new-code-id={new_code_id}")

    network.vote_using_majority(primary, result[1]["id"], True)


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

        new_node = network.create_and_add_node(args.package, args)
        assert new_node

        new_code_id = get_code_id(f"{args.patched_file_name}.so.signed")

        LOG.debug(f"Adding a node with unsupported code id {new_code_id}")
        assert (
            network.create_and_add_node(args.patched_file_name, args) == None
        ), "Adding node with unsupported code id should fail"

        add_new_code(network, new_code_id)

        LOG.debug("Replacing all nodes with previous code version with new code")
        new_nodes = set()
        old_nodes_count = len(network.nodes)

        LOG.debug("Adding more new nodes than originally existed")
        for _ in range(0, old_nodes_count + 1):
            new_node = network.create_and_add_node(args.patched_file_name, args)
            assert new_node
            new_nodes.add(new_node)

        for node in new_nodes:
            new_primary = node
            break

        LOG.debug("Stopping all original nodes")
        old_nodes = set(network.nodes).difference(new_nodes)
        for node in old_nodes:
            LOG.debug(f"Stopping node {node.node_id}")
            node.stop()

        LOG.debug("Waiting for a new primary to be elected...")
        time.sleep(args.election_timeout * 6 / 1000)

        new_primary, _ = network.find_primary()
        LOG.debug(f"Waited, new_primary is {new_primary.node_id}")

        new_node = network.create_and_add_node(args.patched_file_name, args)
        assert new_node
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
