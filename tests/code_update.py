# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.path
import infra.proc
import suite.test_requirements as reqs
<<<<<<< HEAD
import ccf.clients
import tempfile

import os
import subprocess
import sys
=======
import os
import subprocess
import sys
import reconfiguration
>>>>>>> upstream/master

from loguru import logger as LOG


def get_code_id(oe_binary_path, lib_path):
    res = subprocess.run(
        [os.path.join(oe_binary_path, "oesign"), "dump", "-e", lib_path],
        capture_output=True,
        check=True,
    )
    lines = [
        line
        for line in res.stdout.decode().split(os.linesep)
        if line.startswith("mrenclave=")
    ]

    return lines[0].split("=")[1]


<<<<<<< HEAD
@reqs.description("Verify nodes quote")
def test_verify_quotes(network, args):
    primary, _ = network.find_primary()

    with primary.client() as c:
        r = c.get("/node/quotes")
        # LOG.error(r.body.json())
        for quote in r.body.json()["quotes"]:
            LOG.success(quote["raw"])
            with tempfile.NamedTemporaryFile() as nf:
                nf.write(bytes.fromhex(quote["raw"]))
                nf.flush()
                LOG.error(f"Wrote quote to {nf.name}")
                input("")

            ret = subprocess.run(
                [args.hostverify, "-r", quote_path], capture_output=True, check=True
            )


@reqs.description("Update all nodes with new code version")
def test_update_all_nodes(network, args):
    first_code_id = get_code_id(
        infra.path.build_lib_path(args.package, args.enclave_type)
    )

    primary, _ = network.find_nodes()
    with primary.client() as uc:
        r = uc.get("/node/code")
        assert r.body.json() == {
            "versions": [{"digest": first_code_id, "status": "ACCEPTED"}],
        }, r.body

    LOG.info("Adding a new node")
    new_node = network.create_and_trust_node(args.package, "localhost", args)
    assert new_node

    new_code_id = get_code_id(
        infra.path.build_lib_path(args.patched_file_name, args.enclave_type)
    )

    LOG.info(f"Adding a node with unsupported code id {new_code_id}")
    code_not_found_exception = None
    try:
        network.create_and_add_pending_node(
            args.patched_file_name, "localhost", args, timeout=3
        )
    except infra.network.CodeIdNotFound as err:
        code_not_found_exception = err

    assert (
        code_not_found_exception is not None
    ), f"Adding a node with unsupported code id {new_code_id} should fail"

    # Slow quote verification means that any attempt to add a node may cause an election, so confirm primary after adding node
    primary, _ = network.find_primary()

    network.consortium.add_new_code(primary, new_code_id)

=======
@reqs.description("Verify node evidence")
def test_verify_quotes(network, args):
    if args.enclave_type == "virtual":
        LOG.warning("Skipping quote test with virtual enclave")
        return network

    for node in network.get_joined_nodes():
        LOG.info(f"Verifying quote for node {node.node_id}")
        cafile = os.path.join(network.common_dir, "networkcert.pem")
        assert (
            infra.proc.ccall(
                "verify_quote.sh",
                f"https://{node.pubhost}:{node.pubport}",
                "--cacert",
                f"{cafile}",
                log_output=True,
            ).returncode
            == 0
        ), f"Quote verification for node {node.node_id} failed"

    return network


@reqs.description("Node with bad code fails to join")
def test_add_node_with_bad_code(network, args):
    if args.enclave_type == "virtual":
        LOG.warning("Skipping test_add_node_with_bad_code with virtual enclave")
        return network

    replacement_package = (
        "liblogging" if args.package == "libjs_generic" else "libjs_generic"
    )

    new_code_id = get_code_id(
        args.oe_binary,
        infra.path.build_lib_path(replacement_package, args.enclave_type),
    )

    LOG.info(f"Adding a node with unsupported code id {new_code_id}")
    code_not_found_exception = None
    try:
        network.create_and_add_pending_node(
            replacement_package, "local://localhost", args, timeout=3
        )
    except infra.network.CodeIdNotFound as err:
        code_not_found_exception = err

    assert (
        code_not_found_exception is not None
    ), f"Adding a node with unsupported code id {new_code_id} should fail"

    return network


@reqs.description("Update all nodes code")
def test_update_all_nodes(network, args):
    replacement_package = (
        "liblogging" if args.package == "libjs_generic" else "libjs_generic"
    )

    primary, _ = network.find_nodes()

    first_code_id, new_code_id = [
        get_code_id(args.oe_binary, infra.path.build_lib_path(pkg, args.enclave_type))
        for pkg in [args.package, replacement_package]
    ]

    LOG.info("Add new code id")
    network.consortium.add_new_code(primary, new_code_id)
    with primary.client() as uc:
        r = uc.get("/node/code")
        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected = sorted(
            [
                {"digest": first_code_id, "status": "ALLOWED_TO_JOIN"},
                {"digest": new_code_id, "status": "ALLOWED_TO_JOIN"},
            ],
            key=lambda x: x["digest"],
        )
        assert versions == expected, versions

    LOG.info("Remove old code id")
    network.consortium.retire_code(primary, first_code_id)
>>>>>>> upstream/master
    with primary.client() as uc:
        r = uc.get("/node/code")
        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected = sorted(
            [
<<<<<<< HEAD
                {"digest": first_code_id, "status": "ACCEPTED"},
                {"digest": new_code_id, "status": "ACCEPTED"},
            ],
            key=lambda x: x["digest"],
        )
        assert versions == expected, versions

    new_nodes = set()
    old_nodes_count = len(network.nodes)
    new_nodes_count = old_nodes_count + 1

    LOG.info(
        f"Adding more new nodes ({new_nodes_count}) than originally existed ({old_nodes_count})"
    )
    for _ in range(0, new_nodes_count):
        new_node = network.create_and_trust_node(
            args.patched_file_name, "localhost", args
        )
        assert new_node
        new_nodes.add(new_node)

    LOG.info("Stopping all original nodes")
    old_nodes = set(network.nodes).difference(new_nodes)
    for node in old_nodes:
        LOG.debug(f"Stopping old node {node.node_id}")
        node.stop()

    new_primary, _ = network.wait_for_new_primary(primary.node_id)
    LOG.info(f"New_primary is {new_primary.node_id}")

    LOG.info("Adding another node to the network")
    new_node = network.create_and_trust_node(args.patched_file_name, "localhost", args)
    assert new_node
    network.wait_for_node_commit_sync(args.consensus)

    LOG.info("Remove first code id")
    network.consortium.retire_code(new_node, first_code_id)

    with new_node.client() as uc:
        r = uc.get("/node/code")
        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected = sorted(
            [
                {"digest": first_code_id, "status": "RETIRED"},
                {"digest": new_code_id, "status": "ACCEPTED"},
            ],
            key=lambda x: x["digest"],
        )
        assert versions == expected, versions

    LOG.info(f"Adding a node with retired code id {first_code_id}")
    code_not_found_exception = None
    try:
        network.create_and_add_pending_node(args.package, "localhost", args, timeout=3)
    except infra.network.CodeIdRetired as err:
        code_not_found_exception = err

    assert (
        code_not_found_exception is not None
    ), f"Adding a node with unsupported code id {new_code_id} should fail"

    LOG.info("Adding another node with the new code to the network")
    new_node = network.create_and_trust_node(args.patched_file_name, "localhost", args)
    assert new_node
    network.wait_for_node_commit_sync(args.consensus)


def run(args):
    hosts = ["localhost"]

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        test_verify_quotes(network, args)
        # test_update_all_nodes(network, args)
=======
                {"digest": new_code_id, "status": "ALLOWED_TO_JOIN"},
            ],
            key=lambda x: x["digest"],
        )
        assert versions == expected, versions

    old_nodes = network.nodes.copy()

    LOG.info("Start fresh nodes running new code")
    for _ in range(0, len(network.nodes)):
        new_node = network.create_and_trust_node(
            replacement_package, "local://localhost", args
        )
        assert new_node
>>>>>>> upstream/master

    LOG.info("Retire original nodes running old code")
    for node in old_nodes:
        primary, _ = network.find_nodes()
        network.consortium.retire_node(primary, node)
        # Elections take (much) longer than a backup removal which is just
        # a commit, so we need to adjust our timeout accordingly, hence this branch
        if node.node_id == primary.node_id:
            new_primary, new_term = network.wait_for_new_primary(primary.node_id)
            LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")
            primary = new_primary
        network.nodes.remove(node)
        node.stop()

    LOG.info("Check the network is still functional")
    reconfiguration.check_can_progress(new_node)
    return network

<<<<<<< HEAD
    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="liblogging",
        )
        parser.add_argument(
            "--oesign", help="Path to oesign binary", type=str, required=True
        )
        parser.add_argument(
            "--hostverify", help="Path to hostverify binary", type=str, required=True
        )
=======
>>>>>>> upstream/master

def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_verify_quotes(network, args)
        test_add_node_with_bad_code(network, args)
        test_update_all_nodes(network, args)
        test_verify_quotes(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.enclave_type == "virtual":
        LOG.warning("Skipping code update test with virtual enclave")
        sys.exit()

    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
