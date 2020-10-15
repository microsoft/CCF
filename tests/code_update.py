# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.path
import infra.proc
import suite.test_requirements as reqs
import os
import subprocess
import sys
import tempfile

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


def verify_evidence(oe_binary_path, evidence_path):
    # Until https://github.com/microsoft/CCF/issues/1468 is done, CCF
    # uses old attestation API to generate quotes
    report_format = "LEGACY_REPORT_REMOTE"
    res = subprocess.run(
        [
            os.path.join(oe_binary_path, "oeverify"),
            "-f",
            report_format,
            "-r",
            evidence_path,
        ],
        capture_output=True,
        check=True,
    )
    lines = [
        line
        for line in res.stdout.decode().split(os.linesep)
        if line.startswith("Enclave unique_id: ")
    ]

    return lines[0].split("0x")[1]


@reqs.description("Verify node evidence")
def test_verify_quotes(network, args):
    if args.enclave_type == "virtual":
        LOG.warning("Skipping quote test with virtual enclave")
        return network

    for node in network.get_joined_nodes():
        with tempfile.NamedTemporaryFile() as nf:
            with node.client() as c:
                r = c.get("/node/quote")
                raw_quote = bytes.fromhex(r.body.json()["raw"])
                mrenclave = r.body.json()["mrenclave"]
                nf.write(raw_quote)
                nf.flush()
                result = verify_evidence(args.oe_binary, nf.name)
                assert (
                    mrenclave == result
                ), f"/node/quote mrenclave does not match quote mrenclave for node {node.node_id}"

    return network


@reqs.description("Update all nodes code")
def test_update_all_nodes(network, args):
    primary, _ = network.find_nodes()

    first_code_id = get_code_id(
        args.oe_binary, infra.path.build_lib_path(args.package, args.enclave_type)
    )

    with primary.client() as uc:
        r = uc.get("/node/code")
        assert r.body.json() == {
            "versions": [{"digest": first_code_id, "status": "ACCEPTED"}],
        }, r.body

    LOG.info("Adding a new node")
    new_node = network.create_and_trust_node(args.package, "localhost", args)
    assert new_node

    new_code_id = get_code_id(
        args.oe_binary,
        infra.path.build_lib_path(args.patched_file_name, args.enclave_type),
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

    with primary.client() as uc:
        r = uc.get("/node/code")
        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected = sorted(
            [
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
    network.wait_for_node_commit_sync()

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
    network.wait_for_node_commit_sync()


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_verify_quotes(network, args)
        test_update_all_nodes(network, args)
        test_verify_quotes(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.enclave_type == "virtual":
        LOG.warning("Skipping code update test with virtual enclave")
        sys.exit()

    args.package = args.app_script and "liblua_generic" or "liblogging"
    args.patched_file_name = "{}.patched".format(args.package)
    run(args)
