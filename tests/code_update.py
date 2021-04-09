# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.path
import infra.proc
import suite.test_requirements as reqs
import os
import subprocess
import reconfiguration
import hashlib

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

    if args.enclave_type != "virtual":
        first_code_id, new_code_id = [
            get_code_id(
                args.oe_binary, infra.path.build_lib_path(pkg, args.enclave_type)
            )
            for pkg in [args.package, replacement_package]
        ]
    else:
        def make_fake_virtual_code_id(s):
            return hashlib.sha256(s.encode()).hexdigest()
        first_code_id = make_fake_virtual_code_id("Old")
        network.consortium.add_new_code(primary, first_code_id) # Pretend this was already there
        new_code_id = make_fake_virtual_code_id("New")

    LOG.info("Add new code id")
    network.consortium.add_new_code(primary, new_code_id)
    with primary.client() as uc:
        r = uc.get("/node/code")
        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected = sorted(
            [
                {"digest": first_code_id, "status": "AllowedToJoin"},
                {"digest": new_code_id, "status": "AllowedToJoin"},
            ],
            key=lambda x: x["digest"],
        )
        assert versions == expected, versions

    LOG.info("Remove old code id")
    network.consortium.retire_code(primary, first_code_id)
    with primary.client() as uc:
        r = uc.get("/node/code")
        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected = sorted(
            [
                {"digest": new_code_id, "status": "AllowedToJoin"},
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


@reqs.description("Adding a new code ID invalidates open proposals")
def test_proposal_invalidation(network, args):
    # # Create some open proposals
    # pending_proposals = []
    # with node.client(None, "member0") as c:
    #     r = c.post(
    #         "/gov/proposals.js",
    #         valid_set_recovery_threshold,
    #     )
    #     assert r.status_code == 200, r.body.text()
    #     body = r.body.json()
    #     assert body["state"] == "Open", body
    #     pending_proposals.append(body["proposal_id"])

    #     r = c.post(
    #         "/gov/proposals.js",
    #         always_accept_with_one_vote,
    #     )
    #     assert r.status_code == 200, r.body.text()
    #     body = r.body.json()
    #     assert body["state"] == "Open", body
    #     pending_proposals.append(body["proposal_id"])

    # # Create a set_constitution proposal, with test proposals removed, and pass it
    # original_constitution = args.constitution
    # modified_constitution = [
    #     path for path in original_constitution if "test_actions.js" not in path
    # ]
    # network.consortium.set_constitution(node, modified_constitution)

    # with node.client(None, "member0") as c:
    #     # Check all other proposals were invalidated
    #     for proposal_id in pending_proposals:
    #         r = c.get(f"/gov/proposals.js/{proposal_id}")
    #         assert r.status_code == 200, r.body.text()
    #         assert r.body.json()["state"] == "Invalidated", r.body.json()

    #     # Confirm constitution has changed by proposing test actions which are no longer present
    #     r = c.post(
    #         "/gov/proposals.js",
    #         always_accept_noop,
    #     )
    #     assert (
    #         r.status_code == 400
    #         and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
    #     ), r.body.text()

    #     r = c.post(
    #         "/gov/proposals.js",
    #         always_reject_noop,
    #     )
    #     assert (
    #         r.status_code == 400
    #         and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
    #     ), r.body.text()

    #     # Confirm modified constitution can still accept valid proposals
    #     r = c.post(
    #         "/gov/proposals.js",
    #         valid_set_recovery_threshold,
    #     )
    #     assert r.status_code == 200, r.body.text()
    #     body = r.body.json()
    #     assert body["state"] == "Open", body

    # # Confirm original constitution was restored
    # r = c.post(
    #     "/gov/proposals.js",
    #     always_accept_noop,
    # )
    # assert r.status_code == 200, r.body.text()
    # body = r.body.json()
    # assert body["state"] == "Accepted", body

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_verify_quotes(network, args)
        test_add_node_with_bad_code(network, args)
        test_update_all_nodes(network, args)
        test_proposal_invalidation(network, args)

        # Run again at the end to confirm current nodes are acceptable
        test_verify_quotes(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
