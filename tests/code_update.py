# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.path
import infra.proc
import infra.utils
import suite.test_requirements as reqs
import os
import reconfiguration


from loguru import logger as LOG


@reqs.description("Verify node evidence")
def test_verify_quotes(network, args):
    if args.enclave_type == "virtual":
        LOG.warning("Skipping quote test with virtual enclave")
        return network

    LOG.info("Check the network is stable")
    primary, _ = network.find_primary()
    reconfiguration.check_can_progress(primary)

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

    new_code_id = infra.utils.get_code_id(
        args.enclave_type, args.oe_binary, replacement_package
    )

    LOG.info(f"Adding a node with unsupported code id {new_code_id}")
    code_not_found_exception = None
    try:
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, replacement_package, args, timeout=3)
    except infra.network.CodeIdNotFound as err:
        code_not_found_exception = err

    assert (
        code_not_found_exception is not None
    ), f"Adding a node with unsupported code id {new_code_id} should fail"

    return network


def get_replacement_package(args):
    return "liblogging" if args.package == "libjs_generic" else "libjs_generic"


@reqs.description("Update all nodes code")
def test_update_all_nodes(network, args):
    replacement_package = get_replacement_package(args)

    primary, _ = network.find_nodes()

    first_code_id = infra.utils.get_code_id(
        args.enclave_type, args.oe_binary, args.package
    )
    new_code_id = infra.utils.get_code_id(
        args.enclave_type, args.oe_binary, replacement_package
    )

    if args.enclave_type == "virtual":
        # Pretend this was already present
        network.consortium.add_new_code(primary, first_code_id)

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
    for _ in range(0, len(old_nodes)):
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, replacement_package, args)
        network.trust_node(new_node, args)
        assert new_node

    LOG.info("Retire original nodes running old code")
    for node in old_nodes:
        primary, _ = network.find_nodes()
        network.retire_node(primary, node)
        # Elections take (much) longer than a backup removal which is just
        # a commit, so we need to adjust our timeout accordingly, hence this branch
        if node.node_id == primary.node_id:
            new_primary, _ = network.wait_for_new_primary(primary)
            primary = new_primary
        node.stop()

    LOG.info("Check the network is still functional")
    reconfiguration.check_can_progress(new_node)
    return network


@reqs.description("Adding a new code ID invalidates open proposals")
def test_proposal_invalidation(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Create an open proposal")
    pending_proposals = []
    with primary.client(None, "member0") as c:
        new_member_proposal, _, _ = network.consortium.generate_and_propose_new_member(
            primary, curve=args.participants_curve
        )
        pending_proposals.append(new_member_proposal.proposal_id)

    LOG.info("Add temporary code ID")
    temp_code_id = infra.utils.get_code_id(
        args.enclave_type, args.oe_binary, get_replacement_package(args)
    )
    network.consortium.add_new_code(primary, temp_code_id)

    LOG.info("Confirm open proposals are dropped")
    with primary.client(None, "member0") as c:
        for proposal_id in pending_proposals:
            r = c.get(f"/gov/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Dropped", r.body.json()

    LOG.info("Remove temporary code ID")
    network.consortium.retire_code(primary, temp_code_id)

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_verify_quotes(network, args)
        test_add_node_with_bad_code(network, args)
        # NB: Assumes the current nodes are still using args.package, so must run before test_proposal_invalidation
        test_proposal_invalidation(network, args)
        test_update_all_nodes(network, args)

        # Run again at the end to confirm current nodes are acceptable
        test_verify_quotes(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
