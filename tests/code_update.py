# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from base64 import b64encode
import infra.e2e_args
import infra.network
import infra.path
import infra.proc
import infra.utils
import suite.test_requirements as reqs
import os
import time
from infra.checker import check_can_progress
from infra.is_snp import (
    DEFAULT_SNP_SECURITY_POLICY_B64,
    IS_SNP,
    DEFAULT_SNP_HOST_DATA,
    DEFAULT_SNP_SECURITY_POLICY,
)


from loguru import logger as LOG

# Dummy code id used by virtual nodes
VIRTUAL_CODE_ID = "0" * 96

# Digest of the UVM, in our control as long as we have a self hosted agent pool
SNP_ACI_MEASUREMENT = "858cc56259152dba38f1029a4f6ed18c6e88a5631bad6ea13e959d2b1137fb6d86023f762d7299a31df61e1a77386c5c"


@reqs.description("Verify node evidence")
def test_verify_quotes(network, args):
    if args.enclave_platform == "virtual":
        LOG.warning("Skipping quote test with virtual enclave")
        return network
    elif IS_SNP:
        LOG.warning(
            "Skipping quote test until there is a separate utility to verify SNP quotes"
        )
        return network

    LOG.info("Check the network is stable")
    primary, _ = network.find_primary()
    check_can_progress(primary)

    for node in network.get_joined_nodes():
        LOG.info(f"Verifying quote for node {node.node_id}")
        cafile = os.path.join(network.common_dir, "service_cert.pem")
        assert (
            infra.proc.ccall(
                "verify_quote.sh",
                f"https://{node.get_public_rpc_host()}:{node.get_public_rpc_port()}",
                "--cacert",
                f"{cafile}",
                log_output=True,
            ).returncode
            == 0
        ), f"Quote verification for node {node.node_id} failed"

    return network


@reqs.description("Test that the SNP measurements table")
@reqs.snp_only()
def test_snp_measurements_table(network, args):
    primary, _ = network.find_nodes()

    with primary.client() as client:
        r = client.get("/gov/snp/measurements")
        measurements = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
    expected = [{"digest": SNP_ACI_MEASUREMENT, "status": "AllowedToJoin"}]
    expected.sort(key=lambda x: x["digest"])
    assert measurements == expected, [(a, b) for a, b in zip(measurements, expected)]

    dummy_snp_mesurement = "a" * 96
    network.consortium.add_snp_measurement(primary, dummy_snp_mesurement)

    with primary.client() as client:
        r = client.get("/gov/snp/measurements")
        measurements = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
    expected = [
        {"digest": SNP_ACI_MEASUREMENT, "status": "AllowedToJoin"},
        {"digest": dummy_snp_mesurement, "status": "AllowedToJoin"},
    ]
    expected.sort(key=lambda x: x["digest"])
    assert measurements == expected, [(a, b) for a, b in zip(measurements, expected)]

    network.consortium.remove_snp_measurement(primary, dummy_snp_mesurement)
    with primary.client() as client:
        r = client.get("/gov/snp/measurements")
        measurements = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
    expected = [{"digest": SNP_ACI_MEASUREMENT, "status": "AllowedToJoin"}]
    expected.sort(key=lambda x: x["digest"])
    assert measurements == expected, [(a, b) for a, b in zip(measurements, expected)]

    return network


@reqs.description("Test that the security policies table is correctly populated")
@reqs.snp_only()
def test_host_data_table(network, args):

    primary, _ = network.find_nodes()
    with primary.client() as client:
        r = client.get("/gov/snp/host_data")
        host_data = sorted(r.body.json()["host_data"], key=lambda x: x["raw"])

    expected = [
        {
            "raw": DEFAULT_SNP_HOST_DATA,
            "metadata": "",
        }
    ]
    expected.sort(key=lambda x: x["raw"])

    assert host_data == expected, [(a, b) for a, b in zip(host_data, expected)]


@reqs.description(
    """
Node with no security policy set but good digest joins successfully when the
KV also doesn't have a raw policy associated with the digest.
"""
)
@reqs.snp_only()
def test_add_node_with_host_data(network, args):

    # If we don't throw an exception, joining was successful
    new_node = network.create_node("local://localhost")
    network.join_node(
        new_node,
        args.package,
        args,
        timeout=3,
        env={"SECURITY_POLICY": DEFAULT_SNP_SECURITY_POLICY_B64},
    )
    network.trust_node(new_node, args)


@reqs.description(
    """
Node with no security policy set but good digest joins successfully when the
KV does have a raw policy associated with the digest.
"""
)
@reqs.snp_only()
def test_add_node_with_no_security_policy_not_matching_kv(network, args):

    LOG.info("Change the entry for trusted security policies to include a raw policy")
    primary, _ = network.find_nodes()
    network.consortium.retire_host_data(primary, DEFAULT_SNP_HOST_DATA)
    network.consortium.add_new_host_data(
        primary,
        DEFAULT_SNP_SECURITY_POLICY,
        DEFAULT_SNP_HOST_DATA,
    )

    # If we don't throw an exception, joining was successful
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, timeout=3)
    network.trust_node(new_node, args)

    network.consortium.retire_host_data(
        primary,
        DEFAULT_SNP_HOST_DATA,
    )
    network.consortium.add_new_host_data(primary, "", DEFAULT_SNP_HOST_DATA)


@reqs.description("Node where raw security policy doesn't match digest fails to join")
@reqs.snp_only()
def test_add_node_with_mismatched_host_data(network, args):

    try:
        new_node = network.create_node("local://localhost")
        network.join_node(
            new_node,
            args.package,
            args,
            timeout=3,
            env={"SECURITY_POLICY": b64encode(b"invalid_security_policy").decode()},
        )
        network.trust_node(new_node, args)
    except TimeoutError:
        ...
    else:
        raise AssertionError("Node joining unexpectedly succeeded")

    new_node.stop()


@reqs.description("Node with bad host data fails to join")
@reqs.snp_only()
def test_add_node_with_bad_host_data(network, args):

    primary, _ = network.find_nodes()

    LOG.info(
        "Removing security policy set by node 0 so that a new joiner is seen as an unmatching policy"
    )
    network.consortium.retire_host_data(primary, DEFAULT_SNP_HOST_DATA)

    new_node = network.create_node("local://localhost")
    try:
        network.join_node(
            new_node,
            args.package,
            args,
            timeout=3,
            env={"SECURITY_POLICY": DEFAULT_SNP_SECURITY_POLICY_B64},
        )
        network.trust_node(new_node, args)
    except Exception:
        ...
    else:
        raise AssertionError("Node joining unexpectedly succeeded")

    network.consortium.add_new_host_data(primary, "", DEFAULT_SNP_HOST_DATA)
    new_node.stop()


@reqs.description("Node with bad code fails to join")
def test_add_node_with_bad_code(network, args):
    if args.enclave_platform != "sgx":
        LOG.warning("Skipping test_add_node_with_bad_code with non-sgx enclave")
        return network

    replacement_package = (
        "samples/apps/logging/liblogging"
        if args.package == "libjs_generic"
        else "libjs_generic"
    )

    new_code_id = infra.utils.get_code_id(
        args.enclave_type, args.enclave_platform, args.oe_binary, replacement_package
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
    return (
        "samples/apps/logging/liblogging"
        if args.package == "libjs_generic"
        else "libjs_generic"
    )


@reqs.description("Update all nodes code")
@reqs.not_snp()  # Not yet supported as all nodes run the same measurement/security policy in SNP CI
def test_update_all_nodes(network, args):
    replacement_package = get_replacement_package(args)

    primary, _ = network.find_nodes()

    first_code_id = infra.utils.get_code_id(
        args.enclave_type, args.enclave_platform, args.oe_binary, args.package
    )
    new_code_id = infra.utils.get_code_id(
        args.enclave_type, args.enclave_platform, args.oe_binary, replacement_package
    )

    if args.enclave_platform == "virtual":
        # Pretend this was already present
        network.consortium.add_new_code(primary, first_code_id)

    LOG.info("Add new code id")
    network.consortium.add_new_code(primary, new_code_id)
    LOG.info("Check reported trusted measurements")
    with primary.client() as uc:
        r = uc.get("/node/code")
        expected = [
            {"digest": first_code_id, "status": "AllowedToJoin"},
            {"digest": new_code_id, "status": "AllowedToJoin"},
        ]
        if args.enclave_platform == "virtual":
            expected.insert(0, {"digest": VIRTUAL_CODE_ID, "status": "AllowedToJoin"})

        versions = sorted(r.body.json()["versions"], key=lambda x: x["digest"])
        expected.sort(key=lambda x: x["digest"])
        assert versions == expected, f"{versions} != {expected}"

    LOG.info("Remove old code id")
    network.consortium.retire_code(primary, first_code_id)
    with primary.client() as uc:
        r = uc.get("/node/code")
        expected = [
            {"digest": first_code_id, "status": "AllowedToJoin"},
            {"digest": new_code_id, "status": "AllowedToJoin"},
        ]
        if args.enclave_platform == "virtual":
            expected.insert(0, {"digest": VIRTUAL_CODE_ID, "status": "AllowedToJoin"})

        expected.sort(key=lambda x: x["digest"])
        assert versions == expected, f"{versions} != {expected}"

    old_nodes = network.nodes.copy()

    LOG.info("Start fresh nodes running new code")
    for _ in range(0, len(old_nodes)):
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, replacement_package, args)
        network.trust_node(new_node, args)

    LOG.info("Retire original nodes running old code")
    for node in old_nodes:
        primary, _ = network.find_nodes()
        network.retire_node(primary, node)
        # Elections take (much) longer than a backup removal which is just
        # a commit, so we need to adjust our timeout accordingly, hence this branch
        if node.node_id == primary.node_id:
            new_primary, _ = network.wait_for_new_primary(primary)
            primary = new_primary
            #  See https://github.com/microsoft/CCF/issues/1713
            check_can_progress(new_primary)
        node.stop()

    LOG.info("Check the network is still functional")
    check_can_progress(new_node)
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
        args.enclave_type,
        args.enclave_platform,
        args.oe_binary,
        get_replacement_package(args),
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


@reqs.description("Update CCF network from one version to another on SNP")
def test_snp_code_update(network, args):

    snp_secondary_ip_addresses_path = "/home/agent/secondary_ip_addresses"
    LOG.info(snp_secondary_ip_addresses_path)

    timeout = 60 * 60  # 60 minutes
    start_time = time.time()
    end_time = start_time + timeout

    while time.time() < end_time and not os.path.exists(
        snp_secondary_ip_addresses_path
    ):
        LOG.info(
            f"({time.time() - start_time}) Waiting for SNP secondary IP addresses file ({snp_secondary_ip_addresses_path}) to be created"
        )
        time.sleep(60)

    if os.path.exists(snp_secondary_ip_addresses_path):
        LOG.info("SNP secondary IP addresses file created")
        with open(snp_secondary_ip_addresses_path, "r", encoding="utf-8") as f:
            secondary_acis = [
                tuple(secondary_aci.split(" "))
                for secondary_aci in f.read().splitlines()
            ]
            for secondary_name, secondary_ip in secondary_acis:
                LOG.info(
                    f'Secondary ACI with name "{secondary_name}" has IP: {secondary_ip}'
                )
            new_node = network.create_node(f"ssh://{secondary_acis[0][1]}")
            LOG.info(f"New Node: {new_node}")
            network.join_node(new_node, args.package, args)

    else:
        LOG.error("SNP secondary IP addresses file not created before timeout")


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        #     test_verify_quotes(network, args)
        #     test_snp_measurements_table(network, args)
        #     test_host_data_table(network, args)
        #     test_add_node_with_host_data(network, args)
        #     test_add_node_with_no_security_policy_not_matching_kv(network, args)
        #     test_add_node_with_mismatched_host_data(network, args)
        #     test_add_node_with_bad_host_data(network, args)
        #     test_add_node_with_bad_code(network, args)
        #     # NB: Assumes the current nodes are still using args.package, so must run before test_proposal_invalidation
        #     test_proposal_invalidation(network, args)
        #     test_update_all_nodes(network, args)

        #     # Run again at the end to confirm current nodes are acceptable
        #     test_verify_quotes(network, args)

        test_snp_code_update(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
