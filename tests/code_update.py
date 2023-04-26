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
import infra.snp as snp
import tempfile
import shutil

from loguru import logger as LOG

# Dummy code id used by virtual nodes
VIRTUAL_CODE_ID = "0" * 64


@reqs.description("Verify node evidence")
def test_verify_quotes(network, args):
    if args.enclave_platform == "virtual":
        LOG.warning("Skipping quote test with virtual enclave")
        return network
    elif snp.IS_SNP:
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
def test_snp_measurements_tables(network, args):
    primary, _ = network.find_nodes()

    LOG.info("SNP measurements table")

    def get_trusted_measurements(node):
        with node.client() as client:
            r = client.get("/gov/kv/nodes/snp/measurements")
            return r.body.json()

    measurements = get_trusted_measurements(primary)
    assert (
        len(measurements) == 0
    ), "Expected no measurement as UVM endorsements are used by default"

    LOG.debug("Add dummy measurement")
    dummy_snp_mesurement = "a" * 96
    network.consortium.add_snp_measurement(primary, dummy_snp_mesurement)
    measurements = get_trusted_measurements(primary)
    expected_dummy = {dummy_snp_mesurement: "AllowedToJoin"}
    assert len(measurements) == 1, f"Expected one measurement, {measurements}"
    assert (
        measurements == expected_dummy
    ), f"One of the measurements should match the dummy that was populated, dummy={expected_dummy}, actual={measurements}"

    LOG.debug("Remove dummy measurement")
    network.consortium.remove_snp_measurement(primary, dummy_snp_mesurement)
    measurements = get_trusted_measurements(primary)
    assert (
        len(measurements) == 0
    ), "Expected no measurement as UVM endorsements are used by default"

    LOG.info("SNP UVM endorsement table")

    def get_trusted_uvm_endorsements(node):
        with node.client() as client:
            r = client.get("/gov/kv/nodes/snp/uvm_endorsements")
            return r.body.json()

    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert (
        len(uvm_endorsements) == 1
    ), f"Expected one UVM endorsement, {uvm_endorsements}"
    did, value = next(iter(uvm_endorsements.items()))
    feed, data = next(iter(value.items()))
    svn = data["svn"]
    assert feed == "ContainerPlat-AMD-UVM"

    LOG.debug("Add new feed for same DID")
    new_feed = "New feed"
    network.consortium.add_snp_uvm_endorsement(primary, did=did, feed=new_feed, svn=svn)
    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    did, value = next(iter(uvm_endorsements.items()))
    assert len(value) == 2
    assert value[new_feed]["svn"] == svn

    LOG.debug("Bump SVN for new feed")
    bumped_svn = svn + 1
    network.consortium.add_snp_uvm_endorsement(
        primary, did=did, feed=new_feed, svn=bumped_svn
    )
    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert (
        len(uvm_endorsements) == 1
    ), f"Expected one UVM endorsement, {uvm_endorsements}"
    did, value = next(iter(uvm_endorsements.items()))
    assert value[new_feed]["svn"] == bumped_svn

    LOG.debug("Add new DID")
    new_did = "did:x509:newdid"
    network.consortium.add_snp_uvm_endorsement(
        primary, did=new_did, feed=new_feed, svn=svn
    )
    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert len(uvm_endorsements) == 2
    assert new_did in uvm_endorsements
    assert new_feed in uvm_endorsements[new_did]

    LOG.debug("Remove new DID")
    network.consortium.remove_snp_uvm_endorsement(primary, did=new_did, feed=new_feed)
    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert len(uvm_endorsements) == 1
    assert new_did not in uvm_endorsements
    assert did in uvm_endorsements

    LOG.debug("Remove new issuer for original DID")
    network.consortium.remove_snp_uvm_endorsement(primary, did=did, feed=new_feed)
    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert len(uvm_endorsements) == 1
    _, value = next(iter(uvm_endorsements.items()))
    assert new_feed not in value
    assert feed in value

    return network


@reqs.description("Test that the security policies table is correctly populated")
@reqs.snp_only()
def test_host_data_table(network, args):
    primary, _ = network.find_nodes()
    with primary.client() as client:
        host_data = client.get("/gov/kv/nodes/snp/host_data").body.json()

    expected = {
        snp.get_container_group_security_policy_digest(): snp.get_container_group_security_policy(),
    }

    assert host_data == expected, f"{host_data} != {expected}"
    return network


@reqs.description("Join node with no security policy")
@reqs.snp_only()
def test_add_node_without_security_policy(network, args):
    security_context_dir = snp.get_security_context_dir()
    with tempfile.TemporaryDirectory() as snp_dir:
        if security_context_dir is not None:
            shutil.copytree(security_context_dir, snp_dir, dirs_exist_ok=True)
            os.remove(os.path.join(snp_dir, snp.ACI_SEV_SNP_FILENAME_SECURITY_POLICY))

        new_node = network.create_node("local://localhost")
        network.join_node(
            new_node,
            args.package,
            args,
            timeout=3,
            set_snp_security_policy_envvar=True,
            snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
        )
        network.trust_node(new_node, args)
        return network


@reqs.description("Remove raw security policy from trusted host data and join new node")
@reqs.snp_only()
def test_add_node_remove_trusted_security_policy(network, args):
    LOG.info("Remove raw security policy from trusted host data")
    primary, _ = network.find_nodes()
    network.consortium.retire_host_data(
        primary, snp.get_container_group_security_policy_digest()
    )
    network.consortium.add_new_host_data(
        primary,
        snp.EMPTY_SNP_SECURITY_POLICY,
        snp.get_container_group_security_policy_digest(),
    )

    # If we don't throw an exception, joining was successful
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, timeout=3)
    network.trust_node(new_node, args)

    # Revert to original state
    network.consortium.retire_host_data(
        primary,
        snp.get_container_group_security_policy_digest(),
    )
    network.consortium.add_new_host_data(
        primary,
        snp.get_container_group_security_policy(),
        snp.get_container_group_security_policy_digest(),
    )
    return network


@reqs.description("Start node with mismatching security policy")
@reqs.snp_only()
def test_start_node_with_mismatched_host_data(network, args):
    try:
        security_context_dir = snp.get_security_context_dir()
        with tempfile.TemporaryDirectory() as snp_dir:
            if security_context_dir is not None:
                shutil.copytree(security_context_dir, snp_dir, dirs_exist_ok=True)
                with open(
                    os.path.join(snp_dir, snp.ACI_SEV_SNP_FILENAME_SECURITY_POLICY),
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(b64encode(b"invalid_security_policy").decode())

            new_node = network.create_node("local://localhost")
            network.join_node(
                new_node,
                args.package,
                args,
                timeout=3,
                snp_security_policy=b64encode(b"invalid_security_policy").decode()
                if security_context_dir is None
                else None,
                snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
            )
    except (TimeoutError, RuntimeError):
        LOG.info("As expected, node with invalid security policy failed to startup")
    else:
        raise AssertionError("Node startup unexpectedly succeeded")

    return network


@reqs.description("Node with bad host data fails to join")
@reqs.snp_only()
def test_add_node_with_bad_host_data(network, args):
    primary, _ = network.find_nodes()

    LOG.info(
        "Removing trusted security policy so that a new joiner is seen as an unmatching policy"
    )
    network.consortium.retire_host_data(
        primary, snp.get_container_group_security_policy_digest()
    )

    new_node = network.create_node("local://localhost")
    try:
        network.join_node(new_node, args.package, args, timeout=3)
    except TimeoutError:
        LOG.info("As expected, node with untrusted security policy failed to join")
    else:
        raise AssertionError("Node join unexpectedly succeeded")

    network.consortium.add_new_host_data(
        primary,
        snp.get_container_group_security_policy(),
        snp.get_container_group_security_policy_digest(),
    )
    return network


@reqs.description("Node with no UVM endorsements fails to join")
@reqs.snp_only()
def test_add_node_with_no_uvm_endorsements(network, args):
    LOG.info("Add new node without UVM endorsements (expect failure)")

    security_context_dir = snp.get_security_context_dir()
    with tempfile.TemporaryDirectory() as snp_dir:
        if security_context_dir is not None:
            shutil.copytree(security_context_dir, snp_dir, dirs_exist_ok=True)
            os.remove(os.path.join(snp_dir, snp.ACI_SEV_SNP_FILENAME_UVM_ENDORSEMENTS))

        try:
            new_node = network.create_node("local://localhost")
            network.join_node(
                new_node,
                args.package,
                args,
                timeout=3,
                set_snp_uvm_endorsements_envvar=False,
                snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
            )
        except infra.network.CodeIdNotFound:
            LOG.info("As expected, node with no UVM endorsements failed to join")
        else:
            raise AssertionError("Node join unexpectedly succeeded")

        LOG.info("Add trusted measurement")
        primary, _ = network.find_nodes()
        with primary.client() as client:
            r = client.get("/node/quotes/self")
            measurement = r.body.json()["mrenclave"]
        network.consortium.add_snp_measurement(primary, measurement)

        LOG.info("Add new node without UVM endorsements (expect success)")
        # This succeeds because node measurement are now trusted
        new_node = network.create_node("local://localhost")
        network.join_node(
            new_node,
            args.package,
            args,
            timeout=3,
            set_snp_uvm_endorsements_envvar=False,
            snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
        )
        new_node.stop()

        network.consortium.remove_snp_measurement(primary, measurement)

    return network


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
@reqs.not_snp(
    "Not yet supported as all nodes run the same measurement/security policy in SNP CI"
)
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
        r = uc.get("/gov/kv/nodes/code_ids")
        expected = {first_code_id: "AllowedToJoin", new_code_id: "AllowedToJoin"}
        if args.enclave_platform == "virtual":
            expected[VIRTUAL_CODE_ID] = "AllowedToJoin"

        versions = dict(sorted(r.body.json().items(), key=lambda x: x[0]))
        expected = dict(sorted(expected.items(), key=lambda x: x[0]))
        assert versions == expected, f"{versions} != {expected}"

    LOG.info("Remove old code id")
    network.consortium.retire_code(primary, first_code_id)
    with primary.client() as uc:
        r = uc.get("/gov/kv/nodes/code_ids")
        expected = {first_code_id: "AllowedToJoin", new_code_id: "AllowedToJoin"}
        if args.enclave_platform == "virtual":
            expected[VIRTUAL_CODE_ID] = "AllowedToJoin"

        expected = dict(sorted(expected.items(), key=lambda x: x[0]))
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


@reqs.description(
    "Test deploying secondary ACIs which will be used to test SNP code update"
)
@reqs.snp_only()
def test_snp_secondary_deployment(network, args):
    LOG.info(f"Secondary ACI information expected at: {args.snp_secondary_acis_path}")
    if args.snp_secondary_acis_path is None:
        LOG.warning(
            "Skipping test snp secondary deployment as no target secondary ACIs specified"
        )
        return network

    timeout = 60 * 60  # 60 minutes
    start_time = time.time()
    end_time = start_time + timeout

    while time.time() < end_time and not os.path.exists(args.snp_secondary_acis_path):
        LOG.info(
            f"({time.time() - start_time}) Waiting for SNP secondary IP addresses file at: ({args.snp_secondary_acis_path}) to be created"
        )
        time.sleep(10)

    if os.path.exists(args.snp_secondary_acis_path):
        LOG.info("SNP secondary IP addresses file created")
        with open(args.snp_secondary_acis_path, "r", encoding="utf-8") as f:
            secondary_acis = [
                tuple(secondary_aci.split(" "))
                for secondary_aci in f.read().splitlines()
            ]
            for secondary_name, secondary_ip in secondary_acis:
                LOG.info(
                    f'Secondary ACI with name "{secondary_name}" has IP: {secondary_ip}'
                )

    else:
        LOG.error("SNP secondary IP addresses file not created before timeout")


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        test_verify_quotes(network, args)
        test_snp_measurements_tables(network, args)
        test_add_node_with_no_uvm_endorsements(network, args)
        test_host_data_table(network, args)
        test_add_node_without_security_policy(network, args)
        test_add_node_remove_trusted_security_policy(network, args)
        test_start_node_with_mismatched_host_data(network, args)
        test_add_node_with_bad_host_data(network, args)
        test_add_node_with_bad_code(network, args)
        # NB: Assumes the current nodes are still using args.package, so must run before test_proposal_invalidation
        test_proposal_invalidation(network, args)
        test_update_all_nodes(network, args)

        # Run again at the end to confirm current nodes are acceptable
        test_verify_quotes(network, args)

        test_snp_secondary_deployment(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
