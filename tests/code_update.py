# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from base64 import b64encode, b64decode
import infra.e2e_args
import infra.network
import infra.path
import infra.proc
import infra.utils
import infra.crypto
import infra.platform_detection
import suite.test_requirements as reqs
import os
from infra.checker import check_can_progress
import infra.snp as snp
import tempfile
import shutil
import http
import json
from hashlib import sha256


from loguru import logger as LOG


@reqs.description("Verify node evidence")
def test_verify_quotes(network, args):
    LOG.info("Check the network is stable")
    primary, _ = network.find_primary()
    check_can_progress(primary)

    with primary.api_versioned_client(api_version=args.gov_api_version) as uc:
        r = uc.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r

        policy = r.body.json()

        trusted_virtual_measurements = policy["virtual"]["measurements"]
        trusted_virtual_host_data = policy["virtual"]["hostData"]

        r = uc.get("/node/attestations")
        all_quotes = r.body.json()["attestations"]
        assert len(all_quotes) >= len(
            network.get_joined_nodes()
        ), f"There are {len(network.get_joined_nodes())} joined nodes, yet got only {len(all_quotes)} quotes: {json.dumps(all_quotes, indent=2)}"

    for node in network.get_joined_nodes():
        LOG.info(f"Verifying quote for node {node.node_id}")
        with node.client() as c:
            r = c.get("/node/attestations/self")
            assert r.status_code == http.HTTPStatus.OK, r

            j = r.body.json()
            if j["format"] == "Insecure_Virtual":
                # A virtual attestation makes 3 claims:
                # - The measurement (same on any virtual node) is a hard-coded string, currently unmodifiable
                claimed_measurement = j["measurement"]
                # For consistency with other platforms, this endpoint always returns a hex-string.
                # But for virtual, it's encoding some ASCII string, not a digest, so decode it for readability
                claimed_measurement = bytes.fromhex(claimed_measurement).decode()
                expected_measurement = infra.utils.get_measurement(
                    args.enclave_platform, args.package
                )
                assert (
                    claimed_measurement == expected_measurement
                ), f"{claimed_measurement} != {expected_measurement}"

                raw = json.loads(b64decode(j["raw"]))
                assert raw["measurement"] == claimed_measurement

                # - The host_data (equal to any equivalent node) is the sha256 of the package (library) it loaded
                host_data = raw["host_data"]
                expected_host_data, _ = infra.utils.get_host_data_and_security_policy(
                    args.enclave_platform, args.package
                )
                assert (
                    host_data == expected_host_data
                ), f"{host_data} != {expected_host_data}"

                # - The report_data (unique to this node) is the sha256 of the node's public key, in DER encoding
                # That is the same value we use as the node's ID, though that is usually represented as a hex string
                report_data = b64decode(raw["report_data"])
                assert report_data.hex() == node.node_id

                # Additionally, we check that the measurement and host_data are in the service's currently trusted values.
                # Note this might not always be true - a node may be added while it was trusted, and persist past the point its values become untrusted!
                # But it _is_ true in this test, and a sensible thing to check most of the time
                assert (
                    claimed_measurement in trusted_virtual_measurements
                ), f"This node's measurement ({claimed_measurement}) is not one of the currently trusted measurements ({trusted_virtual_measurements})"
                assert (
                    host_data in trusted_virtual_host_data
                ), f"This node's host data ({host_data}) is not one of the currently trusted values ({trusted_virtual_host_data})"

            elif j["format"] == "AMD_SEV_SNP_v1":
                LOG.warning(
                    "Skipping client-side verification of SNP node's quote until there is a separate utility to verify SNP quotes"
                )

            # Quick API validation - confirm that all of these /quotes/self entries match the collection returned from /quotes
            assert (
                j in all_quotes
            ), f"Didn't find {node.node_id}'s quote in collection\n{j}\n{json.dumps(all_quotes)}"

    return network


def get_trusted_uvm_endorsements(node):
    with node.api_versioned_client(api_version=args.gov_api_version) as client:
        r = client.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r
        return r.body.json()["snp"]["uvmEndorsements"]


@reqs.description("Test the measurements tables")
def test_measurements_tables(network, args):
    primary, _ = network.find_nodes()

    def get_trusted_measurements(node):
        with node.api_versioned_client(api_version=args.gov_api_version) as client:
            r = client.get("/gov/service/join-policy")
            assert r.status_code == http.HTTPStatus.OK, r
            return sorted(
                r.body.json()[infra.platform_detection.get_platform()]["measurements"]
            )

    original_measurements = get_trusted_measurements(primary)

    if infra.platform_detection.is_snp():
        assert (
            len(original_measurements) == 0
        ), "Expected no measurement as UVM endorsements are used by default"

    LOG.debug("Add dummy measurement")
    measurement_length = 96 if infra.platform_detection.is_snp() else 64
    dummy_measurement = "a" * measurement_length
    network.consortium.add_measurement(
        primary, args.enclave_platform, dummy_measurement
    )
    measurements = get_trusted_measurements(primary)
    expected_measurements = sorted(original_measurements + [dummy_measurement])
    assert (
        measurements == expected_measurements
    ), f"One of the measurements should match the dummy that was populated, expected={expected_measurements}, actual={measurements}"

    LOG.debug("Remove dummy measurement")
    network.consortium.remove_measurement(
        primary, args.enclave_platform, dummy_measurement
    )
    measurements = get_trusted_measurements(primary)
    assert (
        measurements == original_measurements
    ), f"Did not restore original measurements after removing dummy, expected={original_measurements}, actual={measurements}"

    return network


@reqs.description("Test the endorsements tables")
@reqs.snp_only()
def test_endorsements_tables(network, args):
    primary, _ = network.find_nodes()

    LOG.info("SNP UVM endorsement table")

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

    LOG.debug("Change SVN for new feed")
    new_svn = f"{svn}_2"
    network.consortium.add_snp_uvm_endorsement(
        primary, did=did, feed=new_feed, svn=new_svn
    )
    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert (
        len(uvm_endorsements) == 1
    ), f"Expected one UVM endorsement, {uvm_endorsements}"
    did, value = next(iter(uvm_endorsements.items()))
    assert value[new_feed]["svn"] == new_svn

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


@reqs.description("Test that the host data tables are correctly populated")
def test_host_data_tables(network, args):
    primary, _ = network.find_nodes()

    def get_trusted_host_data(node):
        with node.api_versioned_client(api_version=args.gov_api_version) as client:
            r = client.get("/gov/service/join-policy")
            assert r.status_code == http.HTTPStatus.OK, r
            return r.body.json()[infra.platform_detection.get_platform()]["hostData"]

    original_host_data = get_trusted_host_data(primary)

    host_data, security_policy = infra.utils.get_host_data_and_security_policy(
        args.enclave_platform, args.package
    )

    if infra.platform_detection.is_snp():
        expected = {host_data: security_policy}
    elif infra.platform_detection.is_virtual():
        expected = [host_data]
    else:
        raise ValueError(f"Unsupported platform: {args.enclave_platform}")

    assert original_host_data == expected, f"{original_host_data} != {expected}"

    LOG.debug("Add dummy host data")
    dummy_host_data_value = "Open Season"
    # For SNP compatibility, the host_data key must be the digest of the content/metadata
    dummy_host_data_key = sha256(dummy_host_data_value.encode()).hexdigest()
    network.consortium.add_host_data(
        primary, args.enclave_platform, dummy_host_data_key, dummy_host_data_value
    )
    host_data = get_trusted_host_data(primary)
    if infra.platform_detection.is_snp():
        expected_host_data = {
            **original_host_data,
            dummy_host_data_key: dummy_host_data_value,
        }
    elif infra.platform_detection.is_virtual():
        host_data = sorted(host_data)
        expected_host_data = sorted([*original_host_data, dummy_host_data_key])
    else:
        raise ValueError(f"Unsupported platform: {args.enclave_platform}")

    assert host_data == expected_host_data, f"{host_data} != {expected_host_data}"

    LOG.debug("Remove dummy host data")
    network.consortium.remove_host_data(
        primary, args.enclave_platform, dummy_host_data_key
    )
    host_data = get_trusted_host_data(primary)
    assert (
        host_data == original_host_data
    ), f"Did not restore original host data after removing dummy, expected={original_host_data}, actual={host_data}"

    return network


@reqs.description("Test tcb version tables")
@reqs.snp_only()
def test_tcb_version_tables(network, args):
    primary, _ = network.find_nodes()

    permissive_tcb_version = {"boot_loader": 0, "microcode": 0, "snp": 0, "tee": 0}

    LOG.info("Checking that the cpuid is correctly validated")
    for invalid_cpuid in (
        "",  # Too short
        "0",  # Not a multiple of 2
        "000000",  # Too short
        "0000000000",  # Too long
        "0000000g",  # Non-hex character
        "0000000A",  # Not lower-case
    ):
        try:
            network.consortium.set_snp_minimum_tcb_version(
                primary, invalid_cpuid, permissive_tcb_version
            )
        except infra.proposal.ProposalNotCreated:
            LOG.success("Failed as expected")
        else:
            assert (
                False
            ), f"Expected cpuid '{invalid_cpuid}' to be refused by validation code"

    LOG.info("Checking that the TCB versions is correctly populated")
    cpuid, tcb_version = None, None
    with primary.api_versioned_client(api_version=args.gov_api_version) as client:
        r = client.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r
        versions = r.body.json()["snp"]["tcbVersions"]
        assert len(versions) == 1, f"Expected one TCB version, {versions}"
        cpuid, tcb_version = next(iter(versions.items()))

    LOG.info("CPUID should be lowercase")
    assert cpuid.lower() == cpuid, f"Expected lowercase CPUID, {cpuid}"

    LOG.info("Change current cpuid's TCB version")
    network.consortium.set_snp_minimum_tcb_version(
        primary, cpuid, permissive_tcb_version
    )
    with primary.api_versioned_client(api_version=args.gov_api_version) as client:
        r = client.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r
        versions = r.body.json()["snp"]["tcbVersions"]
        assert cpuid in versions, f"Expected {cpuid} in TCB versions, {versions}"
        assert (
            versions[cpuid] == permissive_tcb_version
        ), f"TCB version does not match, {versions} != {permissive_tcb_version}"

    LOG.info("Removing current cpuid's TCB version")
    network.consortium.remove_snp_minimum_tcb_version(primary, cpuid)
    with primary.api_versioned_client(api_version=args.gov_api_version) as client:
        r = client.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r
        versions = r.body.json()["snp"]["tcbVersions"]
        assert len(versions) == 0, f"Expected no TCB versions, {versions}"

    LOG.info("Checking new nodes are prevented from joining")
    thrown_exception = None
    try:
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args, timeout=3)
        network.trust_node(new_node, args)
    except TimeoutError as e:
        thrown_exception = e
    assert thrown_exception is not None, "New node should not have been able to join"

    LOG.info("Adding new cpuid's TCB version")
    network.consortium.set_snp_minimum_tcb_version(primary, cpuid, tcb_version)
    with primary.api_versioned_client(api_version=args.gov_api_version) as client:
        r = client.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r
        versions = r.body.json()["snp"]["tcbVersions"]
        assert len(versions) == 1, f"Expected one TCB version, {versions}"

    LOG.info("Checking new nodes are allowed to join")
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, timeout=3)
    network.trust_node(new_node, args)


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
            snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
        )
        network.trust_node(new_node, args)
        return network


@reqs.description("Remove raw security policy from trusted host data and join new node")
def test_add_node_with_stubbed_security_policy(network, args):
    LOG.info("Remove raw security policy from trusted host data")
    primary, _ = network.find_nodes()

    host_data, security_policy = infra.utils.get_host_data_and_security_policy(
        args.enclave_platform, args.package
    )

    network.consortium.remove_host_data(primary, args.enclave_platform, host_data)
    network.consortium.add_host_data(
        primary,
        args.enclave_platform,
        host_data,
        "",  # Remove the raw security policy metadata, while retaining the host_data key
    )

    # If we don't throw an exception, joining was successful
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, timeout=3)
    network.trust_node(new_node, args)

    # Revert to original state
    network.consortium.remove_host_data(primary, args.enclave_platform, host_data)
    network.consortium.add_host_data(
        primary, args.enclave_platform, host_data, security_policy
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
                snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
            )
    except (TimeoutError, RuntimeError):
        LOG.info("As expected, node with invalid security policy failed to startup")
    else:
        raise AssertionError("Node startup unexpectedly succeeded")

    return network


@reqs.description("Node with untrusted measurement fails to join")
def test_add_node_with_untrusted_measurement(network, args):
    primary, _ = network.find_nodes()

    measurement = infra.utils.get_measurement(args.enclave_platform, args.package)

    LOG.info("Removing this measurement so that a new joiner is refused")
    network.consortium.remove_measurement(primary, args.enclave_platform, measurement)

    new_node = network.create_node("local://localhost")
    try:
        network.join_node(new_node, args.package, args, timeout=3)
    except infra.network.MeasurementNotFound:
        LOG.info("As expected, node with untrusted measurement failed to join")
    else:
        raise AssertionError("Node join unexpectedly succeeded")

    network.consortium.add_measurement(
        primary,
        args.enclave_platform,
        measurement,
    )
    return network


@reqs.description("Node with untrusted host data fails to join")
def test_add_node_with_untrusted_host_data(network, args):
    primary, _ = network.find_nodes()

    host_data, security_policy = infra.utils.get_host_data_and_security_policy(
        args.enclave_platform, args.package
    )

    LOG.info("Removing this host data value so that a new joiner is refused")
    network.consortium.remove_host_data(primary, args.enclave_platform, host_data)

    new_node = network.create_node("local://localhost")
    try:
        network.join_node(new_node, args.package, args, timeout=3)
    except infra.network.HostDataNotFound:
        LOG.info("As expected, node with untrusted host data failed to join")
    else:
        raise AssertionError("Node join unexpectedly succeeded")

    network.consortium.add_host_data(
        primary,
        args.enclave_platform,
        host_data,
        security_policy,
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
                snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
            )
        except infra.network.MeasurementNotFound:
            LOG.info("As expected, node with no UVM endorsements failed to join")
        else:
            raise AssertionError("Node join unexpectedly succeeded")

        LOG.info("Add trusted measurement")
        primary, _ = network.find_nodes()
        with primary.client() as client:
            r = client.get("/node/quotes/self")
            measurement = r.body.json()["measurement"]
        network.consortium.add_snp_measurement(primary, measurement)

        LOG.info("Add new node without UVM endorsements (expect success)")
        # This succeeds because node measurement are now trusted
        new_node = network.create_node("local://localhost")
        network.join_node(
            new_node,
            args.package,
            args,
            timeout=3,
            snp_uvm_security_context_dir=snp_dir if security_context_dir else None,
        )
        new_node.stop()

        network.consortium.remove_snp_measurement(primary, measurement)

    return network


@reqs.description("Node running other package (binary) fails to join")
@reqs.not_snp(
    "Not yet supported as all nodes run the same measurement AND security policy in SNP CI"
)
def test_add_node_with_different_package(network, args):
    if infra.platform_detection.is_snp():
        LOG.warning(
            "Skipping test_add_node_with_different_package with SNP - policy does not currently restrict packages"
        )
        return network

    replacement_package = get_replacement_package(args)

    LOG.info(f"Adding unsupported node running {replacement_package}")
    exception_thrown = None
    try:
        new_node = network.create_node("local://localhost")
        network.join_node(
            new_node,
            replacement_package,
            args,
            timeout=3,
        )

    except (infra.network.MeasurementNotFound, infra.network.HostDataNotFound) as err:
        exception_thrown = err

    assert (
        exception_thrown is not None
    ), f"Adding a node with {replacement_package} should fail"
    if infra.platform_detection.is_virtual():
        assert isinstance(
            exception_thrown, infra.network.HostDataNotFound
        ), "Virtual node package should affect host data"
    else:
        raise ValueError("Unchecked platform")

    return network


def get_replacement_package(args):
    return (
        "samples/apps/logging/liblogging"
        if args.package == "libjs_generic"
        else "libjs_generic"
    )


@reqs.description("Update all nodes code")
@reqs.not_snp(
    "Not yet supported as all nodes run the same measurement AND security policy in SNP CI"
)
def test_update_all_nodes(network, args):
    replacement_package = get_replacement_package(args)

    primary, _ = network.find_nodes()

    initial_measurement = infra.utils.get_measurement(
        args.enclave_platform, args.package
    )
    initial_host_data, initial_security_policy = (
        infra.utils.get_host_data_and_security_policy(
            args.enclave_platform, args.package
        )
    )
    new_measurement = infra.utils.get_measurement(
        args.enclave_platform, replacement_package
    )
    new_host_data, new_security_policy = infra.utils.get_host_data_and_security_policy(
        args.enclave_platform, replacement_package
    )

    measurement_changed = initial_measurement != new_measurement
    host_data_changed = initial_host_data != new_host_data
    assert (
        measurement_changed or host_data_changed
    ), "Cannot test code update, as new package produced identical measurement and host_data as original"

    LOG.info("Add new measurement and host_data")
    network.consortium.add_measurement(primary, args.enclave_platform, new_measurement)
    network.consortium.add_host_data(
        primary, args.enclave_platform, new_host_data, new_security_policy
    )

    with primary.api_versioned_client(api_version=args.gov_api_version) as uc:
        r = uc.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r
        platform_policy = r.body.json()[infra.platform_detection.get_platform()]

        if measurement_changed:
            LOG.info("Check reported trusted measurements")
            actual_measurements: list = platform_policy["measurements"]

            expected_measurements = [initial_measurement, new_measurement]

            actual_measurements.sort()
            expected_measurements.sort()
            assert (
                actual_measurements == expected_measurements
            ), f"{actual_measurements} != {expected_measurements}"

            LOG.info("Remove old measurement")
            network.consortium.remove_measurement(
                primary, args.enclave_platform, initial_measurement
            )

            r = uc.get("/gov/service/join-policy")
            assert r.status_code == http.HTTPStatus.OK, r
            actual_measurements = r.body.json()[
                infra.platform_detection.get_platform()
            ]["measurements"]

            expected_measurements.remove(initial_measurement)

            actual_measurements.sort()
            expected_measurements.sort()
            assert (
                actual_measurements == expected_measurements
            ), f"{actual_measurements} != {expected_measurements}"

        if initial_host_data != new_host_data:

            def format_expected_host_data(entries):
                if infra.platform_detection.is_snp():
                    return {
                        host_data: security_policy
                        for host_data, security_policy in entries
                    }
                elif infra.platform_detection.is_virtual():
                    return set(host_data for host_data, _ in entries)
                else:
                    raise ValueError(f"Unsupported platform: {args.enclave_platform}")

            LOG.info("Check reported trusted host datas")
            actual_host_datas = platform_policy["hostData"]
            if infra.platform_detection.is_virtual():
                actual_host_datas = set(actual_host_datas)
            expected_host_datas = format_expected_host_data(
                [
                    (initial_host_data, initial_security_policy),
                    (new_host_data, new_security_policy),
                ]
            )
            assert (
                actual_host_datas == expected_host_datas
            ), f"{actual_host_datas} != {expected_host_datas}"

            LOG.info("Remove old host_data")
            network.consortium.remove_host_data(
                primary, args.enclave_platform, initial_host_data
            )

            r = uc.get("/gov/service/join-policy")
            assert r.status_code == http.HTTPStatus.OK, r
            actual_host_datas = r.body.json()[infra.platform_detection.get_platform()][
                "hostData"
            ]
            if infra.platform_detection.is_virtual():
                actual_host_datas = set(actual_host_datas)
            expected_host_datas = format_expected_host_data(
                [(new_host_data, new_security_policy)]
            )
            assert (
                actual_host_datas == expected_host_datas
            ), f"{actual_host_datas} != {expected_host_datas}"

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

    args.package = replacement_package

    LOG.info("Check the network is still functional")
    check_can_progress(new_node)
    return network


@reqs.description("Adding a new measurement invalidates open proposals")
@reqs.not_snp("Cannot produce alternative measurement on SNP")
def test_proposal_invalidation(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Create an open proposal")
    pending_proposals = []
    with primary.client(None, "member0") as c:
        new_member_proposal, _, _ = network.consortium.generate_and_propose_new_member(
            primary, curve=args.participants_curve
        )
        pending_proposals.append(new_member_proposal.proposal_id)

    LOG.info("Add temporary measurement")
    temporary_measurement = infra.utils.get_measurement(
        args.enclave_platform,
        get_replacement_package(args),
    )
    network.consortium.add_measurement(
        primary, args.enclave_platform, temporary_measurement
    )

    LOG.info("Confirm open proposals are dropped")
    with primary.api_versioned_client(
        None, "member0", api_version=args.gov_api_version
    ) as c:
        for proposal_id in pending_proposals:
            r = c.get(f"/gov/members/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Dropped", r.body.json()

    LOG.info("Remove temporary measurement")
    network.consortium.remove_measurement(
        primary, args.enclave_platform, temporary_measurement
    )

    return network


@reqs.description(
    "Node fails to join if KV contains no UVM endorsements roots of trust"
)
@reqs.snp_only()
def test_add_node_with_no_uvm_endorsements_in_kv(network, args):
    LOG.info("Remove KV endorsements roots of trust (expect failure)")
    primary, _ = network.find_nodes()

    uvm_endorsements = get_trusted_uvm_endorsements(primary)
    assert (
        len(uvm_endorsements) == 1
    ), f"Expected one UVM endorsement, {uvm_endorsements}"
    did, value = next(iter(uvm_endorsements.items()))
    feed, data = next(iter(value.items()))

    network.consortium.remove_snp_uvm_endorsement(primary, did, feed)

    try:
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args, timeout=3)
    except infra.network.UVMEndorsementsNotAuthorised:
        LOG.info("As expected, node with no UVM endorsements failed to join")
    else:
        raise AssertionError("Node join unexpectedly succeeded")

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        test_verify_quotes(network, args)

        # Measurements
        test_measurements_tables(network, args)
        if not infra.platform_detection.is_snp():
            test_add_node_with_untrusted_measurement(network, args)

        # Host data/security policy
        test_host_data_tables(network, args)
        test_add_node_with_untrusted_host_data(network, args)

        if infra.platform_detection.is_snp():
            # Virtual has no security policy, _only_ host data (unassociated with anything)
            test_add_node_with_stubbed_security_policy(network, args)
            test_start_node_with_mismatched_host_data(network, args)
            test_add_node_without_security_policy(network, args)
            test_tcb_version_tables(network, args)

            # Endorsements
            test_endorsements_tables(network, args)
            test_add_node_with_no_uvm_endorsements(network, args)

        if not infra.platform_detection.is_snp():
            # NB: Assumes the current nodes are still using args.package, so must run before test_update_all_nodes
            test_proposal_invalidation(network, args)

            # This is in practice equivalent to either "unknown measurement" or "unknown host data", but is explicitly
            # testing that (without artifically removing/corrupting those values) a replacement package differs
            # in one of these values
            test_add_node_with_different_package(network, args)
            test_update_all_nodes(network, args)

        # Run again at the end to confirm current nodes are acceptable
        test_verify_quotes(network, args)

        if infra.platform_detection.is_snp():
            test_add_node_with_no_uvm_endorsements_in_kv(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
