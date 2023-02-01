# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.net
import infra.logging_app as app
from infra.tx_status import TxStatus
import suite.test_requirements as reqs
import tempfile
from shutil import copy
from copy import deepcopy
import os
import time
import ccf.ledger
import json
import infra.crypto
from datetime import datetime
from infra.checker import check_can_progress
from governance_history import check_signatures
from infra.snp import IS_SNP
from infra.runner import ConcurrentRunner
import http
import random

from loguru import logger as LOG


def node_configs(network):
    configs = {}
    for node in network.get_joined_nodes():
        try:
            with node.client() as nc:
                configs[node.node_id] = nc.get("/node/config").body.json()
        except Exception:
            pass
    return configs


def count_nodes(configs, network):
    nodes = set(str(k) for k in configs.keys())
    stopped = {str(n.node_id) for n in network.nodes if n.is_stopped()}
    for node_id, node_config in configs.items():
        nodes_in_config = set(node_config.keys()) - stopped
        assert nodes == nodes_in_config, f"{nodes} {nodes_in_config} {node_id}"
    return len(nodes)


def wait_for_reconfiguration_to_complete(network, timeout=10):
    max_num_configs = 0
    max_rid = 0
    all_same_rid = False
    end_time = time.time() + timeout
    while max_num_configs > 1 or not all_same_rid:
        max_num_configs = 0
        all_same_rid = True
        for node in network.get_joined_nodes():
            with node.client(verify_ca=False) as c:
                try:
                    r = c.get("/node/consensus")
                    rj = r.body.json()
                    cfgs = rj["details"]["configs"]
                    num_configs = len(cfgs)
                    max_num_configs = max(max_num_configs, num_configs)
                    if num_configs == 1 and cfgs[0]["rid"] != max_rid:
                        max_rid = max(max_rid, cfgs[0]["rid"])
                        all_same_rid = False
                except Exception as ex:
                    # OK, retiring node may be gone or a joining node may not be ready yet
                    LOG.info(f"expected RPC failure because of: {ex}")
        time.sleep(0.5)
        LOG.info(f"max num configs: {max_num_configs}, max rid: {max_rid}")
        if time.time() > end_time:
            raise Exception("Reconfiguration did not complete in time")


@reqs.description("Adding a node with invalid target service certificate")
def test_add_node_invalid_service_cert(network, args):
    primary, _ = network.find_primary()

    # Incorrect target service certificate file, in this case the primary's node
    # identity
    service_cert_file = os.path.join(primary.common_dir, f"{primary.local_node_id}.pem")
    new_node = network.create_node("local://localhost")
    try:
        network.join_node(
            new_node,
            args.package,
            args,
            service_cert_file=service_cert_file,
            timeout=3,
            stop_on_error=True,
        )
    except infra.network.ServiceCertificateInvalid:
        LOG.info(
            f"Node {new_node.local_node_id} with invalid service certificate failed to start, as expected"
        )
    else:
        assert (
            False
        ), f"Node {new_node.local_node_id} with invalid service certificate unexpectedly started"

    return network


@reqs.description("Adding a valid node")
def test_add_node(network, args, from_snapshot=True):
    # Note: host is supplied explicitly to avoid having differently
    # assigned IPs for the interfaces, something which the test infra doesn't
    # support widely yet.
    operator_rpc_interface = "operator_rpc_interface"
    host = infra.net.expand_localhost()
    new_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    host=host
                ),
                operator_rpc_interface: infra.interfaces.RPCInterface(
                    host=host,
                    endorsement=infra.interfaces.Endorsement(
                        authority=infra.interfaces.EndorsementAuthority.Node
                    ),
                ),
            }
        )
    )
    network.join_node(new_node, args.package, args, from_snapshot=from_snapshot)

    # Verify self-signed node certificate validity period
    new_node.verify_certificate_validity_period(interface_name=operator_rpc_interface)

    network.trust_node(
        new_node,
        args,
        validity_period_days=args.maximum_node_certificate_validity_days // 2,
    )

    if not from_snapshot:
        with new_node.client() as c:
            s = c.get("/node/state")
            assert s.body.json()["node_id"] == new_node.node_id
            assert (
                s.body.json()["startup_seqno"] == 0
            ), "Node started without snapshot but reports startup seqno != 0"

    # Now that the node is trusted, verify endorsed certificate validity period
    new_node.verify_certificate_validity_period()

    return network


@reqs.description("Adding a node with an invalid certificate validity period")
def test_add_node_invalid_validity_period(network, args):
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args)
    try:
        network.trust_node(
            new_node,
            args,
            validity_period_days=args.maximum_node_certificate_validity_days + 1,
        )
    except infra.proposal.ProposalNotAccepted:
        LOG.info(
            "As expected, node could not be trusted since its certificate validity period is invalid"
        )
    else:
        raise Exception(
            "Node should not be trusted if its certificate validity period is invalid"
        )
    return network


def test_add_node_on_other_curve(network, args):
    original_curve = args.curve_id
    args.curve_id = (
        infra.network.EllipticCurve.secp256r1
        if original_curve is None
        else original_curve.next()
    )
    network = test_add_node(network, args)
    args.curve_id = original_curve
    return network


@reqs.description("Changing curve used for identity of new nodes and new services")
def test_change_curve(network, args):
    # NB: This doesn't actually test things, it just changes the configuration
    # for future tests. Expects to be part of an interesting suite
    original_curve = args.curve_id
    args.curve_id = (
        infra.network.EllipticCurve.secp256r1
        if original_curve is None
        else original_curve.next()
    )
    return network


@reqs.description("Adding a valid node from a backup")
@reqs.at_least_n_nodes(2)
def test_add_node_from_backup(network, args):
    new_node = network.create_node("local://localhost")
    network.join_node(
        new_node,
        args.package,
        args,
        target_node=network.find_any_backup(),
    )
    network.trust_node(new_node, args)
    return network


@reqs.description("Adding a node with AMD endorsements endpoint")
def test_add_node_amd_endorsements_endpoint(network, args):
    primary, _ = network.find_primary()
    if not IS_SNP:
        LOG.warning("Skipping test as running on non SEV-SNP")
        return network

    args_copy = deepcopy(args)
    test_vectors = [
        (["AMD:kdsintf.amd.com"], True),
        (["AMD:invalid.amd.com"], False),
        (["Azure:invalid.azure.com", "AMD:kdsintf.amd.com"], True),  # Fallback server
    ]

    for servers, expected_result in test_vectors:
        LOG.info(
            f"Joining new node with endorsement server {servers} (expect success: {expected_result})"
        )
        new_node = network.create_node("local://localhost")
        args_copy.snp_endorsements_servers = servers
        try:
            network.join_node(new_node, args.package, args_copy, timeout=15)
        except TimeoutError:
            assert not expected_result
            LOG.info(
                "Node with invalid quote endorsement server could not join as expected"
            )
        else:
            assert (
                expected_result
            ), "Node with invalid quote endorsement server joined unexpectedly"
            network.retire_node(primary, new_node)
        new_node.stop()

    return network


@reqs.description("Adding a valid node from snapshot")
@reqs.at_least_n_nodes(2)
def test_add_node_from_snapshot(network, args, copy_ledger=True, from_backup=False):
    # Before adding the node from a snapshot, override at least one app entry
    # and wait for a new committed snapshot covering that entry, so that there
    # is at least one historical entry to verify.
    network.txs.issue(network, number_txs=1)
    idx, historical_entry = network.txs.get_last_tx(priv=True)
    network.txs.issue(network, number_txs=1, repeat=True)

    new_node = network.create_node("local://localhost")
    network.join_node(
        new_node,
        args.package,
        args,
        copy_ledger=copy_ledger,
        target_node=network.find_any_backup() if from_backup else None,
        from_snapshot=True,
    )
    network.trust_node(new_node, args)

    with new_node.client() as c:
        r = c.get("/node/state")
        assert (
            r.body.json()["startup_seqno"] != 0
        ), "Node started from snapshot but reports startup seqno of 0"

    # Finally, verify all app entries on the new node, including historical ones
    # from the historical ledger and skip historical entries if ledger
    # was not copied to node.
    network.txs.verify(node=new_node, include_historical=copy_ledger)

    # Check that historical entry can be retrieved (or not, if new node does not
    # have access to historical ledger files).
    try:
        network.txs.verify_tx(
            node=new_node,
            idx=idx,
            msg=historical_entry["msg"],
            seqno=historical_entry["seqno"],
            view=historical_entry["view"],
            historical=True,
        )
    except infra.logging_app.LoggingTxsVerifyException:
        assert (
            not copy_ledger
        ), f"New node {new_node.local_node_id} without ledger should not be able to serve historical entries"
    else:
        assert (
            copy_ledger
        ), f"New node {new_node.local_node_id} with ledger should be able to serve historical entries"

    if not copy_ledger:
        # Pick some sequence numbers before the snapshot the new node started from, and for which
        # the new node does not have corresponding ledger chunks
        missing_txids = []
        with new_node.client("user0") as c:
            r = c.get("/node/state")
            assert r.status_code == http.HTTPStatus.OK, r
            startup_seqno = r.body.json()["startup_seqno"]
            assert startup_seqno != 0, startup_seqno
            possible_seqno_range = range(1, startup_seqno)
            num_samples = min(len(possible_seqno_range), 5)
            missing_seqnos = sorted(random.sample(possible_seqno_range, num_samples))
            LOG.info(f"Verifying status of transactions at seqnos: {missing_seqnos}")
            view = 2
            for seqno in missing_seqnos:
                assert seqno != 0, "0 is not a valid seqno"
                status = TxStatus.Invalid
                while status == TxStatus.Invalid:
                    r = c.get(f"/node/tx?transaction_id={view}.{seqno}")
                    assert r.status_code == http.HTTPStatus.OK, r
                    status = TxStatus(r.body.json()["status"])
                    if status == TxStatus.Committed:
                        missing_txids.append(f"{view}.{seqno}")
                    else:
                        # Should never happen, because we're looking at seqnos for which there
                        # is a committed snapshot, and so are definitely committed.
                        assert status != TxStatus.Pending, status
                        view += 1
                        # Not likely to happen on purpose
                        assert view < 10, view

        LOG.info("Check historical queries return ACCEPTED")
        with new_node.client("user0") as c:
            for txid in missing_txids:
                # New node knows transactions are committed
                rc = c.get(f"/node/tx?transaction_id={txid}")
                status = TxStatus(r.body.json()["status"])
                assert status == TxStatus.Committed
                # But can't read their contents
                rc = c.get(f"/app/receipt?transaction_id={txid}")
                assert rc.status_code == http.HTTPStatus.ACCEPTED, rc
                time.sleep(3)
                # Not even after giving the host enough time
                rc = c.get(f"/app/receipt?transaction_id={txid}")
                assert rc.status_code == http.HTTPStatus.ACCEPTED, rc

    primary, _ = network.find_primary()
    network.retire_node(primary, new_node)
    return network


@reqs.description("Adding as many pending nodes as current number of nodes")
@reqs.supports_methods("/app/log/private")
def test_add_as_many_pending_nodes(network, args):
    # Killing pending nodes should not change the raft consensus rules
    primary, _ = network.find_primary()
    number_new_nodes = len(network.nodes)
    LOG.info(
        f"Adding {number_new_nodes} pending nodes - consensus rules should not change"
    )

    new_nodes = []
    for _ in range(number_new_nodes):
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args)
        new_nodes.append(new_node)

    for new_node in new_nodes:
        new_node.stop()

    # Even though pending nodes (half the number of nodes) are stopped,
    # service can still make progress
    check_can_progress(primary)

    # Cleanup killed pending nodes
    for new_node in new_nodes:
        network.retire_node(primary, new_node)

    wait_for_reconfiguration_to_complete(network)

    return network


@reqs.description("Retiring a backup")
@reqs.at_least_n_nodes(2)
@reqs.can_kill_n_nodes(1)
def test_retire_backup(network, args):
    primary, _ = network.find_primary()
    backup_to_retire = network.find_any_backup()
    network.retire_node(primary, backup_to_retire)
    backup_to_retire.stop()
    check_can_progress(primary)
    wait_for_reconfiguration_to_complete(network)
    return network


@reqs.description("Retiring the primary")
@reqs.can_kill_n_nodes(1)
def test_retire_primary(network, args):
    pre_count = count_nodes(node_configs(network), network)

    primary, backup = network.find_primary_and_any_backup()
    network.retire_node(primary, primary, timeout=15)
    # Query this backup to find the new primary. If we ask any other
    # node, then this backup may not know the new primary by the
    # time we call check_can_progress.
    new_primary, _ = network.wait_for_new_primary(primary, nodes=[backup])
    # See https://github.com/microsoft/CCF/issues/1713
    check_can_progress(new_primary)
    check_can_progress(backup)
    post_count = count_nodes(node_configs(network), network)
    assert pre_count == post_count + 1
    primary.stop()
    wait_for_reconfiguration_to_complete(network)
    return network


@reqs.description("Test node filtering by status")
def test_node_filter(network, args):
    primary, _ = network.find_primary_and_any_backup()
    with primary.client() as c:

        def get_nodes(status):
            r = c.get(f"/node/network/nodes?status={status}")
            nodes = r.body.json()["nodes"]
            # Primary may change during operation, so do not check for primary equality
            for node in nodes:
                del node["primary"]
            return sorted(nodes, key=lambda node: node["node_id"])

        trusted_before = get_nodes("Trusted")
        pending_before = get_nodes("Pending")
        retired_before = get_nodes("Retired")
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args, target_node=primary)
        trusted_after = get_nodes("Trusted")
        pending_after = get_nodes("Pending")
        retired_after = get_nodes("Retired")
        assert trusted_before == trusted_after, (trusted_before, trusted_after)
        assert len(pending_before) + 1 == len(pending_after), (
            pending_before,
            pending_after,
        )
        assert retired_before == retired_after, (retired_before, retired_after)

        assert all(info["status"] == "Trusted" for info in trusted_after), trusted_after
        assert all(info["status"] == "Pending" for info in pending_after), pending_after
        assert all(info["status"] == "Retired" for info in retired_after), retired_after
    return network


@reqs.description("Get node CCF version")
def test_version(network, args):
    if args.ccf_version is None:
        LOG.warning(
            "Skipping network version check as no expected version is specified"
        )
        return

    nodes = network.get_joined_nodes()

    for node in nodes:
        with node.client() as c:
            r = c.get("/node/version")
            assert r.body.json()["ccf_version"] == args.ccf_version
            assert r.body.json()["unsafe"] == os.path.exists(
                os.path.join(args.binary_dir, "UNSAFE")
            )


@reqs.description("Issue fake join requests as untrusted client")
def test_issue_fake_join(network, args):
    primary, _ = network.find_primary()

    # Assemble dummy join request body
    net = {"bind_address": "0:0"}
    req = {}
    req["node_info_network"] = {
        "node_to_node_interface": net,
        "rpc_interfaces": {"name": net},
    }
    req["consensus_type"] = "CFT"
    req["startup_seqno"] = 0
    with open(
        os.path.join(network.common_dir, "member0_enc_pubk.pem"), "r", encoding="utf-8"
    ) as f:
        req["public_encryption_key"] = f.read()

    with primary.client(identity="user0") as c:
        # First, retrieve real quote from primary node
        own_quote = c.get("/node/quotes/self").body.json()

        LOG.info("Join with SGX dummy quote")
        req["quote_info"] = {"format": "OE_SGX_v1", "quote": "", "endorsements": ""}
        r = c.post("/node/join", body=req)
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED
        assert (
            r.body.json()["error"]["code"] == "InvalidQuote"
        ), "Quote verification should fail when OE_SGX_v1 is specified"

        LOG.info("Join with SGX real quote, but different TLS key")
        req["quote_info"] = {
            "format": "OE_SGX_v1",
            "quote": own_quote["raw"],
            "endorsements": own_quote["endorsements"],
        }
        r = c.post("/node/join", body=req)
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED
        assert r.body.json()["error"]["code"] == "InvalidQuote"
        if args.enclave_platform != "sgx":
            assert r.body.json()["error"]["message"] == "Quote could not be verified"
        else:
            assert (
                r.body.json()["error"]["message"]
                == "Quote report data does not contain node's public key hash"
            )

        LOG.info("Join with AMD SEV-SNP quote")
        req["quote_info"] = {
            "format": "AMD_SEV_SNP_v1",
            "quote": own_quote["raw"],
            "endorsements": own_quote["endorsements"],
        }
        r = c.post("/node/join", body=req)
        if args.enclave_platform != "snp":
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED
            assert r.body.json()["error"]["code"] == "InvalidQuote"
            assert r.body.json()["error"]["message"] == "Quote could not be verified"
        else:
            assert (
                r.body.json()["error"]["message"]
                == "Quote report data does not contain node's public key hash"
            )

        LOG.info("Join with virtual quote")
        req["quote_info"] = {
            "format": "Insecure_Virtual",
            "quote": "",
            "endorsements": "",
        }
        r = c.post("/node/join", body=req)
        if args.enclave_platform == "virtual":
            assert r.status_code == http.HTTPStatus.OK
            assert r.body.json()["node_status"] == ccf.ledger.NodeStatus.PENDING.value
        else:
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED
            assert (
                r.body.json()["error"]["code"] == "InvalidQuote"
            ), "Virtual node must never join non-virtual network"

    return network


@reqs.description("Replace a node on the same addresses")
@reqs.can_kill_n_nodes(1)
def test_node_replacement(network, args):
    primary, backups = network.find_nodes()

    node_to_replace = backups[-1]
    LOG.info(f"Retiring node {node_to_replace.local_node_id}")
    network.retire_node(primary, node_to_replace)
    node_to_replace.stop()
    check_can_progress(primary)

    LOG.info("Adding one node on same address as retired node")
    replacement_node = network.create_node(
        f"local://{node_to_replace.get_public_rpc_host()}:{node_to_replace.get_public_rpc_port()}",
        node_port=node_to_replace.n2n_interface.port,
    )
    network.join_node(replacement_node, args.package, args)
    network.trust_node(replacement_node, args)

    assert replacement_node.node_id != node_to_replace.node_id
    assert (
        replacement_node.get_public_rpc_host() == node_to_replace.get_public_rpc_host()
    )
    assert replacement_node.n2n_interface.port == node_to_replace.n2n_interface.port
    assert (
        replacement_node.get_public_rpc_port() == node_to_replace.get_public_rpc_port()
    )

    allowed_to_suspend_count = network.get_f() - len(network.get_stopped_nodes())
    backups_to_suspend = backups[:allowed_to_suspend_count]
    LOG.info(
        f"Suspending {len(backups_to_suspend)} other nodes to make progress depend on the replacement"
    )
    for other_backup in backups_to_suspend:
        other_backup.suspend()
    # Confirm the network can make progress
    check_can_progress(primary)
    for other_backup in backups_to_suspend:
        other_backup.resume()

    return network


@reqs.description("Join straddling a primary retirement")
@reqs.at_least_n_nodes(3)
def test_join_straddling_primary_replacement(network, args):
    # We need a fourth node before we attempt the replacement, otherwise
    # we will reach a situation where two out four nodes in the voting quorum
    # are unable to participate (one retired and one not yet joined).
    test_add_node(network, args)
    primary, _ = network.find_primary()
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args)
    proposal_body = {
        "actions": [
            {
                "name": "transition_node_to_trusted",
                "args": {
                    "node_id": new_node.node_id,
                    "valid_from": str(datetime.utcnow()),
                },
            },
            {
                "name": "remove_node",
                "args": {"node_id": primary.node_id},
            },
        ]
    }

    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    network.consortium.vote_using_majority(
        primary,
        proposal,
        {"ballot": "export function vote (proposal, proposer_id) { return true }"},
        timeout=10,
    )

    network.wait_for_new_primary(primary)
    new_node.wait_for_node_to_join(timeout=10)

    primary.stop()
    network.nodes.remove(primary)
    wait_for_reconfiguration_to_complete(network)
    return network


@reqs.description("Test retired nodes have emitted at most one signature")
def test_retiring_nodes_emit_at_most_one_signature(network, args):
    primary, _ = network.find_primary()

    # Force ledger flush of all transactions so far
    network.get_latest_ledger_public_state()
    ledger = ccf.ledger.Ledger(primary.remote.ledger_paths())

    retiring_nodes = set()
    retired_nodes = set()
    for chunk in ledger:
        for tr in chunk:
            tables = tr.get_public_domain().get_tables()
            if ccf.ledger.NODES_TABLE_NAME in tables:
                nodes = tables[ccf.ledger.NODES_TABLE_NAME]
                for nid, info_ in nodes.items():
                    if info_ is None:
                        # Node was removed
                        continue
                    info = json.loads(info_)
                    if info["status"] == "Retired":
                        retiring_nodes.add(nid)

            if ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables:
                sigs = tables[ccf.ledger.SIGNATURE_TX_TABLE_NAME]
                assert len(sigs) == 1, sigs.keys()
                (sig_,) = sigs.values()
                sig = json.loads(sig_)
                assert (
                    sig["node"] not in retired_nodes
                ), f"Unexpected signature from {sig['node']}"
                retired_nodes |= retiring_nodes
                retiring_nodes = set()

    assert not retiring_nodes, (retiring_nodes, retired_nodes)
    LOG.info("{} nodes retired throughout test", len(retired_nodes))

    wait_for_reconfiguration_to_complete(network)

    return network


@reqs.description("Adding a learner without snapshot")
def test_learner_catches_up(network, args):
    primary, _ = network.find_primary()
    num_nodes_before = 0

    with primary.client() as c:
        s = c.get("/node/consensus")
        rj = s.body.json()
        # At this point, there should be exactly one configuration
        assert len(rj["details"]["configs"]) == 1
        c0 = rj["details"]["configs"][0]["nodes"]
        num_nodes_before = len(c0)

    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args)
    network.trust_node(new_node, args)

    with new_node.client() as c:
        s = c.get("/node/network/nodes/self")
        rj = s.body.json()
        assert rj["status"] == "Learner" or rj["status"] == "Trusted"

    network.wait_for_node_in_store(
        primary,
        new_node.node_id,
        node_status=(ccf.ledger.NodeStatus.TRUSTED),
        timeout=3,
    )

    with primary.client() as c:
        s = c.get("/node/consensus")
        rj = s.body.json()
        assert len(rj["details"]["learners"]) == 0

        # At this point, there should be exactly one configuration, which includes the new node.
        assert len(rj["details"]["configs"]) == 1
        c0 = rj["details"]["configs"][0]["nodes"]
        assert len(c0) == num_nodes_before + 1
        assert new_node.node_id in c0

    return network


@reqs.description("Test node certificates validity period")
def test_node_certificates_validity_period(network, args):
    for node in network.get_joined_nodes():
        node.verify_certificate_validity_period()
    return network


@reqs.description("Add a new node without a snapshot but with the historical ledger")
def test_add_node_with_read_only_ledger(network, args):
    network.txs.issue(network, number_txs=10)
    network.txs.issue(network, number_txs=2, repeat=True)

    new_node = network.create_node("local://localhost")
    network.join_node(
        new_node, args.package, args, from_snapshot=False, copy_ledger=True
    )
    network.trust_node(new_node, args)
    return network


@reqs.description("Test reconfiguration type in service config")
def test_service_config_endpoint(network, args):
    for n in network.get_joined_nodes():
        with n.client() as c:
            r = c.get("/node/service/configuration")
            rj = r.body.json()
            assert args.reconfiguration_type == rj["reconfiguration_type"]


@reqs.description("Confirm ledger contains expected entries")
def test_ledger_invariants(network, args):
    # Force ledger flush of all transactions so far
    network.get_latest_ledger_public_state()

    for node in network.nodes:
        LOG.info(f"Examining ledger on node {node.local_node_id}")
        ledger_directories = node.remote.ledger_paths()
        ledger = ccf.ledger.Ledger(ledger_directories)
        check_signatures(ledger)

    return network


def run_all(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)

        test_version(network, args)
        test_issue_fake_join(network, args)

        test_add_as_many_pending_nodes(network, args)
        test_add_node_invalid_service_cert(network, args)
        test_add_node(network, args, from_snapshot=False)
        test_add_node_with_read_only_ledger(network, args)
        test_join_straddling_primary_replacement(network, args)
        test_node_replacement(network, args)
        test_add_node_from_backup(network, args)
        test_add_node_amd_endorsements_endpoint(network, args)
        test_add_node_on_other_curve(network, args)
        test_retire_backup(network, args)
        test_add_node(network, args)
        test_retire_primary(network, args)

        test_add_node_from_snapshot(network, args)
        test_add_node_from_snapshot(network, args, from_backup=True)
        test_add_node_from_snapshot(network, args, copy_ledger=False)

        test_node_filter(network, args)
        test_retiring_nodes_emit_at_most_one_signature(network, args)

        if args.reconfiguration_type == "TwoTransaction":
            test_learner_catches_up(network, args)

        test_service_config_endpoint(network, args)
        test_node_certificates_validity_period(network, args)
        test_add_node_invalid_validity_period(network, args)

        test_ledger_invariants(network, args)

    run_join_old_snapshot(args)


def run_join_old_snapshot(args):
    txs = app.LoggingTxs("user0")
    nodes = ["local://localhost"]

    with tempfile.TemporaryDirectory() as tmp_dir:
        with infra.network.network(
            nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            pdb=args.pdb,
            txs=txs,
        ) as network:
            network.start_and_open(args)
            primary, _ = network.find_primary()

            # First, retrieve and save one committed snapshot
            txs.issue(network, number_txs=args.snapshot_tx_interval)
            old_committed_snapshots = network.get_committed_snapshots(primary)
            copy(
                os.path.join(
                    old_committed_snapshots, os.listdir(old_committed_snapshots)[0]
                ),
                tmp_dir,
            )

            # Then generate another newer snapshot, and add two more nodes from it
            txs.issue(network, number_txs=args.snapshot_tx_interval)

            for _ in range(0, 2):
                new_node = network.create_node("local://localhost")
                network.join_node(
                    new_node,
                    args.package,
                    args,
                    from_snapshot=True,
                )
                network.trust_node(new_node, args)

            # Kill primary and wait for a new one: new primary is
            # guaranteed to have started from the new snapshot
            primary.stop()
            network.wait_for_new_primary(primary)

            # Start new node from the old snapshot
            try:
                new_node = network.create_node("local://localhost")
                network.join_node(
                    new_node,
                    args.package,
                    args,
                    from_snapshot=True,
                    snapshots_dir=tmp_dir,
                    timeout=3,
                )
            except infra.network.StartupSeqnoIsOld:
                LOG.info(
                    f"Node {new_node.local_node_id} started from old snapshot could not join the service, as expected"
                )
            else:
                raise RuntimeError(
                    f"Node {new_node.local_node_id} started from old snapshot unexpectedly joined the service"
                )

            # Start new node from no snapshot
            try:
                new_node = network.create_node("local://localhost")
                network.join_node(
                    new_node,
                    args.package,
                    args,
                    from_snapshot=False,
                    timeout=3,
                )
            except infra.network.StartupSeqnoIsOld:
                LOG.info(
                    f"Node {new_node.local_node_id} started without snapshot could not join the service, as expected"
                )
            else:
                raise RuntimeError(
                    f"Node {new_node.local_node_id} started without snapshot unexpectedly joined the service successfully"
                )


def get_current_nodes_table(network):
    tables, _ = network.get_latest_ledger_public_state()
    tn = "public:ccf.gov.nodes.info"
    r = {}
    for nid, info in tables[tn].items():
        r[nid.decode()] = json.loads(info)
    return r


def check_2tx_ledger(ledger_paths, learner_id):
    pending_at = 0
    learner_at = 0
    trusted_at = 0

    ledger = ccf.ledger.Ledger(ledger_paths, committed_only=False)

    for chunk in ledger:
        for tr in chunk:
            tables = tr.get_public_domain().get_tables()
            if ccf.ledger.NODES_TABLE_NAME in tables:
                nodes = tables[ccf.ledger.NODES_TABLE_NAME]
                for nid, info_ in nodes.items():
                    info = json.loads(info_)
                    if nid.decode() == learner_id and "status" in info:
                        seq_no = tr.get_public_domain().get_seqno()
                        if info["status"] == "Pending":
                            pending_at = seq_no
                        elif info["status"] == "Learner":
                            learner_at = seq_no
                        elif info["status"] == "Trusted":
                            trusted_at = seq_no

    assert pending_at < learner_at < trusted_at


@reqs.description("Migrate from 1tx to 2tx reconfiguration scheme")
def test_migration_2tx_reconfiguration(
    network, args, initial_is_1tx=True, valid_from=None, **kwargs
):
    primary, _ = network.find_primary()

    # Check that the service config agrees that this is a 1tx network
    with primary.client() as c:
        s = c.get("/node/service/configuration").body.json()
        if initial_is_1tx:
            assert s["reconfiguration_type"] == "OneTransaction"

    network.consortium.submit_2tx_migration_proposal(primary)
    network.wait_for_all_nodes_to_commit(primary)

    # Check that the service config has been updated
    with primary.client() as c:
        rj = c.get("/node/service/configuration").body.json()
        assert rj["reconfiguration_type"] == "TwoTransaction"

    # Check that all nodes have updated their consensus parameters
    for node in network.nodes:
        with node.client() as c:
            rj = c.get("/node/consensus").body.json()
            assert "reconfiguration_type" in rj["details"]
            assert rj["details"]["reconfiguration_type"] == "TwoTransaction"
            assert len(rj["details"]["learners"]) == 0

    new_node = network.create_node("local://localhost", **kwargs)
    network.join_node(new_node, args.package, args)
    network.trust_node(new_node, args, valid_from=valid_from)

    # Check that the new node has the right consensus parameter
    with new_node.client() as c:
        rj = c.get("/node/consensus").body.json()
        assert "reconfiguration_type" in rj["details"]
        assert "learners" in rj["details"]
        assert rj["details"]["reconfiguration_type"] == "TwoTransaction"
        assert len(rj["details"]["learners"]) == 0


def run_migration_tests(args):
    if args.reconfiguration_type != "OneTransaction":
        return

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        test_migration_2tx_reconfiguration(network, args)
        primary, _ = network.find_primary()
        new_node = network.nodes[-1]

        ledger_paths = primary.remote.ledger_paths()
        learner_id = new_node.node_id

    check_2tx_ledger(ledger_paths, learner_id)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--include-2tx-reconfig",
            help="Include tests for the 2-transaction reconfiguration scheme",
            default=False,
            action="store_true",
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "1tx_reconfig",
        run_all,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        reconfiguration_type="OneTransaction",
    )

    if cr.args.include_2tx_reconfig:
        cr.add(
            "2tx_reconfig",
            run_all,
            package="samples/apps/logging/liblogging",
            nodes=infra.e2e_args.min_nodes(cr.args, f=1),
            reconfiguration_type="TwoTransaction",
        )

        cr.add(
            "migration",
            run_migration_tests,
            package="samples/apps/logging/liblogging",
            nodes=infra.e2e_args.min_nodes(cr.args, f=1),
            reconfiguration_type="OneTransaction",
        )

    cr.run()
