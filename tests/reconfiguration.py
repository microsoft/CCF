# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.logging_app as app
import suite.test_requirements as reqs
import tempfile
from shutil import copy
import os
from infra.checker import check_can_progress
import ccf.ledger
import json

from loguru import logger as LOG


def node_configs(network):
    configs = {}
    for node in network.nodes:
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


@reqs.description("Adding a valid node without snapshot")
def test_add_node(network, args):
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, from_snapshot=False)
    network.trust_node(new_node, args)
    with new_node.client() as c:
        s = c.get("/node/state")
        assert s.body.json()["node_id"] == new_node.node_id
        assert (
            s.body.json()["startup_seqno"] == 0
        ), "Node started without snapshot but reports startup seqno != 0"
    assert new_node
    return network


@reqs.description("Adding a node on different curve")
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
        new_node, args.package, args, target_node=network.find_any_backup()
    )
    network.trust_node(new_node, args)
    return network


@reqs.description("Adding a valid node from snapshot")
@reqs.at_least_n_nodes(2)
def test_add_node_from_snapshot(
    network, args, copy_ledger_read_only=True, from_backup=False
):
    # Before adding the node from a snapshot, override at least one app entry
    # and wait for a new committed snapshot covering that entry, so that there
    # is at least one historical entry to verify.
    network.txs.issue(network, number_txs=1)
    for _ in range(1, args.snapshot_tx_interval):
        network.txs.issue(network, number_txs=1, repeat=True)
        last_tx = network.txs.get_last_tx(priv=True)
        if network.wait_for_snapshot_committed_for(seqno=last_tx[1]["seqno"]):
            break

    target_node = None
    snapshot_dir = None
    if from_backup:
        primary, target_node = network.find_primary_and_any_backup()
        # Retrieve snapshot from primary as only primary node
        # generates snapshots
        snapshot_dir = network.get_committed_snapshots(primary)

    new_node = network.create_node("local://localhost")
    network.join_node(
        new_node,
        args.package,
        args,
        copy_ledger_read_only=copy_ledger_read_only,
        target_node=target_node,
        snapshot_dir=snapshot_dir,
    )
    network.trust_node(new_node, args)

    if copy_ledger_read_only:
        with new_node.client() as c:
            r = c.get("/node/state")
            assert (
                r.body.json()["startup_seqno"] != 0
            ), "Node started from snapshot but reports startup seqno of 0"

    # Finally, verify all app entries on the new node, including historical ones
    network.txs.verify(node=new_node)

    return network


@reqs.description("Adding as many pending nodes as current number of nodes")
@reqs.supports_methods("log/private")
def test_add_as_many_pending_nodes(network, args):
    # Should not change the raft consensus rules (i.e. majority)
    primary, _ = network.find_primary()
    number_new_nodes = len(network.nodes)
    LOG.info(
        f"Adding {number_new_nodes} pending nodes - consensus rules should not change"
    )

    new_nodes = []
    for _ in range(number_new_nodes):
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args, from_snapshot=False)
        new_nodes.append(new_node)

    check_can_progress(primary)

    for new_node in new_nodes:
        network.retire_node(primary, new_node)
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
    return network


@reqs.description("Retiring the primary")
@reqs.can_kill_n_nodes(1)
def test_retire_primary(network, args):
    pre_count = count_nodes(node_configs(network), network)

    primary, backup = network.find_primary_and_any_backup()
    network.retire_node(primary, primary)
    network.wait_for_new_primary(primary)
    check_can_progress(backup)
    post_count = count_nodes(node_configs(network), network)
    assert pre_count == post_count + 1
    primary.stop()
    return network


@reqs.description("Test node filtering by status")
def test_node_filter(network, args):
    primary, _ = network.find_primary_and_any_backup()
    with primary.client() as c:

        def get_nodes(status):
            r = c.get(f"/node/network/nodes?status={status}")
            nodes = r.body.json()["nodes"]
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
    assert new_node
    return network


@reqs.description("Get node CCF version")
def test_version(network, args):
    if args.ccf_version is None:
        return

    nodes = network.get_joined_nodes()

    for node in nodes:
        with node.client() as c:
            r = c.get("/node/version")
            assert r.body.json()["ccf_version"] == args.ccf_version


@reqs.description("Replace a node on the same addresses")
@reqs.at_least_n_nodes(3)  # Should be at_least_f_failures(1)
def test_node_replacement(network, args):
    primary, backups = network.find_nodes()

    nodes = network.get_joined_nodes()
    node_to_replace = backups[-1]
    f = infra.e2e_args.max_f(args, len(nodes))
    f_backups = backups[:f]

    # Retire one node
    network.retire_node(primary, node_to_replace)
    node_to_replace.stop()
    check_can_progress(primary)

    # Add in a node using the same address
    replacement_node = network.create_node(
        f"local://{node_to_replace.host}:{node_to_replace.rpc_port}",
        node_port=node_to_replace.node_port,
    )
    network.join_node(replacement_node, args.package, args, from_snapshot=False)
    network.trust_node(replacement_node, args)

    assert replacement_node.node_id != node_to_replace.node_id
    assert replacement_node.host == node_to_replace.host
    assert replacement_node.node_port == node_to_replace.node_port
    assert replacement_node.rpc_port == node_to_replace.rpc_port
    LOG.info(
        f"Stopping {len(f_backups)} other nodes to make progress depend on the replacement"
    )
    for other_backup in f_backups:
        other_backup.suspend()
    # Confirm the network can make progress
    check_can_progress(primary)
    for other_backup in f_backups:
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
    network.trust_node(new_node, args)
    proposal_body = {
        "actions": [
            {
                "name": "transition_node_to_trusted",
                "args": {"node_id": new_node.node_id},
            },
            {"name": "remove_node", "args": {"node_id": primary.node_id}},
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
    return network


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

    return network


@reqs.description("Adding a learner without snapshot")
def test_learner_catches_up(network, args):
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, from_snapshot=False)
    network.trust_node(new_node, args, ccf.ledger.NodeStatus.LEARNER)
    with new_node.client() as c:
        s = c.get("/node/state")
        assert s.body.json()["node_id"] == new_node.node_id
        assert (
            s.body.json()["startup_seqno"] == 0
        ), "Node started without snapshot but reports startup seqno != 0"

        # No promotion yet, check that the node is still a learner
        s = c.get("/node/network/nodes/self")
        assert s.body.json()["status"] == "Learner"

        s = c.get("/node/commit")
        tx = s.body.json()["transaction_id"]
        assert tx != "0.0" and tx != "2.0"
    network.wait_for_node_commit_sync()
    return network


def run(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_join(args)

        test_version(network, args)

        if args.consensus == "cft":
            test_join_straddling_primary_replacement(network, args)
            test_node_replacement(network, args)
            test_add_node_from_backup(network, args)
            test_add_node(network, args)
            test_add_node_on_other_curve(network, args)
            test_retire_backup(network, args)
            test_add_as_many_pending_nodes(network, args)
            test_add_node(network, args)
            test_retire_primary(network, args)

            test_add_node_from_snapshot(network, args)
            test_add_node_from_snapshot(network, args, from_backup=True)
            test_add_node_from_snapshot(network, args, copy_ledger_read_only=False)
            latest_node_log = network.get_joined_nodes()[-1].remote.log_path()
            with open(latest_node_log, "r+") as log:
                assert any(
                    "No snapshot found: Node will replay all historical transactions"
                    in l
                    for l in log.readlines()
                ), "New nodes shouldn't join from snapshot if snapshot evidence cannot be verified"

            test_node_filter(network, args)
            test_retiring_nodes_emit_at_most_one_signature(network, args)
        elif args.consensus == "bft":
            test_learner_catches_up(network, args)
        else:
            raise Exception("Unknown consensus protocol")


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
            network.start_and_join(args)
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
                    snapshot_dir=tmp_dir,
                    timeout=3,
                )
            except infra.network.StartupSnapshotIsOld:
                pass


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.initial_user_count = 1

    run(args)

    if args.consensus == "cft":
        run_join_old_snapshot(args)
