# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.logging_app as app
from ccf.tx_id import TxID
import suite.test_requirements as reqs
import tempfile
from shutil import copy
import os
import pprint

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


def check_can_progress(node, timeout=3):
    # Check that a write transaction issued on one node is eventually
    # committed by the service by a specified timeout
    with node.client("user0") as c:
        r = c.post("/app/log/private", {"id": 42, "msg": "Hello world"})
        try:
            c.wait_for_commit(r, timeout=timeout)
            return r
        except TimeoutError:
            details = c.get("/node/consensus").body.json()
            assert False, f"Stuck before {r.view}.{r.seqno}: {pprint.pformat(details)}"


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
    number_new_nodes = len(network.nodes)
    LOG.info(
        f"Adding {number_new_nodes} pending nodes - consensus rules should not change"
    )

    new_nodes = []
    for _ in range(number_new_nodes):
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args, from_snapshot=False)
        new_nodes.append(new_node)

    primary, _ = network.find_primary()

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
    nodes = network.get_joined_nodes()

    for node in nodes:
        with node.client() as c:
            r = c.get("/node/version")
            assert r.body.json()["ccf_version"] == args.ccf_version


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
        test_add_node_from_backup(network, args)
        test_add_node(network, args)
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
                "No snapshot found: Node will replay all historical transactions" in l
                for l in log.readlines()
            ), "New nodes shouldn't join from snapshot if snapshot evidence cannot be verified"

        test_node_filter(network, args)


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
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 1

    run(args)
    run_join_old_snapshot(args)
