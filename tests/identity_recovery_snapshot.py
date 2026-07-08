# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import shutil
import time

import infra.e2e_args
import infra.network
import infra.node
import infra.logging_app as app
import suite.test_requirements as reqs
from infra.runner import ConcurrentRunner
from loguru import logger as LOG

# Log fragments emitted by the network identity subsystem
# (src/node/rpc/network_identity_subsystem.h), kept in sync with the C++ code.
#
# IDENTITY_FETCH_DONE_LOG is logged by log_status() once the endorsement chain
# has been fetched successfully. For a node joining from a pre-recovery snapshot
# it can only appear if the node built the identity chain spanning the recovery
# boundary, so it is a deterministic, reliable signal that cross-recovery chain
# building works end to end.
#
# STALE_IDENTITY_RETRY_LOG is logged by retry_fetch_first() when the topmost
# endorsement in the (still-stale) local store is signed by a previous service
# identity. Whether it appears depends on a startup race: the node has to reach
# part-of-network while its local store still exposes the pre-recovery service as
# OPEN, before the recovered service-open transaction is applied. That race
# cannot be forced deterministically through the join API, so it is only checked
# best-effort here. The deterministic regression coverage for the retry path is
# the unit test network_identity_subsystem_test.
IDENTITY_FETCH_DONE_LOG = "Network identity fetching settled at Done"
STALE_IDENTITY_RETRY_LOG = "signed by a stale service identity"


def preserve_oldest_committed_snapshot(network, primary, dest_name):
    """Copy the oldest committed snapshot into a dedicated directory and return
    that directory. Because this snapshot predates the recovery, a node that
    later joins from it momentarily observes the pre-recovery service identity in
    its local store until it replays the committed ledger suffix."""
    committed_snapshots_dir = network.get_committed_snapshots(primary)
    snapshots = sorted(
        os.listdir(committed_snapshots_dir),
        key=lambda name: infra.node.get_snapshot_seqnos(name)[0],
    )
    assert snapshots, "Expected at least one committed snapshot before recovery"
    oldest = snapshots[0]
    dest_dir = os.path.join(network.common_dir, dest_name)
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy(os.path.join(committed_snapshots_dir, oldest), dest_dir)
    LOG.info(f"Preserved pre-recovery snapshot {oldest} in {dest_dir}")
    return dest_dir


def wait_for_node_log(node, needle, timeout=30):
    """Poll a node's stdout log until `needle` appears or the timeout elapses,
    returning the log contents from the final read. Trusting a node does not
    block on the asynchronous network identity fetch, so callers use this to wait
    for that subsystem to settle before asserting on its log output."""
    out_path, _ = node.get_logs()
    assert out_path is not None, "Could not locate the node's log file"
    deadline = time.time() + timeout
    node_log = ""
    while time.time() < deadline:
        with open(out_path, encoding="utf-8") as f:
            node_log = f.read()
        if needle in node_log:
            return node_log
        time.sleep(0.2)
    return node_log


@reqs.description(
    "A node joining from a pre-recovery snapshot catches up past the recovery"
)
def test_join_from_stale_pre_recovery_snapshot(network, args):
    # Capture a committed snapshot from before the recovery. A node started from
    # this snapshot sees the OLD (pre-recovery) service identity as current until
    # it replays the committed ledger suffix that includes the recovery.
    primary, _ = network.find_primary()
    stale_snapshots_dir = preserve_oldest_committed_snapshot(
        network, primary, "stale_pre_recovery_snapshot"
    )

    # Disaster-recover the service. Recovery mints a new network identity which
    # endorses the previous one, extending the identity endorsement chain and
    # changing the service identity that new nodes are handed when they join.
    network.save_service_identity(args)
    primary, _ = network.find_primary()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    network.stop_all_nodes()

    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        existing_network=network,
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    recovered_network.recover(args)
    LOG.success("Service recovered under a new network identity")

    # Add a new node that joins the recovered service from the STALE snapshot,
    # replaying the ledger suffix from the primary. copy_ledger=False keeps the
    # joining node's local store at the snapshot state initially (the realistic
    # production join path), so its bootstrap has to walk the identity chain
    # across the recovery boundary before it can settle.
    new_node = recovered_network.create_node()
    recovered_network.join_node(
        new_node,
        args.package,
        args,
        from_snapshot=True,
        snapshots_dir=stale_snapshots_dir,
        copy_ledger=False,
    )
    recovered_network.trust_node(new_node, args)
    LOG.success("New node joined from the stale pre-recovery snapshot and caught up")

    # The joining node started from a pre-recovery snapshot yet successfully
    # bootstrapped its network identity. That is only possible if it built the
    # endorsement chain spanning the recovery boundary (from the recovered
    # identity back to the pre-recovery self-endorsement); had cross-recovery
    # chain building regressed, the node would fail bootstrap and never settle at
    # Done. The identity fetch is asynchronous and not awaited by trust_node, so
    # wait for it to settle before asserting. This is the deterministic check.
    node_log = wait_for_node_log(new_node, IDENTITY_FETCH_DONE_LOG, timeout=30)
    assert (
        IDENTITY_FETCH_DONE_LOG in node_log
    ), "Joining node network identity fetching did not settle at Done"

    # Best-effort: if the startup race lined up, the node will also have logged
    # the stale-identity retry. This is not asserted because the race cannot be
    # forced through the join API (see the note by STALE_IDENTITY_RETRY_LOG); the
    # retry path is covered deterministically by network_identity_subsystem_test.
    if STALE_IDENTITY_RETRY_LOG in node_log:
        LOG.success(
            "Joining node hit and recovered from the stale pre-recovery identity "
            "retry path"
        )
    else:
        LOG.info(
            "Joining node caught up before the stale-identity window opened; the "
            "retry path is covered deterministically by the unit test"
        )

    return recovered_network


def run(args):
    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        # Issue enough transactions that several snapshots are produced and
        # committed before the recovery, so the oldest one is comfortably stale.
        network.txs.issue(network, number_txs=30)
        network = test_join_from_stale_pre_recovery_snapshot(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.description = (
            "Reproduce a node joining a recovered service from a snapshot taken "
            "before the recovery, and verify it catches up once the recovery is "
            "replayed."
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "recovery_stale_snapshot_join",
        run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=10,
    )

    cr.run()
