# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.logging_app as app
import infra.checker
import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Recovering a network")
@reqs.recover(number_txs=2)
def test(network, args, from_snapshot=True):
    old_primary, _ = network.find_primary()

    snapshot_dir = None
    if from_snapshot:
        snapshot_dir = network.get_committed_snapshots(old_primary)
    current_ledger_dir, committed_ledger_dir = old_primary.get_ledger(
        include_read_only_dirs=True
    )

    network.stop_all_nodes()

    recovered_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dir=committed_ledger_dir,
        snapshot_dir=snapshot_dir,
    )
    recovered_network.recover(args)
    return recovered_network


@reqs.description("Recovering a network, kill one node while submitting shares")
@reqs.recover(number_txs=2)
def test_share_resilience(network, args, from_snapshot=True):
    old_primary, _ = network.find_primary()

    snapshot_dir = None
    if from_snapshot:
        snapshot_dir = network.get_committed_snapshots(old_primary)
    current_ledger_dir, committed_ledger_dir = old_primary.get_ledger(
        include_read_only_dirs=True
    )

    network.stop_all_nodes()

    recovered_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dir=committed_ledger_dir,
        snapshot_dir=snapshot_dir,
    )
    primary, _ = recovered_network.find_primary()
    recovered_network.consortium.accept_recovery(primary)

    # Submit all required recovery shares minus one. Last recovery share is
    # submitted after a new primary is found.
    submitted_shares_count = 0
    for m in recovered_network.consortium.get_active_members():
        with primary.client() as nc:
            if (
                submitted_shares_count
                >= recovered_network.consortium.recovery_threshold - 1
            ):
                last_member_to_submit = m
                break

            check_commit = infra.checker.Checker(nc)
            check_commit(m.get_and_submit_recovery_share(primary))
            submitted_shares_count += 1

    LOG.info(
        f"Shutting down node {primary.node_id} before submitting last recovery share"
    )
    primary.stop()
    new_primary, _ = recovered_network.wait_for_new_primary(primary.node_id)
    assert (
        new_primary is not primary
    ), f"Primary {primary.node_id} should have changed after election"

    last_member_to_submit.get_and_submit_recovery_share(new_primary)

    for node in recovered_network.get_joined_nodes():
        recovered_network.wait_for_state(
            node, "partOfNetwork", timeout=args.ledger_recovery_timeout
        )

    recovered_network.consortium.check_for_service(
        new_primary,
        infra.network.ServiceStatus.OPEN,
    )
    return recovered_network


def run(args):
    txs = app.LoggingTxs()
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_join(args)

        for i in range(args.recovery):
            # Issue transactions which will required historical ledger queries recovery
            # when the network is shutdown
            network.txs.issue(network, number_txs=1)
            network.txs.issue(network, number_txs=1, repeat=True)

            # Alternate between recovery with primary change and stable primary-ship,
            # with and without snapshots
            if i % 2 == 0:
                recovered_network = test_share_resilience(
                    network, args, from_snapshot=True
                )
            else:
                recovered_network = test(network, args, from_snapshot=False)
            network = recovered_network
            LOG.success("Recovery complete on all nodes")


if __name__ == "__main__":

    def add(parser):
        parser.description = """
This test executes multiple recoveries (as specified by the "--recovery" arg),
with a fixed number of messages applied between each network crash (as
specified by the "--msgs-per-recovery" arg). After the network is recovered
and before applying new transactions, all transactions previously applied are
checked. Note that the key for each logging message is unique (per table).
"""
        parser.add_argument(
            "--recovery", help="Number of recoveries to perform", type=int, default=2
        )
        parser.add_argument(
            "--msgs-per-recovery",
            help="Number of public and private messages between two recoveries",
            type=int,
            default=5,
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)

    run(args)
