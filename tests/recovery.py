# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.node
import infra.logging_app as app
import infra.checker
import suite.test_requirements as reqs
import ccf.split_ledger
import ccf.ledger
import os
import random
import json
import shutil
from infra.runner import ConcurrentRunner
from infra.consortium import slurp_file

from loguru import logger as LOG


def split_all_ledger_files_in_dir(input_dir, output_dir):
    # A ledger file can only be split at a seqno that contains a signature
    # (so that all files end on a signature that verifies their integrity).
    # We first detect all signature transactions in a ledger file and truncate
    # at any one (but not the last one, which would have no effect) at random.
    for ledger_file in os.listdir(input_dir):
        sig_seqnos = []

        if ledger_file.endswith(ccf.ledger.RECOVERY_FILE_SUFFIX):
            # Ignore recovery files
            continue

        ledger_file_path = os.path.join(input_dir, ledger_file)
        ledger_chunk = ccf.ledger.LedgerChunk(ledger_file_path, ledger_validator=None)
        for transaction in ledger_chunk:
            public_domain = transaction.get_public_domain()
            if ccf.ledger.SIGNATURE_TX_TABLE_NAME in public_domain.get_tables().keys():
                sig_seqnos.append(public_domain.get_seqno())

        if len(sig_seqnos) <= 1:
            # A chunk may not contain enough signatures to be worth truncating
            continue

        # Ignore last signature, which would result in a no-op split
        split_seqno = random.choice(sig_seqnos[:-1])

        assert ccf.split_ledger.run(
            [ledger_file_path, str(split_seqno), f"--output-dir={output_dir}"]
        ), f"Ledger file {ledger_file_path} was not split at {split_seqno}"
        LOG.info(
            f"Ledger file {ledger_file_path} was successfully split at {split_seqno}"
        )
        LOG.debug(f"Deleting input ledger file {ledger_file_path}")
        os.remove(ledger_file_path)


def save_service_identity(network, args):
    current_identity = os.path.join(network.common_dir, "service_cert.pem")
    previous_identity = os.path.join(network.common_dir, "previous_service_cert.pem")
    shutil.copy(current_identity, previous_identity)
    args.previous_service_identity_file = previous_identity


@reqs.description("Recover a service")
@reqs.recover(number_txs=2)
def test_recover_service(network, args, from_snapshot=False, split_ledger=False):
    save_service_identity(network, args)
    old_primary, _ = network.find_primary()

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    if split_ledger:
        # Test that ledger files can be arbitrarily split and that recovery
        # and historical queries work as expected.
        # Note: For real operations, it would be best practice to use a separate
        # output directory
        split_all_ledger_files_in_dir(current_ledger_dir, current_ledger_dir)
        if committed_ledger_dirs:
            split_all_ledger_files_in_dir(
                committed_ledger_dirs[0], committed_ledger_dirs[0]
            )

    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )

    recovered_network.recover(args)

    return recovered_network


@reqs.description("Recover a service with previous service identity")
@reqs.recover(number_txs=2)
def test_recover_service_with_previous_identity(network, args):
    old_primary, _ = network.find_primary()

    snapshots_dir = network.get_committed_snapshots(old_primary)

    network.stop_all_nodes()

    save_service_identity(network, args)
    first_service_identity_file = args.previous_service_identity_file

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    # Attempt a recovery with the wrong previous service certificate

    args.previous_service_identity_file = network.consortium.user_cert_path("user0")

    broken_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )

    exception = None
    try:
        broken_network.start_in_recovery(
            args,
            ledger_dir=current_ledger_dir,
            committed_ledger_dirs=committed_ledger_dirs,
            snapshots_dir=snapshots_dir,
        )
    except Exception as ex:
        exception = ex

    broken_network.stop_all_nodes(skip_verification=True)

    # At least one node has to abort because of the snapshot cert check failure
    found_expected_error = False
    for n in broken_network.nodes:
        broken_network.ignoring_shutdown_errors = True
        if n.check_log_for_error_message(
            "Error starting node: Previous service identity does not endorse the node identity that signed the snapshot"
        ):
            found_expected_error = True
            break

    if exception is None:
        raise ValueError("Recovery should have failed")
    if not found_expected_error:
        raise ValueError("Node log does not contain the expect error message")

    # Recover, now with the right service identity

    args.previous_service_identity_file = first_service_identity_file

    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )

    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )

    recovered_network.recover(args)

    return recovered_network


@reqs.description("Attempt to recover a service but abort before recovery is complete")
def test_recover_service_aborted(network, args, from_snapshot=False):
    save_service_identity(network, args)
    old_primary, _ = network.find_primary()

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    network.stop_all_nodes()
    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    aborted_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    aborted_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )

    LOG.info("Fill in ledger to trigger new chunks, which should be marked as recovery")
    primary, _ = aborted_network.find_primary()
    while (
        len(
            [
                f
                for f in os.listdir(primary.remote.ledger_paths()[0])
                if f.endswith(
                    f"{ccf.ledger.COMMITTED_FILE_SUFFIX}{ccf.ledger.RECOVERY_FILE_SUFFIX}"
                )
            ]
        )
        < 2
    ):
        # Submit large proposal until at least two recovery ledger chunks are committed
        aborted_network.consortium.create_and_withdraw_large_proposal(primary)

    LOG.info(
        "Do not complete service recovery on purpose and initiate new recovery from scratch"
    )

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(primary)

    # Check that all nodes have the same (recovery) ledger files
    aborted_network.stop_all_nodes(
        skip_verification=True, read_recovery_ledger_files=True
    )

    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=aborted_network,
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )
    recovered_network.recover(args)
    return recovered_network


@reqs.description("Recovering a service, kill one node while submitting shares")
@reqs.recover(number_txs=2)
def test_share_resilience(network, args, from_snapshot=False):
    save_service_identity(network, args)
    old_primary, _ = network.find_primary()

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    recovered_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
    )
    primary, _ = recovered_network.find_primary()
    recovered_network.consortium.transition_service_to_open(
        primary,
        previous_service_identity=slurp_file(args.previous_service_identity_file),
    )

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
    new_primary, _ = recovered_network.wait_for_new_primary(primary)

    last_member_to_submit.get_and_submit_recovery_share(new_primary)

    for node in recovered_network.get_joined_nodes():
        recovered_network.wait_for_state(
            node,
            infra.node.State.PART_OF_NETWORK.value,
            timeout=args.ledger_recovery_timeout,
        )

    recovered_network.consortium.check_for_service(
        new_primary,
        infra.network.ServiceStatus.OPEN,
    )
    return recovered_network


@reqs.description("Recover a service from malformed ledger")
@reqs.recover(number_txs=2)
def test_recover_service_truncated_ledger(
    network,
    args,
    corrupt_first_tx=False,
    corrupt_last_tx=False,
    corrupt_first_sig=False,
):
    old_primary, _ = network.find_primary()

    LOG.info("Force new ledger chunk for app txs to be in committed chunks")
    network.consortium.force_ledger_chunk(old_primary)

    LOG.info(
        "Fill ledger with dummy entries until at least one ledger chunk is not committed, and contains a signature"
    )
    current_ledger_path = old_primary.remote.ledger_paths()[0]
    while True:
        network.consortium.create_and_withdraw_large_proposal(
            old_primary, wait_for_commit=True
        )
        # A signature will have been emitted by now (wait_for_commit)
        network.consortium.create_and_withdraw_large_proposal(old_primary)
        if not all(
            f.endswith(ccf.ledger.COMMITTED_FILE_SUFFIX)
            for f in os.listdir(current_ledger_path)
        ):
            break

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    # Corrupt _uncommitted_ ledger before starting new service
    ledger = ccf.ledger.Ledger(
        [current_ledger_dir], committed_only=False, insecure_skip_verification=True
    )

    def get_middle_tx_offset(tx):
        offset, next_offset = tx.get_offsets()
        return offset + (next_offset - offset) // 2

    for chunk in ledger:
        chunk_filename = chunk.filename()
        first_tx_offset = None
        last_tx_offset = None
        first_sig_offset = None
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()
            if (
                first_sig_offset is None
                and ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables
            ):
                first_sig_offset = get_middle_tx_offset(tx)
            last_tx_offset = get_middle_tx_offset(tx)
            if first_tx_offset is None:
                first_tx_offset = get_middle_tx_offset(tx)

    truncated_ledger_file_path = os.path.join(current_ledger_dir, chunk_filename)
    if corrupt_first_tx:
        truncate_offset = first_tx_offset
    elif corrupt_last_tx:
        truncate_offset = last_tx_offset
    elif corrupt_first_sig:
        truncate_offset = first_sig_offset

    with open(truncated_ledger_file_path, "r+", encoding="utf-8") as f:
        f.truncate(truncate_offset)
    LOG.warning(
        f"Truncated ledger file {truncated_ledger_file_path} at {truncate_offset}"
    )

    recovered_network = infra.network.Network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    recovered_network.recover(args)

    return recovered_network


def run_corrupted_ledger(args):
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
        network = test_recover_service_truncated_ledger(
            network, args, corrupt_first_tx=True
        )
        network = test_recover_service_truncated_ledger(
            network, args, corrupt_last_tx=True
        )
        network = test_recover_service_truncated_ledger(
            network, args, corrupt_first_sig=True
        )

    # Make sure ledger can be read once recovered (i.e. ledger corruption does not affect recovered ledger)
    for node in network.nodes:
        ledger = ccf.ledger.Ledger(node.remote.ledger_paths(), committed_only=False)
        _, last_seqno = ledger.get_latest_public_state()
        LOG.info(
            f"Successfully read ledger for node {node.local_node_id} up to seqno {last_seqno}"
        )


def run(args):
    recoveries_count = 3

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

        network = test_recover_service_with_previous_identity(network, args)

        for i in range(recoveries_count):
            # Issue transactions which will required historical ledger queries recovery
            # when the network is shutdown
            network.txs.issue(network, number_txs=1)
            network.txs.issue(network, number_txs=1, repeat=True)

            # Alternate between recovery with primary change and stable primary-ship,
            # with and without snapshots
            if i % recoveries_count == 0:
                if args.consensus != "BFT":
                    network = test_share_resilience(network, args, from_snapshot=True)
            elif i % recoveries_count == 1:
                network = test_recover_service_aborted(
                    network, args, from_snapshot=False
                )
            else:
                network = test_recover_service(
                    network, args, from_snapshot=False, split_ledger=True
                )

            for node in network.get_joined_nodes():
                node.verify_certificate_validity_period()

            primary, _ = network.find_primary()

            LOG.success("Recovery complete on all nodes")

    # Verify that a new ledger chunk was created at the start of each recovery
    ledger = ccf.ledger.Ledger(primary.remote.ledger_paths(), committed_only=False)
    for chunk in ledger:
        chunk_start_seqno, _ = chunk.get_seqnos()
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()
            seqno = tx.get_public_domain().get_seqno()
            if ccf.ledger.SERVICE_INFO_TABLE_NAME in tables:
                service_status = json.loads(
                    tables[ccf.ledger.SERVICE_INFO_TABLE_NAME][
                        ccf.ledger.WELL_KNOWN_SINGLETON_TABLE_KEY
                    ]
                )["status"]
                if service_status == "Opening":
                    LOG.info(f"New ledger chunk found for service opening at {seqno}")
                    assert (
                        chunk_start_seqno == seqno
                    ), f"Opening service at seqno {seqno} did not start a new ledger chunk (started at {chunk_start_seqno})"


if __name__ == "__main__":

    def add(parser):
        parser.description = """
This test_recover_service executes multiple recoveries (as specified by the "--recovery" arg),
with a fixed number of messages applied between each network crash (as
specified by the "--msgs-per-recovery" arg). After the network is recovered
and before applying new transactions, all transactions previously applied are
checked. Note that the key for each logging message is unique (per table).
"""
        parser.add_argument(
            "--msgs-per-recovery",
            help="Number of public and private messages between two recoveries",
            type=int,
            default=5,
        )

    args = infra.e2e_args.cli_args(add)

    cr = ConcurrentRunner()

    # Test-specific values so that it is likely that ledger files contain
    # at least two signatures, so that they can be split at the first one
    cr.add(
        "recovery",
        run,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(args, f=1),
        ledger_chunk_bytes="50KB",
        snasphot_tx_interval=30,
    )

    # Note: `run_corrupted_ledger` runs with very a specific node configuration
    # so that the contents of recovered (and tampered) ledger chunks
    # can be dictated by the test. In particular, the signature interval is large # enough to create in-progress ledger files that do not end on a signature. The
    # test is also in control of the ledger chunking.
    cr.add(
        "recovery_corrupt_ledger",
        run_corrupted_ledger,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(args, f=0),  # 1 node suffices for recovery
        sig_ms_interval=1000,
        ledger_chunk_bytes="1GB",
        snasphot_tx_interval=1000000,
    )

    cr.run()
