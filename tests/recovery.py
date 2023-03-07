# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.node
import infra.logging_app as app
import infra.checker
import suite.test_requirements as reqs
import ccf.ledger
import os
import json
from infra.runner import ConcurrentRunner
from distutils.dir_util import copy_tree
from infra.consortium import slurp_file
import infra.health_watcher
import time
from e2e_logging import verify_receipt
import infra.service_load
import ccf.tx_id
import tempfile

from loguru import logger as LOG


def get_and_verify_historical_receipt(network, ref_msg):
    primary, _ = network.find_primary()
    if not ref_msg:
        if not network.txs.priv:
            network.txs.issue(network, number_txs=1)
        idx, _ = network.txs.get_last_tx()
        ref_msg = network.txs.priv[idx][-1]
        ref_msg["idx"] = idx
    r = network.txs.get_receipt(
        primary,
        ref_msg["idx"],
        ref_msg["seqno"],
        ref_msg["view"],
    )
    verify_receipt(r.json()["receipt"], network.cert)
    return ref_msg


@reqs.description("Recover a service")
@reqs.recover(number_txs=2)
def test_recover_service(network, args, from_snapshot=True):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    prev_ident = open(args.previous_service_identity_file, "r", encoding="utf-8").read()
    # Strip trailing null byte
    prev_ident = prev_ident.strip("\x00")
    with old_primary.client() as c:
        r = c.get("/node/service/previous_identity")
        assert r.status_code in (200, 404), r.status_code
        prev_view = c.get("/node/network").body.json()["current_view"]

    snapshots_dir = None
    if from_snapshot:
        snapshots_dir = network.get_committed_snapshots(old_primary)

    # Start health watcher and stop nodes one by one until a recovery has to be staged
    watcher = infra.health_watcher.NetworkHealthWatcher(network, args, verbose=True)
    watcher.start()

    for node in network.get_joined_nodes():
        time.sleep(args.election_timeout_ms / 1000)
        node.stop()

    watcher.wait_for_recovery()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()

    with tempfile.NamedTemporaryFile(mode="w+") as node_data_tf:
        start_node_data = {"this is a": "recovery node"}
        json.dump(start_node_data, node_data_tf)
        node_data_tf.flush()
        recovered_network = infra.network.Network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            existing_network=network,
            node_data_json_file=node_data_tf.name,
        )

        with tempfile.NamedTemporaryFile(mode="w+") as ntf:
            service_data = {"this is a": "recovery service"}
            json.dump(service_data, ntf)
            ntf.flush()
            recovered_network.start_in_recovery(
                args,
                ledger_dir=current_ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=snapshots_dir,
                service_data_json_file=ntf.name,
            )
            LOG.info("Check that service data has been set")
            primary, _ = recovered_network.find_primary()
            with primary.client() as c:
                r = c.get("/node/network").body.json()
                assert r["service_data"] == service_data
                LOG.info("Check that the node data has been set")
                r = c.get("/node/network/nodes").body.json()
                assert r["nodes"]
                did_check = False
                for node in r["nodes"]:
                    if node["status"] == "Trusted":
                        assert node["node_data"] == start_node_data
                        did_check = True
                assert did_check

    recovered_network.verify_service_certificate_validity_period(
        args.initial_service_cert_validity_days
    )

    new_nodes = recovered_network.find_primary_and_any_backup()
    for n in new_nodes:
        with n.client() as c:
            r = c.get("/node/service/previous_identity")
            assert r.status_code == 200, r.status_code
            body = r.body.json()
            assert "previous_service_identity" in body, body
            received_prev_ident = body["previous_service_identity"]
            assert (
                received_prev_ident == prev_ident
            ), f"Response doesn't match previous identity: {received_prev_ident} != {prev_ident}"

    recovered_network.recover(args)

    LOG.info("Check that new service view is as expected")
    new_primary, _ = recovered_network.find_primary()
    with new_primary.client() as c:
        assert (
            ccf.tx_id.TxID.from_str(
                c.get("/node/network").body.json()["current_service_create_txid"]
            ).view
            == prev_view + 2
        )

    return recovered_network


@reqs.description("Recover a service with wrong service identity")
@reqs.recover(number_txs=2)
def test_recover_service_with_wrong_identity(network, args):
    old_primary, _ = network.find_primary()

    snapshots_dir = network.get_committed_snapshots(old_primary)

    network.save_service_identity(args)
    first_service_identity_file = args.previous_service_identity_file

    network.stop_all_nodes()

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

    broken_network.ignoring_shutdown_errors = True
    broken_network.stop_all_nodes(skip_verification=True)

    if exception is None:
        raise ValueError("Recovery should have failed")
    if not broken_network.nodes[0].check_log_for_error_message(
        "Previous service identity does not endorse the node identity that signed the snapshot"
    ):
        raise ValueError("Node log does not contain the expected error message")

    # Attempt a second recovery with the broken cert but no snapshot
    # Now the mismatch is only noticed when the transition proposal is submitted

    broken_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        existing_network=network,
    )

    broken_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )

    exception = None
    try:
        broken_network.recover(args)
    except Exception as ex:
        exception = ex

    broken_network.ignoring_shutdown_errors = True
    broken_network.stop_all_nodes(skip_verification=True)

    if exception is None:
        raise ValueError("Recovery should have failed")
    if not broken_network.nodes[0].check_log_for_error_message(
        "Unable to open service: Previous service identity does not match."
    ):
        raise ValueError("Node log does not contain the expected error message")

    # Recover, now with the correct service identity

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


@reqs.description("Recover a service with expired service identity")
def test_recover_service_with_expired_cert(args):
    expired_service_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "expired_service"
    )

    new_common = infra.network.get_common_folder_name(args.workspace, args.label)
    copy_tree(os.path.join(expired_service_dir, "common"), new_common)

    network = infra.network.Network(args.nodes, args.binary_dir)

    args.previous_service_identity_file = os.path.join(
        expired_service_dir, "common", "service_cert.pem"
    )

    network.start_in_recovery(
        args,
        ledger_dir=os.path.join(expired_service_dir, "0.ledger"),
        committed_ledger_dirs=[os.path.join(expired_service_dir, "0.ledger")],
        snapshots_dir=os.path.join(expired_service_dir, "0.snapshots"),
        common_dir=new_common,
    )

    network.recover(args)

    primary, _ = network.find_primary()
    infra.checker.check_can_progress(primary)

    r = primary.get_receipt(2, 3)
    verify_receipt(r.json(), network.cert)


@reqs.description("Attempt to recover a service but abort before recovery is complete")
def test_recover_service_aborted(network, args, from_snapshot=False):
    network.save_service_identity(args)
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
        # Wait until at least two recovery ledger chunks are committed
        aborted_network.consortium.force_ledger_chunk(primary)

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
    network.save_service_identity(args)
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
    encrypted_submitted_shares_count = 0
    for m in recovered_network.consortium.get_active_members():
        with primary.client() as nc:
            if (
                encrypted_submitted_shares_count
                >= recovered_network.consortium.recovery_threshold - 1
            ):
                last_member_to_submit = m
                break

            check_commit = infra.checker.Checker(nc)
            check_commit(m.get_and_submit_recovery_share(primary))
            encrypted_submitted_shares_count += 1

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

    recovered_network.recovery_count += 1
    recovered_network.consortium.check_for_service(
        new_primary,
        infra.network.ServiceStatus.OPEN,
        recovery_count=recovered_network.recovery_count,
    )

    if recovered_network.service_load:
        recovered_network.service_load.set_network(recovered_network)
    return recovered_network


@reqs.description("Recover a service from malformed ledger")
@reqs.recover(number_txs=2)
def test_recover_service_truncated_ledger(network, args, get_truncation_point):
    network.save_service_identity(args)
    old_primary, _ = network.find_primary()

    LOG.info("Force new ledger chunk for app txs to be in committed chunks")
    network.consortium.force_ledger_chunk(old_primary)

    LOG.info(
        "Fill ledger with dummy entries until at least one ledger chunk is not committed, and contains a signature"
    )
    current_ledger_path = old_primary.remote.ledger_paths()[0]
    while True:
        # NB: This is used as an app agnostic write, nothing to do with the large
        # size, or trying to force a chunk
        network.consortium.create_and_withdraw_large_proposal(
            old_primary, wait_for_commit=True
        )
        # A signature will have been emitted by now (wait_for_commit)
        # Wait a little longer so it should have been persisted to disk, but
        # retry if that has produced a committed chunk
        # Also wait long enough to avoid proposal replay protection
        time.sleep(1)
        if not all(
            f.endswith(ccf.ledger.COMMITTED_FILE_SUFFIX)
            for f in os.listdir(current_ledger_path)
        ):
            LOG.warning(
                f"Decided to stop network after looking at ledger dir {current_ledger_path}: {os.listdir(current_ledger_path)}"
            )
            break

    network.stop_all_nodes()

    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()
    LOG.warning(
        f"Ledger dir after stopping node is {current_ledger_dir}: {os.listdir(current_ledger_dir)}"
    )

    # Corrupt _uncommitted_ ledger before starting new service
    ledger = ccf.ledger.Ledger([current_ledger_dir], committed_only=False)

    chunk_filename, truncate_offset = get_truncation_point(ledger)

    assert truncate_offset is not None, "Should always truncate within tx"

    truncated_ledger_file_path = os.path.join(current_ledger_dir, chunk_filename)

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

        def get_middle_tx_offset(tx):
            offset, next_offset = tx.get_offsets()
            return offset + (next_offset - offset) // 2

        def all_txs(ledger, verbose):
            for chunk in ledger:
                if verbose:
                    LOG.info(f"Considering chunk {chunk.filename()}")
                for tx in chunk:
                    if verbose:
                        LOG.info(f"Considering tx {tx.get_tx_digest()}")
                    yield chunk, tx

        def corrupt_first_tx(ledger, verbose=False):
            LOG.info("Finding first tx to corrupt")
            for chunk, tx in all_txs(ledger, verbose):
                return chunk.filename(), get_middle_tx_offset(tx)
            return None, None

        def corrupt_last_tx(ledger, verbose=False):
            LOG.info("Finding last tx to corrupt")
            chunk_filename, truncate_offset = None, None
            for chunk, tx in all_txs(ledger, verbose):
                chunk_filename = chunk.filename()
                truncate_offset = get_middle_tx_offset(tx)
            return chunk_filename, truncate_offset

        def corrupt_first_sig(ledger, verbose=False):
            LOG.info("Finding first sig to corrupt")
            for chunk, tx in all_txs(ledger, verbose):
                tables = tx.get_public_domain().get_tables()
                if ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables:
                    return chunk.filename(), get_middle_tx_offset(tx)
            return None, None

        network = test_recover_service_truncated_ledger(network, args, corrupt_first_tx)
        network = test_recover_service_truncated_ledger(network, args, corrupt_last_tx)
        network = test_recover_service_truncated_ledger(
            network, args, corrupt_first_sig
        )

    network.stop_all_nodes()

    # Make sure ledger can be read once recovered (i.e. ledger corruption does not affect recovered ledger)
    for node in network.nodes:
        ledger = ccf.ledger.Ledger(node.remote.ledger_paths(), committed_only=False)
        _, last_seqno = ledger.get_latest_public_state()
        LOG.info(
            f"Successfully read ledger for node {node.local_node_id} up to seqno {last_seqno}"
        )


def find_recovery_tx_seqno(node):
    min_recovery_seqno = 0
    with node.client() as c:
        r = c.get("/node/state").body.json()
        if "last_recovered_seqno" not in r:
            return None
        min_recovery_seqno = r["last_recovered_seqno"]

    ledger = ccf.ledger.Ledger(node.remote.ledger_paths(), committed_only=False)
    for chunk in ledger:
        _, chunk_end_seqno = chunk.get_seqnos()
        if chunk_end_seqno < min_recovery_seqno:
            continue
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()
            seqno = tx.get_public_domain().get_seqno()
            if ccf.ledger.SERVICE_INFO_TABLE_NAME in tables:
                service_status = json.loads(
                    tables[ccf.ledger.SERVICE_INFO_TABLE_NAME][
                        ccf.ledger.WELL_KNOWN_SINGLETON_TABLE_KEY
                    ]
                )["status"]
                if service_status == "Open":
                    return seqno
    return None


def check_snapshots(args, network):
    primary, _ = network.find_primary()
    seqno = find_recovery_tx_seqno(primary)

    if seqno:
        # Check that primary node has produced a snapshot. The wait timeout is larger than the
        # signature interval, so the snapshots should become available within the timeout.
        assert args.sig_ms_interval < 3000
        if not network.get_committed_snapshots(
            primary, target_seqno=True, issue_txs=False
        ):
            raise ValueError(
                f"No snapshot found after seqno={seqno} on primary {primary.local_node_id}"
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
        primary, _ = network.find_primary()

        LOG.info("Check for well-known genesis service TxID")
        with primary.client() as c:
            r = c.get("/node/network").body.json()
            assert ccf.tx_id.TxID.from_str(
                r["current_service_create_txid"]
            ) == ccf.tx_id.TxID(2, 1)

        if args.with_load:
            # See https://github.com/microsoft/CCF/issues/3788 for justification
            LOG.info("Loading service before recovery...")
            primary, _ = network.find_primary()
            with infra.service_load.load() as load:
                load.begin(network, rate=infra.service_load.DEFAULT_REQUEST_RATE_S * 10)
                while True:
                    with primary.client() as c:
                        r = c.get("/node/commit", log_capture=[]).body.json()
                        tx_id = ccf.tx_id.TxID.from_str(r["transaction_id"])
                        if tx_id.seqno > args.sig_tx_interval:
                            LOG.info(f"Loaded service successfully: tx_id, {tx_id}")
                            break
                    time.sleep(0.1)

        ref_msg = get_and_verify_historical_receipt(network, None)

        network = test_recover_service_with_wrong_identity(network, args)

        for i in range(recoveries_count):
            # Issue transactions which will required historical ledger queries recovery
            # when the network is shutdown
            network.txs.issue(network, number_txs=1)
            network.txs.issue(network, number_txs=1, repeat=True)

            # Alternate between recovery with primary change and stable primary-ship,
            # with and without snapshots
            if i % recoveries_count == 0:
                network = test_share_resilience(network, args, from_snapshot=True)
            elif i % recoveries_count == 1:
                network = test_recover_service_aborted(
                    network, args, from_snapshot=False
                )
            else:
                # Vary nodes certificate elliptic curve
                args.curve_id = infra.network.EllipticCurve.secp256r1
                network = test_recover_service(network, args, from_snapshot=False)

            for node in network.get_joined_nodes():
                node.verify_certificate_validity_period()

            check_snapshots(args, network)
            ref_msg = get_and_verify_historical_receipt(network, ref_msg)

            LOG.success("Recovery complete on all nodes")

        primary, _ = network.find_primary()
        network.stop_all_nodes()

    # Verify that a new ledger chunk was created at the start of each recovery
    ledger = ccf.ledger.Ledger(
        primary.remote.ledger_paths(),
        committed_only=False,
        validator=ccf.ledger.LedgerValidator(accept_deprecated_entry_types=False),
    )
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
                if service_status == "Opening" or service_status == "Recovering":
                    LOG.info(
                        f"New ledger chunk found for service {service_status.lower()} at {seqno}"
                    )
                    assert (
                        chunk_start_seqno == seqno
                    ), f"{service_status} service at seqno {seqno} did not start a new ledger chunk (started at {chunk_start_seqno})"

    test_recover_service_with_expired_cert(args)


if __name__ == "__main__":

    def add(parser):
        parser.description = """
This test_recover_service executes multiple recoveries,
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
        parser.add_argument(
            "--with-load",
            help="If set, the service is loaded before being recovered",
            action="store_true",
            default=False,
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "recovery",
        run,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=30,
    )

    # Note: `run_corrupted_ledger` runs with very a specific node configuration
    # so that the contents of recovered (and tampered) ledger chunks
    # can be dictated by the test. In particular, the signature interval is large
    # enough to create in-progress ledger files that do not end on a signature. The
    # test is also in control of the ledger chunking.
    cr.add(
        "recovery_corrupt_ledger",
        run_corrupted_ledger,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),  # 1 node suffices for recovery
        sig_ms_interval=1000,
        ledger_chunk_bytes="1GB",
        snapshot_tx_interval=1000000,
    )

    cr.run()
