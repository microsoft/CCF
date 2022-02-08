# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import os
import shutil

import infra.logging_app as app
import infra.e2e_args
import infra.network
import ccf.ledger
import suite.test_requirements as reqs
import infra.crypto
import ipaddress
import infra.interfaces
import infra.path
import infra.proc


from loguru import logger as LOG


@reqs.description("Move committed ledger files to read-only directory")
def test_save_committed_ledger_files(network, args):
    # Issue txs in a loop to force a signature and a new ledger chunk
    # each time. Record log messages at the same key (repeat=True) so
    # that CCF makes use of historical queries when verifying messages
    for _ in range(1, 5):
        network.txs.issue(network, 1, repeat=True)

    LOG.info(f"Moving committed ledger files to {args.common_read_only_ledger_dir}")
    primary, _ = network.find_primary()
    for ledger_dir in primary.remote.ledger_paths():
        for l in os.listdir(ledger_dir):
            if infra.node.is_file_committed(l):
                shutil.move(
                    os.path.join(ledger_dir, l),
                    os.path.join(args.common_read_only_ledger_dir, l),
                )

    network.txs.verify(network)
    return network


def test_parse_snapshot_file(network, args):
    primary, _ = network.find_primary()
    network.txs.issue(network, number_txs=args.snapshot_tx_interval * 2)
    committed_snapshots_dir = network.get_committed_snapshots(primary)
    for snapshot in os.listdir(committed_snapshots_dir):
        with ccf.ledger.Snapshot(os.path.join(committed_snapshots_dir, snapshot)) as s:
            assert len(
                s.get_public_domain().get_tables()
            ), "No public table in snapshot"
    return network


@reqs.description("Forced ledger chunk")
def test_forced_ledger_chunk(network, args):
    primary, _ = network.find_primary()

    # Submit some dummy transactions
    network.txs.issue(network, number_txs=7)

    # Submit a proposal to force a ledger chunk at the following signature
    proposal_body, careful_vote = network.consortium.make_proposal(
        "request_ledger_chunk", node_id=primary.node_id
    )
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    proposal = network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )

    # Issue some more transactions
    network.txs.issue(network, number_txs=13)

    # Wait for the signature interval to ensure we see at least one signature
    time.sleep(args.sig_ms_interval / 1000)

    ledger_dirs = primary.remote.ledger_paths()
    network.check_ledger_files_identical()

    # Check that there is indeed a ledger chunk that ends at the
    # first signature after proposal.seqno
    ledger = ccf.ledger.Ledger(ledger_dirs)
    for chunk in ledger:
        first = last = next_signature = None
        for tx in chunk:
            pd = tx.get_public_domain()
            if first is None:
                first = pd.get_seqno()
            else:
                last = pd.get_seqno()
            tables = pd.get_tables()
            if (
                pd.get_seqno() >= proposal.seqno
                and next_signature is None
                and ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables
            ):
                next_signature = pd.get_seqno()
        if first <= proposal.seqno and proposal.seqno <= last:
            LOG.info(
                f"Found ledger chunk {chunk.filename()} with chunking proposal @{proposal.seqno} and signature @{next_signature}"
            )
            assert last == next_signature
            assert next_signature - proposal.seqno < args.sig_tx_interval


def run_file_operations(args):
    with tempfile.TemporaryDirectory() as tmp_dir:
        txs = app.LoggingTxs("user0")
        with infra.network.network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            pdb=args.pdb,
            txs=txs,
        ) as network:

            args.common_read_only_ledger_dir = tmp_dir
            network.start_and_join(args)

            test_save_committed_ledger_files(network, args)
            test_parse_snapshot_file(network, args)
            test_forced_ledger_chunk(network, args)


def run_tls_san_checks(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        args.common_read_only_ledger_dir = None  # Reset from previous test
        network.start_and_join(args)

        LOG.info("Check SAN value in TLS certificate")
        dummy_san = "*.dummy.com"
        new_node = network.create_node(
            infra.interfaces.HostSpec(
                rpc_interfaces={
                    infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                        endorsement=infra.interfaces.Endorsement(authority="Node")
                    )
                }
            )
        )
        args.subject_alt_names = [f"dNSName:{dummy_san}"]
        network.join_node(new_node, args.package, args)
        sans = infra.crypto.get_san_from_pem_cert(new_node.get_tls_certificate_pem())
        assert len(sans) == 1, "Expected exactly one SAN"
        assert sans[0].value == dummy_san

        LOG.info("A node started with no specified SAN defaults to public RPC host")
        dummy_public_rpc_host = "123.123.123.123"
        args.subject_alt_names = []

        new_node = network.create_node(
            infra.interfaces.HostSpec(
                rpc_interfaces={
                    infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                        public_host=dummy_public_rpc_host,
                        endorsement=infra.interfaces.Endorsement(authority="Node"),
                    )
                }
            )
        )
        network.join_node(new_node, args.package, args)
        # Cannot trust the node here as client cannot authenticate dummy public IP in cert
        with open(
            os.path.join(network.common_dir, f"{new_node.local_node_id}.pem"),
            encoding="utf-8",
        ) as self_signed_cert:
            sans = infra.crypto.get_san_from_pem_cert(self_signed_cert.read())
        assert len(sans) == 1, "Expected exactly one SAN"
        assert sans[0].value == ipaddress.ip_address(dummy_public_rpc_host)


def run_configuration_file_checks(args):
    LOG.info(
        f"Verifying JSON configuration samples in {args.config_samples_dir} directory"
    )
    CCHOST_BINARY_NAME = "cchost"
    MIGRATE_CONFIGURATION_SCRIPT = "migrate_1_x_config.py"
    OUTPUT_2_X_CONFIGURATION_FILE = "2_x_config.json"

    bin_path = infra.path.build_bin_path(CCHOST_BINARY_NAME, binary_dir=args.binary_dir)

    # Assumes MIGRATE_CONFIGURATION_SCRIPT is in the path
    cmd = [
        MIGRATE_CONFIGURATION_SCRIPT,
        args.config_file_1x,
        OUTPUT_2_X_CONFIGURATION_FILE,
    ]
    assert infra.proc.ccall(*cmd).returncode == 0
    config_files_to_check = [OUTPUT_2_X_CONFIGURATION_FILE]
    config_files_to_check.extend(
        [
            os.path.join(args.config_samples_dir, c)
            for c in os.listdir(args.config_samples_dir)
        ]
    )

    for config in config_files_to_check:
        cmd = [bin_path, f"--config={config}", "--check"]
        rc = infra.proc.ccall(*cmd).returncode
        assert rc == 0, f"Failed to run tutorial script: {rc}"


def run(args):

    run_file_operations(args)
    run_tls_san_checks(args)
    run_configuration_file_checks(args)
