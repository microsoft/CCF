# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import os
import signal
import shutil

import infra.logging_app as app
import infra.e2e_args
import infra.network
import infra.platform_detection
import ccf.ledger
from ccf.tx_id import TxID
import base64
import suite.test_requirements as reqs
import infra.crypto
import ipaddress
import infra.interfaces
import infra.path
import infra.proc
import random
import json
import subprocess
import time
import http
import copy
import struct
import infra.snp as snp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import cbor2
import sys
import pathlib
import infra.concurrency
import ccf.read_ledger
import re

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
        for ledger_file_path in os.listdir(ledger_dir):
            if infra.node.is_file_committed(ledger_file_path):
                shutil.move(
                    os.path.join(ledger_dir, ledger_file_path),
                    os.path.join(args.common_read_only_ledger_dir, ledger_file_path),
                )

    network.txs.verify(network)
    return network


def test_parse_snapshot_file(network, args):
    class ReaderThread(infra.concurrency.StoppableThread):
        def __init__(self, network):
            super().__init__(name="reader")
            primary, _ = network.find_primary()
            self.snapshots_dir = os.path.join(
                primary.remote.remote.root,
                primary.remote.snapshots_dir_name,
            )

        def run(self):
            seen = set()
            while not self.is_stopped():
                for snapshot in os.listdir(self.snapshots_dir):
                    if (
                        ccf.ledger.is_snapshot_file_committed(snapshot)
                        and snapshot not in seen
                    ):
                        seen.add(snapshot)
                        with ccf.ledger.Snapshot(
                            os.path.join(self.snapshots_dir, snapshot)
                        ) as s:
                            assert len(
                                s.get_public_domain().get_tables()
                            ), "No public table in snapshot"
                            LOG.success(f"Successfully parsed snapshot: {snapshot}")
            LOG.info(f"Tested {len(seen)} snapshots")
            assert len(seen) > 0, "No snapshots seen, so this tested nothing"

    class WriterThread(infra.concurrency.StoppableThread):
        def __init__(self, network, reader):
            super().__init__(name="writer")
            self.primary, _ = network.find_primary()
            self.member = network.consortium.get_any_active_member()
            self.reader = reader

        def run(self):
            while not self.is_stopped() and self.reader.is_alive():
                self.member.update_ack_state_digest(self.primary)

    reader_thread = ReaderThread(network)
    reader_thread.start()

    writer_thread = WriterThread(network, reader_thread)
    writer_thread.start()

    # When this test was added, the original failure was occurring 100% of the time within 0.5s.
    # This fix has been manually verified across multi-minute runs.
    # 5s is a plausible run-time in the CI, that should still provide convincing coverage.
    time.sleep(5)

    writer_thread.stop()
    writer_thread.join()

    reader_thread.stop()
    reader_thread.join()

    return network


def find_ledger_chunk_for_seqno(ledger, seqno):
    for chunk in ledger:
        first, last = chunk.get_seqnos()
        next_signature = None
        for tx in chunk:
            pd = tx.get_public_domain()
            tables = pd.get_tables()
            if (
                pd.get_seqno() >= seqno
                and next_signature is None
                and ccf.ledger.SIGNATURE_TX_TABLE_NAME in tables
            ):
                next_signature = pd.get_seqno()
        if first <= seqno and seqno <= last:
            return chunk, first, last, next_signature
    return None, None, None, None


@reqs.description("Forced ledger chunk")
@app.scoped_txs()
def test_forced_ledger_chunk(network, args):
    primary, _ = network.find_primary()

    # Submit some dummy transactions
    network.txs.issue(network, number_txs=3)

    # Submit a proposal to force a ledger chunk at the following signature
    proposal = network.consortium.force_ledger_chunk(primary)

    # Issue some more transactions
    network.txs.issue(network, number_txs=5)

    ledger_dirs = primary.remote.ledger_paths()

    # Check that there is indeed a ledger chunk that ends at the
    # first signature after proposal.completed_seqno
    ledger = ccf.ledger.Ledger(ledger_dirs)
    chunk, _, last, next_signature = find_ledger_chunk_for_seqno(
        ledger, proposal.completed_seqno
    )
    LOG.info(
        f"Found ledger chunk {chunk.filename()} with chunking proposal @{proposal.completed_seqno} and signature @{next_signature}"
    )
    assert chunk.is_complete and chunk.is_committed()
    assert last == next_signature
    assert next_signature - proposal.completed_seqno < args.sig_tx_interval
    return network


@reqs.description("Forced snapshot")
@app.scoped_txs()
def test_forced_snapshot(network, args):
    inner_args = copy.deepcopy(args)
    inner_args.common_read_only_ledger_dir = (
        None  # Side-effect setting which would break the starting node
    )
    inner_args.label = f"{inner_args.label}_forced_snapshot"
    inner_args.snapshot_tx_interval = (
        10000  # Large interval to avoid interference from regular snapshots
    )

    # Use a separate network to ensure unforced snapshots do not happen
    with infra.network.network(
        inner_args.nodes,
        inner_args.binary_dir,
        inner_args.debug_nodes,
        pdb=inner_args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as inner_network:
        inner_network.start_and_open(inner_args)

        primary, _ = inner_network.find_primary()

        # Submit some dummy transactions
        inner_network.txs.issue(inner_network, number_txs=3)

        with primary.client() as c:
            r = c.get("/node/commit").body.json()
            hwm_pre_proposal = TxID.from_str(r["transaction_id"]).seqno

        # Ensure there is at least one signature greater than the hwm
        inner_network.txs.issue(inner_network, number_txs=1, wait_for_sync=True)

        # Submit a proposal to force a snapshot
        proposal_body, careful_vote = inner_network.consortium.make_proposal(
            "trigger_snapshot"
        )
        proposal = inner_network.consortium.get_any_active_member().propose(
            primary, proposal_body
        )
        proposal = inner_network.consortium.vote_using_majority(
            primary,
            proposal,
            careful_vote,
        )

        # Issue some more transactions
        inner_network.txs.issue(inner_network, number_txs=5)

        snapshots_dir = inner_network.get_committed_snapshots(
            primary, target_seqno=hwm_pre_proposal + 1
        )

        for s in os.listdir(snapshots_dir):
            with ccf.ledger.Snapshot(os.path.join(snapshots_dir, s)) as snapshot:
                snapshot_seqno = snapshot.get_public_domain().get_seqno()
                if snapshot_seqno > hwm_pre_proposal:
                    LOG.info(
                        f"Found a snapshot at {snapshot_seqno} which is after the pre-proposal-high-water-mark {hwm_pre_proposal}"
                    )
                    return network

        raise RuntimeError("Could not find matching snapshot file")

    return network


# https://github.com/microsoft/CCF/issues/1858
@reqs.description("Generate snapshot larger than ring buffer max message size")
def test_large_snapshot(network, args):
    primary, _ = network.find_primary()

    # Submit some dummy transactions
    entry_size = 10000  # Lower bound on serialised write set size
    iterations = int(args.max_msg_size_bytes) // entry_size
    LOG.debug(f"Recording {iterations} large entries")
    with primary.client(identity="user0") as c:
        for idx in range(iterations):
            c.post(
                "/app/log/public?scope=test_large_snapshot",
                body={"id": idx, "msg": "X" * entry_size},
                log_capture=[],
            )

    # Submit a proposal to force a snapshot at the following signature
    proposal_body, careful_vote = network.consortium.make_proposal("trigger_snapshot")
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    proposal = network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )

    # Check that there is at least a snapshot larger than args.max_msg_size_bytes
    snapshots_dir = network.get_committed_snapshots(primary)
    extra_data_size_bytes = 10000  # Upper bound on additional snapshot data (e.g. receipt) that is passed separately from the snapshot
    for s in os.listdir(snapshots_dir):
        snapshot_size = os.stat(os.path.join(snapshots_dir, s)).st_size
        if snapshot_size > int(args.max_msg_size_bytes) + extra_data_size_bytes:
            # Make sure that large snapshot can be parsed
            snapshot = ccf.ledger.Snapshot(os.path.join(snapshots_dir, s))
            assert snapshot.get_len() == snapshot_size
            LOG.info(
                f"Found snapshot [{snapshot_size}] larger than ring buffer max msg size {args.max_msg_size_bytes}"
            )
            return network

    raise RuntimeError(
        f"Could not find any snapshot file larger than {args.max_msg_size_bytes}"
    )


def test_snapshot_access(network, args):
    primary, backups = network.find_nodes()

    snapshots_dir = network.get_committed_snapshots(primary)
    snapshot_name = ccf.ledger.latest_snapshot(snapshots_dir)
    snapshot_index, _ = ccf.ledger.snapshot_index_from_filename(snapshot_name)

    with open(os.path.join(snapshots_dir, snapshot_name), "rb") as f:
        snapshot_data = f.read()

    for node in (primary, *backups):
        with node.client(interface_name=infra.interfaces.PRIMARY_RPC_INTERFACE) as c:
            r = c.head("/node/snapshot")
            assert r.status_code == http.HTTPStatus.NOT_FOUND, r
            r = c.get("/node/snapshot")
            assert r.status_code == http.HTTPStatus.NOT_FOUND, r

    interface = primary.host.rpc_interfaces[infra.interfaces.FILE_SERVING_RPC_INTERFACE]
    loc = f"https://{interface.public_host}:{interface.public_port}"

    with primary.client(
        interface_name=infra.interfaces.FILE_SERVING_RPC_INTERFACE
    ) as file_client:
        with primary.client(
            interface_name=infra.interfaces.PRIMARY_RPC_INTERFACE
        ) as disabled_client:

            def do_request(http_verb, *args, **kwargs):
                r = disabled_client.call(*args, http_verb=http_verb, **kwargs)
                assert (
                    r.status_code == http.HTTPStatus.NOT_FOUND
                ), f"Expected inaccessible due to disabled opt-in feature. Found:\n{r}"
                return file_client.call(*args, http_verb=http_verb, **kwargs)

            r = do_request("HEAD", "/node/snapshot", allow_redirects=False)
            assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value, r
            assert "location" in r.headers, r.headers
            location = r.headers["location"]
            path = f"/node/snapshot/{snapshot_name}"
            assert location == f"{loc}{path}"
            LOG.warning(r.headers)

            for since, expected in (
                (0, location),
                (1, location),
                (snapshot_index // 2, location),
                (snapshot_index - 1, location),
                (snapshot_index, None),
                (snapshot_index + 1, None),
            ):
                for method in ("GET", "HEAD"):
                    r = do_request(
                        method,
                        f"/node/snapshot?since={since}",
                        allow_redirects=False,
                    )
                    if expected is None:
                        assert r.status_code == http.HTTPStatus.NOT_FOUND, r
                    else:
                        assert (
                            r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                        ), r
                        assert "location" in r.headers, r.headers
                        actual = r.headers["location"]
                        assert actual == expected

            r = do_request("HEAD", path)
            assert r.status_code == http.HTTPStatus.OK.value, r
            assert r.headers["accept-ranges"] == "bytes", r.headers
            total_size = int(r.headers["content-length"])

            a = total_size // 3
            b = a * 2
            for start, end in [
                (0, None),
                (0, total_size),
                (0, a),
                (a, a),
                (a, b),
                (b, b),
                (b, total_size),
                (b, None),
            ]:
                range_header_value = f"{start}-{'' if end is None else end}"
                r = do_request(
                    "GET", path, headers={"range": f"bytes={range_header_value}"}
                )
                assert r.status_code == http.HTTPStatus.PARTIAL_CONTENT.value, r

                expected = snapshot_data[start:end]
                actual = r.body.data()
                assert (
                    expected == actual
                ), f"Binary mismatch, {len(expected)} vs {len(actual)}:\n{expected}\nvs\n{actual}"

            for negative_offset in [
                1,
                a,
                b,
            ]:
                range_header_value = f"-{negative_offset}"
                r = do_request(
                    "GET", path, headers={"range": f"bytes={range_header_value}"}
                )
                assert r.status_code == http.HTTPStatus.PARTIAL_CONTENT.value, r

                expected = snapshot_data[-negative_offset:]
                actual = r.body.data()
                assert (
                    expected == actual
                ), f"Binary mismatch, {len(expected)} vs {len(actual)}:\n{expected}\nvs\n{actual}"

            # Check error handling for invalid ranges
            for invalid_range, err_msg in [
                (f"{a}-foo", "Unable to parse end of range value foo"),
                ("foo-foo", "Unable to parse start of range value foo"),
                (f"foo-{b}", "Unable to parse start of range value foo"),
                (f"{b}-{a}", "out of order"),
                ("-1-5", "Invalid format"),
                ("-", "Invalid range"),
                ("-foo", "Unable to parse end of range offset value foo"),
                ("", "Invalid format"),
            ]:
                r = do_request("GET", path, headers={"range": f"bytes={invalid_range}"})
                assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r
                assert err_msg in r.body.json()["error"]["message"], r


def test_snapshot_selection(network, args):
    inner_args = copy.deepcopy(args)
    inner_args.common_read_only_ledger_dir = (
        None  # Side-effect setting which would break the starting node
    )
    inner_args.label = f"{inner_args.label}_snapshot_selection"
    inner_args.snapshot_tx_interval = (
        10000  # Large interval to avoid interference from regular snapshots
    )

    # Use a separate network to ensure unforced snapshots do not happen
    with infra.network.network(
        inner_args.nodes,
        inner_args.binary_dir,
        inner_args.debug_nodes,
        pdb=inner_args.pdb,
    ) as inner_network:
        inner_network.start_and_open(inner_args)
        _test_snapshot_selection(inner_network, inner_args)


def _test_snapshot_selection(network, args):
    # Add nodes so we have at least 3
    while len(network.get_joined_nodes()) < 3:
        new_node = network.create_node()
        network.join_node(
            new_node,
            args.package,
            args,
            from_snapshot=False,
        )
        network.trust_node(new_node, args)

    def trigger_snapshot(node):
        LOG.info(f"Triggering snapshot on {node.local_node_id}")
        proposal_body, careful_vote = network.consortium.make_proposal(
            "trigger_snapshot"
        )
        proposal = network.consortium.get_any_active_member().propose(
            node, proposal_body
        )
        network.consortium.vote_using_majority(
            node,
            proposal,
            careful_vote,
        )

    LOG.info("Creating snapshots")
    primary, backups = network.find_nodes()
    for i in range(3):
        trigger_snapshot(primary)
        # Snapshot creation and commit takes time. All of the helpers we have to track/poll this
        # are expensive, so try a short sleep
        time.sleep(1)

    snapshots_dir = network.get_committed_snapshots(
        primary,
        force_txs=False,
    )

    src_snapshots = []
    for snapshot_name in os.listdir(snapshots_dir):
        if ccf.ledger.is_snapshot_file_committed(snapshot_name):
            seqno, _ = ccf.ledger.snapshot_index_from_filename(snapshot_name)
            src_snapshots.append(
                (seqno, snapshot_name, os.path.join(snapshots_dir, snapshot_name))
            )

    src_snapshots.sort()
    best_snapshot = src_snapshots[-1][1]

    node_to_snapshot = {}
    node_to_snapshot[primary] = best_snapshot

    LOG.info("Copying new snapshots to backup directories")
    for i, backup in enumerate(backups):
        # Re-create empty directory
        snapshot_dir = os.path.join(
            backup.remote.remote.root, backup.remote.snapshots_dir_name
        )
        shutil.rmtree(snapshot_dir)
        pathlib.Path(snapshot_dir).mkdir(parents=True, exist_ok=True)

        # Copy single snapshot into dir
        candidate = src_snapshots[-1 - i]
        _, snapshot_name, src_path = candidate
        shutil.copy(src_path, snapshot_dir)
        node_to_snapshot[backup] = snapshot_name

    LOG.success(node_to_snapshot)

    def find_snapshot(node):
        with node.client(
            interface_name=infra.interfaces.FILE_SERVING_RPC_INTERFACE
        ) as c:
            r = c.head("/node/snapshot", allow_redirects=True)
            assert r.status_code == 200, r
            snapshot_name = r.headers["x-ms-ccf-snapshot-name"]
            assert ccf.ledger.is_snapshot_file_committed(snapshot_name)
            return snapshot_name

    # Each node redirects to the best snapshot, while the primary holding it is still live and primary
    for node in node_to_snapshot.keys():
        actual_snapshot_name = find_snapshot(node)
        assert actual_snapshot_name == best_snapshot

    # Once an election happens, the new primary's snapshot is returned, which may no longer be the best
    suspended = set()
    while True:
        primary.suspend()
        suspended.add(primary)

        try:
            new_primary, _ = network.wait_for_new_primary(
                old_primary=primary, timeout_multiplier=3
            )
            new_primarys_snapshot = find_snapshot(new_primary)
        except infra.network.PrimaryNotFound:
            # We've suspended so many nodes that elections fail. Now each node
            # falls back to returning only its _own_ best snapshot
            new_primary = None
            new_primarys_snapshot = None

        for node, nodes_best_snapshot in node_to_snapshot.items():
            if node in suspended:
                continue

            snapshot_name = find_snapshot(node)
            if new_primarys_snapshot is None:
                assert snapshot_name == nodes_best_snapshot
            else:
                assert snapshot_name == new_primarys_snapshot

        if new_primary is None:
            break
        else:
            primary = new_primary

    for node in suspended:
        node.resume()


def test_empty_snapshot(network, args):

    LOG.info("Check that empty snapshot is ignored")

    with tempfile.TemporaryDirectory() as snapshots_dir:
        LOG.debug(f"Using {snapshots_dir} as snapshots directory")

        snapshot_name = "snapshot_1000_1500.committed"

        with open(
            os.path.join(snapshots_dir, snapshot_name), "wb+"
        ) as temp_empty_snapshot:

            LOG.debug(f"Created empty snapshot {temp_empty_snapshot.name}")

            # Check the file is indeed empty
            assert (
                os.stat(temp_empty_snapshot.name).st_size == 0
            ), temp_empty_snapshot.name

            # Create new node and join network
            new_node = network.create_node()
            network.join_node(
                new_node,
                args.package,
                args,
                snapshots_dir=snapshots_dir,
                # Don't try to fetch a snapshot, look at the local files
                fetch_recent_snapshot=False,
            )
            new_node.stop()

            # Check that the empty snapshot is correctly skipped
            if not new_node.check_log_for_error_message(
                f"Ignoring empty snapshot file {snapshot_name}"
            ):
                raise AssertionError(
                    f"Expected empty snapshot file {snapshot_name} to be skipped in node logs"
                )


def test_nulled_snapshot(network, args):

    with tempfile.TemporaryDirectory() as snapshots_dir:
        LOG.debug(f"Using {snapshots_dir} as snapshots directory")

        snapshot_name = "snapshot_1000_1500.committed"

        with open(
            os.path.join(snapshots_dir, snapshot_name), "wb+"
        ) as temp_empty_snapshot:

            LOG.debug(f"Created empty snapshot {temp_empty_snapshot.name}")
            temp_empty_snapshot.write(b"\x00" * 64)

        LOG.info(
            "Attempt to join a node using the corrupted snapshot copy (should fail)"
        )
        new_node = network.create_node()
        failed = False
        try:
            network.join_node(
                new_node,
                args.package,
                args,
                snapshots_dir=snapshots_dir,
                # Don't try to fetch a snapshot, look at the local files
                fetch_recent_snapshot=False,
            )
        except Exception as e:
            failed = True
            LOG.info(f"Node failed to join as expected: {e}")

        # (Existing assertion logic retained)
        assert failed, "Node should not have joined successfully"


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
        ledger_chunk = ccf.ledger.LedgerChunk(
            ledger_file_path,
        )
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


@reqs.description("Split ledger")
def test_split_ledger_on_stopped_network(primary, args):
    # Test that ledger files can be arbitrarily split.
    # Note: For real operations, it would be best practice to use a separate
    # output directory

    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    split_all_ledger_files_in_dir(current_ledger_dir, current_ledger_dir)
    if committed_ledger_dirs:
        split_all_ledger_files_in_dir(
            committed_ledger_dirs[0], committed_ledger_dirs[0]
        )

    # Check that the split ledger can be read successfully
    ccf.ledger.Ledger(
        [current_ledger_dir] + committed_ledger_dirs, committed_only=False
    )


def run_file_operations(args):
    with tempfile.NamedTemporaryFile(mode="w+") as ntf:
        service_data = {"the owls": "are not", "what": "they seem"}
        json.dump(service_data, ntf)
        ntf.flush()

        args.max_msg_size_bytes = f"{1024 ** 2}"

        with tempfile.TemporaryDirectory() as tmp_dir:
            txs = app.LoggingTxs("user0")
            with infra.network.network(
                args.nodes,
                args.binary_dir,
                args.debug_nodes,
                pdb=args.pdb,
                txs=txs,
            ) as network:
                args.common_read_only_ledger_dir = tmp_dir
                network.start_and_open(args, service_data_json_file=ntf.name)

                LOG.info("Check that service data has been set")
                primary, _ = network.find_primary()
                with primary.client() as c:
                    r = c.get("/node/network").body.json()
                    assert r["service_data"] == service_data

                test_save_committed_ledger_files(network, args)
                test_parse_snapshot_file(network, args)
                test_forced_ledger_chunk(network, args)
                test_forced_snapshot(network, args)
                test_large_snapshot(network, args)
                test_snapshot_access(network, args)
                test_snapshot_selection(network, args)
                test_empty_snapshot(network, args)
                test_nulled_snapshot(network, args)

                primary, _ = network.find_primary()
                # Scoped transactions are not handled by historical range queries
                network.stop_all_nodes(skip_verification=True)

                test_split_ledger_on_stopped_network(primary, args)
                args.common_read_only_ledger_dir = None  # Reset for future tests


def run_tls_san_checks(const_args):
    args = copy.deepcopy(const_args)
    args.label += "_tls_san"
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        network.verify_service_certificate_validity_period(
            args.initial_service_cert_validity_days
        )

        LOG.info("Check SAN value in TLS certificate")
        dummy_san = "*.dummy.com"
        host_spec = infra.interfaces.HostSpec()
        host_spec.get_primary_interface().endorsement.authority = (
            infra.interfaces.EndorsementAuthority.Node
        )
        new_node = network.create_node(host_spec)
        args.subject_alt_names = [f"dNSName:{dummy_san}"]
        network.join_node(new_node, args.package, args)
        sans = infra.crypto.get_san_from_pem_cert(new_node.get_tls_certificate_pem())
        assert len(sans) == 1, "Expected exactly one SAN"
        assert sans[0].value == dummy_san

        LOG.info("A node started with no specified SAN defaults to public RPC host(s)")
        dummy_public_rpc_hosts = set()
        args.subject_alt_names = []

        for i, interface in enumerate(host_spec.rpc_interfaces.values()):
            dummy_public_rpc_host = f"123.123.123.{i}"
            interface.public_host = dummy_public_rpc_host
            dummy_public_rpc_hosts.add(ipaddress.ip_address(dummy_public_rpc_host))

        new_node = network.create_node(host_spec)
        network.join_node(new_node, args.package, args)
        # Cannot trust the node here as client cannot authenticate dummy public IP in cert
        with open(
            os.path.join(network.common_dir, f"{new_node.local_node_id}.pem"),
            encoding="utf-8",
        ) as self_signed_cert:
            sans = infra.crypto.get_san_from_pem_cert(self_signed_cert.read())
        assert len(sans) == len(
            dummy_public_rpc_hosts
        ), f"Expected {len(dummy_public_rpc_hosts)} SANs ({dummy_public_rpc_hosts}), found {len(sans)} ({sans})"
        ip_sans = set(sans.get_values_for_type(x509.IPAddress))
        assert (
            ip_sans == dummy_public_rpc_hosts
        ), f"Expected SANs do not match: {ip_sans} vs {dummy_public_rpc_hosts}"


def run_config_timeout_check(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.nodes(args, 1)
    args.label += "_config_timeout"
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
    # This is relatively direct test to make sure the config timeout feature
    # works as intended. It is difficult to do with the existing framework
    # as is because of the indirections and the fact that start() is a
    # synchronous call.
    node = network.nodes[0]
    start_node_path = node.remote.remote.root
    # Remove ledger and pid file to allow a restart
    shutil.rmtree(os.path.join(start_node_path, "0.ledger"))
    os.remove(os.path.join(start_node_path, "node.pid"))
    os.remove(os.path.join(start_node_path, "service_cert.pem"))
    # Move configuration
    shutil.move(
        os.path.join(start_node_path, "0.config.json"),
        os.path.join(start_node_path, "0.config.json.bak"),
    )
    LOG.info("No config at all")
    assert not os.path.exists(os.path.join(start_node_path, "0.config.json"))
    LOG.info(f"Attempt to start node without a config under {start_node_path}")
    config_timeout = 10
    env = {}

    if infra.platform_detection.is_snp():
        env.update(snp.get_aci_env())

    proc = subprocess.Popen(
        [
            os.path.join(".", os.path.basename(node.remote.BIN)),
            "--config",
            "0.config.json",
            "--config-timeout",
            f"{config_timeout}s",
        ],
        cwd=start_node_path,
        env=env,
        stdout=open(os.path.join(start_node_path, "out"), "wb"),
        stderr=open(os.path.join(start_node_path, "err"), "wb"),
    )
    time.sleep(2)
    LOG.info("Copy a partial config")
    # Replace it with a prefix
    with open(os.path.join(start_node_path, "0.config.json"), "w") as f:
        f.write("{")
    time.sleep(2)
    LOG.info("Move a full config back")
    shutil.copy(
        os.path.join(start_node_path, "0.config.json.bak"),
        os.path.join(start_node_path, "0.config.json"),
    )
    LOG.info(f"Wait out the rest of the {config_timeout}s timeout")
    time.sleep(config_timeout)
    LOG.info("Check node")
    assert proc.poll() is None, "Node process should still be running"
    assert os.path.exists(os.path.join(start_node_path, "service_cert.pem"))
    proc.terminate()
    proc.wait()


def run_sighup_check(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.nodes(args, 1)
    args.label += "_sighup_check"
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        network.nodes[0].remote.remote.hangup()
        time.sleep(5)
        assert network.nodes[0].remote.check_done(), "Node should have exited"
        out, _ = network.nodes[0].remote.get_logs()
        with open(out, "r") as outf:
            lines = outf.readlines()
        assert any("SIGHUP: " in line for line in lines), "Hangup should be logged"


def run_configuration_file_checks(args):
    LOG.info(
        f"Verifying JSON configuration samples in {args.config_samples_dir} directory"
    )
    bin_path = args.package

    config_files_to_check = [
        os.path.join(args.config_samples_dir, c)
        for c in os.listdir(args.config_samples_dir)
    ]

    for config in config_files_to_check:
        cmd = [bin_path, f"--config={config}", "--check"]
        rc = infra.proc.ccall(
            *cmd,
        ).returncode
        assert rc == 0, f"Failed to check configuration: {rc}"
        LOG.success(f"Successfully check sample configuration file {config}")


def run_preopen_readiness_check(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start(args)
        primary, _ = network.find_primary()
        with primary.client() as c:
            r = c.get("/node/ready/gov")
            assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r
            r = c.get("/node/ready/app")
            assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE.value, r
        network.open(args)
        with primary.client() as c:
            r = c.get("/node/ready/gov")
            assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r
            r = c.get("/node/ready/app")
            assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r


def run_pid_file_check(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        LOG.info("Check that pid file exists")
        node = network.nodes[0]
        node.stop()
        # Delete ledger directory, since that too would prevent a restart
        shutil.rmtree(
            os.path.join(node.remote.remote.root, node.remote.ledger_dir_name)
        )
        node.remote.start()
        timeout = 10
        start = time.time()
        LOG.info("Wait for node to shut down")
        while time.time() - start < timeout:
            if node.remote.check_done():
                break
            time.sleep(0.1)
        out, _ = node.remote.get_logs()
        with open(out, "r") as outf:
            last_line = outf.readlines()[-1].strip()
        assert last_line.endswith(
            "PID file node.pid already exists. Exiting."
        ), last_line
        LOG.info("Node shut down for the right reason")
        network.ignoring_shutdown_errors = True


def run_max_uncommitted_tx_count(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.nodes(args, 2)
    args.label += "_max_uncommitted_tx"
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        uncommitted_cap = 20
        network.per_node_args_override[0] = {
            "max_uncommitted_tx_count": uncommitted_cap
        }
        network.start_and_open(args)
        LOG.info(
            f"Start network with max_uncommitted_tx_count set to {uncommitted_cap}"
        )
        # Stop the backup node, to freeze commit
        primary, backups = network.find_nodes()
        backups[0].stop()
        unavailable_count = 0
        last_accepted_index = 0

        with primary.client(identity="user0") as c:
            for idx in range(uncommitted_cap + 1):
                r = c.post(
                    "/app/log/public?scope=test_large_snapshot",
                    body={"id": idx, "msg": "X" * 42},
                    log_capture=[],
                )
                if r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE:
                    unavailable_count += 1
                    if last_accepted_index == 0:
                        last_accepted_index = idx - 1
        LOG.info(f"Last accepted: {last_accepted_index}, {unavailable_count} 503s")
        assert unavailable_count > 0, "Expected at least one SERVICE_UNAVAILABLE"

        with primary.client() as c:
            r = c.get("/node/network")
            assert r.status_code == http.HTTPStatus.OK.value, r


def run_service_subject_name_check(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args, service_subject_name="CN=This test service")
        # Check service_cert.pem
        with open(network.cert_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
            assert cert.subject.rfc4514_string() == "CN=This test service", cert
        # Check /node/service endpoint
        primary, _ = network.find_primary()
        with primary.client() as c:
            r = c.get("/node/network")
            assert r.status_code == http.HTTPStatus.OK.value, r
            cert_pem = r.body.json()["service_certificate"]
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            assert cert.subject.rfc4514_string() == "CN=This test service", cert


def run_cose_signatures_config_check(args):
    nargs = copy.deepcopy(args)
    nargs.nodes = infra.e2e_args.max_nodes(nargs, f=0)

    with infra.network.network(
        nargs.nodes,
        nargs.binary_dir,
        nargs.debug_nodes,
        pdb=nargs.pdb,
    ) as network:
        network.start_and_open(
            nargs,
            cose_signatures_issuer="test.issuer.example.com",
            cose_signatures_subject="test.subject",
        )

        for node in network.get_joined_nodes():
            with node.client("user0") as client:
                r = client.get("/commit")
                assert r.status_code == http.HTTPStatus.OK
                txid = TxID.from_str(r.body.json()["transaction_id"])
                max_retries = 10
                for _ in range(max_retries):
                    response = client.get(
                        "/log/public/cose_signature",
                        headers={
                            infra.clients.CCF_TX_ID_HEADER: f"{txid.view}.{txid.seqno}"
                        },
                    )

                    if response.status_code == http.HTTPStatus.OK:
                        signature = response.body.json()["cose_signature"]
                        signature = base64.b64decode(signature)
                        signature_filename = os.path.join(
                            network.common_dir, f"cose_signature_{txid}.cose"
                        )
                        with open(signature_filename, "wb") as f:
                            f.write(signature)
                        sig = cbor2.loads(signature)
                        assert sig.tag == 18
                        phdr = cbor2.loads(sig.value[0])
                        assert 15 in phdr, "CWT_Claims"
                        assert phdr[15][1] == "test.issuer.example.com"
                        assert phdr[15][2] == "test.subject"
                        assert sig.value[2] is None, "Detached payload"
                        LOG.debug(
                            "Well-formed COSE signature schema for issuer and subject"
                        )
                        break
                    elif response.status_code == http.HTTPStatus.ACCEPTED:
                        LOG.debug(f"Transaction {txid} accepted, retrying")
                        time.sleep(0.1)
                    else:
                        LOG.error(f"Failed to get COSE signature for txid {txid}")
                        break
                else:
                    assert (
                        False
                    ), f"Failed to get receipt for txid {txid} after {max_retries} retries"


def run_late_mounted_ledger_check(args):
    nargs = copy.deepcopy(args)
    nargs.nodes = infra.e2e_args.min_nodes(nargs, f=0)

    with infra.network.network(
        nargs.nodes,
        nargs.binary_dir,
        nargs.debug_nodes,
        pdb=nargs.pdb,
    ) as network:
        network.start_and_open(
            nargs,
        )

        primary, _ = network.find_primary()

        msg_id = 42
        msg = str(random.random())

        # Write a new entry
        with primary.client("user0") as c:
            r = c.post(
                "/app/log/private",
                body={"id": msg_id, "msg": msg},
            )
            assert r.status_code == http.HTTPStatus.OK.value, r
            c.wait_for_commit(r)

            msg_seqno = r.seqno
            msg_tx_id = f"{r.view}.{r.seqno}"

        def try_historical_fetch(node, timeout=1):
            with node.client("user0") as c:
                start_time = time.time()
                while time.time() < (start_time + timeout):
                    r = c.get(
                        f"/app/log/private/historical?id={msg_id}",
                        headers={infra.clients.CCF_TX_ID_HEADER: msg_tx_id},
                    )
                    if r.status_code == http.HTTPStatus.OK:
                        assert r.body.json()["msg"] == msg
                        return True
                    assert r.status_code == http.HTTPStatus.ACCEPTED
                    time.sleep(0.2)
            return False

        # Confirm this can be retrieved with a historical query
        assert try_historical_fetch(primary)

        expected_errors = []

        # Create a temporary directory to manually construct a ledger in
        with tempfile.TemporaryDirectory() as temp_dir:
            new_node = network.create_node()
            network.join_node(
                new_node,
                nargs.package,
                nargs,
                from_snapshot=True,
                copy_ledger=False,
                common_read_only_ledger_dir=temp_dir,  # New node will try to read from temp directory
            )
            network.trust_node(new_node, args)

            # Due to copy_ledger=False, this new node cannot access this historical entry
            assert not try_historical_fetch(new_node)
            expected_errors.append(f"Cannot find ledger file for seqno {msg_seqno}")

            # Gather the source files that the operator should backfill
            src_ledger_dir = primary.remote.ledger_paths()[0]
            dst_files = {
                os.path.join(temp_dir, filename): os.path.join(src_ledger_dir, filename)
                for filename in os.listdir(src_ledger_dir)
            }

            # Create empy files in the new node's directory, with the correct names
            for dst_path in dst_files.keys():
                with open(dst_path, "wb") as f:
                    pass

            # Historical query still fails, but node survives
            assert not try_historical_fetch(new_node)
            expected_errors.append("Failed to read positions offset from ledger file")

            # Create files of the correct size, but filled with zeros
            for dst_path, src_path in dst_files.items():
                with open(dst_path, "wb") as f:
                    f.write(bytes(os.path.getsize(src_path)))

            # Historical query still fails, but node survives
            assert not try_historical_fetch(new_node)
            expected_errors.append("cannot be read: invalid table offset (0)")

            # Write an invalid table offset at the start of each file
            for dst_path, src_path in dst_files.items():
                with open(dst_path, "r+b") as f:
                    f.seek(0)
                    size = os.path.getsize(src_path)
                    f.write(struct.pack("<Q", size + 1))

            # Historical query still fails, but node survives
            assert not try_historical_fetch(new_node)
            expected_errors.append("greater than total file size")

            # Copy correct files
            for dst_path, src_path in dst_files.items():
                with open(dst_path, "wb") as f:
                    f.write(open(src_path, "rb").read())

            # Historical query now passes
            assert try_historical_fetch(new_node)

            # Remove node
            network.retire_node(primary, new_node)
            new_node.stop()

            # Check node output for expected errors
            out_path, _ = new_node.get_logs()
            for line in open(out_path, "r", encoding="utf-8").readlines():
                expected_errors = [
                    error for error in expected_errors if error not in line
                ]
                if len(expected_errors) == 0:
                    break
            else:
                LOG.error("Expected to find following error messages in node output:")
                for error in expected_errors:
                    LOG.error(f"  {error}")
                raise AssertionError(expected_errors)


def run_empty_ledger_dir_check(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        LOG.info("Check that empty ledger directory is handled correctly")
        with tempfile.TemporaryDirectory() as tmp_dir:
            LOG.debug(f"Using {tmp_dir} as ledger directory")

            dir_name = os.path.basename(tmp_dir)

            # Check tmp_dir is indeed empty
            assert len(os.listdir(tmp_dir)) == 0, tmp_dir

            # Start network, this should not fail
            network.start_and_open(args, ledger_dir=tmp_dir)
            primary, _ = network.find_primary()
            network.stop_all_nodes()

            # Now write a file in the directory
            with open(os.path.join(tmp_dir, "ledger_1000_1500.committed"), "wb") as f:
                f.write(b"bar")

            # Start new network, this should fail
            try:
                network.start(args, ledger_dir=tmp_dir)
            except Exception:
                pass

            # Check that the node has failed with the expected error message
            if not primary.check_log_for_error_message(
                f"On start, ledger directory should not exist or be empty ({dir_name})"
            ):
                raise AssertionError(
                    f"Expected node error message with non-empty ledger directory {dir_name}"
                )


def run_initial_uvm_descriptor_checks(const_args):
    args = copy.deepcopy(const_args)
    args.label += "_uvm_descriptor"
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        LOG.info("Start a network and stop it")
        network.start_and_open(args)
        primary, _ = network.find_primary()
        old_common = infra.network.get_common_folder_name(args.workspace, args.label)
        snapshots_dir = network.get_committed_snapshots(primary)
        network.stop_all_nodes()
        LOG.info("Check that the a UVM descriptor is present")

        ledger_dirs = primary.remote.ledger_paths()
        ledger = ccf.ledger.Ledger(ledger_dirs)
        first_chunk = next(iter(ledger))
        first_tx = next(iter(first_chunk))
        tables = first_tx.get_public_domain().get_tables()
        endorsements = tables["public:ccf.gov.nodes.snp.uvm_endorsements"]
        assert len(endorsements) == 1, endorsements
        (key,) = endorsements.keys()
        assert key.startswith(b"did:x509:"), key
        LOG.info(f"Initial UVM endorsement found in ledger: {endorsements[key]}")

        LOG.info("Start a recovery network and stop it")
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
        recovered_network_args = copy.deepcopy(args)
        recovered_network_args.label += "_recovery"

        with infra.network.network(
            recovered_network_args.nodes,
            recovered_network_args.binary_dir,
            recovered_network_args.debug_nodes,
            existing_network=network,
        ) as recovered_network:

            recovered_network_args.previous_service_identity_file = os.path.join(
                old_common, "service_cert.pem"
            )
            recovered_network.start_in_recovery(
                recovered_network_args,
                common_dir=old_common,
                ledger_dir=current_ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=snapshots_dir,
            )
            recovered_primary, _ = recovered_network.find_primary()
            LOG.info("Check that the UVM descriptor is present in the recovery tx")
            recovery_seqno = None
            with recovered_primary.client() as c:
                r = c.get("/node/network").body.json()
                recovery_seqno = int(r["current_service_create_txid"].split(".")[1])
            network.stop_all_nodes()
            ledger = ccf.ledger.Ledger(
                recovered_primary.remote.ledger_paths(),
                committed_only=False,
                read_recovery_files=True,
            )
            for chunk in ledger:
                _, chunk_end_seqno = chunk.get_seqnos()
                if chunk_end_seqno < recovery_seqno:
                    continue
                for tx in chunk:
                    tables = tx.get_public_domain().get_tables()
                    seqno = tx.get_public_domain().get_seqno()
                    if seqno < recovery_seqno:
                        continue
                    else:
                        tables = tx.get_public_domain().get_tables()
                        endorsements = tables[
                            "public:ccf.gov.nodes.snp.uvm_endorsements"
                        ]
                        assert len(endorsements) == 1, endorsements
                        (key,) = endorsements.keys()
                        assert key.startswith(b"did:x509:"), key
                        LOG.info(
                            f"Recovery UVM endorsement found in ledger: {endorsements[key]}"
                        )
                        return
            assert False, "No UVM endorsement found in recovery ledger"


def run_initial_tcb_version_checks(const_args):
    args = copy.deepcopy(const_args)
    args.label += "_tcb_version"
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        LOG.info("Start a network and stop it")
        network.start_and_open(args)
        primary, _ = network.find_primary()
        old_common = infra.network.get_common_folder_name(args.workspace, args.label)
        snapshots_dir = network.get_committed_snapshots(primary)
        network.stop_all_nodes()

        LOG.info("Check that the a SNP tcb_version is present")
        ledger_dirs = primary.remote.ledger_paths()
        ledger = ccf.ledger.Ledger(ledger_dirs)
        first_chunk = next(iter(ledger))
        first_tx = next(iter(first_chunk))
        tables = first_tx.get_public_domain().get_tables()
        tcb_versions = tables["public:ccf.gov.nodes.snp.tcb_versions"]
        assert len(tcb_versions) == 1, tcb_versions
        LOG.info(f"Initial TCB_version found in ledger: {tcb_versions}")

        LOG.info("Start a recovery network and stop it")
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

        recovered_network_args = copy.deepcopy(args)
        recovered_network_args.previous_service_identity_file = os.path.join(
            old_common, "service_cert.pem"
        )
        recovered_network_args.label += "_recovery"
        with infra.network.network(
            recovered_network_args.nodes,
            recovered_network_args.binary_dir,
            recovered_network_args.debug_nodes,
            existing_network=network,
        ) as recovered_network:
            recovered_network.start_in_recovery(
                recovered_network_args,
                common_dir=old_common,
                ledger_dir=current_ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=snapshots_dir,
            )
            recovered_primary, _ = recovered_network.find_primary()
            LOG.info("Check that the TCB_version is present in the recovery tx")
            recovery_seqno = None
            with recovered_primary.client() as c:
                r = c.get("/node/network").body.json()
                recovery_seqno = int(r["current_service_create_txid"].split(".")[1])
            network.stop_all_nodes()
            ledger = ccf.ledger.Ledger(
                recovered_primary.remote.ledger_paths(),
                committed_only=False,
                read_recovery_files=True,
            )
            for chunk in ledger:
                _, chunk_end_seqno = chunk.get_seqnos()
                if chunk_end_seqno < recovery_seqno:
                    continue
                for tx in chunk:
                    tables = tx.get_public_domain().get_tables()
                    seqno = tx.get_public_domain().get_seqno()
                    if seqno < recovery_seqno:
                        continue
                    else:
                        tables = tx.get_public_domain().get_tables()
                        tcb_versions = tables["public:ccf.gov.nodes.snp.tcb_versions"]
                        assert len(tcb_versions) == 1, tcb_versions
                        LOG.info(
                            f"Recovery TCB_version found in ledger: {tcb_versions}"
                        )
                        return
            assert False, "No TCB_version found in recovery ledger"


def wait_for_sealed_secrets(node, min_seqno=0, timeout=10):
    out, _ = node.remote.get_logs()
    start = time.time()
    while time.time() < start + timeout:
        with open(out, "r") as outf:
            for line in outf.readlines():
                if "Sealing complete of ledger secret to" in line:
                    try:
                        path = line.split()[-1]
                        filename = os.path.basename(path)
                        seqno = int(filename.split(".")[0])
                        if seqno >= min_seqno:
                            return
                    except (IndexError, ValueError):
                        continue

        time.sleep(0.1)

    raise TimeoutError(
        f"Could not find sealed secrets for seqno {min_seqno} after {timeout}s in logs"
    )


def run_recovery_local_unsealing(
    const_args, recovery_f=0, rekey=False, recovery_shares_refresh=False
):
    LOG.info("Running recovery local unsealing")
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.enable_local_sealing = True
    args.label += "_unsealing"

    with infra.network.network(args.nodes, args.binary_dir) as network:
        network.start_and_open(args)

        network.save_service_identity(args)

        primary, _ = network.find_primary()
        if rekey:
            network.wait_for_node_commit_sync()
            with primary.client() as c:
                r = c.get("/node/commit").body.json()
                min_seqno = TxID.from_str(r["transaction_id"]).seqno
            network.consortium.trigger_ledger_rekey(primary)
        else:
            min_seqno = 0
        if recovery_shares_refresh:
            network.consortium.trigger_recovery_shares_refresh(primary)

        for node in network.nodes:
            wait_for_sealed_secrets(node, min_seqno=min_seqno)

        node_secret_map = {
            node.local_node_id: node.save_sealed_ledger_secret()
            for node in network.nodes
        }

        network.stop_all_nodes()

        prev_network = network
        for node in network.nodes:
            recovery_network_args = copy.deepcopy(args)
            recovery_network_args.nodes = infra.e2e_args.min_nodes(args, f=recovery_f)
            recovery_network_args.previous_sealed_ledger_secret_location = (
                node_secret_map[node.local_node_id]
            )
            recovery_network_args.label += f"_recovery_from_node_{node.local_node_id}"

            with infra.network.network(
                recovery_network_args.nodes,
                recovery_network_args.binary_dir,
                next_node_id=prev_network.next_node_id,
            ) as recovery_network:

                # Reset consortium and users to prevent issues with hosts from existing_network
                recovery_network.consortium = prev_network.consortium
                recovery_network.users = prev_network.users
                recovery_network.txs = prev_network.txs
                recovery_network.jwt_issuer = prev_network.jwt_issuer

                current_ledger_dir, committed_ledger_dirs = node.get_ledger()
                recovery_network.start_in_recovery(
                    recovery_network_args,
                    common_dir=infra.network.get_common_folder_name(
                        args.workspace, args.label
                    ),
                    ledger_dir=current_ledger_dir,
                    committed_ledger_dirs=committed_ledger_dirs,
                )

                recovery_network.recover(recovery_network_args, via_local_sealing=True)

                recovery_network.stop_all_nodes()
                prev_network = recovery_network


def run_recovery_unsealing_validate_audit(const_args):
    LOG.info("Running recovery local unsealing")
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.enable_local_sealing = True
    args.label += "_unsealing_audit"

    with infra.network.network(args.nodes, args.binary_dir) as network:
        network.start_and_open(args)

        network.save_service_identity(args)
        for node in network.nodes:
            wait_for_sealed_secrets(node)
        node0_secrets = network.nodes[0].save_sealed_ledger_secret()

        latest_public_tables, _ = network.get_latest_ledger_public_state()
        node_info = latest_public_tables["public:ccf.gov.nodes.info"]
        for info in node_info.values():
            node_info = json.loads(info.decode("utf-8"))
            assert node_info["will_locally_seal_ledger_secrets"]
        assert (
            "public:ccf.internal.last_recovery_type" not in latest_public_tables
        ), "last_recovery_type was set when no recovery was performed."

        network.stop_all_nodes()

        prev_network = network
        for via_local_unsealing in [True, False]:
            recovery_network_args = copy.deepcopy(args)
            recovery_network_args.nodes = infra.e2e_args.min_nodes(args, f=0)
            if via_local_unsealing:
                recovery_network_args.label += "_via_local_unsealing"
            else:
                recovery_network_args.label += "_via_recovery_shares"

            if via_local_unsealing:
                recovery_network_args.previous_sealed_ledger_secret_location = (
                    node0_secrets
                )
            with infra.network.network(
                recovery_network_args.nodes,
                recovery_network_args.binary_dir,
                next_node_id=prev_network.next_node_id,
            ) as recovery_network:

                # Reset consortium and users to prevent issues with hosts from existing_network
                recovery_network.consortium = prev_network.consortium
                recovery_network.users = prev_network.users
                recovery_network.txs = prev_network.txs
                recovery_network.jwt_issuer = prev_network.jwt_issuer

                current_ledger_dir, committed_ledger_dirs = network.nodes[
                    0
                ].get_ledger()
                recovery_network.start_in_recovery(
                    recovery_network_args,
                    common_dir=infra.network.get_common_folder_name(
                        args.workspace, args.label
                    ),
                    ledger_dir=current_ledger_dir,
                    committed_ledger_dirs=committed_ledger_dirs,
                )

                recovery_network.recover(
                    recovery_network_args, via_local_sealing=via_local_unsealing
                )

                latest_public_tables, _ = (
                    recovery_network.get_latest_ledger_public_state()
                )
                recovery_type = latest_public_tables[
                    "public:ccf.internal.last_recovery_type"
                ][b"\x00\x00\x00\x00\x00\x00\x00\x00"].decode("utf-8")
                expected_recovery_type = (
                    '"LOCAL_UNSEALING"' if via_local_unsealing else '"RECOVERY_SHARES"'
                )
                assert (
                    recovery_type == expected_recovery_type
                ), f"Network recovery type was {recovery_type} instead of {expected_recovery_type}"

                recovery_network.stop_all_nodes()

                prev_network = recovery_network


def run_recovery_unsealing_corrupt(const_args, recovery_f=0):
    LOG.info("Running recovery local unsealing corrupted secret")
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.enable_local_sealing = True
    args.label += "_recovery_unsealing_corrupt"

    with infra.network.network(args.nodes, args.binary_dir) as network:
        network.start_and_open(args)

        network.save_service_identity(args)
        for node in network.nodes:
            wait_for_sealed_secrets(node)

        node_secret_map = {
            node.local_node_id: node.save_sealed_ledger_secret()
            for node in network.nodes
        }

        network.stop_all_nodes()

        class Corruption:
            def __init__(self, tag, lamb, expected_exception):
                self.tag = tag
                self.lamb = lamb
                self.expected_exception = expected_exception

            def run(self, src_dir, dst_dir):
                secrets = {}
                for file in os.listdir(src_dir):
                    version = file.split(".")[0]
                    try:
                        data = json.loads(
                            open(os.path.join(src_dir, file), "rb").read()
                        )
                    except json.JSONDecodeError:
                        continue

                    secrets[int(version)] = data

                corrupted_secrets = self.lamb(secrets)

                pathlib.Path(dst_dir).mkdir(parents=True, exist_ok=True)
                for version, data in corrupted_secrets.items():
                    secret_path = os.path.join(dst_dir, f"{version}.sealed.json")
                    with open(secret_path, "wb") as w:
                        w.write(json.dumps(data).encode("utf-8"))

        corruptions = [Corruption("delete_everything", lambda _: {}, True)]

        corruptions.append(
            Corruption(
                "max_version_ignored",
                lambda s: s
                | {
                    int(sys.maxsize): {
                        "ciphertext": "some data",
                        "aad_text": "some aad",
                    }
                },
                False,
            )
        )

        corruptions.append(
            Corruption(
                "invalid_file",
                lambda s: s
                | {"asdf": {"ciphertext": "some data", "aad_text": "some aad"}},
                False,
            )
        )

        corruptions.append(
            Corruption(
                "xor_ciphertext",
                lambda s: {
                    v: {
                        "ciphertext": base64.b64encode(
                            bytes(
                                [b ^ 0xFF for b in base64.b64decode(s[v]["ciphertext"])]
                            )
                        ).decode("utf-8"),
                        "aad_text": s[v]["aad_text"],
                    }
                    for v in s.keys()
                },
                True,
            )
        )

        # corrupt one of the ledgers
        node = network.nodes[0]
        ledger_secret = list(node_secret_map.values())[0]

        prev_network = network
        for corruption in corruptions:
            LOG.info("Corruption: " + corruption.tag)
            corrupt_ledger_secret = ledger_secret + f"{corruption.tag}.corrupt"
            corruption.run(ledger_secret, corrupt_ledger_secret)

            recovery_network_args = copy.deepcopy(args)
            recovery_network_args.nodes = infra.e2e_args.min_nodes(
                recovery_network_args, f=recovery_f
            )
            recovery_network_args.previous_sealed_ledger_secret_location = (
                corrupt_ledger_secret
            )
            recovery_network_args.label += f"_{corruption.tag}"
            with infra.network.network(
                recovery_network_args.nodes,
                recovery_network_args.binary_dir,
                next_node_id=prev_network.next_node_id,
            ) as recovery_network:

                # Reset consortium and users to prevent issues with hosts from existing_network
                recovery_network.consortium = prev_network.consortium
                recovery_network.users = prev_network.users
                recovery_network.txs = prev_network.txs
                recovery_network.jwt_issuer = prev_network.jwt_issuer

                current_ledger_dir, committed_ledger_dirs = node.get_ledger()
                exception_thrown = None
                try:
                    recovery_network.start_in_recovery(
                        recovery_network_args,
                        common_dir=infra.network.get_common_folder_name(
                            args.workspace, args.label
                        ),
                        ledger_dir=current_ledger_dir,
                        committed_ledger_dirs=committed_ledger_dirs,
                    )

                    recovery_network.recover(
                        recovery_network_args, via_local_sealing=True
                    )
                except Exception as e:
                    exception_thrown = e
                    pass

                if corruption.expected_exception:
                    assert (
                        exception_thrown is not None
                    ), f"Expected exception to be thrown for {corruption.tag} corruption"
                else:
                    assert (
                        exception_thrown is None
                    ), f"Expected no exception to be thrown for {corruption.tag} corruption"

                recovery_network.stop_all_nodes()
                prev_network = recovery_network


def run_self_healing_open(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
    ) as network:
        LOG.info("Start a network and stop it")
        network.start_and_open(args)
        network.save_service_identity(args)
        network.stop_all_nodes()

        recovery_args = copy.deepcopy(args)

        ledger_dirs = {}
        committed_ledger_dirs = {}
        for i, node in enumerate(network.nodes):
            l_dir, c = node.get_ledger()
            ledger_dirs[i] = l_dir
            committed_ledger_dirs[i] = c

        LOG.info("Start a recovery network and stop it")
        with infra.network.network(
            recovery_args.nodes,
            recovery_args.binary_dir,
            recovery_args.debug_nodes,
            existing_network=network,
        ) as recovered_network:
            recovered_network.start_in_self_healing_open(
                recovery_args,
                ledger_dirs=ledger_dirs,
                committed_ledger_dirs=committed_ledger_dirs,
            )

            # Wait until all relevant nodes have restarted
            time.sleep(3)

            # Refresh the the declared state of nodes which have shut themselves down to join.
            for node in recovered_network.nodes:
                node.refresh_network_state(verify_ca=False)

            recovered_network.refresh_service_identity_file(recovery_args)

            recovered_network.consortium.recover_with_shares(
                recovered_network.find_random_node()
            )

            LOG.info("Submitted recovery shares")

            # Wait for all live replicas to report being part of the opened network
            successfully_opened = 0
            for node in recovered_network.get_joined_nodes():
                try:
                    recovered_network.wait_for_status(
                        node,
                        "Open",
                        timeout=10,
                    )
                    recovered_network._wait_for_app_open(node)
                    successfully_opened += 1
                except TimeoutError:
                    pass

            assert successfully_opened == 1

            LOG.info("Completed self-healing open successfully")

            recovered_network.stop_all_nodes(accept_ledger_diff=True)


def run_self_healing_open_timeout_path(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
    ) as network:
        LOG.info("Start a network and stop it")
        network.start_and_open(args)
        network.save_service_identity(args)
        network.stop_all_nodes()

        recovery_args = copy.deepcopy(args)

        ledger_dirs = {}
        committed_ledger_dirs = {}
        for i, node in enumerate(network.nodes):
            l_dir, c = node.get_ledger()
            ledger_dirs[i] = l_dir
            committed_ledger_dirs[i] = c

        LOG.info("Start a recovery network and stop it")
        with infra.network.network(
            recovery_args.nodes,
            recovery_args.binary_dir,
            recovery_args.debug_nodes,
            existing_network=network,
        ) as recovered_network:
            recovered_network.start_in_self_healing_open(
                recovery_args,
                ledger_dirs=ledger_dirs,
                committed_ledger_dirs=committed_ledger_dirs,
                starting_nodes=1,  # Force timeout path by starting only one node
            )

            # Wait until all relevant nodes have restarted
            time.sleep(3)

            # Refresh the the declared state of nodes which have shut themselves down to join.
            for node in recovered_network.nodes:
                node.refresh_network_state(verify_ca=False)

            recovered_network.refresh_service_identity_file(recovery_args)

            recovered_network.consortium.recover_with_shares(
                recovered_network.find_random_node()
            )

            LOG.info("Submitted recovery shares")

            # Wait for all live replicas to report being part of the opened network
            successfully_opened = 0
            for node in recovered_network.get_joined_nodes():
                try:
                    recovered_network.wait_for_status(
                        node,
                        "Open",
                        timeout=10,
                    )
                    recovered_network._wait_for_app_open(node)
                    successfully_opened += 1
                except TimeoutError:
                    pass

            assert successfully_opened == 1

            LOG.info("Completed self-healing open successfully")

            recovered_network.stop_all_nodes()


def run_self_healing_open_local_unsealing(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.enable_local_sealing = True

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
    ) as network:
        LOG.info("Start a network and stop it")
        network.start_and_open(args)
        network.save_service_identity(args)
        node_secrets = [node.save_sealed_ledger_secret() for node in network.nodes]
        network.stop_all_nodes()

        recovery_args = copy.deepcopy(args)

        ledger_dirs = {}
        committed_ledger_dirs = {}
        for i, node in enumerate(network.nodes):
            l_dir, c = node.get_ledger()
            ledger_dirs[i] = l_dir
            committed_ledger_dirs[i] = c

        LOG.info("Start a recovery network")
        recovered_network = infra.network.Network(
            recovery_args.nodes,
            recovery_args.binary_dir,
            recovery_args.debug_nodes,
            existing_network=network,
        )
        recovered_network.start_in_self_healing_open(
            recovery_args,
            ledger_dirs=ledger_dirs,
            committed_ledger_dirs=committed_ledger_dirs,
            sealed_ledger_secrets=node_secrets,
        )

        # Wait until all relevant nodes have restarted
        time.sleep(3)

        # Refresh the the declared state of nodes which have shut themselves down to join.
        for node in recovered_network.nodes:
            node.refresh_network_state(verify_ca=False)

        recovered_network.refresh_service_identity_file(recovery_args)

        # Wait for all live replicas to report being part of the opened network
        successfully_opened = 0
        for node in recovered_network.get_joined_nodes():
            try:
                recovered_network.wait_for_status(
                    node,
                    "Open",
                    timeout=10,
                )
                recovered_network._wait_for_app_open(node)
                successfully_opened += 1
            except TimeoutError:
                pass

        assert successfully_opened == 1

        LOG.info("Completed self-healing open successfully")

        recovered_network.stop_all_nodes()


def run_read_ledger_on_testdata(args):
    for testdata_dir in os.scandir(args.historical_testdata):
        assert testdata_dir.is_dir()
        testdata_path = os.path.join(
            args.historical_testdata, testdata_dir.name, "ledger"
        )
        LOG.info(f"Reading and validating ledger in {testdata_path}")
        tx_count = 0
        ledger = ccf.ledger.Ledger(
            [testdata_path],
            committed_only=False,
            read_recovery_files=False,
        )
        for chunk in ledger:
            for tx in chunk:
                tables = tx.get_public_domain().get_tables()
                tx_count += 1
        LOG.info(f"Read {tx_count} transactions from {testdata_path}")
        snapshot_path = os.path.join(
            args.historical_testdata, testdata_dir.name, "snapshots"
        )
        for snapshot_file in os.scandir(snapshot_path):
            if snapshot_file.is_file() and snapshot_file.name.endswith(".committed"):
                snapshot_path = os.path.join(snapshot_path, snapshot_file.name)
                LOG.info(f"Reading and validating snapshot {snapshot_path}")
                with ccf.ledger.Snapshot(snapshot_file.path) as snapshot:
                    tables = snapshot.get_public_domain().get_tables()
                    LOG.info(
                        f"Valid snapshot at {snapshot_file.path} with {len(tables)} tables"
                    )

    # Corrupt a single chunk to confirm that read_ledger throws appropriate errors
    source_chunk = os.path.join(
        args.historical_testdata,
        "double_sealed_service",
        "ledger",
        "ledger_44-64.committed",
    )
    good_chunk = ccf.ledger.LedgerChunk(source_chunk)
    start_seqno, end_seqno = good_chunk.get_seqnos()
    expected_range = end_seqno - start_seqno + 1
    tx_count_error = (
        f"Expected to contain {expected_range} transactions due to filename"
    )
    chunk_name = os.path.basename(source_chunk)
    with open(source_chunk, "rb") as src_f:
        good_data = src_f.read()
    source_size = len(good_data)
    header_size = ccf.ledger.LEDGER_HEADER_SIZE
    source_offset = int.from_bytes(good_data[0:header_size], byteorder="little")
    assert source_offset > 0
    assert source_offset < source_size

    # Create an alternate version of the chunk without the offsets table. Should be equivalent to the file immediately before it was marked `.committed`
    no_offsets_table = (
        int(0).to_bytes(header_size, byteorder="little")
        + good_data[header_size:source_offset]
    )

    null_block_size = source_size // 8

    for name, corrupted_data, expected_parse_error in [
        (
            "truncate_pre_offsets",
            good_data[: source_offset - 1],
            f"File header claims offset table is at {source_offset}",
        ),
        (
            "truncate_at_offsets",
            good_data[:source_offset],
            tx_count_error,
        ),
        (
            "truncate_tx_no_offsets",
            no_offsets_table[: source_size // 2],
            tx_count_error,
        ),
        (
            "nulled_block",
            good_data[: source_size // 2]
            + b"\00" * null_block_size
            + good_data[source_size // 2 + null_block_size :],
            "index out of range",
        ),
        (
            "header_offset_too_large",
            (source_size + 1).to_bytes(header_size, byteorder="little")
            + good_data[header_size:],
            f"File header claims offset table is at {source_size + 1}",
        ),
        (
            "truncate_mid_offsets",
            good_data[:-4],
            tx_count_error,
        ),
        (
            "misaligned_offsets_too_small",
            good_data[:-1],
            "Expected positions to contain uint32s",
        ),
        (
            "misaligned_offsets_too_large",
            good_data + b"\x00",
            "Expected positions to contain uint32s",
        ),
        (
            "unread_data",
            good_data + b"\x00" * 4,
            tx_count_error,
        ),
        (
            "unread_data_no_offsets_misaligned",
            no_offsets_table + b"\x00",
            "Failed to read precise number of bytes",
        ),
        (
            "unread_data_no_offsets",
            no_offsets_table + b"\x00" * 8,
            tx_count_error,
        ),
    ]:
        temp_dir = tempfile.TemporaryDirectory(
            dir="workspace", prefix=name + "-", delete=False
        )
        corrupted_chunk_path = os.path.join(temp_dir.name, chunk_name)
        LOG.info(f"Testing chunk corruption {name} in {corrupted_chunk_path}")
        with open(corrupted_chunk_path, "wb") as dst_f:
            dst_f.write(corrupted_data)

        try:
            chunk = ccf.ledger.LedgerChunk(corrupted_chunk_path)
            for tx in chunk:
                tx.get_public_domain()

            assert (
                False
            ), f"Expected to raise exception while parsing corrupted ledger chunk {name}"

        except Exception as e:
            assert expected_parse_error in str(
                e
            ), f"Unexpected error message for corruption {name}: {e}"

        # NB: cleanup() is deliberately skipped if an assertion fails, so the corrupted files can be inspected
        temp_dir.cleanup()


def test_error_message_on_failure_to_read_aci_sec_context(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()

        args_copy = copy.deepcopy(args)

        new_node = network.create_node()
        args_copy.snp_endorsements_servers = ["Azure:invalid.azure.com"]
        args_copy.snp_security_policy_file = "/a/fake/path"
        args_copy.snp_uvm_endorsements_file = "/a/fake/path"
        args_copy.snp_endorsements_file = "/a/fake/path"
        failed = False
        try:
            network.join_node(new_node, args.package, args_copy, timeout=20)
        except infra.network.CollateralFetchTimeout:
            LOG.info(
                "Node with invalid quote endorsement servers could not join as expected"
            )
            failed = True
        assert (
            failed
        ), "Node with invalid quote endorsement servers should not be able to join"

        expected_log_messages = [
            "Could not read snp_security_policy from /a/fake/path",
            "Could not read snp_uvm_endorsements from /a/fake/path",
            "Could not read snp_endorsements from /a/fake/path",
        ]

        out_path, _ = new_node.get_logs()
        for line in open(out_path, "r", encoding="utf-8").readlines():
            for expected in expected_log_messages:
                if expected in line:
                    expected_log_messages.remove(expected)
                    LOG.info(f"Found expected log message: {expected}")
            if len(expected_log_messages) == 0:
                break

        assert (
            len(expected_log_messages) == 0
        ), f"Did not find expected log messages: {expected_log_messages}"


def test_error_message_on_failure_to_fetch_snapshot(const_args):
    args = copy.deepcopy(const_args)
    args.nodes = infra.e2e_args.min_nodes(args, 0)
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()

        new_node = network.create_node()

        # Shut down primary to cause snapshot fetch to fail
        primary.remote.stop()

        failed = False
        try:
            LOG.info("Starting join")
            network.join_node(
                new_node,
                args.package,
                args,
                target_node=primary,
                timeout=10,
                from_snapshot=False,
                wait_for_node_in_store=False,
            )
            new_node.wait_for_node_to_join(timeout=5)
        except Exception as e:
            LOG.info(f"Joining node could not join as expected {e}")
            failed = True

        assert failed, "Joining node could not join failed node as expected"

        expected_log_messages = [
            re.compile(r"Fetching snapshot from .* \(attempt 1/3\)"),
            re.compile(r"Fetching snapshot from .* \(attempt 2/3\)"),
            re.compile(r"Fetching snapshot from .* \(attempt 3/3\)"),
            re.compile(
                r"Exceeded maximum snapshot fetch retries \([0-9]+\), giving up"
            ),
        ]

        out_path, _ = new_node.get_logs()
        for line in open(out_path, "r", encoding="utf-8").readlines():
            for expected in expected_log_messages:
                match = re.search(expected, line)
                if match:
                    expected_log_messages.remove(expected)
                    LOG.info(f"Found expected log message: {line}")
            if len(expected_log_messages) == 0:
                break

        assert (
            len(expected_log_messages) == 0
        ), f"Did not find expected log messages: {expected_log_messages}"


def run_propose_request_vote(const_args):
    args = copy.deepcopy(const_args)
    args.label += "_propose_vote"
    args.nodes = infra.e2e_args.nodes(args, 3)
    # use a high timeout to hedge against flaky nodes which pause for seconds
    # In most cases this should not matter as the propose_request_vote will cause the election quickly
    args.election_timeout = 20000
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        LOG.info("Start a network")
        network.start_and_open(args, ignore_first_sigterm=True)
        original_primary, original_term = network.find_primary()
        backups = [
            n
            for n in network.get_joined_nodes()
            if n.node_id != original_primary.node_id
        ]

        original_primary.remote.remote.proc.send_signal(signal.SIGTERM)
        # Find any primary which wasn't the original one
        # If propose_request_vote worked, the new primary will be elected immediately
        # So if this times out, the propose_request_vote likely failed
        new_primary, new_term = network.find_primary(
            nodes=backups, timeout=(0.9 * args.election_timeout)
        )
        assert (
            new_primary.node_id != original_primary.node_id
        ), "A new primary should have been elected"
        assert (
            new_term > original_term
        ), "The new primary should be in a higher term than the original primary"

        LOG.info(f"New primary is node {new_primary.node_id}")

        # send a sigterm to ensure they shutdown correctly
        for node in backups:
            node.remote.remote.proc.send_signal(signal.SIGTERM)


def run_snp_tests(args):
    run_initial_uvm_descriptor_checks(args)
    run_initial_tcb_version_checks(args)
    run_recovery_local_unsealing(args)
    run_recovery_local_unsealing(args, rekey=True)
    run_recovery_local_unsealing(args, recovery_shares_refresh=True)
    run_recovery_local_unsealing(args, recovery_f=1)
    run_recovery_unsealing_corrupt(args)
    run_recovery_unsealing_validate_audit(args)
    test_error_message_on_failure_to_read_aci_sec_context(args)
    run_self_healing_open_local_unsealing(args)


def run(args):
    run_max_uncommitted_tx_count(args)
    run_file_operations(args)
    run_tls_san_checks(args)
    run_config_timeout_check(args)
    run_configuration_file_checks(args)
    run_pid_file_check(args)
    run_preopen_readiness_check(args)
    run_sighup_check(args)
    run_service_subject_name_check(args)
    run_cose_signatures_config_check(args)
    run_late_mounted_ledger_check(args)
    run_empty_ledger_dir_check(args)
    run_self_healing_open(args)
    run_self_healing_open_timeout_path(args)
    run_read_ledger_on_testdata(args)
    run_propose_request_vote(args)
