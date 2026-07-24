# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import copy
import hashlib
import os
import shutil

import ccf.ledger
import infra.e2e_args
import infra.logging_app as app
import infra.network
import infra.node
from infra.runner import ConcurrentRunner
from loguru import logger as LOG


def _logs(node):
    out_path, _ = node.get_logs()
    assert out_path is not None
    with open(out_path, encoding="utf-8") as output:
        return output.read()


def _stop_incomplete_recovery(network):
    network.stop_all_nodes(
        skip_verification=True,
        skip_verify_chunking=True,
        check_file_invariants=False,
    )


def _recover_and_open(network, args, label):
    recovery_args = copy.deepcopy(args)
    recovery_args.label = label
    network.save_service_identity(recovery_args)
    primary, _ = network.find_primary()
    network.stop_all_nodes()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

    recovered = infra.network.Network(
        recovery_args.nodes,
        recovery_args.binary_dir,
        recovery_args.debug_nodes,
        existing_network=network,
    )
    recovered.start_in_recovery(
        recovery_args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    recovered.recover(recovery_args)

    app.LoggingTxs("user0").issue(
        recovered,
        number_txs=2,
        send_private=False,
        send_public=True,
        wait_for_sync=True,
    )
    recovered.get_latest_ledger_public_state()
    return recovered, recovery_args


def _start_recovery_attempt(
    base_network,
    args,
    label,
    ledger_dir,
    committed_ledger_dirs,
    snapshots_dir,
    previous_service_identity_file,
    next_node_id,
):
    attempt_args = copy.deepcopy(args)
    attempt_args.label = label
    attempt_args.previous_service_identity_file = previous_service_identity_file
    attempt = infra.network.Network(
        attempt_args.nodes,
        attempt_args.binary_dir,
        attempt_args.debug_nodes,
        existing_network=base_network,
        next_node_id=next_node_id,
    )
    attempt.ignore_errors_on_shutdown()
    attempt.start_in_recovery(
        attempt_args,
        ledger_dir=ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
        snapshots_dir=snapshots_dir,
        common_dir=base_network.common_dir,
    )
    return attempt


def _copy_ledger_prefix(source_dirs, destination, first_excluded_seqno):
    shutil.rmtree(destination, ignore_errors=True)
    os.makedirs(destination)
    copied = 0
    for source_dir in source_dirs:
        for name in os.listdir(source_dir):
            if not ccf.ledger.is_ledger_chunk_committed(name):
                continue
            _, end_seqno = ccf.ledger.range_from_filename(name)
            if end_seqno is None or end_seqno >= first_excluded_seqno:
                continue
            destination_path = os.path.join(destination, name)
            if not os.path.exists(destination_path):
                shutil.copy(os.path.join(source_dir, name), destination_path)
                copied += 1
    assert copied > 0


def _assert_node_snapshot_unchanged(
    network, node, snapshot_name, expected_snapshot_digest
):
    snapshots_dir = network.get_committed_snapshots(node, force_txs=False)
    snapshot_path = os.path.join(snapshots_dir, snapshot_name)
    assert os.path.isfile(snapshot_path), snapshot_path
    with open(snapshot_path, "rb") as snapshot_file:
        assert hashlib.sha256(snapshot_file.read()).digest() == expected_snapshot_digest


def _assert_malformed_snapshot_falls_back(
    base_network,
    args,
    label,
    ledger_dir,
    committed_ledger_dirs,
    target_identity_file,
    snapshot_name,
    snapshot_bytes,
    next_node_id,
    expected_log,
):
    snapshots_dir = os.path.join(base_network.common_dir, label)
    shutil.rmtree(snapshots_dir, ignore_errors=True)
    os.makedirs(snapshots_dir)
    snapshot_path = os.path.join(snapshots_dir, snapshot_name)
    with open(snapshot_path, "wb") as snapshot_file:
        snapshot_file.write(snapshot_bytes)
    snapshot_digest = hashlib.sha256(snapshot_bytes).digest()

    attempt = _start_recovery_attempt(
        base_network,
        args,
        label,
        ledger_dir,
        committed_ledger_dirs,
        snapshots_dir,
        target_identity_file,
        next_node_id,
    )
    try:
        primary, _ = attempt.find_primary()
        logs = _logs(primary)
        assert expected_log in logs
        assert "Starting to read public ledger" in logs
        assert "Setting startup snapshot seqno" not in logs
        assert "Deserialising snapshot (size:" not in logs
        assert "Snapshot successfully deserialised" not in logs
        _assert_node_snapshot_unchanged(
            attempt, primary, snapshot_name, snapshot_digest
        )
    finally:
        _stop_incomplete_recovery(attempt)


def run_recovery_snapshot_endorsements(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as initial_network:
        initial_network.start_and_open(args)
        primary, _ = initial_network.find_primary()

        app.LoggingTxs("user0").issue(
            initial_network,
            number_txs=2,
            send_private=False,
            send_public=True,
            wait_for_sync=True,
        )
        snapshot_trigger = primary.trigger_snapshot()
        committed_snapshots_dir = initial_network.get_committed_snapshots(
            primary,
            target_seqno=snapshot_trigger.seqno,
            wait_for_target_seqno=True,
        )
        snapshots = sorted(
            (
                name
                for name in os.listdir(committed_snapshots_dir)
                if name.startswith("snapshot_")
                and ccf.ledger.is_snapshot_file_committed(name)
            ),
            key=lambda name: infra.node.get_snapshot_seqnos(name)[0],
        )
        assert snapshots
        snapshot_name = snapshots[-1]
        original_snapshot_path = os.path.join(committed_snapshots_dir, snapshot_name)

        source_snapshots_dir = os.path.join(
            initial_network.common_dir, "recovery_snapshot_endorsements_source"
        )
        shutil.rmtree(source_snapshots_dir, ignore_errors=True)
        os.makedirs(source_snapshots_dir)
        source_snapshot_path = shutil.copy(original_snapshot_path, source_snapshots_dir)
        with open(source_snapshot_path, "rb") as snapshot_file:
            source_snapshot_bytes = snapshot_file.read()
        snapshot_digest = hashlib.sha256(source_snapshot_bytes).digest()

        first_recovery, first_args = _recover_and_open(
            initial_network, args, f"{args.label}_identity_1"
        )
        second_recovery, second_args = _recover_and_open(
            first_recovery, first_args, f"{args.label}_identity_2"
        )

        second_recovery.save_service_identity(second_args)
        target_identity_file = second_args.previous_service_identity_file
        primary, _ = second_recovery.find_primary()
        with primary.client() as client:
            service_create_txid = client.get("/node/network").body.json()[
                "current_service_create_txid"
            ]
        service_create_seqno = int(service_create_txid.split(".")[1])
        second_recovery.stop_all_nodes()
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

        valid_attempt = _start_recovery_attempt(
            second_recovery,
            second_args,
            f"{args.label}_in_memory_chain",
            current_ledger_dir,
            committed_ledger_dirs,
            source_snapshots_dir,
            target_identity_file,
            100,
        )
        try:
            valid_primary, _ = valid_attempt.find_primary()
            logs = _logs(valid_primary)
            scan_log = "scanning the public ledger suffix for COSE endorsements"
            validated_log = "Validated 2 recovery snapshot endorsement(s) in memory"
            snapshot_body_log = "Deserialising snapshot (size:"
            public_recovery_log = "Starting to read public ledger"
            assert (
                logs.index(scan_log)
                < logs.index(validated_log)
                < logs.index(snapshot_body_log)
                < logs.index(public_recovery_log)
            )
            _assert_node_snapshot_unchanged(
                valid_attempt, valid_primary, snapshot_name, snapshot_digest
            )
        finally:
            _stop_incomplete_recovery(valid_attempt)

        incomplete_ledger_dir = os.path.join(
            second_recovery.common_dir, "recovery_snapshot_incomplete_ledger"
        )
        shutil.rmtree(incomplete_ledger_dir, ignore_errors=True)
        os.makedirs(incomplete_ledger_dir)
        incomplete_committed_ledger_dir = os.path.join(
            second_recovery.common_dir,
            "recovery_snapshot_incomplete_committed_ledger",
        )
        _copy_ledger_prefix(
            [current_ledger_dir, *committed_ledger_dirs],
            incomplete_committed_ledger_dir,
            service_create_seqno,
        )
        fallback_attempt = _start_recovery_attempt(
            second_recovery,
            second_args,
            f"{args.label}_incomplete_suffix",
            incomplete_ledger_dir,
            [incomplete_committed_ledger_dir],
            source_snapshots_dir,
            target_identity_file,
            101,
        )
        try:
            fallback_primary, _ = fallback_attempt.find_primary()
            logs = _logs(fallback_primary)
            assert "Falling back to full-ledger recovery" in logs
            assert "Setting startup snapshot seqno" not in logs
            _assert_node_snapshot_unchanged(
                fallback_attempt, fallback_primary, snapshot_name, snapshot_digest
            )
        finally:
            _stop_incomplete_recovery(fallback_attempt)

        malformed_snapshots = (
            (
                "zeroed_snapshot",
                snapshot_name,
                bytes(64),
                "transaction size should not be zero",
            ),
            (
                "truncated_snapshot_header",
                snapshot_name,
                source_snapshot_bytes[:4],
                "Insufficient space",
            ),
            (
                "oversized_snapshot_body",
                snapshot_name,
                source_snapshot_bytes[:8],
                "exceeds available buffer size",
            ),
            (
                "malformed_snapshot_filename",
                "snapshot_not-a-seqno_1.committed",
                source_snapshot_bytes,
                "Unable to discover a valid recovery snapshot",
            ),
        )
        for offset, (
            malformed_label,
            malformed_name,
            malformed_bytes,
            expected_log,
        ) in enumerate(malformed_snapshots, start=102):
            _assert_malformed_snapshot_falls_back(
                second_recovery,
                second_args,
                f"{args.label}_{malformed_label}",
                current_ledger_dir,
                committed_ledger_dirs,
                target_identity_file,
                malformed_name,
                malformed_bytes,
                offset,
                expected_log,
            )

        LOG.success(
            "In-memory recovery snapshot endorsement validation, malformed "
            "candidate rejection, and fallback succeeded"
        )


if __name__ == "__main__":

    def add(parser):
        parser.description = (
            "Verify in-memory recovery snapshot endorsement chains across multiple "
            "disaster recoveries."
        )

    cr = ConcurrentRunner(add)
    cr.add(
        "recovery_snapshot_endorsements",
        run_recovery_snapshot_endorsements,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=10,
        sig_tx_interval=1,
    )
    cr.run()
