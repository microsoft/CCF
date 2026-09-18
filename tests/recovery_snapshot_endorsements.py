# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import copy
import hashlib
import http
import os
import shutil
import tempfile

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


def _assert_node_snapshot_unchanged(node, snapshot_name, expected_snapshot_digest):
    snapshot_paths = [
        path
        for path in node.get_snapshots(include_read_only=True)
        if os.path.basename(path) == snapshot_name
    ]
    assert (
        snapshot_paths
    ), f"Snapshot {snapshot_name} not found on node {node.local_node_id}"
    for snapshot_path in snapshot_paths:
        with open(snapshot_path, "rb") as snapshot_file:
            assert (
                hashlib.sha256(snapshot_file.read()).digest()
                == expected_snapshot_digest
            ), snapshot_path


def run_recovery_snapshot_endorsements(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as initial_network:
        initial_network.start_and_open(args)
        primary, _ = initial_network.find_primary()

        target = app.LoggingTxs("user0").issue(
            initial_network,
            number_txs=2,
            send_private=False,
            send_public=True,
            wait_for_sync=True,
        )
        primary.trigger_snapshot()
        primary.wait_for_snapshot(target.seqno)
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
        assert len(snapshots) >= 2
        snapshot_name = snapshots[-2]
        malformed_snapshot_name = snapshots[-1]

        source_snapshots_dir = os.path.join(
            initial_network.common_dir, "recovery_snapshot_endorsements_source"
        )
        shutil.rmtree(source_snapshots_dir, ignore_errors=True)
        os.makedirs(source_snapshots_dir)
        source_snapshot_path = shutil.copy(
            os.path.join(committed_snapshots_dir, snapshot_name), source_snapshots_dir
        )
        malformed_snapshot_path = shutil.copy(
            os.path.join(committed_snapshots_dir, malformed_snapshot_name),
            source_snapshots_dir,
        )
        with open(malformed_snapshot_path, "r+b") as malformed_snapshot:
            malformed_snapshot.seek(0, os.SEEK_END)
            malformed_snapshot.truncate(malformed_snapshot.tell() - 1)
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
            malformed_log = (
                "Recovery snapshot recovery_snapshot_endorsements_source/"
                f"{malformed_snapshot_name} cannot be verified"
            )
            assert (
                logs.index(malformed_log)
                < logs.index("Looking for an older snapshot")
                < logs.index(scan_log)
                < logs.index(validated_log)
                < logs.index(snapshot_body_log)
                < logs.index(public_recovery_log)
            )
            _assert_node_snapshot_unchanged(
                valid_primary, snapshot_name, snapshot_digest
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
            assert "No usable local snapshot found" in logs
            assert "Setting startup snapshot seqno" not in logs
            _assert_node_snapshot_unchanged(
                fallback_primary, snapshot_name, snapshot_digest
            )
        finally:
            _stop_incomplete_recovery(fallback_attempt)

        LOG.success(
            "In-memory recovery snapshot endorsement validation and "
            "incomplete-suffix fallback succeeded"
        )


def run_recovery_join_snapshot(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as source, tempfile.TemporaryDirectory() as snapshot_dir:
        source.start_and_open(args)
        primary, _ = source.find_primary()
        target = app.LoggingTxs("user0").issue(source, number_txs=1)
        primary.trigger_snapshot()
        snapshot_path = primary.wait_for_snapshot(target.seqno)
        snapshot_name = os.path.basename(snapshot_path)
        snapshot_seqno, _ = ccf.ledger.snapshot_index_from_filename(snapshot_name)
        shutil.copy2(snapshot_path, snapshot_dir)
        source.save_service_identity(args)
        source.stop_all_nodes()
        ledger_dir, committed_ledger_dirs = primary.get_ledger()

        recovered = infra.network.Network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            existing_network=source,
        )
        try:
            recovered.start_in_recovery(
                args,
                ledger_dir=ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=snapshot_dir,
            )
            recovery_primary, _ = recovered.find_primary()
            tampered = args.tamper_snapshot_receipt
            if tampered:
                served_snapshot = next(
                    path
                    for path in recovery_primary.get_snapshots()
                    if os.path.basename(path) == snapshot_name
                )
                # The last byte is in the generated COSE Sign1 signature.
                # Keep the encrypted snapshot body and digest claim unchanged.
                with open(served_snapshot, "r+b") as snapshot:
                    snapshot.seek(-1, os.SEEK_END)
                    signature_byte = snapshot.read(1)
                    snapshot.seek(-1, os.SEEK_END)
                    snapshot.write(bytes([signature_byte[0] ^ 1]))
                recovered.ignore_errors_on_shutdown()

            joiners = []
            for local_snapshot in (True, False):
                joiner = recovered.create_node()
                recovered.join_node(
                    joiner,
                    args.package,
                    args,
                    recovery=True,
                    target_node=recovery_primary,
                    copy_ledger=False,
                    from_snapshot=local_snapshot,
                    snapshots_dir=snapshot_dir if local_snapshot else None,
                    fetch_recent_snapshot=True,
                )
                with joiner.client() as c:
                    state = c.get("/node/state").body.json()
                    assert (
                        state["state"] == infra.node.State.PART_OF_PUBLIC_NETWORK.value
                    )
                    assert state["startup_seqno"] == snapshot_seqno, state
                    assert c.get("/node/ready/app").status_code == (
                        http.HTTPStatus.SERVICE_UNAVAILABLE
                    )
                if not local_snapshot:
                    assert f"Received snapshot {snapshot_name} from peer" in _logs(
                        joiner
                    )
                joiners.append(joiner)

            if tampered:
                recovered.consortium.activate(recovery_primary)
                with open(args.previous_service_identity_file, encoding="utf-8") as f:
                    previous_identity = f.read()
                recovered.consortium.transition_service_to_open(
                    recovery_primary, previous_service_identity=previous_identity
                )
                recovered.consortium.recover_with_shares(recovery_primary)
                fetched_joiner = joiners[-1]
                assert fetched_joiner.remote.check_done(timeout=20)
                logs = _logs(fetched_joiner)
                assert "Failed to verify deferred recovery snapshot" in logs, logs
                assert "Deferred recovery snapshot signature verified" not in logs
                return

            recovered.recover(args)
            for joiner in joiners:
                assert "Deferred recovery snapshot signature verified" in _logs(joiner)
            for node in recovered.get_joined_nodes():
                with node.client() as c:
                    assert c.get("/node/ready/app").status_code == (
                        http.HTTPStatus.NO_CONTENT
                    )
            target = app.LoggingTxs("user0").issue(recovered, number_txs=1)
            recovery_primary.trigger_snapshot()
            recovery_primary.wait_for_snapshot(target.seqno)
            primary_snapshot_dir = os.path.join(
                recovery_primary.remote.remote.root,
                recovery_primary.remote.snapshots_dir_name,
            )
            for path in recovery_primary.get_snapshots():
                os.remove(path)
            shutil.copy2(
                os.path.join(snapshot_dir, snapshot_name), primary_snapshot_dir
            )
            for local_snapshot in (True, False):
                joiner = recovered.create_node()
                recovered.join_node(
                    joiner,
                    args.package,
                    args,
                    target_node=recovery_primary,
                    copy_ledger=False,
                    from_snapshot=local_snapshot,
                    snapshots_dir=snapshot_dir if local_snapshot else None,
                    fetch_recent_snapshot=True,
                )
                recovered.trust_node(joiner, args)
                with joiner.client() as c:
                    assert c.get("/node/state").body.json()["startup_seqno"] == (
                        snapshot_seqno
                    )
                assert (
                    "Join snapshot signature verified after authenticated "
                    "deserialisation"
                ) in _logs(joiner)
        finally:
            recovered.stop_all_nodes(skip_verification=True)


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
    for tampered in (False, True):
        cr.add(
            "recovery_join_snapshot_tampered" if tampered else "recovery_join_snapshot",
            run_recovery_join_snapshot,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.min_nodes(cr.args, f=0),
            ledger_chunk_bytes="50KB",
            snapshot_tx_interval=1000000,
            sig_tx_interval=1,
            tamper_snapshot_receipt=tampered,
        )
    cr.run()
