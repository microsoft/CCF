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


def _copy_recovery_snapshot_cache(network, destination):
    primary, _ = network.find_primary()
    copied = network.get_committed_snapshots(primary, force_txs=False)
    shutil.rmtree(destination, ignore_errors=True)
    shutil.copytree(copied, destination)
    return destination


def _verify_snapshot_cache(
    snapshots_dir, snapshot_name, snapshot_digest, target_identity
):
    snapshot_path = os.path.join(snapshots_dir, snapshot_name)
    sidecar_path = ccf.ledger.snapshot_endorsements_path(snapshot_path)
    assert os.path.isfile(sidecar_path), sidecar_path
    with open(snapshot_path, "rb") as snapshot_file:
        assert hashlib.sha256(snapshot_file.read()).digest() == snapshot_digest

    endorsements = ccf.ledger.read_snapshot_endorsements(sidecar_path)
    assert len(endorsements) == 2, len(endorsements)
    with ccf.ledger.Snapshot(snapshot_path) as snapshot:
        snapshot.verify_cose_receipt(target_identity, endorsements)
    return sidecar_path


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
        with open(original_snapshot_path, "rb") as snapshot_file:
            snapshot_digest = hashlib.sha256(snapshot_file.read()).digest()

        source_snapshots_dir = os.path.join(
            initial_network.common_dir, "recovery_snapshot_endorsements_source"
        )
        shutil.rmtree(source_snapshots_dir, ignore_errors=True)
        os.makedirs(source_snapshots_dir)
        shutil.copy(original_snapshot_path, source_snapshots_dir)

        first_recovery, first_args = _recover_and_open(
            initial_network, args, f"{args.label}_identity_1"
        )
        second_recovery, second_args = _recover_and_open(
            first_recovery, first_args, f"{args.label}_identity_2"
        )

        second_recovery.save_service_identity(second_args)
        target_identity_file = second_args.previous_service_identity_file
        with open(target_identity_file, "rb") as target_file:
            target_identity = target_file.read()
        primary, _ = second_recovery.find_primary()
        second_recovery.stop_all_nodes()
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

        cache_dir = os.path.join(
            second_recovery.common_dir, "recovery_snapshot_endorsements_cache"
        )
        first_attempt = _start_recovery_attempt(
            second_recovery,
            second_args,
            f"{args.label}_derive_sidecar",
            current_ledger_dir,
            committed_ledger_dirs,
            source_snapshots_dir,
            target_identity_file,
            100,
        )
        try:
            first_primary, _ = first_attempt.find_primary()
            logs = _logs(first_primary)
            scan_log = "scanning the public ledger suffix for COSE endorsements"
            persisted_log = "Persisted 2 verified recovery snapshot endorsement(s)"
            snapshot_body_log = "Deserialising snapshot (size:"
            public_recovery_log = "Starting to read public ledger"
            assert (
                logs.index(scan_log)
                < logs.index(persisted_log)
                < logs.index(snapshot_body_log)
                < logs.index(public_recovery_log)
            )
            _copy_recovery_snapshot_cache(first_attempt, cache_dir)
            sidecar_path = _verify_snapshot_cache(
                cache_dir, snapshot_name, snapshot_digest, target_identity
            )
        finally:
            _stop_incomplete_recovery(first_attempt)

        reuse_attempt = _start_recovery_attempt(
            second_recovery,
            second_args,
            f"{args.label}_reuse_sidecar",
            current_ledger_dir,
            committed_ledger_dirs,
            cache_dir,
            target_identity_file,
            101,
        )
        try:
            reuse_primary, _ = reuse_attempt.find_primary()
            assert "Reusing verified snapshot endorsements sidecar" in _logs(
                reuse_primary
            )
        finally:
            _stop_incomplete_recovery(reuse_attempt)

        with open(sidecar_path, "rb") as sidecar_file:
            tampered = bytearray(sidecar_file.read())
        tampered[-1] ^= 0xFF
        with open(sidecar_path, "wb") as sidecar_file:
            sidecar_file.write(tampered)

        tamper_attempt = _start_recovery_attempt(
            second_recovery,
            second_args,
            f"{args.label}_replace_tampered_sidecar",
            current_ledger_dir,
            committed_ledger_dirs,
            cache_dir,
            target_identity_file,
            102,
        )
        try:
            tamper_primary, _ = tamper_attempt.find_primary()
            logs = _logs(tamper_primary)
            assert "Snapshot endorsements sidecar" in logs
            assert "is invalid" in logs
            assert "Persisted 2 verified recovery snapshot endorsement(s)" in logs
            _copy_recovery_snapshot_cache(tamper_attempt, cache_dir)
            _verify_snapshot_cache(
                cache_dir, snapshot_name, snapshot_digest, target_identity
            )
        finally:
            _stop_incomplete_recovery(tamper_attempt)

        fallback_dir = os.path.join(
            second_recovery.common_dir, "recovery_snapshot_endorsements_fallback"
        )
        shutil.rmtree(fallback_dir, ignore_errors=True)
        os.makedirs(fallback_dir)
        shutil.copy(os.path.join(cache_dir, snapshot_name), fallback_dir)
        wrong_identity_file = second_recovery.consortium.user_cert_path("user0")

        fallback_attempt = _start_recovery_attempt(
            second_recovery,
            second_args,
            f"{args.label}_fallback",
            current_ledger_dir,
            committed_ledger_dirs,
            fallback_dir,
            wrong_identity_file,
            103,
        )
        try:
            fallback_primary, _ = fallback_attempt.find_primary()
            logs = _logs(fallback_primary)
            assert "Falling back to full-ledger recovery" in logs
            assert "Setting startup snapshot seqno" not in logs
            assert not os.path.exists(
                ccf.ledger.snapshot_endorsements_path(
                    os.path.join(fallback_dir, snapshot_name)
                )
            )
        finally:
            _stop_incomplete_recovery(fallback_attempt)

        LOG.success(
            "Recovery snapshot sidecar derivation, verification, reuse, "
            "tamper replacement, and fallback all succeeded"
        )


if __name__ == "__main__":

    def add(parser):
        parser.description = (
            "Verify recovery snapshot COSE endorsement sidecars across multiple "
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
