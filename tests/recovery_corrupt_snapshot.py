# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import re
import shutil

import ccf.ledger
import infra.e2e_args
import infra.logging_app as app
import infra.network
import infra.node
from infra.runner import ConcurrentRunner


def run_recovery_corrupt_snapshot(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()

        for _ in range(2):
            app.LoggingTxs("user0").issue(
                network,
                number_txs=2,
                send_private=False,
                send_public=True,
                wait_for_sync=True,
            )
            snapshot_trigger = primary.trigger_snapshot()
            committed_snapshots_dir = network.get_committed_snapshots(
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
        valid_snapshot_name = snapshots[-2]
        corrupt_snapshot_name = snapshots[-1]

        recovery_snapshots_dir = os.path.join(
            network.common_dir, "recovery_corrupt_snapshot"
        )
        shutil.rmtree(recovery_snapshots_dir, ignore_errors=True)
        os.makedirs(recovery_snapshots_dir)
        shutil.copy(
            os.path.join(committed_snapshots_dir, valid_snapshot_name),
            recovery_snapshots_dir,
        )
        corrupt_snapshot_path = shutil.copy(
            os.path.join(committed_snapshots_dir, corrupt_snapshot_name),
            recovery_snapshots_dir,
        )
        with open(corrupt_snapshot_path, "r+b") as corrupt_snapshot:
            # Remain non-empty so discovery selects this before the valid snapshot.
            corrupt_snapshot.truncate(1)

        network.save_service_identity(args)
        network.stop_all_nodes()
        current_ledger_dir, committed_ledger_dirs = primary.get_ledger()

        recovered = infra.network.Network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            existing_network=network,
        )
        with infra.network.close_on_error(recovered):
            recovered.start_in_recovery(
                args,
                ledger_dir=current_ledger_dir,
                committed_ledger_dirs=committed_ledger_dirs,
                snapshots_dir=recovery_snapshots_dir,
            )
            recovered.recover(args)

            recovered_primary, _ = recovered.find_primary()
            expected_seqno = infra.node.get_snapshot_seqnos(valid_snapshot_name)[0]
            out_path, _ = recovered_primary.get_logs()
            assert out_path is not None
            with open(out_path, encoding="utf-8", errors="replace") as output:
                startup_seqnos = [
                    int(match.group(1))
                    for line in output
                    if (
                        match := re.search(
                            r"Setting startup snapshot seqno to (\d+)", line
                        )
                    )
                ]
            assert startup_seqnos == [expected_seqno], startup_seqnos


if __name__ == "__main__":
    cr = ConcurrentRunner()
    cr.add(
        "recovery_corrupt_snapshot",
        run_recovery_corrupt_snapshot,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=10,
        sig_tx_interval=1,
    )
    cr.run()
