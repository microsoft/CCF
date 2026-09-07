# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import os
import shutil
import tempfile

import ccf.ledger
import governance_history
import infra.e2e_args
import infra.interfaces
import infra.logging_app as app
import infra.network
import recovery
from ccf.tx_id import TxID
from infra.remote import StartType
from infra.runner import ConcurrentRunner


def check_watermark(node, startup_seqno, expected):
    with node.client() as c:
        r = c.get("/node/state")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["startup_seqno"] == startup_seqno, r
    actual = node._get_local_ledger_start_seqno()
    assert actual == expected, (
        f"Node {node.local_node_id} ({node.remote.start_type.name}): "
        f"startup_seqno={startup_seqno}, local watermark={actual}, expected={expected}"
    )


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
        txs=app.LoggingTxs("user0"),
    ) as network:
        network.start_and_open(args)
        assert {n.remote.start_type for n in network.get_joined_nodes()} == {
            StartType.start,
            StartType.join,
        }
        for node in network.get_joined_nodes():
            check_watermark(node, startup_seqno=0, expected=1)

        primary, _ = network.find_primary()
        with tempfile.TemporaryDirectory() as snapshots_dir:
            snapshot_seqno = 0
            if args.from_snapshot:
                trigger = primary.trigger_snapshot()
                committed_snapshots = network.get_committed_snapshots(
                    primary,
                    target_seqno=trigger.seqno,
                    wait_for_target_seqno=True,
                )
                snapshot_name = ccf.ledger.latest_snapshot(committed_snapshots)
                assert snapshot_name is not None
                snapshot_seqno, _ = ccf.ledger.snapshot_index_from_filename(
                    snapshot_name
                )
                shutil.copy(
                    os.path.join(committed_snapshots, snapshot_name), snapshots_dir
                )

            # Freeze the recovery snapshot, then commit later old-service entries.
            # get_ledger() will place this committed prefix in read-only recovery input.
            network.txs.issue(network, number_txs=2)
            old_service_seqno = network.create_and_wait_for_ledger_chunk(primary)
            assert old_service_seqno > snapshot_seqno + 1

            recovered = recovery.test_recover_service(
                network,
                args,
                from_snapshot=args.from_snapshot,
                snapshots_dir=snapshots_dir if args.from_snapshot else None,
            )

        with infra.network.close_on_error(recovered, pdb=args.pdb):
            recovery_nodes = [
                n
                for n in recovered.get_joined_nodes()
                if n.remote.start_type == StartType.recover
            ]
            assert len(recovery_nodes) == 1
            recovery_node = recovery_nodes[0]
            with recovery_node.client() as c:
                r = c.get("/node/network")
                assert r.status_code == http.HTTPStatus.OK, r
                service_start = TxID.from_str(
                    r.body.json()["current_service_create_txid"]
                ).seqno
            assert service_start > old_service_seqno

            with recovery_node.client(
                interface_name=infra.interfaces.FILE_SERVING_RPC_INTERFACE
            ) as c:
                # This node reached primary via force_become_primary, not via
                # consensus's init_as_backup, so its host-side ledger init_idx
                # (src/host/ledger.h) is never set and stays 0. The "redirect to
                # next node" branch in file_serving_handlers.h only fires when
                # since_idx < init_idx, so it can never trigger here: this
                # request is guaranteed to fall through to 404, regardless of
                # how many other nodes are in the network.
                r = c.get(
                    f"/node/ledger_chunk?since={snapshot_seqno + 1}",
                    allow_redirects=False,
                )
                assert r.status_code == http.HTTPStatus.NOT_FOUND, r

            check_watermark(recovery_node, snapshot_seqno, service_start)
            joiners = [
                n
                for n in recovered.get_joined_nodes()
                if n.remote.start_type == StartType.join
            ]
            assert joiners
            for node in joiners:
                check_watermark(node, snapshot_seqno, snapshot_seqno + 1)

            governance_history.test_ledger_is_readable(recovered, args)
            recovered.stop_all_nodes()


if __name__ == "__main__":
    cr = ConcurrentRunner()
    for from_snapshot in (True, False):
        cr.add(
            "snapshot" if from_snapshot else "no_snapshot",
            run,
            from_snapshot=from_snapshot,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.max_nodes(cr.args, f=0),
            ledger_recovery_timeout=20,
        )
    cr.run()
