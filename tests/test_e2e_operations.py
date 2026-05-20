import infra.logging_app as app
import infra
from tests.e2e_operations import (
    test_backup_snapshot_fetch,
    test_backup_snapshot_fetch_max_size,
    test_error_message_on_failure_to_fetch_snapshot,
    test_join_idempotency_short_circuits_on_backup,
    test_join_time_snapshot_fetch_failure,
)


class BackupSnapshotDownload(infra.network.NetworkTestCase):
    label = "backup_snapshot_download"
    test_config_overrides = lambda args: {
        "snapshot_tx_interval": 30,
        "nodes": infra.e2e_args.max_nodes(args, f=0),
    }
    start_and_open_kwargs = {"backup_snapshot_fetch_enabled": True}
    network_kwargs = lambda _: {"txs": app.LoggingTxs("user0")}

    def test_backup_snapshot_fetch(self):
        test_backup_snapshot_fetch(self.network, self.args)

    def test_backup_snapshot_fetch_max_size(self):
        test_backup_snapshot_fetch_max_size(self.network, self.args)

    def test_join_idempotency_short_circuits_on_backup(self):
        test_join_idempotency_short_circuits_on_backup(self.network, self.args)

    def test_join_time_snapshot_fetch_failure(self):
        test_join_time_snapshot_fetch_failure(self.network, self.args)

    def test_error_message_on_failure_to_fetch_snapshot(self):
        test_error_message_on_failure_to_fetch_snapshot(self.network, self.args)
