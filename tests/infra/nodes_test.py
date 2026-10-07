# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import unittest
from unittest import mock

import nodes


class NodeAcknowledgementsTest(unittest.TestCase):
    def make_network(self, live_ack_age=7, backup_ack_age=0):
        def response(body):
            result = mock.Mock()
            result.status_code = 200
            result.body.json.return_value = body
            return result

        old_primary = mock.MagicMock(node_id="stopped")
        new_primary = mock.MagicMock(node_id="primary")
        backup = mock.MagicMock(node_id="backup")
        old_primary.client.return_value.__enter__.return_value.get.return_value = (
            response({"view_history": ["1.1"]})
        )
        new_primary.client.return_value.__enter__.return_value.get.side_effect = [
            response({"view_history": ["1.1", "2.2"]}),
            response({}),
            response(
                {
                    "details": {
                        "acks": {
                            "stopped": {"last_received_ms": 1072, "seqno": 0},
                            "backup": {"last_received_ms": live_ack_age, "seqno": 29},
                        }
                    }
                }
            ),
        ]
        backup.client.return_value.__enter__.return_value.get.side_effect = [
            response({}),
            response(
                {
                    "details": {
                        "acks": {
                            "stopped": {"last_received_ms": backup_ack_age},
                            "primary": {"last_received_ms": backup_ack_age},
                        }
                    }
                }
            ),
        ]
        network = mock.Mock()
        network.args.election_timeout_ms = 1000
        network.find_primary_and_any_backup.return_value = old_primary, backup
        network.wait_for_new_primary.return_value = new_primary, 2
        network.get_joined_nodes.return_value = [new_primary, backup]
        return network

    def test_stopped_peer_ack_can_expire(self):
        network = self.make_network()
        with mock.patch("nodes.wait_for_committed_tx_in_current_view"):
            self.assertIs(
                nodes.test_kill_primary_no_reqs(network, network.args), network
            )

    def test_live_peer_ack_must_be_fresh(self):
        for age in (1000, 1072):
            with (
                self.subTest(age=age),
                mock.patch("nodes.wait_for_committed_tx_in_current_view"),
                self.assertRaises(AssertionError),
            ):
                network = self.make_network(live_ack_age=age)
                nodes.test_kill_primary_no_reqs(network, network.args)

    def test_backup_ack_age_must_still_be_zero(self):
        network = self.make_network(backup_ack_age=1)
        with (
            mock.patch("nodes.wait_for_committed_tx_in_current_view"),
            self.assertRaisesRegex(
                AssertionError, "should report time of last acks of 0"
            ),
        ):
            nodes.test_kill_primary_no_reqs(network, network.args)


if __name__ == "__main__":
    unittest.main()
