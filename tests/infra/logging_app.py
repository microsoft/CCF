# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.ccf

from loguru import logger as LOG


class LoggingTxs:
    def __init__(self, notifications_queue=None):
        self.pub = {}
        self.priv = {}
        self.next_pub_index = 0
        self.next_priv_index = 0
        self.notifications_queue = notifications_queue

    def issue(self, network, number_txs, on_backup=False):
        LOG.success(f"Applying {number_txs} logging txs")
        primary, backup = network.find_primary_and_any_backup()
        remote_node = backup if on_backup else primary

        with remote_node.node_client(format="json") as mc:
            check_commit = infra.checker.Checker(mc)
            check_commit_n = infra.checker.Checker(mc, self.notifications_queue)

            with remote_node.user_client(format="json") as uc:
                for _ in range(number_txs):
                    priv_msg = f"Private message at index {self.next_priv_index}"
                    pub_msg = f"Public message at index {self.next_pub_index}"
                    rep_priv = uc.rpc(
                        "LOG_record", {"id": self.next_priv_index, "msg": priv_msg,},
                    )
                    rep_pub = uc.rpc(
                        "LOG_record_pub", {"id": self.next_pub_index, "msg": pub_msg,},
                    )
                    check_commit_n(rep_priv, result=True)
                    check_commit(rep_pub, result=True)

                    self.priv[self.next_priv_index] = priv_msg
                    self.pub[self.next_pub_index] = pub_msg
                    self.next_priv_index += 1
                    self.next_pub_index += 1

        network.wait_for_node_commit_sync()

    def verify(self, network):
        LOG.success(f"Verifying all logging txs")
        primary, term = network.find_primary()

        with primary.node_client(format="json") as mc:
            check = infra.checker.Checker()

            with primary.user_client(format="json") as uc:

                for pub_tx_index in self.pub:
                    check(
                        uc.rpc("LOG_get_pub", {"id": pub_tx_index}),
                        result={"msg": self.pub[pub_tx_index]},
                    )

                for priv_tx_index in self.priv:
                    check(
                        uc.rpc("LOG_get", {"id": priv_tx_index}),
                        result={"msg": self.priv[priv_tx_index]},
                    )
