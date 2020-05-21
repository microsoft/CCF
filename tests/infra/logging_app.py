# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.checker
import time
import requests

from loguru import logger as LOG


class LoggingTxs:
    def __init__(
        self,
        notifications_queue=None,
        tx_index_start=0,
        can_fail=False,
        wait_for_sync=True,
        timeout=3,
    ):
        self.pub = {}
        self.priv = {}
        self.next_pub_index = tx_index_start
        self.next_priv_index = tx_index_start
        self.notifications_queue = notifications_queue
        self.can_fail = can_fail
        self.timeout = timeout
        self.wait_for_sync = wait_for_sync
        self.tx_index_start = tx_index_start

    def issue(self, network, number_txs, consensus, on_backup=False):
        LOG.success(f"Applying {number_txs} logging txs")
        remote_node, _ = network.find_primary()
        if on_backup:
            remote_node = network.find_any_backup()

        self.issue_on_node(network, remote_node, number_txs, consensus)

    def issue_on_node(self, network, remote_node, number_txs, consensus):
        LOG.success(f"Applying {number_txs} logging txs to node {remote_node.node_id}")
        with remote_node.node_client() as mc:
            check_commit = infra.checker.Checker(mc)
            check_commit_n = infra.checker.Checker(mc, self.notifications_queue)

            with remote_node.user_client() as uc:
                for _ in range(self.tx_index_start, self.tx_index_start + number_txs):
                    end_time = time.time() + self.timeout
                    while time.time() < end_time:
                        try:
                            priv_msg = (
                                f"Private message at index {self.next_priv_index}"
                            )
                            pub_msg = f"Public message at index {self.next_pub_index}"
                            rep_priv = uc.rpc(
                                "LOG_record",
                                {"id": self.next_priv_index, "msg": priv_msg,},
                            )
                            rep_pub = uc.rpc(
                                "LOG_record_pub",
                                {"id": self.next_pub_index, "msg": pub_msg,},
                            )
                            check_commit_n(rep_priv, result=True)
                            check_commit(rep_pub, result=True)

                            self.priv[self.next_priv_index] = priv_msg
                            self.pub[self.next_pub_index] = pub_msg
                            self.next_priv_index += 1
                            self.next_pub_index += 1
                            break
                        except (TimeoutError, requests.exceptions.ReadTimeout,) as e:
                            LOG.info("Network is unavailable")
                            if not self.can_fail:
                                raise RuntimeError(e)

        if self.wait_for_sync:
            self.node_commit_sync(network, consensus)

    def node_commit_sync(self, network, consensus):
        end_time = time.time() + self.timeout
        while time.time() < end_time:
            try:
                network.wait_for_node_commit_sync(consensus)
                break
            except (TimeoutError, infra.clients.CCFConnectionException) as e:
                LOG.error("Timeout error while waiting for nodes to sync")
                if not self.can_fail:
                    raise RuntimeError(e)
                time.sleep(0.1)

    def verify(self, network):
        LOG.success("Verifying all logging txs")
        for n in network.get_joined_nodes():
            for pub_tx_index in self.pub:
                self._verify_pub_tx(n, pub_tx_index)
            for priv_tx_index in self.priv:
                self._verify_priv_tx(n, priv_tx_index)

    def verify_last_tx(self, network):
        LOG.success("Verifying last logging tx")
        for n in network.get_joined_nodes():
            self._verify_pub_tx(n, self.next_pub_index - 1)
            self._verify_priv_tx(n, self.next_priv_index - 1)

    def _verify_pub_tx(self, node, pub_tx_index):
        with node.node_client() as mc:
            check = infra.checker.Checker(mc)
            with node.user_client() as uc:
                check(
                    uc.get("LOG_get_pub", {"id": pub_tx_index}),
                    result={"msg": self.pub[pub_tx_index]},
                )

    def _verify_priv_tx(self, node, priv_tx_index):
        with node.node_client() as mc:
            check = infra.checker.Checker(mc)
            with node.user_client() as uc:
                check(
                    uc.get("LOG_get", {"id": priv_tx_index}),
                    result={"msg": self.priv[priv_tx_index]},
                )
