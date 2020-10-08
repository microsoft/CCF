# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.checker
import ccf.clients
import suite.test_requirements as reqs
import time
import http

from loguru import logger as LOG


class LoggingTxs:
    def __init__(self, user_id=0):
        self.pub = {}
        self.priv = {}
        self.next_pub_index = 1
        self.next_priv_index = 1
        self.user = f"user{user_id}"

    def issue(
        self,
        network,
        number_txs,
        on_backup=False,
    ):
        remote_node, _ = network.find_primary()
        if on_backup:
            remote_node = network.find_any_backup()

        LOG.info(f"Applying {number_txs} logging txs to node {remote_node.node_id}")

        with remote_node.client(self.user) as uc:
            check_commit = infra.checker.Checker(uc)
            check_commit_n = infra.checker.Checker(uc)

            for _ in range(number_txs):
                priv_msg = f"Private message at index {self.next_priv_index}"
                pub_msg = f"Public message at index {self.next_pub_index}"
                rep_priv = uc.post(
                    "/app/log/private",
                    {
                        "id": self.next_priv_index,
                        "msg": priv_msg,
                    },
                )
                rep_pub = uc.post(
                    "/app/log/public",
                    {
                        "id": self.next_pub_index,
                        "msg": pub_msg,
                    },
                )
                check_commit_n(rep_priv, result=True)
                check_commit(rep_pub, result=True)

                self.priv[self.next_priv_index] = priv_msg
                self.pub[self.next_pub_index] = pub_msg
                self.next_priv_index += 1
                self.next_pub_index += 1

        network.wait_for_node_commit_sync()

    def verify(self, network, timeout=3):
        LOG.info("Verifying all logging txs")
        for n in network.get_joined_nodes():
            for pub_tx_index in self.pub:
                self._verify_tx(n, pub_tx_index, priv=False, timeout=timeout)
            for priv_tx_index in self.priv:
                self._verify_tx(n, priv_tx_index, priv=True, timeout=timeout)

    def _verify_tx(self, node, idx, priv=True, timeout=3):
        txs = self.priv if priv else self.pub
        cmd = "/app/log/private" if priv else "/app/log/public"

        end_time = time.time() + timeout
        while time.time() < end_time:
            with node.client(self.user) as uc:
                rep = uc.get(f"{cmd}?id={idx}")
                if rep.status_code == http.HTTPStatus.NOT_FOUND.value:
                    LOG.warning("User frontend is not yet opened")
                    time.sleep(0.1)
                else:
                    check = infra.checker.Checker(uc)
                    check(
                        rep,
                        result={"msg": txs[idx]},
                    )
                    break
