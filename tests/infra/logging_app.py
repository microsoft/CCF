# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.checker
import time
import requests

from loguru import logger as LOG


class LoggingTxs:
    def __init__(self, notifications_queue=None):
        self.pub = {}
        self.priv = {}
        self.next_pub_index = 0
        self.next_priv_index = 0
        self.notifications_queue = notifications_queue
        self.can_fail = False
        self.sync_timeout = 3
        self.sync = True

    def set_fail_tolerance(self, can_fail):
        self.can_fail = can_fail 
    
    def set_sync_timeout(self, timeout):
        self.sync_timeout = timeout
    
    def set_sync(self, sync):
        self.sync = sync

    def issue(self, network, number_txs, consensus, on_backup=False):
        LOG.success(f"Applying {number_txs} logging txs")
        primary, backup = network.find_primary_and_any_backup()
        remote_node = backup if on_backup else primary

        self.issue_on_node(network, remote_node, number_txs, consensus, on_backup=False)
    
    def issue_on_node(self, network, remote_node, number_txs, consensus, on_backup=False):
        LOG.success(f"Applying {number_txs} logging txs")
        with remote_node.node_client() as mc:
            check_commit = infra.checker.Checker(mc)
            check_commit_n = infra.checker.Checker(mc, self.notifications_queue)

            with remote_node.user_client() as uc:
                for _ in range(number_txs):
                    try:
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
                    except (TimeoutError, requests.exceptions.ReadTimeout,) as e:
                        LOG.info("Network is unavailable")
                        if not self.can_fail:
                            raise RuntimeError(e)
        
        if self.sync:
            self.node_commit_sync(network, consensus)
    

    def node_commit_sync(self, network, consensus):
        if self.can_fail:
            end_time = time.time() + self.sync_timeout
            while time.time() < end_time:
                try:
                    network.wait_for_node_commit_sync(consensus)
                    break
                except TimeoutError:
                        LOG.error(f"Timeout error while waiting for nodes to sync")
                        time.sleep(0.1)
        else:
            network.wait_for_node_commit_sync(consensus)

    def verify_pub_tx(self, node, pub_tx_index):
        with node.node_client() as mc:
            check = infra.checker.Checker(mc)
            with node.user_client() as uc:
                check(
                    uc.get("LOG_get_pub", {"id": pub_tx_index}),
                    result={"msg": self.pub[pub_tx_index]},
                )
    
    def verify_priv_tx(self, node, priv_tx_index):
        with node.node_client() as mc:
            check = infra.checker.Checker(mc)
            with node.user_client() as uc:
                check(
                    uc.get("LOG_get", {"id": priv_tx_index}),
                    result={"msg": self.priv[priv_tx_index]},
                )

    def verify(self, network):
        LOG.success("Verifying all logging txs")
        for n in network.get_joined_nodes():
            for pub_tx_index in self.pub:
                self.verify_pub_tx(n, pub_tx_index)
            for priv_tx_index in self.priv:
                self.verify_priv_tx(n, priv_tx_index)
    
    def verify_last_tx(self, network):
        LOG.success("Verifying last logging tx")
        for n in network.get_joined_nodes():
            self.verify_pub_tx(n, self.next_pub_index - 1)
            self.verify_priv_tx(n, self.next_priv_index - 1)