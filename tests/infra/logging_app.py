# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.checker
import suite.test_requirements as reqs
import time

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("log/private", "log/public")
def test_run_txs(
    network,
    args,
    nodes=None,
    num_txs=1,
    verify=True,
    timeout=3,
    ignore_failures=False,
    wait_for_sync=False,
):
    if nodes is None:
        nodes = network.get_joined_nodes()
    num_nodes = len(nodes)

    for tx in range(num_txs):
        network.txs.issue_on_node(
            network=network,
            remote_node=nodes[tx % num_nodes],
            number_txs=1,
            consensus=args.consensus,
            timeout=timeout,
            ignore_failures=ignore_failures,
            wait_for_sync=wait_for_sync,
        )

    if verify:
        network.txs.verify_last_tx(network)
    else:
        LOG.warning("Skipping log messages verification")

    return network


class LoggingTxs:
    def __init__(
        self, notifications_queue=None,
    ):
        self.pub = {}
        self.priv = {}
        self.next_pub_index = 1
        self.next_priv_index = 1
        self.notifications_queue = notifications_queue

    def issue(
        self,
        network,
        number_txs,
        consensus,
        on_backup=False,
        ignore_failures=False,
        wait_for_sync=True,
        timeout=3,
    ):
        remote_node, _ = network.find_primary()
        if on_backup:
            remote_node = network.find_any_backup()

        self.issue_on_node(
            network,
            remote_node,
            number_txs,
            consensus,
            ignore_failures,
            wait_for_sync,
            timeout,
        )

    def issue_on_node(
        self,
        network,
        remote_node,
        number_txs,
        consensus,
        ignore_failures=False,
        wait_for_sync=True,
        timeout=3,
    ):
        LOG.success(f"Applying {number_txs} logging txs to node {remote_node.node_id}")
        with remote_node.client() as mc:
            check_commit = infra.checker.Checker(mc)
            check_commit_n = infra.checker.Checker(mc, self.notifications_queue)

            with remote_node.client("user0") as uc:
                for _ in range(number_txs):
                    end_time = time.time() + timeout
                    while time.time() < end_time:
                        try:
                            priv_msg = (
                                f"Private message at index {self.next_priv_index}"
                            )
                            pub_msg = f"Public message at index {self.next_pub_index}"
                            rep_priv = uc.rpc(
                                "/app/log/private",
                                {"id": self.next_priv_index, "msg": priv_msg,},
                            )
                            rep_pub = uc.rpc(
                                "/app/log/public",
                                {"id": self.next_pub_index, "msg": pub_msg,},
                            )
                            check_commit_n(rep_priv, result=True)
                            check_commit(rep_pub, result=True)

                            self.priv[self.next_priv_index] = priv_msg
                            self.pub[self.next_pub_index] = pub_msg
                            self.next_priv_index += 1
                            self.next_pub_index += 1
                            break
                        except (
                            TimeoutError,
                            infra.clients.CCFConnectionException,
                        ):
                            LOG.debug("Network is unavailable")
                            if not ignore_failures:
                                raise

        if wait_for_sync:
            self.node_commit_sync(network, consensus, timeout, ignore_failures)

    def node_commit_sync(self, network, consensus, timeout=3, ignore_failures=False):
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                network.wait_for_node_commit_sync(consensus)
                break
            except (TimeoutError, infra.clients.CCFConnectionException):
                LOG.error("Timeout error while waiting for nodes to sync")
                if not ignore_failures:
                    raise
                time.sleep(0.1)

    def verify(self, network, timeout=5):
        LOG.success("Verifying all logging txs")
        for n in network.get_joined_nodes():
            for pub_tx_index in self.pub:
                self._verify_tx(n, pub_tx_index, priv=False, timeout=timeout)
            for priv_tx_index in self.priv:
                self._verify_tx(n, priv_tx_index, priv=True, timeout=timeout)

    def verify_last_tx(self, network, timeout=5):
        LOG.success("Verifying last logging tx")
        for n in network.get_joined_nodes():
            self._verify_tx(n, self.next_pub_index - 1, priv=False, timeout=timeout)
            self._verify_tx(n, self.next_priv_index - 1, priv=True, timeout=timeout)

    def _verify_tx(self, node, idx, priv=True, timeout=5):
        txs = self.priv if priv else self.pub
        cmd = "/app/log/private" if priv else "/app/log/public"

        end_time = time.time() + timeout
        while time.time() < end_time:
            with node.client("user0") as uc:
                rep = uc.get(cmd, {"id": idx})
                if rep.status == 404:
                    LOG.warning("User frontend is not yet opened")
                    time.sleep(0.1)
                else:
                    check = infra.checker.Checker(uc)
                    check(
                        rep, result={"msg": txs[idx]},
                    )
                    break
