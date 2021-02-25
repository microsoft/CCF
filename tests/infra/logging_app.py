# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.checker
import time
import http
import ccf.clients
import ccf.commit
from collections import defaultdict


from loguru import logger as LOG


class LoggingTxsVerifyException(Exception):
    """
    Exception raised if a LoggingTxs instance cannot successfully verify all
    entries previously issued.
    """


class LoggingTxs:
    def __init__(self, user_id=0):
        self.pub = defaultdict(list)
        self.priv = defaultdict(list)
        self.idx = 0
        self.user = f"user{user_id}"
        self.network = None

    def get_last_tx(self, priv=True):
        txs = self.priv if priv else self.pub
        idx, msgs = list(txs.items())[-1]
        return (idx, msgs[-1])

    def issue(
        self,
        network,
        number_txs=1,
        on_backup=False,
        repeat=False,
    ):
        self.network = network
        remote_node, _ = network.find_primary()
        if on_backup:
            remote_node = network.find_any_backup()

        LOG.info(f"Applying {number_txs} logging txs to node {remote_node.node_id}")

        with remote_node.client(self.user) as c:
            check_commit = infra.checker.Checker(c)

            for _ in range(number_txs):
                if not repeat:
                    self.idx += 1

                priv_msg = (
                    f"Private message at idx {self.idx} [{len(self.priv[self.idx])}]"
                )
                rep_priv = c.post(
                    "/app/log/private",
                    {
                        "id": self.idx,
                        "msg": priv_msg,
                    },
                )
                self.priv[self.idx].append(
                    {"msg": priv_msg, "seqno": rep_priv.seqno, "view": rep_priv.view}
                )

                pub_msg = (
                    f"Public message at idx {self.idx} [{len(self.pub[self.idx])}]"
                )
                rep_pub = c.post(
                    "/app/log/public",
                    {
                        "id": self.idx,
                        "msg": pub_msg,
                    },
                )
                self.pub[self.idx].append(
                    {"msg": pub_msg, "seqno": rep_pub.seqno, "view": rep_pub.view}
                )
            if number_txs:
                check_commit(rep_pub, result=True)

        network.wait_for_node_commit_sync()

    def verify(self, network=None, node=None, timeout=3):
        LOG.info("Verifying all logging txs")
        if network is not None:
            self.network = network
        if self.network is None:
            raise ValueError(
                "Network object is not yet set - txs should be issued before calling verify"
            )

        nodes = self.network.get_joined_nodes() if node is None else [node]
        for node in nodes:
            for pub_idx, pub_value in self.pub.items():
                # As public records do not yet handle historical queries,
                # only verify the latest entry
                entry = pub_value[-1]
                self._verify_tx(
                    node,
                    pub_idx,
                    entry["msg"],
                    entry["seqno"],
                    entry["view"],
                    priv=False,
                    timeout=timeout,
                )

            for priv_idx, priv_value in self.priv.items():
                for v in priv_value:
                    self._verify_tx(
                        node,
                        priv_idx,
                        v["msg"],
                        v["seqno"],
                        v["view"],
                        priv=True,
                        historical=True,
                        timeout=timeout,
                    )

    def _verify_tx(
        self, node, idx, msg, seqno, view, priv=True, historical=False, timeout=3
    ):
        if historical and not priv:
            raise ValueError(
                "Historical queries are only implemented with private records"
            )

        cmd = "/app/log/private" if priv else "/app/log/public"
        headers = {}
        if historical:
            cmd = "/app/log/private/historical"
            headers = {
                ccf.clients.CCF_TX_VIEW_HEADER: str(view),
                ccf.clients.CCF_TX_SEQNO_HEADER: str(seqno),
            }

        found = False
        start_time = time.time()
        while time.time() < (start_time + timeout):
            with node.client(self.user) as c:
                ccf.commit.wait_for_commit(c, seqno, view, timeout)

                rep = c.get(f"{cmd}?id={idx}", headers=headers)
                if rep.status_code == http.HTTPStatus.OK:
                    expected_result = {"msg": msg}
                    assert (
                        rep.body.json() == expected_result
                    ), "Expected {}, got {}".format(expected_result, rep.body)
                    found = True
                    break
                elif rep.status_code == http.HTTPStatus.NOT_FOUND:
                    LOG.warning("User frontend is not yet opened")
                    continue

                if historical:
                    if rep.status_code == http.HTTPStatus.ACCEPTED:
                        retry_after = rep.headers.get("retry-after")
                        if retry_after is None:
                            raise ValueError(
                                f"Response with status {rep.status_code} is missing 'retry-after' header"
                            )
                        retry_after = int(retry_after)
                        LOG.info(
                            f"Sleeping for {retry_after}s waiting for historical query processing..."
                        )
                        # Bump the timeout enough so that it is likely that the next
                        # command will have time to be issued, without causing this
                        # to loop for too long if the entry cannot be found
                        timeout += retry_after * 0.8
                        time.sleep(retry_after)
                    elif rep.status_code == http.HTTPStatus.NO_CONTENT:
                        raise ValueError(
                            f"Historical query response claims there was no write to {idx} at {view}.{seqno}"
                        )
                    else:
                        raise ValueError(
                            f"Unexpected response status code {rep.status_code}: {rep.body}"
                        )
                time.sleep(0.1)

        if not found:
            raise LoggingTxsVerifyException(
                f"Unable to retrieve entry at {idx} (seqno: {seqno}, view: {view}) after {timeout}s"
            )
