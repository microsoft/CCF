# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.checker
import infra.jwt_issuer
import time
import http
import random
import infra.clients
import infra.commit
from collections import defaultdict
from ccf.tx_id import TxID


from loguru import logger as LOG


class LoggingTxsVerifyException(Exception):
    """
    Exception raised if a LoggingTxs instance cannot successfully verify all
    entries previously issued.
    """


def sample_list(l, n):
    if n > len(l):
        # Return all elements
        return l
    elif n == 0:
        return []
    elif n == 1:
        # Return last element only
        return l[-1:]
    elif n == 2:
        # Return first and last elements
        return l[:1] + l[-1:]
    else:
        # Return first, last, and random sample of values in-between
        return l[:1] + random.sample(l[1:-1], n - 2) + l[-1:]


class LoggingTxs:
    def __init__(self, user_id=None, jwt_issuer=None):
        self.pub = defaultdict(list)
        self.priv = defaultdict(list)
        self.idx = 0
        self.network = None
        self.user = user_id
        self.jwt_issuer = jwt_issuer
        assert (
            self.user or self.jwt_issuer
        ), "User identity or JWT issuer are required to issue logging txs"

    def clear(self):
        self.pub.clear()
        self.priv.clear()
        self.idx = 0

    def _get_headers_base(self):
        return (
            infra.jwt_issuer.make_bearer_header(self.jwt_issuer.issue_jwt())
            if self.jwt_issuer
            else {}
        )

    def get_last_tx(self, priv=True, idx=None):
        if idx is None:
            idx = self.idx
        txs = self.priv if priv else self.pub
        msgs = txs[idx]
        return (idx, msgs[-1])

    def find_max_log_id(self):
        max_id = None
        for txs in [self.priv, self.pub]:
            for k in txs:
                if max_id is None or k > max_id:
                    max_id = k
        return 0 if max_id is None else max_id

    def get_log_id(self, txid):
        for p in [True, False]:
            txs = self.priv if p else self.pub
            for k, v in txs.items():
                for e in v:
                    if e["seqno"] == txid.seqno:
                        return (p, k)
        raise ValueError("tx not found")

    def issue(
        self,
        network,
        number_txs=1,
        on_backup=False,
        repeat=False,
        idx=None,
        wait_for_sync=True,
        log_capture=None,
        send_private=True,
        send_public=True,
        record_claim=False,
    ):
        self.network = network
        remote_node, _ = network.find_primary(log_capture=log_capture)
        if on_backup:
            remote_node = network.find_any_backup()

        LOG.info(
            f"Applying {number_txs} logging txs to node {remote_node.local_node_id}"
        )

        with remote_node.client(self.user) as c:
            check_commit = infra.checker.Checker(c)

            for _ in range(number_txs):
                if not repeat and idx is None:
                    self.idx += 1

                target_idx = idx
                if target_idx is None:
                    target_idx = self.idx

                if send_private:
                    priv_msg = f"Private message at idx {target_idx} [{len(self.priv[target_idx])}]"
                    rep_priv = c.post(
                        "/app/log/private",
                        {
                            "id": target_idx,
                            "msg": priv_msg,
                        },
                        headers=self._get_headers_base(),
                        log_capture=log_capture,
                    )
                    assert rep_priv.status_code == http.HTTPStatus.OK, rep_priv
                    self.priv[target_idx].append(
                        {
                            "msg": priv_msg,
                            "seqno": rep_priv.seqno,
                            "view": rep_priv.view,
                        }
                    )
                    wait_point = rep_priv

                if send_public:
                    pub_msg = f"Public message at idx {target_idx} [{len(self.pub[target_idx])}]"
                    payload = {
                        "id": target_idx,
                        "msg": pub_msg,
                    }
                    if record_claim:
                        payload["record_claim"] = True
                    rep_pub = c.post(
                        "/app/log/public",
                        payload,
                        headers=self._get_headers_base(),
                        log_capture=log_capture,
                    )
                    assert rep_pub.status_code == http.HTTPStatus.OK, rep_pub
                    self.pub[target_idx].append(
                        {"msg": pub_msg, "seqno": rep_pub.seqno, "view": rep_pub.view}
                    )
                    wait_point = rep_pub
            if number_txs and wait_for_sync:
                check_commit(wait_point, result=True)

        if wait_for_sync:
            network.wait_for_all_nodes_to_commit(
                tx_id=TxID(wait_point.view, wait_point.seqno)
            )
        return TxID(wait_point.view, wait_point.seqno)

    def verify(
        self,
        network=None,
        node=None,
        timeout=3,
        log_capture=None,
        include_historical=True,
    ):
        if network is not None:
            self.network = network
        if self.network is None:
            raise ValueError(
                "Network object is not yet set - txs should be issued before calling verify"
            )

        sample_count = 5
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
                    log_capture=log_capture,
                )

            for priv_idx, priv_value in self.priv.items():
                # Verifying all historical transactions is expensive, verify only a sample
                for v in sample_list(priv_value, sample_count):
                    is_historical_entry = v != priv_value[-1]
                    if not is_historical_entry or include_historical:
                        self._verify_tx(
                            node,
                            priv_idx,
                            v["msg"],
                            v["seqno"],
                            v["view"],
                            priv=True,
                            historical=is_historical_entry,
                            timeout=timeout,
                            log_capture=log_capture,
                        )

        LOG.info("Successfully verified logging txs")

    def _verify_tx(
        self,
        node,
        idx,
        msg,
        seqno,
        view,
        priv=True,
        historical=False,
        log_capture=None,
        timeout=3,
    ):
        if historical and not priv:
            raise ValueError(
                "Historical queries are only implemented with private records"
            )

        cmd = "/app/log/private" if priv else "/app/log/public"
        headers = self._get_headers_base()
        if historical:
            cmd = "/app/log/private/historical"
            headers.update(
                {
                    infra.clients.CCF_TX_ID_HEADER: f"{view}.{seqno}",
                }
            )

        found = False
        start_time = time.time()
        while time.time() < (start_time + timeout):
            with node.client(self.user) as c:
                infra.commit.wait_for_commit(
                    c, seqno, view, timeout, log_capture=log_capture
                )

                rep = c.get(f"{cmd}?id={idx}", headers=headers, log_capture=log_capture)
                if rep.status_code == http.HTTPStatus.OK:
                    expected_result = {"msg": msg}
                    assert (
                        rep.body.json() == expected_result
                    ), "Expected {}, got {}".format(expected_result, rep.body)
                    found = True
                    break
                elif rep.status_code == http.HTTPStatus.NOT_FOUND:
                    LOG.warning("User frontend is not yet opened")
                    time.sleep(0.1)
                    continue

                if historical:
                    if rep.status_code == http.HTTPStatus.ACCEPTED:
                        retry_after = rep.headers.get("retry-after")
                        if retry_after is None:
                            raise ValueError(
                                f"Response with status {rep.status_code} is missing 'retry-after' header"
                            )
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
                f"Unable to retrieve entry at TxID {view}.{seqno} (idx:{idx}) on node {node.local_node_id} after {timeout}s"
            )

    def get_receipt(self, node, idx, seqno, view, timeout=3, domain="private"):

        cmd = f"/app/log/{domain}/historical_receipt"
        headers = self._get_headers_base()
        headers.update(
            {
                infra.clients.CCF_TX_ID_HEADER: f"{view}.{seqno}",
            }
        )

        found = False
        start_time = time.time()
        while time.time() < (start_time + timeout):
            with node.client(self.user) as c:
                infra.commit.wait_for_commit(c, seqno, view, timeout)

                rep = c.get(f"{cmd}?id={idx}", headers=headers)
                if rep.status_code == http.HTTPStatus.OK:
                    return rep.body
                elif rep.status_code == http.HTTPStatus.NOT_FOUND:
                    LOG.warning("User frontend is not yet opened")
                    continue

                if rep.status_code == http.HTTPStatus.ACCEPTED:
                    retry_after = rep.headers.get("retry-after")
                    if retry_after is None:
                        raise ValueError(
                            f"Response with status {rep.status_code} is missing 'retry-after' header"
                        )
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
                f"Unable to retrieve entry at TxID {view}.{seqno} (idx:{idx}) on node {node.local_node_id} after {timeout}s"
            )

    def delete(self, log_id, priv=False, log_capture=None):
        primary, _ = self.network.find_primary(log_capture=log_capture)
        check = infra.checker.Checker()
        with primary.client(self.user) as c:
            table = "private" if priv else "public"
            check(
                c.delete(
                    f"/app/log/{table}?id={log_id}", headers=self._get_headers_base()
                )
            )
            if priv:
                self.priv.pop(log_id)
            else:
                self.pub.pop(log_id)

    def request(self, log_id, priv=False, log_capture=None):
        primary, _ = self.network.find_primary(log_capture=log_capture)
        with primary.client(self.user) as c:
            table = "private" if priv else "public"
            return c.get(
                f"/app/log/{table}?id={log_id}", headers=self._get_headers_base()
            )
