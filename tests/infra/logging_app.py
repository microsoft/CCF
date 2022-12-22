# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import functools
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


class LoggingTxsIssueException(Exception):
    """
    Exception raised if a LoggingTxs instance cannot successfully issue a
    new entry.
    """

    def __init__(self, response, *args, **kwargs):
        super(LoggingTxsIssueException, self).__init__(*args, **kwargs)
        self.response = response


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
    def __init__(self, user_id=None, jwt_issuer=None, scope=None):
        self.scope = scope
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
        msg=None,
        user=None,
        url_suffix=None,
        private_url=None,
    ):
        self.network = network
        if on_backup:
            remote_node = network.find_any_backup(log_capture=log_capture)
        else:
            remote_node, _ = network.find_primary(log_capture=log_capture)

        LOG.info(
            f"Applying {number_txs} logging txs to node {remote_node.local_node_id}"
        )

        headers = None
        if not user:
            headers = self._get_headers_base()

        with remote_node.client(user or self.user) as c:
            check_commit = infra.checker.Checker(c)

            for _ in range(number_txs):
                if not repeat and idx is None:
                    self.idx += 1

                target_idx = idx
                if target_idx is None:
                    target_idx = self.idx

                if send_private:
                    if msg:
                        priv_msg = msg
                    else:
                        priv_msg = f"Private message at idx {target_idx} [{len(self.priv[target_idx])}]"
                    args = {"id": target_idx, "msg": priv_msg}
                    if self.scope is not None:
                        args["scope"] = self.scope
                    url = "/app/log/private"
                    url = private_url if private_url else url
                    if url_suffix:
                        url += "/" + url_suffix
                    if self.scope is not None:
                        url += "?scope=" + self.scope
                    rep_priv = c.post(
                        url,
                        args,
                        headers=headers,
                        log_capture=log_capture,
                    )
                    if rep_priv.status_code != http.HTTPStatus.OK:
                        raise LoggingTxsIssueException(rep_priv)
                    assert rep_priv.status_code == http.HTTPStatus.OK, rep_priv
                    self.priv[target_idx].append(
                        {
                            "msg": priv_msg,
                            "seqno": rep_priv.seqno,
                            "view": rep_priv.view,
                            "scope": self.scope,
                        }
                    )
                    wait_point = rep_priv

                if send_public:
                    if msg:
                        pub_msg = msg
                    else:
                        pub_msg = f"Public message at idx {target_idx} [{len(self.pub[target_idx])}]"
                    payload = {
                        "id": target_idx,
                        "msg": pub_msg,
                    }
                    url = "/app/log/public"
                    if url_suffix:
                        url += "/" + url_suffix
                    if self.scope is not None:
                        url += "?scope=" + self.scope
                    if record_claim:
                        payload["record_claim"] = True
                    rep_pub = c.post(
                        url,
                        payload,
                        headers=headers,
                        log_capture=log_capture,
                    )
                    if rep_pub.status_code != http.HTTPStatus.OK:
                        raise LoggingTxsIssueException(rep_priv)
                    self.pub[target_idx].append(
                        {
                            "msg": pub_msg,
                            "seqno": rep_pub.seqno,
                            "view": rep_pub.view,
                            "scope": self.scope,
                        }
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
                self.verify_tx(
                    node,
                    pub_idx,
                    entry["msg"],
                    entry["seqno"],
                    entry["view"],
                    entry["scope"],
                    priv=False,
                    timeout=timeout,
                    log_capture=log_capture,
                )

            for priv_idx, priv_value in self.priv.items():
                # Verifying all historical transactions is expensive, verify only a sample
                for v in sample_list(priv_value, sample_count):
                    is_historical_entry = v != priv_value[-1]
                    if not is_historical_entry or include_historical:
                        self.verify_tx(
                            node,
                            priv_idx,
                            v["msg"],
                            v["seqno"],
                            v["view"],
                            v["scope"],
                            priv=True,
                            historical=is_historical_entry,
                            timeout=timeout,
                            log_capture=log_capture,
                        )

        LOG.info("Successfully verified logging txs")

    def verify_tx(
        self,
        node,
        idx,
        msg,
        seqno,
        view,
        scope=None,
        priv=True,
        historical=False,
        log_capture=None,
        timeout=3,
    ):
        if self.scope is not None and scope != self.scope:
            return

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

        url = f"{cmd}?id={idx}"
        if scope is not None:
            url += "&scope=" + scope

        found = False
        start_time = time.time()
        while time.time() < (start_time + timeout):
            with node.client(self.user) as c:
                infra.commit.wait_for_commit(
                    c, seqno, view, timeout, log_capture=log_capture
                )

                rep = c.get(url, headers=headers, log_capture=log_capture)
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

    def delete(
        self, log_id, priv=False, log_capture=None, user=None, wait_for_sync=True
    ):
        primary, _ = self.network.find_primary(log_capture=log_capture)
        check = infra.checker.Checker()
        with primary.client(user or self.user) as c:
            table = "private" if priv else "public"
            url = f"/app/log/{table}?id={log_id}"
            if self.scope is not None:
                url += "&scope=" + self.scope
            wait_point = c.delete(
                url, headers=None if user else self._get_headers_base()
            )
            check(wait_point, result=True)
            if priv:
                self.priv.pop(log_id)
            else:
                self.pub.pop(log_id)
        if wait_for_sync:
            self.network.wait_for_all_nodes_to_commit(
                tx_id=TxID(wait_point.view, wait_point.seqno)
            )

    def request(self, log_id, priv=False, log_capture=None, user=None, url_suffix=""):
        primary, _ = self.network.find_primary(log_capture=log_capture)
        with primary.client(user or self.user) as c:
            table = "private" if priv else "public"
            url = f"/app/log/{table}"
            if url_suffix:
                url += "/" + url_suffix
            url += f"?id={log_id}"
            if self.scope is not None:
                url += "&scope=" + self.scope
            return c.get(url, headers=None if user else self._get_headers_base())

    def post_raw_text(self, log_id, msg, log_capture=None, user=None):
        primary, _ = self.network.find_primary(log_capture=log_capture)
        with primary.client(user or self.user) as c:
            url = f"/app/log/private/raw_text/{log_id}"
            if self.scope is not None:
                url += "?scope=" + self.scope
            headers = {"content-type": "text/plain"}
            if not user:
                headers = {**headers, **self._get_headers_base()}
            return c.post(
                url,
                msg,
                headers=headers,
            )


def scoped_txs(identity="user0", verify=False):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not isinstance(args[0], infra.network.Network):
                raise ValueError("expected first argument to be of type Network")

            network = args[0]
            node = None
            previous_scope = None
            headers = {}

            if hasattr(network, "jwt_issuer") and network.jwt_issuer is not None:
                headers = infra.jwt_issuer.make_bearer_header(
                    network.jwt_issuer.issue_jwt()
                )
            node, _ = network.find_primary()
            previous_scope = network.txs.scope

            scope = get_fresh_scope(node, identity, headers)

            if network:
                network.txs.scope = scope
                network.txs.network = network
                r = func(*args, **kwargs)
            else:
                r = func(*args, **dict(kwargs, scope=scope))

            if network:
                if verify:
                    network.txs.verify(network=network)
                network.txs.scope = previous_scope

            return r

        def get_count(client, headers, scope, private=False):
            table = "private" if private else "public"
            r = client.get(f"/app/log/{table}/count?scope={scope}", headers=headers)
            if r.status_code == http.HTTPStatus.OK:
                return int(r.body.json())
            else:
                return None

        def get_fresh_scope(node, identity, headers, attempts=5):
            prefix = func.__name__
            scope = prefix
            i = 1
            while attempts > 0:
                with node.client(identity) as c:
                    public_count = get_count(c, headers, scope)
                    if public_count is None:
                        attempts -= 1
                        time.sleep(0.1)
                    else:
                        private_count = get_count(c, headers, scope, private=True)
                        if public_count + private_count == 0:
                            return scope
                        else:
                            scope = f"{prefix}_{i}"

            raise ValueError("fresh scope request failed")

        return wrapper

    return decorator
