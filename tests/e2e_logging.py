# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args
from ccf.tx_status import TxStatus
import infra.checker
import inspect
import http
import ssl
import socket
import os
from collections import defaultdict
import time
import tempfile
import base64
import json
import hashlib
import ccf.clients
from ccf.log_capture import flush_info
import ccf.receipt
from ccf.tx_id import TxID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("log/private", "log/public")
@reqs.at_least_n_nodes(2)
def test(network, args, verify=True):
    network.txs.issue(
        network=network,
        number_txs=1,
    )
    network.txs.issue(
        network=network,
        number_txs=1,
        on_backup=True,
    )
    if verify:
        network.txs.verify()
    else:
        LOG.warning("Skipping log messages verification")

    return network


@reqs.description("Protocol-illegal traffic")
@reqs.supports_methods("log/private", "log/public")
@reqs.at_least_n_nodes(2)
def test_illegal(network, args, verify=True):
    primary, _ = network.find_primary()

    # Send malformed HTTP traffic and check the connection is closed
    cafile = os.path.join(network.common_dir, "networkcert.pem")
    context = ssl.create_default_context(cafile=cafile)
    context.load_cert_chain(
        certfile=os.path.join(network.common_dir, "user0_cert.pem"),
        keyfile=os.path.join(network.common_dir, "user0_privk.pem"),
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(sock, server_side=False, server_hostname=primary.host)
    conn.connect((primary.host, primary.pubport))
    conn.sendall(b"NOTAVERB ")
    rv = conn.recv(1024)
    assert rv == b"", rv
    # Valid transactions are still accepted
    network.txs.issue(
        network=network,
        number_txs=1,
    )
    network.txs.issue(
        network=network,
        number_txs=1,
        on_backup=True,
    )
    if verify:
        network.txs.verify()
    else:
        LOG.warning("Skipping log messages verification")

    return network


@reqs.description("Write/Read large messages on primary")
@reqs.supports_methods("log/private")
def test_large_messages(network, args):
    primary, _ = network.find_primary()

    with primary.client() as nc:
        check_commit = infra.checker.Checker(nc)
        check = infra.checker.Checker()

        with primary.client("user0") as c:
            log_id = 44
            for p in range(14, 20) if args.consensus == "cft" else range(10, 13):
                long_msg = "X" * (2 ** p)
                check_commit(
                    c.post("/app/log/private", {"id": log_id, "msg": long_msg}),
                    result=True,
                )
                check(c.get(f"/app/log/private?id={log_id}"), result={"msg": long_msg})
                log_id += 1

    return network


@reqs.description("Write/Read/Delete messages on primary")
@reqs.supports_methods("log/private")
def test_remove(network, args):
    supported_packages = ["libjs_generic", "liblogging"]
    if args.package in supported_packages:
        primary, _ = network.find_primary()

        with primary.client() as nc:
            check_commit = infra.checker.Checker(nc)
            check = infra.checker.Checker()

            with primary.client("user0") as c:
                log_id = 44
                msg = "Will be deleted"

                for table in ["private", "public"]:
                    resource = f"/app/log/{table}"
                    check_commit(
                        c.post(resource, {"id": log_id, "msg": msg}),
                        result=True,
                    )
                    check(c.get(f"{resource}?id={log_id}"), result={"msg": msg})
                    check(
                        c.delete(f"{resource}?id={log_id}"),
                        result=None,
                    )
                    get_r = c.get(f"{resource}?id={log_id}")
                    if args.package == "libjs_generic":
                        check(
                            get_r,
                            result={"error": "No such key"},
                        )
                    else:
                        check(
                            get_r,
                            error=lambda status, msg: status
                            == http.HTTPStatus.BAD_REQUEST.value,
                        )
    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application ({args.package}) is not in supported packages: {supported_packages}"
        )

    return network


@reqs.description("Write/Read with cert prefix")
@reqs.supports_methods("log/private/prefix_cert", "log/private")
def test_cert_prefix(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        for user in network.users:
            with primary.client(user.local_id) as c:
                log_id = 101
                msg = "This message will be prefixed"
                c.post("/app/log/private/prefix_cert", {"id": log_id, "msg": msg})
                r = c.get(f"/app/log/private?id={log_id}")
                assert f"CN={user.local_id}" in r.body.json()["msg"], r

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Write as anonymous caller")
@reqs.supports_methods("log/private/anonymous", "log/private")
def test_anonymous_caller(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        # Create a new user but do not record its identity
        network.create_user("user5", args.participants_curve, record=False)

        log_id = 101
        msg = "This message is anonymous"
        with primary.client("user5") as c:
            r = c.post("/app/log/private/anonymous", {"id": log_id, "msg": msg})
            assert r.body.json() == True
            r = c.get(f"/app/log/private?id={log_id}")
            assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value, r

        with primary.client("user0") as c:
            r = c.get(f"/app/log/private?id={log_id}")
            assert msg in r.body.json()["msg"], r

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Use multiple auth types on the same endpoint")
@reqs.supports_methods("multi_auth")
def test_multi_auth(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]
    member = network.consortium.members[0]

    with primary.client(user.local_id) as c:
        response = c.get("/app/api")
        supported_methods = response.body.json()["paths"]
        if "/multi_auth" in supported_methods.keys():
            response_bodies = set()

            def require_new_response(r):
                assert r.status_code == http.HTTPStatus.OK.value, r.status_code
                r_body = r.body.text()
                assert r_body not in response_bodies, r_body
                response_bodies.add(r_body)

            LOG.info("Anonymous, no auth")
            with primary.client() as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as a user, via TLS cert")
            with primary.client(user.local_id) as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as same user, now with user data")
            network.consortium.set_user_data(
                primary, user.service_id, {"some": ["interesting", "data", 42]}
            )
            with primary.client(user.local_id) as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as a different user, via TLS cert")
            with primary.client("user1") as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as a member, via TLS cert")
            with primary.client(member.local_id) as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as same member, now with user data")
            network.consortium.set_member_data(
                primary, member.service_id, {"distinct": {"arbitrary": ["data"]}}
            )
            with primary.client(member.local_id) as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as a different member, via TLS cert")
            with primary.client("member1") as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as a user, via HTTP signature")
            with primary.client(None, user.local_id) as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as a member, via HTTP signature")
            with primary.client(None, member.local_id) as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate as user2 but sign as user1")
            with primary.client("user2", "user1") as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            network.create_user("user5", args.participants_curve, record=False)

            LOG.info("Authenticate as invalid user5 but sign as valid user3")
            with primary.client("user5", "user3") as c:
                r = c.get("/app/multi_auth")
                require_new_response(r)

            LOG.info("Authenticate via JWT token")
            jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
            jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)
            jwt_kid = "my_key_id"
            jwt_issuer = "https://example.issuer"
            # Add JWT issuer
            with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
                jwt_cert_der = infra.crypto.cert_pem_to_der(jwt_cert_pem)
                der_b64 = base64.b64encode(jwt_cert_der).decode("ascii")
                data = {
                    "issuer": jwt_issuer,
                    "jwks": {
                        "keys": [{"kty": "RSA", "kid": jwt_kid, "x5c": [der_b64]}]
                    },
                }
                json.dump(data, metadata_fp)
                metadata_fp.flush()
                network.consortium.set_jwt_issuer(primary, metadata_fp.name)

            with primary.client() as c:
                jwt = infra.crypto.create_jwt({}, jwt_key_priv_pem, jwt_kid)
                r = c.get("/app/multi_auth", headers={"authorization": "Bearer " + jwt})
                require_new_response(r)

        else:
            LOG.warning(
                f"Skipping {inspect.currentframe().f_code.co_name} as application does not implement '/multi_auth'"
            )

    return network


@reqs.description("Call an endpoint with a custom auth policy")
@reqs.supports_methods("custom_auth")
def test_custom_auth(network, args):
    if args.package == "liblogging":
        primary, other = network.find_primary_and_any_backup()

        for node in (primary, other):
            with node.client() as c:
                LOG.info("Request without custom headers is refused")
                r = c.get("/app/custom_auth")
                assert (
                    r.status_code == http.HTTPStatus.UNAUTHORIZED.value
                ), r.status_code

                name_header = "x-custom-auth-name"
                age_header = "x-custom-auth-age"

                LOG.info("Requests with partial headers are refused")
                r = c.get("/app/custom_auth", headers={name_header: "Bob"})
                assert (
                    r.status_code == http.HTTPStatus.UNAUTHORIZED.value
                ), r.status_code
                r = c.get("/app/custom_auth", headers={age_header: "42"})
                assert (
                    r.status_code == http.HTTPStatus.UNAUTHORIZED.value
                ), r.status_code

                LOG.info("Requests with unacceptable header contents are refused")
                r = c.get(
                    "/app/custom_auth", headers={name_header: "", age_header: "42"}
                )
                assert (
                    r.status_code == http.HTTPStatus.UNAUTHORIZED.value
                ), r.status_code
                r = c.get(
                    "/app/custom_auth", headers={name_header: "Bob", age_header: "12"}
                )
                assert (
                    r.status_code == http.HTTPStatus.UNAUTHORIZED.value
                ), r.status_code

                LOG.info("Request which meets all requirements is accepted")
                r = c.get(
                    "/app/custom_auth", headers={name_header: "Alice", age_header: "42"}
                )
                assert r.status_code == http.HTTPStatus.OK.value, r.status_code
                response = r.body.json()
                assert response["name"] == "Alice", response
                assert response["age"] == 42, response

    return network


@reqs.description("Call an endpoint with a custom auth policy which throws")
@reqs.supports_methods("custom_auth")
def test_custom_auth_safety(network, args):
    if args.package == "liblogging":
        primary, other = network.find_primary_and_any_backup()

        for node in (primary, other):
            with node.client() as c:
                r = c.get(
                    "/app/custom_auth",
                    headers={"x-custom-auth-explode": "Boom goes the dynamite"},
                )
                assert (
                    r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value
                ), r.status_code

    return network


@reqs.description("Write non-JSON body")
@reqs.supports_methods("log/private/raw_text/{id}", "log/private")
def test_raw_text(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        log_id = 101
        msg = "This message is not in JSON"
        with primary.client("user0") as c:
            r = c.post(
                f"/app/log/private/raw_text/{log_id}",
                msg,
                headers={"content-type": "text/plain"},
            )
            assert r.status_code == http.HTTPStatus.OK.value
            r = c.get(f"/app/log/private?id={log_id}")
            assert msg in r.body.json()["msg"], r

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Read metrics")
@reqs.supports_methods("api/metrics")
def test_metrics(network, args):
    primary, _ = network.find_primary()

    def get_metrics(r, path, method):
        return next(
            v
            for v in r.body.json()["metrics"]
            if v["path"] == path and v["method"] == method
        )

    calls = 0
    errors = 0
    with primary.client("user0") as c:
        r = c.get("/app/api/metrics")
        m = get_metrics(r, "api/metrics", "GET")
        calls = m["calls"]
        errors = m["errors"]

    with primary.client("user0") as c:
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "api/metrics", "GET")["calls"] == calls + 1
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "api/metrics", "GET")["calls"] == calls + 2

    with primary.client() as c:
        r = c.get("/app/api/metrics", headers={"accept": "nonsense"})
        assert r.status_code == http.HTTPStatus.NOT_ACCEPTABLE.value

    with primary.client() as c:
        r = c.get("/app/api/metrics")
        assert get_metrics(r, "api/metrics", "GET")["errors"] == errors + 1

    return network


@reqs.description("Read historical state")
@reqs.supports_methods("log/private", "log/private/historical")
def test_historical_query(network, args):
    if args.consensus == "bft":
        LOG.warning("Skipping historical queries in BFT")
        return network

    network.txs.issue(network, number_txs=2)
    network.txs.issue(network, number_txs=2, repeat=True)
    network.txs.verify()

    return network


@reqs.description("Read historical receipts")
@reqs.supports_methods("log/private", "log/private/historical_receipt")
def test_historical_receipts(network, args):
    if args.consensus == "bft":
        LOG.warning("Skipping historical queries in BFT")
        return network

    primary, backups = network.find_nodes()
    cert_path = os.path.join(primary.common_dir, f"{primary.local_node_id}.pem")
    with open(cert_path) as c:
        primary_cert = load_pem_x509_certificate(
            c.read().encode("ascii"), default_backend()
        )

    TXS_COUNT = 5
    network.txs.issue(network, number_txs=5)
    for idx in range(1, TXS_COUNT + 1):
        for node in [primary, backups[0]]:
            first_msg = network.txs.priv[idx][0]
            first_receipt = network.txs.get_receipt(
                node, idx, first_msg["seqno"], first_msg["view"]
            )
            r = first_receipt.json()["receipt"]
            assert r["root"] == ccf.receipt.root(r["leaf"], r["proof"])
            ccf.receipt.verify(r["root"], r["signature"], primary_cert)

    # receipt.verify() raises if it fails, but does not return anything
    verified = True
    try:
        ccf.receipt.verify(
            hashlib.sha256(b"").hexdigest(), r["signature"], primary_cert
        )
    except InvalidSignature:
        verified = False
    assert not verified

    return network


@reqs.description("Read range of historical state")
@reqs.supports_methods("log/private", "log/private/historical/range")
def test_historical_query_range(network, args):
    if args.consensus == "bft":
        LOG.warning("Skipping historical queries in BFT")
        return network

    if args.package != "liblogging":
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )
        return network

    primary, _ = network.find_primary()

    id_a = 142
    id_b = 143

    first_seqno = None
    last_seqno = None

    def get_all_entries(target_id, from_seqno=None, to_seqno=None):
        LOG.info(
            f"Getting historical entries{f' from {from_seqno}' if from_seqno is not None else ''}{f' to {last_seqno}' if to_seqno is not None else ''} for id {target_id}"
        )
        logs = []
        with primary.client("user0") as c:
            timeout = 5
            end_time = time.time() + timeout
            entries = []
            path = f"/app/log/private/historical/range?id={target_id}"
            if from_seqno is not None:
                path += f"&from_seqno={first_seqno}"
            if to_seqno is not None:
                path += f"&to_seqno={to_seqno}"
            while time.time() < end_time:
                r = c.get(path, log_capture=logs)
                if r.status_code == http.HTTPStatus.OK:
                    j_body = r.body.json()
                    entries += j_body["entries"]
                    if "@nextLink" in j_body:
                        path = j_body["@nextLink"]
                        continue
                    else:
                        # No @nextLink means we've reached end of range
                        return entries
                elif r.status_code == http.HTTPStatus.ACCEPTED:
                    # Ignore retry-after header, retry soon
                    time.sleep(0.1)
                    continue
                else:
                    LOG.error("Printing historical/range logs on unexpected status")
                    flush_info(logs, None)
                    raise ValueError(
                        f"Unexpected status code from historical range query: {r.status_code}"
                    )

        LOG.error("Printing historical/range logs on timeout")
        flush_info(logs, None)
        raise TimeoutError(f"Historical range not available after {timeout}s")

    with primary.client("user0") as c:
        # Submit many transactions, overwriting the same IDs
        # Need to submit through network.txs so these can be verified at shutdown, but also need to submit one at a
        # time to retrieve the submitted transactions
        msgs = dict()
        n_entries = 100
        for i in range(n_entries):
            idx = id_b if i % 3 == 0 else id_a
            network.txs.issue(
                network, repeat=True, idx=idx, wait_for_sync=False, log_capture=[]
            )
            _, tx = network.txs.get_last_tx(idx=idx)
            msg = tx["msg"]
            seqno = tx["seqno"]
            view = tx["view"]
            msgs[seqno] = msg

            if first_seqno is None:
                first_seqno = seqno

            last_seqno = seqno

        ccf.commit.wait_for_commit(c, seqno=last_seqno, view=view, timeout=3)

        entries_a = get_all_entries(id_a)
        entries_b = get_all_entries(id_b)

        # Confirm that we can retrieve these with more specific queries, and we end up with the same result
        alt_a = get_all_entries(id_a, from_seqno=first_seqno)
        assert alt_a == entries_a
        alt_a = get_all_entries(id_a, to_seqno=last_seqno)
        assert alt_a == entries_a
        alt_a = get_all_entries(id_a, from_seqno=first_seqno, to_seqno=last_seqno)
        assert alt_a == entries_a

        actual_len = len(entries_a) + len(entries_b)
        assert (
            n_entries == actual_len
        ), f"Expected {n_entries} total entries, got {actual_len}"

        # Iterate through both lists, by i, checking retrieved entries match expectations
        for i in range(n_entries):
            entries = entries_b if i % 3 == 0 else entries_a
            expected_id = id_b if i % 3 == 0 else id_a
            entry = entries.pop(0)
            assert entry["id"] == expected_id
            assert entry["msg"] == msgs[entry["seqno"]]

        # Make sure this has checked every entry
        assert len(entries_a) == 0
        assert len(entries_b) == 0

    return network


@reqs.description("Testing forwarding on member and user frontends")
@reqs.supports_methods("log/private")
@reqs.at_least_n_nodes(2)
def test_forwarding_frontends(network, args):
    backup = network.find_any_backup()

    with backup.client() as c:
        check_commit = infra.checker.Checker(c)
        ack = network.consortium.get_any_active_member().ack(backup)
        check_commit(ack)

    with backup.client("user0") as c:
        check_commit = infra.checker.Checker(c)
        check = infra.checker.Checker()
        msg = "forwarded_msg"
        log_id = 123
        check_commit(
            c.post("/app/log/private", {"id": log_id, "msg": msg}),
            result=True,
        )
        check(c.get(f"/app/log/private?id={log_id}"), result={"msg": msg})

    return network


@reqs.description("Test user-data used for access permissions")
@reqs.supports_methods("log/private/admin_only")
def test_user_data_ACL(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        user = network.users[0]

        # Give isAdmin permissions to a single user
        network.consortium.set_user_data(
            primary, user.service_id, user_data={"isAdmin": True}
        )

        # Confirm that user can now use this endpoint
        with primary.client(user.local_id) as c:
            r = c.post("/app/log/private/admin_only", {"id": 42, "msg": "hello world"})
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code

        # Remove permission
        network.consortium.set_user_data(
            primary, user.service_id, user_data={"isAdmin": False}
        )

        # Confirm that user is now forbidden on this endpoint
        with primary.client(user.local_id) as c:
            r = c.post("/app/log/private/admin_only", {"id": 42, "msg": "hello world"})
            assert r.status_code == http.HTTPStatus.FORBIDDEN.value, r.status_code

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Check for commit of every prior transaction")
def test_view_history(network, args):
    if args.consensus == "bft":
        # This appears to work in BFT, but it is unacceptably slow:
        # - Each /tx request is a write, with a non-trivial roundtrip response time
        # - Since each read (eg - /tx and /commit) has produced writes and a unique tx ID,
        #    there are too many IDs to test exhaustively
        # We could rectify this by making this test non-exhaustive (bisecting for view changes,
        # sampling within a view), but for now it is exhaustive and Raft-only
        LOG.warning("Skipping view reconstruction in BFT")
        return network

    check = infra.checker.Checker()

    previous_node = None
    previous_tx_ids = ""
    for node in network.get_joined_nodes():
        with node.client("user0") as c:
            r = c.get("/node/commit")
            check(c)

            commit_tx_id = TxID.from_str(r.body.json()["transaction_id"])

            # Retrieve status for all possible Tx IDs
            seqno_to_views = {}
            for seqno in range(1, commit_tx_id.seqno + 1):
                views = []
                for view in range(1, commit_tx_id.view + 1):
                    r = c.get(f"/node/tx?transaction_id={view}.{seqno}", log_capture=[])
                    check(r)
                    status = TxStatus(r.body.json()["status"])
                    if status == TxStatus.Committed:
                        views.append(view)
                seqno_to_views[seqno] = views

            # Check we have exactly one Tx ID for each seqno
            txs_ok = True
            for seqno, views in seqno_to_views.items():
                if len(views) != 1:
                    txs_ok = False
                    LOG.error(
                        f"Node {node.node_id}: Found {len(views)} committed Tx IDs for seqno {seqno}"
                    )

            tx_ids_condensed = ", ".join(
                " OR ".join(f"{view}.{seqno}" for view in views or ["UNKNOWN"])
                for seqno, views in seqno_to_views.items()
            )

            if txs_ok:
                LOG.success(
                    f"Node {node.node_id}: Found a valid sequence of Tx IDs:\n{tx_ids_condensed}"
                )
            else:
                LOG.error(
                    f"Node {node.node_id}: Invalid sequence of Tx IDs:\n{tx_ids_condensed}"
                )
                raise RuntimeError(
                    f"Node {node.node_id}: Incomplete or inconsistent view history"
                )

            # Compare view history between nodes
            if previous_tx_ids:
                # Some nodes may have a slightly longer view history so only compare the common prefix
                min_tx_ids_len = min(len(previous_tx_ids), len(tx_ids_condensed))
                assert (
                    tx_ids_condensed[:min_tx_ids_len]
                    == previous_tx_ids[:min_tx_ids_len]
                ), f"Tx IDs don't match between node {node.node_id} and node {previous_node.node_id}: {tx_ids_condensed[:min_tx_ids_len]} and {previous_tx_ids[:min_tx_ids_len]}"

            previous_tx_ids = tx_ids_condensed
            previous_node = node

    return network


class SentTxs:
    # view -> seqno -> status
    txs = defaultdict(lambda: defaultdict(lambda: TxStatus.Unknown))

    @staticmethod
    def update_status(view, seqno, status=None):
        current_status = SentTxs.txs[view][seqno]
        if status is None:
            # If you don't know the current status, we exit here. Since we have
            # accessed the value in the defaultdict, we have recorded this tx id
            # so it will be returned by future calls to get_all_tx_ids()
            return

        if status != current_status:
            valid = False
            # Only valid transitions from Unknown to any, or Pending to Committed/Invalid
            if current_status == TxStatus.Unknown:
                valid = True
            elif current_status == TxStatus.Pending and (
                status == TxStatus.Committed or status == TxStatus.Invalid
            ):
                valid = True

            if valid:
                SentTxs.txs[view][seqno] = status
            else:
                raise ValueError(
                    f"Transaction {view}.{seqno} making invalid transition from {current_status} to {status}"
                )

    @staticmethod
    def get_all_tx_ids():
        return [
            (view, seqno)
            for view, view_txs in SentTxs.txs.items()
            for seqno, status in view_txs.items()
        ]


@reqs.description("Build a list of Tx IDs, check they transition states as expected")
@reqs.supports_methods("log/private")
def test_tx_statuses(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        check = infra.checker.Checker()
        r = c.post("/app/log/private", {"id": 0, "msg": "Ignored"})
        check(r)
        # Until this tx is globally committed, poll for the status of this and some other
        # related transactions around it (and also any historical transactions we're tracking)
        target_view = r.view
        target_seqno = r.seqno
        SentTxs.update_status(target_view, target_seqno)
        SentTxs.update_status(target_view, target_seqno + 1)
        SentTxs.update_status(target_view - 1, target_seqno)

        end_time = time.time() + 10
        while True:
            if time.time() > end_time:
                raise TimeoutError(
                    f"Took too long waiting for global commit of {target_view}.{target_seqno}"
                )

            done = False
            for view, seqno in SentTxs.get_all_tx_ids():
                r = c.get(f"/node/tx?transaction_id={view}.{seqno}")
                check(r)
                status = TxStatus(r.body.json()["status"])
                SentTxs.update_status(view, seqno, status)
                if (
                    status == TxStatus.Committed
                    and target_view == view
                    and target_seqno == seqno
                ):
                    done = True

            if done:
                break
            time.sleep(0.1)

    return network


@reqs.description("Primary and redirection")
@reqs.at_least_n_nodes(2)
def test_primary(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.head("/node/primary")
        assert r.status_code == http.HTTPStatus.OK.value

    backup = network.find_any_backup()
    with backup.client() as c:
        r = c.head("/node/primary", allow_redirects=False)
        assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
        assert (
            r.headers["location"]
            == f"https://{primary.pubhost}:{primary.pubport}/node/primary"
        )
    return network


@reqs.description("Network node info")
@reqs.at_least_n_nodes(2)
def test_network_node_info(network, args):
    primary, backups = network.find_nodes()

    all_nodes = [primary, *backups]

    with primary.client() as c:
        r = c.get("/node/network/nodes", allow_redirects=False)
        assert r.status_code == http.HTTPStatus.OK
        nodes = r.body.json()["nodes"]
        nodes_by_id = {node["node_id"]: node for node in nodes}
        for n in all_nodes:
            node = nodes_by_id[n.node_id]
            assert node["host"] == n.pubhost
            assert node["port"] == str(n.pubport)
            assert node["primary"] == (n == primary)
            del nodes_by_id[n.node_id]

        assert nodes_by_id == {}

    # Populate node_infos by calling self
    node_infos = {}
    for node in all_nodes:
        with node.client() as c:
            # /node/network/nodes/self is always a redirect
            r = c.get("/node/network/nodes/self", allow_redirects=False)
            assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
            assert (
                r.headers["location"]
                == f"https://{node.pubhost}:{node.pubport}/node/network/nodes/{node.node_id}"
            ), r.headers["location"]

            # Following that redirect gets you the node info
            r = c.get("/node/network/nodes/self", allow_redirects=True)
            assert r.status_code == http.HTTPStatus.OK.value
            body = r.body.json()
            assert body["node_id"] == node.node_id
            assert body["host"] == node.pubhost
            assert body["port"] == str(node.pubport)
            assert body["primary"] == (node == primary)

            node_infos[node.node_id] = body

    for node in all_nodes:
        with node.client() as c:
            # /node/primary is a 200 on the primary, and a redirect (to a 200) elsewhere
            r = c.head("/node/primary", allow_redirects=False)
            if node != primary:
                assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
                assert (
                    r.headers["location"]
                    == f"https://{primary.pubhost}:{primary.pubport}/node/primary"
                ), r.headers["location"]
                r = c.head("/node/primary", allow_redirects=True)

            assert r.status_code == http.HTTPStatus.OK.value

            # /node/network/nodes/primary is always a redirect
            r = c.get("/node/network/nodes/primary", allow_redirects=False)
            assert r.status_code == http.HTTPStatus.PERMANENT_REDIRECT.value
            actual = r.headers["location"]
            expected = f"https://{node.pubhost}:{node.pubport}/node/network/nodes/{primary.node_id}"
            assert actual == expected, f"{actual} != {expected}"

            # Following that redirect gets you the primary's node info
            r = c.get("/node/network/nodes/primary", allow_redirects=True)
            assert r.status_code == http.HTTPStatus.OK.value
            body = r.body.json()
            assert body == node_infos[primary.node_id]

            # Node info can be retrieved directly by node ID, from and about every node, without redirection
            for target_node in all_nodes:
                r = c.get(
                    f"/node/network/nodes/{target_node.node_id}", allow_redirects=False
                )
                assert r.status_code == http.HTTPStatus.OK.value
                body = r.body.json()
                assert body == node_infos[target_node.node_id]

    return network


@reqs.description("Memory usage")
def test_memory(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/node/memory")
        assert r.status_code == http.HTTPStatus.OK.value
        assert (
            r.body.json()["peak_allocated_heap_size"]
            <= r.body.json()["max_total_heap_size"]
        )
        assert (
            r.body.json()["current_allocated_heap_size"]
            <= r.body.json()["peak_allocated_heap_size"]
        )
    return network


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("log/private")
@reqs.at_least_n_nodes(2)
def test_ws(network, args):
    primary, other = network.find_primary_and_any_backup()

    msg = "Hello world"
    LOG.info("Write on primary")
    with primary.client("user0", ws=True) as c:
        for i in [1, 50, 500]:
            r = c.post("/app/log/private", {"id": 42, "msg": msg * i})
            assert r.body.json() == True, r

    # Before we start sending transactions to the secondary,
    # we want to wait for its app frontend to be open, which is
    # when it's aware that the network is open. Before that,
    # we will get 404s.
    end_time = time.time() + 10
    with other.client("user0") as nc:
        while time.time() < end_time:
            r = nc.post("/app/log/private", {"id": 42, "msg": msg * i})
            if r.status_code == http.HTTPStatus.OK.value:
                break
            else:
                time.sleep(0.1)
        assert r.status_code == http.HTTPStatus.OK.value, r

    LOG.info("Write on secondary through forwarding")
    with other.client("user0", ws=True) as c:
        for i in [1, 50, 500]:
            r = c.post("/app/log/private", {"id": 42, "msg": msg * i})
            assert r.body.json() == True, r

    return network


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("receipt", "log/private")
@reqs.at_least_n_nodes(2)
def test_receipts(network, args):
    primary, _ = network.find_primary_and_any_backup()
    cert_path = os.path.join(primary.common_dir, f"{primary.local_node_id}.pem")
    with open(cert_path) as c:
        node_cert = load_pem_x509_certificate(
            c.read().encode("ascii"), default_backend()
        )

    with primary.client() as mc:
        check_commit = infra.checker.Checker(mc)
        msg = "Hello world"

        LOG.info("Write/Read on primary")
        with primary.client("user0") as c:
            for j in range(10):
                idx = j + 10000
                r = c.post("/app/log/private", {"id": idx, "msg": msg})
                check_commit(r, result=True)
                start_time = time.time()
                while time.time() < (start_time + 3.0):
                    rc = c.get(f"/app/receipt?transaction_id={r.view}.{r.seqno}")
                    if rc.status_code == http.HTTPStatus.OK:
                        receipt = rc.body.json()
                        assert receipt["root"] == ccf.receipt.root(
                            receipt["leaf"], receipt["proof"]
                        )
                        ccf.receipt.verify(
                            receipt["root"], receipt["signature"], node_cert
                        )
                        break
                    elif rc.status_code == http.HTTPStatus.ACCEPTED:
                        time.sleep(0.5)
                    else:
                        assert False, rc

    return network


@reqs.description("Test basic app liveness")
@reqs.at_least_n_nodes(1)
def test_liveness(network, args):
    txs = app.LoggingTxs()
    txs.issue(
        network=network,
        number_txs=3,
    )
    txs.verify()
    return network


@reqs.description("Rekey the ledger once")
@reqs.at_least_n_nodes(1)
def test_rekey(network, args):
    primary, _ = network.find_primary()
    network.consortium.trigger_ledger_rekey(primary)
    return network


def run(args):
    txs = app.LoggingTxs()
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_join(args)

        network = test(
            network,
            args,
            verify=args.package != "libjs_generic",
        )
        network = test_illegal(network, args, verify=args.package != "libjs_generic")
        network = test_large_messages(network, args)
        network = test_remove(network, args)
        network = test_forwarding_frontends(network, args)
        network = test_user_data_ACL(network, args)
        network = test_cert_prefix(network, args)
        network = test_anonymous_caller(network, args)
        network = test_multi_auth(network, args)
        network = test_custom_auth(network, args)
        network = test_custom_auth_safety(network, args)
        network = test_raw_text(network, args)
        network = test_historical_query(network, args)
        network = test_historical_query_range(network, args)
        network = test_view_history(network, args)
        network = test_primary(network, args)
        network = test_network_node_info(network, args)
        network = test_metrics(network, args)
        network = test_memory(network, args)
        # BFT does not handle re-keying yet
        if args.consensus == "cft":
            network = test_liveness(network, args)
            network = test_rekey(network, args)
            network = test_liveness(network, args)
        if args.package == "liblogging":
            network = test_ws(network, args)
            network = test_receipts(network, args)
        network = test_historical_receipts(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    if args.js_app_bundle:
        args.package = "libjs_generic"
    else:
        args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 4
    args.initial_member_count = 2
    run(args)
