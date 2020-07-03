# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.notification
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args
from infra.tx_status import TxStatus
import inspect
import http
import ssl
import socket
import os
from collections import defaultdict
import time
import infra.clients

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("log/private", "log/public")
@reqs.at_least_n_nodes(2)
def test(network, args, notifications_queue=None, verify=True):
    txs = app.LoggingTxs(notifications_queue=notifications_queue)
    txs.issue(
        network=network, number_txs=1, consensus=args.consensus,
    )
    txs.issue(
        network=network, number_txs=1, on_backup=True, consensus=args.consensus,
    )
    if verify:
        txs.verify(network)
    else:
        LOG.warning("Skipping log messages verification")

    return network


@reqs.description("Protocol-illegal traffic")
@reqs.supports_methods("log/private", "log/public")
@reqs.at_least_n_nodes(2)
def test_illegal(network, args, notifications_queue=None, verify=True):
    # Send malformed HTTP traffic and check the connection is closed
    cafile = cafile = os.path.join(network.common_dir, "networkcert.pem")
    context = ssl.create_default_context(cafile=cafile)
    context.set_ecdh_curve(infra.clients.get_curve(cafile).name)
    context.load_cert_chain(
        certfile=os.path.join(network.common_dir, "user0_cert.pem"),
        keyfile=os.path.join(network.common_dir, "user0_privk.pem"),
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(
        sock, server_side=False, server_hostname=network.nodes[0].host
    )
    conn.connect((network.nodes[0].host, network.nodes[0].rpc_port))
    conn.sendall(b"NOTAVERB ")
    rv = conn.recv(1024)
    assert rv == b"", rv
    # Valid transactions are still accepted
    txs = app.LoggingTxs(notifications_queue=notifications_queue)
    txs.issue(
        network=network, number_txs=1, consensus=args.consensus,
    )
    txs.issue(
        network=network, number_txs=1, on_backup=True, consensus=args.consensus,
    )
    if verify:
        txs.verify(network)
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
            for p in range(14, 20) if args.consensus == "raft" else range(10, 13):
                long_msg = "X" * (2 ** p)
                check_commit(
                    c.rpc("/app/log/private", {"id": log_id, "msg": long_msg}),
                    result=True,
                )
                check(
                    c.get("/app/log/private", {"id": log_id}), result={"msg": long_msg}
                )
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
                        c.rpc(resource, {"id": log_id, "msg": msg}), result=True,
                    )
                    check(c.get(resource, {"id": log_id}), result={"msg": msg})
                    check(
                        c.delete(resource, {"id": log_id}, params_in_query=True),
                        result=None,
                    )
                    get_r = c.get(resource, {"id": log_id})
                    if args.package == "libjs_generic":
                        check(
                            get_r, result={"error": "No such key"},
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

        for user_id in network.user_ids:
            with primary.client(f"user{user_id}") as c:
                log_id = 101
                msg = "This message will be prefixed"
                c.rpc("/app/log/private/prefix_cert", {"id": log_id, "msg": msg})
                r = c.get("/app/log/private", {"id": log_id})
                assert r.result is not None
                assert f"CN=user{user_id}" in r.result["msg"]

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
        network.create_user(4, args.participants_curve, record=False)

        log_id = 101
        msg = "This message is anonymous"
        with primary.client("user4") as c:
            r = c.rpc("/app/log/private/anonymous", {"id": log_id, "msg": msg})
            assert r.result == True
            r = c.get("/app/log/private", {"id": log_id})
            assert (
                r.error is not None
            ), "Anonymous user is not authorised to call log/private"

        with primary.client("user0") as c:
            r = c.get("/app/log/private", {"id": log_id})
            assert r.result is not None
            assert msg in r.result["msg"]
    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Write non-JSON body")
@reqs.supports_methods("log/private/raw_text", "log/private")
def test_raw_text(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        log_id = 101
        msg = "This message is not in JSON"
        with primary.client("user0") as c:
            r = c.rpc(
                "/app/log/private/raw_text",
                msg,
                headers={"content-type": "text/plain", "x-log-id": str(log_id)},
            )
            assert r.status == http.HTTPStatus.OK.value
            r = c.get("/app/log/private", {"id": log_id})
            assert r.result is not None
            assert msg in r.result["msg"]

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Read historical state")
@reqs.supports_methods("log/private", "log/private/historical")
def test_historical_query(network, args):
    if args.consensus == "pbft":
        LOG.warning("Skipping historical queries in PBFT")
        return network

    if args.package == "liblogging":
        primary, _ = network.find_primary()

        with primary.client() as nc:
            check_commit = infra.checker.Checker(nc)
            check = infra.checker.Checker()

            with primary.client("user0") as c:
                log_id = 10
                msg = "This tests historical queries"
                record_response = c.rpc("/app/log/private", {"id": log_id, "msg": msg})
                check_commit(record_response, result=True)
                view = record_response.view
                seqno = record_response.seqno

                msg2 = "This overwrites the original message"
                check_commit(
                    c.rpc("/app/log/private", {"id": log_id, "msg": msg2}), result=True
                )
                check(c.get("/app/log/private", {"id": log_id}), result={"msg": msg2})

                timeout = 15
                found = False
                headers = {
                    infra.clients.CCF_TX_VIEW_HEADER: str(view),
                    infra.clients.CCF_TX_SEQNO_HEADER: str(seqno),
                }
                params = {"id": log_id}
                end_time = time.time() + timeout

                while time.time() < end_time:
                    get_response = c.get(
                        "/app/log/private/historical", params, headers=headers
                    )
                    if get_response.status == http.HTTPStatus.ACCEPTED:
                        retry_after = get_response.headers.get("retry-after")
                        if retry_after is None:
                            raise ValueError(
                                f"Response with status {get_response.status} is missing 'retry-after' header"
                            )
                        retry_after = int(retry_after)
                        time.sleep(retry_after)
                    elif get_response.status == http.HTTPStatus.OK:
                        assert (
                            get_response.result["msg"] == msg
                        ), f"{get_response.result}"
                        found = True
                        break
                    elif get_response.status == http.HTTPStatus.NO_CONTENT:
                        raise ValueError(
                            f"Historical query response claims there was no write to {log_id} at {view}.{seqno}"
                        )
                    else:
                        raise ValueError(
                            f"Unexpected response status {get_response.status}: {get_response.error}"
                        )

                if not found:
                    raise TimeoutError(
                        f"Unable to handle historical query after {timeout}s"
                    )

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Testing forwarding on member and node frontends")
@reqs.supports_methods("/node/tx")
@reqs.at_least_n_nodes(2)
def test_forwarding_frontends(network, args):
    primary, backup = network.find_primary_and_any_backup()

    with primary.client() as nc:
        check_commit = infra.checker.Checker(nc)
        ack = network.consortium.get_any_active_member().ack(backup)
        check_commit(ack)

    return network


@reqs.description("Uninstalling Lua application")
@reqs.lua_generic_app
def test_update_lua(network, args):
    if args.package == "liblua_generic":
        LOG.info("Updating Lua application")
        primary, _ = network.find_primary()

        check = infra.checker.Checker()

        # Create a new lua application file (minimal app)
        new_app_file = "new_lua_app.lua"
        with open(new_app_file, "w") as qfile:
            qfile.write(
                """
                    return {
                    ping = [[
                        tables, args = ...
                        return {result = "pong"}
                    ]],
                    }"""
            )

        network.consortium.set_lua_app(
            remote_node=primary, app_script_path=new_app_file
        )
        with primary.client("user0") as c:
            check(c.rpc("/app/ping"), result="pong")

            LOG.debug("Check that former endpoints no longer exists")
            for endpoint in [
                "/app/log/private",
                "/app/log/public",
            ]:
                check(
                    c.rpc(endpoint),
                    error=lambda status, msg: status == http.HTTPStatus.NOT_FOUND.value,
                )
    else:
        LOG.warning("Skipping Lua app update as application is not Lua")

    return network


@reqs.description("Check for commit of every prior transaction")
@reqs.supports_methods("/node/commit", "/node/tx")
def test_view_history(network, args):
    if args.consensus == "pbft":
        # This appears to work in PBFT, but it is unacceptably slow:
        # - Each /tx request is a write, with a non-trivial roundtrip response time
        # - Since each read (eg - /tx and /commit) has produced writes and a unique tx ID,
        #    there are too many IDs to test exhaustively
        # We could rectify this by making this test non-exhaustive (bisecting for view changes,
        # sampling within a view), but for now it is exhaustive and Raft-only
        LOG.warning("Skipping view reconstruction in PBFT")
        return network

    check = infra.checker.Checker()

    for node in network.get_joined_nodes():
        with node.client("user0") as c:
            r = c.get("/node/commit")
            check(c)

            commit_view = r.result["view"]
            commit_seqno = r.result["seqno"]

            # Temporarily disable logging of RPCs for readability
            rpc_loggers = c.rpc_loggers
            c.rpc_loggers = ()
            LOG.warning("RPC logging temporarily suppressed")

            # Retrieve status for all possible Tx IDs
            seqno_to_views = {}
            for seqno in range(1, commit_seqno + 1):
                views = []
                for view in range(1, commit_view + 1):
                    r = c.get("/node/tx", {"view": view, "seqno": seqno})
                    check(r)
                    status = TxStatus(r.result["status"])
                    if status == TxStatus.Committed:
                        views.append(view)
                seqno_to_views[seqno] = views

            c.rpc_loggers = rpc_loggers
            LOG.warning("RPC logging restored")

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
@reqs.supports_methods("log/private", "/node/tx")
def test_tx_statuses(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        check = infra.checker.Checker()
        r = c.rpc("/app/log/private", {"id": 0, "msg": "Ignored"})
        check(r)
        # Until this tx is globally committed, poll for the status of this and some other
        # related transactions around it (and also any historical transactions we're tracking)
        target_view = r.view
        target_seqno = r.seqno
        SentTxs.update_status(target_view, target_seqno)
        SentTxs.update_status(target_view, target_seqno + 1)
        SentTxs.update_status(target_view - 1, target_seqno, TxStatus.Invalid)

        end_time = time.time() + 10
        while True:
            if time.time() > end_time:
                raise TimeoutError(
                    f"Took too long waiting for global commit of {target_view}.{target_seqno}"
                )

            done = False
            for view, seqno in SentTxs.get_all_tx_ids():
                r = c.get("/node/tx", {"view": view, "seqno": seqno})
                check(r)
                status = TxStatus(r.result["status"])
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


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "pbft" else 2)

    with infra.notification.notification_server(args.notify_server) as notifications:
        # Lua apps do not support notifications
        # https://github.com/microsoft/CCF/issues/415
        notifications_queue = (
            notifications.get_queue()
            if (args.package == "liblogging" and args.consensus == "raft")
            else None
        )

        with infra.ccf.network(
            hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
        ) as network:
            network.start_and_join(args)
            network = test(
                network,
                args,
                notifications_queue,
                verify=args.package is not "libjs_generic",
            )
            network = test_illegal(
                network, args, verify=args.package is not "libjs_generic"
            )
            network = test_large_messages(network, args)
            network = test_remove(network, args)
            network = test_forwarding_frontends(network, args)
            network = test_update_lua(network, args)
            network = test_cert_prefix(network, args)
            network = test_anonymous_caller(network, args)
            network = test_raw_text(network, args)
            network = test_historical_query(network, args)
            network = test_view_history(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    if args.js_app_script:
        args.package = "libjs_generic"
    elif args.app_script:
        args.package = "liblua_generic"
    else:
        args.package = "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
