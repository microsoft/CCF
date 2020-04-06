# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.notification
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args
import inspect
import http

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("LOG_record", "LOG_record_pub", "LOG_get", "LOG_get_pub")
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


@reqs.description("Write/Read large messages on primary")
@reqs.supports_methods("LOG_record", "LOG_get")
def test_large_messages(network, args):
    primary, _ = network.find_primary()

    with primary.node_client() as nc:
        check_commit = infra.checker.Checker(nc)
        check = infra.checker.Checker()

        with primary.user_client() as c:
            id = 44
            for p in range(14, 20) if args.consensus == "raft" else range(10, 13):
                long_msg = "X" * (2 ** p)
                check_commit(
                    c.rpc("LOG_record", {"id": id, "msg": long_msg}), result=True,
                )
                check(c.get("LOG_get", {"id": id}), result={"msg": long_msg})
                id += 1

    return network


@reqs.description("Write/Read with cert prefix")
@reqs.supports_methods("LOG_record_prefix_cert", "LOG_get")
def test_cert_prefix(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        for user_id in network.initial_users:
            with primary.user_client(user_id) as c:
                log_id = 101
                msg = "This message will be prefixed"
                c.rpc("LOG_record_prefix_cert", {"id": log_id, "msg": msg})
                r = c.get("LOG_get", {"id": log_id})
                assert r.result is not None
                assert f"CN=user{user_id}" in r.result["msg"]

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Write as anonymous caller")
@reqs.supports_methods("LOG_record_anonymous", "LOG_get")
def test_anonymous_caller(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        # Create a new user but do not record its identity
        network.create_user(4, args.participants_curve)

        log_id = 101
        msg = "This message is anonymous"
        with primary.user_client(user_id=4) as c:
            r = c.rpc("LOG_record_anonymous", {"id": log_id, "msg": msg})
            assert r.result == True
            r = c.get("LOG_get", {"id": log_id})
            assert (
                r.error is not None
            ), "Anonymous user is not authorised to call LOG_get"

        with primary.user_client(user_id=0) as c:
            r = c.get("LOG_get", {"id": log_id})
            assert r.result is not None
            assert msg in r.result["msg"]
    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Write non-JSON body")
@reqs.supports_methods("LOG_record_raw_text", "LOG_get")
def test_raw_text(network, args):
    if args.package == "liblogging":
        primary, _ = network.find_primary()

        log_id = 101
        msg = "This message is not in JSON"
        with primary.user_client() as c:
            r = c.rpc(
                "LOG_record_raw_text",
                msg,
                headers={"content-type": "text/plain", "x-log-id": str(log_id)},
            )
            assert r.status == http.HTTPStatus.OK.value
            r = c.get("LOG_get", {"id": log_id})
            assert r.result is not None
            assert msg in r.result["msg"]

    else:
        LOG.warning(
            f"Skipping {inspect.currentframe().f_code.co_name} as application is not C++"
        )

    return network


@reqs.description("Testing forwarding on member and node frontends")
@reqs.supports_methods("mkSign")
@reqs.at_least_n_nodes(2)
def test_forwarding_frontends(network, args):
    primary, backup = network.find_primary_and_any_backup()

    with primary.node_client() as nc:
        check_commit = infra.checker.Checker(nc)
        with backup.node_client() as c:
            check_commit(c.rpc("mkSign"), result=True)
        with backup.member_client() as c:
            check_commit(c.rpc("mkSign"), result=True)

    return network


@reqs.description("Uninstalling Lua application")
@reqs.lua_generic_app
def test_update_lua(network, args):
    if args.package == "liblua_generic":
        LOG.info("Updating Lua application")
        primary, term = network.find_primary()

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

        network.consortium.set_lua_app(remote_node=primary, app_script=new_app_file)
        with primary.user_client() as c:
            check(c.rpc("ping"), result="pong")

            LOG.debug("Check that former endpoints no longer exists")
            for endpoint in [
                "LOG_record",
                "LOG_record_pub",
                "LOG_get",
                "LOG_get_pub",
            ]:
                check(
                    c.rpc(endpoint),
                    error=lambda status, msg: status == http.HTTPStatus.NOT_FOUND.value,
                )
    else:
        LOG.warning("Skipping Lua app update as application is not Lua")

    return network


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

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
            network = test_large_messages(network, args)
            network = test_forwarding_frontends(network, args)
            network = test_update_lua(network, args)
            network = test_cert_prefix(network, args)
            network = test_anonymous_caller(network, args)
            network = test_raw_text(network, args)


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
