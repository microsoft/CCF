# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.notification
import suite.test_requirements as reqs
import infra.logging_app as app
import e2e_args

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("LOG_record", "LOG_record_pub", "LOG_get", "LOG_get_pub")
@reqs.at_least_n_nodes(2)
def test(network, args, notifications_queue=None, verify=True):
    txs = app.LoggingTxs(notifications_queue=notifications_queue)
    txs.issue(network=network, number_txs=1, wait_for_sync=args.consensus == "raft")
    txs.issue(
        network=network,
        number_txs=1,
        on_backup=True,
        wait_for_sync=args.consensus == "raft",
    )
    # TODO: Once the JS app supports both public and private tables, always verify
    if verify:
        txs.verify(network)
    else:
        LOG.warning("Skipping log messages verification")

    return network


@reqs.description("Write/Read large messages on primary")
@reqs.supports_methods("LOG_record", "LOG_get")
def test_large_messages(network, args):
    primary, _ = network.find_primary()

    with primary.node_client(format="json") as nc:
        check_commit = infra.checker.Checker(nc)
        check = infra.checker.Checker()

        with primary.user_client(format="json") as c:
            id = 44
            for p in range(14, 20) if args.consensus == "raft" else range(10, 13):
                long_msg = "X" * (2 ** p)
                check_commit(
                    c.rpc("LOG_record", {"id": id, "msg": long_msg}), result=True,
                )
                check(c.rpc("LOG_get", {"id": id}), result={"msg": long_msg})
                id += 1

    return network


@reqs.description("Testing forwarding on member and node frontends")
@reqs.supports_methods("mkSign")
@reqs.at_least_n_nodes(2)
def test_forwarding_frontends(network, args):
    primary, backup = network.find_primary_and_any_backup()

    with primary.node_client(format="json") as nc:
        check_commit = infra.checker.Checker(nc)
        with backup.node_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)
        with backup.member_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)

    return network


@reqs.description("Uninstalling Lua application")
@reqs.lua_generic_app
def test_update_lua(network, args):
    if args.package == "libluagenericenc":
        LOG.info("Updating Lua application")
        primary, term = network.find_primary()

        check = infra.checker.Checker()

        # Create a new lua application file (minimal app)
        # TODO: Writing to file will not be required when memberclient is deprecated
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
            member_id=1, remote_node=primary, app_script=new_app_file
        )
        with primary.user_client(format="json") as c:
            check(c.rpc("ping", params={}), result="pong")

            LOG.debug("Check that former endpoints no longer exists")
            for endpoint in [
                "LOG_record",
                "LOG_record_pub",
                "LOG_get",
                "LOG_get_pub",
            ]:
                check(
                    c.rpc(endpoint, params={}),
                    error=lambda e: e is not None
                    and e["code"] == infra.jsonrpc.ErrorCode.METHOD_NOT_FOUND.value,
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
            if (args.package == "libloggingenc" and args.consensus == "raft")
            else None
        )

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
        ) as network:
            network.start_and_join(args)
            network = test(
                network,
                args,
                notifications_queue,
                verify=args.package is not "libjsgenericenc",
            )
            network = test_large_messages(network, args)
            network = test_forwarding_frontends(network, args)
            network = test_update_lua(network, args)


if __name__ == "__main__":

    args = e2e_args.cli_args()
    if args.js_app_script:
        args.package = "libjsgenericenc"
    elif args.app_script:
        args.package = "libluagenericenc"
    else:
        args.package = "libloggingenc"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
