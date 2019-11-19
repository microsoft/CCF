# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import getpass
import time
import logging
import multiprocessing
import shutil
from random import seed
import infra.ccf
import infra.proc
import infra.jsonrpc
import infra.notification
import infra.net
import suite.test_requirements as reqs
import e2e_args

from loguru import logger as LOG


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


@reqs.logging_app
@reqs.at_least_2_nodes
def test(network, args, notifications_queue=None):
    LOG.info("Running transactions against logging app")
    primary, backup = network.find_primary_and_any_backup()

    with primary.node_client() as mc:
        check_commit = infra.checker.Checker(mc, notifications_queue)
        check = infra.checker.Checker()

        msg = "Hello world"
        msg2 = "Hello there"
        backup_msg = "Msg sent to a backup"

        LOG.info("Write/Read on primary")
        with primary.user_client(format="json") as c:
            check_commit(c.rpc("LOG_record", {"id": 42, "msg": msg}), result=True)
            check_commit(c.rpc("LOG_record", {"id": 43, "msg": msg2}), result=True)
            check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})
            check(c.rpc("LOG_get", {"id": 43}), result={"msg": msg2})

        LOG.info("Write on all backup frontends")
        with backup.node_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)
        with backup.member_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)

        LOG.info("Write/Read on backup")

        with backup.user_client(format="json") as c:
            check_commit(
                c.rpc("LOG_record", {"id": 100, "msg": backup_msg}), result=True
            )
            check(c.rpc("LOG_get", {"id": 100}), result={"msg": backup_msg})
            check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})

        # TODO: Remove when HTTP supports large messages
        if not os.getenv("HTTP"):
            LOG.info("Write/Read large messages on primary")
            with primary.user_client(format="json") as c:
                id = 44
                for p in range(14, 20):
                    long_msg = "X" * (2 ** p)
                    check_commit(
                        c.rpc("LOG_record", {"id": id, "msg": long_msg}), result=True,
                    )
                    check(c.rpc("LOG_get", {"id": id}), result={"msg": long_msg})
                    id += 1

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:
        # Lua apps do not support notifications
        # https://github.com/microsoft/CCF/issues/415
        notifications_queue = (
            notifications.get_queue() if args.package == "libloggingenc" else None
        )

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            network.start_and_join(args)
            test(network, args, notifications_queue)
            test_update_lua(network, args)


if __name__ == "__main__":

    args = e2e_args.cli_args()
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
