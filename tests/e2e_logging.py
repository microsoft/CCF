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
import e2e_args

from loguru import logger as LOG


def log_get_string(msg):
    if args.package == "libloggingenc":
        return {"msg": msg}
    else:
        return msg


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:
        # Lua apps do not support notifications
        notifications_queue = (
            notifications.get_queue() if args.package == "libloggingenc" else None
        )

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            primary, (backup,) = network.start_and_join(args)

            with primary.node_client() as mc:
                check_commit = infra.ccf.Checker(mc, notifications_queue)
                check = infra.ccf.Checker()

                msg = "Hello world"
                msg2 = "Hello there"
                backup_msg = "Msg sent to a backup"

                LOG.debug("Write/Read on primary")
                with primary.user_client(format="json") as c:
                    check_commit(
                        c.rpc("LOG_record", {"id": 42, "msg": msg}), result=True
                    )
                    check_commit(
                        c.rpc("LOG_record", {"id": 43, "msg": msg2}), result=True
                    )
                    check(c.rpc("LOG_get", {"id": 42}), result=log_get_string(msg))
                    check(c.rpc("LOG_get", {"id": 43}), result=log_get_string(msg2))

                    LOG.debug("Write on all backup frontends")
                    with backup.node_client(format="json") as c:
                        check_commit(c.do("mkSign", params={}), result=True)
                    with backup.member_client(format="json") as c:
                        check_commit(c.do("mkSign", params={}), result=True)

                LOG.debug("Write/Read on backup")

                if args.package == "libluagenericenc":
                    LOG.success("Hint is write")
                    readonly_hint = False

                with backup.user_client(format="json") as c:
                    check_commit(
                        c.rpc(
                            "LOG_record",
                            {"id": 100, "msg": backup_msg},
                            readonly_hint=readonly_hint,
                        ),
                        result=True,
                    )
                    check(
                        c.rpc("LOG_get", {"id": 100}), result=log_get_string(backup_msg)
                    )
                    check(c.rpc("LOG_get", {"id": 42}), result=log_get_string(msg))

                LOG.debug("Write/Read large messages on primary")
                with primary.user_client(format="json") as c:
                    id = 44
                    for p in range(14, 20):
                        long_msg = "X" * (2 ** p)
                        check_commit(
                            c.rpc("LOG_record", {"id": id, "msg": long_msg}),
                            result=True,
                        )
                        check(
                            c.rpc("LOG_get", {"id": id}),
                            result=log_get_string(long_msg),
                        )
                    id += 1


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
