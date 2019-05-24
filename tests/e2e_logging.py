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


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            primary, (follower,) = network.start_and_join(args)

            with primary.management_client() as mc:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()
                check_notification = infra.ccf.Checker(None, notifications.get_queue())

                msg = "Hello world"
                msg2 = "Hello there"
                follower_msg = "Msg sent to a follower"

                LOG.debug("Write/Read on leader")
                with primary.user_client(format="json") as c:
                    check_commit(
                        c.rpc("LOG_record", {"id": 42, "msg": msg}), result="OK"
                    )
                    check_notification(
                        c.rpc("LOG_record", {"id": 43, "msg": msg2}), result="OK"
                    )
                    check(c.rpc("LOG_get", {"id": 42}), result=msg)
                    check(c.rpc("LOG_get", {"id": 43}), result=msg2)

                LOG.debug("Write on all follower frontends")
                with follower.management_client(format="json") as c:
                    check_commit(c.do("mkSign", params={}), result="OK")
                with follower.member_client(format="json") as c:
                    check_commit(c.do("mkSign", params={}), result="OK")

                LOG.debug("Write/Read on follower")
                with follower.user_client(format="json") as c:
                    check_commit(
                        c.rpc("LOG_record", {"id": 100, "msg": follower_msg}),
                        result="OK",
                    )
                    check(c.rpc("LOG_get", {"id": 100}), result=follower_msg)
                    check(c.rpc("LOG_get", {"id": 42}), result=msg)

                LOG.debug("Write/Read large messages on leader")
                with primary.user_client(format="json") as c:
                    id = 44
                    for p in range(14, 20):
                        long_msg = "X" * (2 ** p)
                        check_commit(
                            c.rpc("LOG_record", {"id": id, "msg": long_msg}),
                            result="OK",
                        )
                        check(c.rpc("LOG_get", {"id": id}), result=long_msg)
                    id += 1


if __name__ == "__main__":

    args = e2e_args.cli_args()
    args.package = "libloggingenc"
    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
