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

                LOG.debug("Write/Read on follower")
                with follower.user_client(format="json") as c:
                    # In the case of leader forwarding, record the follower's current commit index
                    if args.leader_forwarding:
                        id = c.request("getCommit", {})
                        commit_before = c.response(id).commit

                    check(
                        c.rpc("LOG_record", {"id": 0, "msg": follower_msg}),
                        error=lambda e: e["code"]
                        == (
                            infra.jsonrpc.ErrorCode.RPC_FORWARDED
                            if args.leader_forwarding
                            else infra.jsonrpc.ErrorCode.TX_NOT_LEADER
                        ),
                    )
                    check(c.rpc("LOG_get", {"id": 42}), result=msg)

                    if args.leader_forwarding:
                        # In the case of leader forwarding, wait until the forwarded transaction
                        # has been replicated before reading record
                        for _ in range(network.replication_delay):
                            id = c.request("getCommit", {})
                            if c.response(id).commit >= commit_before + 2:
                                break
                            time.sleep(1)

                        check(c.rpc("LOG_get", {"id": 0}), result=follower_msg)

                LOG.debug("Write/Read large messages on leader")
                with primary.user_client(format="json") as c:
                    long_msg = "X" * 16384
                    check_commit(
                        c.rpc("LOG_record", {"id": 44, "msg": long_msg}), result="OK"
                    )
                    check(c.rpc("LOG_get", {"id": 44}), result=long_msg)


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
