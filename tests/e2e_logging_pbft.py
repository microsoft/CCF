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
    hosts = ["localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            primary, _ = network.start_and_join(args)

            with primary.management_client() as mc:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()

                msg = "Hello world"
                msg2 = "Hello there"

                LOG.debug("Write/Read on primary")
                with primary.user_client(format="json") as c:
                    check_commit(
                        c.rpc("LOG_record", {"id": 42, "msg": msg}), result=True
                    )
                    check_commit(
                        c.rpc("LOG_record", {"id": 43, "msg": msg2}), result=True
                    )
                    check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})
                    check(c.rpc("LOG_get", {"id": 43}), result={"msg": msg2})

                LOG.debug("Write/Read large messages on primary")
                with primary.user_client(format="json") as c:
                    id = 44
                    # For larger values of p, PBFT crashes since the size of the
                    # request is bigger than the max size supported by PBFT
                    # (Max_message_size)
                    for p in range(10, 13):
                        long_msg = "X" * (2 ** p)
                        check_commit(
                            c.rpc("LOG_record", {"id": id, "msg": long_msg}),
                            result=True,
                        )
                        check(c.rpc("LOG_get", {"id": id}), result={"msg": long_msg})
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
