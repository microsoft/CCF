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

            time.sleep(3)

            with primary.user_client(format="json") as c:
                c.rpc("LOG_record", {"id": 42, "msg": "Hello"})


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
