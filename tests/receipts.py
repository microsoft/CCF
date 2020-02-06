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
import infra.notification
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("getReceipt", "verifyReceipt", "LOG_get")
@reqs.at_least_n_nodes(2)
def test(network, args, notifications_queue=None):
    primary, backup = network.find_primary_and_any_backup()

    with primary.node_client() as mc:
        check_commit = infra.checker.Checker(mc, notifications_queue)
        check = infra.checker.Checker()

        msg = "Hello world"

        LOG.info("Write/Read on primary")
        with primary.user_client(format="json") as c:
            check_commit(c.rpc("LOG_record", {"id": 42, "msg": msg}), result=True)
            r = c.rpc("LOG_get", {"id": 42})
            check(r, result={"msg": msg})
            r = c.rpc("getReceipt", {"commit": r.commit})
            check(
                c.rpc("verifyReceipt", {"receipt": r.result["receipt"]}),
                result={"valid": True},
            )
            invalid = r.result["receipt"]
            invalid[-3] += 1
            check(c.rpc("verifyReceipt", {"receipt": invalid}), result={"valid": False})

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:
        notifications_queue = notifications.get_queue()

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            network.start_and_join(args)
            test(network, args, notifications_queue)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script or "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
