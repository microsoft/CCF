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
import infra.e2e_args
from threading import Timer
import random
import contextlib

from loguru import logger as LOG

# 256 is the number of most recent messages that PBFT keeps in memory before needing to replay the ledger
TOTAL_REQUESTS = 256


def timeout(node, suspend, election_timeout):
    if suspend:
        # We want to suspend the nodes' process so we need to initiate a new timer to wake it up eventually
        node.suspend()
        next_timeout = random.uniform(2 * election_timeout, 3 * election_timeout)
        LOG.info(f"New timer set for node {node.node_id} is {next_timeout} seconds")
        t = Timer(next_timeout, timeout, args=[node, False, 0])
        t.start()
    else:
        node.resume()


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        first_node, (backups) = network.start_and_join(args)

        term_info = {}
        long_msg = "X" * (2 ** 14)

        # first timer determines after how many seconds each node will be suspended
        timeouts = []
        t = random.uniform(1, 10)
        LOG.info(f"Initial timer for node {first_node.node_id} is {t} seconds...")
        timeouts.append((t, first_node))
        for backup in backups:
            t = random.uniform(1, 10)
            LOG.info(f"Initial timer for node {backup.node_id} is {t} seconds...")
            timeouts.append((t, backup))

        for t, node in timeouts:
            tm = Timer(t, timeout, args=[node, True, args.election_timeout / 1000],)
            tm.start()

        with first_node.node_client() as mc:
            check_commit = infra.checker.Checker(mc)
            check = infra.checker.Checker()

            clients = []
            with contextlib.ExitStack() as es:
                LOG.info("Write messages to nodes using round robin")
                clients.append(es.enter_context(first_node.user_client(format="json")))
                for backup in backups:
                    clients.append(es.enter_context(backup.user_client(format="json")))
                node_id = 0
                for id in range(1, TOTAL_REQUESTS):
                    node_id += 1
                    c = clients[node_id % len(clients)]
                    try:
                        resp = c.rpc("LOG_record", {"id": id, "msg": long_msg})
                    except Exception:
                        LOG.info("Trying to access a suspended node")
                    try:
                        cur_primary, cur_term = network.find_primary()
                        term_info[cur_term] = cur_primary.node_id
                    except Exception:
                        LOG.info("Trying to access a suspended node")
                    id += 1

                # wait for the last request to commit
                final_msg = "Hello world!"
                check_commit(
                    c.rpc("LOG_record", {"id": 1000, "msg": final_msg}), result=True,
                )
                check(
                    c.rpc("LOG_get", {"id": 1000}), result={"msg": final_msg},
                )

                # check that a new node can catch up after all the requests
                new_node = network.create_and_trust_node(
                    lib_name=args.package, host="localhost", args=args,
                )
                assert new_node

                # give new_node a second to catch up
                time.sleep(1)

                with new_node.user_client(format="json") as c:
                    check(
                        c.rpc("LOG_get", {"id": 1000}), result={"msg": final_msg},
                    )

                # assert that view changes actually did occur
                assert len(term_info) > 1

                LOG.success("----------- terms and primaries recorded -----------")
                for term, primary in term_info.items():
                    LOG.success(f"term {term} - primary {primary}")


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script and "libluageneric" or "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
