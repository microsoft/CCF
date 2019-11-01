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
from threading import Timer
import random

from loguru import logger as LOG

# 256 is the number of messages PBFT keeps in memory before needing to replay the ledger
# by setting 200 pure requests we will surpass 256 messages being passed throught the protocol
TOTAL_REQUESTS = 200


def timeout(node, suspend, election_timeout):
    if suspend:
        # We want to suspend the nodes' process so we need to initiate a new timer to wake it up eventually
        if not node.suspend():
            LOG.info("Node can not be suspended, probably has stopped running")
            return
        next_timeout = random.uniform(election_timeout, 3 * election_timeout)
        LOG.info(f"New timer set for node {node.node_id} is {next_timeout} seconds")
        t = Timer(next_timeout, timeout, args=[node, False, 0])
        t.start()
    else:
        node.resume()


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.notification.notification_server(args.notify_server) as notifications:
        # Lua apps do not support notifications
        # https://github.com/microsoft/CCF/issues/415
        notifications_queue = (
            notifications.get_queue() if args.package == "libloggingenc" else None
        )

        with infra.ccf.network(
            hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            first_node, (backups) = network.start_and_join(args)

            term_info = {}
            long_msg = "X" * (2 ** 14)

            # first timer determines after how many seconds each node will be suspended
            t0 = random.uniform(1, 10)
            LOG.info(f"Initial timer for primary is {t0} seconds...")
            t1 = random.uniform(1, 10)
            LOG.info(f"Initial timer for backup 1 is {t1} seconds...")
            t2 = random.uniform(1, 10)
            LOG.info(f"Initial timer for backup 2 is {t2} seconds...")
            tm0 = Timer(
                t0, timeout, args=[first_node, True, args.election_timeout / 1000],
            )
            tm0.start()
            tm1 = Timer(
                t1, timeout, args=[backups[0], True, args.election_timeout / 1000]
            )
            tm1.start()
            tm2 = Timer(
                t2, timeout, args=[backups[1], True, args.election_timeout / 1000]
            )
            tm2.start()

            with first_node.node_client() as mc:
                check_commit = infra.ccf.Checker(mc, notifications_queue)
                check = infra.ccf.Checker()

                LOG.info("Write messages to nodes using round robin")
                with first_node.user_client(format="json") as c0:
                    with backups[0].user_client(format="json") as c1:
                        with backups[1].user_client(format="json") as c2:
                            node_id = 0
                            for id in range(1, TOTAL_REQUESTS):
                                node_id += 1
                                node_id %= 3
                                if node_id == 0:
                                    c = c0
                                elif node_id == 1:
                                    c = c1
                                else:
                                    c = c2
                                try:
                                    resp = c.rpc(
                                        "LOG_record", {"id": id, "msg": long_msg}
                                    )
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
                                c.rpc("LOG_record", {"id": 1000, "msg": final_msg}),
                                result=True,
                            )
                            check(
                                c.rpc("LOG_get", {"id": 1000}),
                                result={"msg": final_msg},
                            )

                            # check that a new node can catch up after all the requests
                            new_node = network.create_and_trust_node(
                                lib_name=args.package,
                                host="localhost",
                                args=args,
                                should_wait=False,
                            )
                            assert new_node

                            with new_node.user_client(format="json") as c:
                                while True:
                                    rep = c.do("LOG_get", {"id": 1000})
                                    if rep.error == None and rep.result is not None:
                                        LOG.success(f"Last node is all caught up!")
                                        break

                            # assert that view changes actually did occur
                            assert len(term_info) > 1

                            LOG.success(
                                "----------- terms and primaries recorded -----------"
                            )
                            for term, primary in term_info.items():
                                LOG.success(f"term {term} - primary {primary}")


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
