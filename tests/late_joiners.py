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
import requests

from loguru import logger as LOG

# 256 is the number of most recent messages that PBFT keeps in memory before needing to replay the ledger
# the rpc requests that are issued for spinning up the network and checking that all nodes have joined,
# along with TOTAL_REQUESTS, are enough to exceed this limit
TOTAL_REQUESTS = 60

s = random.randint(1, 10)
LOG.info(f"setting seed to {s}")
random.seed(s)


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


def find_primary(network):
    # track if there is a new primary
    term_info = {}
    try:
        cur_primary, cur_term = network.find_primary()
        term_info[cur_term] = cur_primary.node_id
    except TimeoutError:
        LOG.info("Trying to access a suspended node")
    return term_info


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


def assert_node_up_to_date(check, node, final_msg, final_msg_id):
    with node.user_client(format="json") as c:
        try:
            check(
                c.rpc("LOG_get", {"id": final_msg_id}), result={"msg": final_msg},
            )
        except TimeoutError:
            LOG.error(f"Timeout error for LOG_get on node {node.node_id}")


def wait_for_nodes(nodes, final_msg, final_msg_id):
    with nodes[0].node_client() as mc:
        check_commit = infra.checker.Checker(mc)
        check = infra.checker.Checker()
        for i, node in enumerate(nodes):
            with node.user_client(format="json") as c:
                check_commit(
                    c.rpc("LOG_record", {"id": final_msg_id + i, "msg": final_msg}),
                    result=True,
                )

        # assert all nodes are caught up
        for node in nodes:
            assert_node_up_to_date(check, node, final_msg, final_msg_id)


def run_requests(nodes, total_requests, start_id, final_msg, final_msg_id):
    with nodes[0].node_client() as mc:
        check_commit = infra.checker.Checker(mc)
        check = infra.checker.Checker()
        clients = []
        with contextlib.ExitStack() as es:
            for node in nodes:
                clients.append(es.enter_context(node.user_client(format="json")))
            node_id = 0
            long_msg = "X" * (2 ** 14)
            for id in range(start_id, (start_id + total_requests)):
                node_id += 1
                c = clients[node_id % len(clients)]
                try:
                    c.rpc("LOG_record", {"id": id, "msg": long_msg})
                except (TimeoutError, requests.exceptions.ReadTimeout,) as e:
                    LOG.info("Trying to access a suspended node")
                id += 1
        wait_for_nodes(nodes, final_msg, final_msg_id)


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        first_node, backups = network.find_nodes()
        all_nodes = network.get_joined_nodes()

        term_info = find_primary(network)
        first_msg = "Hello, world!"
        second_msg = "Hello, world hello!"
        final_msg = "Goodbye, world!"

        nodes_to_kill = [backups[0]]
        nodes_to_keep = [first_node, backups[1]]

        # first timer determines after how many seconds each node will be suspended
        if not args.skip_suspension:
            timeouts = []
            for node in all_nodes:
                t = random.uniform(1, 10)
                LOG.info(f"Initial timer for node {node.node_id} is {t} seconds...")
                timeouts.append((t, node))

            for t, node in timeouts:
                tm = Timer(t, timeout, args=[node, True, args.election_timeout / 1000],)
                tm.start()

        LOG.info(
            "Adding another node after f = 0 but before we need to send append entries"
        )
        # check that a new node can catch up naturally
        new_node = network.create_and_trust_node(
            lib_name=args.package, host="localhost", args=args,
        )
        assert new_node
        nodes_to_keep.append(new_node)

        with first_node.node_client() as mc:
            check_commit = infra.checker.Checker(mc)
            check = infra.checker.Checker()

            run_requests(all_nodes, TOTAL_REQUESTS, 0, first_msg, 1000)
            term_info.update(find_primary(network))

            # check that new node has caught up ok
            assert_node_up_to_date(check, new_node, first_msg, 1000)
            # add new node to backups list
            all_nodes.append(new_node)

            # check that a new node can catch up after all the requests
            LOG.info("Adding a very late joiner")
            last_node = network.create_and_trust_node(
                lib_name=args.package, host="localhost", args=args,
            )
            assert last_node
            nodes_to_keep.append(last_node)

            run_requests(all_nodes, TOTAL_REQUESTS, 1001, second_msg, 2000)
            term_info.update(find_primary(network))

            assert_node_up_to_date(check, last_node, first_msg, 1000)
            assert_node_up_to_date(check, last_node, second_msg, 2000)

            # replace the 2 backups with the 2 new nodes, kill the old ones and ensure we are still making progress
            for node in nodes_to_kill:
                LOG.info(f"Stopping node {node.node_id}")
                node.stop()

            wait_for_nodes(nodes_to_keep, final_msg, 4000)

            # we have asserted that all nodes are caught up

            if not args.skip_suspension:
                # assert that view changes actually did occur
                assert len(term_info) > 1

                LOG.success("----------- terms and primaries recorded -----------")
                for term, primary in term_info.items():
                    LOG.success(f"term {term} - primary {primary}")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--skip-suspension",
            help="Don't suspend any nodes (i.e. just do late join)",
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add)
    if args.js_app_script:
        args.package = "libjsgeneric"
    elif args.app_script:
        args.package = "libluageneric"
    else:
        args.package = "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
