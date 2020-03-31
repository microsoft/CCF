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

# pbft will store up to 64 of each message type (pre-prepare/prepare/commit) and retransmit these messages to replicas that are behind, enabling catch up.
# If a replica is too far behind then we need to send entries from the ledger, which is one of the things we want to test here.
# By sending 33 RPC requests and a getCommit for each of them (what raft consideres as a read pbft will process as a write),
# we are sure that we will have to go via the ledger to help late joiners catch up (total 66 reqs > 64)
TOTAL_REQUESTS = 33

s = random.randint(1, 10)
LOG.info(f"setting seed to {s}")
random.seed(s)


def timeout_handler(node, suspend, election_timeout):
    if suspend:
        # We want to suspend the nodes' process so we need to initiate a new timer to wake it up eventually
        node.suspend()
        next_timeout = random.uniform(2 * election_timeout, 3 * election_timeout)
        LOG.info(f"New timer set for node {node.node_id} is {next_timeout} seconds")
        t = Timer(next_timeout, timeout_handler, args=[node, False, 0])
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
        LOG.info("Trying to access a suspended network")
    return term_info


def assert_node_up_to_date(check, node, final_msg, final_msg_id, timeout=30):
    with node.user_client() as c:
        # Wait until final_msg_id is available in the node.
        # We need to catch timeout and assertion errors as
        # the node (e.g. late joiner) might not be up to date yet
        # or we might be in the middle of a view change so the node
        # will not be responsive. This timeout should be reduced when
        # checkpoints are implemented making catchup take less time
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                check(
                    c.get("LOG_get", {"id": final_msg_id}), result={"msg": final_msg},
                )
                return
            except (TimeoutError, requests.exceptions.ReadTimeout,) as e:
                LOG.error(f"Timeout error for LOG_get on node {node.node_id}")
                time.sleep(0.1)
            except AssertionError as e:
                LOG.error(
                    f"Assertion error for LOG_get on node {node.node_id}, error:{e}"
                )
                time.sleep(0.1)
        raise AssertionError(f"{node.nodeid} is not up to date")


def wait_for_nodes(nodes, final_msg, final_msg_id, timeout=30):
    # in the event of an early view change this might
    # take longer than usual to complete and we don't want the test to break here
    timeout = timeout * len(nodes)
    with nodes[0].node_client() as mc:
        check_commit = infra.checker.Checker(mc)
        check = infra.checker.Checker()
        for i, node in enumerate(nodes):
            with node.user_client() as c:
                end_time = time.time() + timeout
                while time.time() < end_time:
                    try:
                        check_commit(
                            c.rpc(
                                "LOG_record", {"id": final_msg_id + i, "msg": final_msg}
                            ),
                            result=True,
                        )
                        break
                    except TimeoutError:
                        LOG.error(f"Timeout error for LOG_get on node {node.node_id}")
                        time.sleep(0.1)
        # assert all nodes are caught up
        for node in nodes:
            assert_node_up_to_date(check, node, final_msg, final_msg_id)


def run_requests(
    nodes, total_requests, start_id, final_msg, final_msg_id, cant_fail=True
):
    with nodes[0].node_client() as mc:
        check_commit = infra.checker.Checker(mc)
        check = infra.checker.Checker()
        clients = []
        with contextlib.ExitStack() as es:
            for node in nodes:
                clients.append(es.enter_context(node.user_client()))
            node_id = 0
            long_msg = "X" * (2 ** 14)
            for id in range(start_id, (start_id + total_requests)):
                node_id += 1
                c = clients[node_id % len(clients)]
                try:
                    check_commit(
                        c.rpc("LOG_record", {"id": id, "msg": long_msg}), result=True
                    )
                except (TimeoutError, requests.exceptions.ReadTimeout,) as e:
                    LOG.info("Trying to access a suspended network")
                    if cant_fail:
                        raise RuntimeError(e)
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
        catchup_msg = "Hey world!"
        final_msg = "Goodbye, world!"

        with first_node.node_client() as mc:
            check_commit = infra.checker.Checker(mc)
            check = infra.checker.Checker()

            run_requests(all_nodes, TOTAL_REQUESTS, 0, first_msg, 1000)
            term_info.update(find_primary(network))

            nodes_to_kill = [network.find_any_backup()]
            nodes_to_keep = [n for n in all_nodes if n not in nodes_to_kill]

            # check that a new node can catch up after all the requests
            LOG.info("Adding a very late joiner")
            late_joiner = network.create_and_trust_node(
                lib_name=args.package, host="localhost", args=args,
            )
            nodes_to_keep.append(late_joiner)

            # some requests to be processed while the late joiner catches up
            # (no strict checking that these requests are actually being processed simultaneously with the node catchup)
            run_requests(all_nodes, int(TOTAL_REQUESTS / 2), 1001, second_msg, 2000)
            term_info.update(find_primary(network))

            assert_node_up_to_date(check, late_joiner, first_msg, 1000)
            assert_node_up_to_date(check, late_joiner, second_msg, 2000)

            if not args.skip_suspension:
                # kill the old node(s) and ensure we are still making progress with the new one(s)
                for node in nodes_to_kill:
                    LOG.info(f"Stopping node {node.node_id}")
                    node.stop()

                wait_for_nodes(nodes_to_keep, catchup_msg, 3000)

                cur_primary, _ = network.find_primary()
                cur_primary_id = cur_primary.node_id

                # first timer determines after how many seconds each node will be suspended
                timeouts = []
                suspended_nodes = []
                for i, node in enumerate(nodes_to_keep):
                    # if pbft suspend half of them including the primary
                    if i % 2 != 0 and args.consensus == "pbft":
                        continue
                    LOG.success(f"Will suspend node with id {node.node_id}")
                    t = random.uniform(1, 2)
                    LOG.info(f"Initial timer for node {node.node_id} is {t} seconds...")
                    timeouts.append((t, node))
                    suspended_nodes.append(node.node_id)

                for t, node in timeouts:
                    et = (
                        args.pbft_view_change_timeout / 1000
                        if args.consensus == "pbft"
                        else args.raft_election_timeout / 1000
                    )

                    if node.node_id == cur_primary_id and args.consensus == "pbft":
                        # if pbft suspend the primary for twice the elecetion timeout
                        # in order to make sure view changes will be triggered
                        et += et
                    tm = Timer(t, timeout_handler, args=[node, True, et])
                    tm.start()

                run_requests(
                    nodes_to_keep,
                    2 * TOTAL_REQUESTS,
                    2001,
                    final_msg,
                    4000,
                    cant_fail=False,
                )

                term_info.update(find_primary(network))

                wait_for_nodes(nodes_to_keep, final_msg, 5000)

                # we have asserted that all nodes are caught up
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
        args.package = "libjs_generic"
    elif args.app_script:
        args.package = "liblua_generic"
    else:
        args.package = "liblogging"
    run(args)
