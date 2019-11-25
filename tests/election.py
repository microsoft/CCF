# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import getpass
import logging
import time
import math
import infra.ccf
import infra.proc
import infra.jsonrpc
import e2e_args

from loguru import logger as LOG

# This test starts from a given number of nodes (hosts), commits
# a transaction, stops the current primary, waits for an election and repeats
# this process until no progress can be made (i.e. no primary can be elected
# as F > N/2).


def wait_for_index_globally_committed(index, term, nodes):
    """
    Wait for a specific version at a specific term to be committed on all nodes.
    """
    for _ in range(infra.ccf.Network.replication_delay):
        up_to_date_f = []
        for f in nodes:
            with f.node_client() as c:
                id = c.request("getCommit", {"commit": index})
                res = c.response(id)
                if res.result["term"] == term and (res.global_commit >= index):
                    up_to_date_f.append(f.node_id)
        if len(up_to_date_f) == len(nodes):
            break
        time.sleep(1)
    assert len(up_to_date_f) == len(
        nodes
    ), "Only {} out of {} backups are up to date".format(len(up_to_date_f), len(nodes))


def run(args):
    # Three nodes minimum to make sure that the raft network can still make progress
    # if one node stops

    if args.consensus == "pbft":
        hosts = ["localhost", "localhost", "localhost", "localhost"]
    else:
        hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:

        network.start_and_join(args)
        current_term = None

        # Time before an election completes
        max_election_duration = args.election_timeout * 4 // 1000

        # Number of nodes F to stop until network cannot make progress
        nodes_to_stop = math.ceil(len(hosts) / 2)
        if args.consensus == "pbft":
            nodes_to_stop = math.ceil(len(hosts) / 3)

        for _ in range(nodes_to_stop):
            # Note that for the first iteration, the primary is known in advance anyway
            LOG.debug("Find freshly elected primary")
            primary, current_term = network.find_primary()

            LOG.debug(
                "Commit new transactions, primary:{}, current_term:{}".format(
                    primary, current_term
                )
            )
            commit_index = None
            with primary.user_client(format="json") as c:
                res = c.do(
                    "LOG_record",
                    {
                        "id": current_term,
                        "msg": "This log is committed in term {}".format(current_term),
                    },
                    readonly_hint=None,
                    expected_result=True,
                )
                commit_index = res.commit

            LOG.debug("Waiting for transaction to be committed by all nodes")
            wait_for_index_globally_committed(
                commit_index, current_term, network.get_joined_nodes()
            )

            LOG.debug("Stopping primary")
            primary.stop()

            LOG.debug("Waiting for a new primary to be elected...")
            time.sleep(max_election_duration)

        # More than F nodes have been stopped, trying to commit any message
        LOG.debug(
            "No progress can be made as more than {} nodes have stopped".format(
                nodes_to_stop
            )
        )
        try:
            primary, current_term = network.find_primary()
            assert False, "Primary should not be found"
        except TypeError:
            assert args.consensus == "pbft", "Unexpected error"
        except AssertionError:
            assert args.consensus == "raft", "Unexpected error"

        LOG.info(
            "As expected, primary could not be found after election timeout. Test ended successfully."
        )


if __name__ == "__main__":

    args = e2e_args.cli_args()
    args.package = "libloggingenc"
    run(args)
