# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import getpass
import os
import time
import logging
import multiprocessing
import e2e_args
from random import seed
import infra.ccf
import infra.proc
import infra.jsonrpc
import infra.remote
import json
import functools

from loguru import logger as LOG

# Maximum number of retries of getCommit/getSignedIndex before test failure
MAX_GET_STATUS_RETRY = 3


class Txs:
    def __init__(self, nb_msgs, offset=0):
        self.pub = {}
        self.priv = {}

        for i in range(offset * nb_msgs, nb_msgs + offset * nb_msgs):
            self.pub[i] = "Public msg #{}".format(i)
            self.priv[i] = "Private msg #{}".format(i)


def check_nodes_have_msgs(nodes, txs):
    """
    Read and check values for messages at an offset. This effectively
    makes sure nodes have recovered state.
    """
    for node in nodes:
        with node.user_client() as c:
            for n, msg in txs.priv.items():
                c.do("LOG_get", {"id": n}, {"msg": msg.encode()})
            for n, msg in txs.pub.items():
                c.do("LOG_get_pub", {"id": n}, {"msg": msg.encode()})


def log_msgs(primary, txs):
    """
    Log a new series of messages
    """
    LOG.debug("Applying new transactions")
    responses = []
    with primary.user_client() as c:
        for n, msg in txs.priv.items():
            responses.append(c.rpc("LOG_record", {"id": n, "msg": msg}))
        for n, msg in txs.pub.items():
            responses.append(c.rpc("LOG_record_pub", {"id": n, "msg": msg}))
    return responses


def check_responses(responses, result, check, check_commit):
    for response in responses[:-1]:
        check(response, result=result)
    check_commit(responses[-1], result=result)


def wait_for_state(node, state):
    """
    Wait for the public ledger to be read completely on a node.
    """
    for _ in range(MAX_GET_STATUS_RETRY):
        try:
            with node.management_client() as c:
                id = c.request("getSignedIndex", {})
                r = c.response(id).result
                if r["state"] == state:
                    break
        except ConnectionRefusedError:
            pass
        time.sleep(1)
    else:
        raise TimeoutError("Timed out waiting for public ledger to be read")


def run(args):
    hosts = ["localhost", "localhost"]
    ledger = None
    sealed_secrets = []

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, backups = network.start_and_join(args)
        txs = Txs(args.msgs_per_recovery)

        with primary.management_client() as mc:
            check_commit = infra.ccf.Checker(mc)
            check = infra.ccf.Checker()

            rs = log_msgs(primary, txs)
            check_responses(rs, True, check, check_commit)
            network.wait_for_node_commit_sync()
            check_nodes_have_msgs(backups, txs)

            ledger = primary.remote.get_ledger()
            sealed_secrets = primary.remote.get_sealed_secrets()

    for recovery_idx in range(args.recovery):
        with infra.ccf.network(
            hosts,
            args.build_dir,
            args.debug_nodes,
            args.perf_nodes,
            node_offset=(recovery_idx + 1) * len(hosts),
            pdb=args.pdb,
        ) as network:
            primary, backups = network.start_in_recovery(args, ledger, sealed_secrets)

            with primary.management_client() as mc:
                check_commit = infra.ccf.Checker(mc)
                check = infra.ccf.Checker()

                for node in network.nodes:
                    wait_for_state(node, b"partOfPublicNetwork")
                network.wait_for_node_commit_sync()
                LOG.success("Public CFTR started")

                LOG.debug(
                    "2/3 members verify that the new nodes have joined the network"
                )
                for member_id in network.get_members()[0:2]:
                    with primary.member_client(member_id) as c:
                        new_node_ids_offsets = (recovery_idx + 1) * len(hosts)
                        for new_node_id in range(
                            new_node_ids_offsets, new_node_ids_offsets + len(hosts)
                        ):
                            id = c.request(
                                "read", {"table": "nodes", "key": new_node_id}
                            )
                            assert (
                                infra.remote.NodeStatus(c.response(id).result["status"])
                                == infra.remote.NodeStatus.trusted
                            )

                LOG.debug("2/3 members vote to complete the recovery")
                rc, result = network.propose(
                    1, primary, "accept_recovery", f"--sealed-secrets={sealed_secrets}"
                )
                assert rc and not result["completed"]
                proposal_id = result["id"]

                rc, result = network.vote(2, primary, proposal_id, True)
                assert rc and result

                for node in network.nodes:
                    wait_for_state(node, b"partOfNetwork")
                LOG.success("All nodes part of network")

                for _ in range(MAX_GET_STATUS_RETRY):
                    try:
                        with primary.management_client() as c:
                            id = c.request("getSignedIndex", {})
                            r = c.response(id).result
                            if r.get("state") == b"partOfNetwork":
                                break
                    except ConnectionRefusedError:
                        pass
                    time.sleep(1)
                else:
                    raise TimeoutError(
                        "Timed out waiting for private ledger to be read"
                    )
                LOG.success("Private ledger has been read on primary")

                old_txs = Txs(args.msgs_per_recovery, recovery_idx)

                for recovery_cnt in range(args.recovery):
                    check_nodes_have_msgs(network.nodes, old_txs)
                LOG.success(
                    "Recovery #{} complete on all nodes".format(recovery_idx + 1)
                )

                new_txs = Txs(args.msgs_per_recovery, recovery_idx + 1)

                rs = log_msgs(primary, new_txs)
                check_responses(rs, True, check, check_commit)
                network.wait_for_node_commit_sync()
                check_nodes_have_msgs(backups, new_txs)

                ledger = primary.remote.get_ledger()
                sealed_secrets = primary.remote.get_sealed_secrets()


if __name__ == "__main__":

    def add(parser):
        parser.description = """
This test executes multiple recoveries (as specified by the "--recovery" arg),
with a fixed number of messages applied between each network crash (as
specified by the "--msgs-per-recovery" arg). After the network is recovered
and before applying new transactions, all transactions previously applied are
checked. Note that the key for each logging message is unique (per table).
"""
        parser.add_argument(
            "--recovery", help="Number of recoveries to perform", type=int, default=2
        )
        parser.add_argument(
            "--msgs-per-recovery",
            help="Number of public and private messages between two recoveries",
            type=int,
            default=5,
        )

    args = e2e_args.cli_args(add)
    args.package = "libloggingenc"
    run(args)
