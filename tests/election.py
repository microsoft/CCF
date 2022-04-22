# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from ccf.tx_id import TxID
from infra.network import PrimaryNotFound
import math
import infra.network
import infra.proc
import infra.e2e_args
import infra.checker
import suite.test_requirements as reqs
from infra.runner import ConcurrentRunner
import copy
import infra.service_load

from loguru import logger as LOG

# This test starts from a given number of nodes (hosts), commits
# a transaction, stops the current primary, waits for an election and repeats
# this process until no progress can be made (i.e. no primary can be elected
# as F > N/2).


@reqs.description("Stop current primary and wait for a new one to be elected")
def test_kill_primary_no_reqs(network, args):
    old_primary, _ = network.find_primary_and_any_backup()
    old_primary.stop()
    new_primary, _ = network.wait_for_new_primary(old_primary)

    # Verify that the TxID reported just after an election is valid
    # Note that the first TxID read after an election may be of a signature
    # Tx (time-based signature generation) in the new term rather than the
    # last entry in the previous term
    for node in network.get_joined_nodes():
        with node.client() as c:
            r = c.get("/node/network")
            c.wait_for_commit(r)

            # Also verify that reported last ack time are as expected
            r = c.get("/node/consensus")
            acks = r.body.json()["details"]["acks"]
            for ack in acks.values():
                if node is new_primary:
                    assert (
                        ack["last_received_ms"] < network.args.election_timeout_ms
                    ), acks
                else:
                    assert (
                        ack["last_received_ms"] == 0
                    ), f"Backup {node.local_node_id} should report time of last acks of 0: {acks}"

    return network


# Called by test suite. Election test deliberately makes service unusable.
@reqs.can_kill_n_nodes(1)
def test_kill_primary(network, args):
    return test_kill_primary_no_reqs(network, args)


def run(args):
    with infra.service_load.load() as load:
        with infra.network.network(
            args.nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            pdb=args.pdb,
            service_load=load,
        ) as network:
            check = infra.checker.Checker()

            network.start_and_open(args)
            current_view = None
            primary, current_view = network.find_primary()

            # Number of nodes F to stop until network cannot make progress
            nodes_to_stop = math.ceil(len(args.nodes) / 2)
            if args.consensus == "BFT":
                nodes_to_stop = math.ceil(len(args.nodes) / 3)

            primary_is_known = True
            for node_to_stop in range(nodes_to_stop):
                primary, current_view = network.find_primary()

                LOG.debug(
                    "Commit new transactions, primary:{}, current_view:{}".format(
                        primary.local_node_id, current_view
                    )
                )
                with primary.client("user0") as c:
                    res = c.post(
                        "/app/log/private",
                        {
                            "id": current_view,
                            "msg": "This log is committed in view {}".format(
                                current_view
                            ),
                        },
                    )
                    check(res, result=True)

                LOG.debug("Waiting for transaction to be committed by all nodes")

                network.wait_for_all_nodes_to_commit(tx_id=TxID(res.view, res.seqno))

                try:
                    test_kill_primary_no_reqs(network, args)
                except PrimaryNotFound:
                    if node_to_stop < nodes_to_stop - 1:
                        raise
                    else:
                        primary_is_known = False

            assert not primary_is_known, "Primary is still known"
            LOG.success("Test ended successfully.")


if __name__ == "__main__":

    cr = ConcurrentRunner()

    args = copy.deepcopy(cr.args)

    if cr.args.consensus in ("CFT", "ALL"):
        args.consensus = "CFT"
        cr.add(
            "cft",
            run,
            package="samples/apps/logging/liblogging",
            nodes=infra.e2e_args.min_nodes(args, f=1),
            election_timeout_ms=1000,
            consensus="CFT",
        )

    if cr.args.consensus in ("BFT", "ALL"):
        args.consensus = "BFT"
        cr.add(
            "bft",
            run,
            package="samples/apps/logging/liblogging",
            nodes=infra.e2e_args.min_nodes(args, f=1),
            consensus="BFT",
        )

    cr.run(1)
