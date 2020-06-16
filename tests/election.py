# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import time
import math
import infra.ccf
import infra.proc
import infra.e2e_args
import http

from infra.tx_status import TxStatus
from loguru import logger as LOG

# This test starts from a given number of nodes (hosts), commits
# a transaction, stops the current primary, waits for an election and repeats
# this process until no progress can be made (i.e. no primary can be elected
# as F > N/2).


def wait_for_seqno_to_commit(seqno, view, nodes):
    """
    Wait for a specific seqno at a specific view to be committed on all nodes.
    """
    for _ in range(infra.ccf.Network.replication_delay * 10):
        up_to_date_f = []
        for f in nodes:
            with f.node_client() as c:
                r = c.get("tx", {"view": view, "seqno": seqno})
                assert (
                    r.status == http.HTTPStatus.OK
                ), f"tx request returned HTTP status {r.status}"
                status = TxStatus(r.result["status"])
                if status == TxStatus.Committed:
                    up_to_date_f.append(f.node_id)
                elif status == TxStatus.Invalid:
                    raise RuntimeError(
                        f"Node {f.node_id} reports transaction ID {view}.{seqno} is invalid and will never be committed"
                    )
                else:
                    pass
        if len(up_to_date_f) == len(nodes):
            break
        time.sleep(0.1)
    assert len(up_to_date_f) == len(
        nodes
    ), "Only {} out of {} nodes are up to date".format(len(up_to_date_f), len(nodes))


def run(args):
    # Three nodes minimum to make sure that the raft network can still make progress
    # if one node stops
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 3)

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        check = infra.checker.Checker()

        network.start_and_join(args)
        current_view = None

        # Number of nodes F to stop until network cannot make progress
        nodes_to_stop = math.ceil(len(hosts) / 2)
        if args.consensus == "pbft":
            nodes_to_stop = math.ceil(len(hosts) / 3)

        for _ in range(nodes_to_stop):
            # Note that for the first iteration, the primary is known in advance anyway
            LOG.debug("Find freshly elected primary")
            # After a view change in pbft, finding the new primary takes longer
            primary, current_view = network.find_primary(
                request_timeout=(30 if args.consensus == "pbft" else 3)
            )

            LOG.debug(
                "Commit new transactions, primary:{}, current_view:{}".format(
                    primary.node_id, current_view
                )
            )
            with primary.user_client() as c:
                res = c.rpc(
                    "LOG_record",
                    {
                        "id": current_view,
                        "msg": "This log is committed in view {}".format(current_view),
                    }
                )
                check(res, result=True)
                seqno = res.seqno

            LOG.debug("Waiting for transaction to be committed by all nodes")
            wait_for_seqno_to_commit(seqno, current_view, network.get_joined_nodes())

            LOG.debug("Stopping primary")
            primary.stop()

            LOG.debug(
                f"Waiting {network.election_duration}s for a new primary to be elected..."
            )
            time.sleep(network.election_duration)

        # More than F nodes have been stopped, trying to commit any message
        LOG.debug(
            "No progress can be made as more than {} nodes have stopped".format(
                nodes_to_stop
            )
        )
        try:
            primary, _ = network.find_primary()
            assert False, "Primary should not be found"
        except infra.ccf.PrimaryNotFound:
            pass

        LOG.success(
            f"As expected, primary could not be found after election duration ({network.election_duration}s)."
        )
        LOG.success("Test ended successfully.")


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    run(args)
