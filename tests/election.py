# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import copy
import http
import math

import infra.checker
import infra.e2e_args
import infra.network
import infra.proc
import infra.service_load
import suite.test_requirements as reqs
from ccf.tx_id import TxID
from infra.network import PrimaryNotFound
from infra.runner import ConcurrentRunner
from loguru import logger as LOG

# This test starts from a given number of nodes (hosts), commits
# a transaction, stops the current primary, waits for an election and repeats
# this process until no progress can be made (i.e. no primary can be elected
# as F > N/2).


@reqs.description("Stop current primary and wait for a new one to be elected")
def test_kill_primary_no_reqs(network, args):
    old_primary, _ = network.find_primary_and_any_backup()

    with old_primary.client() as c:
        # Get the current view history
        LOG.info("getting inital view history")
        res = c.get("/app/commit?view_history=true")
        assert res.status_code == http.HTTPStatus.OK
        assert "view_history" in res.body.json()
        assert type(res.body.json()["view_history"]) == list
        old_view_history = res.body.json()["view_history"]

    old_primary.stop()

    new_primary, _ = network.wait_for_new_primary(old_primary)

    with new_primary.client() as c:
        # Get the current view history
        LOG.info("getting updated view history")
        res = c.get("/app/commit?view_history=true")
        assert res.status_code == http.HTTPStatus.OK
        assert "view_history" in res.body.json()
        assert type(res.body.json()["view_history"]) == list
        new_view_history = res.body.json()["view_history"]
        # Check that the view history has been updated with a new term for the new primary
        # new view history should be longer than old view history but may be more than one ahead due to multiple rounds occurring.
        assert len(new_view_history) >= len(old_view_history)
        assert old_view_history == new_view_history[: len(old_view_history)]

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


@reqs.description("Test the commit endpoints view_history feature")
def test_commit_view_history(network, args):
    remote_node, _ = network.find_primary()
    with remote_node.client() as c:
        # Endpoint works with no query parameter
        res = c.get("/app/commit")
        assert res.status_code == http.HTTPStatus.OK
        assert "view_history" not in res.body.json()

        # Invalid query parameter
        res = c.get("/app/commit?view_history=nottrue")
        assert res.status_code == http.HTTPStatus.BAD_REQUEST
        assert res.body.json() == {
            "error": {
                "code": "InvalidQueryParameterValue",
                "message": "Invalid value for view_history, must be one of [true, false] when present",
            }
        }

        # true view_history should list all history
        res = c.get("/app/commit?view_history=true")
        assert res.status_code == http.HTTPStatus.OK
        assert "view_history" in res.body.json()
        assert type(res.body.json()["view_history"]) == list
        view_history = res.body.json()["view_history"]

        res = c.get("/node/network")
        assert res.status_code == http.HTTPStatus.OK
        current_view = res.body.json()["current_view"]

        # ask for an invalid view
        res = c.get("/app/commit?view_history_since=0")
        assert res.status_code == http.HTTPStatus.BAD_REQUEST
        assert res.body.json() == {
            "error": {
                "code": "InvalidQueryParameterValue",
                "message": "Invalid value for view_history_since, must be in range [1, current_term]",
            }
        }

        # views start at 1, at least internally
        res = c.get("/app/commit?view_history_since=1")
        assert res.status_code == http.HTTPStatus.OK
        assert res.body.json()["view_history"] == view_history

        # in reality they start at 2
        res = c.get("/app/commit?view_history_since=2")
        assert res.status_code == http.HTTPStatus.OK
        assert res.body.json()["view_history"] == view_history[1:]

        # getting from the current one should give just that
        res = c.get(f"/app/commit?view_history_since={current_view}")
        assert res.status_code == http.HTTPStatus.OK
        assert res.body.json()["view_history"] == [view_history[-1]]

        # getting from the future doesn't work
        res = c.get(f"/app/commit?view_history_since={current_view + 1}")
        assert res.status_code == http.HTTPStatus.NOT_FOUND
        assert res.body.json() == {
            "error": {
                "code": "InvalidQueryParameterValue",
                "message": "Invalid value for view_history_since, must be in range [1, current_term]",
            }
        }

        # view_history should override the view_history_since
        res = c.get(f"/app/commit?view_history=true&view_history_since={current_view}")
        assert res.status_code == http.HTTPStatus.OK
        assert res.body.json()["view_history"] == view_history

    return network


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
                    test_commit_view_history(network, args)
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
