# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from threading import Timer
import time
import suite.test_requirements as reqs
import infra.ccf
import random
from enum import Enum

from loguru import logger as LOG


class LateJoinerStatus(Enum):
    # late joiner is stuck and needs all other replicas to view change
    Stuck = "STUCK"
    # late joiner is not accepting the getLocalCommit RPC's
    NotReady = "NOT_READY"
    # late joiner has caught up with the other replicas
    Ready = "READY"


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


def update_view_info(network, view_info):
    try:
        cur_primary, cur_view = network.find_primary()
        view_info[cur_view] = cur_primary.node_id
    except TimeoutError:
        LOG.warning("Trying to access a suspended network")


def get_node_local_commit(node):
    with node.client() as c:
        r = c.get("/node/commit")
        return r.result["seqno"], r.global_commit


def wait_for_late_joiner(old_node, late_joiner, strict=False, timeout=60):
    old_node_lc, old_node_gc = get_node_local_commit(old_node)
    LOG.success(
        f"node {old_node.node_id} is at state local_commit:{old_node_lc}, global_commit:{old_node_gc}"
    )

    local_commit = 0
    end = time.time() + timeout
    while time.time() <= end:
        try:
            local_commit, gc = get_node_local_commit(late_joiner)
            LOG.success(
                f"late joiner {late_joiner.node_id} is at state local_commit:{local_commit}, global_commit:{gc}"
            )
            if local_commit >= old_node_lc:
                return LateJoinerStatus.Ready
            time.sleep(1)
        except (TimeoutError, infra.clients.CCFConnectionException,) as exc:
            LOG.warning(
                f"late joiner with node id {late_joiner.node_id} isn't quite ready yet: {exc}"
            )
    return_state = None
    if local_commit == 0:
        return_state = LateJoinerStatus.NotReady
    else:
        return_state = LateJoinerStatus.Stuck
    if strict:
        raise AssertionError(
            f"late joiner with node id {late_joiner.node_id} failed to catch up, it's final state is {return_state}"
        )
    else:
        return return_state


@reqs.description("Suspend nodes")
def test_suspend_nodes(network, args, nodes=None):
    cur_primary, _ = network.find_primary()
    if nodes is None:
        nodes = network.get_joined_nodes()

    # first timer determines after how many seconds each node will be suspended
    timeouts = []
    for i, node in enumerate(nodes):
        # if pbft suspend half of them including the primary
        if i % 2 != 0 and args.consensus == "pbft":
            continue
        LOG.success(f"Will suspend node with id {node.node_id}")
        t = random.uniform(0, 2)
        LOG.info(f"Initial timer for node {node.node_id} is {t} seconds...")
        timeouts.append((t, node))

    for t, node in timeouts:
        suspend_time = (
            args.pbft_view_change_timeout / 1000
            if args.consensus == "pbft"
            else args.raft_election_timeout / 1000
        )
        if node.node_id == cur_primary.node_id and args.consensus == "pbft":
            # if pbft suspend the primary for more than twice the election timeout
            # in order to make sure view changes will be triggered
            suspend_time = 2.5 * suspend_time
        tm = Timer(t, timeout_handler, args=[node, True, suspend_time])
        tm.start()
    return network
