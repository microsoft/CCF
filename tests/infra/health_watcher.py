from enum import Enum, auto
from collections import Counter
import time
import threading

from loguru import logger as LOG


class HealthState(Enum):
    healthy = auto()
    unavailable = auto()
    partitioned = auto()
    election = auto()
    recovery = auto()


def get_primary(node, client_node_timeout_s=3):
    with node.client() as c:
        try:
            r = c.get("/node/network", timeout=client_node_timeout_s).body.json()
            return (r["primary_id"], r["current_view"])
        except Exception as e:
            LOG.warning(f"Could not connect to node {node.local_node_id}: {e}")
            return None


def get_network_health(network, client_node_timeout_s=3):
    primaries = {}
    nodes = network.get_joined_nodes()
    quorum = (len(nodes) + 1) // 2
    LOG.success(f"Quorum is {quorum}")
    for node in nodes:
        primaries[node.node_id] = get_primary(node, client_node_timeout_s)

    assert len(primaries) == len(nodes)

    primaries_count = Counter(primaries.values())
    most_common_primary, most_common_count = primaries_count.most_common()[0]
    LOG.info(primaries)
    LOG.warning(primaries_count)
    LOG.success(most_common_primary)
    if most_common_primary is None:
        # A majority of nodes are unreachable
        return HealthState.unavailable

    if primaries[most_common_primary[0]] != most_common_primary:
        # A majority of nodes still report a primary but this primary is
        # about to lose its primaryship
        return HealthState.election

    return (
        HealthState.healthy if most_common_count < quorum else HealthState.election
    )  # TODO: Wrong on purpose


def watch_network_health(
    network,
    election_timeout_s=5,
    election_timeout_factor=1,
    poll_interval_s=1,
    client_node_timeout_s=3,
):
    election_start_time = None
    while True:
        health_state = get_network_health(network, client_node_timeout_s)
        if health_state == HealthState.healthy:
            election_start_time = None
            LOG.success(f"Healthy network")
        else:
            LOG.warning(f"Election network")
            if election_start_time is None:
                election_start_time = time.time()
            LOG.info(election_timeout_factor * election_timeout_s)
            if (
                time.time() - election_start_time
                > election_timeout_factor * election_timeout_s
            ):
                LOG.error("Recovery!")
                return

        time.sleep(poll_interval_s)


def start_watch_network_health(network):
    t = threading.Thread(watch_network_health, args=None)
    t.start()
    t.join()
