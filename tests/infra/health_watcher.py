from enum import Enum, auto
from collections import Counter
import time

from loguru import logger as LOG


class HealthState(Enum):
    healthy = auto()
    partitioned = auto()
    election = auto()
    recovery = auto()


def watch_network_health(
    network,
    election_timeout_s=5,
    election_timeout_factor=1,
    poll_interval_s=1,
    client_node_timeout_s=3,
):
    network_health_state = None
    primaries = {}
    candidates = {}
    election_start_time = None

    while True:

        nodes = network.get_joined_nodes()
        quorum = (len(nodes) + 1) // 2
        LOG.success(f"Quorum is {quorum}")
        for node in nodes:
            with node.client() as c:
                try:
                    r = c.get(
                        "/node/network", timeout=client_node_timeout_s
                    ).body.json()
                except Exception as e:
                    LOG.warning(f"Could not connect to node {node.local_node_id}: {e}")
                primaries[node.local_node_id] = (r["primary_id"], r["current_view"])

        LOG.error(primaries)
        primaries_count = Counter(primaries.values())
        LOG.info(primaries_count)
        most_common_primary, most_common_count = primaries_count.most_common()[0]
        LOG.success(most_common_primary)
        if most_common_count < quorum:  # TODO: Wrong on purpose
            LOG.success(
                f"Healthy network: {most_common_count} nodes reported same primary {most_common_primary}"
            )
            network_health_state = HealthState.healthy
        else:
            LOG.warning(f"Election network")
            if election_start_time is None:
                election_start_time = time.time()
                LOG.success(election_start_time)
            network_health_state = HealthState.election
            LOG.info(election_timeout_factor * election_timeout_s)
            if (
                time.time() - election_start_time
                > election_timeout_factor * election_timeout_s
            ):
                LOG.error("Recovery!")
                return

        time.sleep(poll_interval_s)
    # TODO:
    # 1. If quorum of nodes return same primary (that is part of them) in same term, healthy
    # 2. Otherwise, if some nodes are candidates, start election process
    # 3. Otherwise, unknown
