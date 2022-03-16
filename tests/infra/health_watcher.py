from enum import Enum, auto
from collections import Counter
import time
import threading

from loguru import logger as LOG


class HealthState(Enum):
    stable = auto()
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


def get_network_health(network, get_primary_fn, client_node_timeout_s=3):
    primaries = {}
    nodes = network.get_joined_nodes()
    quorum = (len(nodes) + 1) // 2
    LOG.success(f"Quorum is {quorum}")
    for node in nodes:
        primaries[node.node_id] = get_primary_fn(node, client_node_timeout_s)

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

    return HealthState.stable if most_common_count < quorum else HealthState.election




class StoppableThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stop_event = threading.Event()
        LOG.success("ctor")

    def stop(self):
        LOG.error("stop")
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


class NetworkHealthWatcher(StoppableThread):
    def __init__(self, network):
        super().__init__()
        self.network = network

    def run(
        self,
        get_primary_fn=get_primary,
        election_timeout_s=5,
        election_timeout_factor=1,
        poll_interval_s=0.1,
        client_node_timeout_s=3,
    ):
        election_start_time = None

        while not self.is_stopped():
            health_state = get_network_health(
                self.network, get_primary_fn, client_node_timeout_s
            )
            if health_state == HealthState.stable:
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


if __name__ == "__main__":

    class N:
        def __init__(self, node_id, primary_id, view):
            self.node_id = node_id
            self.primary = (primary_id, view)

        def update_primary(self, primary_id, view):
            self.primary = (primary_id, view)

    def test_get_primary(node, client_node_timeout_s=None):
        return node.primary

    class TestNetwork:
        def __init__(self, nodes):
            self.nodes = nodes

        def get_joined_nodes(self):
            return self.nodes

    def test_get_network_health(*args):
        return get_network_health(TestNetwork([*args]), test_get_primary)

    # Stable primary-ship
    assert (
        test_get_network_health(N(0, 0, 2), N(1, 0, 2), N(2, 0, 2))
        == HealthState.stable
    )
    # One node becomes candidate
    assert (
        test_get_network_health(N(0, 0, 2), N(1, None, 3), N(2, 0, 2))
        == HealthState.stable
    )
    # Majority of nodes are now candidates
    assert (
        test_get_network_health(N(0, 0, 2), N(1, None, 4), N(2, None, 3))
        == HealthState.election
    )
    # Election converges on candidates, old primary still isolated
    assert (
        test_get_network_health(N(0, 0, 2), N(1, 1, 4), N(2, 1, 4))
        == HealthState.stable
    )
