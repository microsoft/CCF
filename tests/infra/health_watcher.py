from enum import Enum, auto
from collections import Counter
import time
import threading
import infra.network

from loguru import logger as LOG


class HealthState(Enum):
    stable = auto()
    unavailable = auto()
    partitioned = auto()
    election = auto()
    recovery = auto()


def get_primary(node, client_node_timeout_s=3, verbose=True):
    """Returns the primary reported by a given node"""
    with node.client() as c:
        try:
            logs = None if verbose else []
            r = c.get(
                "/node/network", timeout=client_node_timeout_s, log_capture=logs
            ).body.json()
            return (r["primary_id"], r["current_view"])
        except Exception as e:
            LOG.warning(f"Could not connect to node {node.local_node_id}: {e}")
            return None


def get_network_health(network, get_primary_fn, client_node_timeout_s=3, verbose=True):
    """Returns the current state of a network"""
    primaries = {}
    nodes = network.get_joined_nodes()
    quorum = (len(nodes) + 1) // 2
    LOG.success(f"Quorum is {quorum}")
    for node in nodes:
        primaries[node.node_id] = get_primary_fn(
            node, client_node_timeout_s, verbose=verbose
        )
    assert len(primaries) == len(nodes)

    # Count how many primary nodes are reported. If a majority of nodes report
    # the same primary node in the same term, the service is stable.
    primaries_count = Counter(primaries.values())
    most_common_primary, most_common_count = primaries_count.most_common()[0]

    if most_common_primary is None:
        # A majority of nodes are unreachable
        return HealthState.unavailable

    if primaries[most_common_primary[0]] != most_common_primary:
        # A majority of nodes still report a primary but this primary is
        # about to lose its primaryship
        return HealthState.election

    return (
        HealthState.stable if most_common_count < quorum else HealthState.election
    )  # TODO: Wrong on purpose


class StoppableThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


class NetworkHealthWatcher(StoppableThread):
    def __init__(self, network, args, verbose=False):
        super().__init__(name="health")
        LOG.error(network)
        self.network = network
        self.args = args
        self.verbose = verbose

    def run(
        self,
        get_primary_fn=get_primary,
        election_timeout_s=5,
        election_timeout_factor=1,
        poll_interval_s=1,
        client_node_timeout_s=3,
    ):
        """
        Monitor the health of the network. If the network is not stable for more than
        a specific period (election_timeout_s * election_timeout_factor), a recovery event
        is automatically triggered.
        """
        election_start_time = None

        while not self.is_stopped():
            health_state = get_network_health(
                self.network,
                get_primary_fn,
                client_node_timeout_s,
                verbose=self.verbose,
            )
            if health_state == HealthState.stable:
                election_start_time = None
                LOG.success(f"Healthy network")
            else:
                LOG.warning(f"Election network")
                if election_start_time is None:
                    election_start_time = time.time()
                if (
                    time.time() - election_start_time
                    > election_timeout_factor * election_timeout_s
                ):
                    LOG.error(
                        f"Network has been in unstable state for more than {election_timeout_factor * election_timeout_s}s"
                    )

                    old_primary, _ = self.network.find_primary()
                    self.network.stop_all_nodes()
                    self.network.save_service_identity(self.args)
                    current_ledger_dir, committed_ledger_dirs = old_primary.get_ledger()
                    self.network = infra.network.Network(
                        self.args.nodes,
                        self.args.binary_dir,
                        self.args.debug_nodes,
                        self.args.perf_nodes,
                        existing_network=self.network,
                    )
                    LOG.error(self.network)
                    LOG.warning(id(self.network))
                    # self.network.start_in_recovery(
                    #     self.args,
                    #     ledger_dir=current_ledger_dir,
                    #     committed_ledger_dirs=committed_ledger_dirs,
                    #     # snapshots_dir=snapshots_dir,
                    # )

                    return

            time.sleep(poll_interval_s)


if __name__ == "__main__":
    # Run this for unit tests
    class N:
        def __init__(self, node_id, primary_id, view):
            self.node_id = node_id
            self.primary = (primary_id, view)

        def update_primary(self, primary_id, view):
            self.primary = (primary_id, view)

    def test_get_primary(node, *args, **kwargs):
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
    # Majority of nodes are now candidates, in different terms
    assert (
        test_get_network_health(N(0, 0, 2), N(1, None, 4), N(2, None, 3))
        == HealthState.election
    )
    # Election converges on candidates, old primary still isolated
    assert (
        test_get_network_health(N(0, 0, 2), N(1, 1, 4), N(2, 1, 4))
        == HealthState.stable
    )
    # Old primary becomes follower
    assert (
        test_get_network_health(N(0, 1, 4), N(1, 1, 4), N(2, 1, 4))
        == HealthState.stable
    )
