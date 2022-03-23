# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from enum import Enum, auto
from collections import Counter
import time
import threading

from loguru import logger as LOG

# How often each node in the network is polled
DEFAULT_POLLING_INTERVAL_S = 1

# Maximum duration after which unestablished connections consider
# the node as unreachable
DEFAULT_CLIENT_NODE_TIMEOUT_S = 3

# Maximum number of unsuccessful elections after which the
# network is considered as _not_ self-healable and thus should
# be recovered by operators (i.e. disaster recovery procedure).
# Unreliable networks should set this to a higher value.
DEFAULT_ELECTION_FACTOR = 1


class HealthState(Enum):
    stable = auto()  # Network can commit new transactions
    unavailable = auto()  # The primary or majority of nodes are unreachable
    election = auto()  # An election is in progress


def get_primary(
    node, client_node_timeout_s=DEFAULT_CLIENT_NODE_TIMEOUT_S, verbose=True
):
    """
    Returns the primary reported by a given node, and in which view or
    None if the given node is unreachable.
    """
    try:
        with node.client() as c:
            logs = None if verbose else []
            r = c.get(
                "/node/consensus", timeout=client_node_timeout_s, log_capture=logs
            ).body.json()
            return (r["details"]["primary_id"], r["details"]["current_view"])
    except Exception as e:
        LOG.warning(f"Could not connect to node {node.local_node_id}: {e}")
        return None


def get_network_health(network, get_primary_fn, client_node_timeout_s=3, verbose=True):
    """Returns the current state of a network"""
    nodes = network.nodes

    # Number of nodes required for network to commit new transactions
    majority = (len(nodes) + 1) // 2

    primaries = {}
    for node in nodes:
        primaries[node.node_id] = get_primary_fn(
            node, client_node_timeout_s, verbose=verbose
        )
    assert len(primaries) == len(nodes)

    # Count how many (primary nodes, views) are reported by all nodes in
    # the network. If a majority of nodes report the same primary node in
    # the same term, the service is stable.
    primaries_count = Counter(primaries.values())

    if not primaries_count:
        return HealthState.unavailable

    most_common_primary, most_common_count = primaries_count.most_common()[0]

    if most_common_primary is None:
        # A majority of nodes are unreachable
        return HealthState.unavailable

    if most_common_primary[0] not in primaries:
        # The current primary is unreachable
        return HealthState.unavailable

    if primaries[most_common_primary[0]] != most_common_primary:
        # A majority of nodes still report a primary but this primary is
        # about to lose its primaryship
        return HealthState.election

    return HealthState.stable if most_common_count >= majority else HealthState.election


class StoppableThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


class NetworkHealthWatcher(StoppableThread):
    def __init__(
        self,
        network,
        args,
        election_timeout_factor=DEFAULT_ELECTION_FACTOR,
        poll_interval_s=DEFAULT_POLLING_INTERVAL_S,
        client_node_timeout_s=DEFAULT_CLIENT_NODE_TIMEOUT_S,
        verbose=False,
    ):
        super().__init__(name="health")
        self.network = network
        self.poll_interval_s = poll_interval_s
        self.client_node_timeout_s = client_node_timeout_s
        self.unstable_threshold_s = (
            election_timeout_factor * args.election_timeout_ms / 1000
        )
        self.verbose = verbose

    def wait_for_recovery(self, timeout=None):
        timeout = timeout or self.unstable_threshold_s
        self.join(timeout=timeout)
        if self.is_alive():
            self.stop()
            raise TimeoutError(
                f"Health watcher did not detect recovery after {timeout}s"
            )

    def run(self):
        """
        Monitor the health of the network. If the network is not stable for more than
        a specific period (election_timeout * election_timeout_factor), the health
        watcher automatically stops and a disaster recovery procedure should be staged.
        """
        election_start_time = None

        # Note: this currently does not detect one-way partitions backups -> primary
        # See https://github.com/microsoft/CCF/issues/3688 for fix.

        while not self.is_stopped():
            if self.verbose:
                LOG.info("Polling network health...")
            health_state = get_network_health(
                self.network,
                get_primary,
                self.client_node_timeout_s,
                verbose=self.verbose,
            )
            if health_state == HealthState.stable:
                election_start_time = None
            else:
                LOG.info("Network is unstable")
                if election_start_time is None:
                    election_start_time = time.time()
                if time.time() - election_start_time > self.unstable_threshold_s:
                    LOG.error(
                        f"Network has been unstable for more than {self.unstable_threshold_s}s. Exiting"
                    )
                    return

            time.sleep(self.poll_interval_s)
