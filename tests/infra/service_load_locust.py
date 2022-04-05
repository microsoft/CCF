# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import time
import os
import subprocess
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
from shutil import copyfileobj
from enum import Enum, auto
import infra.concurrency


from loguru import logger as LOG


# Interval (s) at which the network is polled to find out
# when the load client should be restarted
NETWORK_POLL_INTERVAL_S = 1

# Number of requests sent to the service per sec
DEFAULT_LOAD_RATE_PER_S = 10  # TODO: Change back

# Scope for logging txs so that they do not conflict
# with the txs recorded by the actual tests
LOGGING_TXS_SCOPE = "load"

LOCUST_STATS_HISTORY_SUFFIX = "stats_history.csv"

# Number of clients launched by locust
LOAD_USERS_COUNT = 10


RESULTS_CSV_FILE_NAME = "load_results.csv"
RESULTS_IMG_FILE_NAME = "load_results.png"
LOCUST_FILE_NAME = "locust_file.py"


def in_common_dir(network, file):
    return os.path.join(network.common_dir, file)


class LoadStrategy(Enum):
    PRIMARY = auto()
    ALL = auto()
    ANY_BACKUP = auto()
    SINGLE = auto()


class LoadClient:
    def __init__(
        self,
        network,
        strategy=LoadStrategy.PRIMARY,
        rate=DEFAULT_LOAD_RATE_PER_S,
        target_node=None,
        existing_events=None,
    ):
        self.network = network
        self.rate = rate
        self.strategy = strategy
        self.target_node = target_node
        self.events = existing_events or []
        self.proc = None
        self.title = None
        self.env = None
        self.stats = None

    def _start_client(self, primary, backups, event):
        target_node = primary
        target_host = f"https://{target_node.get_public_rpc_host()}:{target_node.get_public_rpc_port()}"

        self.title = target_node.label

        this_dir = os.path.dirname(os.path.realpath(__file__))
        locust_file_path = os.path.join(this_dir, LOCUST_FILE_NAME)
        cmd = ["locust"]
        cmd += ["--headless"]
        cmd += ["--loglevel", "CRITICAL"]
        cmd += ["--locustfile", locust_file_path]
        cmd += ["--csv-full-history"]  # Record history
        cmd += ["--csv", in_common_dir(self.network, f"tmp_{LOGGING_TXS_SCOPE}")]

        # Client authentication
        sa = primary.session_auth("user0")["session_auth"]
        cmd += ["--ca", primary.session_ca()["ca"]]
        cmd += ["--key", sa.key]
        cmd += ["--cert", sa.cert]

        # Users
        cmd += ["--users", f"{LOAD_USERS_COUNT}"]
        cmd += [
            "--spawn-rate",
            f"{LOAD_USERS_COUNT}",
        ]  # All users are spawned within 1s

        # Targets
        cmd += ["--node-host", target_host]  # TODO: Construct hosts based on strategy
        cmd += ["--host", "https://0.0.0.0"]  # Dummy host required to start locust

        LOG.info(f'Starting locust: {" ".join(cmd)}')
        self.proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)

        self.events.append((event, time.time()))

    def _aggregate_results(self):
        # Aggregate the results from the last run into all results so far.
        # Note: for a single test run, multiple instances of the LoadClient
        # can be started one after the other and since the results csv file
        # is the same for all instances (within the same test/common dir),
        # the latest instance of the LoadClient will render all results.
        tmp_file = in_common_dir(
            self.network, f"tmp_{LOGGING_TXS_SCOPE}_{LOCUST_STATS_HISTORY_SUFFIX}"
        )
        if os.path.exists(tmp_file):
            with open(tmp_file, "rb") as input, open(
                in_common_dir(self.network, RESULTS_CSV_FILE_NAME), "ab"
            ) as output:
                copyfileobj(input, output)

    def _stop_client(self):
        LOG.error("Stopping runner")
        if self.proc:
            self.proc.terminate()
            self.proc.wait()

        self._aggregate_results()

    def start(self, primary, backups):
        self._start_client(primary, backups, event="start")

    def stop(self):
        self._stop_client()
        self._render_results()

    def restart(self, primary, backups, event="node change"):
        self._stop_client()
        self._start_client(primary, backups, event)

    def _render_results(self):
        df = pd.read_csv(
            os.path.join(self.network.common_dir, RESULTS_CSV_FILE_NAME),
            keep_default_na=False,
        ).set_index("Timestamp")
        df.index = pd.to_datetime(df.index, unit="s")

        fig, ax1 = plt.subplots()
        plt.title(f"Load for {self.title}")

        # Throughput
        color = "tab:blue"
        ax1.set_xlabel("time")
        ax1.set_ylabel("req/s", color=color)
        ax1.tick_params(axis="y", labelcolor=color)
        ax1.tick_params(axis="x", rotation=90)
        ax1.scatter(df.index, df["Requests/s"], color=color)

        # Failures
        ax2 = ax1.twinx()
        ax2.set_ylim(bottom=0.0)
        color = "tab:red"
        ax2.set_ylabel("failures/s", color=color)
        ax2.tick_params(axis="y", labelcolor=color)
        ax2.scatter(df.index, df["Failures/s"], color=color, s=10)

        # Network events
        extra_ticks = []
        extra_ticks_labels = []
        for name, t in self.events:
            extra_ticks.append(t / 3600 / 24)
            extra_ticks_labels.append(name)

        secx = ax1.secondary_xaxis("top")
        secx.set_xticks(extra_ticks)
        secx.set_xticklabels(extra_ticks_labels)
        secx.tick_params(rotation=45)

        fig.savefig(
            in_common_dir(self.network, RESULTS_IMG_FILE_NAME),
            bbox_inches="tight",
            dpi=500,
        )
        plt.close(fig)
        LOG.debug(f"Load results rendered to {RESULTS_IMG_FILE_NAME}")


class ServiceLoad(infra.concurrency.StoppableThread):
    def __init__(self, network, verbose=False, *args, **kwargs):
        super().__init__(name="load")
        self.network = network
        self.verbose = verbose
        self.client = LoadClient(self.network, *args, **kwargs)

    def start(self):
        self.client.start(*self.network.find_nodes())
        super().start()
        LOG.info("Load client started")

    def stop(self):
        self.client.stop()
        super().stop()
        LOG.info(f"Load client stopped")

    def get_existing_events(self):
        return self.client.events

    def run(self):
        log_capture = None if self.verbose else []
        primary, backups = self.network.find_nodes(timeout=10, log_capture=log_capture)
        known_nodes = [primary] + backups
        while not self.is_stopped():
            try:
                new_primary, new_backups = self.network.find_nodes(
                    timeout=10, log_capture=log_capture
                )
                new_nodes = [new_primary] + new_backups
                if new_nodes != known_nodes:
                    LOG.warning(
                        "Network configuration has changed, restarting service load client"
                    )
                    event = "unknown"
                    if primary not in new_nodes:
                        event = f"stop p{primary.local_node_id}"
                    elif new_primary != primary:
                        event = f"elect p{primary.local_node_id} -> p{new_primary.local_node_id}"
                    else:
                        added = list(set(new_nodes) - set(known_nodes))
                        removed = list(set(known_nodes) - set(new_nodes))
                        event = ""
                        if added:
                            event += f"add n{[n.local_node_id for n in added]}"
                        if removed:
                            event += f"- rm n{[n.local_node_id for n in removed]}"
                    primary = new_primary
                    backups = new_backups
                    self.client.restart(new_primary, new_backups, event=event)
                known_nodes = new_nodes
            except Exception as e:
                LOG.warning(f"Error finding nodes: {e}")
            time.sleep(NETWORK_POLL_INTERVAL_S)
        return
