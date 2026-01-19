# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import time
import os
import subprocess
import matplotlib.pyplot as plt
import pandas as pd
from shutil import copyfileobj
from enum import Enum, auto
import infra.concurrency
import random
from contextlib import contextmanager


from loguru import logger as LOG

# Interval (s) at which the network is polled to find out
# when the load client should be restarted
NETWORK_POLL_INTERVAL_S = 1


# Scope for logging txs so that they do not conflict
# with the txs recorded by the actual tests
LOGGING_TXS_SCOPE = "load"

LOCUST_STATS_HISTORY_SUFFIX = "stats_history.csv"

# Number of clients launched by locust
LOAD_USERS_COUNT = 10

# Default request rate issued to service
# Currently limited to ~1000 req/s (see https://github.com/locustio/locust/issues/2066)
DEFAULT_REQUEST_RATE_S = 100

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


def make_target_host(target_node):
    return f"https://{target_node.get_public_rpc_host()}:{target_node.get_public_rpc_port()}"


class LoadClient:
    def __init__(
        self,
        network,
        strategy=LoadStrategy.PRIMARY,
        target_node=None,
        existing_events=None,
        rate=DEFAULT_REQUEST_RATE_S,
    ):
        self.network = network
        self.strategy = strategy
        self.target_node = target_node
        self.events = existing_events or []
        self.proc = None
        self.title = None
        self.env = None
        self.stats = None
        self.rate = rate

    def _start_client(self, primary, backups, event):
        self.title = primary.label
        this_dir = os.path.dirname(os.path.realpath(__file__))
        locust_file_path = os.path.join(this_dir, LOCUST_FILE_NAME)

        cmd = ["locust"]
        cmd += ["--headless"]
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
        cmd += ["--rate", f"{self.rate}"]

        # Targets
        if self.strategy == LoadStrategy.PRIMARY:
            cmd += ["--node-host", make_target_host(primary)]
        elif self.strategy == LoadStrategy.ALL:
            for node in [primary] + backups:
                cmd += ["--node-host", make_target_host(node)]
        elif self.strategy == LoadStrategy.ANY_BACKUP:
            cmd += ["--node-host", make_target_host(random.choice(backups))]
        elif self.strategy == LoadStrategy.SINGLE:
            cmd += ["--node-host", make_target_host(self.target_node)]

        cmd += ["--host", "https://0.0.0.0"]  # Dummy host required to start locust

        LOG.debug(f'Starting locust: {" ".join(cmd)}')
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
        aggregated_file = in_common_dir(self.network, RESULTS_CSV_FILE_NAME)
        is_new = not os.path.exists(aggregated_file)
        if os.path.exists(tmp_file):
            with open(tmp_file, "rb") as in_, open(aggregated_file, "ab") as out_:
                if not is_new:
                    in_.readline()
                copyfileobj(in_, out_)

    def _stop_client(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
        self._aggregate_results()

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
        request_column_name = "Requests/s"
        ax1.set_xlabel("time")
        ax1.set_ylabel(request_column_name, color=color)
        request_column_max = df[request_column_name].max()
        ax1.tick_params(axis="y", labelcolor=color)
        ax1.tick_params(axis="x", rotation=90)
        if request_column_max > 0:
            ax1.set_ylim(0, request_column_max)
        ax1.scatter(df.index, df[request_column_name], marker=".", color=color)

        # Failures
        ax2 = ax1.twinx()
        color = "tab:red"
        failure_column_name = "Failures/s"
        ax2.set_ylabel(failure_column_name, color=color)
        ax2.tick_params(axis="y", labelcolor=color)
        if request_column_max > 0:
            ax2.set_ylim(0, request_column_max)
        ax2.scatter(df.index, df[failure_column_name], marker=".", color=color)

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
        LOG.debug(
            f"Load results rendered to {in_common_dir(self.network,RESULTS_IMG_FILE_NAME)}"
        )

    def start(self, primary, backups):
        self._start_client(primary, backups, event="run")

    def stop(self):
        self._stop_client()
        self._render_results()

    def restart(self, primary, backups, event="run"):
        self._stop_client()
        self._start_client(primary, backups, event)


class ServiceLoad(infra.concurrency.StoppableThread):
    def __init__(self, verbose=False):
        super().__init__(name="load")
        self.network = None
        self.client = None
        self.verbose = verbose

    def begin(self, network, *args, **kwargs):
        self.network = network
        self.client = LoadClient(self.network, *args, **kwargs)
        self.client.start(*self.network.find_nodes())
        super().start()
        LOG.info("Service load started")

    def set_network(self, network):
        self.network = network

    def end(self):
        super().stop()
        if self.client:
            self.client.stop()
        LOG.info("Service load stopped")

    def run(self):
        log_capture = None if self.verbose else []
        primary, backups = self.network.find_nodes(timeout=10, log_capture=log_capture)
        known_nodes = [primary] + backups
        known_network = self.network
        while not self.is_stopped():
            try:
                new_primary, new_backups = self.network.find_nodes(
                    timeout=10, log_capture=log_capture
                )
                new_nodes = [new_primary] + new_backups
                if new_nodes != known_nodes or self.network != known_network:
                    LOG.warning(
                        "Network configuration has changed, restarting service load client"
                    )
                    event = ""
                    if self.network != known_network:
                        event = "recovery"
                    elif primary not in new_nodes:
                        event = f"stop p[{primary.local_node_id}]"
                    elif new_primary != primary:
                        event = f"elect p[{primary.local_node_id}] -> p[{new_primary.local_node_id}]"
                    else:
                        added = set(new_nodes) - set(known_nodes)
                        removed = set(known_nodes) - set(new_nodes)
                        event = ""
                        if added:
                            event += f"add n{[n.local_node_id for n in added]}"
                        if removed:
                            if event:
                                event += "- "
                            event += f"stop n{[n.local_node_id for n in removed]}"
                    primary = new_primary
                    backups = new_backups
                    self.client.restart(new_primary, new_backups, event=event)
                known_nodes = new_nodes
            except Exception as e:
                LOG.warning(f"Error finding nodes: {e}")
            time.sleep(NETWORK_POLL_INTERVAL_S)
        return


@contextmanager
def load(*args, **kwargs):
    s = ServiceLoad(*args, **kwargs)
    yield s
    s.end()
