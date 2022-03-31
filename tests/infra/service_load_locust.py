# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from nntplib import NNTPDataError
from pstats import Stats
import time
import os
import subprocess
import generate_vegeta_targets as TargetGenerator
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
from shutil import copyfileobj
from enum import Enum, auto
import datetime
import infra.concurrency
import gevent
from locust.env import Environment
from locust import FastHttpUser, task, events, between
import locust.stats

# from locust.stats import StatsCSVFileWriter


from loguru import logger as LOG


# Interval (s) at which the network is polled to find out
# when the load client should be restarted
NETWORK_POLL_INTERVAL_S = 1

# Number of requests sent to the service per sec
DEFAULT_LOAD_RATE_PER_S = 10  # TODO: Change back

# Scope for logging txs so that they do not conflict
# with the txs recorded by the actual tests
LOGGING_TXS_SCOPE = "load"

# Load client configuration
VEGETA_BIN = "/opt/vegeta/vegeta"
TARGET_FILE_NAME = "load_targets"
TMP_RESULTS_CSV_FILE_NAME = "load_results.tmp"
RESULTS_CSV_FILE_NAME = "load_results.csv"
RESULTS_IMG_FILE_NAME = "load_results.png"

locust.stats.CSV_STATS_INTERVAL_SEC = 0.1
locust.stats.CSV_STATS_FLUSH_INTERVAL_SEC = 1


@events.init.add_listener
def on_test_start(environment, **kwargs):
    # if environment.host is None:
    #     raise RuntimeError("-H must be specified")
    LOG.warning(environment.host)


class Submitter(FastHttpUser):
    # def __init__(self, environment, network, *args, **kwargs):
    #     super().__init__(*args, environment, **kwargs)
    #     self.network = network
    #     self.primary, _ = self.network.find_primary()
    #     self.host = self.primary
    # wait_time = between(1, 3)

    @task
    def submit(self):
        LOG.success(self.host)
        r = self.client.get("/node/memory")
        LOG.success(r.json())


# class Submitter(FastHttpUser):
#     fixed_count = 10

#     @task
#     def submit(self):
#         # assert self.host
#         LOG.success(self.host)

#         # for _ in retrieve_signed_claimsets(
#         #     from_seqno=None,
#         #     to_seqno=None,
#         #     ccf_url=self.host,
#         #     development=True,
#         #     session=self.client,
#         #     is_locust_session=True,
#         # ):
#         #     pass


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

    # def _create_targets(self, nodes, strategy):
    #     with open(
    #         in_common_dir(self.network, TARGET_FILE_NAME),
    #         "w",
    #         encoding="utf-8",
    #     ) as f:
    #         primary, backup = self.network.find_primary_and_any_backup()
    #         self.title = primary.label
    #         # Note: Iteration count does not matter as vegeta plays requests in a loop
    #         for i in range(10):
    #             if strategy == LoadStrategy.PRIMARY:
    #                 node = primary
    #             elif strategy == LoadStrategy.ALL:
    #                 node = nodes[i % len(nodes)]
    #             elif strategy == LoadStrategy.ANY_BACKUP:
    #                 node = backup
    #             else:
    #                 assert self.target_node, "A target node should have been specified"
    #                 node = self.target_node
    #             TargetGenerator.write_vegeta_target_line(
    #                 f,
    #                 f"{node.get_public_rpc_host()}:{node.get_public_rpc_port()}",
    #                 f"/app/log/private?scope={LOGGING_TXS_SCOPE}",
    #                 body={"id": i, "msg": f"Private message: {i}"},
    #             )

    def _start_client(self, nodes, event):
        target_node = nodes[0]
        target_host = f"https://{target_node.get_public_rpc_host()}:{target_node.get_public_rpc_port()}"
        LOG.success(f"target: {target_host}")

        self.env = Environment(user_classes=[Submitter], host=target_host)
        self.env.create_local_runner()
        PERCENTILES_TO_REPORT = [0.50, 0.90, 0.99, 1.0]
        stats_writer = locust.stats.StatsCSVFileWriter(
            self.env,
            PERCENTILES_TO_REPORT,
            os.path.join(self.network.common_dir, "load"),
            full_history=True,
        )
        self.stats = gevent.spawn(stats_writer)
        self.env.runner.start(user_count=1, spawn_rate=20)

    def _aggregate_results(self):
        # Aggregate the results from the last run into all results so far.
        # Note: for a single test run, multiple instances of the LoadClient
        # can be started one after the other and since the results csv file
        # is the same for all instances (within the same test/common dir),
        # the latest instance of the LoadClient will render all results.
        tmp_file = in_common_dir(self.network, TMP_RESULTS_CSV_FILE_NAME)
        if tmp_file:
            with open(tmp_file, "rb") as input, open(
                in_common_dir(self.network, RESULTS_CSV_FILE_NAME), "ab"
            ) as output:
                copyfileobj(input, output)

    def _stop_client(self):
        # self._aggregate_results()
        LOG.error("Stopping runner")
        gevent.kill(self.stats)
        # LOG.warning(self.env.stats.history)
        self.env.runner.stop()
        # if self.proc:
        #     self.proc.terminate()
        #     self.proc.wait()

    def start(self, nodes):
        self._start_client(nodes, event="start")

    def stop(self):
        self._stop_client()
        # self._render_results()

    def restart(self, nodes, event="node change"):
        self._stop_client()
        self._start_client(nodes, event)

    def _render_results(self):
        df = pd.read_csv(
            os.path.join(self.network.common_dir, RESULTS_CSV_FILE_NAME),
            header=None,
            keep_default_na=False,
            names=[
                "timestamp",
                "code",
                "latency",
                "bytesout",
                "bytesin",
                "error",
                "response_body",
                "attack_name",
                "seqno",
                "method",
                "url",
                "response_headers",
            ],
        ).set_index("timestamp")
        df.index = pd.to_datetime(df.index, unit="ns")
        df["latency"] = df.latency.apply(lambda x: x / 1e6)
        # Truncate error message for more compact rendering
        def truncate_error_msg(msg, max_=25):
            if msg is None:
                return None
            else:
                return msg[-max_:] if len(msg) > max_ else msg

        df["error"] = df.error.apply(truncate_error_msg)

        fig, ax1 = plt.subplots()
        plt.title(f"Load for {self.title}")

        # Latency
        color = "tab:blue"
        ax1.set_xlabel("time")
        ax1.set_ylabel("latency (ms)", color=color)
        ax1.set_yscale("log")
        ax1.tick_params(axis="y", labelcolor=color)
        ax1.tick_params(axis="x", rotation=90)
        ax1.scatter(df.index, df["latency"], color=color)

        # Error code
        ax2 = ax1.twinx()
        color = "tab:green"
        ax2.set_ylabel("http code", color=color)
        ax2.tick_params(axis="y", labelcolor=color)
        ax2.scatter(df.index, df["code"], color=color, s=10)

        # Errors
        ax3 = ax1.twinx()
        color = "tab:red"
        ax3.set_ylabel("errors", color=color)
        ax3.tick_params(axis="y", labelcolor=color)
        ax3.scatter(df.index, df["error"], marker=".", color=color, s=10)

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
        self.client.start(nodes=self.network.get_joined_nodes())
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
                    self.client.restart(new_nodes, event=event)
                known_nodes = new_nodes
            except Exception as e:
                LOG.warning(f"Error finding nodes: {e}")
            time.sleep(NETWORK_POLL_INTERVAL_S)
        return
