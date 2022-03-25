# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import threading
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

from loguru import logger as LOG


# Interval (s) at which the network is polled to find out
# when the load client should be restarted
NETWORK_POLL_INTERVAL_S = 1

# Number of requests sent to the service per sec
DEFAULT_LOAD_RATE_PER_S = 500

# Load client configuration
VEGETA_BIN = "/opt/vegeta/vegeta"
VEGETA_TARGET_FILE_NAME = "vegeta_targets"
TMP_RESULTS_CSV_FILE_NAME = "vegeta_results.tmp"
RESULTS_CSV_FILE_NAME = "vegeta_results.csv"
RESULTS_IMG_FILE_NAME = "vegeta_results.png"


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
    ):
        self.network = network
        self.rate = rate
        self.strategy = strategy
        self.target_node = target_node
        self.events = []

    def _create_targets(self, nodes, strategy):
        with open(
            in_common_dir(self.network, VEGETA_TARGET_FILE_NAME),
            "w",
            encoding="utf-8",
        ) as f:
            primary, backup = self.network.find_primary_and_any_backup()
            # Note: Iteration count does not matter as vegeta plays requests in a loop
            for i in range(10):
                if strategy == LoadStrategy.PRIMARY:
                    node = primary
                elif strategy == LoadStrategy.ALL:
                    node = nodes[i % len(nodes)]
                elif strategy == LoadStrategy.ANY_BACKUP:
                    node = backup
                else:
                    assert self.target_node, "A target node should have been specified"
                    node = self.target_node
                # TODO: Use more endpoints
                TargetGenerator.write_vegeta_target_line(
                    f,
                    f"{node.get_public_rpc_host()}:{node.get_public_rpc_port()}",
                    "/app/log/private",
                    body={"id": i, "msg": f"Private message: {i}"},
                )

    def _start_client(self, nodes):
        self._create_targets(nodes, self.strategy)
        attack_cmd = [VEGETA_BIN, "attack"]
        attack_cmd += [
            "--targets",
            in_common_dir(self.network, VEGETA_TARGET_FILE_NAME),
        ]
        attack_cmd += ["--format", "json"]
        attack_cmd += ["--rate", f"{self.rate}"]
        attack_cmd += ["--max-workers", "10"]  # TODO: Find sensible default, 10?
        sa = nodes[0].session_auth("user0")
        attack_cmd += ["--cert", sa["session_auth"].cert]
        attack_cmd += ["--key", sa["session_auth"].key]
        attack_cmd += ["--root-certs", nodes[0].session_ca(False)["ca"]]

        attack = subprocess.Popen(attack_cmd, stdout=subprocess.PIPE)
        tee_split = subprocess.Popen(
            ["tee", "vegeta_results.bin"],
            stdin=attack.stdout,
            stdout=subprocess.PIPE,
        )
        encode_cmd = [
            VEGETA_BIN,
            "encode",
            "--to",
            "csv",
            "--output",
            in_common_dir(self.network, TMP_RESULTS_CSV_FILE_NAME),
        ]
        self.proc = subprocess.Popen(encode_cmd, stdin=tee_split.stdout)
        self.events.append(("start", time.time()))
        LOG.debug("Load client started")

    def _aggregate_results(self):
        # Aggregate the results from the last run into all results so far
        with open(
            in_common_dir(self.network, TMP_RESULTS_CSV_FILE_NAME), "rb"
        ) as input, open(
            in_common_dir(self.network, RESULTS_CSV_FILE_NAME), "ab"
        ) as output:
            copyfileobj(input, output)

    def _stop_client(self):
        self._aggregate_results()
        self.proc.terminate()
        self.proc.wait()

    def start(self, nodes):
        self._start_client(nodes)

    def stop(self):
        self._stop_client()
        self._render_results()

    def restart(self, nodes, event="node change"):
        self._stop_client()
        self._start_client(nodes)

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
        # Smooth latency output
        df["latency"] = df.latency.rolling(self.rate // 10).mean()
        df["latency"] = df.latency.apply(lambda x: x / 1e6)

        LOG.error(df.index)

        fig, ax1 = plt.subplots()
        color = "tab:blue"
        ax1.set_xlabel("time")
        ax1.set_ylabel("latency (ms)", color=color)
        ax1.set_yscale("log")
        ax1.tick_params(axis="y", labelcolor=color)
        extra_ticks = []
        extra_ticks_labels = []
        for name, t in self.events:
            extra_ticks.append(t / 3600 / 24)
            extra_ticks_labels.append(name)

        ax1.plot(df.index, df["latency"], color=color, linewidth=1)

        # xt.append(xt, )

        LOG.warning(list(ax1.get_xticks()) + extra_ticks)
        LOG.success(list(ax1.get_xticklabels()) + extra_ticks_labels)
        # ax1.set_xticks(list(ax1.get_xticks()) + extra_ticks)
        # ax1.set_xticklabels(list(ax1.get_xticklabels()) + extra_ticks_labels)

        ax2 = ax1.twinx()
        color = "tab:red"
        ax2.set_ylabel("errors", color=color)
        ax2.tick_params(axis="y", labelcolor=color)
        ax2.scatter(df.index, df["error"], color=color, s=10)

        fig.savefig(
            in_common_dir(self.network, RESULTS_IMG_FILE_NAME),
            bbox_inches="tight",
            dpi=1000,
        )
        LOG.debug(f"Load results rendered to {RESULTS_IMG_FILE_NAME}")


class StoppableThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


class ServiceLoad(StoppableThread):
    def __init__(self, network, *args, **kwargs):
        super().__init__(name="load")
        self.network = network
        self.client = LoadClient(self.network, *args, **kwargs)

    def start(self):
        self.client.start(nodes=self.network.get_joined_nodes())
        super().start()
        LOG.info("Load client started")

    def stop(self):
        self.client.stop()
        super().stop()
        LOG.info(f"Load client stopped")

    def run(self):
        primary, backups = self.network.find_nodes(timeout=10)
        known_nodes = [primary] + backups
        # TODO: Record event on graph
        while not self.is_stopped():
            new_primary, new_backups = self.network.find_nodes(timeout=10)
            new_nodes = [new_primary] + new_backups
            if new_nodes != known_nodes:
                LOG.warning("Network configuration has changed, restarting load client")
                self.client.restart(new_nodes)
            known_nodes = new_nodes
            time.sleep(NETWORK_POLL_INTERVAL_S)
        return
