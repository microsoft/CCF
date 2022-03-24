# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import threading
import time
import os
import subprocess
import generate_vegeta_targets as TargetGenerator
import json

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

import pandas as pd

from loguru import logger as LOG

# Note: while vegeta is great, it does not allow for updating the targets
# after the "attack" has been started. Instead, ServiceLoad polls the network
# at regular intervals and restart the attack if the network configuration has changed.

# Interval (s) at which the network is polled to find out
# when the load client should be restarted
NETWORK_POLL_INTERVAL_S = 1

# Number of requests sent to the service per sec
DEFAULT_LOAD_RATE_PER_S = 50

# Load client configuration
VEGETA_BIN = "/opt/vegeta/vegeta"
VEGETA_TARGET_FILE_NAME = "vegeta_targets"
RESULTS_CSV_FILE_NAME = "vegeta_results.csv"
RESULTS_IMG_FILE_NAME = "vegeta_results.png"


class LoadClient:
    def __init__(self, network, rate=DEFAULT_LOAD_RATE_PER_S):
        self.network = network
        self.rate = rate

    def _start_client(self, nodes):
        with open(
            os.path.join(self.network.common_dir, VEGETA_TARGET_FILE_NAME),
            "w",
            encoding="utf-8",
        ) as f:
            for i in range(10):
                # node = nodes[i % len(nodes)]
                node = nodes[0]
                TargetGenerator.write_vegeta_target_line(
                    f,
                    f"{node.get_public_rpc_host()}:{node.get_public_rpc_port()}",
                    "/app/log/private",
                    body={"id": i, "msg": f"Private message: {i}"},
                )

        attack_cmd = [VEGETA_BIN, "attack"]
        attack_cmd += [
            "--targets",
            os.path.join(self.network.common_dir, VEGETA_TARGET_FILE_NAME),
        ]
        attack_cmd += ["--format", "json"]
        attack_cmd += ["--rate", f"{self.rate}"]
        sa = nodes[0].session_auth("user0")
        attack_cmd += ["--cert", sa["session_auth"].cert]
        attack_cmd += ["--key", sa["session_auth"].key]
        attack_cmd += ["--root-certs", nodes[0].session_ca(False)["ca"]]

        attack_cmd_s = " ".join(attack_cmd)
        LOG.debug(f"Starting: {attack_cmd_s}")
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
            os.path.join(self.network.common_dir, RESULTS_CSV_FILE_NAME),
        ]
        self.proc = subprocess.Popen(encode_cmd, stdin=tee_split.stdout)
        LOG.success("running")

    def _stop_client(self, timeout=15):
        self.proc.terminate()
        self.proc.wait()
        LOG.success("Process killed")

        self._render_results()

    def start(self, nodes):
        self._start_client(nodes)

    def stop(self):
        self._stop_client()

    def restart(self, nodes):
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
        df["latency"] = df.latency.apply(lambda x: x / 1e6)

        fig, ax1 = plt.subplots()
        color = "tab:blue"
        ax1.set_xlabel("time")
        ax1.set_ylabel("latency (ms)", color=color)
        ax1.tick_params(axis="y", labelcolor=color)
        ax1.plot(df.index, df["latency"], color=color)

        ax2 = ax1.twinx()
        color = "tab:red"
        ax2.set_ylabel("errors", color=color)
        ax2.tick_params(axis="y", labelcolor=color)
        ax2.plot(df.index, df["error"], color=color)

        fig.savefig(os.path.join(self.network.common_dir, RESULTS_IMG_FILE_NAME))
        LOG.info(f"Load results rendered to {RESULTS_IMG_FILE_NAME}")


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
    def __init__(self, network, rate=DEFAULT_LOAD_RATE_PER_S):
        super().__init__(name="load")
        self.network = network
        self.client = LoadClient(self.network, rate)

    def start(self):
        self.client.start(nodes=self.network.get_joined_nodes())
        super().start()
        LOG.info("Load client started")

    def stop(self):
        self.client.stop()
        super().stop()
        LOG.info(f"Load client stopped")

    def run(self):
        known_nodes = self.network.get_joined_nodes()
        while not self.is_stopped():
            LOG.info("Polling network...")  # TODO: Delete
            nodes = self.network.get_joined_nodes()
            if nodes != known_nodes:
                LOG.warning("Network configuration has changed, restarting load client")
                self.client.restart(nodes)
            known_nodes = nodes
            time.sleep(NETWORK_POLL_INTERVAL_S)
        return
