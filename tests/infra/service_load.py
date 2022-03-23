# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import threading
import time
import os
import subprocess
import generate_vegeta_targets as TargetGenerator

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

import pandas as pd

from loguru import logger as LOG

VEGETA_BIN = "/opt/vegeta/vegeta"
VEGETA_TARGET_FILE_NAME = "vegeta_targets"
RESULTS_CSV_FILE_NAME = "vegeta_results.csv"
RESULTS_IMG_FILE_NAME = "vegeta_results.png"


class LoadClient:
    def __init__(self, network):
        self.network = network

    def start(self):
        primary, _ = self.network.find_primary()

        nodes = self.network.get_joined_nodes()

        with open(
            os.path.join(self.network.common_dir, VEGETA_TARGET_FILE_NAME),
            "w",
            encoding="utf-8",
        ) as f:
            for i in range(10):
                # node = nodes[i % len(nodes)]
                node = primary
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
        attack_cmd += ["--duration", "10s"]
        attack_cmd += ["--rate", "50"]
        sa = primary.session_auth("user0")
        attack_cmd += ["--cert", sa["session_auth"].cert]
        attack_cmd += ["--key", sa["session_auth"].key]
        attack_cmd += ["--root-certs", primary.session_ca(False)["ca"]]

        attack_cmd_s = " ".join(attack_cmd)
        LOG.info(f"Starting: {attack_cmd_s}")
        self.proc = subprocess.Popen(
            attack_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        tee_split = subprocess.Popen(
            ["tee", "vegeta_results.bin"],
            stdin=self.proc.stdout,
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
        self.report = subprocess.Popen(encode_cmd, stdin=tee_split.stdout)
        LOG.start("running")

    def wait_for_completion(self, timeout=15):
        try:
            self.report.communicate()
        except TimeoutError:
            self.report.kill()

        self._render_results()

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


class StoppableThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    # TODO:
    # 1. Basic setup (DONE)
    # 2. Print vegeta results (DONE)
    # 3. Distribute load on multiple nodes
    # 4. Cope with node removal + addition


class ServiceLoad(StoppableThread):
    def __init__(self, network, *args, **kwargs):
        super().__init__(name="load", *args, **kwargs)
        self.network = network
        self.client = LoadClient(self.network)

    def start(self):
        LOG.error("start")
        self.client.start()
        super().start()

    def run(self):
        LOG.warning("Waiting for process to end")
        self.client.wait_for_completion()
        return
