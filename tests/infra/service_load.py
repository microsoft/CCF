# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import threading
import time
import subprocess
import generate_vegeta_targets as TargetGenerator

import matplotlib.pyplot as plt
import matplotlib.cbook as cbook

import pandas as pd

from loguru import logger as LOG

VEGETA_BIN = "/opt/vegeta/vegeta"
RESULTS_CSV_FILE_NAME = "vegeta_results.csv"


class LoadClient:
    def __init__(self, network):
        self.network = network

    def start(self):
        primary, _ = self.network.find_primary()
        primary_hostname = (
            f"{primary.get_public_rpc_host()}:{primary.get_public_rpc_port()}"
        )

        vegeta_targets = "vegeta_targets"
        with open(vegeta_targets, "w", encoding="utf-8") as f:
            for i in range(10):
                TargetGenerator.write_vegeta_target_line(
                    f,
                    primary_hostname,
                    "/app/log/private",
                    body={"id": i, "msg": f"Private message: {i}"},
                )

            # for i in range(10):
            #     TargetGenerator.write_vegeta_target_line(
            #         f, primary_hostname, f"/app/log/private?id={i}", method="GET"
            #     )

            # for i in range(10):
            #     TargetGenerator.write_vegeta_target_line(
            #         f,
            #         primary_hostname,
            #         "/app/log/public",
            #         body={"id": i, "msg": f"Public message: {i}"},
            #     )

            # for i in range(10):
            #     TargetGenerator.write_vegeta_target_line(
            #         f, primary_hostname, f"/app/log/public?id={i}", method="GET"
            #     )

        attack_cmd = [VEGETA_BIN, "attack"]
        attack_cmd += ["--targets", vegeta_targets]
        attack_cmd += ["--format", "json"]
        attack_cmd += ["--duration", "10s"]
        attack_cmd += ["--rate", "50"]
        sa = primary.session_auth("user0")
        attack_cmd += ["--cert", sa["session_auth"].cert]
        attack_cmd += ["--key", sa["session_auth"].key]
        attack_cmd += ["--root-certs", primary.session_ca(False)["ca"]]

        attack_cmd_s = " ".join(attack_cmd)
        LOG.info(f"Starting: {attack_cmd_s}")
        self.proc = subprocess.Popen(attack_cmd, stdout=subprocess.PIPE)

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
            RESULTS_CSV_FILE_NAME,
        ]
        self.report = subprocess.Popen(encode_cmd, stdin=tee_split.stdout)
        LOG.start("running")

    def wait_for_completion(self):
        self.report.communicate()
        self._render_results()

    def _render_results(self):
        csv = pd.read_csv(
            RESULTS_CSV_FILE_NAME,
            header=None,
            names=[
                "timestamp",
                "code",
                "latency",
                "bytesout",
                "bytesin",
                "error",
                "rate",
                "method",
                "url",
                "response_headers",
            ],
        ).set_index("timestamp")
        csv.index = pd.to_datetime(csv.index, unit="ns")
        csv["latency"] = csv.latency.apply(lambda x: x / 1e9)

        LOG.info(type(csv))
        LOG.error(csv)

        df = pd.DataFrame()
        df["latency"] = csv.latency  # .resample("1S").agg(lambda x: x.quantile(0.90))
        df["rate"] = csv.rate  # .resample("1S").max()
        plot = df.rate.plot()
        plot = df.latency.plot(secondary_y=True)
        fig = plot.get_figure()
        fig.savefig("output.png")


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
    # 2. Print vegeta results:
    # $ /opt/vegeta/vegeta attack -duration=10s -rate=50 -format json -targets vegeta_targets | tee results.bin | /opt/vegeta/vegeta encode -to csv -output report.csv
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
