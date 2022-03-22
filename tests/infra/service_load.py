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
        # {"attack":"","seq":1,"code":200,"timestamp":"2022-03-22T12:17:51.942008217Z","latency":117952597,"bytes_out":38,"bytes_in":4,"error":"","body":"dHJ1ZQ==","method":"POST","url":"https://127.82.156.156:32923/app/log/private","headers":{"Content-Type":["application/json"],"X-Ms-Ccf-Transaction-Id":["2.20"],"Content-Length":["4"]}}
        df = pd.read_csv(
            RESULTS_CSV_FILE_NAME,
            header=None,
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

        x = df.index
        y = df["latency"]
        plt.plot(x, y)
        plt.savefig("output.png")
        # df["latency"] = csv.latency  # .resample("1S").agg(lambda x: x.quantile(0.90))
        # # df["rate"] = csv.rate  # .resample("1S").max()
        # ax = df[["latency"]].plot(title="lala")
        # # ax.set_xticks(df["timestamp"])
        # ax.set_xlabel("time")
        # fig = ax.get_figure()

        # # plot = df.rate.plot()
        # # plot = df.latency.plot(secondary_y=True)
        # # fig = plot.get_figure()
        # fig.savefig("output.png")


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
