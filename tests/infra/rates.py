# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import infra.proc
import collections
from statistics import mean, harmonic_mean, median, pstdev
import matplotlib.pyplot as plt

from loguru import logger as LOG

COMMIT_COUNT_CUTTOF = 20


class TxRates:
    def __init__(self, primary):
        self.get_histogram = False
        self.primary = primary
        self.same_commit_count = 0
        self.data = {}
        self.commit = 0

        with open("getMetrics.json", "w") as gtxrf:
            gtxrf.write('{"id":1,"jsonrpc":"2.0","method":"getMetrics","params":{}}\n')
        with open("getCommit.json", "w") as gcf:
            gcf.write('{"id":1,"jsonrpc":"2.0","method":"getCommit","params":{}}\n')

    def process_next(self):
        rv = infra.proc.ccall(
            "./client",
            "--host={}".format(self.primary.host),
            "--port={}".format(self.primary.tls_port),
            "--ca=networkcert.pem",
            "userrpc",
            "--cert=user1_cert.pem",
            "--pk=user1_privk.pem",
            "--req=getCommit.json",
            log_output=False,
        )
        print(rv.stdout.decode())
        result = rv.stdout.decode().split("\n")[1]
        result = json.loads(result)
        next_commit = result["result"]["commit"]
        if self.commit == next_commit:
            self.same_commit_count += 1
        else:
            self.same_commit_count = 0

        self.commit = next_commit

        if self.same_commit_count > COMMIT_COUNT_CUTTOF:
            self._get_metrics()
            return False
        return True

    def print_results(self):
        print(json.dumps(self.data, indent=4))

    def save_results(self):
        with open("tx_rates.txt", "w") as file:
            for key in sorted(self.data.keys()):
                file.write(key + " : " + str(self.data[key]))
                file.write("\n")

    def _get_metrics(self):
        rv = infra.proc.ccall(
            "./client",
            "--host={}".format(self.primary.host),
            "--port={}".format(self.primary.tls_port),
            "--ca=networkcert.pem",
            "userrpc",
            "--cert=user1_cert.pem",
            "--pk=user1_privk.pem",
            "--req=getMetrics.json",
            log_output=False,
        )

        result = rv.stdout.decode().split("\n")[1]
        result = json.loads(result)
        result = result["result"]["metrics"]
        all_rates = []
        all_durations = []
        plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
        plt.grid(True)
        fig, ax = plt.subplots(nrows=1, ncols=2, figsize=(15, 8))
        plt.tight_layout()

        # TODO get from file instead of via RPC!!
        if "tx_rates" in result:
            rates = result["tx_rates"]
            for key in rates:
                if rates[key]["rate"] > 1000:
                    all_rates.append(rates[key]["rate"])
                    all_durations.append(float(rates[key]["duration"]))
            # calculate stats
            print("----- mean ----: " + str(mean(all_rates)))
            print("----- harmonic mean ----: " + str(harmonic_mean(all_rates)))
            print("---- standard deviation ----: " + str(pstdev(all_rates)))
            print("----- median ----: " + str(median(all_rates)))
            print("---- max ----: " + str(max(all_rates)))
            print("---- min ----: " + str(min(all_rates)))
            times, rates = (list(t) for t in zip(*sorted(zip(all_durations, all_rates))))
            ax[0].plot(times, rates)
            ax[0].title.set_text('tx/sec for test duration')
            ax[0].set_ylabel("tx/sec")
            ax[0].set_xlabel("seconds")

        else:
            LOG.info("No tx rate metrics found...")

        if "histogram" not in result:
            LOG.info("No histogram metrics found...")
            return

        histogram = result["histogram"]
        histogram_buckets = histogram["buckets"]

        LOG.info("Filtering histogram results...")
        hist_data = {}

        for key in histogram_buckets:
            if histogram_buckets[key] > 0:
                range_1, range_2 = key.split("..")
                hist_data[int(range_1)] = (range_2, histogram_buckets[key])

        ordered_data = collections.OrderedDict(sorted(hist_data.items(), key=lambda x: x[0]))
        self.data["histogram"] = {}
        buckets = []
        rates = []
        for key, value_tuple in ordered_data.items():
            self.data["histogram"][str(key) + ".." + value_tuple[0]] = value_tuple[1]
            buckets.append(str(key) + ".." + value_tuple[0])
            rates.append(value_tuple[1])
        ax[1].bar(buckets, rates, 1)
        ax[1].title.set_text('tx/sec rates histogram')
        ax[1].set_ylabel("bucket count")
        ax[1].set_xlabel("bucket range (tx/sec)")
        plt.xticks(rotation=45, rotation_mode="anchor", ha="right")
        plt.savefig("tx_rates.png", bbox_inches="tight", pad_inches=0)

        self.data["low"] = histogram["low"]
        self.data["high"] = histogram["high"]
        self.data["underflow"] = histogram["underflow"]
        self.data["overflow"] = histogram["overflow"]
