# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import infra.proc
import collections
from statistics import mean, harmonic_mean, median, pstdev

from loguru import logger as LOG

COMMIT_COUNT_CUTTOF = 20


class TxRates:
    def __init__(self, primary):
        self.get_histogram = False
        self.primary = primary
        self.same_commit_count = 0
        self.histogram_data = {}
        self.tx_rates_data = []
        self.all_metrics = {}
        self.commit = 0

    def __str__(self):
        out_list = ["----------- tx rates -----------"]
        out_list.append("----- mean ----: " + str(mean(self.tx_rates_data)))
        out_list.append(
            "----- harmonic mean ----: " + str(harmonic_mean(self.tx_rates_data))
        )
        out_list.append(
            "---- standard deviation ----: " + str(pstdev(self.tx_rates_data))
        )
        out_list.append("----- median ----: " + str(median(self.tx_rates_data)))
        out_list.append("---- max ----: " + str(max(self.tx_rates_data)))
        out_list.append("---- min ----: " + str(min(self.tx_rates_data)))
        out_list.append("----------- tx rates histogram -----------")
        out_list.append(json.dumps(self.histogram_data, indent=4))
        return "\n".join(out_list)

    def save_results(self, output_file):
        with open(output_file, "w") as mfile:
            json.dump(self.all_metrics, mfile)

    def process_next(self):
        with self.primary.user_client(format="json") as client:
            rv = client.rpc("getCommit", {})
            result = rv.to_dict()
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

    def _get_metrics(self):
        with self.primary.user_client(format="json") as client:
            rv = client.rpc("getMetrics", {})
            result = rv.to_dict()
            result = result["result"]["metrics"]
            self.all_metrics = result

            all_rates = []
            all_durations = []
            rates = result.get("tx_rates")
            if rates is None:
                LOG.info("No tx rate metrics found...")
            else:
                for key in rates:
                    all_rates.append(rates[key]["rate"])
                    all_durations.append(float(rates[key]["duration"]))
                self.tx_rates_data = all_rates

            histogram = result.get("histogram")
            if histogram is None:
                LOG.info("No histogram metrics found...")
            else:
                histogram_buckets = histogram["buckets"]

                LOG.info("Filtering histogram results...")
                hist_data = {}

                for key in histogram_buckets:
                    if histogram_buckets[key] > 0:
                        range_1, range_2 = key.split("..")
                        hist_data[int(range_1)] = (range_2, histogram_buckets[key])

                self.histogram_data["histogram"] = {}
                buckets = []
                rates = []
                for key, value_tuple in sorted(hist_data.items(), key=lambda x: x[0]):
                    self.histogram_data["histogram"][
                        str(key) + ".." + value_tuple[0]
                    ] = value_tuple[1]
                    buckets.append(str(key) + ".." + value_tuple[0])
                    rates.append(value_tuple[1])

                self.histogram_data["low"] = histogram["low"]
                self.histogram_data["high"] = histogram["high"]
                self.histogram_data["underflow"] = histogram["underflow"]
                self.histogram_data["overflow"] = histogram["overflow"]
