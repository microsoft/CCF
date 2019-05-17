# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import infra.proc
import collections
from statistics import mean, harmonic_mean, median, pstdev

from loguru import logger as LOG

COMMIT_COUNT_CUTTOF = 50


class TxRates:
    def __init__(self, primary):
        self.get_histogram = False
        self.primary = primary
        self.same_commit_count = 0
        self.histogram_data = {}
        self.tx_rates_data = []
        self.save_metrics = {}
        self.commit = 0

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

    def print_results(self):
        print("----- mean ----: " + str(mean(self.tx_rates_data)))
        print("----- harmonic mean ----: " + str(harmonic_mean(self.tx_rates_data)))
        print("---- standard deviation ----: " + str(pstdev(self.tx_rates_data)))
        print("----- median ----: " + str(median(self.tx_rates_data)))
        print("---- max ----: " + str(max(self.tx_rates_data)))
        print("---- min ----: " + str(min(self.tx_rates_data)))
        print(json.dumps(self.data, indent=4))

    def save_results(self):
        with open("tx_rates.json", "w") as file:
            file.write(self.save_metrics)

    def _get_metrics(self):
        with self.primary.user_client(format="json") as client:
            rv = client.rpc("getMetrics", {})
            result = rv.to_dict()
            result = result["result"]["metrics"]
            self.save_metrics = result

            if "tx_rates" in result:
                rates = result["tx_rates"]
                if rates is None:
                    LOG.info("No tx rate metrics found...")
                else:
                    for key in rates:
                        if rates[key]["rate"] > 1000:
                            all_rates.append(rates[key]["rate"])
                            all_durations.append(float(rates[key]["duration"]))
                    self.tx_rates_data = all_rates

            else:
                LOG.info("No tx rate metrics found...")

            if "histogram" not in result:
                LOG.info("No histogram metrics found...")
            else:
                histogram = result["histogram"]
                histogram_buckets = histogram["buckets"]

                LOG.info("Filtering histogram results...")
                hist_data = {}

                for key in histogram_buckets:
                    if histogram_buckets[key] > 0:
                        range_1, range_2 = key.split("..")
                        hist_data[int(range_1)] = (range_2, histogram_buckets[key])

                ordered_data = collections.OrderedDict(
                    sorted(hist_data.items(), key=lambda x: x[0])
                )
                self.histogram_data["histogram"] = {}
                buckets = []
                rates = []
                for key, value_tuple in ordered_data.items():
                    self.histogram_data["histogram"][
                        str(key) + ".." + value_tuple[0]
                    ] = value_tuple[1]
                    buckets.append(str(key) + ".." + value_tuple[0])
                    rates.append(value_tuple[1])

                self.histogram_data["low"] = histogram["low"]
                self.histogram_data["high"] = histogram["high"]
                self.histogram_data["underflow"] = histogram["underflow"]
                self.histogram_data["overflow"] = histogram["overflow"]
