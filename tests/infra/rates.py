# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import infra.proc
import collections
from statistics import mean, harmonic_mean, median, pstdev

from loguru import logger as LOG


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
        out_list = []

        def format_title(s):
            out_list.append(f"{s:-^42}")

        def format(s, n):
            out_list.append(f"--- {s:>20}: {n:>12.2f} ---")

        format_title("Summary")
        format("mean", mean(self.tx_rates_data))
        format("harmonic mean", harmonic_mean(self.tx_rates_data))
        format("standard deviation", pstdev(self.tx_rates_data))
        format("median", median(self.tx_rates_data))
        format("max", max(self.tx_rates_data))
        format("min", min(self.tx_rates_data))

        format_title("Histogram")
        buckets_list = self.histogram_data["buckets"]
        buckets = {tuple(e[0]): e[1] for e in buckets_list}
        out_list.append(f"({sum(buckets.values())} samples in {len(buckets)} buckets)")
        max_count = max(buckets.values())
        for k, count in sorted(buckets.items()):
            out_list.append(
                "{:>12}: {}".format(
                    f"{k[0]}-{k[1]}", "*" * min(count, (60 * count // max_count))
                )
            )

        return "\n".join(out_list)

    def save_results(self, output_file):
        with open(output_file, "w") as mfile:
            json.dump(self.all_metrics, mfile)

    def process_next(self):
        with self.primary.user_client() as client:
            rv = client.get("getCommit")
            result = rv.to_dict()
            next_commit = result["result"]["commit"]
            more_to_process = self.commit != next_commit
            self.commit = next_commit

            return more_to_process

    def get_metrics(self):
        with self.primary.user_client() as client:
            rv = client.get("getMetrics")
            result = rv.to_dict()
            result = result["result"]
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
                self.histogram_data = histogram
