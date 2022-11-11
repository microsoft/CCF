# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import pandas as pd  # type: ignore

# pylint: disable=import-error
from prettytable import PrettyTable  # type: ignore
import numpy as np
import matplotlib.pyplot as plt  # type: ignore
from typing import List
import sys
from loguru import logger as LOG
import re

SEC_MS = 1000

# Change default log format
LOG.remove()
LOG.add(
    sys.stdout,
    format="<green>[{time:HH:mm:ss.SSS}]</green> {message}",
)


class Analyze:
    def __init__(self):
        self.latency_list = []
        self.ms_latency_list = []

    def get_req_type(self, df_responses: pd.DataFrame) -> str:
        return df_responses.iloc[0]["rawResponse"].split(" ")[0]

    def get_latency_at_i(
        self, df_sends: pd.DataFrame, df_responses: pd.DataFrame, req_id: int
    ):
        # will need to handle the re-submission response from submitter when decided
        return (
            df_responses.iloc[req_id]["receiveTime"] - df_sends.iloc[req_id]["sendTime"]
        )

    def check_success(self, df_responses: pd.DataFrame, req_id: int) -> int:
        req_resp = df_responses.iloc[req_id]["rawResponse"].split("\n")
        status_list = req_resp[0].split(" ")
        # if we get a full statues and says ok increase the successful
        if len(status_list) > 1 and re.search("^2[0-9][0-9]$", status_list[1]):
            return 1
        return 0

    def iter_for_success_and_latency(
        self, df_sends: pd.DataFrame, df_responses: pd.DataFrame
    ) -> float:
        successful_reqs = 0

        for i in range(len(df_sends.index)):
            successful_reqs += self.check_success(df_responses, i)

            latency_i = self.get_latency_at_i(df_sends, df_responses, i)
            self.latency_list.append(latency_i)
            self.ms_latency_list.append(latency_i * SEC_MS)

        return successful_reqs / len(df_sends.index) * 100

    def total_time_in_sec(self, df_sends: pd.DataFrame, df_responses: pd.DataFrame):
        # time_spent is: last timestamp of responses - first timestamp of sends
        return df_responses.iloc[-1]["receiveTime"] - df_sends.iloc[0]["sendTime"]

    def sec_to_ms(self, time_in_sec: float) -> float:
        return time_in_sec / SEC_MS

    def time_success_throughput_table(
        self,
        df_sends: pd.DataFrame,
        df_responses: pd.DataFrame,
        successful_percent: float,
    ) -> PrettyTable:
        generic_output_table = PrettyTable()

        generic_output_table.field_names = [
            "Total Requests",
            "Total Time (s)",
            "Pass (%)",
            "Fail (%)",
            "Throughput (req/s)",
        ]

        time_spent = self.total_time_in_sec(df_sends, df_responses)

        generic_output_table.add_row(
            [
                len(df_sends.index),
                round(time_spent, 3),
                round(successful_percent, 1),
                round(100 - successful_percent, 1),
                round(len(df_sends.index) / time_spent, 1),
            ]
        )
        return generic_output_table

    def latencies_table(
        self, df_sends: pd.DataFrame, df_responses: pd.DataFrame
    ) -> PrettyTable:
        ms_time_spent_sum = self.total_time_in_sec(df_sends, df_responses) * SEC_MS
        latency_output_table = PrettyTable()
        latency_output_table.field_names = [
            "Latency (50th) (ms)",
            "Average Latency (ms)",
            "Latency 80th (ms)",
            "Latency 90th (ms)",
            "Latency 95th (ms)",
            "Latency 99th (ms)",
            "Latency 99.9th (ms)",
        ]
        latency_output_table.add_row(
            [
                round(np.percentile(self.ms_latency_list, 50), 3),
                round(ms_time_spent_sum / len(df_sends.index), 3),
                round(np.percentile(self.ms_latency_list, 80), 3),
                round(np.percentile(self.ms_latency_list, 90), 3),
                round(np.percentile(self.ms_latency_list, 95), 3),
                round(np.percentile(self.ms_latency_list, 99), 3),
                round(np.percentile(self.ms_latency_list, 99.9), 3),
            ]
        )
        return latency_output_table

    def customize_table(self, fields_list: List[str], values_list: List[List]):
        custom_table = PrettyTable()
        custom_table.field_names = fields_list
        for val_row in values_list:
            custom_table.add_row(val_row)
        return custom_table

    def plot_latency_by_id(self, df_sends: pd.DataFrame) -> None:
        id_unit = [x for x in range(0, len(df_sends.index))]
        lat_unit = self.ms_latency_list
        plt.figure()
        plt.scatter(id_unit, lat_unit, s=1)
        plt.ylabel("Latency_ms")
        plt.xlabel("ids")
        plt.savefig("latency_per_id.png")
        plt.figure(figsize=(15, 15), dpi=80)

    def plot_latency_across_time(self, df_responses) -> None:
        time_unit = [
            x - df_responses["receiveTime"][0] + 1 for x in df_responses["receiveTime"]
        ]
        plt.figure()
        plt.scatter(time_unit, self.ms_latency_list, s=1)
        plt.ylabel("Latency(ms)")
        plt.xlabel("time(s)")
        plt.savefig("latency_across_time.png")
        plt.figure(figsize=(15, 15), dpi=80)

    def plot_throughput_per_block(
        self, df_responses: pd.DataFrame, time_block: float
    ) -> None:
        """
        It splits the dataset in buckets of time_block seconds difference
        and will plot the throughput for each bucket
        """
        # sort the latencies as it makes sense to get the throughput

        # by time unit ignoring the ids
        sorted_receive_times = sorted(df_responses["receiveTime"].tolist())
        block_indexes = [0]
        time_block_comparator = sorted_receive_times[0]
        for i, lat in enumerate(sorted_receive_times):
            if lat > time_block_comparator + time_block:
                block_indexes.append(i)
                time_block_comparator += time_block
        req_per_block = []
        block_latency = []
        if len(block_indexes) > 1:
            for i in range(len(block_indexes) - 1):
                req_per_block.append(block_indexes[i + 1] - block_indexes[i])
                # Assuming there are no 2 consecutive timestamps with difference > time_block
                block_latency.append(time_block * SEC_MS * (i + 1))
            req_per_block.append(len(sorted_receive_times) - block_indexes[-1])
            block_latency.append(
                block_latency[-1]
                + int((sorted_receive_times[-1] - time_block_comparator) * SEC_MS)
            )
        throughput_per_block = [
            x / time_block for x in req_per_block
        ]  # x/time_block comes from rule of three
        print(req_per_block)
        print(block_latency)
        plt.figure()
        plt.plot(block_latency, throughput_per_block)
        plt.ylabel("Throughput(req/s)")
        plt.xlabel("time(ms)")
        plt.savefig("throughput_across_time.png")

    def plot_latency_distribution(self, ms_separator: float, highest_vals=15):
        """
        Starting from minimum latency with ms_separator
        step split the ms latency list in buckets
        and plots the highest_vals top buckets
        """
        max_latency = max(self.ms_latency_list)
        min_latency = min(self.ms_latency_list)

        if max_latency < ms_separator:
            LOG.remove()
            LOG.add(
                sys.stdout,
                format="<red>[ERROR]:</red> {message}",
            )

            LOG.error(
                f"Latency values are less than {ms_separator}, cannot produce latency distribution graph"
            )
            return

        bins_number = (
            int(
                (max_latency - min_latency) // ms_separator
                + bool((max_latency - min_latency) % ms_separator)
            )
            + 1
        )

        counts = [0] * bins_number
        bins = [min_latency]
        bin_val = min_latency
        for _ in range(bins_number):
            bin_val += ms_separator
            bins.append(bin_val)

        for lat in self.ms_latency_list:
            counts[
                int(
                    (lat - min_latency) // ms_separator
                    + bool((lat - min_latency) % ms_separator)
                )
            ] += 1

        top_bins = []
        top_counts = []
        min_count = sorted(counts)[-highest_vals]
        for ind in range(len(counts)):
            if counts[ind] >= min_count:
                top_bins.append(round(bins[ind], 3))
                top_counts.append(counts[ind])

        x_axis = range(len(top_bins))
        plt.figure()
        fig, ax = plt.subplots()
        ax.bar(x_axis, top_counts, 0.9, align="center")
        ax.set_xticks(x_axis)
        ax.set_xticklabels(top_bins, rotation=25)
        plt.ylabel("Count")
        plt.xlabel("Latency")
        fig.subplots_adjust(bottom=0.2)
        plt.savefig("latency_distribution.png")


def get_df_from_parquet_file(input_file: str):
    return pd.read_parquet(input_file, engine="fastparquet")


def default_analysis(send_file, response_file):
    """
    Produce the analysis results
    """
    analysis = Analyze()
    df_sends = get_df_from_parquet_file(send_file)
    df_responses = get_df_from_parquet_file(response_file)

    successful_percent = analysis.iter_for_success_and_latency(df_sends, df_responses)

    LOG.info(f"The request type sent is {analysis.get_req_type(df_responses)}")

    print(
        analysis.time_success_throughput_table(
            df_sends, df_responses, successful_percent
        )
    )
    print(analysis.latencies_table(df_sends, df_responses))

    x = "-" * 20
    LOG.info(f'{"".join(x)} Start plotting  {"".join(x)}')

    analysis.plot_latency_by_id(df_sends)
    analysis.plot_latency_across_time(df_responses)
    analysis.plot_throughput_per_block(df_responses, 0.1)

    LOG.info(f'{"".join(x)}Finished plotting{"".join(x)}')
