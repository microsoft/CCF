# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import re
import sys
from email.parser import Parser
from pathlib import Path
from typing import List

import matplotlib.pyplot as plt  # type: ignore
import numpy as np
import pandas as pd  # type: ignore
from loguru import logger as LOG

# pylint: disable=import-error
from prettytable import PrettyTable  # type: ignore

SEC_MS = 1000
DEFAULT_FIGURE_SIZE = (8, 2.5)
SMALL_FIGURE_SIZE = (4, 2)

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
        self.request_verb = []
        self.throughput = 0

    def get_req_type(self, df_responses: pd.DataFrame) -> str:
        return df_responses.iloc[0]["rawResponse"].split(b" ")[0].decode("ascii")

    def get_latency_at_i(
        self, df_sends: pd.DataFrame, df_responses: pd.DataFrame, req_id: int
    ):
        # will need to handle the re-submission response from submitter when decided
        return (
            df_responses.iloc[req_id]["receiveTime"] - df_sends.iloc[req_id]["sendTime"]
        )

    def check_success(self, df_responses: pd.DataFrame, req_id: int) -> int:
        req_resp = df_responses.iloc[req_id]["rawResponse"].split(b"\n")
        status_list = req_resp[0].split(b" ")
        # if we get a full statues and says ok increase the successful
        if len(status_list) > 1 and re.search(b"^2[0-9][0-9]$", status_list[1]):
            return 1
        return 0

    def iter_for_success_and_latency(
        self, df_input: pd.DataFrame, df_sends: pd.DataFrame, df_responses: pd.DataFrame
    ) -> float:
        successful_reqs = 0

        for i in range(len(df_sends.index)):
            successful_reqs += self.check_success(df_responses, i)

            latency_i = self.get_latency_at_i(df_sends, df_responses, i)
            self.latency_list.append(latency_i)
            self.ms_latency_list.append(latency_i * SEC_MS)
            self.request_verb.append(df_input["request"][i].decode().split(" ")[0])

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
        self.throughput = len(df_sends.index) / time_spent

        generic_output_table.add_row(
            [
                len(df_sends.index),
                round(time_spent, 3),
                round(successful_percent, 1),
                round(100 - successful_percent, 1),
                round(self.throughput, 1),
            ]
        )
        return generic_output_table

    def latencies_table(
        self, df_sends: pd.DataFrame, df_responses: pd.DataFrame
    ) -> PrettyTable:
        latency_output_table = PrettyTable()
        latency_output_table.field_names = [
            "Mean Latency (ms)",
            "Latency 50th (ms)",
            "Latency 90th (ms)",
            "Latency 99th (ms)",
            "Latency 99.9th (ms)",
        ]
        latency_output_table.add_row(
            [
                round(np.mean(self.ms_latency_list), 3),
                round(np.percentile(self.ms_latency_list, 50), 3),
                round(np.percentile(self.ms_latency_list, 90), 3),
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

    def plot_commits(
        self,
        df_responses: pd.DataFrame,
        df_generator: pd.DataFrame,
        results_directory=Path("."),
    ):
        """
        For submitted requests of the type: N posts 1 commit, this function will
        plot the number of posted versus committed messages
        """
        custom_tx_header = "x-ms-ccf-transaction-id"
        custom_commit_header = "transaction_id"

        # Get the first write Tx in parser and then the id
        raw_0 = Parser().parsestr(
            df_responses.iloc[0]["rawResponse"].split(b"\r\n", 1)[1].decode("ascii")
        )
        init_tx_id = int(raw_0[custom_tx_header].split(".")[1]) - 1
        init_time = float(df_responses.iloc[0]["receiveTime"])

        tx_ids = []
        committed_ids = []
        time_units = []
        for row in range(len(df_generator.index)):
            if df_generator.iloc[row]["request"].split(b" ")[
                0
            ] == b"GET" and df_generator.iloc[row]["request"].split(b" ")[1].endswith(
                b"commit"
            ):
                # Break when the first of the aggressive
                # commits (consecutive GETs) reached the posts
                if (
                    len(tx_ids) > 1
                    and tx_ids[-1] == committed_ids[-1] - 1
                    and df_generator.iloc[row - 1]["request"].split(b" ")[0] == b"GET"
                ):
                    break

                commit_tx = df_responses.iloc[row]["rawResponse"].split(b"\r\n\r\n")[-1]

                headers_alone = (
                    df_responses.iloc[row - 1]["rawResponse"]
                    .split(b"\r\n", 1)[1]
                    .decode("ascii")
                )
                raw = Parser().parsestr(headers_alone)

                if df_generator.iloc[row - 1]["request"].split(b" ")[0] != b"GET":
                    tx_ids.append(int(raw[custom_tx_header].split(".")[1]) - init_tx_id)
                else:
                    tx_ids.append(tx_ids[-1])

                committed_ids.append(
                    int(json.loads(commit_tx)[custom_commit_header][2:]) - init_tx_id
                )

                time_units.append(
                    (float(df_responses.iloc[row]["receiveTime"]) - init_time)
                )
        plt.figure()
        plt.scatter(time_units, tx_ids, label="Txid", marker="o")
        plt.scatter(time_units, committed_ids, label="Commits", marker="+")
        plt.ylabel("Requests")
        plt.xlabel("Time (s)")
        plt.legend()
        plt.savefig(results_directory / "posted_vs_committed.pdf")
        plt.close()

    def plot_latency_by_id(
        self,
        df_sends: pd.DataFrame,
        results_directory=Path("."),
        y_limits=(None, None),
        **kwargs,
    ) -> None:
        id_unit = [x for x in range(0, len(df_sends.index))]
        lat_unit = self.ms_latency_list
        plt.figure(**kwargs)
        plt.scatter(id_unit, lat_unit, s=1, c="black")
        plt.ylabel("Latency (ms)")
        plt.xlabel("Requests")
        plt.xlim([0, len(df_sends.index)])
        plt.ylim(y_limits)
        if y_limits == (None, None):
            range_string = "all"
        else:
            range_string = f"from_{y_limits[0]}ms_to_{y_limits[1]}ms"
        filename = f"latency_per_id_{range_string}.pdf"
        plt.savefig(results_directory / filename)
        plt.close()

    def plot_latency_by_id_and_verb(
        self, df_sends: pd.DataFrame, results_directory=Path("."), **kwargs
    ) -> None:
        id_unit = {}
        lat_unit = {}
        for verb in VERBS:
            id_unit[verb] = []
            lat_unit[verb] = []

        for i, verb in enumerate(self.request_verb):
            id_unit[verb].append(i)
            lat_unit[verb].append(self.ms_latency_list[i])

        plt.figure(**kwargs)
        for verb in VERBS:
            plt.scatter(id_unit[verb], lat_unit[verb], s=1, label=verb)
        plt.legend()
        plt.ylabel("Latency (ms)")
        plt.xlabel("Requests")
        plt.xlim([0, len(df_sends.index)])
        plt.ylim(bottom=0)
        plt.savefig(results_directory / "latency_per_id_and_verb.pdf")
        plt.close()

    def plot_latency_cdf(self, results_directory=Path("."), **kwargs) -> None:
        latencies_sorted = np.sort(self.ms_latency_list)
        proportion = (
            1.0 * np.arange(len(self.ms_latency_list)) / (len(self.ms_latency_list) - 1)
        )
        plt.figure(**kwargs)
        plt.plot(latencies_sorted, proportion)
        plt.ylabel("$p$")
        plt.ylim([0, 1])
        plt.xlabel("Latency (ms)")
        plt.savefig(results_directory / "latency_cdf.pdf")
        plt.close()

    def plot_latency_across_time(
        self, df_responses, results_directory=Path("."), **kwargs
    ) -> None:
        time_unit = [
            x - df_responses["receiveTime"][0] for x in df_responses["receiveTime"]
        ]
        plt.figure(**kwargs)
        plt.scatter(time_unit, self.ms_latency_list, s=1)
        plt.ylabel("Latency (ms)")
        plt.xlabel("Time (s)")
        plt.savefig(results_directory / "latency_across_time.pdf")
        plt.close()

    def plot_throughput_per_block(
        self,
        df_responses: pd.DataFrame,
        time_block: float,
        results_directory=Path("."),
        **kwargs,
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
        block_latency_sec = [x / SEC_MS for x in block_latency]
        plt.figure(**kwargs)
        plt.plot(block_latency_sec, throughput_per_block)
        plt.ylabel("Throughput (req/s)")
        plt.xlabel("Time (s)")
        plt.ylim(bottom=0)
        filename = f"throughput_across_time_{time_block}_buckets.pdf"
        plt.savefig(results_directory / filename)
        plt.close()

    def plot_latency_distribution(
        self, ms_separator: float, results_directory=Path("."), highest_vals=15
    ):
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
        plt.xlabel("Latency (ms)")
        fig.subplots_adjust(bottom=0.2)
        plt.savefig(results_directory / "latency_distribution.pdf")
        plt.close()

    def default_plots(self, df_sends, df_responses, results_directory=Path(".")):
        x = "-" * 20
        LOG.info(f'{"".join(x)} Start plotting  {"".join(x)}')
        prettify_graphs()
        self.plot_latency_by_id(df_sends, results_directory, figsize=SMALL_FIGURE_SIZE)
        self.plot_latency_by_id(
            df_sends, results_directory, y_limits=(0, 10), figsize=SMALL_FIGURE_SIZE
        )
        self.plot_latency_by_id(
            df_sends, results_directory, y_limits=(2, 4), figsize=SMALL_FIGURE_SIZE
        )
        self.plot_latency_across_time(df_responses, results_directory)
        self.plot_throughput_per_block(df_responses, 0.1, results_directory)
        self.plot_throughput_per_block(df_responses, 0.01, results_directory)
        self.plot_latency_cdf(results_directory)
        self.plot_latency_by_id_and_verb(df_sends, results_directory)
        LOG.info(f'{"".join(x)}Finished plotting{"".join(x)}')


def get_df_from_parquet_file(input_file: Path):
    return pd.read_parquet(input_file)


def prettify_graphs():
    fontsize = 9
    params = {
        "axes.labelsize": fontsize,
        "font.size": fontsize,
        "legend.fontsize": fontsize,
        "xtick.labelsize": fontsize,
        "ytick.labelsize": fontsize,
        "figure.figsize": DEFAULT_FIGURE_SIZE,
        "xtick.direction": "in",
        "ytick.direction": "in",
        "xtick.top": True,
        "ytick.right": True,
        "xtick.minor.visible": True,
        "ytick.minor.visible": True,
        "lines.linewidth": 2,
        "legend.frameon": False,
        "axes.grid": False,
        "savefig.bbox": "tight",
    }
    plt.rcParams.update(params)


def default_analysis(
    input_file: Path,
    send_file: Path,
    response_file: Path,
    results_directory=Path("."),
    error_on_failure=False,
    plot_graphs=True,
):
    """
    Produce the analysis results.
    A summary of results will be printed to stdout and a collection of
    graphs will also be saved to results_directory, provided that plot_graphs
    is True. Analysis will terminate with an error if error_on_failure
    is set and any requests have not succeeded.
    """
    analysis = Analyze()
    df_input = get_df_from_parquet_file(input_file)
    df_sends = get_df_from_parquet_file(send_file)
    df_responses = get_df_from_parquet_file(response_file)

    successful_percent = analysis.iter_for_success_and_latency(
        df_input, df_sends, df_responses
    )

    if error_on_failure and successful_percent < 100:
        assert False, "Not all requests were successful"

    LOG.info(f"The request type sent is {analysis.get_req_type(df_responses)}")
    verbs = analysis.request_verb
    verb_counts = {v: verbs.count(v) for v in set(verbs)}
    LOG.info(
        f"Request verbs counts are: { ', '.join(f'{v} {c}' for v,c in verb_counts.items()) }"
    )

    print(
        analysis.time_success_throughput_table(
            df_sends, df_responses, successful_percent
        )
    )
    print(analysis.latencies_table(df_sends, df_responses))

    if plot_graphs:
        analysis.default_plots(df_sends, df_responses, results_directory)

    return analysis


def default_analysis_with_default_filenames(test_directory: Path, **kwargs):
    return default_analysis(
        test_directory / "input.parquet",
        test_directory / "send.parquet",
        test_directory / "responses.parquet",
        test_directory,
        **kwargs,
    )
