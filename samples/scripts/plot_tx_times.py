# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import json
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from collections import defaultdict
from cycler import cycler


def compute_linear_regression(x, y):
    model = LinearRegression().fit(x, y)
    return model.coef_[0]


def plot_timeseries(sent, received, ax, title, args):
    commit_lines = defaultdict(list)
    tx_time_lines = defaultdict(list)

    # Add cumcount column to deal with duplicate idxs
    sent = sent.assign(cumcount=sent.groupby("idx").cumcount())
    received = received.assign(cumcount=received.groupby("idx").cumcount())

    # Join DataFrames
    test_df = sent.merge(received, on=["idx", "cumcount"]).drop("cumcount", 1)
    test_df["recv_msec"] = test_df["recv_sec"] * 1000
    test_df["sent_msec"] = test_df["sent_sec"] * 1000
    test_df["request_time"] = test_df["recv_msec"] - test_df["sent_msec"]

    if not args.no_throughput:
        # Print performance global throughput in dedicated box
        successful_global_commit_rate = compute_linear_regression(
            test_df["sent_sec"].values.reshape((-1, 1)), test_df["global_commit"]
        )
        global_rate_string = f"""global commit throughput (successful txs only):
                                {int(successful_global_commit_rate)} tx/s"""
        props = dict(boxstyle="round", facecolor="wheat", alpha=0.5)
        ax.text(
            0.5,
            0.20,
            global_rate_string,
            transform=ax.transAxes,
            fontsize=12,
            verticalalignment="top",
            bbox=props,
        )

    # Remove error values
    test_df["commit"].replace(0, np.nan, inplace=True)
    test_df["global_commit"].replace(0, np.nan, inplace=True)

    # Set axis properties
    ax.title.set_text(title)

    # Plot second axis of commit versions
    # (Plotted first so it gets consistent colors)
    commit_ax = ax.twinx()
    for column in ("commit", "global_commit"):
        commit_lines[column] += commit_ax.plot(
            test_df["sent_msec"], test_df[column], label=column
        )
    commit_ax.set_ylim(bottom=0, auto=True)

    # Based on label_outer, but keeping label on last col rather than first
    if commit_ax.is_last_col():
        commit_ax.set_ylabel("Version")
    else:
        commit_ax.set_yticks([])

    if args.combine_methods:
        test_df["method"] = test_df["method"].apply(lambda s: s.split("_")[0])

    colours = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    used_colours = len(commit_lines)
    colours = colours[used_colours:] + colours[:used_colours]

    ax.set_prop_cycle(cycler(color=colours))

    # Plot transaction times, by method
    for method, grp in test_df.groupby("method"):
        tx_time_lines[method] += ax.plot(
            grp["sent_msec"], grp["request_time"], ".", label=method
        )
    ax.set_ylim(bottom=0, auto=True)
    ax.set_xlim(auto=True)
    ax.set(xlabel="Sent time (ms)")

    # Based on label_outer, but keeping x labels for all
    if commit_ax.is_first_col():
        ax.set_ylabel("Response delay (ms)")

    ax.grid(axis="y")

    return (commit_lines, tx_time_lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--title", help="Title for plot", type=str)
    parser.add_argument(
        "--width", help="Total width of plotted figure", default=12, type=int
    )
    parser.add_argument(
        "--height", help="Total height of plotted figure", default=8, type=int
    )
    parser.add_argument("--save-to", help="Path to saved resulting plot", type=str)
    parser.add_argument(
        "--combine-methods",
        help="Only keep method name up to first underscore, combining similar",
        action="store_true",
    )
    parser.add_argument(
        "--no-legend", help="Do not display legends", action="store_true"
    )
    parser.add_argument(
        "--no-throughput",
        help="Do not display average throughput overlay",
        action="store_true",
    )

    subparsers = parser.add_subparsers(
        title="subcommands", dest="command", required=True
    )

    single_parser = subparsers.add_parser("single", help="Plot results of single test")
    single_parser.add_argument(
        "sent", help="Path to file containing timings of sent tx requests", type=str
    )
    single_parser.add_argument(
        "received",
        help="Path to file containing timnigs of received tx responses",
        type=str,
    )

    compare_parser = subparsers.add_parser(
        "compare", help="Plot results of multiple test variants, for comparison"
    )
    compare_parser.add_argument(
        "variants", help="Path to file defining tests to compare", type=str
    )

    args = parser.parse_args()

    figsize = (args.width, args.height)

    commit_lines = {}
    time_lines = {}

    if args.command == "single":
        figure = plt.figure(figsize=figsize)
        sent_df = pd.read_csv(args.sent)
        received_df = pd.read_csv(args.received)

        ax = plt.axes()
        commits, times = plot_timeseries(sent_df, received_df, ax, args.title, args)
        commit_lines.update(commits)
        time_lines.update(times)

    elif args.command == "compare":
        variants = json.load(open(args.variants))
        if not isinstance(variants, list):
            raise TypeError(
                "Contents of variants file is not a list: {}".format(variants)
            )

        row_len = max(len(row) for row in variants)

        figure, axes = plt.subplots(
            len(variants), row_len, figsize=figsize, squeeze=False, sharey="row"
        )
        figure.subplots_adjust(wspace=0, hspace=0.6)

        figure.suptitle(args.title)

        for y, row in enumerate(variants):
            print("Row {}".format(y))
            for x, variant in enumerate(row):
                print(" Column {}".format(x))
                ax = axes[y, x]

                # Hide empty axes
                if variant is None:
                    ax.axis("off")
                    continue

                # Run command
                cmd = variant.get("command")
                if cmd is not None:
                    if isinstance(cmd, list):
                        cmd = " ".join(cmd)
                    print("  Executing:")
                    print("   {}".format(cmd))
                    result = subprocess.run(cmd, shell=True, capture_output=True)
                    print("  Done, plotting")
                else:
                    print("  No command to execute")

                # Load and plotresults
                sent_df = pd.read_csv(variant["sent"])
                received_df = pd.read_csv(variant["received"])
                commits, times = plot_timeseries(
                    sent_df, received_df, ax, variant["subtitle"], args
                )
                commit_lines.update(commits)
                time_lines.update(times)

            # Hide empty axes after short rows
            for x in range(x + 1, row_len):
                axes[y, x].axis("off")

    if not args.no_legend:
        commit_values = {k: vs[0] for (k, vs) in commits.items()}
        commit_legend = figure.legend(
            commit_values.values(),
            commit_values.keys(),
            loc="upper right",
            bbox_to_anchor=(1.1, 0.95),
        )

        time_values = {k: vs[0] for (k, vs) in times.items()}
        time_legend = figure.legend(
            time_values.values(),
            time_values.keys(),
            loc="upper right",
            bbox_to_anchor=(1.1, 0.85),
        )

        figure.add_artist(commit_legend)

    plt.tight_layout()

    if args.save_to is not None:
        print("Writing image to {}".format(args.save_to))
        plt.savefig(args.save_to, bbox_inches="tight")
    else:
        print("Displaying")
        plt.show()
