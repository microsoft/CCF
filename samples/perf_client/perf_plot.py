import argparse
import json
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from collections import defaultdict


def compute_linear_regression(x, y):
    model = LinearRegression().fit(x, y)
    return model.coef_[0]


def plot_timeseries(sent, received, ax, title):
    commit_lines = defaultdict(list)
    tx_time_lines = defaultdict(list)

    # Add cumcount column to deal with duplicate idxs
    sent = sent.assign(cumcount=sent.groupby("idx").cumcount())
    received = received.assign(cumcount=received.groupby("idx").cumcount())

    # Join DataFrames
    test_df = sent.merge(received, on=["idx", "cumcount"]).drop("cumcount", 1)
    test_df["request_time"] = test_df["recv_sec"] - test_df["sent_sec"]

    # Print performance global throughput in dedicated box
    # successful_global_commit_rate = compute_linear_regression(
    #     test_df["sent_sec"].values.reshape((-1, 1)), test_df["global_commit"]
    # )
    # global_rate_string = f"""global commit throughput (successful txs only):
    #                         {int(successful_global_commit_rate)} tx/s"""
    # props = dict(boxstyle="round", facecolor="wheat", alpha=0.5)
    # ax.text(
    #     0.5,
    #     0.20,
    #     global_rate_string,
    #     transform=ax.transAxes,
    #     fontsize=12,
    #     verticalalignment="top",
    #     bbox=props,
    # )

    # Remove error values
    test_df["commit"].replace(0, np.nan, inplace=True)
    test_df["global_commit"].replace(0, np.nan, inplace=True)

    # Set axis properties
    ax.title.set_text(title)
    ax.set_xlim(left=0, auto=True)

    # Plot second axis of commit versions
    # (Plotted first so it gets consistent colors)
    commit_ax = ax.twinx()
    for column in ("commit", "global_commit"):
        commit_lines[column] += commit_ax.plot(
            test_df["sent_sec"], test_df[column], label=column
        )
    commit_ax.set_ylim(bottom=0, auto=True)

    # Based on label_outer, but keeping label on last col rather than first
    if commit_ax.is_last_col():
        commit_ax.set_ylabel("Version")
    else:
        commit_ax.set_yticks([])

    # Plot transaction times, by method
    for method, grp in test_df.groupby("method"):
        tx_time_lines[method] += ax.plot(
            grp["sent_sec"], grp["request_time"], ".", label=method
        )
    ax.set_ylim(bottom=0, auto=True)
    ax.set(xlabel="Sent time (s)")

    # Based on label_outer, but keeping x labels for all
    if commit_ax.is_first_col():
        ax.set_ylabel("Response delay (s)")

    ax.grid(axis="y")

    return (commit_lines, tx_time_lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--title", help="Title for plot", default="")
    parser.add_argument(
        "--width", help="Total width of plotted figure", default=12, type=int
    )
    parser.add_argument(
        "--height", help="Total height of plotted figure", default=8, type=int
    )
    parser.add_argument("--save-to", help="Path to saved resulting plot", type=str)

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

    if args.command == "single":
        figure = plt.figure(figsize=figsize)
        sent_df = pd.read_csv(args.sent)
        received_df = pd.read_csv(args.received)

        ax = plt.axes()
        plot_timeseries(sent_df, received_df, ax, args.title)
        #plt.tight_layout()

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
                cmd = variant["command"]
                if isinstance(cmd, list):
                    cmd = " ".join(cmd)
                print("  Executing:")
                print("   {}".format(cmd))
                result = subprocess.run(cmd, shell=True, capture_output=True)
                print("  Done, plotting")

                # Load and plotresults
                sent_df = pd.read_csv(variant["sent"])
                received_df = pd.read_csv(variant["received"])
                plot_timeseries(sent_df, received_df, ax, variant["subtitle"])

            # Hide empty axes after short rows
            for x in range(x + 1, row_len):
                axes[y, x].axis("off")

    if args.save_to is not None:
        print("Writing image to {}".format(args.save_to))
        plt.savefig(args.save_to)
    else:
        print("Displaying")
        plt.show()
