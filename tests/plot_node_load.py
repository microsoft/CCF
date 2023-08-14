# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import datetime
import json
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import os
import polars as pl

_AVAIL_COLOURS = [
    "#1f77b4",
    "#ff7f0e",
    "#2ca02c",
    "#d62728",
    "#9467bd",
    "#8c564b",
    "#e377c2",
    "#7f7f7f",
    "#bcbd22",
    "#17becf",
    "lemonchiffon",
    "slategray",
    "khaki",
    "goldenrod",
]
COLOURS = {}


def update_colour_mapping(labels):
    colours = []
    for label in labels:
        if label not in COLOURS:
            c = _AVAIL_COLOURS.pop(0)
            COLOURS[label] = c
            colours.append(c)
        else:
            colours.append(COLOURS[label])

    return colours


def num_to_bytes_formatter(n, _):
    suffixes = ("B", "KB", "MB", "GB")
    i = 0
    while n >= 1024 and i < len(suffixes) - 1:
        n /= 1024.0
        i += 1
    return f"{n:,.2f} {suffixes[i]}"


def stack_it(ax, df, y_label, y_is_bytes=False):
    top, other = get_top(df)
    df = df.with_columns(
        other=sum(df.select(other).fill_null(0)),
    )
    labels = [*top, "other"]
    colours = update_colour_mapping(labels)
    ax.stackplot(
        df["startTime"],
        *(df[col] for col in top),
        df["other"],
        labels=[*top, "other"],
        colors=colours,
    )

    ax.set_ylabel(y_label)
    if y_is_bytes:
        ax.yaxis.set_major_formatter(num_to_bytes_formatter)


def get_top(df):
    msg_types = [col.name for col in df if col.dtype is pl.Int64]
    top_msgs = (
        df.select(msg_types)
        .sum()
        .transpose(include_header=True, header_name="msg", column_names=["count"])
        .top_k(args.k, by="count")
    )["msg"]
    other_msgs = set(msg_types) - set(top_msgs)
    return top_msgs, other_msgs


def parse_load(line):
    j = json.loads(line.split("|", maxsplit=1)[1].split(":", maxsplit=1)[1])
    counts = {
        "startTime": datetime.datetime.fromtimestamp(j["start_time_ms"] / 1000),
        "endTime": datetime.datetime.fromtimestamp(j["end_time_ms"] / 1000),
    }
    sizes = counts.copy()
    for k, v in j["ringbuffer_messages"].items():
        counts[k] = v["count"]
        sizes[k] = v["bytes"]
    return counts, sizes


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "load_file",
        type=argparse.FileType("r"),
        help="Path to node output file to be parsed",
    )
    parser.add_argument("--k", type=int, default=4, help="How many values to keep")

    args = parser.parse_args()

    host_counts = []
    host_sizes = []
    enclave_counts = []
    enclave_sizes = []
    ENCLAVE_FIND = "Enclave load:"
    HOST_FIND = "Host load:"
    for line in args.load_file.readlines():
        if ENCLAVE_FIND in line:
            c, s = parse_load(line)
            enclave_counts.append(c)
            enclave_sizes.append(s)
        elif HOST_FIND in line:
            c, s = parse_load(line)
            host_counts.append(c)
            host_sizes.append(s)

    _, axs = plt.subplots(4, sharex="all", figsize=(6, 15))

    df = pl.DataFrame(host_counts)
    stack_it(axs[0], df, "Host counts")

    df = pl.DataFrame(host_sizes)
    stack_it(axs[1], df, "Host bytes", y_is_bytes=True)

    df = pl.DataFrame(enclave_counts)
    stack_it(axs[2], df, "Enclave counts")

    df = pl.DataFrame(enclave_sizes)
    stack_it(axs[3], df, "Enclave bytes", y_is_bytes=True)

    legend = {}
    for ax in axs:
        handles, labels = ax.get_legend_handles_labels()
        for h, l in zip(handles, labels):
            if l not in legend:
                legend[l] = h

    plt.figlegend(handles=legend.values(), labels=legend.keys())

    path_without_ext, _ = os.path.splitext(args.load_file.name)
    output_path = f"{path_without_ext}.png"
    print(f"Saving plot to {output_path}")
    plt.savefig(output_path, bbox_inches="tight")
