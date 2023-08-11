# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import datetime
import json
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import os
import polars as pl

# For consistency between plots we want a function from label (name) to colour.
# We could do this programatically from the hashes to handle general values, but
# this is sufficient and makes it simple to group similar messages with similar colours
LABELS_TO_COLOURS = {
    # Processed on Host
    "AdminMessage::log_msg": "dimgray",
    "AdminMessage::work_stats": "gainsboro",
    "ccf::add_node": "lime",
    "ccf::node_outbound": "lightgreen",
    "consensus::ledger_append": "red",
    "consensus::ledger_get_range": "indianred",
    "consensus::ledger_commit": "maroon",
    "consensus::ledger_truncate": "rosybrown",
    "consensus::ledger_init": "firebrick",
    "consensus::ledger_open": "darkred",
    "tls::tls_closed": "darkkhaki",
    "tls::tls_connect": "khaki",
    "tls::tls_outbound": "gold",
    "tls::tls_stop": "goldenrod",
    # Processed in enclave
    "AdminMessage::tick": "dimgray",
    "ccf::node_inbound": "darkgreen",
    "consensus::ledger_entry_range": "red",
    "tls::tls_close": "darkkhaki",
    "tls::tls_inbound": "lemonchiffon",
    "tls::tls_start": "goldenrod",
    # Processed in both
    "OversizedMessage::fragment": "slategray",
}

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


def plot_stacked(jsons, key):
    labels = []
    for j in jsons:
        for label in j["ringbuffer_messages"].keys():
            if label not in labels:
                labels.append(label)

    labels.sort()

    colours = []
    default_colour = "black"
    for i, label in enumerate(labels):
        try:
            colours.append(LABELS_TO_COLOURS[label])
        except KeyError:
            print(f"No colour for '{label}', defaulting to {default_colour}")
            colours.append(default_colour)

    xs = []
    ys = [[] for _ in range(len(labels))]
    for j in jsons:
        xs.append(j["end_time_ms"])
        messages = j["ringbuffer_messages"]
        for i, label in enumerate(labels):
            try:
                count = messages[label][key]
            except KeyError:
                count = 0
            ys[i].append(count)

    def ms_to_date_formatter(ms, _):
        s = ms / 1000.0
        return datetime.datetime.fromtimestamp(s).strftime("%H:%M:%S")

    _, ax = plt.subplots()
    plt.title(f"Ringbuffer messages - {key}")
    plt.ylabel(f"{key}")
    plt.ticklabel_format(useOffset=False)

    ax.xaxis.set_major_formatter(ms_to_date_formatter)
    ax.locator_params(axis="x", nbins=5)
    ax.xaxis.set_minor_locator(ticker.MultipleLocator(1000))

    if key == "bytes":
        ax.yaxis.set_major_formatter(num_to_bytes_formatter)

    ax.stackplot(xs, ys, colors=colours, labels=labels)
    ax.legend(prop={"size": 8}, loc="upper left")

    path_without_ext, _ = os.path.splitext(args.load_file.name)
    output_path = f"{path_without_ext}_{key}.png"
    print(f"Saving plot to {output_path}")
    plt.savefig(output_path, bbox_inches="tight")


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
        .top_k(4, by="count")
    )["msg"]
    other_msgs = set(msg_types) - set(top_msgs)
    return top_msgs, other_msgs


def parse_load(line):
    j = json.loads(line.split("|")[1])
    counts = {
        "startTime": datetime.datetime.fromtimestamp(j["start_time_ms"] / 1000),
        "endTime": datetime.datetime.fromtimestamp(j["end_time_ms"] / 1000),
    }
    sizes = counts.copy()
    # Note: Purely working with message counts for now, ignoring bytes
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

    args = parser.parse_args()

    host_counts = []
    host_sizes = []
    enclave_counts = []
    enclave_sizes = []
    ENCLAVE_FIND = "load_monitor.h:91"
    HOST_FIND = "load_monitor.h:84"
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
