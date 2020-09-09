# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import datetime
import json
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import os

# For consistency between plots we want a function from label (name) to colour.
# We could do this programatically from the hashes to handle general values, but
# this is sufficient and makes it simple to group similar messages with similar colours
LABELS_TO_COLOURS = {
    # Processed on Host
    "AdminMessage::log_msg": "dimgray",
    "AdminMessage::notification": "silver",
    "AdminMessage::work_stats": "gainsboro",
    "ccf::add_node": "lime",
    "ccf::node_outbound": "darkgreen",
    "consensus::ledger_append": "red",
    "consensus::ledger_get": "indianred",
    "consensus::ledger_commit": "maroon",
    "consensus::ledger_truncate": "rosybrown",
    "tls::tls_closed": "darkkhaki",
    "tls::tls_connect": "khaki",
    "tls::tls_outbound": "gold",
    "tls::tls_stop": "goldenrod",
    # Processed in enclave
    "AdminMessage::tick": "dimgray",
    "ccf::node_inbound": "darkgreen",
    "consensus::ledger_entry": "red",
    "tls::tls_close": "darkkhaki",
    "tls::tls_inbound": "gold",
    "tls::tls_start": "goldenrod",
    # Processed in both
    "OversizedMessage::fragment": "slategray",
}


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
    ax.legend(prop={"size": 8})

    path_without_ext, _ = os.path.splitext(args.load_file.name)
    output_path = f"{path_without_ext}_{key}.png"
    print(f"Saving plot to {output_path}")
    plt.savefig(output_path, bbox_inches="tight")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "load_file",
        type=argparse.FileType("r"),
        help="Path to load log file to be parsed",
    )

    args = parser.parse_args()

    lines = args.load_file.readlines()
    jsons = [json.loads(line) for line in lines]

    plot_stacked(jsons, "count")
    plot_stacked(jsons, "bytes")
