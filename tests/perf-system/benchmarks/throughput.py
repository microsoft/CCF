import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

FANCY_PATTERNS = ["xx", "..", "///"]
BORING_COLORS = ["lightgrey", "grey", "darkgrey"]


def plot_simple_graph(
    labels,
    ydata,
    xlabel,
    ylabel,
    filename_full,
):
    plt.figure()
    plt.plot(
        labels,
        ydata,
        label=labels,
    )
    plt.ylabel(ylabel)
    plt.xlabel(xlabel)
    plt.savefig(filename_full)
    plt.close()


def plot_simple_bar_chart(
    labels,
    data,
    xlabel,
    ylabel,
    filename_full,
):
    plt.figure()
    plt.bar(
        labels,
        data,
        edgecolor="black",
        label=labels,
    )
    plt.ylabel(ylabel)
    plt.xlabel(xlabel)
    plt.savefig(filename_full)
    plt.close()


def plot_throughput_comparision(
    throughputs_reqs,
    read_labels,
    results_directory: Path,
):
    throughputs_kreqs = [throughput_reqs / 1000 for throughput_reqs in throughputs_reqs]
    plot_simple_bar_chart(
        read_labels,
        throughputs_kreqs,
        "Read percentage",
        "Throughput (kreq/s)",
        results_directory / "throughput_comparison.pdf",
    )


def plot_throughput_comparision_line(
    throughputs_reqs,
    analysis_labels,
    results_directory: Path,
    xlabel="Read percentage",
    ylabel="Throughput (kreq/s)",
    filename="throughput_comparison.pdf",
):
    throughputs_kreqs = [throughput_reqs / 1000 for throughput_reqs in throughputs_reqs]
    plot_simple_graph(
        analysis_labels,
        throughputs_kreqs,
        xlabel,
        ylabel,
        results_directory / filename,
    )


def plot_throughput_comparision_sets(
    throughputs_reqs,  # 2 or 3 datasets to compare
    dataset_labels,  # labels for the datasets
    analysis_labels,
    results_directory: Path,
    xlabel="Read percentage",
    ylabel="Throughput (kreq/s)",
    legend_title=None,
    filename="throughput_comparison_sets.pdf",
    bar_labels=False,
    log_scale=False,
):
    bar_width = 0.3
    label_locations = np.arange(len(analysis_labels))
    if len(throughputs_reqs) == 2:
        xbars = [label_locations - bar_width / 2, label_locations + bar_width / 2]
    else:
        xbars = [
            label_locations - bar_width,
            label_locations,
            label_locations + bar_width,
        ]

    plt.figure()
    for i in range(len(throughputs_reqs)):
        heights = [throughput_reqs / 1000 for throughput_reqs in throughputs_reqs[i]]
        plt.bar(
            xbars[i],
            heights,
            bar_width,
            edgecolor="black",
            label=dataset_labels[i],
            color=BORING_COLORS[i],
            hatch=FANCY_PATTERNS[i],
        )
        if bar_labels:
            for b in range(len(xbars[i])):
                plt.text(
                    xbars[i][b],
                    heights[b],
                    str(int(heights[b])),
                    horizontalalignment="center",
                    verticalalignment="bottom",
                )

    plt.ylabel(ylabel)
    if log_scale:
        plt.yscale("log")
    if bar_labels:
        y_min, y_max = plt.ylim()
        plt.ylim(y_min, y_max * 1.1)
    plt.xlabel(xlabel)
    plt.xticks(label_locations, analysis_labels)
    plt.legend(title=legend_title)
    plt.savefig(results_directory / filename)
    plt.close()
