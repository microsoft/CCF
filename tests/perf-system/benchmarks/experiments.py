# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import datetime
import os
from pathlib import Path

import benchmarks
import throughput
import output


def run_experiment_and_analyze_results(**kwargs):
    output.analyze_results(benchmarks.run_logging_experiments(**kwargs))


def calibration_test(test_servers, test_directory):
    run_experiment_and_analyze_results(
        test_dir=test_directory,
        write_percentages=[100],
        number_of_concurrent_requests=1,
        ccf_node_ips=test_servers[:3],
        number_of_requests=1000,
    )


def simple_test(test_servers, test_directory):
    write_percentages = range(100, -1, -10)
    run_experiment_and_analyze_results(
        test_dir=test_directory,
        write_percentages=write_percentages,
        number_of_concurrent_requests=1000,
        ccf_node_ips=test_servers[:3],
        number_of_piccolos=4,
        leader_only=False,
    )


def load_balancing_test(test_servers, test_directory):
    for leader_only in [True, False]:
        run_experiment_and_analyze_results(
            test_dir=test_directory,
            write_percentages=[100, 0],
            number_of_concurrent_requests=1000,
            ccf_node_ips=test_servers[:5],
            number_of_piccolos=10,
            leader_only=leader_only,
        )


def sigs_snapshots_latency_test(test_servers, test_directory):
    run_experiment_and_analyze_results(
        test_dir=test_directory,
        write_percentages=[100, 50, 0],
        number_of_concurrent_requests=1,
        ccf_node_ips=test_servers[:1],
        number_of_requests=2000,
        sig_tx_interval=100,
        snapshot_tx_interval=250,
        number_of_piccolos=1,
    )


def mode_app_table_test(test_servers, test_directory):
    apps = ["js_logging", "cpp_logging"]
    modes = ["virtual", "sgx"]
    throughputs = {}
    for app in apps:
        throughputs[app] = {}
        for mode in modes:
            experiment_dir = benchmarks.run_logging_experiments(
                app,
                mode,
                test_directory,
                test_servers[:3],
                write_percentages=[100, 0],
                number_of_piccolos=4,
            )
            throughputs[app][mode] = (
                output.analyze_results(experiment_dir)[0][0].throughput,
                output.analyze_results(experiment_dir)[1][0].throughput,
            )
    for app in apps:
        for mode in modes:
            print(app, mode, throughputs[app][mode])


def many_piccolos_test(test_servers, test_directory):
    numbers_of_piccolos = [1, 2, 3, 4, 5, 6]
    write_percentages = [100]
    throughputs = []
    for number_of_piccolos in numbers_of_piccolos:
        experiment_dir = benchmarks.run_logging_experiments(
            "cpp_logging",
            "sgx",
            test_directory,
            write_percentages=write_percentages,
            number_of_concurrent_requests=1000,
            ccf_node_ips=test_servers[:3],
            number_of_piccolos=number_of_piccolos,
            leader_only=True,
        )
        analyzers = output.analyze_results(experiment_dir)
        throughputs.append(output.get_throughputs(analyzers)[0])
    throughput.plot_throughput_comparision_line(
        throughputs, numbers_of_piccolos, test_directory, xlabel="clients"
    )


def scale_test(test_servers, test_directory):
    analyzers = []
    sets_of_nodes = [1, 3, 5]
    write_percentages = range(100, -1, -10)

    for number_of_ccf_nodes in sets_of_nodes:
        experiment_dir = benchmarks.run_logging_experiments(
            "cpp_logging",
            "sgx",
            test_directory,
            ccf_node_ips=test_servers[:number_of_ccf_nodes],
            worker_threads=0,
            number_of_piccolos=8,
            write_percentages=write_percentages,
            leader_only=False,
        )
        analyzers.append(output.analyze_results(experiment_dir))
    throughputs = [output.get_throughputs(analysis_list) for analysis_list in analyzers]
    read_labels = [f"{100 - w}%" for w in write_percentages]
    throughput.plot_throughput_comparision_sets(
        throughputs,
        [str(i) for i in sets_of_nodes],
        read_labels,
        test_directory,
        legend_title="# of Nodes",
    )
    throughput.plot_throughput_comparision_sets(
        throughputs,
        [str(i) for i in sets_of_nodes],
        read_labels,
        test_directory,
        legend_title="# of Nodes",
        log_scale=True,
        bar_labels=True,
        filename="throughput_comparison_sets_log_scale.pdf",
    )


def all_tests(*args):
    calibration_test(*args)
    simple_test(*args)
    load_balancing_test(*args)
    sigs_snapshots_latency_test(*args)
    mode_app_table_test(*args)
    many_piccolos_test(*args)
    scale_test(*args)


def test_directory_name():
    return datetime.datetime.now().strftime("%y%m%d%H%M%S")


def create_test_directory():
    test_directory = Path("/datadrive1/test", test_directory_name())
    os.mkdir(test_directory)
    return test_directory
