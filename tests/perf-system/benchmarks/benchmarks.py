# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import json
import os
import random
import signal
import string
import subprocess
import sys
import time
from pathlib import Path
from loguru import logger as LOG

import paramiko
import pysftp


def clean_up_cchost(nodes):
    LOG.info("Cleaning up previous CCF processes")
    for node in set([address.split(":")[0] for address in nodes]):
        with paramiko.SSHClient() as client:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(node)
            LOG.info(f"Killing cchost on {node}")
            client.exec_command("killall cchost")


def fetch_remote_dir(ip_address, remote_dir: Path, local_dir: Path):
    cnopts = pysftp.CnOpts()
    cnopts.hostkeys = None
    with pysftp.Connection(host="localhost", cnopts=cnopts) as sftp:
        LOG.info(f"Copying {remote_dir} from {ip_address} to {local_dir}")
        sftp.get_r(str(remote_dir), str(local_dir))


def create_experiment_dir(
    test_dir,
    enclave_type,
    ccf_app,
    number_of_piccolos,
    leader_only,
    write_percentages,
    ccf_node_ips,
):
    LOG.info("Creating experiment directories")
    number_of_ccf_nodes = len(ccf_node_ips)
    experiment_dir = (
        test_dir
        / f"{enclave_type}_{ccf_app}_{number_of_ccf_nodes}n_{number_of_piccolos}p_{leader_only}"
    )
    LOG.info(f"Experiment results will be saved to {experiment_dir}")
    os.mkdir(experiment_dir)
    for write_percentage in write_percentages:
        os.mkdir(experiment_dir / f"writes{write_percentage}%")
        for piccolo_number in range(number_of_piccolos):
            os.mkdir(
                experiment_dir
                / f"writes{write_percentage}%"
                / f"piccolo{piccolo_number}"
            )
    return experiment_dir


def get_user_cert_args(ccf_dir):
    cert_dir = ccf_dir / "workspace" / "sandbox_common"
    return [
        "--cacert",
        cert_dir / "service_cert.pem",
        "--cert",
        cert_dir / "user0_cert.pem",
        "--key",
        cert_dir / "user0_privk.pem",
    ]


def setup_experiment(
    ccf_app,
    enclave_type,
    experiment_dir,
    ccf_node_ips,
    number_of_piccolos,
    write_percentages,
    number_of_requests,
    snapshot_tx_interval,
    sig_tx_interval,
    sig_ms_interval,
    worker_threads,
    ccf_dir,
    logging_message_length,
    expected_ccf_version,
    user_cert_args,
):
    number_of_ccf_nodes = len(ccf_node_ips)
    LOG.info(f"Starting a CCF service with {number_of_ccf_nodes} nodes")

    sandbox_n_args = [
        "../tests/sandbox/sandbox.sh",
        "--snapshot-tx-interval",
        str(snapshot_tx_interval),
        "--sig-tx-interval",
        str(sig_tx_interval),
        "--sig-ms-interval",
        str(sig_ms_interval),
        "--worker-threads",
        str(worker_threads),
        "--workspace",
        ccf_dir / "workspace",
    ]

    for address in ccf_node_ips:
        sandbox_n_args.append("-n")
        sandbox_n_args.append("ssh://" + address)

    if ccf_app == "js_logging":
        sandbox_n_args += ["--js-app-bundle", "../samples/apps/logging/js/"]
    else:
        sandbox_n_args += ["-p", "samples/apps/logging/liblogging"]

    if enclave_type == "sgx":
        sandbox_n_args += ["-t", "sgx", "-e", "release"]

    if enclave_type == "sgx":
        ccf_build_dir = ccf_dir / "build-sgx"
    else:
        ccf_build_dir = ccf_dir / "build-virtual"

    ccf_server_process = subprocess.Popen(sandbox_n_args, cwd=ccf_build_dir)
    time.sleep(120)

    LOG.info("Preparing workloads using piccolo generator")

    # TOOD: remove this hack
    generator_dir = ccf_dir / "tests" / "perf-system" / "generator"
    sys.path.insert(0, str(generator_dir))
    import generator

    for workload_number, write_percentage in enumerate(write_percentages):
        LOG.info(
            f"Generating workload {workload_number} with {write_percentage}% writes"
        )

        for piccolo_number in range(number_of_piccolos):
            writes = random.sample(
                range(number_of_requests),
                int(number_of_requests * write_percentage / 100),
            )
            LOG.info(
                f"In workload {workload_number} piccolo {piccolo_number} will write {len(writes)} messages and read {number_of_requests - len(writes)} messages"
            )
            workload = generator.Messages()
            for i in range(number_of_requests):
                if i in writes:
                    body = {
                        "id": i,
                        "msg": str(
                            "".join(
                                random.choices(
                                    string.ascii_letters, k=logging_message_length
                                )
                            )
                        ),
                    }
                    workload.append(
                        "/log/public",
                        "POST",
                        body=json.dumps(body),
                    )
                else:
                    workload.append(
                        f"/log/public?id={i}",
                        "GET",
                    )
            workload.to_parquet_file(
                experiment_dir
                / f"writes{write_percentage}%"
                / f"piccolo{piccolo_number}"
                / "input.parquet"
            )
    LOG.info("Workloads generated")

    LOG.info("Checking CCF service is live & new before starting experiment")
    addresses_of_ccf_nodes = [f"https://{i}" for i in ccf_node_ips]
    for id, address in enumerate(addresses_of_ccf_nodes):
        LOG.info(f"Checking node {id} at {address} is ready")

        if expected_ccf_version is not None:
            LOG.info("Checking CCF version")
            version_process = subprocess.run(
                [
                    "curl",
                    address + "/node/version",
                    *user_cert_args,
                ],
                capture_output=True,
            )
            ccf_version = json.loads(version_process.stdout.decode())["ccf_version"]
            assert (
                ccf_version == "expected_ccf_version"
            ), f"CCF version is {ccf_version}"

        LOG.info("Checking commit tx term")
        commit_tx_process = subprocess.run(
            [
                "curl",
                address + "/commit",
                *user_cert_args,
            ],
            capture_output=True,
        )
        commit_tx = json.loads(commit_tx_process.stdout.decode())["transaction_id"]
        assert int(commit_tx.split(".")[0]) == 2, f"Commit tx is {commit_tx}"

        LOG.info("Checking message count is zero before experiment")
        count_process = subprocess.run(
            [
                "curl",
                address + "/log/public/count",
                *user_cert_args,
            ],
            capture_output=True,
        )
        message_count_before = int(count_process.stdout.decode())
        assert (
            message_count_before == 0
        ), f"Message count before test is {message_count_before}"

        LOG.info("Checking consensus state")
        check_consensus_process = subprocess.run(
            [
                "curl",
                address + "/node/consensus",
                *user_cert_args,
            ],
            capture_output=True,
        )

        consensus_state = json.loads(check_consensus_process.stdout.decode())
        node_leadership_state = consensus_state["details"]["leadership_state"]
        if id == 0:
            assert node_leadership_state == "Leader", f"Node {id} is not leader"
        else:
            assert node_leadership_state == "Follower", f"Node {id} is not follower"

        LOG.info(f"Finished checking node {id} at {address} is ready")
        return ccf_server_process


def shutdown_experiment(
    ccf_server_process,
    ccf_node_ips,
    user_cert_args,
    number_of_requests,
    ccf_node_for_piccolo,
    write_percentages,
    experiment_dir,
    ccf_dir,
):
    LOG.info("Confirming CCF service state after experiments")

    addresses_of_ccf_nodes = [f"https://{i}" for i in ccf_node_ips]
    for id, address in enumerate(addresses_of_ccf_nodes):
        LOG.info(f"Checking node {id} at {address}")

        LOG.info("Checking message count")
        message_count_process = subprocess.run(
            [
                "curl",
                address + "/log/public/count",
                *user_cert_args,
            ],
            capture_output=True,
        )
        message_count_after = int(message_count_process.stdout)
        assert (
            number_of_requests == message_count_after
        ), f"Expected {number_of_requests} messages, got {message_count_after}"

        LOG.info("Checking API metrics")

        requests_per_workload = number_of_requests * ccf_node_for_piccolo.count(
            ccf_node_ips[id]
        )
        total_requests = requests_per_workload * len(write_percentages)
        total_posts = 0
        [
            total_posts := total_posts + requests_per_workload * w / 100
            for w in write_percentages
        ]
        total_gets = total_requests - total_posts
        LOG.info(
            f"Expecting {total_requests} requests, comprised of {total_posts} posts and {total_gets} gets"
        )

        metrics_process = subprocess.run(
            [
                "curl",
                address + "/api/metrics",
                *user_cert_args,
            ],
            capture_output=True,
        )
        metrics = json.loads(metrics_process.stdout.decode())["metrics"]

        for metric in metrics:
            assert (
                metric["errors"] == 0
            ), f"Expected 0 errors, got {metric['errors']}. Full metrics: {metrics}"
            assert (
                metric["failures"] == 0
            ), f"Expected 0 failures, got {metric['failures']}. Full metrics: {metrics}"
            assert (
                metric["retries"] == 0
            ), f"Expected 0 retries, got {metric['retries']}. Full metrics: {metrics}"

            # todo: handle case that metric is missing & handle forwarding better
            if metric["path"] == "log/public":
                if metric["method"] == "POST":
                    assert (
                        metric["calls"] >= total_posts
                    ), f"Expected {total_posts} posts, got {metric['calls']}. Full metrics: {metrics}"
                elif metric["method"] == "GET":
                    assert (
                        metric["calls"] >= total_gets
                    ), f"Expected {total_gets} gets, got {metric['calls']}. Full metrics: {metrics}"
                else:
                    assert (
                        False
                    ), f"Unexpected method {metric['method']}. Full metrics: {metrics}"
            else:
                assert metric["path"] in [
                    "api/metrics",
                    "commit",
                    "log/public/count",
                ], f"Unexpected path {metric['path']}"

        LOG.info("Checking node metrics")
        node_metrics_process = subprocess.run(
            [
                "curl",
                address + "/node/metrics",
                *user_cert_args,
            ],
            capture_output=True,
        )
        node_metrics = json.loads(node_metrics_process.stdout.decode())["sessions"]
        actual_peak_sessions = int(node_metrics["peak"])
        expected_peak_sessions = max(ccf_node_for_piccolo.count(ccf_node_ips[id]), 1)
        assert (
            actual_peak_sessions == expected_peak_sessions
        ), f"Expected {expected_peak_sessions} peak sessions, got {actual_peak_sessions}"

        LOG.info("Checking commit tx term")
        commit_tx_process = subprocess.run(
            [
                "curl",
                address + "/commit",
                *user_cert_args,
            ],
            capture_output=True,
        )
        commit_tx = json.loads(commit_tx_process.stdout.decode())["transaction_id"]
        assert int(commit_tx.split(".")[0]) == 2, f"Commit tx is {commit_tx}"

        node_ip = ccf_node_ips[id].split(":")[0]
        LOG.info(f"Fetching workspace from node {id} at {address}")
        sandbox_dir = experiment_dir / "workspaces" / f"node_{id}"
        os.makedirs(sandbox_dir)
        fetch_remote_dir(node_ip, ccf_dir / "workspace" / f"sandbox_{id}", sandbox_dir)
        LOG.info("Fetching completed")

    LOG.info("Shutting down CCF service")
    ccf_server_process.send_signal(signal.SIGINT)
    time.sleep(5)
    clean_up_cchost(ccf_node_ips)

    LOG.info(f"Experiment complete, results in {experiment_dir}")


def run_logging_experiments(
    ccf_app="cpp_logging",  # js_logging or cpp_logging
    enclave_type="sgx",  # sgx or virtual
    test_dir=Path("."),  # where run_experiment will create its results directory
    ccf_node_ips=["127.0.0.1:8000"],  # node addresses, can be local
    number_of_concurrent_requests=1000,  # number of pipelined requests per piccolo
    number_of_piccolos=1,
    write_percentages=[
        100,
        50,
        0,
    ],  # percentage of write requests, should always start with 100
    number_of_requests=100000,  # requests per piccolo
    snapshot_tx_interval=10000,
    sig_tx_interval=5000,
    sig_ms_interval=1000,
    worker_threads=0,
    ccf_dir=Path(
        "/home", "azureuser", "CCF"
    ),  # Assumes ccf is compiled in build-sgx or build-virtual
    leader_only=True,  # all piccolos send requests to leader or round robin split
    logging_message_length=20,
    expected_ccf_version=None,  # set to ccf version to check version on nodes before experiment
) -> Path:
    clean_up_cchost(ccf_node_ips)

    experiment_dir = create_experiment_dir(
        test_dir,
        enclave_type,
        ccf_app,
        number_of_piccolos,
        leader_only,
        write_percentages,
        ccf_node_ips,
    )

    user_cert_args = get_user_cert_args(ccf_dir)

    ccf_server_process = setup_experiment(
        ccf_app,
        enclave_type,
        experiment_dir,
        ccf_node_ips,
        number_of_piccolos,
        write_percentages,
        number_of_requests,
        snapshot_tx_interval,
        sig_tx_interval,
        sig_ms_interval,
        worker_threads,
        ccf_dir,
        logging_message_length,
        expected_ccf_version,
        user_cert_args,
    )

    if leader_only:
        ccf_node_for_piccolo = [ccf_node_ips[0] for i in range(number_of_piccolos)]
    else:
        ccf_node_for_piccolo = [
            ccf_node_ips[i % len(ccf_node_ips)] for i in range(number_of_piccolos)
        ]

    [
        LOG.info(f"Piccolo {id} assigned to {address}")
        for id, address in enumerate(ccf_node_for_piccolo)
    ]

    def run_submitter(workload_name):
        LOG.info(f"Starting experiment {workload_name}")
        piccolo_processes = []
        for piccolo_number in range(number_of_piccolos):
            experiment_dir_full = (
                experiment_dir / workload_name / f"piccolo{piccolo_number}"
            )
            piccolo_processes.append(
                subprocess.Popen(
                    [
                        ccf_dir / "build" / "submit",
                        *user_cert_args,
                        "--server-address",
                        ccf_node_for_piccolo[piccolo_number],
                        "--send-filepath",
                        experiment_dir_full / "send.parquet",
                        "--response-filepath",
                        experiment_dir_full / "responses.parquet",
                        "--generator-filepath",
                        experiment_dir_full / "input.parquet",
                        "--max-writes-ahead",
                        str(number_of_concurrent_requests),
                    ]
                )
            )
        [process.wait() for process in piccolo_processes]
        LOG.info(f"Finished experiment {workload_name}")
        time.sleep(5)

    for write_percentage in write_percentages:
        run_submitter(f"writes{write_percentage}%")

    shutdown_experiment(
        ccf_server_process,
        ccf_node_ips,
        user_cert_args,
        number_of_requests,
        ccf_node_for_piccolo,
        write_percentages,
        experiment_dir,
        ccf_dir,
    )

    return experiment_dir
