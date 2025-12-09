# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.e2e_args
import infra.remote_client
import infra.jwt_issuer
from loguru import logger as LOG
import time
import http
import hashlib
from piccolo import generator
import polars as pl
from typing import Dict, List
import random
import string
import json
import shutil
import datetime
import ccf.ledger
import plotext as plt
import infra.bencher


def configure_remote_client(args, client_id, client_host, common_dir):
    client_host = infra.net.expand_localhost()

    try:
        remote_client = infra.remote_client.CCFRemoteCmd(
            f"client_{client_id}",
            client_host,
            args.client,
            common_dir,
            args.workspace,
            [
                os.path.join(common_dir, "user0_cert.pem"),
                os.path.join(common_dir, "user0_privk.pem"),
                os.path.join(common_dir, "service_cert.pem"),
            ],
        )
        remote_client.setup()
        return remote_client
    except Exception:
        LOG.exception("Failed to start client {}".format(client_host))
        raise


def write_to_key_space(
    key_space: List[str],
    iterations: int,
    msgs: generator.Messages,
    additional_headers: Dict[str, str],
):
    """
    Write fixed-size messages to a range of keys, this is the usual logging workload
    CCF has been running in various forms since early on. Each transaction produces a
    ledger entry and causes replication to backups.
    """
    LOG.info(f"Workload: {iterations} writes to a range of {len(key_space)} keys")
    indices = list(range(iterations))
    random.shuffle(indices)
    for index in indices:
        key = key_space[index % len(key_space)]
        msgs.append(
            f"/records/{key}",
            "PUT",
            additional_headers=additional_headers,
            body=f"{hashlib.sha256(key.encode()).hexdigest()}",
            content_type="text/plain",
        )


def read_from_key_space(
    key_space: List[str],
    iterations: int,
    msgs: generator.Messages,
    additional_headers: Dict[str, str],
):
    LOG.info(f"Workload: {iterations} reads from a range of {len(key_space)} keys")
    indices = list(range(iterations))
    random.shuffle(indices)
    for index in indices:
        key = key_space[index % len(key_space)]
        msgs.append(
            f"/records/{key}",
            "GET",
            additional_headers=additional_headers,
            content_type="text/plain",
        )


def append_to_msgs(definition, key_space, iterations, msgs, additional_headers):
    if definition == "write":
        return write_to_key_space(key_space, iterations, msgs, additional_headers)
    elif definition == "read":
        return read_from_key_space(key_space, iterations, msgs, additional_headers)
    elif definition.startswith("rwmix:"):
        _, ratio = definition.split(":")
        assert iterations % 1000 == 0
        return RWMix(1000, float(ratio))(
            key_space, iterations, msgs, additional_headers
        )
    else:
        raise NotImplementedError(f"No generator for {definition}")


class RWMix:
    """
    Similar to write_to_random_keys, but with the additions of reads back from the keys.
    Reads do not produce ledger entries, but because they are interleaved with writes on
    the same session, they are not offloaded to backups.

    The first pass always writes to all the keys, to make sure they are initialised.
    """

    def __init__(self, batch_size: int, write_fraction: float, msg_len=20):
        self.batch_size = batch_size
        assert write_fraction >= 0 and write_fraction <= 1
        self.write_fraction = write_fraction
        self.msg_len = msg_len

    def __call__(
        self,
        key_space: List[str],
        repetitions: int,
        msgs: generator.Messages,
        additional_headers: Dict[str, str],
    ):
        assert repetitions % self.batch_size == 0
        LOG.info(
            f"Workload: {repetitions} operations to a range of {self.batch_size} keys, with a write fraction of {self.write_fraction}"
        )
        for batch in range(repetitions // self.batch_size):
            # Randomly select a subset of the batch to be writes
            writes = set(
                random.sample(
                    range(self.batch_size), int(self.batch_size * self.write_fraction)
                )
            )
            # Randomly shuffle the keys to be written/read
            indices = list(range(self.batch_size))
            random.shuffle(indices)
            for index in indices:
                key = key_space[index % len(key_space)]
                # The first batch always writes to all keys, to make sure they are initialised
                if (batch == 0) or (key in writes):
                    msgs.append(
                        f"/records/{key}",
                        "PUT",
                        additional_headers=additional_headers,
                        body="".join(
                            random.choices(string.ascii_letters, k=self.msg_len)
                        ),
                        content_type="text/plain",
                    )
                else:
                    msgs.append(
                        f"/records/{key}",
                        "GET",
                        additional_headers=additional_headers,
                    )


def create_and_fill_key_space(size: int, primary: infra.node.Node) -> List[str]:
    LOG.info(f"Creating and filling key space of size {size}")
    space = [f"{i}" for i in range(size)]
    mapping = {key: f"{hashlib.sha256(key.encode()).hexdigest()}" for key in space}
    with primary.client("user0") as c:
        r = c.post("/records", mapping)
        assert r.status_code == http.HTTPStatus.NO_CONTENT, r
        # Quick sanity check
        for j in [0, -1]:
            r = c.get(f"/records/{space[j]}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.text() == mapping[space[j]], r
    LOG.info("Key space created and filled")
    return space


def replace_primary(network, host, old_primary, snapshots_dir, statistics):
    LOG.info(f"Set up new node: {host}")
    node = network.create_node(host)
    statistics["new_node_join_start_time"] = datetime.datetime.now().isoformat()
    network.setup_join_node(
        node,
        args.package,
        args,
        target_node=network.nodes[1],
        timeout=10,
        copy_ledger=False,
        snapshots_dir=snapshots_dir,
        follow_redirect=False,
    )
    LOG.info(f"Shut down primary: {old_primary.local_node_id}")
    statistics["initial_primary_shutdown_time"] = datetime.datetime.now().isoformat()
    old_primary.stop()
    LOG.info(f"Start new node: {node.local_node_id}")
    network.run_join_node(node, wait_for_node_in_store=False)
    primary, _ = network.wait_for_new_primary(old_primary)
    statistics["new_primary_detected_time"] = datetime.datetime.now().isoformat()
    network.wait_for_node_in_store(
        primary,
        node.node_id,
        node_status=ccf.ledger.NodeStatus.PENDING,
        timeout=5,
    )
    LOG.info(f"Replace node {old_primary.local_node_id} with {node.local_node_id}")
    network.replace_stopped_node(old_primary, node, args, statistics=statistics)
    LOG.info(f"Done replacing node: {host}")


def run(args):
    hosts = args.nodes or infra.e2e_args.nodes(args, 1)

    if args.stop_primary_after_s:
        assert (
            len(hosts) > 1
        ), "Can only stop primary if there is at least one other node to fail over to"

    LOG.info("Starting nodes on {}".format(hosts))
    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        # Manipulate election timeouts to produce a deterministic successor to the primary
        # when it is stopped, allowing the submitters to be configured to fail over accordingly
        if args.stop_primary_after_s:
            for i in range(len(hosts)):
                if i != 1:
                    network.per_node_args_override[i] = {"election_timeout_ms": 15000}
        network.start_and_open(args)

        primary, backups = network.find_nodes()
        additional_headers = {}
        if args.use_jwt:
            jwt_issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
            jwt_issuer.register(network)
            jwt = jwt_issuer.issue_jwt()
            additional_headers["Authorization"] = f"Bearer {jwt}"

        key_space = create_and_fill_key_space(args.key_space_size, primary)

        clients = []
        client_idx = 0
        requests_file_paths = []
        for client_def in args.client_def:
            count, gen, iterations, target = client_def.split(",")
            # The round robin index deliberately starts at 1, so that backups/any are
            # loaded uniformly but the first instance slightly less so where possible. This
            # is useful when running a failover test, to avoid the new primary being targeted
            # by reads.
            rr_idx = 1
            for _ in range(int(count)):
                LOG.info(f"Generating {iterations} requests for client_{client_idx}")
                msgs = generator.Messages()
                append_to_msgs(
                    gen, key_space, int(iterations), msgs, additional_headers
                )
                path_to_requests_file = os.path.join(
                    network.common_dir, f"pi_client{client_idx}_requests.parquet"
                )
                LOG.info(f"Writing generated requests to {path_to_requests_file}")
                msgs.to_parquet_file(path_to_requests_file)
                requests_file_paths.append(path_to_requests_file)
                node = None
                if target == "primary":
                    node = primary
                elif target == "backup":
                    node = backups[rr_idx % len(backups)]
                    rr_idx += 1
                elif target == "any":
                    node = network.nodes[rr_idx % len(network.nodes)]
                    rr_idx += 1
                else:
                    raise NotImplementedError(f"Unknown target {target}")
                remote_client = configure_remote_client(
                    args, client_idx, "localhost", network.common_dir
                )
                cmd = [
                    args.client,
                    "--cert",
                    "user0_cert.pem",
                    "--key",
                    "user0_privk.pem",
                    "--cacert",
                    os.path.basename(network.cert_path),
                    f"--server-address={node.get_public_rpc_host()}:{node.get_public_rpc_port()}",
                    "--max-writes-ahead",
                    str(args.max_writes_ahead),
                    "--send-filepath",
                    "pi_requests.parquet",
                    "--response-filepath",
                    "pi_response.parquet",
                    "--generator-filepath",
                    os.path.abspath(path_to_requests_file),
                    "--pid-file-path",
                    "cmd.pid",
                ]
                # All clients talking to the primary are configured to fail over to the first backup,
                # which is the only node whose election timeout has not been raised, to guarantee its
                # election as the old primary becomes unavailable.
                if args.stop_primary_after_s and target == "primary":
                    cmd.append(
                        f"--failover-server-address={backups[0].get_public_rpc_host()}:{backups[0].get_public_rpc_port()}"
                    )
                remote_client.setcmd(cmd)
                remote_client.description = f"{gen} x {iterations} to {target} ({node.get_public_rpc_address()})"
                clients.append(remote_client)
                client_idx += 1

        if args.network_only:
            for remote_client in clients:
                LOG.info(f"Client can be run with: {remote_client.remote.get_cmd()}")
            while True:
                time.sleep(60)
        else:
            for remote_client in clients:
                remote_client.start()

            format_width = len(str(args.client_timeout_s)) + 3

            try:
                statistics = {}
                start_time = time.time()
                primary_has_stopped = False
                while True:
                    stop_waiting = True
                    for i, remote_client in enumerate(clients):
                        done = remote_client.check_done()
                        # all the clients need to be done
                        LOG.info(
                            f"Client {i} has {'completed' if done else 'not completed'} running ({time.time() - start_time:>{format_width}.2f}s / {args.client_timeout_s}s)"
                        )
                        stop_waiting = stop_waiting and done
                    if stop_waiting:
                        break
                    if time.time() > start_time + args.client_timeout_s:
                        raise TimeoutError(
                            f"Client still running after {args.client_timeout_s}s"
                        )
                    if (
                        args.stop_primary_after_s
                        and time.time() > start_time + args.stop_primary_after_s
                        and not primary_has_stopped
                    ):
                        committed_snapshots_dir = network.get_committed_snapshots(
                            primary, force_txs=False
                        )
                        snapshots = os.listdir(committed_snapshots_dir)
                        sorted_snapshots = sorted(
                            snapshots, key=lambda x: int(x.split("_")[1])
                        )
                        latest_snapshot = sorted_snapshots[-1]
                        latest_snapshot_dir = os.path.join(
                            network.common_dir, "snapshots_to_copy"
                        )
                        os.mkdir(latest_snapshot_dir)
                        shutil.copy(
                            os.path.join(committed_snapshots_dir, latest_snapshot),
                            latest_snapshot_dir,
                        )
                        primary_has_stopped = True
                        old_primary = primary
                        if args.add_new_node_after_primary_stops:
                            replace_primary(
                                network,
                                args.add_new_node_after_primary_stops,
                                old_primary,
                                latest_snapshot_dir,
                                statistics,
                            )

                    time.sleep(1)

                for remote_client in clients:
                    remote_client.stop()

                perf_label = args.perf_label

                if not args.stop_primary_after_s:
                    primary, _ = network.find_primary()
                    with primary.client() as nc:
                        r = nc.get("/node/memory")
                        assert r.status_code == http.HTTPStatus.OK.value

                        results = r.body.json()
                        current_value = results["current_allocated_heap_size"]
                        peak_value = results["peak_allocated_heap_size"]

                        bf = infra.bencher.Bencher()
                        bf.set(
                            perf_label,
                            infra.bencher.Memory(
                                current_value,
                                high_value=peak_value,
                            ),
                        )

                network.stop_all_nodes()

                agg = []

                for client_id, remote_client in enumerate(clients):
                    # Note: this assumes client are run locally, but saves a copy
                    send_file = os.path.join(
                        remote_client.remote.root, "pi_requests.parquet"
                    )
                    response_file = os.path.join(
                        remote_client.remote.root, "pi_response.parquet"
                    )
                    LOG.info(f"Analyzing results from {send_file} and {response_file}")

                    def table():
                        payloads = pl.read_parquet(requests_file_paths[client_id])
                        sent = pl.read_parquet(send_file)
                        rcvd = pl.read_parquet(response_file)
                        overall = payloads.join(sent, on="messageID")
                        overall = rcvd.join(overall, on="messageID")
                        overall = overall.with_columns(
                            client=pl.lit(remote_client.name),
                            requestSize=pl.col("request").map_elements(
                                len, return_dtype=pl.Int64
                            ),
                            responseSize=pl.col("rawResponse").map_elements(
                                len, return_dtype=pl.Int64
                            ),
                        )

                        number_of_errors = overall.filter(
                            pl.col("responseStatus") >= 500
                        ).height
                        total_number_of_requests = overall.height
                        print(
                            f"Errors: {number_of_errors} ({number_of_errors / total_number_of_requests * 100:.2f}%)"
                        )

                        overall = overall.with_columns(
                            pl.col("receiveTime").alias("latency") - pl.col("sendTime")
                        )
                        print(overall.sort("latency"))
                        first_send = overall["sendTime"].min()
                        last_recv = overall["receiveTime"].max()
                        print(f"{remote_client.name}: {remote_client.description}")
                        print(
                            f"{remote_client.name}: First send at {first_send}, last receive at {last_recv}"
                        )
                        duration = (last_recv - first_send).total_seconds()
                        print(
                            f"{remote_client.name}: {len(overall)} requests in {duration}s => {len(overall)//duration}tx/s"
                        )
                        agg.append(overall)

                    table()

                agg = pl.concat(agg, rechunk=True)
                LOG.info("Aggregate results")
                print(agg)

                number_of_errors = agg.filter(pl.col("responseStatus") >= 500).height
                total_number_of_requests = agg.height
                print(
                    f"Errors: {number_of_errors} ({number_of_errors / total_number_of_requests * 100:.2f}%)"
                )

                agg_path = os.path.join(
                    network.common_dir, "aggregated_basicperf_output.parquet"
                )
                with open(agg_path, "wb") as f:
                    agg.write_parquet(f)
                print(f"Aggregated results written to {agg_path}")

                start_send = agg["sendTime"].min()
                end_recv = agg["receiveTime"].max()
                duration_s = (end_recv - start_send).total_seconds()
                throughput = len(agg) / duration_s
                statistics["average_throughput_tx/s"] = throughput
                print(f"Average throughput: {throughput:.2f} tx/s")

                byte_input = (agg["requestSize"].sum() / duration_s) / (1024 * 1024)
                statistics["average_request_input_mb/s"] = byte_input
                print(f"Average request input: {byte_input:.2f} Mbytes/s")

                byte_output = (agg["responseSize"].sum() / duration_s) / (1024 * 1024)
                statistics["average_request_output_mb/s"] = byte_output
                print(f"Average request output: {byte_output:.2f} Mbytes/s")

                each_client = agg.partition_by("client")
                latest_start = max(client["sendTime"].min() for client in each_client)
                earliest_end = min(
                    client["receiveTime"].max() for client in each_client
                )
                all_active_duration_s = (earliest_end - latest_start).total_seconds()
                statistics["all_clients_active_from"] = latest_start.isoformat()
                statistics["all_clients_active_to"] = earliest_end.isoformat()
                statistics["all_clients_active_duration_s"] = all_active_duration_s
                print(
                    f"All clients active from {latest_start.time()} to {earliest_end.time()}"
                )
                all_clients_active_percentage = int(
                    (all_active_duration_s / duration_s) * 100
                )
                print(
                    f"This {all_active_duration_s:.3f}s is {all_clients_active_percentage}% of the {duration_s:.3f}s used to calculate throughputs above"
                )
                statistics["all_clients_active_percentage"] = (
                    all_clients_active_percentage
                )
                statistics["total_duration_s"] = duration_s

                agg_all_active = agg.filter(pl.col("sendTime") > latest_start).filter(
                    pl.col("receiveTime") < earliest_end
                )
                all_active_duration_s = (earliest_end - latest_start).total_seconds()
                all_active_throughput = len(agg_all_active) / all_active_duration_s
                statistics["all_clients_active_average_throughput_tx/s"] = (
                    all_active_throughput
                )
                writes = len(
                    agg_all_active.filter(pl.col("request").bin.starts_with(b"PUT "))
                )
                statistics["all_clients_active_write_fraction"] = writes / len(
                    agg_all_active
                )

                statistics_path = os.path.join(network.common_dir, "statistics.json")
                with open(statistics_path, "w") as f:
                    json.dump(statistics, f, indent=2)
                print(f"Aggregated statistics written to {statistics_path}")

                sent_per_sec = (
                    agg.with_columns(
                        (
                            (pl.col("sendTime").alias("second") - start_send) / 1000000
                        ).cast(pl.Int64)
                    )
                    .group_by("second")
                    .len()
                    .rename({"len": "sent"})
                )
                recv_per_sec = (
                    agg.with_columns(
                        (
                            (pl.col("receiveTime").alias("second") - start_send)
                            / 1000000
                        ).cast(pl.Int64)
                    )
                    .group_by("second")
                    .len()
                    .rename({"len": "rcvd"})
                )
                errors_per_sec = (
                    agg.with_columns(
                        (
                            (pl.col("receiveTime").alias("second") - start_send)
                            / 1000000
                        ).cast(pl.Int64)
                    )
                    .filter(pl.col("responseStatus") >= 500)
                    .group_by("second")
                    .len()
                    .rename({"len": "errors"})
                )

                per_sec = (
                    sent_per_sec.join(recv_per_sec, on="second")
                    .join(errors_per_sec, on="second", how="full")
                    .sort("second")
                    .fill_null(0)
                )

                plt.simple_bar(
                    list(per_sec["second"]),
                    list(per_sec["sent"]),
                    width=100,
                    title="Sent requests per second",
                )
                plt.show()

                plt.simple_stacked_bar(
                    list(per_sec["second"]),
                    [list(per_sec["rcvd"]), list(per_sec["errors"])],
                    width=100,
                    labels=["rcvd", "errors"],
                    colors=["green", "red"],
                    title="Received requests per second",
                )
                plt.show()

                if number_of_errors and not args.stop_primary_after_s:
                    raise RuntimeError(
                        f"Errors: {number_of_errors} ({number_of_errors / total_number_of_requests * 100:.2f}%)"
                    )

                bf = infra.bencher.Bencher()
                bf.set(
                    perf_label,
                    infra.bencher.Throughput(round(throughput, 1)),
                )

            except Exception as e:
                LOG.error(f"Stopping clients due to exception: {e}")
                for remote_client in clients:
                    remote_client.stop()
                raise


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--client", help="Client binary", required=True)
    parser.add_argument(
        "-n",
        "--nodes",
        help="List of hostnames[,pub_hostnames:ports]. If empty, spawn minimum working number of local nodes (minimum depends on consensus and other args)",
        action="append",
    )
    parser.add_argument(
        "--use-jwt",
        help="Use JWT with a temporary issuer as authentication method.",
        action="store_true",
    )
    parser.add_argument(
        "--client-timeout-s",
        help="Number of seconds after which unresponsive clients are shut down",
        default=300,
        type=float,
    )
    parser.add_argument(
        "--max-writes-ahead",
        help="Maximum number of writes to send to the server without waiting for a response",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--key-space-size",
        help="Size of the key space to be pre-populated and which writes and reads will be performed on",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "--client-def",
        help="Client definitions, e.g. '3,write,1000,primary' starts 3 clients sending 1000 writes to the primary",
        action="append",
        required=True,
    )
    parser.add_argument(
        "--stop-primary-after-s", help="Stop primary after this many seconds", type=int
    )
    parser.add_argument("--add-new-node-after-primary-stops", type=str)
    return infra.e2e_args.cli_args(
        parser=parser, accept_unknown=False, ledger_chunk_bytes_override="5MB"
    )


if __name__ == "__main__":
    args = cli_args()
    run(args)
