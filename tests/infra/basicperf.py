# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.e2e_args
import infra.remote_client
import infra.jwt_issuer
from loguru import logger as LOG
import cimetrics.upload
import time
import http
import hashlib
from piccolo import generator
import polars as pl
from typing import Dict
import random
import string


def minimum_number_of_local_nodes(args):
    if args.send_tx_to == "backups":
        return 2

    return 1


def filter_nodes(primary, backups, filter_type):
    if filter_type == "primary":
        return [primary]
    elif filter_type == "backups":
        assert backups, "--send-tx-to backups but no backup was found"
        return backups
    else:
        return [primary] + backups


def configure_remote_client(args, client_id, client_host, common_dir):
    if client_host == "localhost":
        client_host = infra.net.expand_localhost()
        remote_impl = infra.remote.LocalRemote
    else:
        remote_impl = infra.remote.SSHRemote
    try:
        remote_client = infra.remote_client.CCFRemoteCmd(
            f"client_{client_id}",
            client_host,
            args.client,
            common_dir,
            args.workspace,
            remote_impl,
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


def write_to_random_keys(
    repetitions: int, msgs: generator.Messages, additional_headers: Dict[str, str]
):
    """
    Write fixed-size messages to a range of keys, this is the usual logging workload
    CCF has been running in various forms since early on. Each transaction produces a
    ledger entry and causes replication to backups.
    """
    batch_size = 100
    LOG.info(f"Workload: {repetitions} writes to a range of {batch_size} keys")
    for i in range(repetitions):
        key = f"{i % batch_size}"
        msgs.append(
            f"/records/{key}",
            "PUT",
            additional_headers=additional_headers,
            body=f"{hashlib.md5(str(i).encode()).hexdigest()}",
            content_type="text/plain",
        )


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
            keys = list(range(self.batch_size))
            random.shuffle(keys)
            for key in keys:
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


def configure_client_hosts(args, backups):
    client_hosts = []
    if args.one_client_per_backup:
        assert backups, "--one-client-per-backup was set but no backup was found"
        client_hosts = ["localhost"] * len(backups)
    else:
        if args.client_nodes:
            client_hosts.extend(args.client_nodes)

    if args.num_localhost_clients:
        client_hosts.extend(["localhost"] * int(args.num_localhost_clients))

    if not client_hosts:
        client_hosts = ["localhost"]
    return client_hosts


def run(args, append_messages):
    hosts = args.nodes
    if not hosts:
        hosts = ["local://localhost"] * minimum_number_of_local_nodes(args)

    LOG.info("Starting nodes on {}".format(hosts))
    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        primary, backups = network.find_nodes()
        additional_headers = {}
        if args.use_jwt:
            jwt_issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
            jwt_issuer.register(network)
            jwt = jwt_issuer.issue_jwt()
            additional_headers["Authorization"] = f"Bearer {jwt}"

        client_hosts = configure_client_hosts(args, backups)
        requests_file_paths = []

        for client_idx in range(len(client_hosts)):
            LOG.info(f"Generating {args.repetitions} requests for client_{client_idx}")
            msgs = generator.Messages()
            append_messages(args.repetitions, msgs, additional_headers)

            path_to_requests_file = os.path.join(
                network.common_dir, f"pi_client{client_idx}_requests.parquet"
            )
            LOG.info(f"Writing generated requests to {path_to_requests_file}")
            msgs.to_parquet_file(path_to_requests_file)
            requests_file_paths.append(path_to_requests_file)

        clients = []
        nodes_to_send_to = filter_nodes(primary, backups, args.send_tx_to)
        for client_id, client_host in enumerate(client_hosts):
            node = nodes_to_send_to[client_id % len(nodes_to_send_to)]

            remote_client = configure_remote_client(
                args, client_id, client_host, network.common_dir
            )
            remote_client.setcmd(
                [
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
                    os.path.abspath(requests_file_paths[client_id]),
                    "--pid-file-path",
                    "cmd.pid",
                ]
            )
            clients.append(remote_client)

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
                start_time = time.time()
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

                    time.sleep(5)

                for remote_client in clients:
                    remote_client.stop()

                primary, _ = network.find_primary()
                additional_metrics = {}
                with primary.client() as nc:
                    r = nc.get("/node/memory")
                    assert r.status_code == http.HTTPStatus.OK.value

                    results = r.body.json()
                    peak_value = results["peak_allocated_heap_size"]

                    # Do not upload empty metrics (virtual doesn't report memory use)
                    if peak_value != 0:
                        # Construct name for heap metric, removing ^ suffix if present
                        heap_peak_metric = args.label
                        if heap_peak_metric.endswith("^"):
                            heap_peak_metric = heap_peak_metric[:-1]
                        heap_peak_metric += "_mem"

                        additional_metrics[heap_peak_metric] = peak_value

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
                            requestSize=pl.col("request").apply(len),
                            responseSize=pl.col("rawResponse").apply(len),
                        )
                        overall = overall.with_columns(
                            pl.col("receiveTime").alias("latency") - pl.col("sendTime")
                        )
                        print(overall.sort("latency"))
                        agg.append(overall)

                    table()

                agg = pl.concat(agg, rechunk=True)
                LOG.info("Aggregate results")
                print(agg)
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
                print(f"Average throughput: {throughput:.2f} tx/s")
                byte_input = (agg["requestSize"].sum() / duration_s) / (1024 * 1024)
                print(f"Average request input: {byte_input:.2f} Mbytes/s")
                byte_output = (agg["responseSize"].sum() / duration_s) / (1024 * 1024)
                print(f"Average request output: {byte_output:.2f} Mbytes/s")

                sent_per_sec = (
                    agg.with_columns(
                        (
                            (pl.col("sendTime").alias("second") - start_send) / 1000000
                        ).cast(pl.Int64)
                    )
                    .groupby("second")
                    .count()
                    .rename({"count": "sent"})
                )
                recv_per_sec = (
                    agg.with_columns(
                        (
                            (pl.col("receiveTime").alias("second") - start_send)
                            / 1000000
                        ).cast(pl.Int64)
                    )
                    .groupby("second")
                    .count()
                    .rename({"count": "rcvd"})
                )

                per_sec = sent_per_sec.join(recv_per_sec, on="second").sort("second")
                print(per_sec)
                per_sec = per_sec.with_columns(
                    sent_rate=pl.col("sent") / per_sec["sent"].max(),
                    rcvd_rate=pl.col("rcvd") / per_sec["rcvd"].max(),
                )
                for row in per_sec.iter_rows(named=True):
                    s = "S" * int(row["sent_rate"] * 20)
                    r = "R" * int(row["rcvd_rate"] * 20)
                    print(f"{row['second']:>3}: {s:>20}|{r:<20}")

                with cimetrics.upload.metrics(complete=False) as metrics:
                    LOG.success("Uploading results")
                    metrics.put(args.label, round(throughput, 1))

                    for key, value in additional_metrics.items():
                        metrics.put(key, value)

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
    client_args_group = parser.add_mutually_exclusive_group()
    client_args_group.add_argument(
        "-cn",
        "--client-nodes",
        help="List of hostnames for spawning client(s). If empty, one client is spawned locally",
        action="append",
    )
    client_args_group.add_argument(
        "--one-client-per-backup",
        help="If set, allocates one (local) client per backup",
        action="store_true",
    )
    parser.add_argument(
        "-nlc",
        "--num-localhost-clients",
        help="The number of localhost clients. \
        This argument is cumulative with the client-nodes and one-client-per-backup and arguments",
    )
    parser.add_argument(
        "--send-tx-to",
        choices=["primary", "backups", "all"],
        default="all",
        help="Send client requests only to primary, only to backups, or to all nodes",
    )
    parser.add_argument(
        "--use-jwt",
        help="Use JWT with a temporary issuer as authentication method.",
        action="store_true",
    )
    parser.add_argument(
        "--repetitions",
        help="Number of requests to send",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--write-tx-times",
        help="Unused, swallowed for compatibility with old args",
        action="store_true",
    )
    parser.add_argument(
        "--client-timeout-s",
        help="Number of seconds after which unresponsive clients are shut down",
        default=90,
        type=float,
    )
    parser.add_argument(
        "--rw-mix",
        help="Run a batched, fractional read/write mix instead of pure writes",
        type=float,
    )
    parser.add_argument(
        "--max-writes-ahead",
        help="Maximum number of writes to send to the server without waiting for a response",
        type=int,
        default=1000,
    )

    return infra.e2e_args.cli_args(
        parser=parser, accept_unknown=False, ledger_chunk_bytes_override="5MB"
    )


if __name__ == "__main__":
    args = cli_args()
    if args.rw_mix is None:
        run(args, write_to_random_keys)
    else:
        run(args, RWMix(1000, args.rw_mix))
