# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.e2e_args
import infra.remote_client
from infra.perf import PERF_COLUMNS
from random import seed
import getpass
from loguru import logger as LOG
import cimetrics.upload
import time
import http
import sys

sys.path.insert(0, "../tests/perf-system/generator")
import generator

sys.path.insert(0, "../tests/perf-system/analyzer")
import analyzer


def get_command_args(args, get_command):
    command_args = []
    return get_command(*command_args)


def minimum_number_of_local_nodes(args):
    """
    If we are using bft then we need to have 3 nodes. CFT will run with 1 nodes, unless it expects a backup
    """
    if args.consensus == "BFT":
        return 3

    if args.send_tx_to == "backups":
        return 2

    return 1


def filter_nodes(primary, backups, filter_type):
    if filter_type == "primary":
        return [primary]
    elif filter_type == "backups":
        if not backups:
            raise Exception("--send-tx-to backups but no backup was found")
        return backups
    else:
        return [primary] + backups


def my_configure_remote_client(args, client_id, client_host, node, command_args):
    if client_host == "localhost":
        client_host = infra.net.expand_localhost()
        remote_impl = infra.remote.LocalRemote
    else:
        remote_impl = infra.remote.SSHRemote
    try:
        remote_client = infra.remote_client.CCFRemoteClient(
            "client_" + str(client_id),
            client_host,
            args.client,
            node.get_public_rpc_host(),
            node.get_public_rpc_port(),
            args.workspace,
            args.label,
            args.config,
            command_args,
            remote_impl,
            piccolo_run=True,
        )
        remote_client.setup()
        return remote_client
    except Exception:
        LOG.exception("Failed to start client {}".format(client_host))
        raise


def run(get_command, args):
    if args.fixed_seed:
        seed(getpass.getuser())

    hosts = args.nodes
    if not hosts:
        hosts = ["local://localhost"] * minimum_number_of_local_nodes(args)

    args.initial_user_count = 3
    args.sig_ms_interval = 1000  # Set to cchost default value
    args.ledger_chunk_bytes = "5MB"  # Set to cchost default value

    LOG.info("Starting nodes on {}".format(hosts))

    label_for_filename = args.label
    if label_for_filename.endswith("^"):
        label_for_filename = label_for_filename[:-1]
    if label_for_filename + ".parquet" not in os.listdir("./"):
        msgs = generator.Messages()
        for i in range(100000):
            msgs.append(
                "127.0.0.1:8000",
                "/app/log/private",
                "POST",
                data='{"id": '
                + str(i)
                + ', "msg": "Unique message: 93b885adfe0da089cdf634904fd59f7'
                + str(i)
                + '"}',
            )
        msgs.to_parquet_file("./pi_ls_virtual_cft.parquet")

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, backups = network.find_nodes()

        command_args = get_command_args(args, get_command)

        if args.use_jwt:
            jwt_issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
            jwt_issuer.register(network)
            jwt = jwt_issuer.issue_jwt()
            command_args += ["--bearer-token", jwt]

        nodes_to_send_to = filter_nodes(primary, backups, args.send_tx_to)
        clients = []
        client_hosts = []
        if args.one_client_per_backup:
            if not backups:
                raise Exception(
                    "--one-client-per-backup was set but no backup was found"
                )
            client_hosts = ["localhost"] * len(backups)
        else:
            if args.client_nodes:
                client_hosts.extend(args.client_nodes)

        if args.num_localhost_clients:
            client_hosts.extend(["localhost"] * int(args.num_localhost_clients))

        if not client_hosts:
            client_hosts = ["localhost"]

        for client_id, client_host in enumerate(client_hosts):
            node = nodes_to_send_to[client_id % len(nodes_to_send_to)]

            remote_client = my_configure_remote_client(
                args, client_id, client_host, node, command_args
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

            hard_stop_timeout = 90
            format_width = len(str(hard_stop_timeout)) + 3

            try:
                with cimetrics.upload.metrics(complete=False) as metrics:
                    start_time = time.time()
                    while True:
                        stop_waiting = True
                        for i, remote_client in enumerate(clients):
                            done = remote_client.check_done()
                            # all the clients need to be done
                            LOG.info(
                                f"Client {i} has {'completed' if done else 'not completed'} running ({time.time() - start_time:>{format_width}.2f}s / {hard_stop_timeout}s)"
                            )
                            stop_waiting = stop_waiting and done
                        if stop_waiting:
                            break
                        if time.time() > start_time + hard_stop_timeout:
                            raise TimeoutError(
                                f"Client still running after {hard_stop_timeout}s"
                            )

                        time.sleep(5)

                    for remote_client in clients:
                        analysis = analyzer.Analyze()

                        df_sends = analyzer.get_df_from_parquet_file(
                            "./workspace/client_0/"
                            + label_for_filename
                            + "_send.parquet"
                        )
                        df_responses = analyzer.get_df_from_parquet_file(
                            "./workspace/client_0/"
                            + label_for_filename
                            + "_response.parquet"
                        )
                        time_spent = analysis.total_time_in_sec(df_sends, df_responses)

                        perf_result = round(len(df_sends.index) / time_spent, 1)
                        LOG.success(f"{args.label}/{remote_client.name}: {perf_result}")

                        # TODO: Only results for first client are uploaded
                        # https://github.com/microsoft/CCF/issues/1046
                        if remote_client == clients[0]:
                            LOG.success(f"Uploading results for {remote_client.name}")
                            metrics.put(args.label, perf_result)
                        else:
                            LOG.warning(f"Skipping upload for {remote_client.name}")

                    primary, _ = network.find_primary()
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

                            metrics.put(heap_peak_metric, peak_value)

                    for remote_client in clients:
                        remote_client.stop()

            except Exception:
                LOG.error("Stopping clients due to exception")
                for remote_client in clients:
                    remote_client.stop()
                raise


def cli_args(add=lambda x: None, accept_unknown=False):
    parser = argparse.ArgumentParser()
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
        "--metrics-file",
        default="metrics.json",
        help="Path to json file where the transaction rate metrics will be saved to",
    )
    parser.add_argument(
        "-f",
        "--fixed-seed",
        help="Set a fixed seed for port and IP generation.",
        action="store_true",
    )
    parser.add_argument(
        "--use-jwt",
        help="Use JWT with a temporary issuer as authentication method.",
        action="store_true",
    )
    parser.add_argument("--config", help="Path to config for client binary", default="")

    return infra.e2e_args.cli_args(
        add=add, parser=parser, accept_unknown=accept_unknown
    )


def generic_run(*args, **kwargs):
    infra.path.mk_new("perf_summary.csv", PERF_COLUMNS)

    run(*args, **kwargs)


if __name__ == "__main__":

    args, unknown_args = cli_args(accept_unknown=True)

    unknown_args = [term for arg in unknown_args for term in arg.split(" ")]

    write_tx_index = unknown_args.index("--write-tx-times")

    def get_command(*args):
        return (
            [*args] + unknown_args[:write_tx_index] + unknown_args[write_tx_index + 1 :]
        )

    run(get_command, args)
