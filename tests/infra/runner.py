# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import getpass
import time
import http
import logging
from random import seed
import infra.jwt_issuer
import infra.network
import infra.proc
import infra.remote_client
import cimetrics.upload
import threading
import copy
from typing import List
import sys
import better_exceptions

from loguru import logger as LOG

logging.getLogger("matplotlib").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def minimum_number_of_local_nodes(args):
    if args.send_tx_to == "backups":
        return 2

    return 1


def get_command_args(args, get_command):
    command_args = []
    return get_command(*command_args)


def filter_nodes(primary, backups, filter_type):
    if filter_type == "primary":
        return [primary]
    elif filter_type == "backups":
        if not backups:
            # pylint: disable=broad-exception-raised
            raise Exception("--send-tx-to backups but no backup was found")
        return backups
    else:
        return [primary] + backups


def configure_remote_client(args, client_id, client_host, node, command_args):
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
                # pylint: disable=broad-exception-raised
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
            remote_client = configure_remote_client(
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
                        perf_result = remote_client.get_result()
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


FAILURES = []


def log_exception(args: threading.ExceptHookArgs):
    description = f"Failure in {args.thread.name}: {repr(args.exc_value)}"
    FAILURES.append(description)
    LOG.error(
        description
        + "\n"
        + "\n".join(
            better_exceptions.format_exception(
                args.exc_type, args.exc_value, args.exc_traceback
            )
        )
    )


threading.excepthook = log_exception


class ConcurrentRunner:
    threads: List[threading.Thread] = []

    def __init__(self, add_options=None) -> None:
        def add(parser):
            parser.add_argument(
                "-N",
                "--show-only",
                help="List all sub-tests without executing",
                action="store_true",
            )
            parser.add_argument(
                "-R",
                "--regex",
                help="Run sub-tests whose name includes this string",
                metavar="<string>",
            )
            if add_options:
                add_options(parser)

        self.args = infra.e2e_args.cli_args(add=add)

    def add(self, prefix, target, **args_overrides):
        args_ = copy.deepcopy(self.args)
        for k, v in args_overrides.items():
            setattr(args_, k, v)
        args_.label = f"{prefix}_{self.args.label}"
        self.threads.append(threading.Thread(name=prefix, target=target, args=[args_]))

    def run(self, max_concurrent=None):
        config = {
            "handlers": [
                {
                    "sink": sys.stderr,
                    "format": "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <red>{{{thread.name}}}</red> <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
                }
            ]
        }
        LOG.configure(**config)

        if self.args.regex:
            self.threads = [
                thread for thread in self.threads if self.args.regex in thread.name
            ]

        if self.args.show_only:
            for thread in self.threads:
                print(thread.name)
            return

        if not max_concurrent:
            max_concurrent = len(self.threads)

        thread_groups = [
            self.threads[i : i + max_concurrent]
            for i in range(0, len(self.threads), max_concurrent)
        ]

        for group in thread_groups:
            for thread in group:
                thread.start()

            for thread in group:
                thread.join()

        if FAILURES:
            # pylint: disable=broad-exception-raised
            raise Exception(FAILURES)
