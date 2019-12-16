# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import getpass
import time
import logging
import multiprocessing
import json
from random import seed
import infra.ccf
import infra.proc
import infra.remote_client
import infra.rates
import os
import re
import cimetrics.upload

from loguru import logger as LOG

logging.getLogger("matplotlib").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def number_of_local_nodes(args):
    """
    If we are using pbft then we need to have 4 nodes. Otherwise with CFT
    on 2-core VMs, we start only one node, but on 4 core, we want to start 2.
    Not 3, because the client is typically running two threads.
    """
    if args.consensus == "pbft":
        return 4

    if multiprocessing.cpu_count() > 2:
        return 2
    else:
        return 1


def get_command_args(args, get_command):
    command_args = []
    return get_command(*command_args)


def filter_nodes(primary, backups, filter_type):
    if filter_type == "primary":
        return [primary]
    elif filter_type == "backups":
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
            node.host,
            node.rpc_port,
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


def run_client(args, primary, command_args):
    command = [
        args.client,
        f"--rpc-address={primary.host}:{primary.rpc_port}",
        f"--transactions={args.iterations}",
        f"--config={args.config}",
    ]
    command += command_args

    LOG.info("Client can be run with {}".format(" ".join(command)))
    while True:
        time.sleep(60)


def run(build_directory, get_command, args):
    if args.fixed_seed:
        seed(getpass.getuser())

    hosts = args.nodes
    if not hosts:
        hosts = ["localhost"] * number_of_local_nodes(args)

    LOG.info("Starting nodes on {}".format(hosts))

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, backups = network.find_nodes()

        command_args = get_command_args(args, get_command)

        if args.network_only:
            run_client(args, primary, command_args)
        else:
            nodes = filter_nodes(primary, backups, args.send_tx_to)
            clients = []
            client_hosts = args.client_nodes or ["localhost"]
            for client_id, client_host in enumerate(client_hosts):
                node = nodes[client_id % len(nodes)]
                remote_client = configure_remote_client(
                    args, client_id, client_host, node, command_args
                )
                clients.append(remote_client)

            for remote_client in clients:
                remote_client.start()

            try:
                with cimetrics.upload.metrics() as metrics:
                    tx_rates = infra.rates.TxRates(primary)
                    while True:
                        stop_waiting = True
                        for i, remote_client in enumerate(clients):
                            done = remote_client.check_done()
                            # all the clients need to be done
                            LOG.info(
                                f"Client {i} has {'completed' if done else 'not completed'} running"
                            )
                            stop_waiting = stop_waiting and done
                        if stop_waiting:
                            break
                        time.sleep(1)

                    tx_rates.get_metrics()
                    for remote_client in clients:
                        # TODO: For now we don't display CI results from PBFT perf runs on CIMetrics
                        upload_metrics = None if args.consensus == "pbft" else metrics
                        remote_client.print_and_upload_result(
                            args.label, upload_metrics
                        )
                        remote_client.stop()

                    LOG.info(f"Rates:\n{tx_rates}")
                    tx_rates.save_results(args.metrics_file)

            except Exception:
                for remote_client in clients:
                    remote_client.stop()
                raise
