# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import argparse
import os
import socket
import time
import math
import create_config
from node import LocalNode
from subprocess import PIPE, Popen, run
import netifaces
from loguru import logger


class Node(LocalNode):
    def run(self, extra_args_replica, extra_args_client):
        if self.is_replica:
            self.set_cmd(
                [
                    f"./{self.server_exe}",
                    "--id",
                    str(self.id),
                    "--privk_file",
                    f"config_private/{self.machine_name}",
                    "--port",
                    self.port,
                ]
                + extra_args_replica
            )
        else:
            self.set_cmd(
                [
                    f"./{self.client_exe}",
                    "--id",
                    str(self.id),
                    "--privk_file",
                    f"config_private/{self.machine_name}",
                    "--port",
                    self.port,
                ]
                + extra_args_client
            )
        super(Node, self).run()


def create_nodes(args):
    nodes = []
    servers = args.servers
    clients = args.clients
    with open(args.test_config, "r") as test_config:
        lines = [line.strip() for line in test_config]
        # remove header
        lines.pop(0)

        for i, line in enumerate(lines):
            if line[0] == "#":
                continue

            values = line.split(",")
            port = values[0].strip()
            public_key_sig = values[1].strip()
            public_key_enc = values[2].strip()
            private_key = values[3].strip()
            if i < servers:
                node = Node(i, port, public_key_sig, public_key_enc, private_key, True)
                node.set_private_ip(args.ip)
                node.set_machine_name(
                    args.machine_name + "-" + str(i) + "-server-" + args.transport
                )
                node.set_public_ip(node.machine_name)

                nodes.append(node)
            elif i < clients + servers:
                node = Node(i, port, public_key_sig, public_key_enc, private_key, False)
                node.set_private_ip(args.ip)
                node.set_machine_name(
                    args.machine_name + "-" + str(i) + "-client-" + args.transport
                )
                node.set_public_ip(node.machine_name)

                nodes.append(node)
            else:
                logger.warning(f"replica configured on line {i} ignored")
    return nodes


def run_nodes(nodes, run_time, extra_args_replica, extra_args_client):
    for node in nodes:
        node.run(extra_args_replica, extra_args_client)
    start = time.time()
    delta = start - start
    total_run_time = run_time

    logger.info("running...")
    while delta < total_run_time:
        logger.info(f"{int(delta)} seconds run from {total_run_time} seconds run time")
        time.sleep(10)
        delta = time.time() - start

    logger.info("Done!")


def log_errors(err_file):
    errors = 0
    # SAN errors
    error_filter = ["ERROR", "AddressSanitizer", "ABORTING"]
    try:
        with open(err_file, "r") as lines:
            for line in lines:
                if any(x in line for x in error_filter):
                    logger.error("{}: {}".format(err_file, line.rstrip()))
                    errors += 1
        if errors:
            try:
                with open(err_file, "r") as lines:
                    logger.error("{} contents:".format(err_file))
                    logger.error(lines.read())
            except IOError:
                logger.exception("Could not read err output {}".format(err_file))
    except IOError:
        logger.exception("Could not check file {} for errors".format(err_file))

    assert errors == 0


def replica_checks(
    replicas, f, with_delays=False, test_client_proxy=False, has_ledger=False
):
    send_view_change = False
    process_view_change = False
    for node in replicas:
        logger.info(f"Checking results on replica - id: {node.id} port: {node.port}")
        replica_ready = False
        syscall_stats = False
        operations_complete = False
        reply_callback = False

        outfile = f"out{node.port}.txt"
        with open(outfile, "r") as log:
            counter_broken_logs = 0
            fix_logs = 0
            for line in log:
                if "Replica ready" in line:
                    replica_ready = True
                # if it is printing stats the replica hasn't aborted
                if "Syscall stats" in line:
                    syscall_stats = True
                if "Sending view change" in line:
                    send_view_change = True
                if "Process new view" in line:
                    process_view_change = True
                if "is smaller than request counter" in line:
                    counter_broken_logs += 1
                if "Fixed" in line:
                    fix_logs += 1
                if "Reply count" in line:
                    reply_callback = True
                if (
                    test_client_proxy
                    and "total requests executed" in line
                    and "total requests executed 0" not in line
                ):
                    operations_complete = True

        assert replica_ready
        assert syscall_stats
        assert fix_logs == counter_broken_logs
        if test_client_proxy:
            if f != 0 or node.id == 0:
                assert operations_complete
            if f == 0:
                assert reply_callback

    if not with_delays or f == 0:
        # if view changes not forced or running with f == 0 we shouldn't see any
        assert not send_view_change
        assert not process_view_change

    if not send_view_change:
        logger.info(
            "***************** NO VIEW CHANGES ISSUED DURING THIS TEST *****************"
        )
    if not process_view_change:
        logger.info(
            "***************** NO VIEW CHANGES PROCESSED DURING THIS TEST *****************"
        )

    if with_delays:
        logger.info("with_delays is set so checking for view changes")
        assert send_view_change
        assert process_view_change

    err_file = f"err{node.port}.txt"
    log_errors(err_file)


def client_checks(clients):
    for node in clients:
        logger.info(f"Checking results on client - id: {node.id} port: {node.port}")
        outfile = f"out{node.port}.txt"
        operations_complete = False
        with open(outfile, "r") as log:
            lines = log.readlines()
            for line in lines:
                # checks that more than 0 operations completed during the test for each client
                if (
                    "operations complete" in line
                    and "- i, 0 operations complete" not in line
                ):
                    operations_complete = True
        assert operations_complete

        err_file = f"err{node.port}.txt"
        log_errors(err_file)


def teardown(nodes, transport):
    for node in nodes:
        fname = f"out{node.port}.txt"
        os.rename(fname, f"{transport}_{fname}")


def discover_machine(args):
    if args.ip is None:
        addrs = netifaces.ifaddresses("eth0")
        args.ip = addrs[netifaces.AF_INET][0]["addr"]
    if args.machine_name is None:
        args.machine_name = socket.gethostname()


def get_extra_args(args):
    extra_args_replica = ["--transport", args.transport, "--config", "config.json"]
    if args.with_delays:
        extra_args_replica.append("--with-delays")
    if args.ledger:
        extra_args_replica.append("--ledger")
    if args.test_client_proxy:
        extra_args_replica.append("--test-client-proxy")
    if args.e:
        extra_args_replica.append("--timer-order")
        extra_args_replica.append(str(args.e))
    if args.d:
        extra_args_replica.append("--delay-order")
        extra_args_replica.append(str(args.d))

    extra_args_client = ["--transport", args.transport, "--config", "config.json"]

    return extra_args_replica, extra_args_client


if __name__ == "__main__":
    """
    Format of test config file should be:
    port, public_key_sig, public_key_enc, private_key
    <comma separated values for servers>
    <comma separated values for clients>
    """
    parser = argparse.ArgumentParser(description="test execution arguments")
    parser.add_argument("--machine-name", help="name of machine we are running on")
    parser.add_argument("--ip", help="machine ip address")
    parser.add_argument(
        "--servers", help="number of server machines", required=True, type=int
    )
    parser.add_argument(
        "--clients", help="number of client machines", required=True, type=int
    )
    parser.add_argument(
        "--test-config", help="name of test configuration", required=True
    )
    parser.add_argument(
        "--transport",
        help="type of transport (UDP_MT | UDP)",
        default="UDP",
        choices=["UDP", "UDP_MT"],
    )
    parser.add_argument("--run-time", help="run time in seconds", default=100, type=int)
    parser.add_argument(
        "--e",
        help="order of magnitude of delay timer timeout (e for every), default will be 1000",
        type=int,
    )
    parser.add_argument(
        "--d",
        help="order of magnitude of random sleep delay (d for delay), default will be 100000",
        type=int,
    )
    parser.add_argument(
        "--with-delays",
        help="Inserts random delays in the replicas causing view changes and roll backs to happen",
        action="store_true",
    )
    parser.add_argument(
        "--test-client-proxy",
        help="Tests client proxy at replica sending requests to the service",
        action="store_true",
    )
    parser.add_argument(
        "--f", help="Set f, the number of permitted Byzantine nodes", type=int
    )
    parser.add_argument(
        "--ledger", help="Record select actions to a ledger", action="store_true"
    )

    args = parser.parse_args()

    discover_machine(args)

    nodes = create_nodes(args)

    replica_nodes = [n for n in nodes if n.is_replica]
    client_nodes = [n for n in nodes if not n.is_replica]

    principals = len(replica_nodes) + len(client_nodes)
    f = args.f
    if f is None:
        f = math.floor((len(replica_nodes) - 1) / 3)
        assert (3 * f + 1) == len(replica_nodes), "Incorrect number of replicas"
        logger.info(f"Setting f to {f}")

    create_config.create_config_file(f, replica_nodes, client_nodes)

    extra_args_replica, extra_args_client = get_extra_args(args)

    run_nodes(nodes, args.run_time, extra_args_replica, extra_args_client)

    for node in nodes:
        node.stop()

    replica_checks(
        replica_nodes, f, args.with_delays, args.test_client_proxy, args.ledger
    )
    client_checks(client_nodes)
    teardown(nodes, args.transport)
