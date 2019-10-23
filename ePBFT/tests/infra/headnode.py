# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import argparse
import os
import time
import create_config
from node import RemoteNode
from loguru import logger
import glob
import paramiko
from contextlib import contextmanager


@contextmanager
def ssh_client(hostname):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname)
        yield client
    finally:
        client.close()


class Node(RemoteNode):
    def setup(self):
        with ssh_client(self.public_ip) as client:
            logger.info(f"Getting IP - {self.public_ip}")
            _, stdout, _ = client.exec_command("ifconfig | grep broadcast")
            stdout = stdout.readlines()
            result = stdout[0].strip()
            result = result.split(" ")
            self.private_ip = result[1]

            _, stdout, _ = client.exec_command("hostname")
            stdout = stdout.readlines()
            self.machine_name = stdout[0].strip()
            logger.info(f"IP: {self.machine_name} - {self.private_ip}")

    def get_results(self, directory):
        output_dir = os.path.join(directory, self.public_ip)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(
            f"downloading output files from {self.machine_name} into {output_dir}"
        )

        with ssh_client(self.public_ip) as client:
            session = client.open_sftp()
            session.get(f"out{self.port}.txt", f"{output_dir}/out{self.port}.txt")
            session.close()

    def run(self, transport, run_time, warmup, cooldown):
        config_params = ["--transport", transport]

        if self.is_replica:
            logger.info(f"starting replica - {self.machine_name}")
            self.set_cmd(
                [
                    "simple-server",
                    "--config",
                    "config.json",
                    "--port",
                    self.port,
                    "--id",
                    str(self.id),
                    "--privk_file",
                    f"config_private/{self.public_ip}",
                ]
                + config_params
            )
        else:
            config_params += [
                "--measure",
                str(run_time * 1000),
                "--warmup",
                str(warmup * 1000),
                "--cooldown",
                str(cooldown * 1000),
            ]
            logger.info(f"starting client - {self.machine_name}")
            self.set_cmd(
                [
                    "simple-client",
                    "--config",
                    "config.json",
                    "--port",
                    self.port,
                    "--id",
                    str(self.id),
                    "--iterations",
                    "1000000",
                    "--privk_file",
                    f"config_private/{self.public_ip}",
                ]
                + config_params
            )

        super(Node, self).run()

    def wait_for_stdout_line(self, line, timeout=10):
        with ssh_client(self.public_ip) as client:
            for _ in range(timeout):
                _, stdout, _ = client.exec_command(
                    f"grep -F '{line}' out{self.port}.txt"
                )
                if stdout.channel.recv_exit_status() == 0:
                    return
                time.sleep(1)
            raise ValueError(f'"{line}" not found in stdout after {timeout} seconds')


def setup_files(location, server_name, client_name):
    with ssh_client(location) as client:
        logger.info("Removing old files")
        client.exec_command("rm out*.txt")
        client.exec_command("rm simple-*")
        client.exec_command("rm config.json")
        client.exec_command("rm -rf config_private")

        logger.info(location)
        logger.info(f"copying to: {location}")
        session = client.open_sftp()
        session.put("config.json", "config.json")
        session.mkdir("config_private")
        for f in glob.glob("config_private/*"):
            session.put(f, f)
        session.put(client_name, client_name)
        session.put(server_name, server_name)
        client.exec_command(f"chmod +x {server_name}")
        client.exec_command(f"chmod +x {client_name}")
        session.close()


def create_nodes(path, client, server):
    nodes = []
    lines = []
    with open(path) as f:
        lines = [line.strip() for line in f]

    lines.pop(0)
    distinct_machines = {}

    node_id_counter = 0
    for line in lines:
        if line[0] == "#":
            continue

        values = line.split(",")
        distinct_ip = values[0].strip()
        node = Node(
            node_id_counter,
            values[1].strip(),
            values[2].strip(),
            values[3].strip(),
            values[4].strip(),
            values[5].strip() == "True",
        )
        node.set_public_ip(distinct_ip)
        node.set_client_exe(client)
        node.set_server_exe(server)
        node_id_counter += 1

        if distinct_ip not in distinct_machines:
            distinct_machines[distinct_ip] = node
            node.setup()
        else:
            same_machine = distinct_machines[distinct_ip]
            node.set_private_ip(same_machine.private_ip)
            node.set_machine_name(same_machine.machine_name)

        nodes.append(node)

    return nodes


def run(replicas, clients, transport, run_time, warmup, cooldown):
    for node in replicas:
        node.run(transport, run_time, warmup, cooldown)
    for node in replicas:
        logger.info(f"wait for replica {node.id} running on {node.public_ip} to start")
        node.wait_for_stdout_line("Replica ready")

    total_run_time = run_time + warmup + cooldown
    logger.info(f"total run time will be {total_run_time} seconds")

    for node in clients:
        node.run(transport, run_time, warmup, cooldown)

    start = time.time()
    delta = start - start

    logger.info("running...")
    while delta < total_run_time:
        logger.info(f"{int(delta)} seconds run from {total_run_time} seconds run time")
        time.sleep(10)
        delta = time.time() - start

    logger.info("Done!")


def teardown(nodes, result_dir, transport, num_clients, num_replicas):
    distinct_machines = {}
    for node in nodes:
        if node.public_ip not in distinct_machines:
            node.stop()
            distinct_machines[node.public_ip] = node

    if not os.path.isdir(result_dir):
        os.mkdir(result_dir)

    result_dir = os.path.join(
        result_dir, f"t_{transport}_clients_{num_clients}_replicas_{num_replicas}"
    )

    if not os.path.isdir(result_dir):
        os.mkdir(result_dir)

    result = os.listdir(result_dir)
    result_int = list(map(lambda x: int(x), result))
    if len(result_int) == 0:
        result_int = [0]
    new_dir = max(result_int) + 1
    new_dir = os.path.join(result_dir, str(new_dir))
    os.mkdir(new_dir)

    for n in nodes:
        n.get_results(new_dir)


def filter_nodes(nodes, num):
    machines = {}

    for node in nodes:
        if node.public_ip in machines:
            machines[node.public_ip].append(node)
        else:
            machines[node.public_ip] = [node]

    return_nodes = []
    while num > 0:
        all_nodes_present = False
        for key in machines:
            if len(machines[key]) > 0 and num > 0:
                return_nodes.append(machines[key].pop())
                num = num - 1
                all_nodes_present = True

        if not all_nodes_present:
            raise Exception(
                "Mismatch between machines specified and configuration file"
            )

    return return_nodes


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="test execution arguments")
    parser.add_argument(
        "-m",
        "--machines",
        help="csv with machines configuration",
        default="./machines.csv",
    )
    parser.add_argument(
        "-s", "--server", help="name of server application", required=True
    )
    parser.add_argument(
        "-c", "--client", help="name of client application", required=True
    )
    parser.add_argument(
        "-r", "--results", help="folder to store results", required=True
    )

    parser.add_argument(
        "--transport",
        help="transport options UDP_MT",
        default="UDP_MT",
        choices=("UDP_MT"),
    )
    parser.add_argument(
        "--num-clients", help="number of client applications", required=True
    )
    parser.add_argument("--num-replicas", help="number of replicas", required=True)
    parser.add_argument("--num-failures", help="number of failures", required=True)
    parser.add_argument(
        "--test-iterations", help="number of test iterations", default=1, type=int
    )
    parser.add_argument(
        "--run-time", help="node run time in seconds", default=120, type=int
    )
    parser.add_argument(
        "--warmup", help="client warmup time in seconds", default=10, type=int
    )
    parser.add_argument(
        "--cooldown", help="client cooldown time in seconds", default=10, type=int
    )
    args = parser.parse_args()

    all_nodes = create_nodes(args.machines, args.client, args.server)

    for num_failures in args.num_failures.split(","):
        for num_replicas in args.num_replicas.split(","):
            for num_clients in args.num_clients.split(","):
                logger.info(f"number of clients - {num_clients}")
                logger.info(f"number of replicas - {num_replicas}")
                logger.info(f"number of failures - {num_failures}")

                for i in range(0, args.test_iterations):

                    logger.info("running new test iteration")
                    logger.info(f"iteration {i} of {args.test_iterations}")

                    list_replicas = [node for node in all_nodes if node.is_replica]
                    list_clients = [node for node in all_nodes if not node.is_replica]

                    replicas_filtered = filter_nodes(list_replicas, int(num_replicas))
                    clients_filtered = filter_nodes(list_clients, int(num_clients))

                    nodes = replicas_filtered + clients_filtered
                    create_config.create_config_file(
                        int(num_failures), list_replicas, list_clients
                    )

                    locations = {node.public_ip for node in nodes}
                    for location in locations:
                        setup_files(location, args.server, args.client)

                    run(
                        replicas_filtered,
                        clients_filtered,
                        args.transport,
                        args.run_time,
                        args.warmup,
                        args.cooldown,
                    )
                    teardown(
                        nodes, args.results, args.transport, num_clients, num_replicas
                    )
