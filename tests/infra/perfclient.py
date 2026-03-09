# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import infra.runner
import infra.e2e_args
from infra.perf import PERF_COLUMNS


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

    # Client binary args are parsed from a config file
    # Default is in the same directory as this script
    default_config_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "common_config.ini"
    )
    parser.add_argument(
        "--config", help="Path to config for client binary", default=default_config_path
    )

    return infra.e2e_args.cli_args(
        add=add, parser=parser, accept_unknown=accept_unknown
    )


def run(*args, **kwargs):
    infra.path.mk_new("perf_summary.csv", PERF_COLUMNS)

    infra.runner.run(*args, **kwargs)


if __name__ == "__main__":
    args, unknown_args = cli_args(accept_unknown=True)

    unknown_args = [term for arg in unknown_args for term in arg.split(" ")]

    def get_command(*args):
        return [*args] + unknown_args

    infra.runner.run(get_command, args)
